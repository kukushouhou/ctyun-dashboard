"""CMSSZTE desktop heartbeat, using the authenticated desktop's own materials.

Adapted from 1936-zero/ecloud-cmsszte-alive (MIT), commit dff401845f41826de51030909ee572ebfb672791.
The local capture uses a 19-byte vendor message header, not the reference's
16-byte header. In particular, its 36-byte agent nudge declares a 20-byte body
but is three bytes short. Do not send that nudge: this server requests HEART
itself. All receiving is buffered and a closed channel always invalidates health.

Node owns desired sessions and retries. A worker only services one open socket;
it never logs in, powers on, reconnects, or writes connection tickets to disk.
"""
from __future__ import annotations

import base64
import ipaddress
import json
import re
import socket
import ssl
import struct
import threading
import time
from pathlib import Path

import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TEMPLATES = Path(__file__).with_name("heartbeat_templates")
# Public constants shipped by the vendor client, not account credentials.
CSAP_COMMAND_KEY = b"SuYan@@Zte".ljust(16, b"\0")
CSAP_CONNECTION_KEY = b"3fec8a54-7e49-48"
HEART_TIMEOUT = 45.0
MAX_MESSAGE = 1 << 20
HEADER_SIZE = 19


class HeartbeatError(RuntimeError):
    """Only credential-free, user-readable messages may be raised here."""


def gateway_for(desktop):
    if desktop.origin_company_code != "CMSSZTE":
        raise HeartbeatError("该桌面不属于 CMSSZTE 分支")
    params = desktop.custom_login_params
    if isinstance(params, str):
        params = json.loads(params)
    if not isinstance(params, dict):
        raise HeartbeatError("平台未返回桌面连接参数")
    csap = params.get("csapip") or params.get("csapIp") or params.get("csap_ip")
    for item in params.get("cagList") or []:
        if not isinstance(item, dict):
            continue
        host = str(item.get("addr") or item.get("ip") or item.get("host") or "")
        try:
            address = ipaddress.ip_address(host)
            port = int(item.get("port") or 8899)
        except (ValueError, TypeError):
            continue
        if address.version == 4 and 0 < port < 65536 and isinstance(csap, str) and csap:
            return host, port, csap
    raise HeartbeatError("平台未返回可用的 IPv4 网关和控制面地址")


def mint_connection(desktop, gateway):
    host, port, csap = gateway
    vmid = str(desktop.machine_id)
    if not re.fullmatch(r"[0-9a-fA-F-]{36}", vmid):
        raise HeartbeatError("桌面 machineId 格式异常")
    timestamp = str(int(time.time() * 1000))
    plain = '{\n\t"opType" : 3,\n\t"timestamp" : "' + timestamp + '",\n\t"vmid" : "' + vmid + '"\n}\n'
    encrypted = AES.new(CSAP_COMMAND_KEY, AES.MODE_ECB).encrypt(pad(plain.encode(), 16))
    body = {"encrypt": 7, "language": "zh", "param": base64.b64encode(encrypted).decode(),
            "timestamp": timestamp}
    # Match the existing HTTP client's proxy policy; no external credential service.
    from ecloud_client import trust_env_enabled
    with requests.Session() as session:
        session.trust_env = trust_env_enabled()
        response = session.post(
            f"http://{host}:{port}/cs/cs_suOperDesktop.action",
            headers={"Content-Type": "application/xml", "Accept": "*/*", "X-Ap-sHost": csap},
            data=json.dumps(body), timeout=(5, 15),
        )
        if response.status_code != 200:
            raise HeartbeatError(f"获取连接票据失败（HTTP {response.status_code}）")
        result = response.json()
    if not isinstance(result, dict) or str(result.get("result")) != "0" or not result.get("connectStr"):
        raise HeartbeatError("平台未签发桌面连接票据")
    decoded = AES.new(CSAP_CONNECTION_KEY, AES.MODE_ECB).decrypt(bytes.fromhex(result["connectStr"]))
    try:
        decoded = unpad(decoded, 16)
    except ValueError:
        decoded = decoded.rstrip(b"\0")
    parts = decoded.decode("utf-8").split()
    flags = {parts[i].lstrip("-"): parts[i + 1]
             for i in range(len(parts) - 1) if parts[i].startswith("-") and not parts[i + 1].startswith("-")}
    address = ipaddress.ip_address(flags.get("hv6") or flags.get("h") or "")
    key = flags.get("k", "")
    if address.version != 6:
        raise HeartbeatError("当前桌面心跳只验证了 IPv6 内网连接格式")
    if (flags.get("vmid") or flags.get("vm-id")) != vmid or not re.fullmatch(r"\d{8}", key):
        raise HeartbeatError("连接票据与所选桌面不匹配或格式不支持")
    inner_port = int(flags.get("p") or flags.get("pv6") or 0)
    proxy_port = int(flags.get("proxy-sport") or flags.get("sport") or 0)
    if not (0 < inner_port < 65536 and 0 < proxy_port < 65536):
        raise HeartbeatError("连接票据缺少有效端口")
    return {"address": address.packed, "vmid": vmid, "key": key,
            "port": inner_port, "proxy_port": proxy_port}


def packets_for(material):
    def read(name):
        return bytearray((TEMPLATES / name).read_bytes())
    auth = read("f23_C2S_220.bin")
    struct.pack_into("<I", auth, 0, material["port"])
    auth[4:20] = material["address"]
    auth[20:56] = material["vmid"].encode("ascii")
    auth[56:60] = b"\0" * 4
    tls_request = read("f26_C2S_116.bin")
    struct.pack_into("<I", tls_request, 8, material["proxy_port"])
    link = read("block_00_C2S_108.bin")
    struct.pack_into("<H", link, 4, material["proxy_port"])
    link[12:28] = material["address"]
    redq = read("block_02_C2S_163.bin")
    slot = re.search(rb"\d{8}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", redq)
    if slot is None:
        raise HeartbeatError("桌面握手模板缺少动态票据字段")
    redq[slot.start():slot.end()] = (material["key"] + material["vmid"]).encode("ascii")
    return bytes(read("f20_C2S_50.bin")), bytes(auth), bytes(tls_request), bytes(link), bytes(redq)


def message(serial, kind, body=b""):
    if len(body) > MAX_MESSAGE:
        raise HeartbeatError("桌面消息过大")
    return struct.pack("<QHI", serial, kind, len(body)) + b"\0" * 5 + body


class DesktopStream:
    """Buffer TCP, CAG multiplex frames, and desktop messages independently."""
    def __init__(self, sock, stopped):
        self.sock = sock
        self.stopped = stopped
        self.network = bytearray()
        self.payload = bytearray()

    def send(self, data):
        if len(data) > 65535:
            raise HeartbeatError("桌面通道发送帧过大")
        self.sock.sendall(struct.pack("<BBH", 0x0a, 1, len(data)) + data)

    def read(self, size, deadline):
        while len(self.payload) < size:
            if self.stopped.is_set():
                raise HeartbeatError("桌面心跳已停止")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("桌面通道等待超时")
            while len(self.network) >= 4:
                command, link, length = struct.unpack_from("<BBH", self.network)
                if len(self.network) < length + 4:
                    break
                frame = bytes(self.network[4:4 + length])
                del self.network[:4 + length]
                if link != 1:
                    continue
                if command == 0x2a:
                    raise HeartbeatError("服务器已关闭桌面通道")
                if command == 0x0a:
                    self.payload.extend(frame)
                if len(self.payload) > MAX_MESSAGE + HEADER_SIZE:
                    raise HeartbeatError("桌面接收缓冲超过上限")
            if len(self.payload) >= size:
                break
            self.sock.settimeout(min(1.0, remaining))
            try:
                chunk = self.sock.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                raise HeartbeatError("桌面连接已断开")
            self.network.extend(chunk)
        result = bytes(self.payload[:size])
        del self.payload[:size]
        return result

    def receive(self, deadline):
        # Keep the header until the complete body arrives, including across timeouts.
        header = self.read(HEADER_SIZE, deadline)
        serial, kind, size = struct.unpack_from("<QHI", header)
        if size > MAX_MESSAGE or header[14:19] != b"\0" * 5:
            raise HeartbeatError("不支持的桌面消息格式")
        try:
            body = self.read(size, deadline)
        except TimeoutError:
            self.payload[:0] = header
            raise
        return serial, kind, body


class HeartbeatWorker:
    def __init__(self, desktop):
        self.desktop = desktop
        self.stopped = threading.Event()
        self.lock = threading.RLock()
        self.sock = None
        self.state = {"state": "connecting", "heartCount": 0, "ackCount": 0,
                      "lastHeartbeatAt": 0, "connectedAt": 0, "finishedAt": 0,
                      "error": "", "tlsWarning": ""}
        self.thread = threading.Thread(target=self._run, daemon=True,
                                       name="ecloud-desktop-heartbeat")

    def start(self):
        self.thread.start()

    def snapshot(self):
        with self.lock:
            return dict(self.state)

    def update(self, **values):
        with self.lock:
            self.state.update(values)

    def stop(self):
        self.stopped.set()
        with self.lock:
            sock = self.sock
        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
        self.update(state="stopped")

    def _track(self, sock):
        with self.lock:
            self.sock = sock
            if self.stopped.is_set():
                sock.close()
                raise HeartbeatError("桌面心跳已停止")
        return sock

    def _exact(self, sock, count):
        data = bytearray()
        deadline = time.monotonic() + 8
        while len(data) < count:
            if self.stopped.is_set() or time.monotonic() >= deadline:
                raise HeartbeatError("网关握手超时或已停止")
            sock.settimeout(max(0.1, deadline - time.monotonic()))
            chunk = sock.recv(count - len(data))
            if not chunk:
                raise HeartbeatError("网关在握手期间断开")
            data.extend(chunk)
        return bytes(data)

    def _connect(self, gateway, packets, relaxed=False):
        if self.stopped.is_set():
            raise HeartbeatError("桌面心跳已停止")
        host, port, _ = gateway
        sock = self._track(socket.create_connection((host, port), timeout=5))
        try:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            sock.sendall(packets[0])
            if not self._exact(sock, 50).startswith(b"ZTEC"):
                raise HeartbeatError("网关认证头不被接受")
            sock.sendall(packets[1])
            auth = self._exact(sock, 36)
            if struct.unpack_from("<I", auth)[0] != 200 or struct.unpack_from("<I", auth, 4)[0] != 0:
                raise HeartbeatError("网关拒绝桌面认证")
            sock.sendall(packets[2])
            context = ssl.create_default_context()
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            if relaxed:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            sock.settimeout(8)
            sock = self._track(context.wrap_socket(sock, server_hostname=host))
            return sock
        except BaseException:
            sock.close()
            raise

    def _run(self):
        stage = "获取桌面连接参数"
        try:
            gateway = gateway_for(self.desktop)
            material = mint_connection(self.desktop, gateway)
            packets = packets_for(material)
            stage = "建立网关连接"
            try:
                sock = self._connect(gateway, packets)
            except ssl.SSLCertVerificationError as exc:
                # Same bounded certificate-defect fallback as the existing CAG path.
                if exc.verify_code not in (10, 18, 19, 20, 21, 62, 64):
                    raise
                self.update(tlsWarning=f"网关证书验证失败（{exc.verify_code}），已重新拨号并放宽本次连接校验")
                sock = self._connect(gateway, packets, relaxed=True)
            stage = "桌面握手"
            sock.sendall(packets[3])
            stream = DesktopStream(sock, self.stopped)
            stream.send(packets[4])
            deadline = time.monotonic() + 10
            header = stream.read(16, deadline)
            if header[:4] != b"REDQ":
                raise HeartbeatError("桌面未返回 REDQ 握手")
            length = struct.unpack_from("<I", header, 12)[0]
            if length < 4 or length > 4096:
                raise HeartbeatError("桌面握手长度异常")
            reply = stream.read(length, deadline)
            if struct.unpack_from("<I", reply)[0] != 0:
                raise HeartbeatError("桌面拒绝连接票据")
            stream.send(b"\0" * 128)
            if stream.read(4, time.monotonic() + 8) != b"\0" * 4:
                raise HeartbeatError("桌面票据认证失败")
            serial, kind, body = stream.receive(time.monotonic() + 8)
            if kind != 0x67:
                raise HeartbeatError("桌面未返回会话初始化")
            self.update(state="waiting", connectedAt=int(time.time() * 1000))
            stage = "维持桌面心跳"
            last_heart = time.monotonic()
            while not self.stopped.is_set():
                serial, kind, body = stream.receive(last_heart + HEART_TIMEOUT)
                if kind == 0x74:
                    if len(body) != 1:
                        raise HeartbeatError("桌面心跳长度异常")
                    stream.send(message(serial, 0x79, b"\0"))
                    last_heart = time.monotonic()
                    with self.lock:
                        self.state["heartCount"] += 1
                        self.state["ackCount"] += 1
                        self.state["lastHeartbeatAt"] = int(time.time() * 1000)
                        self.state["state"] = "healthy" if self.state["heartCount"] >= 2 else "waiting"
                elif kind == 4:
                    stream.send(message(serial, 3, body))
                elif kind == 3 and len(body) == 8:
                    stream.send(message(serial, 1, body[:4]))
        except Exception as exc:
            if not self.stopped.is_set():
                detail = str(exc) if isinstance(exc, HeartbeatError) else type(exc).__name__
                self.update(state="failed", error=f"{stage}：{detail}")
        finally:
            with self.lock:
                sock = self.sock
                self.sock = None
            if sock is not None:
                sock.close()
            if self.stopped.is_set():
                self.update(state="stopped")
            self.update(finishedAt=int(time.time() * 1000))
