import json
import socket
import struct
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "app/ecloud_engine"))
import desktop_heartbeat as hb
import sidecar


def cag(payload, command=0x0a):
    return struct.pack("<BBH", command, 1, len(payload)) + payload


def desktop(iid="test-instance"):
    return SimpleNamespace(instance_id=iid, origin_company_code="CMSSZTE",
                           custom_login_params={"csapip": "192.0.2.10:30087",
                                                "cagList": [{"addr": "192.0.2.20", "port": 8899}]})


class Socket:
    def __init__(self, chunks=()):
        self.chunks = list(chunks)
        self.sent = []
        self.closed = False

    def settimeout(self, value):
        pass

    def recv(self, size):
        if not self.chunks:
            return b""
        item = self.chunks.pop(0)
        if isinstance(item, Exception):
            raise item
        result, rest = item[:size], item[size:]
        if rest:
            self.chunks.insert(0, rest)
        return result

    def sendall(self, data):
        self.sent.append(bytes(data))

    def close(self):
        self.closed = True

    def shutdown(self, _):
        self.closed = True


class WireTests(unittest.TestCase):
    def test_live_heart_fixture_and_reply(self):
        # Actual server frame, with a non-secret serial. Header is 19 bytes.
        incoming = bytes.fromhex("d801000000000000740001000000000000000000")
        sock = Socket([cag(incoming)])
        stream = hb.DesktopStream(sock, threading.Event())
        self.assertEqual(stream.receive(float("inf")), (472, 0x74, b"\0"))
        expected = bytearray(incoming)
        expected[8] = 0x79
        self.assertEqual(hb.message(472, 0x79, b"\0"), expected)

    def test_fragmented_and_coalesced_mux_and_message_frames(self):
        first = hb.message(10, 4, b"0123456789ab")
        second = hb.message(11, 0x74, b"\0")
        wire = cag(first[:7]) + cag(first[7:] + second)
        sock = Socket([wire[i:i + 3] for i in range(0, len(wire), 3)])
        stream = hb.DesktopStream(sock, threading.Event())
        self.assertEqual(stream.receive(float("inf")), (10, 4, b"0123456789ab"))
        self.assertEqual(stream.receive(float("inf")), (11, 0x74, b"\0"))

    def test_close_command_and_eof_are_failures(self):
        for chunks in ([cag(b"\1\0\0\0", 0x2a)], []):
            with self.subTest(chunks=chunks):
                with self.assertRaises(hb.HeartbeatError):
                    hb.DesktopStream(Socket(chunks), threading.Event()).read(1, float("inf"))

    def test_timeout_keeps_partial_body_and_header(self):
        frame = hb.message(12, 4, b"abcdefghijkl")
        stream = hb.DesktopStream(Socket([cag(frame[:23]), socket.timeout(), cag(frame[23:])]), threading.Event())
        with patch.object(hb.time, "monotonic", side_effect=[0, 0, 0, 2]):
            with self.assertRaises(TimeoutError):
                stream.receive(1)
        self.assertEqual(stream.receive(float("inf")), (12, 4, b"abcdefghijkl"))

    def test_rejects_oversized_and_unknown_headers(self):
        oversized = struct.pack("<QHI", 1, 0x74, hb.MAX_MESSAGE + 1) + b"\0" * 5
        unknown = bytearray(hb.message(1, 0x74, b"\0"))
        unknown[18] = 1
        for frame in (oversized, unknown):
            with self.assertRaises(hb.HeartbeatError):
                hb.DesktopStream(Socket([cag(frame)]), threading.Event()).receive(float("inf"))

    def test_gateway_never_falls_back_to_reference_authors_machine(self):
        d = desktop()
        self.assertEqual(hb.gateway_for(d), ("192.0.2.20", 8899, "192.0.2.10:30087"))
        d.custom_login_params = {"csapip": "192.0.2.10:30087", "cagList": []}
        with self.assertRaises(hb.HeartbeatError):
            hb.gateway_for(d)
        d = desktop()
        d.origin_company_code = "ZTE"
        with self.assertRaises(hb.HeartbeatError):
            hb.gateway_for(d)

    def test_templates_use_each_connections_dynamic_materials(self):
        import ipaddress
        values = [("2001:db8::1", "00000000-0000-4000-8000-000000000001", "12345678", 5100, 60063),
                  ("2001:db8::2", "00000000-0000-4000-8000-000000000002", "87654321", 5101, 60065)]
        for address, vmid, key, port, proxy in values:
            raw = ipaddress.ip_address(address).packed
            packets = hb.packets_for(dict(address=raw, vmid=vmid, key=key, port=port, proxy_port=proxy))
            self.assertEqual(packets[1][4:20], raw)
            self.assertEqual(packets[1][20:56], vmid.encode())
            self.assertEqual(struct.unpack_from("<I", packets[1])[0], port)
            self.assertEqual(struct.unpack_from("<I", packets[2], 8)[0], proxy)
            self.assertEqual(packets[3][12:28], raw)
            self.assertIn((key + vmid).encode(), packets[4])


class WorkerTests(unittest.TestCase):
    def test_two_hearts_then_close_does_not_remain_successful(self):
        sock = Socket()
        worker = hb.HeartbeatWorker(desktop())
        worker.sock = sock
        sent = []

        class Stream:
            reads = iter([b"REDQ" + struct.pack("<III", 2, 2, 4), b"\0" * 4, b"\0" * 4])
            messages = iter([(1, 0x67, b"\0" * 64), (2, 4, b"abcdefghijkl"),
                             (3, 0x74, b"\0"), (4, 0x74, b"\0")])

            def __init__(self, *args):
                pass

            def send(self, data):
                sent.append(data)

            def read(self, *args):
                return next(self.reads)

            def receive(self, *args):
                try:
                    return next(self.messages)
                except StopIteration:
                    raise hb.HeartbeatError("服务器已关闭桌面通道")

        with patch.object(hb, "gateway_for", return_value=("192.0.2.20", 8899, "x")), \
             patch.object(hb, "mint_connection", return_value={}), \
             patch.object(hb, "packets_for", return_value=[b"" for _ in range(5)]), \
             patch.object(worker, "_connect", return_value=sock), \
             patch.object(hb, "DesktopStream", Stream):
            worker._run()
        state = worker.snapshot()
        self.assertEqual(state["heartCount"], 2)
        self.assertEqual(state["ackCount"], 2)
        self.assertEqual(state["state"], "failed")
        self.assertIn("关闭", state["error"])
        self.assertTrue(sock.closed)
        frames = [f for f in sent if len(f) >= hb.HEADER_SIZE and f != b"\0" * 128]
        self.assertEqual([struct.unpack_from("<H", f, 8)[0] for f in frames], [3, 0x79, 0x79])
        self.assertEqual(frames[0][19:], b"abcdefghijkl")

    def test_stop_interrupts_socket_and_cannot_open_another(self):
        worker = hb.HeartbeatWorker(desktop())
        sock = Socket()
        worker.sock = sock
        worker.stop()
        self.assertTrue(sock.closed)
        self.assertEqual(worker.snapshot()["state"], "stopped")
        with patch.object(hb.socket, "create_connection") as connect:
            with self.assertRaises(hb.HeartbeatError):
                worker._connect(("192.0.2.20", 8899, "x"), [])
            connect.assert_not_called()


class ReconcileTests(unittest.TestCase):
    def setUp(self):
        sidecar._HEARTBEATS.clear()
        sidecar._SESSIONS["test"] = {"desktops": {"vm": desktop("vm")}}

    def tearDown(self):
        sidecar._HEARTBEATS.clear()
        sidecar._SESSIONS.pop("test", None)

    def test_poll_is_idempotent_and_disabled_desktop_stops(self):
        class Worker:
            def __init__(self, desktop):
                self.alive = False
                self.stopped = False
                self.thread = SimpleNamespace(is_alive=lambda: self.alive)

            def start(self):
                self.alive = True

            def snapshot(self):
                return {"state": "waiting"}

            def stop(self):
                self.alive = False
                self.stopped = True

        with patch.object(sidecar, "HeartbeatWorker", Worker):
            params = {"sessionId": "test", "instanceIds": ["vm"]}
            sidecar.op_heartbeat_sync(params)
            worker = sidecar._HEARTBEATS[("test", "vm")]
            sidecar.op_heartbeat_sync(params)
            self.assertIs(sidecar._HEARTBEATS[("test", "vm")], worker)
            sidecar.op_heartbeat_sync({"sessionId": "test", "instanceIds": []})
            self.assertTrue(worker.stopped)
            self.assertFalse(sidecar._HEARTBEATS)

    def test_failed_connection_observes_retry_delay(self):
        worker = SimpleNamespace(thread=SimpleNamespace(is_alive=lambda: False),
                                 snapshot=lambda: {"state": "failed", "finishedAt": 100000})
        sidecar._HEARTBEATS[("test", "vm")] = worker
        with patch.object(sidecar.time, "time", return_value=120), \
             patch.object(sidecar, "HeartbeatWorker") as new_worker:
            result = sidecar.op_heartbeat_sync({"sessionId": "test", "instanceIds": ["vm"]})
            new_worker.assert_not_called()
            self.assertEqual(result["desktops"]["vm"]["retryAt"], 160000)

    def test_cannot_start_unknown_or_other_vendor_desktop(self):
        for iid in ("unknown", "vm"):
            if iid == "vm":
                sidecar._SESSIONS["test"]["desktops"]["vm"].origin_company_code = "H3C"
            with patch.object(sidecar, "HeartbeatWorker") as worker:
                with self.assertRaises(ValueError):
                    sidecar.op_heartbeat_sync({"sessionId": "test", "instanceIds": [iid]})
                worker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
