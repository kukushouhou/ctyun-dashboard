'use strict';

// 执行真实的子通道、会话与重试循环，仅替换网络及已成功的主干握手。
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { EventEmitter } = require('node:events');
const { createRequire } = require('node:module');
const tlsFile = path.resolve(__dirname, '../app/ydpc/zte_cag_tls.js');
const tlsApi = require(tlsFile);

function linkReply(code = 0, withKey = true) {
  const reply = Buffer.alloc(withKey ? 25 : 20);
  reply.write('REDQ');
  reply.writeUInt32LE(2, 4);
  reply.writeUInt32LE(2, 8);
  reply.writeUInt32LE(reply.length - 16, 12);
  reply.writeUInt32LE(code, 16);
  if (withKey) Buffer.from('30819f300d', 'hex').copy(reply, 20);
  return reply;
}

class Transport extends EventEmitter {
  constructor({ accepted = [], closeMain = false } = {}) {
    super();
    this.accepted = accepted;
    this.closeMain = closeMain;
    this.destroyed = false;
    this.mainWrites = [];
  }
  write(packet) {
    const id = packet[1];
    if (packet[0] === tlsApi.CAG_PROXY_DATA_CMD && id === 1) this.mainWrites.push(packet.subarray(4));
    if (packet[0] !== tlsApi.CAG_PROXY_DATA_CMD || id < 2) return true;
    const payload = packet.subarray(4);
    if (payload.subarray(0, 4).toString() === 'REDQ') {
      const ok = this.accepted.includes(id);
      const reply = tlsApi.packFrame(tlsApi.CAG_PROXY_DATA_CMD, id, linkReply(ok ? 0 : 8, ok));
      // 服务端错误与 close 同包：不能把 result=8 吞成普通的“已关闭”。
      this.emit('data', ok ? reply : Buffer.concat([
        reply, tlsApi.packFrame(tlsApi.CAG_PROXY_CLOSE_LINK_CMD, id, Buffer.alloc(0))
      ]));
    } else if (payload.length === 128) {
      this.emit('data', tlsApi.packFrame(tlsApi.CAG_PROXY_DATA_CMD, id, Buffer.alloc(4)));
    } else if (this.closeMain && (id === 5 || id === 7)) {
      this.emit('data', tlsApi.packFrame(tlsApi.CAG_PROXY_CLOSE_LINK_CMD, 1, Buffer.alloc(0)));
    }
    return true;
  }
  destroy() { this.destroyed = true; this.emit('close'); }
}

function sessionApi(transport) {
  const context = vm.createContext({
    module: { exports: {} }, require: createRequire(tlsFile),
    Buffer, console, setTimeout, clearTimeout,
    simulatedDial: async () => ({ socket: transport, conv: 36 })
  });
  vm.runInContext(fs.readFileSync(tlsFile, 'utf8') + `
    dialCagTcpTls = simulatedDial;
    rawMainHandshake = async () => ({ ok: true, spiceSessionId: 3 });
  `, context, { filename: tlsFile });
  return context.module.exports;
}

const options = { innerHost: '192.0.2.1', innerPort: 5100, key: 'test-key', vmId: 'test-vm' };

test('MAIN_INIT 按字段读取会话编号，不能误读鼠标模式 3', () => {
  const context = vm.createContext({ module: { exports: {} }, require: createRequire(tlsFile), Buffer });
  vm.runInContext(fs.readFileSync(tlsFile, 'utf8'), context, { filename: tlsFile });
  const readSessionId = vm.runInContext('zteMainInitConnectionId', context);
  for (const [length, offset] of [[64, 5], [32, 0]]) {
    const payload = Buffer.alloc(length);
    // 现场的字段排列，替换会话编号和时间，避免把用户会话材料写进测试。
    [0x12345678, 2, 3, 2, 1, 3000, 1000, 64 * 1024 * 1024]
      .forEach((value, i) => payload.writeUInt32LE(value, offset + i * 4));
    assert.equal(readSessionId(payload), 0x12345678);
    const request = tlsApi.buildRawChannelREDQ('test', 'test-vm', 'uuid', 'trace', 'span', readSessionId(payload), 2, 0);
    assert.equal(request.readUInt32LE(16), 0x12345678);
  }
  assert.throws(() => readSessionId(Buffer.alloc(10)), /MAIN_INIT 布局/);
});

test('所有子通道被拒绝：保留返回码、禁止成功回调、关闭连接', async () => {
  const transport = new Transport();
  const api = sessionApi(transport);
  const logs = [];
  let established = 0;
  await assert.rejects(api.runTlsSpiceSession({
    ...options,
    onEstablished: () => established++,
    onLog: (tag, message, level) => logs.push({ tag, message, level })
  }), error => {
    assert.equal(error.code, 'SPICE_DISPLAY_NOT_READY');
    assert.equal(error.failures.length, 7);
    assert.ok(error.failures.every(f => f.stage === '等待 REDQ 回复' && f.code === 8));
    return true;
  });
  assert.equal(established, 0);
  assert.equal(transport.destroyed, true);
  assert.equal(logs.filter(l => l.level === 'warning').length, 7);
  assert.ok(logs.every(l => !l.message.includes(options.key)));
});

test('只有输入通道认证通过仍不能宣称显示会话就绪', async () => {
  const api = sessionApi(new Transport({ accepted: [6] }));
  await assert.rejects(api.runTlsSpiceSession(options), error => {
    assert.equal(error.code, 'SPICE_DISPLAY_NOT_READY');
    assert.match(error.message, /认证 1\/7/);
    return true;
  });
});

test('认证拒绝与读取超时保留各自阶段和错误码', async () => {
  const replies = [linkReply(), Buffer.from([7, 0, 0, 0])];
  const denied = await tlsApi.rawSubChannelHandshake({
    write() {}, readExact: async n => {
      const first = replies[0];
      const out = first.subarray(0, n);
      if (out.length === first.length) replies.shift();
      else replies[0] = first.subarray(n);
      return out;
    }
  }, options, 3, 2, 0, 10);
  assert.equal(denied.ok, false);
  assert.equal(denied.stage, '等待认证结果');
  assert.equal(denied.code, 7);
  const timedOut = await tlsApi.rawSubChannelHandshake({
    write() {}, readExact: async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }); }
  }, options, 3, 2, 0, 10);
  assert.equal(timedOut.stage, '等待 REDQ 回复');
  assert.equal(timedOut.code, 'ETIMEDOUT');
});

test('显示通道通过后主干提前关闭：不能返回正常切片', async () => {
  const transport = new Transport({ accepted: [5, 7] });
  const api = sessionApi(transport);
  let established = 0;
  await assert.rejects(api.runTlsSpiceSession({ ...options, onEstablished: () => {
    established++;
    transport.emit('data', tlsApi.packFrame(tlsApi.CAG_PROXY_CLOSE_LINK_CMD, 1, Buffer.alloc(0)));
  } }),
    error => error.code === 'SPICE_SESSION_INTERRUPTED');
  assert.equal(established, 1);
});

test('初始化期间主干已断开：禁止再发成功回调', async () => {
  const api = sessionApi(new Transport({ accepted: [5, 7], closeMain: true }));
  let established = 0;
  await assert.rejects(api.runTlsSpiceSession({ ...options, onEstablished: () => established++ }),
    error => error.code === 'SPICE_SESSION_INTERRUPTED');
  assert.equal(established, 0);
});

test('健康会话完成切片，并在退出时清理连接', async () => {
  const transport = new Transport({ accepted: [2, 3, 4, 5, 6, 7, 8] });
  const api = sessionApi(transport);
  const session = await api.runTlsSpiceSession({ ...options, holdSeconds: 0.001 });
  assert.equal(session.sessionEstablished, true);
  assert.equal(session.authedSubLinks, 7);
  assert.equal(session.displaySubLinks, 2);
  assert.equal(session.errors, 0);
  assert.equal(transport.destroyed, true);
  assert.equal(transport.mainWrites.length, 0, '主通道不能发送显示/输入初始化消息');
});

test('已关闭的显示通道拒绝写入，不能继续计为成功心跳', () => {
  const transport = new Transport();
  const mux = tlsApi.CagMux.open(transport);
  const link = mux.openLink({ host: '192.0.2.1', port: 5100 });
  transport.emit('data', tlsApi.packFrame(tlsApi.CAG_PROXY_CLOSE_LINK_CMD, link.linkId, Buffer.alloc(0)));
  assert.throws(() => link.write(Buffer.alloc(1)), { code: 'CAG_LINK_CLOSED' });
  mux.close();
});

test('用户主动停止不记作链路失败', async () => {
  const transport = new Transport();
  const api = sessionApi(transport);
  const session = await api.runTlsSpiceSession({ ...options, shouldStop: () => true });
  assert.equal(session.stopped, true);
  assert.equal(session.sessionEstablished, false);
  assert.equal(transport.destroyed, true);
});

for (const earlyDisconnect of [false, true]) {
test(`真实任务循环${earlyDisconnect ? '认证后断开' : '认证失败'}：等待 30 秒且不误报活跃`, async () => {
  const clientFile = path.resolve(__dirname, '../app/ydpc/ydpc_client.js');
  const localRequire = createRequire(clientFile);
  let attempts = 0;
  let client;
  const waits = [];
  const states = [];
  const logs = [];
  const modules = {
    './soho_client': { SohoClient: class { constructor() { this.sohoToken = 'test'; }
      async getFirmAuth() { return { cagIp: '192.0.2.2', cagPort: 8899, vmId: 'test-vm' }; } } },
    './cag_client': {}, './mqtt_client': {}, './scg_keepalive': {}, './zte_cag_raw': {},
    './product_route': localRequire('./product_route'),
    './cag_boot': {
      cagBootVm: async () => ({ success: true, connectStr: 'test' }),
      zteDecodeConnectStr: () => 'test',
      parseConnectCommand: () => ({ spiceHost: options.innerHost, spicePort: 5100, vmId: options.vmId, sessionKey: options.key })
    },
    './zte_cag_tls': { runTlsSpiceSession: opts => {
      attempts++;
      const transport = new Transport({ accepted: earlyDisconnect ? [5, 7] : [] });
      return sessionApi(transport).runTlsSpiceSession({ ...opts, onEstablished: info => {
        opts.onEstablished(info);
        transport.emit('data', tlsApi.packFrame(tlsApi.CAG_PROXY_CLOSE_LINK_CMD, 1, Buffer.alloc(0)));
      } });
    } }
  };
  const context = vm.createContext({
    module: { exports: {} }, require: name => {
      if (!(name in modules)) throw new Error('Unexpected import: ' + name);
      return modules[name];
    },
    Buffer, console, process: { env: {} }, clearTimeout,
    setTimeout: (callback, delay) => {
      waits.push(delay);
      const task = client.dataPlaneTasks.get('test-vm');
      states.push({ failStreak: task.failStreak, active: client.isDataPlaneActive('test-vm'), demoted: task.demoted });
      if (attempts === 3) task.stopFlag = true;
      queueMicrotask(callback);
    }
  });
  vm.runInContext(fs.readFileSync(clientFile, 'utf8'), context, { filename: clientFile });
  client = new context.module.exports.YdpcClient({ name: 'Test' }, {
    appendLog: (tag, message, level) => logs.push({ tag, message, level })
  });
  client.startDataPlaneTask({ _route: { kind: 'ZTE' } }, 'test-vm', 'Test');
  for (let i = 0; i < 100 && client.dataPlaneTasks.has('test-vm'); i++) {
    await new Promise(resolve => setImmediate(resolve));
  }
  assert.equal(attempts, 3);
  assert.equal(client.dataPlaneTasks.size, 0);
  assert.deepEqual(waits, [30000, 30000, 30000]);
  assert.ok(states.every(s => !s.active));
  if (earlyDisconnect) {
    assert.ok(!logs.some(l => l.message.includes('切片完成')));
  } else {
    assert.deepEqual(states.map(s => s.failStreak), [1, 2, 3]);
    assert.equal(states[1].demoted, true);
    assert.ok(!logs.some(l => l.level === 'success'));
  }
});
}
