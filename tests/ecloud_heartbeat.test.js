'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const path = require('node:path');
const { EcloudClient } = require('../app/ecloud/ecloud_client');
const { resolveWorkingPython } = require('../app/ecloud/ecloud_engine');

function client() {
  const account = { id: 'test', enabled: true, features: {}, desktops: [
    { instanceId: 'vm', machineName: 'test desktop', originCompanyCode: 'CMSSZTE', powerState: 'on' },
    { instanceId: 'other', originCompanyCode: 'H3C', powerState: 'on' },
  ] };
  const logs = [];
  const calls = [];
  const c = new EcloudClient(account, {
    appendLog: (...args) => logs.push(args), saveConfig: () => {},
    resolveTaskEnabled: (a, d) => ({ enabled: a.enabled !== false && a.features.keepAlive !== false && d?.keepaliveEnabled !== false }),
  });
  c.engine = { isReady: () => true, syncHeartbeats: async (_sid, ids) => { calls.push(ids); return { desktops: {} }; } };
  return { c, account, logs, calls };
}

test('public desktop protocol and lifecycle tests', async () => {
  const python = await resolveWorkingPython();
  assert.ok(python, 'Python and sidecar dependencies are required');
  const result = spawnSync(python.path, [...python.args, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_ecloud_heartbeat.py'], {
    cwd: path.resolve(__dirname, '..'), encoding: 'utf8', timeout: 30000,
  });
  assert.equal(result.status, 0, (result.stderr || '') + (result.stdout || ''));
});

test('only eligible CMSSZTE desktops get a connection; account and desktop switches stop it', async () => {
  const { c, account, calls } = client();
  await c.syncDesktopHeartbeats();
  assert.deepEqual(calls.pop(), ['vm']);
  account.desktops[0].keepaliveEnabled = false;
  await c.syncDesktopHeartbeats();
  assert.deepEqual(calls.pop(), []);
  account.desktops[0].keepaliveEnabled = true;
  account.features.keepAlive = false;
  await c.syncDesktopHeartbeats();
  assert.deepEqual(calls.pop(), []);
});

test('healthy HTTP probes cannot make a failed or expired desktop heartbeat healthy', () => {
  const { c } = client();
  c.metrics.l1.lastOk = true;
  c.metrics.l2.lastOk = true;
  assert.match(c._desktopHeartbeatAction({ state: 'failed', error: 'closed', heartCount: 2 }).text, /中断/);
  assert.equal(c._desktopHeartbeatAction({ state: 'healthy', lastHeartbeatAt: Date.now() - 46000 }).level, 'error');
});

test('desktop view obeys the master heartbeat switch even when HTTP registration remains enabled', () => {
  const { c, account } = client();
  c.resolveTaskEnabled = (_a, _d, task) => ({ enabled: task === 'ecloudL2DesktopReg', reason: '保活总开关已关闭' });
  c.metrics.desktopHeartbeats.vm = { state: 'healthy', lastHeartbeatAt: Date.now() };
  const view = c.describeDesktopKeepAlive(account.desktops[0]);
  assert.equal(view.enabled, false);
  assert.equal(view.lastAction.level, 'off');
  assert.equal(view.heartbeatMode, true);
});

test('live desktop heartbeat outranks a stale HTTP power observation', () => {
  const { c, account } = client();
  const d = account.desktops[0];
  d._l2NoUptime = true;
  d._l2At = Date.now();
  c.metrics.desktopHeartbeats.vm = { state: 'healthy', lastHeartbeatAt: Date.now() };
  assert.equal(c._effectivePowerState(d).state, 'on');
  c.metrics.desktopHeartbeats.vm.lastHeartbeatAt -= 46000;
  assert.equal(c._effectivePowerState(d).state, 'off');
});

test('repeated healthy polls do not flood logs', async () => {
  const { c, logs } = client();
  const started = Date.now() - 60000;
  c.engine.syncHeartbeats = async () => ({ desktops: { vm: {
    state: 'healthy', connectedAt: started, lastHeartbeatAt: Date.now(), heartCount: 5, ackCount: 5,
  } } });
  await c.syncDesktopHeartbeats();
  await c.syncDesktopHeartbeats();
  await c.syncDesktopHeartbeats();
  assert.equal(logs.length, 1);
  assert.match(logs[0][1], /接收 5 次 \/ 应答 5 次/);
});

test('a pending poll cannot restore a connection after stopping the worker', async () => {
  const { c, calls } = client();
  let resolve;
  c.engine.syncHeartbeats = async (_sid, ids) => {
    calls.push(ids);
    return ids.length ? new Promise(r => { resolve = r; }) : { desktops: {} };
  };
  const pending = c.syncDesktopHeartbeats();
  c.stopKeepAliveWorker();
  resolve({ desktops: { vm: { state: 'healthy' } } });
  await pending;
  assert.deepEqual(c.metrics.desktopHeartbeats, {});
  assert.deepEqual(calls.at(-1), []);
});
