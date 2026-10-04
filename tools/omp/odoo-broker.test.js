'use strict';
// Factory-shape test for odoo-broker.js: no broker, no OMP harness, no
// network. The factory is invoked with a stub pi api (the real loader
// passes CustomToolAPI: cwd/exec/ui/logger/typebox/...); these tools use
// none of it, but the call proves the factory binds without the host.
// Run: node --test tools/omp/odoo-broker.test.js
//
// HTTP is stubbed per-test with streaming ReadableStream-like bodies
// (getReader): the production single streaming bounded reader is the only
// path exercised, so no model/backend/Odoo credentials exist anywhere in
// this file.
//
// PROVEN (2026-10-04): factory shape (12 typed tools, 5-arg execute);
// legitimate routing to typed broker paths; denials surface as isError;
// strict unknown/wrong-typed args rejected with no fetch; non-loopback
// broker URLs refused; redirect:'error' set on every request; token
// redacted from error text. Real-loader binding is proven separately in
// odoo-broker.loader.test.js (bun + installed discover/loadCustomTools,
// temp cwd/.omp/tools, REAL in-process broker for legit+denied calls).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');

const factory = require('./odoo-broker.js');
const src = fs.readFileSync(path.join(__dirname, 'odoo-broker.js'), 'utf8');

function stubPi() {
  return { cwd: '/tmp', exec: async () => { throw new Error('must not exec'); } };
}

function toolsOf() {
  const out = factory(stubPi());
  return Array.isArray(out) ? out : [out];
}

function byName(name) {
  const t = toolsOf().find((t) => t.name === name);
  assert.ok(t, `${name} tool must exist`);
  return t;
}

test('factory returns twelve typed tools with execute + JSON-schema parameters', () => {
  assert.strictEqual(typeof factory, 'function', 'module must export the factory function');
  const tools = toolsOf();
  const names = tools.map((t) => t.name).sort();
  assert.deepStrictEqual(names, [
    'odoo.aggregate',
    'odoo.catalog',
    'odoo.companies',
    'odoo.count',
    'odoo.evidence',
    'odoo.meta',
    'odoo.read',
    'odoo.search',
    'odoo.workspace.list',
    'odoo.workspace.mkdir',
    'odoo.workspace.read',
    'odoo.workspace.write',
  ]);
  for (const t of tools) {
    assert.ok(t.label, `${t.name} needs a label`);
    assert.ok(t.description, `${t.name} needs a description`);
    assert.ok(t.parameters && t.parameters.type === 'object', `${t.name} needs an object parameters schema`);
    assert.strictEqual(typeof t.execute, 'function', `${t.name} needs execute`);
    assert.strictEqual(t.execute.length, 5, `${t.name} execute must take (toolCallId,params,onUpdate,ctx,signal)`);
  }
});

test('no shell fallback, token via env only, factory ignores pi', () => {
  // Strip line comments so prose mentioning shell concepts is not mistaken
  // for code that shells out.
  const code = src.replace(/^[ \t]*\/\/.*$/gm, '');
  assert.ok(!code.includes('child_process'), 'must not shell out');
  assert.ok(!code.includes('execSync'), 'must not shell out');
  assert.ok(!code.includes('spawnSync'), 'must not shell out');
  assert.ok(!code.includes('execFile'), 'must not shell out');
  assert.ok(src.includes('ODOO_BROKER_TOKEN'), 'token must come from env');
  // tools/omp discovery: the loader scans .omp/tools for factory modules.
  assert.ok(src.includes('.omp/tools'), 'must document the .omp/tools load path');
  // Timeout env override must be capped so the bound cannot be disabled.
  assert.ok(src.includes('MAX_TIMEOUT_MS'), 'timeout override must have a ceiling');
});

const TEST_CAP = 4 * 1024 * 1024;

function streamedResponse(chunks, onCancel) {
  let i = 0;
  return {
    body: {
      getReader() {
        return {
          read: async () => (i < chunks.length
            ? { done: false, value: chunks[i++] }
            : { done: true, value: undefined }),
          cancel: async () => { if (onCancel) onCancel(); },
          releaseLock() {},
        };
      },
    },
  };
}

function streamedEnvelope(env) {
  return streamedResponse([Buffer.from(JSON.stringify(env), 'utf8')]);
}

test('legitimate call routes to the broker path', async () => {
  const seen = [];
  const realFetch = global.fetch;
  global.fetch = async (url, opts) => {
    seen.push({ url: String(url), opts });
    return streamedEnvelope({ success: true, result: { rows: [] } });
  };
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const tools = toolsOf();
    const search = tools.find((t) => t.name === 'odoo.search');
    const res = await search.execute('id-1', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, undefined, 'legitimate call must not be isError');
    assert.strictEqual(seen.length, 1);
    assert.ok(seen[0].url.endsWith('/rpc/search'), `routed to ${seen[0].url}`);
    assert.strictEqual(seen[0].opts.headers.Authorization, 'Bearer tok');
    assert.strictEqual(seen[0].opts.redirect, 'error', 'redirects must never be followed with the token attached');
    const text = res.content[0].text;
    assert.ok(text.includes('rows'), `result text must carry the broker result, got ${text}`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('denied call surfaces isError without throwing', async () => {
  const realFetch = global.fetch;
  global.fetch = async () => streamedEnvelope({ success: false, error: 'denied: unknown-model' });
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const tools = toolsOf();
    const read = tools.find((t) => t.name === 'odoo.read');
    const res = await read.execute('id-2', { model: 'nope', ids: [1], fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'denied call must surface isError');
    assert.ok(res.content[0].text.includes('denied'), `denial text must survive, got ${res.content[0].text}`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('workspace.mkdir routes to /rpc/workspace/mkdir', async () => {
  const seen = [];
  const realFetch = global.fetch;
  global.fetch = async (url) => {
    seen.push(String(url));
    return streamedEnvelope({ success: true, result: { path: 'reports', written: true } });
  };
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const tools = toolsOf();
    const mkdir = tools.find((t) => t.name === 'odoo.workspace.mkdir');
    assert.ok(mkdir, 'workspace.mkdir tool must exist');
    const res = await mkdir.execute('id-3', { path: 'reports' }, undefined, {}, undefined);
    assert.strictEqual(res.isError, undefined);
    assert.ok(seen[0].endsWith('/rpc/workspace/mkdir'), `routed to ${seen[0]}`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});


test('unknown args rejected with no fetch', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    calls += 1;
    return streamedEnvelope({ success: true, result: {} });
  };
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const search = byName('odoo.search');
    const bad = await search.execute('id-x', { model: 'res.partner', fields: ['name'], admin: true }, undefined, {}, undefined);
    assert.strictEqual(bad.isError, true, 'unknown arg must be isError');
    assert.ok(bad.content[0].text.includes('unknown argument'), `got ${bad.content[0].text}`);
    const wrong = await search.execute('id-y', { model: 'res.partner', fields: 'name' }, undefined, {}, undefined);
    assert.strictEqual(wrong.isError, true, 'wrong-typed arg must be isError');
    assert.ok(wrong.content[0].text.includes('must be'), `got ${wrong.content[0].text}`);
    assert.strictEqual(calls, 0, 'strict rejection must happen before any fetch');
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('non-loopback broker URL refused', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    calls += 1;
    return streamedEnvelope({ success: true, result: {} });
  };
  process.env.ODOO_BROKER_URL = 'http://192.168.1.10:8471';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-z', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'non-loopback URL must be isError');
    assert.ok(res.content[0].text.includes('loopback'), `got ${res.content[0].text}`);
    assert.strictEqual(calls, 0, 'no request may leave for a non-loopback host');
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('token redacted from error strings', async () => {
  const realFetch = global.fetch;
  global.fetch = async () => streamedEnvelope({ success: false, error: 'denied for token-SECRET-abc token' });
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'token-SECRET-abc';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-r', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true);
    assert.ok(!res.content[0].text.includes('token-SECRET-abc'), `token leaked: ${res.content[0].text}`);
    assert.ok(res.content[0].text.includes('***'), `redaction marker missing: ${res.content[0].text}`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('redirect refused before the token moves', async (t) => {
  // A 302 target that must never see the Authorization header. Uses a real
  // loopback HTTP server (no mocks): the tool fetch must throw on redirect
  // (redirect:'error') and surface a tool error instead of following.
  const evilSeen = [];
  const evil = http.createServer((req, res) => {
    evilSeen.push(req.headers.authorization || '');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end('{}');
  });
  await new Promise((resolve) => evil.listen(0, '127.0.0.1', resolve));
  t.after(() => evil.close());
  const evilPort = evil.address().port;
  const target = http.createServer((req, res) => {
    res.writeHead(302, { Location: `http://127.0.0.1:${evilPort}/evil?next=1` });
    res.end();
  });
  await new Promise((resolve) => target.listen(0, '127.0.0.1', resolve));
  t.after(() => target.close());
  process.env.ODOO_BROKER_URL = `http://127.0.0.1:${target.address().port}`;
  process.env.ODOO_BROKER_TOKEN = 'redirect-probe-token';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-redir', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'redirect must surface isError, not follow');
    assert.strictEqual(evilSeen.length, 0, 'evil server must never be hit with the token');
  } finally {
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('malformed broker URL fails closed before fetch', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    calls += 1;
    return streamedEnvelope({ success: true, result: {} });
  };
  process.env.ODOO_BROKER_URL = '::::not a url::::';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-badurl', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'unparseable broker URL must be isError');
    assert.ok(res.content[0].text.includes('loopback'), `got ${res.content[0].text}`);
    assert.strictEqual(calls, 0, 'unparseable URL must never reach fetch');
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('userinfo-smuggled loopback refused before fetch', async () => {
  // http://127.0.0.1@evil.example/ has a loopback-looking userinfo but a
  // non-loopback host: the joined base+path URL must fail the gate.
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    calls += 1;
    return streamedEnvelope({ success: true, result: {} });
  };
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1@evil.example/';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-userinfo', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'userinfo-smuggled URL must be isError');
    assert.ok(res.content[0].text.includes('loopback'), `got ${res.content[0].text}`);
    assert.strictEqual(calls, 0, 'smuggled host must never reach fetch');
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('strict raw gate accepts canonical loopback, rejects evasions', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = async () => {
    calls += 1;
    return streamedEnvelope({ success: true, result: { rows: [] } });
  };
  process.env.ODOO_BROKER_TOKEN = 'tok';
  const good = ['http://127.0.0.1:8471', 'http://localhost:8471', 'http://[::1]:8471'];
  const bad = [
    'http://0x7f.0.0.1/', 'http://2130706433/', 'http://user@127.0.0.1/',
    'http://127.0.0.1/x', 'http://127.0.0.1?q=1', 'http://127.0.0.1#x',
    'http://127.evil.com/',
  ];
  try {
    const search = byName('odoo.search');
    for (const u of good) {
      calls = 0;
      process.env.ODOO_BROKER_URL = u;
      const res = await search.execute('id-good', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
      assert.strictEqual(res.isError, undefined, `${u} must route (got ${res.content[0].text})`);
      assert.strictEqual(calls, 1, `${u} must reach fetch exactly once`);
    }
    for (const u of bad) {
      calls = 0;
      process.env.ODOO_BROKER_URL = u;
      const res = await search.execute('id-bad', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
      assert.strictEqual(res.isError, true, `${u} must be isError`);
      assert.ok(res.content[0].text.includes('loopback'), `${u} got ${res.content[0].text}`);
      assert.strictEqual(calls, 0, `${u} must never reach fetch`);
    }
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('non-streaming body fails closed without unbounded allocation', async () => {
  const realFetch = global.fetch;
  global.fetch = async () => ({ json: async () => ({ success: true, result: {} }) });
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-nostream', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'non-streaming body must fail closed');
    assert.ok(res.content[0].text.includes('non-JSON'), `got ${res.content[0].text}`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('over-cap body denied whole with no bytes echoed', async () => {
  const realFetch = global.fetch;
  const sentinel = `SENTINEL-${'z'.repeat(64)}`;
  const head = Buffer.from(`{"success":true,"result":"${sentinel}`);
  const big = Buffer.alloc(TEST_CAP, 0x20);
  const tail = Buffer.from('"}');
  let cancelled = false;
  global.fetch = async () => streamedResponse([head, big, tail], () => { cancelled = true; });
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-cap', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'over-cap body must be isError');
    assert.ok(res.content[0].text.includes('exceeded'), `got ${res.content[0].text}`);
    assert.ok(!res.content[0].text.includes(sentinel), 'no body bytes may be echoed on overflow');
    assert.strictEqual(cancelled, true, 'overflow must cancel the stream');
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('valid prefix padded to cap+1 with whitespace still denied', async () => {
  // A fully valid envelope plus trailing whitespace is still one byte too
  // many: the denial is on total bytes, not on parseability of a prefix.
  const realFetch = global.fetch;
  const prefix = Buffer.from('{"success":true,"result":{}}');
  const pad = Buffer.alloc(TEST_CAP - prefix.length + 1, 0x20);
  global.fetch = async () => streamedResponse([prefix, pad], () => {});
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  try {
    const search = byName('odoo.search');
    const res = await search.execute('id-capws', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    assert.strictEqual(res.isError, true, 'cap+1 body must be isError even with a valid prefix');
    assert.ok(res.content[0].text.includes('exceeded'), `got ${res.content[0].text}`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('default timeout fires without caller signal', async () => {
  const realFetch = global.fetch;
  global.fetch = (url, opts) => new Promise((resolve, reject) => {
    const sig = opts && opts.signal;
    if (sig) {
      sig.addEventListener('abort', () => {
        const e = new Error('The operation was aborted.');
        e.name = 'AbortError';
        reject(e);
      }, { once: true });
    }
  });
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  process.env.ODOO_BROKER_TIMEOUT_MS = '25';
  try {
    const search = byName('odoo.search');
    const t0 = Date.now();
    const res = await search.execute('id-timeout', { model: 'res.partner', fields: ['name'] }, undefined, {}, undefined);
    const dt = Date.now() - t0;
    assert.strictEqual(res.isError, true, 'hung broker must time out to isError');
    assert.ok(res.content[0].text.includes('timed out'), `got ${res.content[0].text}`);
    assert.ok(dt < 1000, `timeout must fire fast, took ${dt}ms`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
    delete process.env.ODOO_BROKER_TIMEOUT_MS;
  }
});

test('caller abort still aborts mid-flight', async () => {
  const realFetch = global.fetch;
  let calls = 0;
  global.fetch = (url, opts) => {
    calls += 1;
    return new Promise((resolve, reject) => {
      opts.signal.addEventListener('abort', () => {
        const e = new Error('The operation was aborted.');
        e.name = 'AbortError';
        reject(e);
      }, { once: true });
    });
  };
  process.env.ODOO_BROKER_URL = 'http://127.0.0.1:9';
  process.env.ODOO_BROKER_TOKEN = 'tok';
  process.env.ODOO_BROKER_TIMEOUT_MS = '500';
  try {
    const search = byName('odoo.search');
    const ctrl = new AbortController();
    const p = search.execute('id-abort', { model: 'res.partner', fields: ['name'] }, undefined, {}, ctrl.signal);
    await new Promise((r) => setImmediate(r));
    ctrl.abort();
    const res = await p;
    assert.strictEqual(res.isError, true, 'caller abort must surface isError');
    assert.ok(res.content[0].text.includes('aborted'), `got ${res.content[0].text}`);
    assert.strictEqual(calls, 1, 'abort must combine with the in-flight request, not bypass it');
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_URL;
    delete process.env.ODOO_BROKER_TOKEN;
    delete process.env.ODOO_BROKER_TIMEOUT_MS;
  }
});
