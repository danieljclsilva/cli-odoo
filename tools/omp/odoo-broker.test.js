'use strict';
// Factory-shape test for odoo-broker.js: no broker, no OMP harness, no
// network. The factory is invoked with a stub pi api (the real loader
// passes CustomToolAPI: cwd/exec/ui/logger/typebox/...); these tools use
// none of it, but the call proves the factory binds without the host.
// Run: node --test tools/omp/odoo-broker.test.js
//
// HTTP is stubbed per-test: legitimate routing and denial surfacing are
// proven against a fake fetch, so no model/backend/Odoo credentials exist
// anywhere in this file.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const factory = require('./odoo-broker.js');
const src = fs.readFileSync(path.join(__dirname, 'odoo-broker.js'), 'utf8');

function stubPi() {
  return { cwd: '/tmp', exec: async () => { throw new Error('must not exec'); } };
}

function toolsOf() {
  const out = factory(stubPi());
  return Array.isArray(out) ? out : [out];
}

test('factory returns eleven typed tools with execute + JSON-schema parameters', () => {
  assert.strictEqual(typeof factory, 'function', 'module must export the factory function');
  const tools = toolsOf();
  const names = tools.map((t) => t.name).sort();
  assert.deepStrictEqual(names, [
    'odoo.aggregate',
    'odoo.catalog',
    'odoo.companies',
    'odoo.count',
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
});

test('legitimate call routes to the broker path', async () => {
  const seen = [];
  const realFetch = global.fetch;
  global.fetch = async (url, opts) => {
    seen.push({ url: String(url), opts });
    return { json: async () => ({ success: true, result: { rows: [] } }) };
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
    const text = res.content[0].text;
    assert.ok(text.includes('rows'), `result text must carry the broker result, got ${text}`);
  } finally {
    global.fetch = realFetch;
    delete process.env.ODOO_BROKER_TOKEN;
  }
});

test('denied call surfaces isError without throwing', async () => {
  const realFetch = global.fetch;
  global.fetch = async () => ({ json: async () => ({ success: false, error: 'denied: unknown-model' }) });
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
    return { json: async () => ({ success: true, result: { path: 'reports', written: true } }) };
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
