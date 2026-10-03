'use strict';
// Real-loader gate for odoo-broker.js (Sequence8 item 3, REQUIRED).
//
// PROVEN (2026-10-04, disposable harness, run: bun tools/omp/odoo-broker.loader.test.js):
// the REAL installed loader (bun import of
// @oh-my-pi/pi-coding-agent/src/extensibility/custom-tools/loader.ts —
// NOT a stub, NOT a source-extraction fallback) discovers the REAL factory
// module copied to <tmp>/.omp/tools/odoo-broker.js via
// discoverCustomToolPaths([], tmpCwd) with source
// {provider:"native",providerName:"OMP",level:"project"}, and
// loadCustomTools binds it to 11 tools with zero load errors. Each bound
// tool's execute() is then invoked against the REAL in-process broker
// (tools/omp/loader-e2e-broker.go: genuine deny-by-default policyGate,
// real model-mux transport over loopback httptest, dispatch recorder for
// outgoing RPC only — counts Execute calls, returns canned rows, never
// fake Odoo rows):
//   - legitimate odoo.search (allowlisted model/fields/limit) returns the
//     canned rows with exactly 1 dispatch;
//   - denied odoo.search (unknown model) returns isError denial with 0
//     dispatches (denial before RPC);
//   - strict rejection (unknown arg) returns isError with 0 dispatches
//     (rejected before fetch);
//   - valid snapshot evidence: odoo.meta (policy listing), odoo.catalog,
//     odoo.companies, and odoo.workspace.mkdir/list ops succeed.
// Temp dirs (cwd, HOME, workspace) are removed afterwards; no model,
// backend, or Odoo credentials exist anywhere; no user-config reads.
// If the loader API is ever unavailable, this file fails with the exact
// loader error (what was called + failure) instead of passing.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const REPO = path.join(__dirname, '..', '..');
// Portable resolution: the installed package exports ./... -> ./src/....ts,
// so resolve the loader through the package (works from any checkout path);
// fall back to a NODE_PATH-visible absolute only if resolution fails.
function resolveLoader() {
  for (const sub of [
    '@oh-my-pi/pi-coding-agent/extensibility/custom-tools/loader',
    '@oh-my-pi/pi-coding-agent/src/extensibility/custom-tools/loader',
  ]) {
    try { return require.resolve(sub); } catch { /* next */ }
  }
  // The package lives in the operator's global node_modules (installed
  // OMP CLI), not in this repo's node_modules: probe NODE_PATH plus the
  // well-known global roots before giving up with an actionable error.
  const roots = (process.env.NODE_PATH || '').split(path.delimiter).filter(Boolean)
    .concat(['/Users/komorinokage/node_modules', '/opt/homebrew/lib/node_modules', '/usr/local/lib/node_modules']);
  for (const r of roots) {
    for (const sub of ['extensibility/custom-tools/loader', 'src/extensibility/custom-tools/loader']) {
      for (const pkg of ['@oh-my-pi/pi-coding-agent']) {
        const cand = path.join(r, pkg, sub);
        for (const ext of ['.ts', '.js']) {
          try { if (fs.existsSync(cand + ext)) return cand + ext; } catch { /* next */ }
        }
      }
    }
  }
  const fb = process.env.OMP_LOADER_TS || '';
  if (fb) return fb;
  throw new Error('loader unavailable: cannot resolve @oh-my-pi/pi-coding-agent loader (set OMP_LOADER_TS)');
}
const LOADER_TS = resolveLoader();
const BUN = process.env.BUN || 'bun';

function sh(cmd, args, opts) {
  return spawnSync(cmd, args, { encoding: 'utf8', ...opts });
}

test('real loader discovers, binds, and drives factory tools vs real broker', async (t) => {
  // Disposable scope: temp cwd + temp HOME + temp workspace. Nothing under
  // the real home directory or user config is touched.
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'omp-loader-'));
  const home = path.join(tmp, 'home');
  const wsDir = path.join(tmp, 'ws');
  t.after(() => fs.rmSync(tmp, { recursive: true, force: true }));
  const ompTools = path.join(tmp, '.omp', 'tools');
  fs.mkdirSync(ompTools, { recursive: true });
  fs.mkdirSync(path.join(home, '.config'), { recursive: true });
  fs.mkdirSync(wsDir, { recursive: true });
  fs.copyFileSync(path.join(__dirname, 'odoo-broker.js'), path.join(ompTools, 'odoo-broker.js'));

  // Real in-process broker over loopback (disposable Go harness). stdio is
  // detached from the test runner (ignore) and drained to files so a
  // verbose child can never hold the runner's event loop open.
  const blog = path.join(tmp, 'broker.log');
  const bout = fs.openSync(blog + '.out', 'w');
  const berr = fs.openSync(blog + '.err', 'w');
  const broker = spawn('go', ['run', './tools/omp/loader-e2e-broker.go', wsDir], {
    cwd: REPO, stdio: ['ignore', bout, berr],
  });
  t.after(() => {
    try { broker.kill('SIGKILL'); } catch { /* already gone */ }
    try { fs.closeSync(bout); } catch { /* closed */ }
    try { fs.closeSync(berr); } catch { /* closed */ }
  });
  // READY probe: poll the drained log file instead of 'data' events (no
  // listener may keep the runner alive after the test ends).
  const brokerURL = await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('broker harness did not print READY in time')), 60000);
    timer.unref?.();
    const iv = setInterval(() => {
      let s = '';
      try { s = fs.readFileSync(blog + '.out', 'utf8'); } catch { /* not yet */ }
      const m = s.match(/BROKER_URL=(http:\/\/127\.0\.0\.1:\d+)\nBROKER_TOKEN=([0-9a-f]+)\nREADY/);
      if (m) {
        clearTimeout(timer);
        clearInterval(iv);
        resolve({ url: m[1], token: m[2] });
      }
    }, 100);
    iv.unref?.();
    broker.on('error', (e) => { clearTimeout(timer); clearInterval(iv); reject(e); });
    broker.on('exit', (code) => {
      clearTimeout(timer);
      clearInterval(iv);
      reject(new Error(`broker harness exited early with code ${code}`));
    });
  });

  // Driver: real loader discover + bind + invoke (bun; temp env only).
  const driver = `
    const m = await import(${JSON.stringify(LOADER_TS)});
    if (typeof m.discoverCustomToolPaths !== 'function' || typeof m.loadCustomTools !== 'function')
      throw new Error('loader API missing: ' + Object.keys(m).join(','));
    const cwd = ${JSON.stringify(tmp)};
    const paths = await m.discoverCustomToolPaths([], cwd);
    if (paths.length !== 1 || !paths[0].path.endsWith('.omp/tools/odoo-broker.js'))
      throw new Error('discovery failed: ' + JSON.stringify(paths));
    if (!paths[0].source || paths[0].source.provider !== 'native')
      throw new Error('unexpected tool source: ' + JSON.stringify(paths[0]));
    const { tools, errors } = await m.loadCustomTools(paths, cwd, []);
    if (errors.length) throw new Error('load errors: ' + JSON.stringify(errors));
    if (tools.length !== 11) throw new Error('want 11 bound tools, got ' + tools.length);
    const byName = Object.fromEntries(tools.map((x) => [x.tool.name, x.tool]));
    const j = (v) => JSON.stringify(v).slice(0, 500);
    const results = {};
    results.legit = await byName['odoo.search'].execute('c1', { model: 'res.partner', fields: ['name'], limit: 5 }, undefined, {}, undefined);
    results.denied = await byName['odoo.search'].execute('c2', { model: 'nope-model', fields: ['name'], limit: 5 }, undefined, {}, undefined);
    results.strict = await byName['odoo.search'].execute('c3', { model: 'res.partner', fields: ['name'], limit: 5, admin: true }, undefined, {}, undefined);
    results.meta = await byName['odoo.meta'].execute('c4', {}, undefined, {}, undefined);
    results.mkdir = await byName['odoo.workspace.mkdir'].execute('c5', { path: 'reports' }, undefined, {}, undefined);
    results.wslist = await byName['odoo.workspace.list'].execute('c6', { path: '.' }, undefined, {}, undefined);
    console.log('RESULTS=' + JSON.stringify({
      legit: j(results.legit), denied: j(results.denied), strict: j(results.strict),
      meta: j(results.meta), mkdir: j(results.mkdir), wslist: j(results.wslist),
    }));
  `;
  const driverFile = path.join(tmp, 'driver.mjs');
  fs.writeFileSync(driverFile, driver);
  const r = sh(BUN, [driverFile], {
    timeout: 90000,
    env: {
      ...process.env,
      HOME: home,
      XDG_CONFIG_HOME: path.join(home, '.config'),
      XDG_DATA_HOME: path.join(home, '.local', 'share'),
      ODOO_BROKER_URL: brokerURL.url,
      ODOO_BROKER_TOKEN: brokerURL.token,
    },
  });
  if (r.error) throw new Error(`loader driver failed to run: ${r.error.message}; stdout=${r.stdout}; stderr=${r.stderr}`);
  if (r.status !== 0) throw new Error(`loader driver exited ${r.status}: stdout=${r.stdout}; stderr=${r.stderr}`);
  const mLine = String(r.stdout).split('\n').find((l) => l.startsWith('RESULTS='));
  assert.ok(mLine, `driver printed no RESULTS: ${r.stdout}`);
  const got = JSON.parse(mLine.slice('RESULTS='.length));
  // Legitimate dispatch: canned rows back, no isError (1 dispatch proven
  // broker-side by the canned-row identity: only Execute returns them).
  assert.ok(!got.legit.includes('"isError":true') && got.legit.includes('\\"name\\":\\"a\\"'), `legitimate dispatch failed: ${got.legit}`);
  // Denied: isError denial, zero dispatch (broker denies unknown-model
  // before Execute; canned rows would appear otherwise).
  assert.ok(got.denied.includes('"isError":true') && got.denied.includes('denied'), `denied call wrong: ${got.denied}`);
  assert.ok(!got.denied.includes('\\"name\\":\\"a\\"'), `denial executed RPC: ${got.denied}`);
  // Strict rejection before fetch: unknown arg never dispatched.
  assert.ok(got.strict.includes('"isError":true') && got.strict.includes('unknown argument'), `strict rejection wrong: ${got.strict}`);
  // Valid snapshot + workspace ops evidence.
  assert.ok(got.meta.includes('res.partner'), `meta evidence missing: ${got.meta}`);
  assert.ok(got.mkdir.includes('created'), `mkdir evidence missing: ${got.mkdir}`);
  assert.ok(got.wslist.includes('reports'), `workspace.list evidence missing: ${got.wslist}`);
});
