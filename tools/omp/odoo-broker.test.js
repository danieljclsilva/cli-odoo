'use strict';
// Shape-only test for odoo-broker.js: no broker, no OMP harness, no network.
// Run: node --test tools/omp/odoo-broker.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const mod = require('./odoo-broker.js');
const src = fs.readFileSync(path.join(__dirname, 'odoo-broker.js'), 'utf8');

test('exports ten typed tools, no admin/raw/shell', () => {
  assert.ok(Array.isArray(mod.tools), 'tools must be an array');
  const names = mod.tools.map((t) => t.name).sort();
  assert.deepStrictEqual(names, [
    'odoo.aggregate',
    'odoo.catalog',
    'odoo.companies',
    'odoo.count',
    'odoo.meta',
    'odoo.read',
    'odoo.search',
    'odoo.workspace.list',
    'odoo.workspace.read',
    'odoo.workspace.write',
  ]);
  for (const t of mod.tools) {
    assert.ok(t.description, `${t.name} needs a description`);
    assert.ok(t.inputSchema && t.inputSchema.type === 'object', `${t.name} needs an object inputSchema`);
    assert.strictEqual(typeof t.run, 'function', `${t.name} needs a run function`);
  }
});

test('no shell fallback, token via env only', () => {
  // Strip line comments so prose mentioning shell concepts is not mistaken
  // for code that shells out.
  const code = src.replace(/^[ \t]*\/\/.*$/gm, '');
  assert.ok(!code.includes('child_process'), 'must not shell out');
  assert.ok(!code.includes('execSync'), 'must not shell out');
  assert.ok(!code.includes('spawnSync'), 'must not shell out');
  assert.ok(!code.includes('execFile'), 'must not shell out');
  assert.ok(src.includes('ODOO_BROKER_TOKEN'), 'token must come from env');
});
