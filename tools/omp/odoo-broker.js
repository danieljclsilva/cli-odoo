// OMP custom tools for the cli-odoo Odoo broker.
//
// Tested-against contract: OMP v18.2.6 custom-tool loading (CommonJS module
// exporting `tools`, each tool carrying {name, description, inputSchema,
// run}). Honest note: no local OMP harness was available in this
// environment, so end-to-end OMP loading is operator-verified — run
// `agent omp-init --dir <dir>` and point OMP at the generated snippet, then
// confirm the tools list inside OMP before trusting them.
//
// Runtime: each run() POSTs JSON to the broker model listener
// (ODOO_BROKER_URL, default http://127.0.0.1:8471) with the session token
// from ODOO_BROKER_TOKEN as an Authorization: Bearer header. No
// child_process, no shell fallback, no secrets written to disk. The token
// is never logged.
//
// Typed broker ops only: odoo.search/read/count/aggregate/meta/companies/
// catalog/workspace.list/read/write. No grant/revoke/admin/raw tools.
'use strict';

const { URL } = require('url');

const BROKER_URL = (process.env.ODOO_BROKER_URL || 'http://127.0.0.1:8471').replace(/\/+$/, '');

function token() {
  const t = (process.env.ODOO_BROKER_TOKEN || '').trim();
  if (!t) throw new Error('ODOO_BROKER_TOKEN is not set');
  return t;
}

async function postJSON(path, body) {
  const res = await fetch(BROKER_URL + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token() },
    body: JSON.stringify(body || {}),
  });
  const env = await res.json().catch(() => null);
  if (!env) throw new Error('broker returned non-JSON at ' + path);
  if (!env.success) throw new Error(env.error || ('broker denied ' + path));
  return env.result;
}

async function getJSON(path) {
  const url = new URL(BROKER_URL + path);
  const res = await fetch(url, {
    method: 'GET',
    headers: { Authorization: 'Bearer ' + token() },
  });
  const env = await res.json().catch(() => null);
  if (!env) throw new Error('broker returned non-JSON at ' + path);
  if (!env.success) throw new Error(env.error || ('broker denied ' + path));
  return env.result;
}

function str(desc) { return { type: 'string', description: desc }; }

const tools = [
  {
    name: 'odoo.search',
    description: 'Scoped search_read over an allowlisted Odoo model.',
    inputSchema: {
      type: 'object',
      properties: {
        model: str('Exact Odoo technical name, e.g. res.partner.'),
        domain: { description: 'Odoo domain array.' },
        fields: { type: 'array', items: { type: 'string' }, description: 'Exact allowlisted field names (non-empty).' },
        order: str('Order clause, e.g. "name asc".'),
        limit: { type: 'integer', description: 'Row limit (policy-capped).' },
        offset: { type: 'integer', description: 'Row offset (policy-capped).' },
      },
      required: ['model', 'fields'],
    },
    run: async (args) => postJSON('/rpc/search', args),
  },
  {
    name: 'odoo.read',
    description: 'Scoped by-id read (broker converts to search_read).',
    inputSchema: {
      type: 'object',
      properties: {
        model: str('Exact Odoo technical name.'),
        ids: { type: 'array', items: { type: 'integer' } },
        fields: { type: 'array', items: { type: 'string' } },
      },
      required: ['model', 'ids', 'fields'],
    },
    run: async (args) => postJSON('/rpc/read', args),
  },
  {
    name: 'odoo.count',
    description: 'Scoped record count.',
    inputSchema: {
      type: 'object',
      properties: {
        model: str('Exact Odoo technical name.'),
        domain: { description: 'Odoo domain array.' },
      },
      required: ['model'],
    },
    run: async (args) => postJSON('/rpc/count', args),
  },
  {
    name: 'odoo.aggregate',
    description: 'Scoped read_group aggregation.',
    inputSchema: {
      type: 'object',
      properties: {
        model: str('Exact Odoo technical name.'),
        domain: { description: 'Odoo domain array.' },
        groupby: { type: 'array', items: { type: 'string' } },
        sum: { type: 'array', items: { type: 'string' } },
        avg: { type: 'array', items: { type: 'string' } },
        count: { type: 'boolean' },
        limit: { type: 'integer' },
      },
      required: ['model', 'groupby'],
    },
    run: async (args) => postJSON('/rpc/aggregate', args),
  },
  {
    name: 'odoo.meta',
    description: 'Sealed allowlist metadata (no record data). Optional model query.',
    inputSchema: {
      type: 'object',
      properties: { model: str('Optional exact model name.') },
    },
    run: async (args) => {
      const q = args && args.model ? '?model=' + encodeURIComponent(args.model) : '';
      return getJSON('/rpc/meta' + q);
    },
  },
  {
    name: 'odoo.companies',
    description: 'Company discovery: available/enabled/default (no record data).',
    inputSchema: { type: 'object', properties: {} },
    run: async () => getJSON('/rpc/companies'),
  },
  {
    name: 'odoo.catalog',
    description: 'Per-model catalog with executable flags (no record data).',
    inputSchema: { type: 'object', properties: {} },
    run: async () => getJSON('/rpc/catalog'),
  },
  {
    name: 'odoo.workspace.list',
    description: 'List broker-confined workspace entries.',
    inputSchema: {
      type: 'object',
      properties: {
        path: str('Workspace-relative directory.'),
        max_entries: { type: 'integer', description: 'Entry cap (policy narrows, never widens).' },
      },
      required: ['path'],
    },
    run: async (args) => postJSON('/rpc/workspace/list', args),
  },
  {
    name: 'odoo.workspace.read',
    description: 'Read one broker-confined workspace file.',
    inputSchema: {
      type: 'object',
      properties: { path: str('Workspace-relative file.') },
      required: ['path'],
    },
    run: async (args) => postJSON('/rpc/workspace/read', args),
  },
  {
    name: 'odoo.workspace.write',
    description: 'Write one broker-confined workspace file.',
    inputSchema: {
      type: 'object',
      properties: {
        path: str('Workspace-relative file.'),
        content: str('File content.'),
      },
      required: ['path', 'content'],
    },
    run: async (args) => postJSON('/rpc/workspace/write', args),
  },
];

module.exports = { tools };
