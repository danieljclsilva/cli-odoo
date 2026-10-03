// OMP custom tools for the cli-odoo Odoo broker.
//
// REAL installed contract (read 2026-10-04 at
// /Users/komorinokage/node_modules/@oh-my-pi/pi-coding-agent/dist/types/extensibility/custom-tools/types.d.ts
// plus loader.d.ts):
//
//   export type CustomToolFactory =
//     (pi: CustomToolAPI) => CustomTool | CustomTool[] | Promise<...>
//
//   interface CustomTool {
//     name: string; label: string; description: string;
//     parameters: TParams;              // TSchema = arktype Type | plain JSON Schema
//     execute(toolCallId, params, onUpdate, ctx, signal?):
//       Promise<AgentToolResult>;       // { content: [{type:"text",text}], isError? }
//   }
//
// This module exports the FACTORY directly (module.exports = factory), for
// tools the loader discovers at `.omp/tools/` (+ plugin/configured paths;
// see discoverCustomToolPaths in loader.d.ts). Copy this file to
// `.omp/tools/odoo-broker.js`; do NOT wrap it in `{ tools }` — the old
// prose-only shape this file used to claim. Plain JSON-Schema `parameters`
// objects are accepted (TJsonSchema = Record<string, unknown>, "legacy
// TypeBox emits this shape"), so no TypeBox/arktype import is needed.
//
// MCP note: OMP ships MCP *client* types under dist/types/mcp/ (config,
// transports, exa/mcp-client) for consuming remote MCP servers. This
// module does NOT build an MCP client: the broker speaks plain typed
// JSON-RPC POST, and these tools call it directly over fetch. Wiring OMP
// to the Go MCP stdio adapter (`agent mcp`) instead would need an
// OMP-side MCP transport that this version does not document for custom
// tools, so direct broker POST is the honest, reviewable path.
//
// Runtime: each execute() POSTs/GETs JSON to the broker model listener
// (ODOO_BROKER_URL, default http://127.0.0.1:8471) with the session token
// from ODOO_BROKER_TOKEN as an Authorization: Bearer header. The token is
// read at EXECUTE time, never at load time; it is never logged and never
// written to disk. No child_process, no shell fallback, no secrets in
// output.
//
// Typed broker ops only: odoo.search/read/count/aggregate/meta/companies/
// catalog/workspace.list/read/write/mkdir. No grant/revoke/admin/raw tools.
// Denials surface as { isError: true } results (broker envelope
// success:false), never as thrown protocol errors, so the model sees the
// denial text and no stack leaks.
'use strict';

const { URL } = require('url');

function brokerURL() {
  return (process.env.ODOO_BROKER_URL || 'http://127.0.0.1:8471').replace(/\/+$/, '');
}

function token() {
  const t = (process.env.ODOO_BROKER_TOKEN || '').trim();
  if (!t) throw new Error('ODOO_BROKER_TOKEN is not set');
  return t;
}

function ok(text) {
  return { content: [{ type: 'text', text: String(text) }] };
}

function err(text) {
  return { content: [{ type: 'text', text: String(text) }], isError: true };
}

async function postJSON(path, body, signal) {
  let res;
  try {
    res = await fetch(brokerURL() + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + token() },
      body: JSON.stringify(body || {}),
      signal,
    });
  } catch (e) {
    if (e && e.name === 'AbortError') return err('broker request aborted at ' + path);
    return err('broker unreachable at ' + path);
  }
  const env = await res.json().catch(() => null);
  if (!env) return err('broker returned non-JSON at ' + path);
  if (!env.success) return err(env.error || ('broker denied ' + path));
  return ok(JSON.stringify(env.result));
}

async function getJSON(path, signal) {
  const url = new URL(brokerURL() + path);
  let res;
  try {
    res = await fetch(url, {
      method: 'GET',
      headers: { Authorization: 'Bearer ' + token() },
      signal,
    });
  } catch (e) {
    if (e && e.name === 'AbortError') return err('broker request aborted at ' + path);
    return err('broker unreachable at ' + path);
  }
  const env = await res.json().catch(() => null);
  if (!env) return err('broker returned non-JSON at ' + path);
  if (!env.success) return err(env.error || ('broker denied ' + path));
  return ok(JSON.stringify(env.result));
}

function str(desc) { return { type: 'string', description: desc }; }

// execute(toolCallId, params, onUpdate, ctx, signal) per the installed
// CustomTool.execute signature. Broker denials already arrive as isError
// results from postJSON/getJSON, so execute returns them directly; only a
// missing token throws (operator misconfiguration, not a broker denial).
function exec(path, getArgs) {
  return async (_toolCallId, params, _onUpdate, _ctx, signal) => postJSON(path, getArgs(params), signal);
}

function buildTools() {
  return [
    {
      name: 'odoo.search',
      label: 'Odoo search',
      description: 'Scoped search_read over an allowlisted Odoo model.',
      parameters: {
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
      execute: exec('/rpc/search', (p) => p),
    },
    {
      name: 'odoo.read',
      label: 'Odoo read',
      description: 'Scoped by-id read (broker converts to search_read).',
      parameters: {
        type: 'object',
        properties: {
          model: str('Exact Odoo technical name.'),
          ids: { type: 'array', items: { type: 'integer' } },
          fields: { type: 'array', items: { type: 'string' } },
        },
        required: ['model', 'ids', 'fields'],
      },
      execute: exec('/rpc/read', (p) => p),
    },
    {
      name: 'odoo.count',
      label: 'Odoo count',
      description: 'Scoped record count.',
      parameters: {
        type: 'object',
        properties: {
          model: str('Exact Odoo technical name.'),
          domain: { description: 'Odoo domain array.' },
        },
        required: ['model'],
      },
      execute: exec('/rpc/count', (p) => p),
    },
    {
      name: 'odoo.aggregate',
      label: 'Odoo aggregate',
      description: 'Scoped read_group aggregation.',
      parameters: {
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
      execute: exec('/rpc/aggregate', (p) => p),
    },
    {
      name: 'odoo.meta',
      label: 'Odoo metadata',
      description: 'Sealed allowlist metadata (no record data). Optional model query.',
      parameters: {
        type: 'object',
        properties: { model: str('Optional exact model name.') },
      },
      execute: async (_id, params, _u, _c, signal) => {
        const q = params && params.model ? '?model=' + encodeURIComponent(params.model) : '';
        return getJSON('/rpc/meta' + q, signal);
      },
    },
    {
      name: 'odoo.companies',
      label: 'Odoo companies',
      description: 'Company discovery: available/enabled/default (no record data).',
      parameters: { type: 'object', properties: {} },
      execute: async (_id, _p, _u, _c, signal) => getJSON('/rpc/companies', signal),
    },
    {
      name: 'odoo.catalog',
      label: 'Odoo catalog',
      description: 'Per-model catalog with MethodManifest and provenance (read-only pass-through, no record data).',
      parameters: { type: 'object', properties: {} },
      execute: async (_id, _p, _u, _c, signal) => getJSON('/rpc/catalog', signal),
    },
    {
      name: 'odoo.workspace.list',
      label: 'Workspace list',
      description: 'List broker-confined workspace entries.',
      parameters: {
        type: 'object',
        properties: {
          path: str('Workspace-relative directory.'),
          max_entries: { type: 'integer', description: 'Entry cap (policy narrows, never widens).' },
        },
        required: ['path'],
      },
      execute: exec('/rpc/workspace/list', (p) => p),
    },
    {
      name: 'odoo.workspace.read',
      label: 'Workspace read',
      description: 'Read one broker-confined workspace file.',
      parameters: {
        type: 'object',
        properties: { path: str('Workspace-relative file.') },
        required: ['path'],
      },
      execute: exec('/rpc/workspace/read', (p) => p),
    },
    {
      name: 'odoo.workspace.write',
      label: 'Workspace write',
      description: 'Write one broker-confined workspace file.',
      parameters: {
        type: 'object',
        properties: {
          path: str('Workspace-relative file.'),
          content: str('File content.'),
        },
        required: ['path', 'content'],
      },
      execute: exec('/rpc/workspace/write', (p) => p),
    },
    {
      name: 'odoo.workspace.mkdir',
      label: 'Workspace mkdir',
      description: 'Create broker-confined workspace directories (bounded MkdirAll).',
      parameters: {
        type: 'object',
        properties: { path: str('Workspace-relative directory.') },
        required: ['path'],
      },
      execute: exec('/rpc/workspace/mkdir', (p) => p),
    },
  ];
}

// The loader calls the factory with its session-scoped CustomToolAPI and
// binds the returned tools. The pi arg is intentionally unused here: these
// tools need no exec/UI/logger — they only POST to the broker — but the
// parameter is kept so the shape matches CustomToolFactory exactly.
module.exports = function odooBrokerTools(_pi) {
  return buildTools();
};
