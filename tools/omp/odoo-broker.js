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
// Loader evidence (proven 2026-10-04 with a disposable harness: temp cwd +
// .omp/tools copy, real installed loader via bun, temp HOME, no user config,
// no model/backend/Odoo credentials): the installed
// discoverCustomToolPaths([], tmpCwd) discovers
// <tmpCwd>/.omp/tools/odoo-broker.js with source
// {provider:"native",providerName:"OMP",level:"project"}, and loadCustomTools
// binds this factory to 12 tools (see tools/omp/odoo-broker.loader.test.js).
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
// output. Redirects are never followed (redirect:'error'): a 3xx from the
// broker surfaces a tool error instead of moving the Bearer token.
// Broker base URLs pass a strict raw gate BEFORE WHATWG parsing: http(s)
// scheme, no userinfo, root-only (no basepath/query/fragment), canonical
// loopback literal (127.x dotted-quad, localhost, ::1); the joined
// base+path origin is re-gated BEFORE fetch, failing closed.
// Responses stream through the ONE bounded reader: at most
// MAX_BODY_BYTES+1 bytes (exactly 4 MiB cap) BEFORE JSON decode; overflow
// is denied whole with no body bytes echoed; non-streaming bodies fail
// closed and never allocate unbounded.
// Every request races a DEFAULT_TIMEOUT_MS (exactly 30s) AbortController
// bound combined with the caller signal (headers AND body covered);
// streams cancel and timers/listeners clear on every path.
// Error text is token-redacted before it reaches the model.
//
// Typed broker ops only: odoo.search/read/count/aggregate/meta/companies/
// catalog/workspace.list/read/write/mkdir. No grant/revoke/admin/raw tools.
// Denials surface as { isError: true } results (broker envelope
// success:false), never as thrown protocol errors, so the model sees the
// denial text and no stack leaks.
'use strict';

const { URL } = require('url');
const net = require('net');

function brokerURL() {
  const raw = (process.env.ODOO_BROKER_URL || 'http://127.0.0.1:8471').trim().replace(/\/+$/, '');
  if (!isLoopbackURL(raw)) throw new Error('ODOO_BROKER_URL must be a loopback http(s) URL');
  return raw;
}

// isLoopbackURL: strict loopback-only gate for the bearer-token endpoint.
// Validates the RAW string BEFORE WHATWG normalization: trim; require an
// http(s) scheme; split authority at the first '/' '?' '#'; authority must
// carry no userinfo ('@') and no query/fragment; the path after authority
// must be empty or '/' (root-only base, no basepath). The host (port and
// IPv6 brackets stripped) must be a canonical literal: exact 'localhost',
// a dotted-quad with first octet 127, or '::1' (plus its full form
// 0:0:0:0:0:0:0:1) lowercased. Only then is new URL() + net.isIP used as
// defense in depth. Subdomains, numeric shorthand, hex, IPv4-mapped IPv6,
// userinfo, basepaths, and query/fragment all fail closed.
function isLoopbackURL(raw) {
  if (typeof raw !== 'string') return false;
  const s = raw.trim();
  const lower = s.toLowerCase();
  if (!lower.startsWith('http://') && !lower.startsWith('https://')) return false;
  const schemeEnd = s.indexOf('://');
  if (schemeEnd === -1) return false;
  const afterScheme = s.slice(schemeEnd + 3);
  let end = afterScheme.length;
  for (let i = 0; i < afterScheme.length; i += 1) {
    const c = afterScheme[i];
    if (c === '/' || c === '?' || c === '#') { end = i; break; }
  }
  const authority = afterScheme.slice(0, end);
  const rest = afterScheme.slice(end);
  if (!authority) return false;
  if (authority.includes('@') || authority.includes('?') || authority.includes('#')) return false;
  if (rest !== '' && rest !== '/') return false;
  let host;
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    if (close === -1) return false;
    host = authority.slice(1, close);
    const tail = authority.slice(close + 1);
    if (tail !== '' && !/^:\d*$/.test(tail)) return false;
  } else {
    const colon = authority.indexOf(':');
    if (colon === -1) {
      host = authority;
    } else {
      if (authority.indexOf(':', colon + 1) !== -1) return false;
      host = authority.slice(0, colon);
      if (!/^\d*$/.test(authority.slice(colon + 1))) return false;
    }
  }
  if (!host) return false;
  const hl = host.toLowerCase();
  if (hl === 'localhost') {
    // Exact literal only: subdomains fall through to reject below.
  } else if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) {
    if (host.split('.')[0] !== '127') return false;
  } else if (hl === '::1' || hl === '0:0:0:0:0:0:0:1') {
    // Canonical loopback only: no shorthand tricks, no mapped addresses.
  } else {
    return false;
  }
  let u;
  try {
    u = new URL(s);
  } catch {
    return false;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  if (u.username !== '' || u.password !== '') return false;
  const ph = (u.hostname || '').replace(/^\[|\]$/g, '');
  if (!ph) return false;
  if (ph.toLowerCase() === 'localhost') return hl === 'localhost';
  if (net.isIP(ph)) {
    if (net.isIPv4(ph)) return ph.split('.')[0] === '127';
    const n = ph.toLowerCase();
    return n === '::1' || n === '0:0:0:0:0:0:0:1';
  }
  return false;
}

function token() {
  const t = (process.env.ODOO_BROKER_TOKEN || '').trim();
  if (!t) throw new Error('ODOO_BROKER_TOKEN is not set');
  return t;
}

// redactToken scrubs the session token (raw + encodeURIComponent forms)
// from any text before it reaches the model.
function redactToken(text) {
  const t = (process.env.ODOO_BROKER_TOKEN || '').trim();
  let out = String(text);
  if (!t) return out;
  out = out.split(t).join('***');
  const enc = encodeURIComponent(t);
  if (enc && enc !== t) out = out.split(enc).join('***');
  return out;
}

function ok(text) {
  return { content: [{ type: 'text', text: String(text) }] };
}

function err(text) {
  return { content: [{ type: 'text', text: redactToken(text) }], isError: true };
}

// strictParams rejects unknown or wrong-typed arguments before dispatch.
// Kinds: string | strings | int | ints | bool | any.
function strictParams(tool, spec, params) {
  const p = params == null ? {} : params;
  if (typeof p !== 'object' || Array.isArray(p)) return `${tool}: params must be an object`;
  for (const key of Object.keys(p)) {
    if (!(key in spec)) return `${tool}: unknown argument ${JSON.stringify(key)}`;
    if (!checkKind(spec[key], p[key])) return `${tool}: argument ${JSON.stringify(key)} must be ${spec[key]}`;
  }
  return null;
}

function checkKind(kind, v) {
  switch (kind) {
    case 'any': return true;
    case 'string': return typeof v === 'string';
    case 'bool': return typeof v === 'boolean';
    case 'int': return Number.isInteger(v);
    case 'strings': return Array.isArray(v) && v.every((e) => typeof e === 'string');
    case 'ints': return Array.isArray(v) && v.every((e) => Number.isInteger(e));
    default: return false;
  }
}

// Bounded broker transport. MAX_BODY_BYTES is exactly 4 MiB (4*1024*1024);
// DEFAULT_TIMEOUT_MS is exactly 30000 (30s). ODOO_BROKER_TIMEOUT_MS
// overrides the timeout in milliseconds when set to a finite value in
// (0, MAX_TIMEOUT_MS] (test hook; missing, invalid, or over-cap values
// fall back to 30s so the bound cannot be disabled via env).
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30000;
const MAX_TIMEOUT_MS = 300000;

function resolveTimeoutMs() {
  const raw = process.env.ODOO_BROKER_TIMEOUT_MS;
  if (raw == null || raw === '') return DEFAULT_TIMEOUT_MS;
  const n = Number(raw);
  if (Number.isFinite(n) && n > 0 && n <= MAX_TIMEOUT_MS) return Math.floor(n);
  return DEFAULT_TIMEOUT_MS;
}

// readBoundedJSON is the ONE bounded reader: streaming only. It consumes at
// most MAX_BODY_BYTES+1 bytes BEFORE JSON decode: overflow (including a
// valid prefix padded with whitespace plus one more byte) denies the whole
// response with no body bytes echoed. The stream is cancelled on overflow,
// read error, and abort. A missing/non-streaming body (no getReader) fails
// closed with {nonJSON:true} and never allocates unbounded.
async function readBoundedJSON(res, signal) {
  const body = res ? res.body : null;
  if (!body || typeof body.getReader !== 'function') return { nonJSON: true };
  const reader = body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      if (signal && signal.aborted) {
        const aborted = new Error('The operation was aborted.');
        aborted.name = 'AbortError';
        throw aborted;
      }
      const next = await reader.read();
      if (next.done) break;
      const value = next.value;
      const len = value ? (value.byteLength != null ? value.byteLength : (value.length || 0)) : 0;
      total += len;
      if (total > MAX_BODY_BYTES) {
        try { await reader.cancel(); } catch {}
        return { overflow: true };
      }
      if (value) chunks.push(value);
    }
  } catch (e) {
    try { await reader.cancel(); } catch {}
    throw e;
  } finally {
    try { reader.releaseLock(); } catch {}
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    const u8 = c instanceof Uint8Array ? c : Uint8Array.from(c);
    buf.set(u8, off);
    off += u8.byteLength;
  }
  try {
    return { env: JSON.parse(new TextDecoder('utf-8').decode(buf)) };
  } catch {
    return { nonJSON: true };
  }
}

// requestJSON is the ONE bounded request helper shared by postJSON and
// getJSON. It gates the joined base origin (base before path join) against
// the loopback rule BEFORE fetch (failing closed on any violation), sends
// with redirect:'error', and races every request against a
// DEFAULT_TIMEOUT_MS AbortController combined with the caller signal, so
// headers AND body are covered. The timer and the caller-abort listener
// clear on every path.
async function requestJSON(urlInput, init, path) {
  const url = String(urlInput);
  const originEnd = url.startsWith(path) ? -1 : url.length - path.length;
  const baseOnly = originEnd > 0 ? url.slice(0, originEnd) : url;
  let loopback = false;
  try {
    loopback = isLoopbackURL(baseOnly);
  } catch {
    loopback = false;
  }
  if (!loopback) return err('ODOO_BROKER_URL must be a loopback http(s) URL');
  const caller = init && init.signal ? init.signal : undefined;
  if (caller && caller.aborted) return err('broker request aborted at ' + path);
  const ctrl = new AbortController();
  let timedOut = false;
  const onCallerAbort = () => ctrl.abort(caller.reason);
  if (caller) caller.addEventListener('abort', onCallerAbort, { once: true });
  const timer = setTimeout(() => {
    timedOut = true;
    ctrl.abort(new Error('broker request timed out at ' + path));
  }, resolveTimeoutMs());
  if (timer && typeof timer.unref === 'function') timer.unref();
  let res;
  try {
    try {
      res = await fetch(url, {
        method: init && init.method,
        headers: init && init.headers,
        body: init && init.body,
        redirect: 'error',
        signal: ctrl.signal,
      });
    } catch (e) {
      if (timedOut) return err('broker request timed out at ' + path);
      if ((e && e.name === 'AbortError') || ctrl.signal.aborted) return err('broker request aborted at ' + path);
      return err('broker unreachable at ' + path);
    }
    let out;
    try {
      out = await readBoundedJSON(res, ctrl.signal);
    } catch (e) {
      if (timedOut) return err('broker request timed out at ' + path);
      if ((e && e.name === 'AbortError') || ctrl.signal.aborted) return err('broker request aborted at ' + path);
      return err('broker returned non-JSON at ' + path);
    }
    if (out.overflow) return err('broker response exceeded 4 MiB limit at ' + path);
    if (out.nonJSON || !out.env) return err('broker returned non-JSON at ' + path);
    const env = out.env;
    if (!env.success) return err(env.error || ('broker denied ' + path));
    return ok(JSON.stringify(env.result));
  } finally {
    clearTimeout(timer);
    if (caller) caller.removeEventListener('abort', onCallerAbort);
  }
}

async function postJSON(path, body, signal) {
  let base;
  try {
    base = brokerURL();
  } catch (e) {
    return err(e.message);
  }
  let t;
  try {
    t = token();
  } catch (e) {
    return err(e.message);
  }
  let payload;
  try {
    payload = JSON.stringify(body || {});
  } catch {
    return err('broker request failed at ' + path);
  }
  return requestJSON(base + path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + t },
    body: payload,
    signal,
  }, path);
}

async function getJSON(path, signal) {
  let base;
  try {
    base = brokerURL();
  } catch (e) {
    return err(e.message);
  }
  let t;
  try {
    t = token();
  } catch (e) {
    return err(e.message);
  }
  return requestJSON(base + path, {
    method: 'GET',
    headers: { Authorization: 'Bearer ' + t },
    signal,
  }, path);
}

function str(desc) { return { type: 'string', description: desc }; }

// execute(toolCallId, params, onUpdate, ctx, signal) per the installed
// CustomTool.execute signature. Broker denials already arrive as isError
// results from postJSON/getJSON, so execute returns them directly; only a
// missing token throws (operator misconfiguration, not a broker denial).
// getArgs extracts exactly the declared arguments (no pass-through of
// unknown params); strictParams rejects unknown/wrong-typed args first.
function exec(tool, path, spec, getArgs) {
  return async (_toolCallId, params, _onUpdate, _ctx, signal) => {
    const bad = strictParams(tool, spec, params);
    if (bad) return err(bad);
    return postJSON(path, getArgs(params || {}), signal);
  };
}

const SEARCH_ARGS = { model: 'string', domain: 'any', fields: 'strings', order: 'string', limit: 'int', offset: 'int' };
const READ_ARGS = { model: 'string', ids: 'ints', fields: 'strings' };
const COUNT_ARGS = { model: 'string', domain: 'any' };
const AGG_ARGS = { model: 'string', domain: 'any', groupby: 'strings', sum: 'strings', avg: 'strings', count: 'bool', limit: 'int' };
const META_ARGS = { model: 'string' };
const WS_LIST_ARGS = { path: 'string', max_entries: 'int' };
const WS_PATH_ARGS = { path: 'string' };
const WS_WRITE_ARGS = { path: 'string', content: 'string' };

const EVIDENCE_ARGS = { model: 'string', id: 'int', kind: 'string', limit: 'int', offset: 'int', tracking_offset:'int', attachment_id: 'int', path: 'string' };

function buildTools() {
  return [
    {
      name: 'odoo.evidence', label: 'Odoo linked evidence',
      description: 'Read chatter/tracking/attachments for a visible approved parent. Download linked binary attachments up to 2 MiB into the workspace. Tracking: offset pages messages; tracking_offset pages changes within those messages; response carries paging hints.',
      parameters: { type: 'object', properties: { model: str('Approved parent model'), id: {type:'integer'}, kind: str('chatter, tracking, attachments or download'), limit:{type:'integer'}, offset:{type:'integer'}, tracking_offset:{type:'integer'}, attachment_id:{type:'integer'}, path:str('Download destination relative to workspace') }, required:['model','id','kind'] },
      execute: exec('odoo.evidence', '/rpc/evidence', EVIDENCE_ARGS, (p) => ({ model:p.model, id:p.id, kind:p.kind, limit:p.limit, offset:p.offset, tracking_offset:p.tracking_offset, attachment_id:p.attachment_id, path:p.path })),
    },
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
      execute: exec('odoo.search', '/rpc/search', SEARCH_ARGS, (p) => ({
        model: p.model, domain: p.domain, fields: p.fields,
        order: p.order, limit: p.limit, offset: p.offset,
      })),
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
      execute: exec('odoo.read', '/rpc/read', READ_ARGS, (p) => ({
        model: p.model, ids: p.ids, fields: p.fields,
      })),
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
      execute: exec('odoo.count', '/rpc/count', COUNT_ARGS, (p) => ({
        model: p.model, domain: p.domain,
      })),
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
      execute: exec('odoo.aggregate', '/rpc/aggregate', AGG_ARGS, (p) => ({
        model: p.model, domain: p.domain, groupby: p.groupby,
        sum: p.sum, avg: p.avg, count: p.count, limit: p.limit,
      })),
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
        const bad = strictParams('odoo.meta', META_ARGS, params);
        if (bad) return err(bad);
        const q = params && params.model ? '?model=' + encodeURIComponent(params.model) : '';
        return getJSON('/rpc/meta' + q, signal);
      },
    },
    {
      name: 'odoo.companies',
      label: 'Odoo companies',
      description: 'Company discovery: available/enabled/default (no record data).',
      parameters: { type: 'object', properties: {} },
      execute: async (_id, p, _u, _c, signal) => {
        const bad = strictParams('odoo.companies', {}, p);
        if (bad) return err(bad);
        return getJSON('/rpc/companies', signal);
      },
    },
    {
      name: 'odoo.catalog',
      label: 'Odoo catalog',
      description: 'Per-model catalog with MethodManifest and provenance (read-only pass-through, no record data).',
      parameters: { type: 'object', properties: {} },
      execute: async (_id, p, _u, _c, signal) => {
        const bad = strictParams('odoo.catalog', {}, p);
        if (bad) return err(bad);
        return getJSON('/rpc/catalog', signal);
      },
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
      execute: exec('odoo.workspace.list', '/rpc/workspace/list', WS_LIST_ARGS, (p) => ({
        path: p.path, max_entries: p.max_entries,
      })),
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
      execute: exec('odoo.workspace.read', '/rpc/workspace/read', WS_PATH_ARGS, (p) => ({
        path: p.path,
      })),
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
      execute: exec('odoo.workspace.write', '/rpc/workspace/write', WS_WRITE_ARGS, (p) => ({
        path: p.path, content: p.content,
      })),
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
      execute: exec('odoo.workspace.mkdir', '/rpc/workspace/mkdir', WS_PATH_ARGS, (p) => ({
        path: p.path,
      })),
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
