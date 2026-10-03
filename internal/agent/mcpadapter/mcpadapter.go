// Package mcpadapter exposes the broker's TYPED tools over MCP stdio
// (JSON-RPC 2.0 on stdin/stdout) for runtimes that consume MCP servers.
//
// Typed tools only: search, read, count, aggregate, meta, companies,
// catalog, workspace.list, workspace.read, workspace.write. There are no
// admin, raw, exec, or shell tools: Grant/Revoke never cross this surface,
// and the adapter never spawns a child process.
//
// Auth: the broker session token comes from the ODOO_BROKER_TOKEN
// environment variable (or the configured Token field, e.g. read from
// stdin by the host). The token is sent as an HTTP Bearer header only; it
// is never logged, never echoed in errors, and never placed in model
// output. Broker URL comes from ODOO_BROKER_URL (or BaseURL).
//
// Protocol errors use JSON-RPC error objects. Broker denials surface as
// tool errors (IsError content), not protocol errors.
package mcpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// Version is the adapter protocol surface version (not an OMP version).
const Version = "1.0.0"

// Config carries the broker endpoint and credential. Token is never logged.
type Config struct {
	// BaseURL is the broker model listener, e.g. http://127.0.0.1:8471.
	BaseURL string
	// Token is the broker session token. Prefer env ODOO_BROKER_TOKEN;
	// Config.Token is the explicit override (host-read, e.g. stdin).
	Token string
	// HTTPClient, if nil, defaults to a 30s-timeout client.
	HTTPClient *http.Client
}

// Resolve fills BaseURL/Token from the environment when unset:
// ODOO_BROKER_URL (default http://127.0.0.1:8471) and ODOO_BROKER_TOKEN.
func (c Config) Resolve() Config {
	out := c
	if strings.TrimSpace(out.BaseURL) == "" {
		out.BaseURL = strings.TrimSpace(os.Getenv("ODOO_BROKER_URL"))
		if out.BaseURL == "" {
			out.BaseURL = "http://127.0.0.1:8471"
		}
	}
	if out.Token == "" {
		out.Token = strings.TrimSpace(os.Getenv("ODOO_BROKER_TOKEN"))
	}
	if out.HTTPClient == nil {
		out.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	return out
}

// Tool describes one typed broker tool on tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// Tools lists the typed broker tools only. No admin/raw/exec entries.
func Tools() []Tool {
	obj := func(props map[string]any, required ...string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	str := map[string]any{"type": "string"}
	strs := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}
	num := map[string]any{"type": "integer"}
	boolean := map[string]any{"type": "boolean"}
	domain := map[string]any{}
	return []Tool{
		{Name: "search", Description: "Scoped search_read over an allowlisted model.",
			InputSchema: obj(map[string]any{"model": str, "domain": domain, "fields": strs, "order": str, "limit": num, "offset": num}, "model", "fields")},
		{Name: "read", Description: "Scoped by-id read (converted to search_read server-side).",
			InputSchema: obj(map[string]any{"model": str, "ids": map[string]any{"type": "array", "items": num}, "fields": strs}, "model", "ids", "fields")},
		{Name: "count", Description: "Scoped record count.",
			InputSchema: obj(map[string]any{"model": str, "domain": domain}, "model")},
		{Name: "aggregate", Description: "Scoped read_group aggregation.",
			InputSchema: obj(map[string]any{"model": str, "domain": domain, "groupby": strs, "sum": strs, "avg": strs, "count": boolean, "limit": num}, "model", "groupby")},
		{Name: "meta", Description: "Sealed allowlist metadata (no record data). Optional model query.",
			InputSchema: obj(map[string]any{"model": str})},
		{Name: "companies", Description: "Company discovery: available/enabled/default (no record data).",
			InputSchema: obj(map[string]any{})},
		{Name: "catalog", Description: "Per-model catalog with executable flags (no record data).",
			InputSchema: obj(map[string]any{})},
		{Name: "workspace.list", Description: "List broker-confined workspace entries.",
			InputSchema: obj(map[string]any{"path": str, "max_entries": num}, "path")},
		{Name: "workspace.read", Description: "Read one broker-confined workspace file.",
			InputSchema: obj(map[string]any{"path": str}, "path")},
		{Name: "workspace.write", Description: "Write one broker-confined workspace file.",
			InputSchema: obj(map[string]any{"path": str, "content": str}, "path", "content")},
	}
}

// rpcRequest is one JSON-RPC 2.0 request. Notifications carry no ID.
type rpcRequest struct {
	JSONRPC string           `json:"jsonrpc"`
	Method  string           `json:"method"`
	Params  json.RawMessage  `json:"params"`
	ID      *json.RawMessage `json:"id"`
}

// rpcResponse is one JSON-RPC 2.0 response or error.
type rpcResponse struct {
	JSONRPC string  `json:"jsonrpc"`
	ID      any     `json:"id,omitempty"`
	Result  any     `json:"result,omitempty"`
	Error   *rpcErr `json:"error,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Server adapts typed broker tools to MCP stdio. In and Out default to
// os.Stdin/os.Stdout; tests inject buffers.
type Server struct {
	cfg Config
	In  io.Reader
	Out io.Writer
}

// New returns a stdio server bound to cfg (resolved) with process stdio.
func New(cfg Config) *Server {
	return &Server{cfg: cfg.Resolve(), In: os.Stdin, Out: os.Stdout}
}

// Serve reads JSON-RPC 2.0 values from In and writes responses to Out until
// EOF. Each line (or stream value) is one request; notifications get no
// reply. Unknown methods return MethodNotFound; bad JSON returns ParseError.
func (s *Server) Serve(ctx context.Context) error {
	dec := json.NewDecoder(s.In)
	enc := json.NewEncoder(s.Out)
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				return nil
			}
			_ = enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcErr{Code: -32700, Message: "parse error"}})
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(raw, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
			_ = enc.Encode(rpcResponse{JSONRPC: "2.0", Error: &rpcErr{Code: -32600, Message: "invalid request"}})
			continue
		}
		if req.ID == nil {
			s.handleNotification(req.Method, req.Params)
			continue
		}
		var id any
		_ = json.Unmarshal(*req.ID, &id)
		res, rerr := s.handle(ctx, req.Method, req.Params)
		if rerr != nil {
			_ = enc.Encode(rpcResponse{JSONRPC: "2.0", ID: id, Error: rerr})
			continue
		}
		_ = enc.Encode(rpcResponse{JSONRPC: "2.0", ID: id, Result: res})
	}
}

func (s *Server) handleNotification(method string, _ json.RawMessage) {
	// notifications/initialized is a no-op (handshake completion).
	_ = method
}

func (s *Server) handle(ctx context.Context, method string, params json.RawMessage) (any, *rpcErr) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": "2024-11-05",
			"serverInfo":      map[string]any{"name": "odoo-broker", "version": Version},
			"capabilities":    map[string]any{"tools": map[string]any{}},
		}, nil
	case "tools/list":
		return map[string]any{"tools": Tools()}, nil
	case "tools/call":
		var in struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if len(params) > 0 {
			if err := json.Unmarshal(params, &in); err != nil {
				return nil, &rpcErr{Code: -32602, Message: "invalid params"}
			}
		}
		if strings.TrimSpace(in.Name) == "" {
			return nil, &rpcErr{Code: -32602, Message: "tool name is required"}
		}
		if in.Arguments == nil {
			in.Arguments = map[string]any{}
		}
		out, toolErr, perr := s.callTool(ctx, in.Name, in.Arguments)
		if perr != nil {
			return nil, perr
		}
		if toolErr {
			return map[string]any{"content": []any{map[string]any{"type": "text", "text": out}}, "isError": true}, nil
		}
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": out}}}, nil
	default:
		return nil, &rpcErr{Code: -32601, Message: fmt.Sprintf("unknown method %q", method)}
	}
}

// endpoint maps a typed tool name to its broker path and HTTP method.
func endpoint(name string) (method, path string, ok bool) {
	switch name {
	case "search":
		return http.MethodPost, "/rpc/search", true
	case "read":
		return http.MethodPost, "/rpc/read", true
	case "count":
		return http.MethodPost, "/rpc/count", true
	case "aggregate":
		return http.MethodPost, "/rpc/aggregate", true
	case "meta":
		return http.MethodGet, "/rpc/meta", true
	case "companies":
		return http.MethodGet, "/rpc/companies", true
	case "catalog":
		return http.MethodGet, "/rpc/catalog", true
	case "workspace.list":
		return http.MethodPost, "/rpc/workspace/list", true
	case "workspace.read":
		return http.MethodPost, "/rpc/workspace/read", true
	case "workspace.write":
		return http.MethodPost, "/rpc/workspace/write", true
	}
	return "", "", false
}

// callTool validates the tool name (typed only), forwards to the broker
// with the bearer token, and maps the broker envelope to MCP content.
// Returns (text, isToolError, protocolError). Admin/raw names are unknown
// methods, never forwarded.
func (s *Server) callTool(ctx context.Context, name string, args map[string]any) (string, bool, *rpcErr) {
	method, path, ok := endpoint(name)
	if !ok {
		return "", false, &rpcErr{Code: -32601, Message: fmt.Sprintf("unknown tool %q", name)}
	}
	if strings.TrimSpace(s.cfg.Token) == "" {
		return "broker token is not configured", true, nil
	}
	var body io.Reader
	url := strings.TrimRight(s.cfg.BaseURL, "/") + path
	if method == http.MethodGet {
		// GET tools take no body; meta's optional model query rides the
		// query string so no body shape can smuggle filter state.
		if name == "meta" {
			if m, _ := args["model"].(string); strings.TrimSpace(m) != "" {
				url += "?model=" + strings.TrimSpace(m)
			}
		}
	} else {
		b, err := json.Marshal(args)
		if err != nil {
			return "invalid arguments", true, nil
		}
		if len(b) > 1<<20 {
			return "arguments exceed 1 MiB", true, nil
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return "building broker request failed", true, nil
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Token travels only in the Authorization header; it is never logged,
	// never echoed in errors, and never placed in tool output.
	req.Header.Set("Authorization", "Bearer "+s.cfg.Token)
	res, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return "broker unreachable", true, nil
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		return "reading broker response failed", true, nil
	}
	var env struct {
		Success bool            `json:"success"`
		Result  json.RawMessage `json:"result"`
		Count   int             `json:"count"`
		Error   string          `json:"error"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return "invalid broker response", true, nil
	}
	if !env.Success {
		msg := strings.TrimSpace(env.Error)
		if msg == "" {
			msg = "broker denied the request"
		}
		return msg, true, nil
	}
	out := strings.TrimSpace(string(env.Result))
	if out == "" || out == "null" {
		out = "{}"
	}
	return out, false, nil
}
