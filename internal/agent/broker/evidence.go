package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
)

const maxAttachmentBytes = 2 << 20

type evidenceBody struct {
	Model          string `json:"model"`
	ID             int    `json:"id"`
	Kind           string `json:"kind"`
	Limit          int    `json:"limit"`
	Offset         int    `json:"offset"`
	TrackingOffset int    `json:"tracking_offset"`
	AttachmentID   int    `json:"attachment_id"`
	Path           string `json:"path"`
}

// Evidence phases for classified linked-evidence errors. Each upstream
// dispatch maps to exactly one phase so a tracking failure names the
// stage that failed (parent vs messages vs tracking-values) instead of
// collapsing to one generic message.
const (
	evidencePhaseParent         = "parent"
	evidencePhaseMessages       = "messages"
	evidencePhaseTrackingValues = "tracking-values"
	evidencePhaseAttachmentMeta = "attachment-meta"
	evidencePhaseAttachmentBody = "attachment-content"
	evidencePhaseWorkspaceWrite = "workspace-write"
)

// Compound reads respect the same global RPC cadence as standalone reads.
// This wait is bounded by request cancellation and the existing RPC timeout.
func (b *Broker) evidenceExec(r *http.Request, token string, model string, fields []string, domain []any, limit, offset int) (any, error) {
	if err := b.live(token); err != nil {
		return nil, err
	}
	b.mu.Lock()
	delay := time.Until(b.nextRPC)
	b.mu.Unlock()
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-r.Context().Done():
			return nil, r.Context().Err()
		}
	}
	if err := b.live(token); err != nil {
		return nil, err
	}
	_, kwargs, err := b.scopedArgs(policy.ModelRule{CompanyIndependent: true}, nil)
	if err != nil {
		return nil, err
	}
	kwargs["domain"] = domain
	kwargs["fields"] = fields
	kwargs["limit"] = limit
	kwargs["offset"] = offset
	kwargs["order"] = "id asc"
	return b.dispatchExec(r, model, "search_read", nil, kwargs)
}

// The caller chooses a visible parent, never a raw evidence domain/method.
// Evidence is re-linked on each request; no cached visibility or raw read.
func (b *Broker) handleEvidence(w http.ResponseWriter, r *http.Request) {
	tok, ok := b.authorize(w, r)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), b.rpcTimeoutOf())
	defer cancel()
	r = r.WithContext(ctx)
	// reqID scopes one linked-evidence call for classified errors: a short
	// random hex, never a credential, echoed in safe error text so the
	// human can correlate the failed phase without seeing upstream detail.
	reqID := evidenceReqID()
	var in evidenceBody
	if !b.decodeBody(w, r, &in) {
		b.release(tok)
		return
	}
	if !b.pol.AllowLinkedEvidence || !b.pol.Operations[policy.OpRead] {
		b.writeError(w, r, http.StatusForbidden, "linked evidence not enabled")
		b.release(tok)
		return
	}
	limit := maxLimitOr(in.Limit, defaultSearchLimit())
	if in.ID <= 0 || limit <= 0 || limit > b.pol.Budgets.MaxLimit || in.Offset < 0 || in.Offset > b.pol.Budgets.MaxOffset || in.TrackingOffset < 0 || in.TrackingOffset > b.pol.Budgets.MaxOffset {
		b.writeError(w, r, http.StatusBadRequest, "invalid evidence parent or paging")
		b.release(tok)
		return
	}
	source := ""
	switch in.Kind {
	case "chatter":
		source = "mail.message"
	case "tracking":
		source = "mail.tracking.value"
	case "attachments", "download":
		source = "ir.attachment"
	default:
		b.writeError(w, r, http.StatusBadRequest, "kind must be chatter, tracking, attachments or download")
		b.release(tok)
		return
	}
	evidence, ok := b.pol.Models[source]
	if !ok || !evidence.LinkedEvidence || policy.IsEvidenceModel(in.Model) {
		b.writeError(w, r, http.StatusForbidden, "evidence source or parent not enabled")
		b.release(tok)
		return
	}
	if in.Kind == "download" && (!b.pol.AllowWorkspace || in.AttachmentID <= 0 || in.Path == "") {
		b.writeError(w, r, http.StatusBadRequest, "download requires enabled workspace, attachment_id and destination path")
		b.release(tok)
		return
	}
	parentDomain := []any{[]any{"id", "=", in.ID}}
	rule, ok := b.gate(w, r, policy.Request{Operation: policy.OpRead, Model: in.Model, Fields: []string{"id"}, Domain: parentDomain, Limit: 1})
	if !ok {
		b.release(tok)
		return
	}
	if !b.enforceable(w, r, rule) {
		b.release(tok)
		return
	}
	domain, kwargs, err := b.scopedArgs(rule, parentDomain)
	if err != nil {
		b.writeError(w, r, http.StatusForbidden, "parent scope unavailable")
		b.release(tok)
		return
	}
	wantRows := limit + 1
	if in.Kind == "tracking" {
		wantRows = 2*limit + 1
	}
	if in.Kind == "download" {
		wantRows = 3
	}
	if wantRows > b.pol.Budgets.MaxRowsPerCall {
		b.writeError(w, r, http.StatusBadRequest, "compound evidence read exceeds row budget")
		b.release(tok)
		return
	}
	reserved, err := b.reserveForLimit(tok, wantRows)
	if b.checkError(w, r, err) {
		b.release(tok)
		return
	}
	kwargs["domain"] = domain
	kwargs["fields"] = []string{"id"}
	kwargs["limit"] = 1
	parent, err := b.dispatchExec(r, in.Model, "search_read", nil, kwargs)
	if err != nil {
		b.evidenceError(w, r, evidencePhaseParent, in.Model, reqID, err)
		if errors.Is(err, ErrSessionBudget) || errors.Is(err, errBrokerNotServing) {
			b.releaseReserve(tok, reserved)
		}
		return
	}
	parents, ok := parent.([]any)
	if !ok || len(parents) != 1 {
		b.writeError(w, r, http.StatusForbidden, "parent record unavailable in approved scope")
		return
	}
	p, ok := parents[0].(map[string]any)
	if !ok || !evidenceIDEquals(p["id"], in.ID) {
		b.writeError(w, r, http.StatusBadGateway, "invalid parent response")
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	examined := 1
	var messageIDs []any
	messageOffset := in.Offset
	link := "model"
	if source == "ir.attachment" {
		link = "res_model"
	}
	evidenceDomain := []any{[]any{link, "=", in.Model}, []any{"res_id", "=", in.ID}}
	fields := []string{}
	for _, f := range evidence.Fields {
		if f != "datas" {
			fields = append(fields, f)
		}
	}
	if in.Kind == "tracking" {
		messages, ok := b.pol.Models["mail.message"]
		if !ok || !messages.LinkedEvidence {
			b.writeError(w, r, http.StatusForbidden, "message linkage unavailable")
			return
		}
		result, err := b.evidenceExec(r, tok, "mail.message", []string{"id"}, evidenceDomain, limit, in.Offset)
		if err != nil {
			b.evidenceError(w, r, evidencePhaseMessages, "mail.message", reqID, err)
			return
		}
		rows, ok := result.([]any)
		if !ok || len(rows) > limit {
			b.writeError(w, r, http.StatusBadGateway, "invalid linked message response")
			return
		}
		examined += len(rows)
		ids := []any{}
		for _, row := range rows {
			m, ok := row.(map[string]any)
			if !ok {
				b.writeError(w, r, http.StatusBadGateway, "invalid message row")
				return
			}
			id, valid := evidenceInt(m["id"])
			if !valid || id <= 0 {
				b.writeError(w, r, http.StatusBadGateway, "invalid message identifier")
				return
			}
			ids = append(ids, id)
		}
		evidenceDomain = []any{[]any{"mail_message_id", "in", ids}}
		messageIDs = ids
		// Tracking corresponds to this page of messages; not a claim of a
		// complete history. A bounded tracking limit still applies.
		in.Offset = in.TrackingOffset
	}
	if in.Kind == "download" {
		evidenceDomain = append(evidenceDomain, []any{"id", "=", in.AttachmentID})
		limit = 1
		in.Offset = 0
	}
	result, err := b.evidenceExec(r, tok, source, fields, evidenceDomain, limit, in.Offset)
	if err != nil {
		phase := evidencePhaseAttachmentMeta
		if in.Kind == "tracking" {
			phase = evidencePhaseTrackingValues
		}
		if in.Kind == "chatter" {
			phase = evidencePhaseMessages
		}
		b.evidenceError(w, r, phase, source, reqID, err)
		return
	}
	rows, ok := result.([]any)
	if !ok || len(rows) > limit {
		b.writeError(w, r, http.StatusBadGateway, "invalid evidence response")
		return
	}
	if in.Kind == "download" {
		if len(rows) != 1 {
			b.writeError(w, r, http.StatusForbidden, "attachment not linked to approved parent")
			return
		}
		meta, ok := rows[0].(map[string]any)
		if !ok {
			b.writeError(w, r, http.StatusBadGateway, "invalid attachment metadata")
			return
		}
		size, ok := evidenceInt(meta["file_size"])
		if !ok || size < 0 || size > maxAttachmentBytes || meta["type"] != "binary" {
			b.writeError(w, r, http.StatusBadRequest, "only linked binary attachments up to 2 MiB may be downloaded; URL attachments are not fetched")
			return
		}
		if !containsField(evidence.Fields, "datas") {
			b.writeError(w, r, http.StatusForbidden, "attachment content not enabled")
			return
		}
		content, err := b.evidenceExec(r, tok, source, []string{"id", "datas"}, evidenceDomain, 1, 0)
		if err != nil {
			b.evidenceError(w, r, evidencePhaseAttachmentBody, source, reqID, err)
			return
		}
		contentRows, ok := content.([]any)
		if !ok || len(contentRows) != 1 {
			b.writeError(w, r, http.StatusBadGateway, "attachment content unavailable")
			return
		}
		value, ok := contentRows[0].(map[string]any)
		if !ok || !evidenceIDEquals(value["id"], in.AttachmentID) {
			b.writeError(w, r, http.StatusBadGateway, "invalid attachment content")
			return
		}
		data, err := decodeAttachmentDatas(value["datas"])
		if err != nil {
			b.writeError(w, r, http.StatusBadGateway, "invalid or over-cap attachment content")
			return
		}

		if err := b.live(tok); err != nil {
			b.checkError(w, r, err)
			return
		}
		b.mu.Lock()
		ws := b.ws
		b.mu.Unlock()
		if ws == nil {
			b.evidenceError(w, r, evidencePhaseWorkspaceWrite, source, reqID, errWorkspaceUnavailable)
			return
		}
		if err := ws.Write(in.Path, data); err != nil {
			b.evidenceError(w, r, evidencePhaseWorkspaceWrite, source, reqID, err)
			return
		}
		b.settleRows(tok, reserved, 3)
		sum := sha256.Sum256(data)
		// The hash identifies the bytes for reproducible bundles; content
		// itself is never inspected for secrets (text sanitizer scope).
		// The whole text descriptor passes the common boundary: mimetype
		// is stored record text and may carry a smuggled parameter, so it
		// is sanitized like name. Binary bytes/hash/path semantics stay
		// exact (never redacted, never rewritten).
		clean := SanitizePayload(map[string]any{"name": meta["name"], "mimetype": meta["mimetype"]}).(map[string]any)
		b.writeEnvelope(w, r, tok, map[string]any{"path": in.Path, "bytes": len(data), "sha256": hex.EncodeToString(sum[:]), "name": clean["name"], "mimetype": clean["mimetype"]}, 1)
		return
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return
	}
	b.settleRows(tok, reserved, len(rows)+examined)
	// Central success-payload redaction for linked evidence rows (HTML
	// descriptions, chatter bodies, attachment metadata): same marker and
	// scope as search/read via writeRows. Grant tokens never flow here.
	rows = toSanitizedRows(rows)
	if in.Kind == "tracking" {
		b.writeEnvelope(w, r, tok, map[string]any{"rows": rows, "source_message_ids": messageIDs, "message_offset": messageOffset, "tracking_offset": in.TrackingOffset, "limit": limit, "may_have_more_messages": len(messageIDs) == limit, "may_have_more_tracking": len(rows) == limit}, len(rows))
		return
	}
	b.writeEnvelope(w, r, tok, rows, len(rows))
}

// toSanitizedRows applies SanitizePayload row-wise, preserving the row
// count and order the paging hints describe.
func toSanitizedRows(rows []any) []any {
	out := make([]any, len(rows))
	for i, row := range rows {
		out[i] = SanitizePayload(row)
	}
	return out
}

// evidenceReqID mints a short request-scoped correlation ID (8 hex chars
// from crypto/rand, zero-padded fallback on the impossible read error).
// It is never a credential and never derived from one.
func evidenceReqID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "00000000"
	}
	return hex.EncodeToString(b[:])
}

// Odoo's binary-field payload is base64 text; RPC codecs may carry that
// text as a string or a byte slice. Neither representation is raw file data.
func decodeAttachmentDatas(value any) ([]byte, error) {
	var encoded string
	switch v := value.(type) {
	case string:
		if len(v) > base64.StdEncoding.EncodedLen(maxAttachmentBytes) {
			return nil, fmt.Errorf("encoded attachment exceeds cap")
		}
		encoded = v
	case []byte:
		if len(v) > base64.StdEncoding.EncodedLen(maxAttachmentBytes) {
			return nil, fmt.Errorf("encoded attachment exceeds cap")
		}
		encoded = string(v)
	default:
		return nil, fmt.Errorf("invalid attachment encoding type")
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || len(data) > maxAttachmentBytes {
		return nil, fmt.Errorf("invalid or over-cap attachment")
	}
	return data, nil
}

func containsField(fields []string, name string) bool {
	for _, f := range fields {
		if f == name {
			return true
		}
	}
	return false
}
func evidenceIDEquals(v any, id int) bool { n, ok := evidenceInt(v); return ok && n == id }
func evidenceInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		if n >= 0 && n <= 9007199254740991 {
			return int(n), true
		}
	case float64:
		if n >= 0 && n <= 9007199254740991 && n == float64(int64(n)) {
			return int(n), true
		}
	}
	return 0, false
}

// evidenceError classifies a linked-evidence upstream failure into safe,
// secret-free model text. Phase names the failed stage (parent, messages,
// tracking-values, attachment-meta, attachment-content, workspace-write),
// model the evidence source, and reqID the request correlation ID from
// handleEvidence. The error envelope carries a structured error_meta
// object (phase, model, request_id, category, retryable, status) alongside
// the human-readable message; adapters forward both blocks. Upstream error
// text is NEVER echoed: credentials and raw RPC faults stay out of model
// output. Unknown upstream faults stay category "unknown" with
// retryable:false — never guessed transient, never blanket-retried.
func (b *Broker) evidenceError(w http.ResponseWriter, r *http.Request, phase, model, reqID string, err error) {
	status := http.StatusBadGateway
	category := "unknown"
	retryable := false
	message := fmt.Sprintf("linked %s read failed for %s (req %s); retryable:false", phase, model, reqID)
	if errors.Is(err, ErrSessionBudget) {
		status = http.StatusTooManyRequests
		category = "pacing"
		retryable = true
		message = fmt.Sprintf("RPC pacing/concurrency budget reached during %s for %s (req %s); retry with backoff", phase, model, reqID)
	}
	if errors.Is(err, ErrSessionExpired) || errors.Is(err, ErrSessionUnknown) {
		status = http.StatusUnauthorized
		category = "session"
		message = fmt.Sprintf("session expired or revoked during %s (req %s); renew via human `odoo agent grant`", phase, reqID)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		status = http.StatusGatewayTimeout
		category = "timeout"
		retryable = true
		message = fmt.Sprintf("linked %s read timed out for %s (req %s); retryable:true with backoff", phase, model, reqID)
	}
	if errors.Is(err, errBrokerNotServing) && phase != evidencePhaseWorkspaceWrite {
		status = http.StatusServiceUnavailable
		category = "broker"
		retryable = true
		message = fmt.Sprintf("broker unavailable during %s (req %s); retryable:true with backoff", phase, reqID)
	}
	if errors.Is(err, errWorkspaceUnavailable) {
		status = http.StatusServiceUnavailable
		category = "workspace"
		message = fmt.Sprintf("workspace unavailable during %s (req %s); retryable:false", phase, reqID)
	}
	// Workspace-write failures (nil workspace, refused destination) are a
	// local broker/filesystem class, not an upstream evidence fault: keep
	// the phase correlation ID but report 400/503 instead of the generic
	// 502 so callers do not retry a refused path as a transient RPC fault.
	if phase == evidencePhaseWorkspaceWrite && status == http.StatusBadGateway {
		status = http.StatusBadRequest
		category = "workspace"
		message = fmt.Sprintf("attachment destination refused during %s (req %s); retryable:false", phase, reqID)
	}
	b.writeErrorMeta(w, r, status, message, map[string]any{
		"phase": phase, "model": model, "request_id": reqID,
		"category": category, "retryable": retryable, "status": status,
	})
}
