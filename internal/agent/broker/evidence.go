package broker

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/kolo/xmlrpc"
)

const maxAttachmentBytes = 2 << 20

// maxMessagePages bounds one mail.message source scan: each source page
// costs one billed row, so a window can never bill more than this many
// scan pages no matter how sparse the visible rows are. Sparse windows
// deny past the bound instead of scanning unboundedly (fail closed:
// callers retry with a narrower window or a human reviews scope).
const maxMessagePages = 8

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
	// Continuation must survive Odoo's post-limit access filtering.
	// mail.message._search applies SQL limit/offset FIRST, then strips
	// messages the requester may not see (odoo 17.0
	// addons/mail/models/mail_message.py _search: SQL limit, then
	// per-message allow-list, no refill). offset therefore counts
	// PRE-filter source rows while any visible total counts POST-filter
	// rows: comparing the two cannot establish exhaustion in either
	// direction, and neither can any window shape — an empty window may
	// be fully stripped with visible rows past it. mail.tracking.value
	// carries no _search override and ir.attachment._search DOES refill
	// filtered rows up to the requested limit, so only mail.message
	// windows need this treatment. Treatment: each mail.message window
	// walks forward in source order (id asc) from the caller's offset,
	// collecting up to limit visible ids. Source accounting uses
	// REQUESTED rows only (each completed page consumes its requested
	// limit), so resume cursors never duplicate or skip; exhaustion is
	// decided by cardinality (distinct collected ids vs the paced
	// visible total from the same scoped domain), never by shape.
	// Callers stop a walk when cumulative distinct ids >= visible_total.
	// The probe row still rides along for tracking values and
	// attachments (sound there: no stripping / refill) and costs one
	// reserved row; every scan page bills its fetched rows.
	// Billed rows: parent (1) + count (1 per message window) + scan
	// fetched + window fetched incl. probe (tracking values,
	// attachments) or projection (chatter). Download fetches parent +
	// meta + content (3, no probe, no scan).
	// scanRowsMax bounds one mail.message source scan in FETCHED rows:
	// at most maxMessagePages pages of at most limit visible rows each.
	scanRowsMax := maxMessagePages * limit
	wantRows := limit + 2
	if in.Kind == "chatter" {
		// parent + count + scan fetched + projection (<= limit).
		wantRows = 2 + scanRowsMax + limit
	}
	if in.Kind == "tracking" {
		// parent + count + scan fetched + values incl. probe.
		wantRows = 2 + scanRowsMax + limit + 1
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
	mayHaveMoreMessages := false
	messageOffset := in.Offset
	messageNext := -1
	messageComplete := false
	messageTotal := 0
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
		// The linked-message window walks forward in source order
		// from the caller's message offset until it holds one page
		// of visible message ids. Continuation is the next
		// unconsumed source offset (requested-based, never
		// visible-based, so no duplicates or skips); exhaustion is
		// decided below by cardinality (collected ids vs the paced
		// visible total), never by window shape — an empty window
		// may be fully stripped with visible rows past it.
		messageOffset = in.Offset
		scan, ok := b.evidenceMessageScan(r, tok, reqID, w, evidenceDomain, messageOffset, limit)
		if !ok {
			return
		}
		examined += scan.fetched
		messageTotal, ok = b.evidenceVisibleTotal(r, tok, reqID, w, evidenceDomain)
		if !ok {
			return
		}
		examined++
		// Cardinality, not position: the collected ids are distinct
		// visible rows out of messageTotal visible rows. collected <
		// total proves more rows exist elsewhere; collected >= total
		// proves this page holds them all. (Comparing offset — a
		// pre-filter source position — with the total — a post-filter
		// count — cannot establish exhaustion in either direction.)
		// Totals are live-data best-effort under concurrent
		// modification; resume cursors keep windows disjoint, so a
		// skewed total at worst adds a redundant page, never a
		// duplicate or a skip.
		mayHaveMoreMessages = len(scan.ids) < messageTotal
		messageNext = messageOffset + scan.consumed
		if !mayHaveMoreMessages {
			messageNext = -1
		}
		anyIDs := make([]any, 0, len(scan.ids))
		for _, id := range scan.ids {
			anyIDs = append(anyIDs, id)
		}
		evidenceDomain = []any{[]any{"mail_message_id", "in", anyIDs}}
		messageIDs = anyIDs
		messageComplete = !mayHaveMoreMessages
		// Tracking values page within THIS message batch at the
		// caller's tracking offset (mail.tracking.value carries no
		// post-filter stripping, so its probe row stays sound).
		valueOffset := in.TrackingOffset
		in.Offset = valueOffset
		if len(anyIDs) == 0 {
			// No visible messages in this window: no tracking values
			// can match, and billing stops at parent + scan fetched
			// + count (examined already counts all three). The
			// message dimension reports incomplete unless the total
			// proves otherwise — never exhausted from the window.
			if err := b.live(tok); err != nil {
				b.checkError(w, r, err)
				return
			}
			b.settleRows(tok, reserved, examined)
			rows := toSanitizedRows([]any{})
			nextMessageOffset := -1
			if mayHaveMoreMessages {
				nextMessageOffset = messageNext
			}
			b.writeEnvelope(w, r, tok, map[string]any{"rows": rows, "limit": limit, "offset": valueOffset, "has_more": false, "next_offset": -1, "complete": false, "source_message_ids": messageIDs, "message_offset": messageOffset, "tracking_offset": in.TrackingOffset, "may_have_more_messages": mayHaveMoreMessages, "next_message_offset": nextMessageOffset, "message_complete": messageComplete, "message_visible_total": messageTotal, "may_have_more_tracking": false}, 0)
			return
		}
	}
	if in.Kind == "download" {
		evidenceDomain = append(evidenceDomain, []any{"id", "=", in.AttachmentID})
		limit = 1
		in.Offset = 0
	}
	// The download domain pins one attachment id, so at most one row can
	// match: no probe is needed or taken there. Chatter walks its source
	// in order exactly like the tracking message window (same stripping,
	// same cardinality decision); tracking values (no _search override on
	// mail.tracking.value) and attachments (ir.attachment._search refills
	// filtered rows up to limit) keep the observed probe row over their
	// OWN offsets — values at tracking_offset, attachments at offset.
	// The probe is dropped before the response is built; every fetched
	// row bills the session below.
	fetchLimit := limit + 1
	fetchOffset := in.Offset
	if in.Kind == "download" {
		fetchLimit = 1
		fetchOffset = 0
	}
	fetched := 0
	chatterMore := false
	chatterNext := -1
	chatterComplete := false
	chatterTotal := 0
	if in.Kind == "chatter" {
		scan, ok := b.evidenceMessageScan(r, tok, reqID, w, evidenceDomain, in.Offset, limit)
		if !ok {
			return
		}
		examined += scan.fetched
		chatterTotal, ok = b.evidenceVisibleTotal(r, tok, reqID, w, evidenceDomain)
		if !ok {
			return
		}
		examined++
		chatterMore = len(scan.ids) < chatterTotal
		chatterNext = in.Offset + scan.consumed
		if !chatterMore {
			chatterNext = -1
		}
		chatterComplete = !chatterMore
		// The scan proved the visible window: fetch the full
		// projection for exactly its ids (pinned id domain, offset 0,
		// probe unnecessary — cardinality owns continuation).
		if len(scan.ids) > 0 {
			idList := make([]any, 0, len(scan.ids))
			for _, id := range scan.ids {
				idList = append(idList, id)
			}
			evidenceDomain = []any{[]any{"id", "in", idList}}
			fetchLimit = len(scan.ids)
		} else {
			fetchLimit = 0
		}
		fetchOffset = 0
	}
	rows, ok := []any{}, true
	if fetchLimit == 0 {
		rows = []any{}
	} else {
		fetchResult, fetchErr := b.evidenceExec(r, tok, source, fields, evidenceDomain, fetchLimit, fetchOffset)
		if fetchErr != nil {
			phase := evidencePhaseAttachmentMeta
			if in.Kind == "tracking" {
				phase = evidencePhaseTrackingValues
			}
			if in.Kind == "chatter" {
				phase = evidencePhaseMessages
			}
			b.evidenceError(w, r, phase, source, reqID, fetchErr)
			return
		}
		rows, ok = fetchResult.([]any)
	}
	if !ok || len(rows) > fetchLimit {
		b.writeError(w, r, http.StatusBadGateway, "invalid evidence response")
		return
	}
	// Continuation per kind: chatter uses its cardinality decision
	// (collected vs total; resume is the next unconsumed source
	// offset). Tracking values and attachments keep the observed probe
	// row over their own offsets (no stripping override / refill,
	// respectively). An empty window never proves exhaustion — only
	// the total does.
	fetched = len(rows)
	hasMore := fetched > limit
	if in.Kind == "chatter" {
		hasMore = chatterMore
	}
	if fetched > limit {
		rows = rows[:limit]
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
	// Session billing counts every fetched row: examined carries parent
	// (1) + count dispatches (1 each) + scan fetched rows, and fetched
	// carries this window's rows (probe included for tracking
	// values/attachments; chatter projection rows for the scan-proved
	// ids). The envelope count below stays len(rows) returned — a page
	// size, never the billed figure.
	b.settleRows(tok, reserved, fetched+examined)
	// Central success-payload redaction for linked evidence rows (HTML
	// descriptions, chatter bodies, attachment metadata): same marker and
	// scope as search/read via writeRows. Grant tokens never flow here.
	rows = toSanitizedRows(rows)
	// Every list kind shares one rows+metadata object: rows holds this
	// page (at most limit), count is len(rows) this page — a page size,
	// never a cursor or total. Exhaustion is a cardinality proof
	// (collected distinct ids >= visible_total), never a window shape:
	// an empty or short window is inconclusive, so has_more stays true
	// with a forward resume cursor and complete stays false. Callers
	// stop a walk when cumulative distinct ids >= visible_total.
	// Tracking stays two-dimensional: has_more/next_offset describe THIS
	// window's values (tracking_offset advances them);
	// may_have_more_messages plus next_message_offset describe the
	// message batches (offset advances those, tracking_offset resets to
	// 0). next_* is -1 only when its dimension is proven complete. The
	// legacy may_have_more_* keys stay for existing consumers.
	nextOffset := -1
	if hasMore {
		nextOffset = in.Offset + limit
	}
	paged := map[string]any{"rows": rows, "limit": limit, "offset": in.Offset, "has_more": hasMore, "next_offset": nextOffset}
	if in.Kind == "tracking" {
		nextMessageOffset := -1
		if mayHaveMoreMessages {
			nextMessageOffset = messageNext
		}
		paged["source_message_ids"] = messageIDs
		paged["message_offset"] = messageOffset
		paged["tracking_offset"] = in.TrackingOffset
		paged["may_have_more_messages"] = mayHaveMoreMessages
		paged["next_message_offset"] = nextMessageOffset
		paged["message_complete"] = messageComplete
		paged["message_visible_total"] = messageTotal
		paged["may_have_more_tracking"] = hasMore
		b.writeEnvelope(w, r, tok, paged, len(rows))
		return
	}
	if in.Kind == "chatter" {
		// next_offset is the next unconsumed SOURCE offset from
		// requested-based accounting (or -1 when cardinality proves
		// complete) — never offset+visible, which duplicates after
		// filtering. complete is true only when this page holds all
		// visible_total rows.
		nextOffset = chatterNext
		paged["next_offset"] = nextOffset
		paged["complete"] = chatterComplete
		paged["visible_total"] = chatterTotal
		paged["may_have_more_messages"] = hasMore
		paged["may_have_more_tracking"] = hasMore
		b.writeEnvelope(w, r, tok, paged, len(rows))
		return
	}
	if in.Kind == "attachments" {
		paged["may_have_more_messages"] = hasMore
		paged["may_have_more_tracking"] = hasMore
		b.writeEnvelope(w, r, tok, paged, len(rows))
		return
	}
	b.writeEnvelope(w, r, tok, rows, len(rows))
	return
}

// evidenceMessageScan collects up to limit VISIBLE mail.message ids by
// walking forward in source order from a source offset. Every page —
// there is no probe — goes through evidenceExec, so each inherits the
// session liveness checks, the cancellation-aware pacing wait, and the
// scoped kwargs (allowed_company_ids, company_id, active_test) with id
// asc: identical context to any other evidence fetch, never a bare
// dispatch. Stripped rows simply do not appear in a page.
//
// Source accounting uses REQUESTED rows only: each completed page
// consumes exactly its requested limit (SQL fills before stripping;
// a short page at source end merely overshoots the next offset past
// source end, which can only yield another — equally inconclusive —
// empty window, never a skip: any visible row inside a consumed range
// would have been returned). Visible counts NEVER enter the accounting,
// so continuation cannot duplicate or skip. Each page bills its fetched
// (visible) row count via fetched; dispatches are bounded by
// maxMessagePages — past that the window denies instead of scanning
// unboundedly (fail closed).
//
// The scan proves nothing about exhaustion on its own: an empty window
// may be fully stripped with visible rows past it, and a short page may
// hide more source past stripped rows. Exhaustion is decided by the
// caller via cardinality (distinct collected ids vs the paced visible
// total), never by window shape.
type messageScan struct {
	ids      []int
	consumed int
	fetched  int
}

func (b *Broker) evidenceMessageScan(r *http.Request, tok, reqID string, w http.ResponseWriter, window []any, offset, limit int) (messageScan, bool) {
	var out messageScan
	for page := 0; page < maxMessagePages; page++ {
		// Request only the remaining capacity: a prior sparse page
		// may have left room, and an over-wide request would
		// consume source rows whose visible ids fall past the page
		// and are then dropped (data loss). consumed advances by
		// the requested amount, so resume cursors stay exact.
		want := limit - len(out.ids)
		result, err := b.evidenceExec(r, tok, "mail.message", []string{"id"}, window, want, offset+out.consumed)
		if err != nil {
			b.evidenceError(w, r, evidencePhaseMessages, "mail.message", reqID, err)
			return out, false
		}
		rows, ok := result.([]any)
		if !ok || len(rows) > want {
			b.writeError(w, r, http.StatusBadGateway, "invalid linked message response")
			return out, false
		}
		out.fetched += len(rows)
		out.consumed += want
		for _, row := range rows {
			m, ok := row.(map[string]any)
			if !ok {
				b.writeError(w, r, http.StatusBadGateway, "invalid message row")
				return out, false
			}
			id, valid := evidenceInt(m["id"])
			if !valid || id <= 0 {
				b.writeError(w, r, http.StatusBadGateway, "invalid message identifier")
				return out, false
			}
			out.ids = append(out.ids, id)
			if len(out.ids) == limit {
				return out, true
			}
		}
		if len(rows) == 0 {
			// No visible rows in a full requested range: stop
			// scanning (further pages could still hold visible
			// rows past a fully-stripped range — the caller
			// reports incomplete, never exhausted, unless the
			// cardinality check proves otherwise).
			return out, true
		}
	}
	b.writeError(w, r, http.StatusBadRequest, "message window too sparse to page within budget; narrow the window or escalate to a human")
	return out, false
}

// evidenceVisibleTotal returns the post-filter visible total for one
// scoped evidence window through the SAME paced + scoped path as every
// other evidence fetch: session liveness, cancellation-aware pacing,
// and the scoped kwargs (company/archived context) ride along because
// the dispatch goes through evidenceCountExec, never a bare dispatch.
// search_count routes through the same model _search override, so the
// total and the window see identical filtering. One billed row.
// Errors map to the linked-evidence error contract under the messages
// phase; a malformed scalar denies instead of guessing.
func (b *Broker) evidenceVisibleTotal(r *http.Request, tok, reqID string, w http.ResponseWriter, window []any) (int, bool) {
	total, ok := b.evidenceCountExec(r, tok, reqID, w, window)
	if !ok {
		return 0, false
	}
	return total, true
}

// evidenceCountExec issues one search_count for the given window through
// the paced evidence path: live checks before and after the
// cancellation-aware pacing wait, scoped kwargs preserved (the company
// fragment, allowed_company_ids, company_id, active_test), then the
// single admitted dispatch. It is the count-only twin of evidenceExec:
// same pacing, same context, zero projected fields.
func (b *Broker) evidenceCountExec(r *http.Request, tok, reqID string, w http.ResponseWriter, window []any) (int, bool) {
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return 0, false
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
			b.checkError(w, r, r.Context().Err())
			return 0, false
		}
	}
	if err := b.live(tok); err != nil {
		b.checkError(w, r, err)
		return 0, false
	}
	domain, kwargs, err := b.scopedArgs(policy.ModelRule{CompanyIndependent: true}, window)
	if err != nil {
		b.writeError(w, r, http.StatusForbidden, "message scope unavailable")
		return 0, false
	}
	total, err := b.dispatchExec(r, "mail.message", "search_count", []any{domain}, kwargs)
	if err != nil {
		b.evidenceError(w, r, evidencePhaseMessages, "mail.message", reqID, err)
		return 0, false
	}
	n, ok := evidenceInt(total)
	if !ok {
		b.writeError(w, r, http.StatusBadGateway, "invalid evidence total")
		return 0, false
	}
	return n, true
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
//
// Provably distinguishable upstream causes classify without echo:
//   - pre-dispatch caller cancel (context.Canceled at the evidenceExec /
//     dispatchExec seams, with no DeadlineExceeded in the chain) is a
//     caller-side abort: status 499, category cancelled, not retryable;
//   - an exceeded deadline (context.DeadlineExceeded, including wrapped
//     broker RPC timeouts) is a timeout: 504/timeout, retryable with
//     backoff;
//   - an unreachable/broken transport (net errors: refused, reset, DNS,
//     timeout-kind) is a transport fault: 502/transport, retryable:false
//     (never guessed transient);
//   - an Odoo access denial (XML-RPC Fault code 4: the authenticated
//     user may not read the model at all) is an access fault:
//     403/access, retryable:false (retrying as the same user denies
//     identically; escalate scope/grants to a human);
//   - an undecodable 2xx body (capped JSON decode, XML syntax/unmarshal)
//     is a malformed response: 502/malformed, retryable:false;
//   - real RPC faults (server status codes, XML fault envelopes, json2
//     error members) are opaque server text: 502/unknown, retryable:false.
// Every failure emits one operator log line keyed by reqID (phase, model,
// category, status, upstream kind only — never the upstream message) so a
// human can correlate `req <id>` after the fact while the model envelope
// keeps reqID as today.
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
	// Caller abort vs deadline is provably distinguishable at the dispatch
	// seams: evidenceExec waits on r.Context().Done and dispatchExec /
	// callExec fail closed on ctx.Err() before dispatch, so Canceled with
	// no DeadlineExceeded in the chain means the caller went away — not
	// that the RPC timed out.
	if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		status = 499
		category = "cancelled"
		message = fmt.Sprintf("linked %s read cancelled for %s (req %s); retryable:false", phase, model, reqID)
	} else if errors.Is(err, context.DeadlineExceeded) || evidenceIsTimeoutErr(err) {
		// Socket/client-level timeouts that did not surface as
		// context.DeadlineExceeded (transports that do not bind ctx)
		// are still provably timeouts by TYPE (net.Error Timeout
		// flag) — never message text.
		status = http.StatusGatewayTimeout
		category = "timeout"
		retryable = true
		message = fmt.Sprintf("linked %s read timed out for %s (req %s); retryable:true with backoff", phase, model, reqID)
	} else if evidenceIsTransportErr(err) {
		// Transport breakage is distinguishable by error SHAPE (net
		// errors at the HTTP layer, before any server fault text) — but
		// its cause is not: refused vs reset vs DNS says nothing about
		// whether a retry would succeed, so retryable stays false.
		status = http.StatusBadGateway
		category = "transport"
		retryable = false
		message = fmt.Sprintf("linked %s read failed for %s (req %s); transport upstream; retryable:false", phase, model, reqID)
	} else if evidenceIsAccessErr(err) {
		// Odoo access denial (XML-RPC Fault(4) / AccessError: the
		// authenticated user may not read this model at all —
		// mail.tracking.value is Administration/Settings-only on the
		// investigated server). Proven by fault CODE via errors.As,
		// never message text. Not retryable: retrying the same read
		// as the same user denies identically; escalate to a human
		// for a scope or grants review.
		status = http.StatusForbidden
		category = "access"
		message = fmt.Sprintf("linked %s read denied for %s (req %s); upstream access denied, retryable:false — escalate scope/grants to a human", phase, model, reqID)
	} else if evidenceIsMalformedErr(err) {
		// Undecodable 2xx bodies are distinguishable by error shape
		// (capped JSON decode / XML syntax-unmarshal at the codec layer,
		// before any server fault text). A lying 200 must not be
		// blanket-retried as a transient RPC fault.
		status = http.StatusBadGateway
		category = "malformed"
		message = fmt.Sprintf("linked %s read failed for %s (req %s); malformed upstream; retryable:false", phase, model, reqID)
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
	// Operator diagnostic: one stderr line per evidence failure carrying
	// the correlation ID plus safe classification (phase/model/category/
	// status/upstream-kind). Upstream error TEXT is never logged here —
	// sanitizeErr-redacted faults may still carry server detail — only the
	// KIND (type/timeout flags) so `req <id>` correlates after the fact.
	log.New(os.Stderr, "evidence-error ", log.LstdFlags).Printf("req=%s phase=%s model=%s category=%s status=%d upstream=%s", reqID, phase, model, category, status, evidenceUpstreamKind(err))
	b.writeErrorMeta(w, r, status, message, map[string]any{
		"phase": phase, "model": model, "request_id": reqID,
		"category": category, "retryable": retryable, "status": status,
	})
}

// evidenceUpstreamKind names the safe upstream KIND for the operator log
// without touching error text: "cancelled", "timeout", "transport"
// (net/timeout-kind failures at the HTTP layer), "malformed" (capped
// JSON/XML decode or XML unmarshal of a 2xx body), "fault" (anything else
// that reached evidenceError — server status/fault text or an
// unclassified local error), or "none" (nil). It inspects types and
// timeout flags only, never messages, so credentials and RPC faults
// cannot leak through it.
func evidenceUpstreamKind(err error) string {
	if err == nil {
		return "none"
	}
	if errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
		return "cancelled"
	}
	if errors.Is(err, context.DeadlineExceeded) || evidenceIsTimeoutErr(err) {
		return "timeout"
	}
	var nerr net.Error
	if errors.As(err, &nerr) {
		// A net.Error that is not a timeout is HTTP-layer transport
		// breakage (refused, reset, DNS, closed connection): the error
		// crossed the transport before any server fault text existed.
		return "transport"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "transport"
	}
	if evidenceIsTransportErr(err) {
		return "transport"
	}
	if evidenceIsAccessErr(err) {
		return "access"
	}
	if evidenceIsMalformedErr(err) {
		return "malformed"
	}
	return "fault"
}

// evidenceIsTimeoutErr reports socket/client-level timeouts by TYPE
// (net.Error Timeout flag), without matching message text. These are
// transports that did not surface context.DeadlineExceeded but are
// provably timeouts all the same.
func evidenceIsTimeoutErr(err error) bool {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return true
	}
	return false
}
// evidenceIsTransportErr reports HTTP-layer transport breakage by TYPE,
// without matching message text: net errors at the HTTP layer (refused,
// reset, DNS, closed connection), *url.Error from the HTTP client (which
// wraps the transport fault beneath through the sanitized odoo error
func evidenceIsTransportErr(err error) bool {
	var nerr net.Error
	if errors.As(err, &nerr) {
		// Timeouts are classified before this probe ever runs
		// (evidenceIsTimeoutErr); any net.Error reaching here is
		// HTTP-layer breakage (refused, reset, DNS, closed conn).
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		return true
	}
	var rec tls.RecordHeaderError
	if errors.As(err, &rec) {
		return true
	}
	var tlsErr *tls.CertificateVerificationError
	if errors.As(err, &tlsErr) {
		return true
	}
	return false
}

// evidenceIsAccessErr reports Odoo access denials by fault CODE
// (xmlrpc.FaultError Code 4: AccessError / "not allowed to access"),
// via errors.As through the sanitized client wrap — never message text.
// A denied model stays denied for the same user, so callers must not
// retry as a transient fault.
func evidenceIsAccessErr(err error) bool {
	var fault xmlrpc.FaultError
	if errors.As(err, &fault) && fault.Code == 4 {
		return true
	}
	return false
}

// evidenceIsMalformedErr reports undecodable 2xx bodies by TYPE, without
// matching message text: *json.SyntaxError / unexpected-EOF
// (io.ErrUnexpectedEOF wrapped through decodeJSONCapped) for json2,
// *xml.SyntaxError for XML syntax, and kolo/xmlrpc TypeMismatchError for
// well-formed XML that does not fit the target. Server fault envelopes
// (xmlrpc.FaultError) and status-code faults are NOT malformed — they are
// real RPC faults and stay "fault"/unknown.
func evidenceIsMalformedErr(err error) bool {
	var syn *xml.SyntaxError
	if errors.As(err, &syn) {
		return true
	}
	var jsyn *json.SyntaxError
	if errors.As(err, &jsyn) {
		return true
	}
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var tm xmlrpc.TypeMismatchError
	if errors.As(err, &tm) {
		return true
	}
	return false
}
