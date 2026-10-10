package policy

import (
	"sort"
	"strings"
	"time"
)

// BoundedDomain is an admission guard, not a query-cost guarantee. It
// accepts only flat AND domains with a positive reference anchor or at
// most a 31-day date window. OR/NOT cannot hide an unbounded branch.
func BoundedDomain(domain any) bool {
	return BoundedDomainFor("", domain)
}

// modelAnchors lists reviewed per-model relational anchor fields beyond the
// generic ID/name/date anchors below. Each entry accepts ONLY `=` with a
// positive ID or `in` with 1..100 positive IDs on that model's field, under
// the same flat-AND/size/RPC limits. This is an admission control, not a
// query-cost guarantee. Narrow and reviewed: do not accept every
// relational field, generic OR/NOT, or arbitrary relationship traversal.
var modelAnchors = map[string]map[string]bool{
	"stock.rule":      {"route_id": true},
	"stock.move":      {"raw_material_production_id": true, "production_id": true, "workorder_id": true},
	"stock.move.line": {"production_id": true, "workorder_id": true},
	"mrp.workorder":   {"production_id": true, "operation_id": true},
}

// BoundedHint returns the accepted query shapes for model: its per-model
// anchor fields (if any), the generic anchors, and the 31-day date window.
// It names fields only — never values — so denial hints stay secret-free.
func BoundedHint(model string) string {
	base := "flat AND domain with a positive-ID anchor (= single ID or in <=100 IDs), an exact non-empty name/code/default_code/origin/client_order_ref/partner_ref (<=128 chars), or lower+upper bounds on the same date field spanning <=31 days"
	if anchors, ok := modelAnchors[model]; ok {
		fields := make([]string, 0, len(anchors))
		for f := range anchors {
			fields = append(fields, f)
		}
		sort.Strings(fields)
		return model + " also accepts " + strings.Join(fields, ", ") + " = positive ID or in <=100 positive IDs; " + base
	}
	return base
}

// BoundedDomainFor is the model-aware admission guard. With model == ""
// it behaves exactly as BoundedDomain always has.
func BoundedDomainFor(model string, domain any) bool {
	rows, ok := domain.([]any)
	if !ok || len(rows) == 0 || len(rows) > 64 {
		return false
	}
	anchor := false
	lower := map[string]time.Time{}
	upper := map[string]time.Time{}
	for _, raw := range rows {
		if op, ok := raw.(string); ok {
			if op != "&" {
				return false
			}
			continue
		}
		leaf, ok := raw.([]any)
		if !ok || len(leaf) != 3 {
			return false
		}
		field, _ := leaf[0].(string)
		op, _ := leaf[1].(string)
		if values, ok := leaf[2].([]any); ok && len(values) > 100 {
			return false
		}
		anchors := modelAnchors[model]
		if anchors[field] {
			if op == "=" && positiveID(leaf[2]) {
				anchor = true
			}
			if op == "in" {
				if ids, ok := leaf[2].([]any); ok && len(ids) > 0 && len(ids) <= 100 {
					good := true
					for _, id := range ids {
						good = good && positiveID(id)
					}
					anchor = anchor || good
				}
			}
			continue
		}
		switch field {
		case "id", "product_id", "product_tmpl_id", "bom_id", "order_id", "picking_id", "move_id", "sale_line_id", "purchase_line_id":
			if op == "=" && positiveID(leaf[2]) {
				anchor = true
			}
			if op == "in" {
				if ids, ok := leaf[2].([]any); ok && len(ids) > 0 && len(ids) <= 100 {
					good := true
					for _, id := range ids {
						good = good && positiveID(id)
					}
					anchor = anchor || good
				}
			}
		case "name", "code", "default_code", "origin", "client_order_ref", "partner_ref":
			if value, ok := leaf[2].(string); ok && value != "" && len(value) <= 128 && op == "=" {
				anchor = true
			}
		case "date", "create_date", "write_date", "date_order", "date_done", "scheduled_date", "date_planned":
			if value, ok := leaf[2].(string); ok {
				var t time.Time
				var err error
				for _, layout := range []string{"2006-01-02", "2006-01-02 15:04:05", time.RFC3339} {
					t, err = time.Parse(layout, value)
					if err == nil {
						break
					}
				}
				if err == nil {
					if op == ">=" || op == ">" {
						lower[field] = t
					}
					if op == "<=" || op == "<" {
						upper[field] = t
					}
				}
			}
		}
	}
	if anchor {
		return true
	}
	for field, start := range lower {
		if end, ok := upper[field]; ok && !end.Before(start) && end.Sub(start) <= 31*24*time.Hour {
			return true
		}
	}
	return false
}

func positiveID(v any) bool {
	switch x := v.(type) {
	case int:
		return x > 0
	case int64:
		return x > 0
	case float64:
		return x > 0 && x <= 9007199254740991 && x == float64(int64(x))
	}
	return false
}
