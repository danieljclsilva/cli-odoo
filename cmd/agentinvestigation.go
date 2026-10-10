package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/odoo"
)

type investigationModel struct {
	name                          string
	shared, independent, evidence bool
}

func investigationModels() []investigationModel {
	var out []investigationModel
	for _, name := range []string{
		"helpdesk.ticket", "helpdesk.team", "stock.picking", "stock.move", "stock.move.line", "stock.quant", "stock.picking.type", "stock.warehouse", "stock.lot",
		"sale.order", "sale.order.line", "purchase.order", "purchase.order.line",
		"mrp.production", "mrp.workorder", "mrp.workcenter", "mrp.routing.workcenter",
		"account.move", "account.move.line", "account.account", "account.journal", "account.tax",
	} {
		out = append(out, investigationModel{name: name})
	}
	for _, name := range []string{"product.template", "product.product", "mrp.bom", "mrp.bom.line", "mrp.bom.byproduct", "stock.location", "stock.route", "stock.rule", "ir.sequence", "product.pricelist", "product.pricelist.item", "res.partner", "product.template.attribute.line", "product.template.attribute.value"} {
		out = append(out, investigationModel{name: name, shared: true})
	}
	for _, name := range []string{"uom.uom", "uom.category", "product.category", "product.attribute", "product.attribute.value", "helpdesk.stage"} {
		out = append(out, investigationModel{name: name, independent: true})
	}
	for _, name := range []string{"mail.message", "mail.tracking.value", "ir.attachment"} {
		out = append(out, investigationModel{name: name, evidence: true})
	}
	return out
}

// Human setup reads bounded metadata only. The model never controls these
// discovery queries. Unknown optional modules are reported, not substituted.
func agentDiscoverInvestigation(cli *odoo.Client, extra []string) ([]snapshot.ModelSpec, map[string]map[string]snapshot.SFieldMeta, []string, error) {
	defs := investigationModels()
	seen := map[string]bool{}
	names := []any{}
	for _, d := range defs {
		seen[d.name] = true
		names = append(names, d.name)
	}
	for _, name := range extra {
		if norm, ok := policy.NormalizeName(name); !ok || norm != name || strings.HasPrefix(name, "ir.") || strings.HasPrefix(name, "mail.") || strings.HasPrefix(name, "base.") || name == "res.users" || name == "res.config.settings" {
			return nil, nil, nil, fmt.Errorf("--include-model requires a canonical business model name; admin/credential/evidence namespaces are excluded")
		}
		if !seen[name] {
			defs = append(defs, investigationModel{name: name})
			names = append(names, name)
			seen[name] = true
		}
	}
	if len(defs) > 64 {
		return nil, nil, nil, fmt.Errorf("investigation supports at most 64 models")
	}
	got, err := cli.Execute("ir.model", "search_read", []any{[]any{[]any{"model", "in", names}}, []any{"model"}}, map[string]any{"limit": 65})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("investigation model discovery: %w", err)
	}
	rows, ok := got.([]any)
	if !ok {
		return nil, nil, nil, fmt.Errorf("invalid model metadata response")
	}
	installed := map[string]bool{}
	for _, row := range rows {
		r, ok := row.(map[string]any)
		if !ok {
			return nil, nil, nil, fmt.Errorf("invalid model metadata row")
		}
		n, _ := r["model"].(string)
		if seen[n] {
			installed[n] = true
		}
	}
	got, err = cli.Execute("ir.model.fields", "search_read", []any{[]any{[]any{"model", "in", names}}, []any{"model", "name", "ttype", "relation", "store"}}, map[string]any{"limit": 8193, "order": "id asc"})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("investigation field discovery: %w", err)
	}
	rows, ok = got.([]any)
	if !ok || len(rows) > 8192 {
		return nil, nil, nil, fmt.Errorf("invalid or over-cap field metadata response (8192 fields maximum)")
	}
	specs, metadata, notes, err := agentCompileInvestigation(defs, installed, rows, extra)
	if err != nil {
		return nil, nil, nil, err
	}
	// The registry can contain stale fields or fields hidden from this
	// account. Resolve the actual proposal before human confirmation.
	for i, sp := range specs {
		names := []string{"id"}
		for name := range metadata[sp.Name] {
			names = appendIfMissing(names, name)
		}
		sort.Strings(names)
		args := make([]any, len(names))
		for j, name := range names {
			args[j] = name
		}
		got, err := cli.Execute(sp.Name, "fields_get", []any{args}, map[string]any{"attributes": []any{"type", "relation", "string"}})
		if err != nil {
			return nil, nil, nil, fmt.Errorf("investigation live metadata %s: %w", sp.Name, err)
		}
		live, ok := got.(map[string]any)
		if !ok {
			return nil, nil, nil, fmt.Errorf("invalid live metadata response for %s", sp.Name)
		}
		clean, advisory, omitted, err := agentReconcileInvestigation(sp, metadata[sp.Name], live)
		if err != nil {
			return nil, nil, nil, err
		}
		specs[i], metadata[sp.Name] = clean, advisory
		if len(omitted) > 0 {
			notes = append(notes, fmt.Sprintf("not enabled (unavailable or changed live fields): %s: %s", sp.Name, strings.Join(omitted, ", ")))
		}
	}
	return specs, metadata, notes, nil
}

func investigationEvidenceRequirements(model string) map[string]string {
	return map[string]map[string]string{
		"mail.message":        {"model": "char", "res_id": "integer"},
		"mail.tracking.value": {"mail_message_id": "many2one"},
		"ir.attachment":       {"res_model": "char", "res_id": "integer", "file_size": "integer", "type": "selection", "datas": "binary"},
	}[model]
}

// Pure proposal reconciliation, not an emulation of Odoo behavior. Never
// adds permissions; unavailable optional fields are removed, and missing
// or changed structural/security fields abort the entire setup.
func agentReconcileInvestigation(sp snapshot.ModelSpec, metadata map[string]snapshot.SFieldMeta, live map[string]any) (snapshot.ModelSpec, map[string]snapshot.SFieldMeta, []string, error) {
	required := map[string]bool{"id": true}
	if sp.CompanyField != "" {
		name, _, _ := strings.Cut(sp.CompanyField, ".")
		required[name] = true
	}
	for name := range investigationEvidenceRequirements(sp.Name) {
		required[name] = true
	}
	available := func(name string) bool {
		field, ok := live[name].(map[string]any)
		if !ok {
			return false
		}
		typ, _ := field["type"].(string)
		relation, _ := field["relation"].(string)
		if name == "id" {
			return typ == "integer"
		}
		previous, ok := metadata[name]
		return ok && typ != "" && typ == previous.Type && relation == previous.Relation
	}
	for name := range required {
		if !available(name) {
			return sp, nil, nil, fmt.Errorf("required live metadata unavailable or changed: %s.%s", sp.Name, name)
		}
	}
	fields := []string{}
	omitted := []string{}
	for _, name := range sp.Fields {
		if available(name) {
			fields = append(fields, name)
		} else {
			omitted = append(omitted, name)
		}
	}
	advisory := map[string]snapshot.SFieldMeta{}
	for name, meta := range metadata {
		if available(name) {
			advisory[name] = meta
		}
	}
	sp.Fields = fields
	sort.Strings(omitted)
	return sp, advisory, omitted, nil
}

func agentCompileInvestigation(defs []investigationModel, installed map[string]bool, rows []any, requested []string) ([]snapshot.ModelSpec, map[string]map[string]snapshot.SFieldMeta, []string, error) {
	metadata := map[string]map[string]snapshot.SFieldMeta{}
	approved := map[string][]string{}
	for _, raw := range rows {
		r, ok := raw.(map[string]any)
		if !ok {
			return nil, nil, nil, fmt.Errorf("invalid field metadata row")
		}
		model, _ := r["model"].(string)
		name, _ := r["name"].(string)
		typ, _ := r["ttype"].(string)
		relation, _ := r["relation"].(string)
		if !installed[model] {
			continue
		}
		if norm, ok := policy.NormalizeName(name); !ok || norm != name || strings.Contains(name, ".") {
			return nil, nil, nil, fmt.Errorf("invalid field metadata name")
		}
		if metadata[model] == nil {
			metadata[model] = map[string]snapshot.SFieldMeta{}
		}
		if _, dup := metadata[model][name]; dup {
			return nil, nil, nil, fmt.Errorf("duplicate field metadata %s.%s", model, name)
		}
		metadata[model][name] = snapshot.SFieldMeta{Name: name, Label: name, Type: typ, Relation: relation, Provenance: snapshot.ProvServer}
		stored, _ := r["store"].(bool)
		if investigationReadableField(name, typ, stored) {
			approved[model] = append(approved[model], name)
		}
	}
	specs := []snapshot.ModelSpec{}
	notes := []string{}
	for _, d := range defs {
		if !installed[d.name] {
			notes = append(notes, "not installed: "+d.name)
			continue
		}
		fields := approved[d.name]
		fields = appendIfMissing(fields, "id")
		// Company fields must be inspected even when related/nonstored; they
		// are required for server-side company filtering, never inferred.
		companyField := "company_id"
		cf := metadata[d.name][companyField]
		if d.name == "product.template.attribute.line" || d.name == "product.template.attribute.value" {
			cf = metadata[d.name]["product_tmpl_id"]
			if cf.Type == "many2one" && cf.Relation == "product.template" {
				companyField = "product_tmpl_id.company_id"
				cf = snapshot.SFieldMeta{Type: "many2one", Relation: "res.company"}
			}
		}
		if !d.independent && !d.evidence && (cf.Type != "many2one" || cf.Relation != "res.company") {
			notes = append(notes, "not enabled (no direct company scope): "+d.name)
			continue
		}
		if !d.independent && !d.evidence {
			field, _, _ := strings.Cut(companyField, ".")
			fields = appendIfMissing(fields, field)
		}
		if d.evidence {
			required := investigationEvidenceRequirements(d.name)
			for name, typ := range required {
				f := metadata[d.name][name]
				// Odoo 17 exposes these numeric parent IDs as
				// Many2oneReference, paired with model/res_model. Integer
				// fields are also compatible with the same exact ID domain.
				parentID := name == "res_id" && (d.name == "mail.message" || d.name == "ir.attachment") && f.Type == "many2one_reference"
				if (f.Type != typ && !parentID) || (name == "mail_message_id" && f.Relation != "mail.message") {
					return nil, nil, nil, fmt.Errorf("unusable evidence linkage metadata: %s.%s (type %q)", d.name, name, f.Type)
				}
			}
			wanted := map[string][]string{
				"mail.message":        {"id", "model", "res_id", "date", "subject", "body", "author_id", "message_type", "subtype_id", "tracking_value_ids", "attachment_ids"},
				"mail.tracking.value": {"id", "mail_message_id", "field_id", "field_desc", "old_value_char", "new_value_char", "old_value_text", "new_value_text", "old_value_integer", "new_value_integer", "old_value_float", "new_value_float", "old_value_datetime", "new_value_datetime"},
				"ir.attachment":       {"id", "res_model", "res_id", "res_field", "name", "mimetype", "file_size", "type", "datas"},
			}[d.name]
			fields = nil
			for _, f := range wanted {
				if _, ok := metadata[d.name][f]; ok {
					fields = append(fields, f)
				}
			}
			if len(fields) == 0 {
				return nil, nil, nil, fmt.Errorf("missing evidence metadata: %s", d.name)
			}
		}
		sort.Strings(fields)
		sp := snapshot.ModelSpec{Name: d.name, Label: d.name, Fields: fields, CompanyIndependent: d.independent, IncludeCompanyless: d.shared, AllowAggregate: !d.independent && !d.evidence}
		if !d.independent && !d.evidence {
			sp.CompanyField = companyField
		}
		specs = append(specs, sp)
	}
	enabled := map[string]bool{}
	for _, sp := range specs {
		enabled[sp.Name] = true
	}
	for _, n := range append([]string{"product.product", "product.template"}, requested...) {
		if !enabled[n] {
			return nil, nil, nil, fmt.Errorf("required model %s unavailable or company scope cannot be enforced", n)
		}
	}
	notes = append(notes, "Nonstored/computed and secret-like business fields are metadata only. Binary fields are not generic projections; field-backed worksheets/artwork use parent-linked attachments with an explicit field selector when ir.attachment.res_field is approved (5 MiB download cap).")
	return specs, metadata, notes, nil
}

func appendIfMissing(fields []string, name string) []string {
	for _, f := range fields {
		if f == name {
			return fields
		}
	}
	return append(fields, name)
}

func investigationReadableField(name, typ string, stored bool) bool {
	if policy.IsSecretField(name) {
		return false
	}
	if !stored {
		return false
	}
	switch typ {
	case "boolean", "integer", "float", "monetary", "char", "text", "html", "date", "datetime", "selection", "many2one", "many2many", "json", "properties", "properties_definition":
		return true
	}
	return false
}
