package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/output"
)

func init() {
	RootCmd.AddCommand(newDqCheckCmd())
	RootCmd.AddCommand(newKbSearchCmd())
}

// opsPackIsNull reports unset values. Relational empty (false) counts as
// null only when the field is relational; plain booleans never do.
func opsPackIsNull(v any, relational bool) bool {
	if v == nil {
		return true
	}
	switch t := v.(type) {
	case string:
		return t == ""
	case bool:
		return relational && !t
	case []any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	default:
		return false
	}
}

// opsPackValueKey returns a stable grouping key for duplicate detection.
func opsPackValueKey(v any) string {
	switch t := v.(type) {
	case nil:
		return "nil"
	case string:
		return "s:" + t
	case bool:
		return fmt.Sprintf("b:%v", t)
	default:
		if f, ok := opsPackFloat(v); ok {
			return fmt.Sprintf("n:%v", f)
		}
		return fmt.Sprintf("v:%v", v)
	}
}

func newDqCheckCmd() *cobra.Command {
	var fieldsCSV string
	var limit int
	c := &cobra.Command{
		Use:   "dq-check <model>",
		Short: "Scan records for nulls and duplicates (client-side, bounded)",
		Long: `Fetch up to --limit records via search_read (Odoo 17 safe) and scan the
given --fields (default: all fields from fields_get) for null/empty values
and duplicate values, client-side. Duplicate examples are capped at 10 per field.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "data_quality"
			model := args[0]
			if limit <= 0 {
				limit = 100
			}
			if limit > 1000 {
				limit = 1000
			}
			client, _, err := opsPackClient()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			var fields []string
			if strings.TrimSpace(fieldsCSV) != "" {
				for _, f := range strings.Split(fieldsCSV, ",") {
					if f = strings.TrimSpace(f); f != "" {
						fields = append(fields, f)
					}
				}
			}
			// Field types inform null semantics (relational false == unset).
			types := map[string]string{}
			fg, err := client.Execute(model, "fields_get", []any{[]any{}}, map[string]any{"attributes": []any{"type"}})
			if err != nil {
				if len(fields) == 0 {
					output.Fail(tool, fmt.Errorf("fields_get %s: %w (pass --fields to skip discovery)", model, err))
					return
				}
			} else if m, ok := fg.(map[string]any); ok {
				if len(fields) == 0 {
					for name := range m {
						if name == "id" {
							continue
						}
						fields = append(fields, name)
					}
					sort.Strings(fields)
				}
				for name, meta := range m {
					if mm, ok := meta.(map[string]any); ok {
						types[name] = opsPackStr(mm["type"])
					}
				}
			} else if len(fields) == 0 {
				output.Fail(tool, fmt.Errorf("unexpected fields_get response"))
				return
			}
			if len(fields) == 0 {
				output.Fail(tool, fmt.Errorf("no fields to scan"))
				return
			}
			fieldArgs := make([]any, 0, len(fields))
			for _, f := range fields {
				fieldArgs = append(fieldArgs, f)
			}
			res, err := client.Execute(model, "search_read", []any{[]any{}}, map[string]any{
				"fields": fieldArgs,
				"limit":  limit,
				"offset": 0,
				"order":  "id",
			})
			if err != nil {
				output.Fail(tool, err)
				return
			}
			rows := opsPackRows(res)
			sampled := len(rows)
			isRelational := func(t string) bool {
				return t == "many2one" || t == "one2many" || t == "many2many" || t == "reference"
			}
			fieldStats := map[string]any{}
			var withNulls, withDups int
			for _, f := range fields {
				rel := isRelational(types[f])
				nulls := 0
				counts := map[string]int{}
				examples := map[string]any{}
				for _, r := range rows {
					v, present := r[f]
					if !present || opsPackIsNull(v, rel) {
						nulls++
						continue
					}
					k := opsPackValueKey(v)
					counts[k]++
					if _, ok := examples[k]; !ok {
						examples[k] = v
					}
				}
				type dupT struct {
					key   string
					value any
					count int
				}
				var dups []dupT
				for k, n := range counts {
					if n > 1 {
						dups = append(dups, dupT{key: k, value: examples[k], count: n})
					}
				}
				sort.Slice(dups, func(i, j int) bool {
					if dups[i].count != dups[j].count {
						return dups[i].count > dups[j].count
					}
					return dups[i].key < dups[j].key
				})
				if len(dups) > 10 {
					dups = dups[:10]
				}
				dupList := make([]map[string]any, 0, len(dups))
				for _, d := range dups {
					dupList = append(dupList, map[string]any{"value": d.value, "count": d.count})
				}
				ratio := 0.0
				if sampled > 0 {
					ratio = float64(nulls) / float64(sampled)
				}
				if nulls > 0 {
					withNulls++
				}
				if len(dups) > 0 {
					withDups++
				}
				fieldStats[f] = map[string]any{
					"null_count":      nulls,
					"null_ratio":      ratio,
					"distinct":        len(counts),
					"duplicate_count": len(dups),
					"duplicates":      dupList,
				}
			}
			output.Ok(tool, map[string]any{
				"model":   model,
				"sampled": sampled,
				"limit":   limit,
				"fields":  fieldStats,
				"summary": map[string]any{
					"total_fields":           len(fields),
					"fields_with_nulls":      withNulls,
					"fields_with_duplicates": withDups,
				},
			}, sampled)
		},
	}
	c.Flags().StringVar(&fieldsCSV, "fields", "", "comma-separated fields to scan (default: all fields from fields_get)")
	c.Flags().IntVar(&limit, "limit", 100, "max records to scan (capped at 1000)")
	return c
}

func newKbSearchCmd() *cobra.Command {
	var query string
	var limit int
	c := &cobra.Command{
		Use:   "kb-search <model>",
		Short: "Fuzzy search a model over name/display_name/email/phone",
		Long: `Search a model via name_search plus a search_read OR-domain over the
text fields that exist (name/display_name/email/phone), using only Odoo
17-safe methods. name_search-only hits are merged in via read.`,
		Args: cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "search_knowledge"
			model := args[0]
			q := strings.TrimSpace(query)
			if q == "" {
				output.Fail(tool, fmt.Errorf("missing --query"))
				return
			}
			if limit <= 0 {
				limit = 10
			}
			if limit > 100 {
				limit = 100
			}
			client, _, err := opsPackClient()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			fg, err := client.Execute(model, "fields_get", []any{[]any{}}, map[string]any{"attributes": []any{"type", "string"}})
			if err != nil {
				output.Fail(tool, err)
				return
			}
			meta, ok := fg.(map[string]any)
			if !ok {
				output.Fail(tool, fmt.Errorf("unexpected fields_get response"))
				return
			}
			candidates := []string{"name", "display_name", "email", "phone"}
			var textFields []string
			for _, f := range candidates {
				if _, ok := meta[f]; ok {
					textFields = append(textFields, f)
				}
			}
			var nsIDs []int64
			if ns, err := client.Execute(model, "name_search", []any{q}, map[string]any{"limit": limit}); err == nil {
				nsIDs = opsPackIDsFromNameSearch(ns)
			}
			var conds []any
			for _, f := range textFields {
				conds = append(conds, []any{f, "ilike", q})
			}
			domain := opsPackOr(conds)
			if len(nsIDs) > 0 {
				idsAny := make([]any, 0, len(nsIDs))
				for _, id := range nsIDs {
					idsAny = append(idsAny, id)
				}
				if len(domain) == 0 {
					domain = []any{[]any{"id", "in", idsAny}}
				} else {
					combined := make([]any, 0, len(domain)+2)
					combined = append(combined, "|", []any{"id", "in", idsAny})
					combined = append(combined, domain...)
					domain = combined
				}
			}
			if len(domain) == 0 {
				output.Ok(tool, map[string]any{"model": model, "query": q, "results": []any{}}, 0)
				return
			}
			var show []string
			for _, f := range candidates {
				if _, ok := meta[f]; ok {
					show = append(show, f)
				}
			}
			kwargs := map[string]any{"limit": limit, "offset": 0}
			if len(show) > 0 {
				fa := make([]any, 0, len(show))
				for _, f := range show {
					fa = append(fa, f)
				}
				kwargs["fields"] = fa
			}
			sr, err := client.Execute(model, "search_read", []any{domain}, kwargs)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			results := opsPackRows(sr)
			seen := map[int64]bool{}
			for _, r := range results {
				if id, ok := opsPackInt(r["id"]); ok {
					seen[id] = true
				}
			}
			var missing []any
			for _, id := range nsIDs {
				if !seen[id] {
					missing = append(missing, id)
				}
			}
			if len(missing) > 0 {
				var rd any
				if len(show) > 0 {
					rf := make([]any, 0, len(show))
					for _, f := range show {
						rf = append(rf, f)
					}
					rd, err = client.Execute(model, "read", []any{missing, rf}, nil)
				} else {
					rd, err = client.Execute(model, "read", []any{missing}, nil)
				}
				if err == nil {
					results = append(results, opsPackRows(rd)...)
				}
			}
			if len(results) > limit {
				results = results[:limit]
			}
			out := make([]any, 0, len(results))
			for _, r := range results {
				out = append(out, r)
			}
			output.Ok(tool, map[string]any{"model": model, "query": q, "results": out}, len(out))
		},
	}
	c.Flags().StringVar(&query, "query", "", "search text (required)")
	c.Flags().IntVar(&limit, "limit", 10, "max results (capped at 100)")
	return c
}
