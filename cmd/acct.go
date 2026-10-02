package cmd

import (
	"math"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/KomoriNoKage/cli-odoo/internal/odoo"
	"github.com/KomoriNoKage/cli-odoo/internal/output"
)

func init() {
	RootCmd.AddCommand(newAgingCmd())
	RootCmd.AddCommand(newAcctHealthCmd())
}

// opsPackReadGroup runs an Odoo 17-safe read_group and normalizes the rows.
func opsPackReadGroup(client *odoo.Client, model string, domain []any, fields, groupby []any, limit int) ([]map[string]any, error) {
	kwargs := map[string]any{"lazy": false}
	if limit > 0 {
		kwargs["limit"] = limit
	}
	res, err := client.Execute(model, "read_group", []any{domain, fields, groupby}, kwargs)
	if err != nil {
		return nil, err
	}
	return opsPackRows(res), nil
}

// opsPackAgingAgg accumulates per-partner receivable/payable totals.
type opsPackAgingAgg struct {
	id    int64
	name  string
	recv  float64
	pay   float64
	lines int64
}

// opsPackMergeAging merges receivable and payable read_group rows by partner.
func opsPackMergeAging(recv, pay []map[string]any) []map[string]any {
	agg := map[int64]*opsPackAgingAgg{}
	add := func(rows []map[string]any, side string) {
		for _, r := range rows {
			id, name, ok := opsPackPairID(r["partner_id"])
			if !ok {
				id = 0
				name = "(no partner)"
			}
			a := agg[id]
			if a == nil {
				a = &opsPackAgingAgg{id: id, name: name}
				agg[id] = a
			}
			if a.name == "" || a.name == "(no partner)" {
				a.name = name
			}
			amt, _ := opsPackFloat(r["amount_residual"])
			if amt == 0 {
				amt, _ = opsPackFloat(r["balance"])
			}
			if side == "pay" {
				a.pay += math.Abs(amt)
			} else {
				a.recv += amt
			}
			if n, ok := opsPackInt(r["__count"]); ok {
				a.lines += n
			} else {
				a.lines++
			}
		}
	}
	add(recv, "recv")
	add(pay, "pay")
	rows := make([]map[string]any, 0, len(agg))
	for _, a := range agg {
		rows = append(rows, map[string]any{
			"partner_id":   a.id,
			"partner_name": a.name,
			"receivable":   a.recv,
			"payable":      a.pay,
			"net":          a.recv - a.pay,
			"lines":        a.lines,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return opsPackStr(rows[i]["partner_name"]) < opsPackStr(rows[j]["partner_name"])
	})
	return rows
}

// opsPackAgingFallback groups unreconciled lines client-side via search_read
// plus an account_type lookup when the read_group path is unavailable.
func opsPackAgingFallback(client *odoo.Client, domain []any, limit int) ([]map[string]any, error) {
	res, err := client.Execute("account.move.line", "search_read", []any{domain}, map[string]any{
		"fields": []any{"partner_id", "account_id", "amount_residual", "balance"},
		"limit":  limit,
		"offset": 0,
	})
	if err != nil {
		return nil, err
	}
	type lineT struct {
		pid      int64
		pname    string
		aid      int64
		residual float64
	}
	parsed := []lineT{}
	seen := map[int64]bool{}
	var accIDs []any
	for _, r := range opsPackRows(res) {
		pid, pname, _ := opsPackPairID(r["partner_id"])
		aid, _, ok := opsPackPairID(r["account_id"])
		if !ok {
			continue
		}
		amt, _ := opsPackFloat(r["amount_residual"])
		if amt == 0 {
			amt, _ = opsPackFloat(r["balance"])
		}
		parsed = append(parsed, lineT{pid: pid, pname: pname, aid: aid, residual: amt})
		if !seen[aid] {
			seen[aid] = true
			accIDs = append(accIDs, aid)
		}
	}
	accType := map[int64]string{}
	if len(accIDs) > 0 {
		accs, err := client.Execute("account.account", "read", []any{accIDs, []any{"account_type"}}, nil)
		if err != nil {
			return nil, err
		}
		for _, a := range opsPackRows(accs) {
			id, ok := opsPackInt(a["id"])
			if !ok {
				continue
			}
			accType[id] = opsPackStr(a["account_type"])
		}
	}
	agg := map[int64]*opsPackAgingAgg{}
	for _, l := range parsed {
		var side string
		switch accType[l.aid] {
		case "asset_receivable":
			side = "recv"
		case "liability_payable":
			side = "pay"
		default:
			continue
		}
		a := agg[l.pid]
		if a == nil {
			name := l.pname
			if name == "" {
				name = "(no partner)"
			}
			a = &opsPackAgingAgg{id: l.pid, name: name}
			agg[l.pid] = a
		}
		if side == "pay" {
			a.pay += math.Abs(l.residual)
		} else {
			a.recv += l.residual
		}
		a.lines++
	}
	rows := make([]map[string]any, 0, len(agg))
	for _, a := range agg {
		rows = append(rows, map[string]any{
			"partner_id":   a.id,
			"partner_name": a.name,
			"receivable":   a.recv,
			"payable":      a.pay,
			"net":          a.recv - a.pay,
			"lines":        a.lines,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		return opsPackStr(rows[i]["partner_name"]) < opsPackStr(rows[j]["partner_name"])
	})
	return rows, nil
}

func newAgingCmd() *cobra.Command {
	var partnerID int
	var overdueOnly bool
	var limit int
	c := &cobra.Command{
		Use:   "aging",
		Short: "Receivable/payable aging grouped by partner (read_group)",
		Long: `Summarize open receivable/payable lines grouped by partner using read_group
(Odoo 17 safe; falls back to search_read with client-side grouping).`,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "receivable_payable_aging"
			if limit <= 0 {
				limit = 200
			}
			client, _, err := opsPackClient()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			base := []any{
				[]any{"reconciled", "=", false},
				[]any{"parent_state", "=", "posted"},
			}
			filters := map[string]any{"overdue_only": overdueOnly}
			if partnerID != 0 {
				base = append(base, []any{"partner_id", "=", partnerID})
				filters["partner_id"] = partnerID
			}
			if overdueOnly {
				today := time.Now().Format("2006-01-02")
				base = append(base,
					[]any{"date_maturity", "!=", false},
					[]any{"date_maturity", "<", today},
				)
				filters["maturity_before"] = today
			}
			withType := func(t string) []any {
				d := make([]any, 0, len(base)+1)
				d = append(d, base...)
				return append(d, []any{"account_id.account_type", "=", t})
			}
			recv, errRecv := opsPackReadGroup(client, "account.move.line",
				withType("asset_receivable"), []any{"amount_residual", "balance"}, []any{"partner_id"}, limit)
			pay, errPay := opsPackReadGroup(client, "account.move.line",
				withType("liability_payable"), []any{"amount_residual", "balance"}, []any{"partner_id"}, limit)
			var rows []map[string]any
			if errRecv != nil || errPay != nil {
				r, fberr := opsPackAgingFallback(client, base, limit)
				if fberr != nil {
					if errRecv != nil {
						output.Fail(tool, errRecv)
					} else {
						output.Fail(tool, errPay)
					}
					return
				}
				rows = r
			} else {
				rows = opsPackMergeAging(recv, pay)
			}
			var totRecv, totPay float64
			for _, r := range rows {
				if v, ok := opsPackFloat(r["receivable"]); ok {
					totRecv += v
				}
				if v, ok := opsPackFloat(r["payable"]); ok {
					totPay += v
				}
			}
			output.Ok(tool, map[string]any{
				"partners": rows,
				"totals": map[string]any{
					"receivable": totRecv,
					"payable":    totPay,
					"partners":   len(rows),
				},
				"filters": filters,
			}, len(rows))
		},
	}
	c.Flags().IntVar(&partnerID, "partner-id", 0, "restrict to one partner id")
	c.Flags().BoolVar(&overdueOnly, "overdue-only", false, "only lines past their maturity date")
	c.Flags().IntVar(&limit, "limit", 200, "max groups (read_group) or lines (fallback) to scan")
	return c
}

func newAcctHealthCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "acct-health",
		Short: "Unreconciled totals plus a tax configuration summary",
		Long: `Summarize accounting health using only search_read/read_group (Odoo 17 safe):
open receivable/payable residuals plus an account.tax configuration review.`,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "accounting_health_summary"
			client, _, err := opsPackClient()
			if err != nil {
				output.Fail(tool, err)
				return
			}
			open := func(accountType string, absolute bool) (map[string]any, error) {
				rows, err := opsPackReadGroup(client, "account.move.line",
					[]any{
						[]any{"reconciled", "=", false},
						[]any{"parent_state", "=", "posted"},
						[]any{"account_id.account_type", "=", accountType},
					},
					[]any{"amount_residual", "balance"}, []any{}, 0)
				if err != nil {
					return nil, err
				}
				out := map[string]any{"open_lines": int64(0), "residual": 0.0}
				if len(rows) > 0 {
					if n, ok := opsPackInt(rows[0]["__count"]); ok {
						out["open_lines"] = n
					}
					if v, ok := opsPackFloat(rows[0]["amount_residual"]); ok {
						out["residual"] = v
					} else if v, ok := opsPackFloat(rows[0]["balance"]); ok {
						out["residual"] = v
					}
					if absolute {
						out["residual"] = math.Abs(out["residual"].(float64))
					}
				}
				return out, nil
			}
			recv, err := open("asset_receivable", false)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			pay, err := open("liability_payable", true)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			taxRes, err := client.Execute("account.tax", "search_read", []any{[]any{}}, map[string]any{
				"fields": []any{"name", "amount", "type_tax_use", "active", "company_id"},
				"limit":  100,
				"offset": 0,
				"order":  "id",
			})
			if err != nil {
				output.Fail(tool, err)
				return
			}
			taxes := opsPackRows(taxRes)
			byUse := map[string]int64{}
			zeroRate := []string{}
			var inactive int64
			records := make([]map[string]any, 0, len(taxes))
			for _, t := range taxes {
				use := opsPackStr(t["type_tax_use"])
				byUse[use]++
				active := true
				if b, ok := t["active"].(bool); ok {
					active = b
				}
				if !active {
					inactive++
				}
				amt, _ := opsPackFloat(t["amount"])
				if amt == 0 {
					zeroRate = append(zeroRate, opsPackStr(t["name"]))
				}
				company := ""
				if _, cname, ok := opsPackPairID(t["company_id"]); ok {
					company = cname
				} else {
					company = opsPackStr(t["company_id"])
				}
				records = append(records, map[string]any{
					"name":         opsPackStr(t["name"]),
					"amount":       amt,
					"type_tax_use": use,
					"active":       active,
					"company":      company,
				})
			}
			output.Ok(tool, map[string]any{
				"unreconciled": map[string]any{"receivable": recv, "payable": pay},
				"taxes": map[string]any{
					"total":           len(taxes),
					"active":          len(taxes) - int(inactive),
					"inactive":        inactive,
					"by_use":          byUse,
					"zero_rate_taxes": zeroRate,
					"records":         records,
				},
			}, 1)
		},
	}
}
