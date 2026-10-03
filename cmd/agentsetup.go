// Command handlers for human-only agent boundary administration:
// `agent setup`, `agent snapshot`, `agent companies`, `agent workspace`.
//
// These commands are NEVER on the model surface. They run interactively (or
// with explicit flags) by a human who holds the Odoo login (OS keychain,
// via the existing `odoo login` flow) and who chooses the admin password
// that seals the agent policy. The admin password is read over a TTY with
// no echo (lock.PromptAdminPassword) or, only with --admin-password-stdin,
// from stdin; it is never taken from args or env, and never appears in
// output, envelopes, or errors.
//
// Self-registers via init() with a find-or-create `agent` parent so the
// broker's cmd/agent.go (serve/grant/revoke/status) can attach to the same
// parent regardless of init order.
package cmd

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/danieljclsilva/cli-odoo/internal/agent/lock"
	"github.com/danieljclsilva/cli-odoo/internal/agent/policy"
	"github.com/danieljclsilva/cli-odoo/internal/agent/snapshot"
	"github.com/danieljclsilva/cli-odoo/internal/agent/workspace"
	"github.com/danieljclsilva/cli-odoo/internal/config"
	"github.com/danieljclsilva/cli-odoo/internal/odoo"
	"github.com/danieljclsilva/cli-odoo/internal/output"
)

// DefaultAgentProfilePath is the default sealed-policy file. The broker's
// serve path resolves the same default (same package, shared symbol).
func DefaultAgentProfilePath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".config", "odoo-cli", "agent-profile.json")
}

// DefaultAgentSnapshotPath is the default human-built metadata file.
func DefaultAgentSnapshotPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, ".config", "odoo-cli", "agent-snapshot.json")
}

// agentSetupParent finds the shared `agent` parent or creates it when this
// file's init runs first.
func agentSetupParent() *cobra.Command {
	for _, c := range RootCmd.Commands() {
		if c.Name() == "agent" {
			return c
		}
	}
	parent := &cobra.Command{
		Use:   "agent",
		Short: "Human-only agent boundary administration (setup, snapshot, policy)",
		Long: `Human-only administration for the agent boundary. The model surface
never includes these commands: they approve companies, models, fields,
operations, and budgets, and seal the resulting policy with an admin
password. The broker serves only typed tools gated by that sealed policy.`,
	}
	RootCmd.AddCommand(parent)
	return parent
}

func init() {
	parent := agentSetupParent()
	parent.AddCommand(newAgentSetupCmd())
	parent.AddCommand(newAgentSnapshotCmd())
	parent.AddCommand(newAgentCompaniesCmd())
	parent.AddCommand(newAgentWorkspaceCmd())
}

// agentSetupStdinTTY reports whether prompts can be shown.
func agentSetupStdinTTY() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// agentSetupPrompt prints msg on stderr and reads one line from stdin.
// It refuses when stdin is not a terminal so scripts get an explicit
// "pass the flag" error instead of a silent hang.
func agentSetupPrompt(msg string) (string, error) {
	if !agentSetupStdinTTY() {
		return "", fmt.Errorf("no value given and stdin is not a terminal (pass the flag explicitly)")
	}
	fmt.Fprint(os.Stderr, msg)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", fmt.Errorf("reading answer: %w", err)
	}
	return strings.TrimSpace(line), nil
}

// agentSetupAdminPassword reads the admin password via the lock package:
// --admin-password-stdin only from stdin, otherwise a no-echo TTY prompt.
// confirm asks twice on the setup path so a typo cannot lock the human out.
func agentSetupAdminPassword(adminStdin, confirm bool) (string, error) {
	if adminStdin {
		return lock.ReadAdminPasswordStdin()
	}
	first, err := lock.PromptAdminPassword("Agent admin password: ")
	if err != nil {
		return "", err
	}
	if first == "" {
		return "", fmt.Errorf("empty admin password refused")
	}
	if !confirm {
		return first, nil
	}
	second, err := lock.PromptAdminPassword("Confirm agent admin password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", fmt.Errorf("passwords do not match")
	}
	return first, nil
}

// agentSetupLiveClient resolves the active instance with its keychain
// secret (the existing login flow: `odoo login` first) and connects.
// ResolveNoAuth runs first so an unconfigured instance fails before the
// keychain is touched; Resolve then attaches the secret. Secrets stay in
// the client; they are never printed.
func agentSetupLiveClient(name string) (*odoo.Client, *config.Instance, error) {
	if _, err := config.ResolveNoAuth(name); err != nil {
		return nil, nil, err
	}
	inst, err := config.Resolve(name)
	if err != nil {
		return nil, nil, fmt.Errorf("%w (run: odoo login --url <url> --db <db> --username <user>)", err)
	}
	cli, err := odoo.New(inst)
	if err != nil {
		return nil, nil, err
	}
	return cli, inst, nil
}

// agentSetupCompanies coerces a res.company search_read result.
func agentSetupCompanies(v any) ([]snapshot.Company, error) {
	rows, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("unexpected res.company shape %T", v)
	}
	out := make([]snapshot.Company, 0, len(rows))
	for i, r := range rows {
		m, ok := r.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("res.company row %d has shape %T", i, r)
		}
		id, err := agentSetupInt(m["id"])
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("res.company row %d has bad id", i)
		}
		name, _ := m["name"].(string)
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("res.company row %d has empty name", i)
		}
		out = append(out, snapshot.Company{ID: id, Name: name})
	}
	return out, nil
}

// agentSetupInt coerces XML-RPC numerics.
func agentSetupInt(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case int64:
		return int(n), nil
	case float64:
		if n != float64(int(n)) {
			return 0, fmt.Errorf("non-integral number %v", n)
		}
		return int(n), nil
	default:
		return 0, fmt.Errorf("bad number shape %T", v)
	}
}

// agentSetupParseModelSpec parses one --model value:
// name:field1,field2[:company_id|company_ids|independent][:aggregate]
func agentSetupParseModelSpec(spec string) (snapshot.ModelSpec, error) {
	parts := strings.Split(spec, ":")
	if len(parts) < 2 || len(parts) > 4 {
		return snapshot.ModelSpec{}, fmt.Errorf("invalid --model %q: want name:fields[:company_id|company_ids|independent][:aggregate]", spec)
	}
	name, ok := policy.NormalizeName(parts[0])
	if !ok {
		return snapshot.ModelSpec{}, fmt.Errorf("invalid --model %q: bad model name", spec)
	}
	fields := odoo.ParseCSV(parts[1])
	if len(fields) == 0 {
		return snapshot.ModelSpec{}, fmt.Errorf("invalid --model %q: at least one field is required", spec)
	}
	seen := map[string]bool{}
	clean := make([]string, 0, len(fields))
	for _, f := range fields {
		fn, ok := policy.NormalizeName(f)
		if !ok {
			return snapshot.ModelSpec{}, fmt.Errorf("invalid --model %q: bad field %q", spec, f)
		}
		if !seen[fn] {
			seen[fn] = true
			clean = append(clean, fn)
		}
	}
	sort.Strings(clean)
	out := snapshot.ModelSpec{Name: name, Label: name, Fields: clean}
	for _, extra := range parts[2:] {
		switch strings.TrimSpace(extra) {
		case "":
		case "company_id", "company_ids":
			out.CompanyField = strings.TrimSpace(extra)
		case "independent":
			out.CompanyIndependent = true
		case "aggregate":
			out.AllowAggregate = true
		default:
			return snapshot.ModelSpec{}, fmt.Errorf("invalid --model %q: unknown qualifier %q", spec, extra)
		}
	}
	return out, nil
}

// agentSetupPromptModels runs the interactive approval loop: the human names
// each model and its fields; anything not named here is never described.
func agentSetupPromptModels() ([]snapshot.ModelSpec, error) {
	var specs []snapshot.ModelSpec
	for {
		nameRaw, err := agentSetupPrompt("Approve model (empty to finish): ")
		if err != nil {
			return nil, err
		}
		if nameRaw == "" {
			break
		}
		name, ok := policy.NormalizeName(nameRaw)
		if !ok {
			return nil, fmt.Errorf("invalid model name %q: must match [A-Za-z0-9._]+", nameRaw)
		}
		fieldsRaw, err := agentSetupPrompt("  Fields for " + name + " (comma-separated, at least one): ")
		if err != nil {
			return nil, err
		}
		fields := odoo.ParseCSV(fieldsRaw)
		if len(fields) == 0 {
			return nil, fmt.Errorf("at least one field is required for %s", name)
		}
		for _, f := range fields {
			if _, ok := policy.NormalizeName(f); !ok {
				return nil, fmt.Errorf("invalid field %q for %s", f, name)
			}
		}
		cfRaw, err := agentSetupPrompt("  Company field (company_id|company_ids, empty if none): ")
		if err != nil {
			return nil, err
		}
		sp := snapshot.ModelSpec{Name: name, Label: name, Fields: fields}
		switch strings.TrimSpace(cfRaw) {
		case "":
			indep, err := agentSetupPrompt("  Company-independent shared data you reviewed? (y/N): ")
			if err != nil {
				return nil, err
			}
			sp.CompanyIndependent = strings.EqualFold(indep, "y") || strings.EqualFold(indep, "yes")
		case "company_id", "company_ids":
			sp.CompanyField = strings.TrimSpace(cfRaw)
		default:
			return nil, fmt.Errorf("invalid company field %q: want company_id|company_ids|empty", cfRaw)
		}
		agg, err := agentSetupPrompt("  Allow aggregate on " + name + "? (y/N): ")
		if err != nil {
			return nil, err
		}
		sp.AllowAggregate = strings.EqualFold(agg, "y") || strings.EqualFold(agg, "yes")
		specs = append(specs, sp)
	}
	return specs, nil
}

// agentSetupOps parses the --ops CSV into the Operations allowlist.
func agentSetupOps(s string) (map[policy.Operation]bool, error) {
	out := map[policy.Operation]bool{}
	for _, name := range odoo.ParseCSV(s) {
		var op policy.Operation
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "search":
			op = policy.OpSearch
		case "read":
			op = policy.OpRead
		case "count":
			op = policy.OpCount
		case "aggregate":
			op = policy.OpAggregate
		case "meta":
			op = policy.OpMeta
		default:
			return nil, fmt.Errorf("invalid operation %q: want search|read|count|aggregate|meta", name)
		}
		out[op] = true
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("at least one operation is required")
	}
	return out, nil
}

// agentSetupEnsureDir creates dir with 0700 when missing and returns its
// absolute path. Only setup creates; workspace.Open itself never does.
func agentSetupEnsureDir(dir string) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("workspace directory is required")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("workspace directory: %w", err)
	}
	if st, err := os.Stat(abs); err != nil {
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("workspace directory: %w", err)
		}
		if err := os.MkdirAll(abs, 0700); err != nil {
			return "", fmt.Errorf("creating workspace: %w", err)
		}
	} else if !st.IsDir() {
		return "", fmt.Errorf("workspace %q is not a directory", abs)
	}
	return abs, nil
}

// agentSetupEnsureParent creates the parent of a file path with 0700.
func agentSetupEnsureParent(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("creating %q: %w", dir, err)
	}
	return nil
}

// agentSetupOpenPolicy reads a sealed profile and unseals its policy JSON.
func agentSetupOpenPolicy(profilePath, adminPassword string) (policy.Policy, error) {
	var pol policy.Policy
	b, err := os.ReadFile(profilePath)
	if err != nil {
		return pol, fmt.Errorf("reading profile %q: %w (run: odoo agent setup)", profilePath, err)
	}
	var prof lock.Profile
	if err := json.Unmarshal(b, &prof); err != nil {
		return pol, fmt.Errorf("decoding profile %q: %w", profilePath, err)
	}
	raw, err := prof.Open(adminPassword)
	if err != nil {
		return pol, fmt.Errorf("unlocking profile: %w", err)
	}
	if err := json.Unmarshal(raw, &pol); err != nil {
		return pol, fmt.Errorf("decoding sealed policy: %w", err)
	}
	return pol, nil
}

// agentSetupPolicySpecs converts sealed policy models back into builder
// specs for snapshot refresh.
func agentSetupPolicySpecs(pol policy.Policy) []snapshot.ModelSpec {
	specs := make([]snapshot.ModelSpec, 0, len(pol.Models))
	for name, rule := range pol.Models {
		fields := append([]string(nil), rule.Fields...)
		sort.Strings(fields)
		specs = append(specs, snapshot.ModelSpec{
			Name: name, Label: name, Fields: fields,
			CompanyField: rule.CompanyField, CompanyIndependent: rule.CompanyIndependent,
			AllowAggregate: rule.AllowAggregate,
		})
	}
	sort.Slice(specs, func(i, j int) bool { return specs[i].Name < specs[j].Name })
	return specs
}

func newAgentSetupCmd() *cobra.Command {
	var profilePath, snapshotPath, workspaceDir, companiesStr, opsStr, sharedRecords string
	var defaultCompany int
	var modelFlags []string
	var adminStdin bool
	var maxLimit, maxOffset, maxRowsPerCall, maxResponseBytes int
	var maxCallsPerSession, maxRowsPerSession int64
	var allowWorkspace bool
	c := &cobra.Command{
		Use:   "setup",
		Short: "Human-only guided setup: approve scope, seal policy (never model-invoked)",
		Long: `Human-only guided setup for the agent boundary. Uses the active
instance (--instance flag or ODOO_INSTANCE) with its keychain secret
(run: odoo login first), then:

  1. shows available companies from res.company; you enable >=2 and pick
     the default from the enabled set (--companies 1,2 --default-company 1,
     or interactive prompts);
  2. approves models/fields (--model name:fields[:scope][:aggregate],
     repeatable; scope is company_id|company_ids|independent) or
     interactively; only approved models are ever described with fields_get;
  3. approves operations (--ops), budgets, and shared-record handling
     (--shared-records deny|allow-classified);
  4. takes a workspace directory (--workspace), created 0700 when missing;
  5. builds the snapshot from the live server, writes it 0600;
  6. seals the policy with an admin password (TTY no-echo prompt, or
     --admin-password-stdin only) and writes the profile 0600.

The admin password never appears in output, envelopes, or errors.
MethodManifest in the snapshot is informational only, never executable.`,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "agent_setup"
			if profilePath == "" {
				profilePath = DefaultAgentProfilePath()
			}
			if snapshotPath == "" {
				snapshotPath = DefaultAgentSnapshotPath()
			}
			if profilePath == "" || snapshotPath == "" {
				output.Fail(tool, fmt.Errorf("cannot determine home directory (set --profile and --snapshot-path explicitly)"))
				return
			}
			cli, inst, err := agentSetupLiveClient(InstanceName())
			if err != nil {
				output.Fail(tool, err)
				return
			}
			instanceName := strings.TrimSpace(inst.Name)
			if instanceName == "" {
				instanceName = InstanceName()
			}
			if instanceName == "" {
				instanceName = config.DefaultName()
			}
			if instanceName == "" {
				instanceName = "default"
			}
			companyRows, err := cli.Execute("res.company", "search_read",
				[]any{[]any{}, []any{"id", "name"}},
				map[string]any{"limit": 10000, "order": "id asc"})
			if err != nil {
				output.Fail(tool, fmt.Errorf("reading res.company: %w", err))
				return
			}
			available, err := agentSetupCompanies(companyRows)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			names := make([]string, 0, len(available))
			for _, ac := range available {
				names = append(names, fmt.Sprintf("%d (%s)", ac.ID, ac.Name))
			}
			fmt.Fprintf(os.Stderr, "Available companies on %q: %s\n", instanceName, strings.Join(names, ", "))

			var enabled []int
			if strings.TrimSpace(companiesStr) != "" {
				enabled, err = odoo.ParseIDs(odoo.ParseCSV(companiesStr))
				if err != nil {
					output.Fail(tool, err)
					return
				}
			} else {
				raw, err := agentSetupPrompt("Enable companies (comma-separated ids, at least two): ")
				if err != nil {
					output.Fail(tool, err)
					return
				}
				enabled, err = odoo.ParseIDs(odoo.ParseCSV(raw))
				if err != nil {
					output.Fail(tool, err)
					return
				}
			}
			if defaultCompany == 0 {
				raw, err := agentSetupPrompt("Default company (must be one of the enabled): ")
				if err != nil {
					output.Fail(tool, err)
					return
				}
				ids, err := odoo.ParseIDs(odoo.ParseCSV(raw))
				if err != nil || len(ids) != 1 {
					output.Fail(tool, fmt.Errorf("want exactly one default company id"))
					return
				}
				defaultCompany = ids[0]
			}
			scope := policy.CompanyScope{Enabled: enabled, Default: defaultCompany}

			var specs []snapshot.ModelSpec
			if len(modelFlags) > 0 {
				for _, f := range modelFlags {
					sp, err := agentSetupParseModelSpec(f)
					if err != nil {
						output.Fail(tool, err)
						return
					}
					specs = append(specs, sp)
				}
			} else {
				specs, err = agentSetupPromptModels()
				if err != nil {
					output.Fail(tool, err)
					return
				}
			}
			if len(specs) == 0 {
				output.Fail(tool, fmt.Errorf("at least one approved model is required"))
				return
			}

			ops, err := agentSetupOps(opsStr)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			shared := strings.TrimSpace(sharedRecords)
			if shared != policy.SharedDeny && shared != policy.SharedAllowClassified {
				output.Fail(tool, fmt.Errorf("invalid --shared-records %q: want deny|allow-classified", sharedRecords))
				return
			}
			if maxLimit <= 0 || maxOffset <= 0 || maxRowsPerCall <= 0 || maxResponseBytes <= 0 ||
				maxCallsPerSession <= 0 || maxRowsPerSession <= 0 {
				output.Fail(tool, fmt.Errorf("all budget flags must be positive"))
				return
			}

			if strings.TrimSpace(workspaceDir) == "" {
				suggest := filepath.Join(filepath.Dir(snapshotPath), "agent-workspace")
				raw, err := agentSetupPrompt("Workspace directory [" + suggest + "]: ")
				if err != nil {
					output.Fail(tool, err)
					return
				}
				workspaceDir = strings.TrimSpace(raw)
				if workspaceDir == "" {
					workspaceDir = suggest
				}
			}
			wsAbs, err := agentSetupEnsureDir(workspaceDir)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			ws, err := workspace.Open(wsAbs)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			_ = ws.Close()

			snap, err := snapshot.BuildFromServer(cli, instanceName, scope, specs)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			if err := agentSetupEnsureParent(snapshotPath); err != nil {
				output.Fail(tool, err)
				return
			}
			if err := snapshot.Write(snapshotPath, snap); err != nil {
				output.Fail(tool, err)
				return
			}

			models := make(map[string]policy.ModelRule, len(specs))
			for _, sp := range specs {
				fields := append([]string(nil), sp.Fields...)
				sort.Strings(fields)
				perModel := maxLimit
				models[sp.Name] = policy.ModelRule{
					Fields: fields, MaxLimit: perModel,
					AllowAggregate: sp.AllowAggregate,
					CompanyField:   sp.CompanyField, CompanyIndependent: sp.CompanyIndependent,
				}
			}
			pol := policy.Policy{
				Version: 1, Instance: instanceName,
				Operations: ops, Models: models, Scope: scope,
				SharedRecords: shared,
				Budgets: policy.Budgets{
					MaxLimit: maxLimit, MaxOffset: maxOffset,
					MaxRowsPerCall: maxRowsPerCall, MaxResponseBytes: maxResponseBytes,
					MaxCallsPerSession: maxCallsPerSession, MaxRowsPerSession: maxRowsPerSession,
				},
				AllowWorkspace: allowWorkspace,
				WorkspaceDir:   wsAbs,
				SnapshotPath:   snapshotPath,
			}
			policyJSON, err := json.Marshal(pol)
			if err != nil {
				output.Fail(tool, fmt.Errorf("encoding policy: %w", err))
				return
			}
			adminPassword, err := agentSetupAdminPassword(adminStdin, true)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			prof, err := lock.Seal(policyJSON, adminPassword)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			profJSON, err := json.MarshalIndent(prof, "", "  ")
			if err != nil {
				output.Fail(tool, fmt.Errorf("encoding profile: %w", err))
				return
			}
			if err := agentSetupEnsureParent(profilePath); err != nil {
				output.Fail(tool, err)
				return
			}
			if err := os.WriteFile(profilePath, append(profJSON, '\n'), 0600); err != nil {
				output.Fail(tool, fmt.Errorf("writing profile: %w", err))
				return
			}
			modelNames := make([]string, 0, len(models))
			for name := range models {
				modelNames = append(modelNames, name)
			}
			sort.Strings(modelNames)
			output.Ok(tool, map[string]any{
				"instance": instanceName, "profile": profilePath,
				"snapshot": snapshotPath, "workspace": wsAbs,
				"enabled_companies": scope.Enabled, "default_company": scope.Default,
				"models": modelNames, "shared_records": shared,
			}, len(modelNames))
		},
	}
	c.Flags().StringVar(&profilePath, "profile", "", "sealed profile path (default "+DefaultAgentProfilePath()+")")
	c.Flags().StringVar(&snapshotPath, "snapshot-path", "", "snapshot file path (default "+DefaultAgentSnapshotPath()+")")
	c.Flags().StringVar(&workspaceDir, "workspace", "", "dedicated workspace directory (created 0700 when missing)")
	c.Flags().StringVar(&companiesStr, "companies", "", "enabled company ids, e.g. \"1,2\" (prompts when empty)")
	c.Flags().IntVar(&defaultCompany, "default-company", 0, "default company id, must be enabled (prompts when 0)")
	c.Flags().StringSliceVar(&modelFlags, "model", nil, "approved model name:fields[:scope][:aggregate], repeatable (prompts when empty)")
	c.Flags().StringVar(&opsStr, "ops", "search,read,count,meta", "approved operations CSV")
	c.Flags().StringVar(&sharedRecords, "shared-records", policy.SharedDeny, "shared-record handling: deny|allow-classified")
	c.Flags().BoolVar(&adminStdin, "admin-password-stdin", false, "read admin password from stdin (never args/env)")
	c.Flags().IntVar(&maxLimit, "max-limit", 100, "per-request row cap")
	c.Flags().IntVar(&maxOffset, "max-offset", 10000, "per-request offset cap")
	c.Flags().IntVar(&maxRowsPerCall, "max-rows-per-call", 1000, "rows returned per call cap")
	c.Flags().IntVar(&maxResponseBytes, "max-response-bytes", 1048576, "response byte cap")
	c.Flags().Int64Var(&maxCallsPerSession, "max-calls-per-session", 1000, "session call budget")
	c.Flags().Int64Var(&maxRowsPerSession, "max-rows-per-session", 100000, "session row budget")
	c.Flags().BoolVar(&allowWorkspace, "allow-workspace", true, "grant the model broker-level workspace file tools")
	return c
}

func newAgentSnapshotCmd() *cobra.Command {
	var profilePath, snapshotPath string
	var modelFlags []string
	var adminStdin bool
	c := &cobra.Command{
		Use:   "snapshot",
		Short: "Human-only bounded metadata import/refresh from the live server",
		Long: `Human-only snapshot refresh. Unlocks the sealed profile with the
admin password (TTY no-echo prompt, or --admin-password-stdin only),
rebuilds metadata from the live server for exactly the approved models
in the sealed policy (--model overrides the model set with the same
name:fields[:scope][:aggregate] syntax), and rewrites the snapshot file
0600. Only human-approved models are described with fields_get; custom
models outside the approved set are never touched.`,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "agent_snapshot"
			if profilePath == "" {
				profilePath = DefaultAgentProfilePath()
			}
			if profilePath == "" {
				output.Fail(tool, fmt.Errorf("cannot determine home directory (set --profile explicitly)"))
				return
			}
			adminPassword, err := agentSetupAdminPassword(adminStdin, false)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			pol, err := agentSetupOpenPolicy(profilePath, adminPassword)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			var specs []snapshot.ModelSpec
			if len(modelFlags) > 0 {
				for _, f := range modelFlags {
					sp, err := agentSetupParseModelSpec(f)
					if err != nil {
						output.Fail(tool, err)
						return
					}
					specs = append(specs, sp)
				}
			} else {
				specs = agentSetupPolicySpecs(pol)
			}
			if len(specs) == 0 {
				output.Fail(tool, fmt.Errorf("no approved models to refresh"))
				return
			}
			if strings.TrimSpace(snapshotPath) == "" {
				snapshotPath = pol.SnapshotPath
			}
			if strings.TrimSpace(snapshotPath) == "" {
				snapshotPath = DefaultAgentSnapshotPath()
			}
			cli, _, err := agentSetupLiveClient(pol.Instance)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			snap, err := snapshot.BuildFromServer(cli, pol.Instance, pol.Scope, specs)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			if err := agentSetupEnsureParent(snapshotPath); err != nil {
				output.Fail(tool, err)
				return
			}
			if err := snapshot.Write(snapshotPath, snap); err != nil {
				output.Fail(tool, err)
				return
			}
			output.Ok(tool, map[string]any{
				"instance": pol.Instance, "snapshot": snapshotPath,
				"models": len(specs), "enabled_companies": pol.Scope.Enabled,
				"default_company": pol.Scope.Default,
			}, len(specs))
		},
	}
	c.Flags().StringVar(&profilePath, "profile", "", "sealed profile path (default "+DefaultAgentProfilePath()+")")
	c.Flags().StringVar(&snapshotPath, "snapshot-path", "", "snapshot output path (default: path recorded in the sealed policy)")
	c.Flags().StringSliceVar(&modelFlags, "model", nil, "override model set, same syntax as setup --model (default: sealed policy set)")
	c.Flags().BoolVar(&adminStdin, "admin-password-stdin", false, "read admin password from stdin (never args/env)")
	return c
}

func newAgentCompaniesCmd() *cobra.Command {
	var snapshotPath string
	var live bool
	c := &cobra.Command{
		Use:   "companies",
		Short: "Show discovered vs enabled companies (human inspection)",
		Long: `Human-only company inspection. Shows the snapshot's available
companies (discovery) alongside the enabled set and default
(authorization), kept distinct. With --live, re-reads res.company from
the server (existing keychain login) and marks the enabled/default
selection; live output never changes the sealed policy.`,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "agent_companies"
			if strings.TrimSpace(snapshotPath) == "" {
				snapshotPath = DefaultAgentSnapshotPath()
			}
			snap, snapErr := snapshot.Load(snapshotPath)
			if live {
				cli, _, err := agentSetupLiveClient(InstanceName())
				if err != nil {
					output.Fail(tool, err)
					return
				}
				rows, err := cli.Execute("res.company", "search_read",
					[]any{[]any{}, []any{"id", "name"}},
					map[string]any{"limit": 10000, "order": "id asc"})
				if err != nil {
					output.Fail(tool, fmt.Errorf("reading res.company: %w", err))
					return
				}
				avail, err := agentSetupCompanies(rows)
				if err != nil {
					output.Fail(tool, err)
					return
				}
				// Snapshot scope (if a file exists) only annotates live
				// discovery; it never changes the sealed policy.
				enabled := map[int]bool{}
				def := 0
				if snapErr == nil {
					for _, id := range snap.EnabledCompanies {
						enabled[id] = true
					}
					def = snap.DefaultCompany
				}
				out := make([]map[string]any, 0, len(avail))
				for _, ac := range avail {
					out = append(out, map[string]any{
						"id": ac.ID, "name": ac.Name,
						"enabled": enabled[ac.ID], "default": ac.ID == def,
					})
				}
				output.Ok(tool, map[string]any{"live": true, "companies": out}, len(out))
				return
			}
			if snapErr != nil {
				output.Fail(tool, snapErr)
				return
			}
			avail := make([]map[string]any, 0, len(snap.AvailableCompanies))
			enabled := map[int]bool{}
			for _, id := range snap.EnabledCompanies {
				enabled[id] = true
			}
			for _, ac := range snap.AvailableCompanies {
				avail = append(avail, map[string]any{
					"id": ac.ID, "name": ac.Name,
					"enabled": enabled[ac.ID], "default": ac.ID == snap.DefaultCompany,
				})
			}
			output.Ok(tool, map[string]any{
				"snapshot": snapshotPath, "companies": avail,
				"enabled": snap.EnabledCompanies, "default_company": snap.DefaultCompany,
			}, len(avail))
		},
	}
	c.Flags().StringVar(&snapshotPath, "snapshot-path", "", "snapshot file (default "+DefaultAgentSnapshotPath()+")")
	c.Flags().BoolVar(&live, "live", false, "re-read res.company from the server instead of the snapshot file")
	return c
}

func newAgentWorkspaceCmd() *cobra.Command {
	var profilePath string
	var adminStdin bool
	var maxEntries int
	c := &cobra.Command{
		Use:   "workspace",
		Short: "Show the sealed workspace directory (human inspection)",
		Long: `Human-only workspace inspection. Unlocks the sealed profile with
the admin password (TTY no-echo prompt, or --admin-password-stdin only),
shows the human-chosen workspace directory, and lists its top level
(bounded by --max-entries) to prove confinement. The admin password
never appears in output.`,
		Run: func(cmd *cobra.Command, args []string) {
			const tool = "agent_workspace"
			if profilePath == "" {
				profilePath = DefaultAgentProfilePath()
			}
			if profilePath == "" {
				output.Fail(tool, fmt.Errorf("cannot determine home directory (set --profile explicitly)"))
				return
			}
			adminPassword, err := agentSetupAdminPassword(adminStdin, false)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			pol, err := agentSetupOpenPolicy(profilePath, adminPassword)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			if strings.TrimSpace(pol.WorkspaceDir) == "" {
				output.Fail(tool, fmt.Errorf("sealed policy records no workspace directory"))
				return
			}
			ws, err := workspace.Open(pol.WorkspaceDir)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			defer ws.Close()
			entries, err := ws.List("", maxEntries)
			if err != nil {
				output.Fail(tool, err)
				return
			}
			output.Ok(tool, map[string]any{"dir": pol.WorkspaceDir, "entries": entries}, len(entries))
		},
	}
	c.Flags().StringVar(&profilePath, "profile", "", "sealed profile path (default "+DefaultAgentProfilePath()+")")
	c.Flags().BoolVar(&adminStdin, "admin-password-stdin", false, "read admin password from stdin (never args/env)")
	c.Flags().IntVar(&maxEntries, "max-entries", 100, "top-level listing cap (over-cap denies, never truncates)")
	return c
}
