// Package config loads connection settings. Non-secret connection fields
// (url, db, username, transport, …) come from the YAML file or env.
// Secrets (password / API key) live ONLY in the OS keychain under service
// "cli-odoo" and account "<instance-url>|<db>|<username>"; they are never
// read from files or environment variables. The CLI is read-only: there is
// no writable instance flag and no write gate to loosen.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
	"github.com/zalando/go-keyring"
)

// KeyringService is the OS keychain service name for all stored secrets.
const KeyringService = "cli-odoo"

// Instance holds one Odoo connection profile. Secrets are populated at
// Resolve time from the OS keychain, never from file or env.
type Instance struct {
	URL         string `mapstructure:"url"`
	DB          string `mapstructure:"db"`
	Username    string `mapstructure:"username"`
	Password    string `mapstructure:"-"`
	APIKey      string `mapstructure:"-"`
	Transport   string `mapstructure:"transport"` // xmlrpc (default) | json2
	VerifySSL   bool   `mapstructure:"verify_ssl"`
	TimeoutSecs int    `mapstructure:"timeout"`
	Lang        string `mapstructure:"lang"`
	IsDefault   bool   `mapstructure:"-"`
	Name        string `mapstructure:"-"`
}

// Settings is the resolved runtime configuration.
type Settings struct {
	Instances map[string]*Instance
	Default   string
	Verbose   bool
}

var active *Settings

// AccountName derives the keychain account for an instance identity.
func AccountName(url, db, username string) string {
	return strings.TrimSpace(url) + "|" + strings.TrimSpace(db) + "|" + strings.TrimSpace(username)
}

// account returns this instance's keychain account.
func (inst *Instance) account() string {
	return AccountName(inst.URL, inst.DB, inst.Username)
}

// SaveSecret stores secret in the OS keychain for this instance identity.
func (inst *Instance) SaveSecret(secret string) error {
	if strings.TrimSpace(inst.URL) == "" || strings.TrimSpace(inst.DB) == "" || strings.TrimSpace(inst.Username) == "" {
		return fmt.Errorf("instance identity incomplete (need url, db, username)")
	}
	return keyring.Set(KeyringService, inst.account(), secret)
}

// DeleteSecret removes this instance identity's secret from the keychain.
func (inst *Instance) DeleteSecret() error {
	err := keyring.Delete(KeyringService, inst.account())
	if err != nil && err != keyring.ErrNotFound {
		return err
	}
	return nil
}

// loadSecret fetches this instance's secret from the OS keychain.
func (inst *Instance) loadSecret() (string, error) {
	secret, err := keyring.Get(KeyringService, inst.account())
	if err != nil {
		return "", fmt.Errorf("no keychain secret for %q (run: odoo login --url %s --db %s --username %s)", inst.Name, inst.URL, inst.DB, inst.Username)
	}
	return secret, nil
}

// Load reads non-secret connection fields from config file + env.
// Secrets are never loaded here; Resolve pulls them from the keychain.
func Load(cfgFile string) error {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
	} else if dir := defaultDir(); dir != "" {
		// Home-dir config only: never auto-load ./config.yaml (M2).
		v.AddConfigPath(dir)
	}
	v.SetEnvPrefix("ODOO")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	_ = v.ReadInConfig() // missing file is fine; env-only mode works

	s := &Settings{Instances: map[string]*Instance{}}

	// Multi-instance file layout: instances: {name: {...}}, default_instance: name
	var file struct {
		Instances       map[string]*Instance `mapstructure:"instances"`
		DefaultInstance string               `mapstructure:"default_instance"`
	}
	_ = v.Unmarshal(&file)
	for name, inst := range file.Instances {
		inst.Name = name
		inst.Password = ""
		inst.APIKey = ""
		// Default-deny TLS: unset verify_ssl/verify means verify (H2).
		// Explicit false stays false (user-opt-in InsecureSkipVerify).
		switch {
		case v.IsSet("instances." + name + ".verify_ssl"):
			// Unmarshalled value already correct.
		case v.IsSet("instances." + name + ".verify"):
			inst.VerifySSL = v.GetBool("instances." + name + ".verify")
		default:
			inst.VerifySSL = true
		}
		s.Instances[name] = inst
	}
	s.Default = file.DefaultInstance

	// Single-instance fallback from env / flat keys (non-secret fields only).
	env := &Instance{
		URL:         first(v.GetString("url"), os.Getenv("ODOO_URL")),
		DB:          first(v.GetString("db"), os.Getenv("ODOO_DB")),
		Username:    first(v.GetString("username"), os.Getenv("ODOO_USERNAME")),
		Transport:   first(v.GetString("transport"), os.Getenv("ODOO_TRANSPORT")),
		Lang:        first(v.GetString("lang"), v.GetString("locale"), os.Getenv("ODOO_LOCALE")),
		VerifySSL:   true,
		TimeoutSecs: 10,
	}

	if v.IsSet("verify_ssl") {
		env.VerifySSL = v.GetBool("verify_ssl")
	} else if v.IsSet("verify") {
		env.VerifySSL = v.GetBool("verify")
	} else if v := os.Getenv("ODOO_VERIFY_SSL"); v != "" {
		env.VerifySSL = v != "0" && !strings.EqualFold(v, "false")
	}
	if v.IsSet("timeout") {
		env.TimeoutSecs = v.GetInt("timeout")
	}
	if env.URL != "" {
		env.Name = "default"
		env.IsDefault = true
		s.Instances["default"] = env
		if s.Default == "" {
			s.Default = "default"
		}
	}
	for _, inst := range s.Instances {
		if inst.Transport == "" {
			inst.Transport = "xmlrpc"
		}
		if inst.TimeoutSecs == 0 {
			inst.TimeoutSecs = 10
		}
	}
	if def, ok := s.Instances[s.Default]; ok {
		def.IsDefault = true
	}
	s.Verbose = v.GetBool("verbose")
	active = s
	return nil
}

// Resolve returns the instance for name ("" = default) with its secret
// attached from the OS keychain. Errors if unconfigured or not logged in.
func Resolve(name string) (*Instance, error) {
	if active == nil {
		return nil, fmt.Errorf("config not loaded")
	}
	if name == "" {
		name = active.Default
	}
	if name == "" {
		// Single unnamed file instance convenience.
		if len(active.Instances) == 1 {
			for _, inst := range active.Instances {
				secret, err := inst.loadSecret()
				if err != nil {
					return nil, err
				}
				// Copy so the shared Settings never holds the secret.
				out := *inst
				out.Password = secret
				return &out, nil
			}
		}
		return nil, fmt.Errorf("no Odoo connection configured (run: odoo login --url <url> --db <db> --username <user>)")
	}
	inst, ok := active.Instances[name]
	if !ok {
		return nil, fmt.Errorf("unknown instance %q", name)
	}
	secret, err := inst.loadSecret()
	if err != nil {
		return nil, err
	}
	// Copy so the shared Settings never holds the secret in memory longer
	// than the caller's client lifetime.
	out := *inst
	out.Password = secret
	return &out, nil
}

// ResolveNoAuth returns the instance connection fields without touching the
// keychain. For login/logout bookkeeping only. The result is a copy: the
// shared Settings never leaks secrets held by a concurrent Resolve caller.
func ResolveNoAuth(name string) (*Instance, error) {
	if active == nil {
		return nil, fmt.Errorf("config not loaded")
	}
	if name == "" {
		name = active.Default
	}
	if name == "" {
		if len(active.Instances) == 1 {
			for _, inst := range active.Instances {
				out := *inst
				out.Password = ""
				out.APIKey = ""
				return &out, nil
			}
		}
		return nil, fmt.Errorf("no Odoo connection configured")
	}
	inst, ok := active.Instances[name]
	if !ok {
		return nil, fmt.Errorf("unknown instance %q", name)
	}
	out := *inst
	out.Password = ""
	out.APIKey = ""
	return &out, nil
}

// List returns copies of all configured instances (secrets never attached).
func List() map[string]*Instance {
	if active == nil {
		return nil
	}
	out := make(map[string]*Instance, len(active.Instances))
	for name, inst := range active.Instances {
		cp := *inst
		cp.Password = ""
		cp.APIKey = ""
		out[name] = &cp
	}
	return out
}

// LoggedIn reports whether a keychain secret exists for inst.
func LoggedIn(inst *Instance) bool {
	if inst == nil {
		return false
	}
	_, err := keyring.Get(KeyringService, inst.account())
	return err == nil
}

// DefaultName returns the default instance name (may be empty).
func DefaultName() string {
	if active == nil {
		return ""
	}
	return active.Default
}

func defaultDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "odoo-cli")
}

func first(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
