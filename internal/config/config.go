// Package config loads connection settings from env, flags, and an optional
// YAML file with named instances (mirrors odoo_config.multi.json convention).
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// Instance holds one Odoo connection profile.
type Instance struct {
	URL         string `mapstructure:"url"`
	DB          string `mapstructure:"db"`
	Username    string `mapstructure:"username"`
	Password    string `mapstructure:"password"`
	APIKey      string `mapstructure:"api_key"`
	Transport   string `mapstructure:"transport"` // xmlrpc (default) | json2
	VerifySSL   bool   `mapstructure:"verify_ssl"`
	TimeoutSecs int    `mapstructure:"timeout"`
	Lang        string `mapstructure:"lang"`
	ReadOnly    bool   `mapstructure:"readonly"`
	AuditLog    string `mapstructure:"audit_log"`
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

// Load reads config file + env into the active settings.
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

		// Default-deny writes: read-only unless readonly:false is set
		// explicitly in the file. ODOO_READONLY only tightens.
		inst.ReadOnly = true
		if v.IsSet("instances." + name + ".readonly") {
			inst.ReadOnly = v.GetBool("instances." + name + ".readonly")
		}
		if readonlyEnvForces() {
			inst.ReadOnly = true
		}
		if al := first(v.GetString("instances."+name+".audit_log"), v.GetString("audit_log"), os.Getenv("ODOO_AUDIT_LOG")); al != "" {
			inst.AuditLog = al
		} else {
			inst.AuditLog = defaultAuditLog()
		}
		s.Instances[name] = inst
	}
	s.Default = file.DefaultInstance

	// Single-instance fallback from env / flat keys (mirrors odoo_config.json).
	env := &Instance{
		URL:         first(v.GetString("url"), os.Getenv("ODOO_URL")),
		DB:          first(v.GetString("db"), os.Getenv("ODOO_DB")),
		Username:    first(v.GetString("username"), os.Getenv("ODOO_USERNAME")),
		Password:    first(v.GetString("password"), os.Getenv("ODOO_PASSWORD")),
		APIKey:      first(v.GetString("api_key"), os.Getenv("ODOO_API_KEY")),
		Transport:   first(v.GetString("transport"), os.Getenv("ODOO_TRANSPORT")),
		Lang:        first(v.GetString("lang"), v.GetString("locale"), os.Getenv("ODOO_LOCALE")),
		VerifySSL:   true,
		TimeoutSecs: 10,
	}

	env.ReadOnly = flatReadOnly(v)
	if al := first(v.GetString("audit_log"), os.Getenv("ODOO_AUDIT_LOG")); al != "" {
		env.AuditLog = al
	} else {
		env.AuditLog = defaultAuditLog()
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

// Resolve returns the instance for name ("" = default). Errors if unconfigured.
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
				return inst, nil
			}
		}
		return nil, fmt.Errorf("no Odoo connection configured (set ODOO_URL/ODOO_DB/ODOO_USERNAME/ODOO_PASSWORD or --config file)")
	}
	inst, ok := active.Instances[name]
	if !ok {
		return nil, fmt.Errorf("unknown instance %q", name)
	}
	return inst, nil
}

// List returns all configured instances (credentials redacted by caller).
func List() map[string]*Instance {
	if active == nil {
		return nil
	}
	return active.Instances
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

// readonlyEnvForces reports whether ODOO_READONLY tightens the instance to
// read-only. Only 1/true/yes (case-insensitive) count; any other value is
// ignored so the env gate can never loosen an explicit readonly:false.
func readonlyEnvForces() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("ODOO_READONLY"))) {
	case "1", "true", "yes":
		return true
	default:
		return false
	}
}

// flatReadOnly resolves the flat/env layout default-deny flag: read-only
// unless the flat `readonly` key is set explicitly in the file.
// v.IsSet covers both the file key and ODOO_READONLY via AutomaticEnv, so a
// set-but-not-tightening env value is hidden while resolving the file-only
// value (restored via defer); otherwise ODOO_READONLY=0 would loosen the
// default. A tightening value forces read-only regardless of the file.
func flatReadOnly(v *viper.Viper) bool {
	if readonlyEnvForces() {
		return true
	}
	if _, ok := os.LookupEnv("ODOO_READONLY"); ok {
		val := os.Getenv("ODOO_READONLY")
		_ = os.Unsetenv("ODOO_READONLY")
		defer func() { _ = os.Setenv("ODOO_READONLY", val) }()
	}
	if v.IsSet("readonly") {
		return v.GetBool("readonly")
	}
	return true
}

// defaultAuditLog is <defaultDir>/audit.log, or ./odoo-audit.log when no
// home directory is available.
func defaultAuditLog() string {
	if dir := defaultDir(); dir != "" {
		return filepath.Join(dir, "audit.log")
	}
	return filepath.Join(".", "odoo-audit.log")
}
