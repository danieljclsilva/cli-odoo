module github.com/danieljclsilva/cli-odoo

go 1.25.0

require (
	// kolo/xmlrpc is unmaintained (last commit 2022); pinned pseudo-version,
	// audited use: response bodies capped (maxXMLResponseBytes), server
	// errors truncated, govulncheck in CI. Re-evaluate on any replacement fork.
	github.com/kolo/xmlrpc v0.0.0-20220921171641-a4b6fa1dd06b
	github.com/spf13/cobra v1.9.1
	github.com/spf13/viper v1.20.1
	golang.org/x/term v0.29.0
)

require (
	github.com/zalando/go-keyring v0.2.8
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/fsnotify/fsnotify v1.8.0 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.9.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.39.0 // indirect
)
