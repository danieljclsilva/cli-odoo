// Package output renders stable command results for humans and AI agents.
package output

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Format selects the renderer.
type Format string

const (
	JSON  Format = "json"
	Table Format = "table"
	YAML  Format = "yaml"
)

var def Format = JSON

// ParseFormat validates a --format flag value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(s)) {
	case JSON:
		return JSON, nil
	case Table:
		return Table, nil
	case YAML:
		return YAML, nil
	default:
		return "", fmt.Errorf("invalid --format %q: want json|table|yaml", s)
	}
}

// SetDefault sets the process-wide format (called from PersistentPreRunE).
func SetDefault(f Format) { def = f }

// Print renders v with the default format to stdout.
func Print(v any) {
	switch def {
	case Table:
		printTable(v)
	case YAML:
		b, err := yaml.Marshal(v)
		if err != nil {
			Fatal(err)
		}
		fmt.Print(string(b))
	default:
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			Fatal(err)
		}
		fmt.Println(string(b))
	}
}

// Envelope is the standard command result shape.
type Envelope struct {
	Success bool   `json:"success" yaml:"success"`
	Tool    string `json:"tool" yaml:"tool"`
	Error   string `json:"error,omitempty" yaml:"error,omitempty"`
	Result  any    `json:"result,omitempty" yaml:"result,omitempty"`
	Count   int    `json:"count,omitempty" yaml:"count,omitempty"`
}

// Ok prints a successful result envelope.
func Ok(tool string, result any, count int) {
	Print(Envelope{Success: true, Tool: tool, Result: result, Count: count})
}

// Fail prints a failure envelope and exits non-zero.
func Fail(tool string, err error) {
	Print(Envelope{Success: false, Tool: tool, Error: err.Error()})
	os.Exit(1)
}

// Fatal prints err to stderr and exits non-zero (for pre-output failures).
func Fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}

func printTable(v any) {
	// Best-effort table: JSON fallback for shapes we don't tabulate.
	b, err := json.Marshal(v)
	if err != nil {
		Fatal(err)
	}
	var decoded any
	if err := json.Unmarshal(b, &decoded); err != nil {
		Fatal(err)
	}
	rows := toRows(decoded)
	if len(rows) == 0 {
		fmt.Println(string(b))
		return
	}
	widths := map[int]int{}
	for _, r := range rows {
		for i, c := range r {
			if len(c) > widths[i] {
				widths[i] = len(c)
			}
		}
	}
	for _, r := range rows {
		cells := make([]string, len(r))
		for i, c := range r {
			cells[i] = c + strings.Repeat(" ", widths[i]-len(c))
		}
		fmt.Println(strings.Join(cells, "  "))
	}
}

func toRows(v any) [][]string {
	env, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	res, ok := env["result"]
	if !ok {
		return nil
	}
	list, ok := res.([]any)
	if !ok || len(list) == 0 {
		return nil
	}
	first, ok := list[0].(map[string]any)
	if !ok {
		return nil
	}
	keys := make([]string, 0, len(first))
	for k := range first {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	rows := [][]string{keys}
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return nil
		}
		row := make([]string, len(keys))
		for i, k := range keys {
			row[i] = stringify(m[k])
		}
		rows = append(rows, row)
	}
	return rows
}

func stringify(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}
