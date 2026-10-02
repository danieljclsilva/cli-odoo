package odoo

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// ParseDomain parses a --domain flag value. "" yields an empty domain,
// otherwise the value must be a JSON array (error on objects/scalars).
func ParseDomain(s string) (any, error) {
	if strings.TrimSpace(s) == "" {
		return []any{}, nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, fmt.Errorf("invalid --domain JSON: %w", err)
	}
	switch t := v.(type) {
	case []any:
		return t, nil
	case map[string]any:
		return nil, fmt.Errorf("invalid --domain: want JSON array, got object")
	default:
		return nil, fmt.Errorf("invalid --domain: want JSON array")
	}
}

// ParseCSV splits a --fields style CSV flag, trimming spaces.
// Empty input yields nil.
func ParseCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// ParseJSONObj parses a JSON object flag value. "" yields an empty map.
func ParseJSONObj(s string) (map[string]any, error) {
	if strings.TrimSpace(s) == "" {
		return map[string]any{}, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("invalid JSON object: %w", err)
	}
	return m, nil
}

// ParseIDs converts ID strings to ints, erroring on non-numeric input.
func ParseIDs(strs []string) ([]int, error) {
	out := make([]int, 0, len(strs))
	for _, s := range strs {
		t := strings.TrimSpace(s)
		if t == "" {
			continue
		}
		n, err := strconv.Atoi(t)
		if err != nil {
			return nil, fmt.Errorf("invalid id %q: want integer", s)
		}
		out = append(out, n)
	}
	return out, nil
}
