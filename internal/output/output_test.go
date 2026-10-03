package output

import (
	"strings"
	"testing"
)

func TestSanitizeTableCellControls(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "Acme Corp", "Acme Corp"},
		{"unicode", "Müller café 北京 🙂", "Müller café 北京 🙂"},
		{"esc", "a\x1bb", `a\x1Bb`},
		{"osc52", "\x1b]52;c;Zm9v\x07", `\x1B]52;c;Zm9v\x07`},
		{"c1", "a" + "\u0085" + "b", `a\u0085b`},
		{"del", "a\x7fb", `a\x7Fb`},
		{"newline-tab", "a\nb\tc", `a\nb\tc`},
	}
	for _, tc := range cases {
		if got := sanitizeTableCell(tc.in); got != tc.want {
			t.Errorf("%s: got %q want %q", tc.name, got, tc.want)
		}
	}
}

func TestSanitizeTableCellIdempotent(t *testing.T) {
	in := "x" + "\x1b" + "]52;c;eQ==" + "\x07" + "y\r" + "z" + "\u0085"
	once := sanitizeTableCell(in)
	twice := sanitizeTableCell(once)
	if once != twice {
		t.Errorf("not idempotent: %q vs %q", once, twice)
	}
	if strings.IndexFunc(once, isTableUnsafe) >= 0 {
		t.Errorf("sanitized output still has controls: %q", once)
	}
}

func TestToRowsEscapesCellsAndHeaders(t *testing.T) {
	env := map[string]any{"result": []any{
		map[string]any{"na\x1bme": "a\rb", "ok": "fine ✓"},
	}}
	rows := toRows(env)
	if len(rows) != 2 {
		t.Fatalf("want header+1 row, got %d", len(rows))
	}
	for _, r := range rows {
		for _, c := range r {
			if strings.IndexFunc(c, isTableUnsafe) >= 0 {
				t.Errorf("raw control reached table: %q", c)
			}
		}
	}
	if !strings.Contains(rows[0][0], `\x1B`) {
		t.Errorf("header not escaped: %q", rows[0])
	}
}
