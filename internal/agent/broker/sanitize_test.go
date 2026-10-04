package broker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/danieljclsilva/cli-odoo/internal/config"
)

// Pure unit tests on synthetic strings: no broker, no Odoo, no keychain,
// no network. Malicious fixture tokens are obvious fakes (FAKE-…).

func TestSanitizePlainAccessToken(t *testing.T) {
	in := map[string]any{
		"body": `<a href="https://tickets.example.com/t/2081?access_token=FAKE-TOKEN-123">portal</a>`,
	}
	got := SanitizePayload(in).(map[string]any)["body"].(string)
	if strings.Contains(got, "FAKE-TOKEN-123") {
		t.Fatalf("token survived: %s", got)
	}
	if !strings.Contains(got, "access_token="+RedactionMarker) {
		t.Fatalf("marker missing: %s", got)
	}
	if !strings.Contains(got, "https://tickets.example.com/t/2081?") {
		t.Fatalf("URL destroyed: %s", got)
	}
}

// Item 1: every occurrence redacts, including mixed plain/percent/entity
// forms and repeated parameters in one string.
func TestSanitizeMixedEncodingAllOccurrences(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"mixed plain+encoded", `?access_token=FAKE-A&api%5Fkey=FAKE-B`},
		{"repeated param", `?token=FAKE-A&x=1&token=FAKE-B`},
		{"mixed entity+plain", `?a=1&amp;access_token=FAKE-A&amp;secret=FAKE-B`},
		{"encoded name+sep", `?access%5Ftoken%3DFAKE-A`},
		{"entity separator", `?a=1&#38;password=FAKE-A`},
		{"case-insensitive", `?PASSWORD=FAKE-A&Api_Key=FAKE-B`},
		{"leading fragment", `access_token=FAKE-A`},
		{"semicolon separator", `?a=1;secret=FAKE-A;b=2`},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		if c := strings.Count(got, RedactionMarker); c < strings.Count(tc.in, "FAKE-") {
			t.Fatalf("%s: only %d markers for %q -> %q", tc.name, c, tc.in, got)
		}
	}
}

// Item 2: full credential values with URL-significant characters are
// removed whole (raw and encoded): / + = ? , ( ) inside the value.
func TestSanitizeCredentialValueChars(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"slash", `?password=/FAKE-SECRET`},
		{"plus", `?password=a+FAKE-SECRET+b`},
		{"equals", `?password=a=FAKE-SECRET`},
		{"question", `?password=FAKE-SECRET?x`},
		{"comma", `?secret=FAKE-SECRET,more`},
		{"parens", `?secret=(FAKE-SECRET)`},
		{"encoded slash", `?password=%2FFAKE-SECRET`},
		{"encoded plus", `?password=a%2BFAKE-SECRET`},
		{"embedded", `see https://x.example/?token=FAKE-SECRET&next=1 ok`},
		{"leading", `password=FAKE-SECRET end`},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-SECRET") {
			t.Fatalf("%s: value leaked in %q -> %q", tc.name, tc.in, got)
		}
		if !strings.Contains(got, RedactionMarker) {
			t.Fatalf("%s: marker missing in %q -> %q", tc.name, tc.in, got)
		}
	}
	// Separators that START a new parameter/fragment survive; the marker
	// replaces only the recognized value.
	got := SanitizePayload(`https://x.example/?access_token=FAKE-A&next=1`).(string)
	if !strings.Contains(got, "&next=1") {
		t.Fatalf("parameter delimiter swallowed: %q", got)
	}
	got = SanitizePayload(`https://x.example/?access_token=FAKE-B#frag`).(string)
	if !strings.Contains(got, "#frag") {
		t.Fatalf("fragment delimiter swallowed: %q", got)
	}
}

// Item R5-1: single-pass encoded delimiters open parameters: %26/%3B/%3F/
// %23 before a name, mixed with encoded names/separators, across every
// occurrence. Legitimate unrelated values survive.
func TestSanitizeEncodedDelimiters(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		keep []string
	}{
		{"pct-amp delimiter", `https://x/?ok=1%26api_key%3DFAKE-B`, []string{"ok=1"}},
		{"pct-question path", `https://x/%3Fapi_key%3DFAKE-B`, nil},
		{"pct-semicolon", `?a=1%3Bsecret%3DFAKE-A`, []string{"a=1"}},
		{"pct-hash", `?a=1%23secret%3DFAKE-A`, []string{"a=1"}},
		{"mixed encoded name+sep", `?access%5Ftoken%3DFAKE-A&x=1`, []string{"x=1"}},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		if !strings.Contains(got, RedactionMarker) {
			t.Fatalf("%s: marker missing in %q -> %q", tc.name, tc.in, got)
		}
		for _, k := range tc.keep {
			if !strings.Contains(got, k) {
				t.Fatalf("%s: legitimate value lost in %q -> %q", tc.name, tc.in, got)
			}
		}
	}
}

// Item R5-2: entities inside values — terminator entities end the value
// and survive; other entities are value characters removed with it.
func TestSanitizeValueEntities(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		keep []string
	}{
		{"numeric slash entity", `?password=A&#47;FAKE-B`, nil},
		{"named slash entity", `?password=A&sol;FAKE-B`, nil},
		{"entity terminator survives", `?password=FAKE-A&amp;next=1`, []string{"&amp;", "next=1"}},
		{"numeric term entity", `?password=FAKE-A&#38;next=1`, []string{"&#38;", "next=1"}},
		{"bare amp separates", `?password=FAKE-A&next=1`, []string{"&next=1"}},
		{"unterminated separates", `?password=FAKE-A&ampnext=1`, []string{"&ampnext=1"}},
		{"entity-leading value", `?password=&#65;FAKE-B`, nil},
		{"hex entity value", `?password=A&#x2F;FAKE-B`, nil},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		if !strings.Contains(got, RedactionMarker) {
			t.Fatalf("%s: marker missing in %q -> %q", tc.name, tc.in, got)
		}
		for _, k := range tc.keep {
			if !strings.Contains(got, k) {
				t.Fatalf("%s: legitimate survivor lost in %q -> %q", tc.name, tc.in, got)
			}
		}
	}
	// Legitimate following-parameter and HTML text controls stay exact.
	for _, in := range []string{
		`Fish &amp; chips, 100% sure`,
		`?a=1&amp;b=2`,
	} {
		if got := SanitizePayload(in).(string); got != in {
			t.Fatalf("legitimate text rewritten: %q -> %q", in, got)
		}
	}
}

func TestSanitizeUnicodeScalarEntities(t *testing.T) {
	// Response6 item 1: valid Unicode scalar entity value characters
	// (decimal, hex, >255, entity-leading, malformed/overlong neighbors)
	// are removed WITH the recognized value — never leaked as suffix.
	for _, tc := range []struct {
		name string
		in   string
		keep []string
	}{
		{"astral hex", `<a href="https://x/?password=A&#x1f600;FAKE-B">link</a>`, []string{"<a href=", ">link</a>"}},
		{"decimal 256", `?password=A&#256;FAKE-B`, nil},
		{"entity-leading", `?password=&#65;FAKE-B`, nil},
		{"malformed neighbor", `?password=FAKE-A&note=&#xZZ;`, nil},
		{"overlong ambiguous", `?password=FAKE-A&#1114112;`, nil},
		{"surrogate scalar", `?password=A&#55296;FAKE-B`, nil},
		{"zeros overlong", `?password=A&#0000000000000065;FAKE-B&next=1`, []string{"&next=1"}},
		{"out-of-range 80 nines", `<a href="https://x/?password=A&#` + strings.Repeat("9", 80) + `;FAKE-B">link</a>`, []string{`">link</a>`}},
		{"out-of-range 100 nines", `?password=A&#` + strings.Repeat("9", 100) + `;FAKE-B&next=1`, []string{"&next=1"}},
		{"out-of-range 1000 nines", `?password=A&#` + strings.Repeat("9", 1000) + `;FAKE-B`, nil},
		{"out-of-range hex ffff...", `?password=A&#x` + strings.Repeat("F", 40) + `;FAKE-B`, nil},
		{"zero-leading nonzero 065", `?password=A&#065;FAKE-B&next=1`, []string{"&next=1"}},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		if !strings.Contains(got, RedactionMarker) {
			t.Fatalf("%s: marker missing in %q -> %q", tc.name, tc.in, got)
		}
		for _, k := range tc.keep {
			if !strings.Contains(got, k) {
				t.Fatalf("%s: legitimate survivor lost in %q -> %q", tc.name, tc.in, got)
			}
		}
	}
}

func TestSanitizeHrefEntityValues(t *testing.T) {
	// Response6 item 2: decoded quote/markup entities inside an HTML
	// attribute value are VALUE characters — the entire recognized value
	// is removed while outer markup and true next parameters survive.
	for _, tc := range []struct {
		name string
		in   string
		keep []string
	}{
		{"quot entity", `<a href="https://x/?password=A&quot;FAKE-B">link</a>`, []string{`<a href="`, `">link</a>`}},
		{"lt entity", `<a href="https://x/?password=A&lt;FAKE-B">link</a>`, []string{`<a href="`, `">link</a>`}},
		{"apos entity single-quote", `<a href='https://x/?password=A&apos;FAKE-B'>link</a>`, []string{`<a href='`, `'>link</a>`}},
		{"src attribute", `<img src="https://x/?token=A&lt;FAKE-B">`, []string{`<img src="`, `">`}},
		{"action attribute", `<form action="https://x/?token=A&quot;FAKE-B">`, []string{`<form action="`, `">`}},
		{"non-first param href", `<a href="https://x/?a=1&amp;password=A&quot;FAKE-B">link</a>`, []string{`<a href="`, `">link</a>`}},
		{"long prefix href", `<a href="https://x/` + strings.Repeat("x", 600) + `?password=A&quot;FAKE-B">link</a>`, []string{`">link</a>`}},
		{"next param survives", `<a href="https://x/?password=FAKE-A&amp;order_ref=123">link</a>`, []string{`&amp;order_ref=123`, `">link</a>`}},
		{"second credential redacts", `<a href="https://x/?password=FAKE-A&amp;token=FAKE-B">link</a>`, []string{`">link</a>`}},
		{"unicode ordinary next param", `<a href="https://x/?password=FAKE-A&amp;票=123">link</a>`, []string{`&amp;票=123`, `">link</a>`}},
		{"long ordinary next param", `<a href="https://x/?password=FAKE-A&amp;` + strings.Repeat("a", 65) + `=123">link</a>`, []string{`&amp;` + strings.Repeat("a", 65) + `=123`, `">link</a>`}},
		{"unicode next param single-quote", `<a href='https://x/?password=FAKE-A&amp;naïve=1'>link</a>`, []string{`&amp;naïve=1`, `'>link</a>`}},
		{"numeric-sep unicode next param", `<a href="https://x/?password=FAKE-A&#38;票=123">link</a>`, []string{`&#38;票=123`, `">link</a>`}},
		{"pct-encoded unicode next param", `<a href="https://x/?password=FAKE-A&amp;%E7%A5%A8=123">link</a>`, []string{`&amp;%E7%A5%A8=123`, `">link</a>`}},
		{"1000-char ordinary next param", `<a href="https://x/?password=FAKE-A&amp;` + strings.Repeat("a", 1000) + `=123">link</a>`, []string{`&amp;` + strings.Repeat("a", 1000) + `=123`, `">link</a>`}},
		{"mixed unicode+entity ordinary next param", `<a href="https://x/?password=FAKE-A&amp;票&#95;x=123">link</a>`, []string{`&amp;票&#95;x=123`, `">link</a>`}},
		{"hex entity underscore ordinary next param", `<a href="https://x/?password=FAKE-A&amp;n&#x5F;x=123">link</a>`, []string{`&amp;n&#x5F;x=123`, `">link</a>`}},
		{"pct underscore ordinary next param", `<a href="https://x/?password=FAKE-A&amp;n%5Fx=123">link</a>`, []string{`&amp;n%5Fx=123`, `">link</a>`}},
		{"json-escape underscore ordinary next param", `<a href="https://x/?password=FAKE-A&amp;n\u005Fx=123">link</a>`, []string{`&amp;n\u005Fx=123`, `">link</a>`}},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		if !strings.Contains(got, RedactionMarker) {
			t.Fatalf("%s: marker missing in %q -> %q", tc.name, tc.in, got)
		}
		for _, k := range tc.keep {
			if !strings.Contains(got, k) {
				t.Fatalf("%s: legitimate survivor lost in %q -> %q", tc.name, tc.in, got)
			}
		}
	}
	// Text context (no href/src/action attribute): quote/markup entities
	// are value characters, consumed inside the recognized value
	// (fail closed); the true `&`-separator before the next parameter
	// survives as the following delimiter.
	if got := SanitizePayload(`?password=A&#34;FAKE-B&next=1`).(string); got != `?password=[REDACTED:credential]&next=1` {
		t.Fatalf("text-entity behavior changed: %q", got)
	}
}
func TestSanitizeLexerMalformedAndUnquoted(t *testing.T) {
	// Reviewer P0: `=`-at-EOF inputs carry no secret — byte-for-byte,
	// no panic, no marker.
	for _, in := range []string{`<a href=`, `<a href=   `, `<a foo=`} {
		if got := SanitizePayload(in).(string); got != in {
			t.Fatalf("EOF input changed: %q -> %q", in, got)
		}
	}
	// Reviewer P1: unquoted URL-attribute values redact the credential
	// as body text; raw `>` ends the value so markup survives.
	for _, in := range []string{
		`<a href=https://x/?password=FAKE-B>`,
		`<a href=https://x/?password=FAKExhay>`,
	} {
		got := SanitizePayload(in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("secret survived in %q -> %q", in, got)
		}
		if !strings.Contains(got, `[REDACTED:credential]>`) {
			t.Fatalf("markup lost in %q -> %q", in, got)
		}
	}
	// Response10 item 2: raw `>` stays INSIDE a quoted attribute value —
	// only the matching quote closes. The whole credential value is
	// removed; closing markup and true following params survive.
	for _, tc := range []struct {
		name string
		in   string
		keep []string
	}{
		{"raw gt double-quote", `<a href="https://x/?note=>x&password=A'FAKE-B">link</a>`, []string{`">link</a>`}},
		{"raw gt single-quote", `<a href='https://x/?note=>x&password=A"FAKE-B'>link</a>`, []string{`'>link</a>`}},
		{"raw gt plus next param", `<a href="https://x/?note=>x&password=A'FAKE-B&amp;order_ref=123">link</a>`, []string{`&amp;order_ref=123`, `">link</a>`}},
		{"opposite raw quote inside", `<a href="https://x/?note='q&password=FAKE-B">link</a>`, []string{`">link</a>`}},
		{"backslash plus matching quote", `<a href="https://x/?password=FAKE-B\">link</a>`, []string{`">link</a>`}},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		if !strings.Contains(got, RedactionMarker) {
			t.Fatalf("%s: marker missing in %q -> %q", tc.name, tc.in, got)
		}
		for _, k := range tc.keep {
			if !strings.Contains(got, k) {
				t.Fatalf("%s: legitimate survivor lost in %q -> %q", tc.name, tc.in, got)
			}
		}
	}
	// Response10 item 3: unterminated quoted values run to EOF — consumed
	// once, never reparsed as fabricated inner attribute spans. True
	// later attributes on well-formed tags still lex normally.
	for _, tc := range []struct {
		name string
		in   string
		keep []string
	}{
		{"unterminated double-quote EOF", `<a href="https://x/?note=x href='x&password=A'FAKE-B`, []string{RedactionMarker}},
		{"unterminated single-quote EOF", `<a href='https://x/?note=x href="x&password=A"FAKE-B`, []string{RedactionMarker}},
		{"inner href in non-URL attr", `<a title="a href='x&password=FAKE-B" href="https://x/?a=1">t</a>`, []string{`">t</a>`}},
		{"well-formed later attr", `<a href="https://x/?a=1" title="t">t</a>`, []string{`title="t"`, `">t</a>`}},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		for _, k := range tc.keep {
			if !strings.Contains(got, k) {
				t.Fatalf("%s: legitimate survivor lost in %q -> %q", tc.name, tc.in, got)
			}
		}
	}
}

func TestSanitizeUnrelatedValueBoundaries(t *testing.T) {
	// Comma/colon-joined credential-looking substrings inside an unrelated
	// value are NOT parameters — byte-preserved. A bare `name=value`
	// after whitespace IS a parameter (prose assignment): it redacts by
	// query fragment — see the doc comment on isParamBoundary.
	for _, in := range []string{
		`https://x/?description=foo,password=bar&n=1`,
		`https://x/?description=foo:token=bar&n=1`,
	} {
		if got := SanitizePayload(in).(string); got != in {
			t.Fatalf("ordinary business data rewritten: %q -> %q", in, got)
		}
	}
	for _, in := range []string{
		`https://x/?description=foo&password=FAKE-B&n=1`,
		`https://x/?a=1;secret=FAKE-C`,
	} {
		got := SanitizePayload(in).(string)
		if strings.Contains(got, "FAKE-") || !strings.Contains(got, RedactionMarker) {
			t.Fatalf("true-boundary secret missed in %q -> %q", in, got)
		}
	}
}

// whole-string JSON must still redact; credential-free escaped JSON stays
// byte-identical.
func TestSanitizeJSONEscapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"plain value in JSON string", "{\"url\":\"https://x/?access_token=FAKE-B\"}"},
		{"JSON-escaped separator", "{\"url\":\"https://x/?token\\u003DFAKE-B\"}"},
		{"nested string", "{\"rows\":[\"?token=FAKE-B\"]}"},
		{"fully escaped assignment", `api\u005Fkey\u003DFAKE-B`},
	} {
		got := SanitizePayload(tc.in).(string)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: secret survived in %q -> %q", tc.name, tc.in, got)
		}
		if !strings.Contains(got, RedactionMarker) {
			t.Fatalf("%s: marker missing in %q -> %q", tc.name, tc.in, got)
		}
	}
	for _, in := range []string{
		`{"k":"caf\u00e9 \u2603 \"q\"","n":1}`,
		"{\"a\":1}",
	} {
		if got := SanitizePayload(in).(string); got != in {
			t.Fatalf("credential-free escaped JSON changed: %q -> %q", in, got)
		}
	}
}

// Item R5-4: duplicate members survive a targeted secret edit.
func TestSanitizeJSONDuplicates(t *testing.T) {
	in := `{"a":1,"a":2,"url":"?token=FAKE-B"}`
	got := SanitizePayload(in).(string)
	if strings.Contains(got, "FAKE-") {
		t.Fatalf("secret survived: %q", got)
	}
	if c := strings.Count(got, `"a":`); c != 2 {
		t.Fatalf("duplicate members lost (%d): %q", c, got)
	}
	if !strings.Contains(got, `"a":1`) || !strings.Contains(got, `"a":2`) {
		t.Fatalf("unrelated duplicate values changed: %q", got)
	}
	// Embedded HTML + Unicode/number/escape preservation on the same path.
	in = "{\"note\":\"<b>caf\u00e9</b> &amp; co\",\"n\":1e3,\"url\":\"?secret=FAKE-B\"}"
	got = SanitizePayload(in).(string)
	if strings.Contains(got, "FAKE-") {
		t.Fatalf("secret survived: %q", got)
	}
	for _, k := range []string{`<b>caf`, `&amp; co`, `1e3`} {
		if !strings.Contains(got, k) {
			t.Fatalf("unrelated content lost (%q): %q", k, got)
		}
	}
}

// Item 3: a malformed % in an unrelated parameter never hides a valid
// credential occurrence elsewhere; ordinary unrelated text survives.
func TestSanitizeMalformedUnrelatedEncoding(t *testing.T) {
	got := SanitizePayload(`?api%5Fkey=FAKE-SECRET&note=100%`).(string)
	if strings.Contains(got, "FAKE-SECRET") {
		t.Fatalf("LEAK: %q", got)
	}
	for _, k := range []string{`api%5Fkey=`, `note=100%`} {
		if !strings.Contains(got, k) {
			t.Fatalf("unrelated content lost (%q): %q", k, got)
		}
	}
}

func TestSanitizeAdversarialPerf(t *testing.T) {
	// Response7/9 item 4-5: bounded temporary memory + linear scanning at
	// the 1 MiB input bound, incl. malformed-tag storms (outer + inner
	// cursors advance monotonically — no repeated suffix rescans).
	longAttr := `<a ` + strings.Repeat("z", 100000) + `="https://x/?password=FAKE-B">t</a>`
	manyTags := strings.Repeat(`<a b="c">`, 20000) + `?password=FAKE-B`
	manyParams := `?` + strings.Repeat("a=1&", 20000) + `password=FAKE-B`
	malformed1k := strings.Repeat("<a ", 1000) + `?password=FAKE-B`
	malformed4k := strings.Repeat("<a ", 4000) + `?password=FAKE-B`
	malformed12k := strings.Repeat("<a ", 12000) + `?password=FAKE-B`
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"100k-letter attribute name", longAttr},
		{"20k tags", manyTags},
		{"20k params", manyParams},
		{"108k ordinary text", strings.Repeat("lorem ipsum dolor sit amet ", 4000)},
		{"malformed tags N=1000", malformed1k},
		{"malformed tags N=4000", malformed4k},
		{"malformed tags N=12000", malformed12k},
		// Response12 item 1: unbounded ordinary-name separator lookahead
		// stays near-linear near the 1 MiB bound (index arithmetic only,
		// disjoint segments per entity — no repeated suffix rescans).
		{"900k ordinary name after entity", `<a href="https://x/?password=FAKE-A&amp;` + strings.Repeat("a", 900000) + `=123">link</a>`},
	} {
		start := time.Now()
		got := SanitizePayload(tc.in).(string)
		dt := time.Since(start)
		if strings.Contains(got, "FAKE-") {
			t.Fatalf("%s: LEAK", tc.name)
		}
		if dt > 2*time.Second {
			t.Fatalf("%s: TOO SLOW %v", tc.name, dt)
		}
	}
}

// Item 4: credential-free JSON returns byte-for-byte (whitespace, order,
// large integers, exponents, decimals, Unicode, escapes preserved);
// only strings carrying recognized secrets change.
func TestSanitizeJSONPrecision(t *testing.T) {
	for _, in := range []string{
		` { "z": 9007199254740993, "a": 1 } `,
		`{"n":1e400,"d":0.30000000000000004,"u":"héllo wörld 票","e":"a\"b\\c"}`,
		`[3, 2, 1]`,
		`{"url":"https://x.example/?a=1","id":7}`,
	} {
		if got := SanitizePayload(in).(string); got != in {
			t.Fatalf("credential-free JSON changed: %q -> %q", in, got)
		}
	}
	// Numbers that would lose precision under float64 survive exactly.
	got := SanitizePayload(`{"z": 9007199254740993}`).(string)
	if !strings.Contains(got, "9007199254740993") {
		t.Fatalf("large integer rounded: %q", got)
	}
	// A nested secret redacts the value only (order/whitespace may
	// normalize on this documented path).
	got = SanitizePayload(`{"url":"https://x.example/?access_token=FAKE-E","id":7}`).(string)
	if strings.Contains(got, "FAKE-E") || !strings.Contains(got, RedactionMarker) {
		t.Fatalf("nested secret survived: %q", got)
	}
}

// Item 5: 100k ordinary letters stay linear and unchanged; a mixed
// encoded secret in a large body still redacts.
func TestSanitizeLargeOrdinaryText(t *testing.T) {
	big := strings.Repeat("lorem ipsum dolor sit amet ", 4000) // ~108k chars
	if got := SanitizePayload(big).(string); got != big {
		t.Fatal("large ordinary text rewritten")
	}
	mixed := big + `?access_token=FAKE-A&api%5Fkey=FAKE-B` + big
	got := SanitizePayload(mixed).(string)
	if strings.Contains(got, "FAKE-") {
		t.Fatal("secret survived in large body")
	}
	if c := strings.Count(got, RedactionMarker); c != 2 {
		t.Fatalf("want 2 markers in large body, got %d", c)
	}
}

func TestSanitizeLegitimateControls(t *testing.T) {
	for _, in := range []string{
		`Order SO-12345 for partner 99, ref access_tokenizer-ok`,
		`https://x.example/?order_ref=12345&team_id=1891`,
		`my_access_tokenizer=ok should stay`,
		`Unicode intact: héllo wörld 票 — no params here`,
		`ACCESS_TOKEN without equals stays literal`,
		`see https://x.example/?a=1 and no params`,
	} {
		if got := SanitizePayload(in).(string); got != in {
			t.Fatalf("legitimate text rewritten: %q -> %q", in, got)
		}
	}
	if got := SanitizePayload(float64(1891)).(float64); got != 1891 {
		t.Fatalf("numeric type changed: %v", got)
	}
	rows := []any{map[string]any{"id": 1, "name": "a"}}
	got := SanitizePayload(rows).([]any)
	if len(got) != 1 {
		t.Fatalf("row count changed: %v", got)
	}
}

// Item 6: shared-boundary coverage — writeRows and linked-evidence success
// paths redact record strings (not helper-only). Synthetic stored values;
// no grant/admin tokens involved.
func TestWriteRowsRedactsRecordPayload(t *testing.T) {
	p := testPolicy()
	b, err := New(p, &config.Instance{Name: "test"}, testSnapshot())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tok := grantToken(t, b)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/rpc/search", nil)
	rows := []any{map[string]any{
		"id":   1,
		"body": `<a href="https://tickets.example.com/t/2081?access_token=FAKE-ROW">portal</a>`,
	}}
	b.writeRows(rec, req, tok, rows, 1)
	if rec.Code != http.StatusOK {
		t.Fatalf("writeRows denied: %d (%s)", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "FAKE-ROW") {
		t.Fatalf("record secret survived writeRows: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), RedactionMarker) {
		t.Fatalf("marker missing in writeRows envelope: %s", rec.Body.String())
	}
}

func TestEvidenceDownloadDescriptorSanitized(t *testing.T) {
	// The synthetic trigger from response4 item 6: a stored mimetype
	// carrying a credential parameter must not cross raw.
	got := SanitizePayload(map[string]any{
		"name":     "ticket.pdf",
		"mimetype": "text/plain;password=FAKE-SECRET",
	}).(map[string]any)
	if strings.Contains(got["mimetype"].(string), "FAKE-SECRET") {
		t.Fatalf("mimetype secret survived: %v", got)
	}
	if !strings.Contains(got["mimetype"].(string), RedactionMarker) {
		t.Fatalf("mimetype marker missing: %v", got)
	}
	if got["name"] != "ticket.pdf" {
		t.Fatalf("legitimate name rewritten: %v", got)
	}
}

func TestSanitizeGrantPassthrough(t *testing.T) {
	// The admin grant token envelope never passes through SanitizePayload
	// (raw writer path). This pins the invariant: a bare token string with
	// no credential parameter assignment is NOT rewritten, so routing the
	// grant response here by mistake would still leak — keep it raw.
	raw := "9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d"
	if got := SanitizePayload(raw).(string); got != raw {
		t.Fatalf("bare token rewritten (grant path must stay raw anyway): %q", got)
	}
}
