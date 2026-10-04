package broker

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// RedactionMarker replaces recognized bearer/password/API-secret values in
// successful record payloads. The marker is explicit and stable: operators
// can distinguish "value removed" from "value empty".
const RedactionMarker = "[REDACTED:credential]"

// maxSanitizeStringLen bounds one string through the sanitizer; longer
// strings are still scanned but nested-JSON decoding is skipped past it.
const maxSanitizeStringLen = 1 << 20 // 1 MiB

// maxSanitizeDepth bounds recursive nested-JSON descent.
const maxSanitizeDepth = 3

// maxNameRawLen bounds the raw bytes consumed by one decode-aware name
// match (encoded names are longer than their decoded form). Every match
// attempt is O(1)-bounded, so scanning stays linear in input length.
const maxNameRawLen = 320

// maxEntityNameLen bounds a named-entity scan (`&name;`) inside values and
// names, keeping every entity decision O(1)-bounded.
const maxEntityNameLen = 10

// SanitizePayload deep-walks decoded JSON record values and redacts
// recognized credential-bearing URL query parameter values, replacing them
// with RedactionMarker. Recognized names (case-insensitive, exact):
// access_token, auth_token, token, api_key, apikey, password, passwd,
// secret, client_secret. Business codes/IDs, Unicode, JSON types
// (numbers/bools/null untouched), normal query parameters, ordinary text,
// and legitimate URLs are preserved.
//
// Value rule (URL query context): the value runs from the name/value
// separator to the next parameter separator (`&`, `;`), fragment (`#`),
// whitespace, quote, or angle bracket, or end of string. Characters that
// may legally occur inside a query value — `/`, `+`, `=`, `?`, `,`,
// parens, dots, valid or malformed `%` sequences — are consumed as part of
// the value, so the ENTIRE recognized value is removed and only the
// surrounding delimiters survive.
//
// Encodings (single pass, per segment, every occurrence):
//   - raw names and separators;
//   - `%XX`-encoded bytes in names (`api%5Fkey`), separators (`%3D`), and
//     delimiters before names (`%26`, `%3B`, `%3F`, `%23` act as parameter
//     boundaries, so `?ok=1%26api_key%3Dv` and `/%3Fapi_key%3Dv` redact);
//   - numeric/hex entities in names and separators (`&#95;`, `&#x5F;`,
//     `&#61;`);
//   - entity delimiters between parameters (`&amp;`, `&#38;`, `&#x26;`);
//   - entities INSIDE values interpreted in HTML context: an entity decoding
//     to an actual query separator (`&amp;`, `&#38;`, `&#59;`, `&#35;`,
//     whitespace, …) ends the value before a true next parameter and
//     survives as the following delimiter, while any other valid entity
//     (quotes, markup, `/`, scalars: `&quot;`, `&lt;`, `&#47;`,
//     `&sol;`, …) is a value character removed with the value;
//     a bare `&` (including unterminated legacy forms such as `&amp`
//     without `;`) always separates, per URL behavior.
//
// Matching never fails whole-string on malformed input: undecodable
// segments stay literal while valid credential occurrences elsewhere still
// redact. An ambiguous recognized representation redacts (fail closed).
//
// Nested JSON: whole-string objects/arrays only, validated with UseNumber
// (large integers, exponents, decimals keep exact precision), then edited
// by targeted string-literal surgery — ONLY literals whose decoded content
// carries a recognized secret are re-encoded; every other byte (member
// order including duplicates, whitespace, numbers, unrelated literals and
// their escapes) survives untouched. A rewrite touches just the changed
// literal (re-encoded without HTML escaping). Depth <= maxSanitizeDepth;
// strings over maxSanitizeStringLen skip the JSON attempt (the parameter
// scan still applies).
//
// Supported limits (explicit): one decode pass (double-encoded layers
// beyond it are unproven); raw `\uXXXX` escapes in names/separators
// (e.g. `\u005F`, `\u003D`) plus full supported JSON-string parsing
// with UseNumber precision; named `=` separators such as `&equals;`
// are unsupported; unterminated `&` forms separate rather than decode.
//
// Time/memory: one memoized forward HTML lexical pass per string plus
// one left-to-right scan; each byte is visited O(1) times, outer and
// inner lexical cursors advance monotonically, credential-name/entity
// attempts are raw-bounded (maxNameRawLen/maxEntityNameLen), the
// ordinary-name separator lookahead scans without allocation (index
// arithmetic only, disjoint segments per entity — linear total), and no
// whole-string decode/unescape is ever allocated.
// Finding the URL-attribute context of one value is a binary search
// over the memoized spans (O(log m) in the span count), so total time
// grows with matches × log(spans) on top of the linear scan.
// Binary attachment bytes are NOT examined: a text sanitizer cannot
// establish that downloaded files are secret-free. Grant/admin token
// envelopes MUST NOT pass through here (the admin grant response
// carries the raw session token by design, once, over the unix
// socket); callers keep that path on the raw writer.

func SanitizePayload(v any) any {
	out, _ := sanitizeValueChanged(v, 0)
	return out
}

func sanitizeValueChanged(v any, depth int) (any, bool) {
	switch t := v.(type) {
	case map[string]any:
		changed := false
		for k, e := range t {
			if ne, ch := sanitizeValueChanged(e, depth); ch {
				t[k] = ne
				changed = true
			}
		}
		return t, changed
	case []any:
		changed := false
		for i, e := range t {
			if ne, ch := sanitizeValueChanged(e, depth); ch {
				t[i] = ne
				changed = true
			}
		}
		return t, changed
	case string:
		return sanitizeStringChanged(t, depth)
	default:
		return v, false
	}
}

func sanitizeStringChanged(s string, depth int) (string, bool) {
	if s == "" {
		return s, false
	}
	// Supported representations parse BEFORE any fast-path rejection: a
	// JSON string carries `\uXXXX` escapes with no raw `=%&` bytes, so the
	// fast path below would wrongly declare it secret-free.
	if depth < maxSanitizeDepth && len(s) <= maxSanitizeStringLen {
		trimmed := strings.TrimSpace(s)
		if len(trimmed) >= 2 && (trimmed[0] == '{' || trimmed[0] == '[') {
			if out, ok := sanitizeJSONLiterals(s, trimmed, depth); ok {
				return out, true
			}
		}
	}
	// Fast path: without `=`, `%`, `&`, or `\` no raw, percent-encoded,
	// entity, or `\uXXXX`-escaped separator can exist, so no parameter
	// assignment is possible.
	if !strings.ContainsAny(s, "=%&\\") {
		return s, false
	}
	return redactURLSecrets(s)
}

// sanitizeJSONLiterals validates trimmed as one JSON object/array value
// (UseNumber keeps large integers, exponents, and decimals exact) and then
// rewrites ONLY the string literals whose decoded content carries a
// recognized secret. Duplicate members, member order, whitespace, numbers,
// and unrelated literals (including their escapes) survive byte-for-byte;
// a changed literal is re-encoded without HTML escaping. Malformed JSON
// returns unchanged so the caller falls through to the parameter scan.
func sanitizeJSONLiterals(s, trimmed string, depth int) (string, bool) {
	dec := json.NewDecoder(bytes.NewReader([]byte(trimmed)))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return s, false
	}
	if off := dec.InputOffset(); off < 0 || off > int64(len(trimmed)) || strings.TrimSpace(trimmed[off:]) != "" {
		return s, false
	}
	switch v.(type) {
	case map[string]any, []any:
	default:
		return s, false
	}
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	n := len(s)
	i := 0
	for i < n {
		if s[i] != '"' {
			b.WriteByte(s[i])
			i++
			continue
		}
		j := i + 1
		closed := false
		for j < n {
			if s[j] == '\\' && j+1 < n {
				j += 2
				continue
			}
			if s[j] == '"' {
				closed = true
				break
			}
			j++
		}
		if !closed {
			b.WriteString(s[i:])
			break
		}
		raw := s[i : j+1]
		var decoded string
		if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
			b.WriteString(raw)
			i = j + 1
			continue
		}
		if red, ch := sanitizeStringChanged(decoded, depth+1); ch {
			if enc, err := marshalJSONString(red); err == nil {
				b.WriteString(enc)
				i = j + 1
				changed = true
				continue
			}
		}
		b.WriteString(raw)
		i = j + 1
	}
	if !changed {
		return s, false
	}
	return b.String(), true
}

// marshalJSONString re-encodes one changed literal without HTML escaping,
// so `/`, Unicode, and `&` in the redacted content stay literal.
func marshalJSONString(s string) (string, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return "", err
	}
	return strings.TrimSuffix(b.String(), "\n"), nil
}

// redactURLSecrets replaces every recognized credential-parameter value in
// uniformly: the decode-aware name match sees through `%XX` and entities,
// so mixed (`?access_token=A&api%5Fkey=B`) and repeated parameters all
// redact. Non-matching runs are skipped whole (a parameter name can only
// start at a boundary, never mid-run).
func redactURLSecrets(s string) (string, bool) {
	n := len(s)
	var b strings.Builder
	b.Grow(n)
	var name [64]byte
	var changed bool
	// One forward HTML lexical pass per string (memoized spans): checking
	// one value's URL-attribute context is a binary search over the
	// memoized spans instead of a fresh backward scan per candidate.
	lex := scanHTMLURLAttrs(s)
	i := 0
	for i < n {
		c := s[i]
		if (isNameByte(c) || c == '%' || c == '&' || c == '\\') && isParamBoundary(s, i) {
			if dl, raw := decodeNameBuf(s, i, &name, maxNameRawLen); dl > 0 && credNameBytes(name[:dl]) {
				if sl := matchSepLen(s, i+raw); sl > 0 {
					vstart := i + raw + sl
					if ve := scanValueEndLex(s, vstart, lex); ve > vstart {
						b.WriteString(s[i:vstart])
						b.WriteString(RedactionMarker)
						i = ve
						changed = true
						continue
					}
				}
			}
			if isNameByte(c) {
				j := i + 1
				for j < n && isNameByte(s[j]) {
					j++
				}
				b.WriteString(s[i:j])
				i = j
				continue
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String(), changed
}

// decodeNameBuf decodes a parameter name starting at raw offset i into buf
// (lowercased): literal name bytes, `%XX` bytes, JSON `\uXXXX` escapes, and
// entities (`&#95;`, `&lowbar;`, …) that decode to name bytes. It stops at
// the first byte that is not part of the name (separators, value bytes,
// markup). Returns decoded length and raw bytes consumed; dl == 0 means no
// name.
func decodeNameBuf(s string, i int, buf *[64]byte, maxRaw int) (dl, raw int) {
	n := len(s)
	p := i
	d := 0
	for p < n && d < len(buf) && p-i < maxRaw {
		c := s[p]
		if isNameByte(c) {
			buf[d] = lowerByte(c)
			d++
			p++
			continue
		}
		if c == '\\' && p+5 < n && (s[p+1] == 'u' || s[p+1] == 'U') &&
			isHexByte(s[p+2]) && isHexByte(s[p+3]) && isHexByte(s[p+4]) && isHexByte(s[p+5]) {
			v := int(hexVal(s[p+2]))<<12 | int(hexVal(s[p+3]))<<8 | int(hexVal(s[p+4]))<<4 | int(hexVal(s[p+5]))
			if v > 255 || !isNameByte(byte(v)) {
				break
			}
			buf[d] = lowerByte(byte(v))
			d++
			p += 6
			continue
		}
		if c == '%' && p+2 < n && isHexByte(s[p+1]) && isHexByte(s[p+2]) {
			v := hexVal(s[p+1])<<4 | hexVal(s[p+2])
			if !isNameByte(v) {
				break
			}
			buf[d] = lowerByte(v)
			d++
			p += 3
			continue
		}
		if c == '&' {
			v, el, cls := parseEntity(s, p)
			if cls == entNone || len(v) != 1 || !isNameByte(v[0]) {
				break
			}
			buf[d] = lowerByte(v[0])
			d++
			p += el
			continue
		}
		break
	}
	return d, p - i
}

// matchSepLen matches a name/value separator at raw offset p: raw `=`,
// `%3D`, a JSON `\u003D` escape, or an entity decoding to `=` (`&#61;`,
// `&#x3D;`). Anything else (including `%26` or `&amp;`, which are
// parameter separators, not name/value separators) returns 0.
func matchSepLen(s string, p int) int {
	n := len(s)
	if p >= n {
		return 0
	}
	if s[p] == '=' {
		return 1
	}
	if s[p] == '\\' && p+5 < n && (s[p+1] == 'u' || s[p+1] == 'U') &&
		isHexByte(s[p+2]) && isHexByte(s[p+3]) && isHexByte(s[p+4]) && isHexByte(s[p+5]) &&
		int(hexVal(s[p+2]))<<12|int(hexVal(s[p+3]))<<8|int(hexVal(s[p+4]))<<4|int(hexVal(s[p+5])) == '=' {
		return 6
	}
	if s[p] == '%' && p+2 < n && isHexByte(s[p+1]) && isHexByte(s[p+2]) &&
		hexVal(s[p+1])<<4|hexVal(s[p+2]) == '=' {
		return 3
	}
	if s[p] == '&' {
		if v, el, cls := parseEntity(s, p); cls != entNone && len(v) == 1 && v[0] == '=' {
			return el
		}
	}
	return 0
}

// Entity classes from parseEntity.
const (
	// entNone means no valid entity: a bare `&` separates parameters.
	entNone = 0
	// entSep means the entity decodes to an actual query separator
	// (`&`, `;`, `#`, whitespace): `&amp;`, `&#38;`, `&#59;`, … It can
	// open a true next parameter.
	entSep = 1
	// entChar means the entity is a value character (quotes, markup,
	// slashes, scalars, unknown names); consume it inside the value.
	entChar = 2
)

// parseEntity parses one HTML entity at raw offset k (s[k] == '&'):
// numeric (`&#NNN;`, `&#xHH;`, any valid Unicode scalar value) or a small
// named set (`amp`, `lt`, `gt`, `quot`, `apos`, `sol`, case-insensitive).
// The decoded rune is returned with its UTF-8 encoding and raw length.
// A well-formed but unrecognized name (`&foo;`) is literal text, consumed
// as a value character when one is being scanned. Malformed or out-of-range
// numeric forms (including code points above the Unicode maximum) are
// consumed through the closing `;` INSIDE the recognized value when `;`
// follows before any true structural boundary (fail closed — see
// parseNumEntity); only a true boundary first (`&`, whitespace, quote,
// markup) means no entity at all, falling back to a bare `&` separator.
func parseEntity(s string, k int) (val []byte, rawLen int, cls int) {
	n := len(s)
	if k >= n || s[k] != '&' {
		return nil, 0, entNone
	}
	if r, el, ok := parseNumEntity(s, k); ok {
		enc := utf8Encode(r)
		if len(enc) == 1 && isSepByte(enc[0]) {
			return enc, el, entSep
		}
		return enc, el, entChar
	}
	if k+2 < n && isASCIILetter(s[k+1]) {
		j := k + 2
		for j < n && j-(k+1) <= maxEntityNameLen && isEntityNameByte(s[j]) {
			j++
		}
		if j < n && s[j] == ';' && j > k+1 {
			if v, ok := namedEntityVal(s[k+1 : j]); ok {
				if len(v) == 1 && isSepByte(v[0]) {
					return v, j + 1 - k, entSep
				}
				return v, j + 1 - k, entChar
			}
			return nil, j + 1 - k, entChar
		}
	}
	return nil, 0, entNone
}

// isSepByte reports whether b is an actual query separator: `&`, `;`,
// `#`, or whitespace. Quotes and markup (`"`, `'`, `<`, `>`) are NOT
// separators — their entities stay inside attribute values.
func isSepByte(b byte) bool {
	switch b {
	case '&', ';', '#', ' ', '\t', '\n', '\r':
		return true
	}
	return false
}

// namedEntityVal resolves the small named-entity set used in URL/HTML
// contexts (case-insensitive) to its decoded bytes. Anything else is not
// decoded here.
func namedEntityVal(name string) ([]byte, bool) {
	if len(name) < 2 || len(name) > maxEntityNameLen {
		return nil, false
	}
	lower := make([]byte, len(name))
	for i := 0; i < len(name); i++ {
		lower[i] = lowerByte(name[i])
	}
	switch string(lower) {
	case "amp":
		return []byte{'&'}, true
	case "lt":
		return []byte{'<'}, true
	case "gt":
		return []byte{'>'}, true
	case "quot":
		return []byte{'"'}, true
	case "apos":
		return []byte{'\''}, true
	case "sol":
		return []byte{'/'}, true
	}
	return nil, false
}

// parseNumEntity parses `&#NNN;` or `&#xHH;` (case-insensitive x/hex) at
// raw offset p as a Unicode scalar value. Values above the Unicode maximum
// (U+10FFFF), UTF-16 surrogates (U+D800–U+DFFF), overlong digit runs, and
// malformed lookalikes with entity shape (a following `;` before any true
// structural boundary) are consumed through `;` INSIDE the value (fail
// closed) instead of splitting it. Only a true boundary first (`&`,
// whitespace, quote, markup) means no entity at all, falling back to a
// bare `&` separator. Digit accumulation exits early once above the Unicode
// maximum (bounded arithmetic); the fail-closed tail scan stops at
// structural boundaries, visiting each byte once per value scan.
func parseNumEntity(s string, p int) (rune, int, bool) {
	n := len(s)
	if p+2 >= n || s[p] != '&' || s[p+1] != '#' {
		return 0, 0, false
	}
	q := p + 2
	base := 10
	if q < n && (s[q] == 'x' || s[q] == 'X') {
		base = 16
		q++
	}
	start := q
	val := 0
	for q < n && q-p <= 48 {
		var d int
		if base == 10 {
			if s[q] < '0' || s[q] > '9' {
				break
			}
			d = int(s[q] - '0')
		} else {
			if !isHexByte(s[q]) {
				break
			}
			d = int(hexVal(s[q]))
		}
		val = val*base + d
		if val > 0x10FFFF {
			// Out-of-range digit prefix: same fail-closed tail as the
			// overlong branch below — scan to `;` with structural stops
			// (no length cap; each byte visited once per value scan).
			// A length cap here would fail open past the bound and leak
			// the value suffix.
			r := q
			for r < n && s[r] != ';' && s[r] != '&' && s[r] != ' ' && s[r] != '\t' && s[r] != '\n' && s[r] != '\r' && s[r] != '"' && s[r] != '\'' && s[r] != '<' && s[r] != '>' {
				r++
			}
			if r < n && s[r] == ';' {
				return unicode.ReplacementChar, r + 1 - p, true
			}
			return 0, 0, false
		}
		q++
	}
	if q == start || q >= n || s[q] != ';' {
		// Malformed, overlong, or beyond-bound numeric entity lookalike:
		// when digits run past the scan bound, the entity is ambiguous —
		// but a following `;` still proves entity shape. Scan to that
		// `;` without a length cap (each byte visited once in the value
		// scan; digits cannot loop) and consume through it INSIDE the
		// value (fail closed). A true boundary first means no entity
		// at all (bare `&`).
		r := q
		for r < n && s[r] != ';' && s[r] != '&' && s[r] != ' ' && s[r] != '\t' && s[r] != '\n' && s[r] != '\r' && s[r] != '"' && s[r] != '\'' && s[r] != '<' && s[r] != '>' {
			r++
		}
		if r < n && s[r] == ';' && r > start {
			return unicode.ReplacementChar, r + 1 - p, true
		}
		return 0, 0, false
	}
	r := rune(val)
	if r > unicode.MaxRune || !utf8.ValidRune(r) {
		// Surrogates and other invalid scalars: same fail-closed
		// consumption through `;` (well-formed `;` always present here).
		return unicode.ReplacementChar, q + 1 - p, true
	}
	return r, q + 1 - p, true
}

// utf8Encode encodes r without allocation surprises (ASCII stays one
// byte; astral runes encode to four bytes).
func utf8Encode(r rune) []byte {
	var b [utf8.UTFMax]byte
	return append([]byte(nil), b[:utf8.EncodeRune(b[:], r)]...)
}

// isURLAttr reports whether a lowercased attribute name carries URL-ish
// values whose entity-decoded quotes stay inside the value. href/src/
// action are the ticket-HTML carriers; longdesc/cite/data/poster cover
// the other recognized URL-bearing attributes without opening arbitrary
// attributes (event handlers, style, and custom data-* stay text).
func isURLAttr(n []byte) bool {
	switch string(n) {
	case "href", "src", "action", "longdesc", "cite", "data", "poster":
		return true
	}
	return false
}

// urlAttrSpan is one URL-attribute value span from the memoized forward
// lexical pass: [vstart, vend) with its opening quote.
type urlAttrSpan struct {
	vstart, vend int
	quote        byte
}

// scanHTMLURLAttrs runs ONE forward tag scan per string and records every
// URL-attribute value span (href/src/action/longdesc/cite/data/poster).
// Total work is O(n): indices advance monotonically, names stack-bounded
// (overlong names skipped whole), values scanned once. Callers then answer
// "is p inside a URL attribute" by binary search — O(log m) per value.
func scanHTMLURLAttrs(s string) []urlAttrSpan {
	n := len(s)
	var out []urlAttrSpan
	i := 0
	for i < n {
		lt := -1
		for k := i; k < n; k++ {
			if s[k] == '<' {
				lt = k
				break
			}
		}
		if lt < 0 {
			break
		}
		i = lt + 1
		// Tag name (letters only); `</`, `<!`, `<?`, and `< ` (malformed
		// tag storms like `<a <a <a …`) never carry URL attrs here —
		// advancing past `<` keeps the outer loop linear.
		j := i
		for j < n && isASCIILetter(s[j]) {
			j++
		}
		if j == i {
			continue
		}
		for j < n && s[j] != '>' {
			for j < n && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r' || s[j] == '/') {
				j++
			}
			if j >= n || s[j] == '>' {
				break
			}
			ns := j
			for j < n && j-ns <= 32 && (isASCIILetter(s[j]) || s[j] == '-' || (s[j] >= '0' && s[j] <= '9')) {
				j++
			}
			if j == ns || j-ns > 32 {
				// j == ns: not a name byte (`:`, `?`, `=`, quote inside
				// a rescanned value) — skip one byte, linear.
				// j-ns > 32: overlong name already skipped whole.
				if j == ns {
					j++
				}
				continue
			}
			var aname [32]byte
			al := 0
			for k := ns; k < j; k++ {
				aname[al] = lowerByte(s[k])
				al++
			}
			k := j
			for k < n && (s[k] == ' ' || s[k] == '\t' || s[k] == '\n' || s[k] == '\r') {
				k++
			}
			if k >= n || s[k] != '=' {
				continue
			}
			k++
			for k < n && (s[k] == ' ' || s[k] == '\t' || s[k] == '\n' || s[k] == '\r') {
				k++
			}
			if k >= n {
				break
			}
			if s[k] == '"' || s[k] == '\'' {
				q := s[k]
				vstart := k + 1
				vend := vstart
				for vend < n && s[vend] != q {
					vend++
				}
				if isURLAttr(aname[:al]) {
					out = append(out, urlAttrSpan{vstart: vstart, vend: vend, quote: q})
				}
				// Resume AFTER the value's closing quote when present so a
				// later `?password=` past it is never merged into this span;
				// j was parked at the opening quote (k+1), not past the value.
				// Quoted values stay open through raw `>` (allowed INSIDE
				// quoted HTML attributes) — only the matching quote closes.
				// Unterminated values run to EOF (j = n, still monotonic),
				// so inner `href='x&password=…` text is never rescanned.
				if vend < n && s[vend] == q {
					j = vend + 1
				} else {
					j = n
				}
			} else {
				// Unquoted value (no `"`/`'` delimiter): no span is recorded,
				// so the contextual scanner treats any credential inside as
				// body text (raw `>` ends the value, markup survives). Skip
				// past `=`/value bytes — never the raw first value byte as a
				// quote — stopping at whitespace or `>`; j advances past the
				// scanned value, monotonically.
				j = k + 1
				for j < n && s[j] != '>' && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' {
					j++
				}
			}
		}
		// Advance the OUTER cursor past this tag (or to EOF): without
		// this, `<a <a <a …` (no `>`) rescans the suffix per `<` —
		// quadratic. j is already at/past the tag end here.
		if j > i {
			i = j
		} else {
			i++
		}
	}
	return out
}

// scanValueEndLex is scanValueEndCtx with memoized URL-attribute spans:
// the URL-attribute context lookup is a binary search instead of a
// fresh backward scan per value.
func scanValueEndLex(s string, p int, lex []urlAttrSpan) int {
	lo, hi := 0, len(lex)
	for lo < hi {
		mid := (lo + hi) / 2
		sp := lex[mid]
		if p <= sp.vstart {
			hi = mid
		} else if p > sp.vend {
			lo = mid + 1
		} else {
			return scanValueEndCtx(s, p, true, sp.quote)
		}
	}
	return scanValueEndCtx(s, p, false, 0)
}

// scanValueEndCtx is the credential-value scanner with explicit URL-attribute
// context: the caller supplies inHref/quote from the memoized spans.
// Quote/markup entities stay inside URL-attribute values; only actual query
// separators (`&`-family) before a true next parameter end the value.
func scanValueEndCtx(s string, p int, inHref bool, quote byte) int {
	n := len(s)
	k := p
	for k < n {
		c := s[k]
		if inHref && c == quote {
			return k
		}
		if !inHref && (c == '"' || c == '\'') {
			// No backslash escape in HTML text: a raw quote ends the
			// value (JSON `\"` handling lives in the JSON parser only).
			return k
		}
		if c == '&' {
			v, el, cls := parseEntity(s, k)
			if cls == entNone {
				return k
			}
			if inHref {
				// Split ONLY on separator entities (`&amp;`-family
				// decoding to `&`/`;`/`#`/whitespace) that open a true
				// next parameter. Value-character entities (`&#47;`,
				// `&sol;`, quotes, markup, scalars) stay inside the
				// value and are removed with it.
				if cls == entSep && isEntityNextParam(s, k, el) {
					return k
				}
				k += el
				_ = v
				continue
			}
			if cls == entChar {
				k += el
				continue
			}
			return k
		}
		if !inHref {
			switch c {
			case ';', '#', '"', '\'', '<', '>', ' ', '\t', '\n', '\r':
				return k
			}
		} else {
			switch c {
			case ';', '#', ' ', '\t', '\n', '\r':
				return k
			}
		}
		k++
	}
	return k
}

// isEntityNextParam reports whether the entity at raw offset k (raw length
// el) is followed by a TRUE next query parameter: a name plus a name/value
// separator. Only then does the value end before the entity so the
// following parameter survives (`…FAKE-A&amp;order_ref=123` keeps
// `&amp;order_ref=123`). A second credential parameter likewise survives
// as its own redaction. Anything else (entity quote/markup mid-value,
// trailing entity text) stays inside the value and is removed with it.
// Bounded memory, unbounded ordinary length: decode-aware match
// (capped at maxNameRawLen) plus one raw ordinary-name scan of any
// length (no allocation — index arithmetic over the input, entities
// consumed once each), plus one separator match. The fallback still
// requires a REAL query name/value separator at the raw name end
// (matchSepLen: raw `=`, `%3D`, `\u003D`, `&#61;`-family) — so
// `&amp;foo` / `&amp;123` (no separator) never split, while
// `&amp;票=123` and 1000-char ordinary names survive.
func isEntityNextParam(s string, k, el int) bool {
	var name [64]byte
	j := k + el
	if dl, raw := decodeNameBuf(s, j, &name, maxNameRawLen); dl > 0 {
		if matchSepLen(s, j+raw) > 0 {
			return true
		}
	}
	// Ordinary following parameter whose name the credential decoder
	// cannot represent: decodeNameBuf only decodes ASCII name bytes
	// (isNameByte) into a 64-byte buffer, so a Unicode name
	// (`&amp;票=123`) or a long ASCII name never matches above. Scan a
	// raw ordinary name of ANY length — UTF-8 continuation bytes,
	// valid `%XX` triplets, `\uXXXX` escapes, and entities decoding to
	// name characters (numeric/hex scalar or name-byte entities such as
	// `&#95;`) — up to a real name/value separator. This does NOT
	// expand the credential allowlist (credNameBytes is untouched); it
	// only decides whether a real `&`-family separator ends the value
	// so the tail survives. Single-byte quote/markup entities
	// (`&quot;`, `&lt;`, …) and structural bytes still stop the scan
	// fail-closed (the tail stays inside the value): an entity that
	// could be mistaken for a name/value assignment never splits one.
	// Quote/markup entities never reach here as entity text
	// (parseEntity already classified them entChar, consumed inside
	// the value), so this cannot restore quote-entity leaks; a
	// literal `=`-looking tail inside a quoted entity value stays
	// inside because the value scanner consumes the whole entity
	// before asking this question. The scan stops at the next
	// structural `&`/separator, so successive lookaheads cover
	// disjoint segments: total work stays linear in the input.
	p := j
	for p < len(s) {
		c := s[p]
		if c == '%' {
			// Percent-encoded name byte (`%E7%A5%A8=123`): a valid
			// `%XX` triplet is part of the ordinary name — consume
			// it. An encoded `=` (`%3D`) ends the name so
			// matchSepLen below decides; a bare `%` stops.
			if p+2 < len(s) && isHexByte(s[p+1]) && isHexByte(s[p+2]) {
				if hexVal(s[p+1])<<4|hexVal(s[p+2]) == '=' {
					break
				}
				p += 3
				continue
			}
			break
		}
		if c == '\\' && p+5 < len(s) && (s[p+1] == 'u' || s[p+1] == 'U') &&
			isHexByte(s[p+2]) && isHexByte(s[p+3]) && isHexByte(s[p+4]) && isHexByte(s[p+5]) {
			v := int(hexVal(s[p+2]))<<12 | int(hexVal(s[p+3]))<<8 | int(hexVal(s[p+4]))<<4 | int(hexVal(s[p+5]))
			// `\u003D` (=) ends the name for matchSepLen;
			// ASCII name bytes and non-ASCII runes (e.g. 票)
			// are ordinary name characters; any other ASCII
			// structural stops fail-closed.
			if v == '=' {
				break
			}
			if v > 127 || isNameByte(byte(v)) {
				p += 6
				continue
			}
			break
		}
		if c == '&' {
			// Entity inside an ordinary name: consume it only
			// when it decodes to a name character — a single
			// ASCII name byte (`&#95;` → `_`) or a multi-byte
			// Unicode scalar (`&#31080;` → 票). An entity
			// decoding to `=` ends the name for matchSepLen
			// (`&#61;`-family); separators, quotes, markup,
			// and malformed forms stop fail-closed.
			v, enl, cls := parseEntity(s, p)
			if cls == entNone {
				break
			}
			if len(v) == 1 && v[0] == '=' {
				break
			}
			if len(v) == 1 && isNameByte(v[0]) || len(v) > 1 && cls == entChar {
				p += enl
				continue
			}
			break
		}
		switch c {
		case '=', '&', ';', '#', '"', '\'', '<', '>', ' ', '\t', '\n', '\r', '\\', '?':
			goto named
		}
		p++
	}
named:
	if p == j {
		return false
	}
	return matchSepLen(s, p) > 0
}

// isParamBoundary reports whether raw position i can start a parameter:
// string start, a raw delimiter (query separator, fragment marker,
// whitespace, quote, markup, or bracket), or a single-pass `%XX`-encoded
// delimiter (`%26`, `%3B`, `%3F`, `%23`, …) immediately before i — so
// `?ok=1%26api_key%3Dv` and `/%3Fapi_key%3Dv` still open parameters.
// Bytes that may legally occur inside a value (`.`, `/`, `:`, `,`, `=`,
// …) are NOT boundaries, so a credential-looking substring embedded in a
// longer value is left alone.
func isParamBoundary(s string, i int) bool {
	// Lexical context: a parameter opens at string start, after a REAL
	// delimiter (query `?`, separator `&`/`;`, fragment `#`, whitespace,
	// quote, markup/bracket, backslash-escape quote context), or after a
	// single-pass `%XX`-encoded delimiter. `:` and `,` NEVER open one:
	// they occur inside unrelated values
	// (`description=foo,password=bar`), and treating them as boundaries
	// rewrites ordinary business strings.
	if i == 0 {
		return true
	}
	switch s[i-1] {
	case '?', '&', ';', '#', '"', '\'', ' ', '\t', '\n', '\r', '>', '<', '(', '[', '{', ')', ']', '}', '\\':
		return true
	}
	if i >= 3 && s[i-3] == '%' && isHexByte(s[i-2]) && isHexByte(s[i-1]) {
		switch hexVal(s[i-2])<<4 | hexVal(s[i-1]) {
		case '?', '&', ';', '#', '"', '\'', ' ', '\t', '\n', '\r', '>', '<', '(', '[', '{', ')', ']', '}':
			return true
		}
	}
	return false
}
func isNameByte(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
}

func isASCIILetter(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z'
}

func isEntityNameByte(c byte) bool {
	return isASCIILetter(c) || c >= '0' && c <= '9'
}

// credNameBytes reports whether b exactly names a recognized credential
// parameter (already lowercased by the caller path). Allocation-free.
func credNameBytes(b []byte) bool {
	switch len(b) {
	case 5:
		return eqFoldBytes(b, "token")
	case 6:
		return eqFoldBytes(b, "secret") || eqFoldBytes(b, "passwd") || eqFoldBytes(b, "apikey")
	case 7:
		return eqFoldBytes(b, "api_key")
	case 8:
		return eqFoldBytes(b, "password")
	case 10:
		return eqFoldBytes(b, "auth_token")
	case 12:
		return eqFoldBytes(b, "access_token")
	case 13:
		return eqFoldBytes(b, "client_secret")
	}
	return false
}

func eqFoldBytes(b []byte, s string) bool {
	if len(b) != len(s) {
		return false
	}
	for i := 0; i < len(b); i++ {
		if lowerByte(b[i]) != s[i] {
			return false
		}
	}
	return true
}

func lowerByte(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func isHexByte(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	default:
		return c - 'A' + 10
	}
}
