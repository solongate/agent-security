// SPDX-License-Identifier: Apache-2.0

package auditscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Tool arguments are read out of an agent's transcript and written back out —
// into the CSV `arguments` column, into the JSON report, into the HTML detail
// panes — and they are also the haystack every check greps. Decoding them into
// a plain map[string]any would lose the order the keys arrived in, because Go
// sorts object keys on the way out where JavaScript keeps insertion order. Two
// things then change at once: an exported row stops matching what the npm
// package writes for the same session, and a pattern that happens to straddle a
// key boundary matches in one implementation and not the other.
//
// Args keeps the order. Nested objects keep theirs too, so a round trip through
// this type reproduces what `JSON.stringify` produced.

// Args is a decoded JSON object that remembers the order its keys arrived in.
// The zero value is an empty object and every method is safe on a nil receiver:
// a transcript line with no arguments at all is normal, not an error.
type Args struct {
	keys []string
	vals map[string]any
	// Serialising is the single hottest thing this tool does: every check greps
	// `JSON.stringify(args)` and the chain analysis does it inside a nested
	// loop. The result cannot change once a transcript has been read, so it is
	// computed once. Without this the Go scan was five times SLOWER than the
	// Node one it replaces, entirely on repeated marshalling.
	cached    string
	hasCached bool
}

func NewArgs() *Args { return &Args{vals: map[string]any{}} }

func (a *Args) Len() int {
	if a == nil {
		return 0
	}
	return len(a.keys)
}

func (a *Args) Keys() []string {
	if a == nil {
		return nil
	}
	return a.keys
}

func (a *Args) Get(key string) (any, bool) {
	if a == nil || a.vals == nil {
		return nil, false
	}
	v, ok := a.vals[key]
	return v, ok
}

// Set keeps the position a key was first seen at and replaces its value, which
// is what a JSON parser does with a duplicated key.
func (a *Args) Set(key string, v any) {
	if a.vals == nil {
		a.vals = map[string]any{}
	}
	if _, seen := a.vals[key]; !seen {
		a.keys = append(a.keys, key)
	}
	a.vals[key] = v
	a.hasCached = false
}

func (a *Args) UnmarshalJSON(b []byte) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	v, err := decodeJSONValue(dec)
	if err != nil {
		return err
	}
	obj, ok := v.(*Args)
	if !ok {
		return fmt.Errorf("expected a JSON object")
	}
	*a = *obj
	return nil
}

func (a *Args) MarshalJSON() ([]byte, error) {
	if a == nil || len(a.keys) == 0 {
		return []byte("{}"), nil
	}
	if a.hasCached {
		return []byte(a.cached), nil
	}
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range a.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, err := encodeJSON(k)
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		vb, err := encodeJSON(a.vals[k])
		if err != nil {
			return nil, err
		}
		buf.Write(vb)
	}
	buf.WriteByte('}')
	a.cached = buf.String()
	a.hasCached = true
	return buf.Bytes(), nil
}

// String is this package's `JSON.stringify(args)`. Checks compare against it by
// substring, so it has to be the compact form with no added whitespace.
func (a *Args) String() string {
	if a == nil {
		return "{}"
	}
	if a.hasCached {
		return a.cached
	}
	a.cached = Stringify(a)
	a.hasCached = true
	return a.cached
}

// Indent is `JSON.stringify(args, null, 2)`, for the HTML report's expandable
// argument panes.
func (a *Args) Indent() string {
	compact := a.String()
	var out bytes.Buffer
	if json.Indent(&out, []byte(compact), "", "  ") != nil {
		return compact
	}
	return out.String()
}

// ParseArgsValue decodes an arbitrary JSON value, producing *Args for objects
// so ordering survives at every depth.
func ParseArgsValue(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	return decodeJSONValue(dec)
}

func decodeJSONValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return decodeFromToken(dec, tok)
}

func decodeFromToken(dec *json.Decoder, tok json.Token) (any, error) {
	delim, isDelim := tok.(json.Delim)
	if !isDelim {
		// string, float64, bool or nil — already the value.
		return tok, nil
	}
	switch delim {
	case '{':
		obj := NewArgs()
		for dec.More() {
			kt, err := dec.Token()
			if err != nil {
				return nil, err
			}
			key, ok := kt.(string)
			if !ok {
				return nil, fmt.Errorf("object key was not a string")
			}
			val, err := decodeJSONValue(dec)
			if err != nil {
				return nil, err
			}
			obj.Set(key, val)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return obj, nil
	case '[':
		arr := []any{}
		for dec.More() {
			val, err := decodeJSONValue(dec)
			if err != nil {
				return nil, err
			}
			arr = append(arr, val)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return arr, nil
	}
	return nil, fmt.Errorf("unexpected delimiter %v", delim)
}

// encodeJSON is the whole package's marshaller. HTML escaping is off because
// `JSON.stringify` does not escape `<`, `>` or `&`, and an argument containing
// a shell redirect would otherwise come out of the Go exporter as > and
// stop matching the npm package's output for the same session.
func encodeJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return unescapeLineSeparators(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

var (
	escU2028 = []byte(`\u2028`)
	escU2029 = []byte(`\u2029`)
)

// unescapeLineSeparators undoes Go's escaping of U+2028 and U+2029.
//
// Go's encoder always escapes them, because they terminate a line in JavaScript
// source and an unescaped one breaks a JSONP response. `JSON.stringify` emits
// them raw. Both are valid JSON for the same string, but a transcript
// containing one would make this exporter's CSV row differ from the npm
// exporter's for the same tool call — and the CSV is what people diff.
//
// The rewrite counts escapes rather than doing a plain replace: a string that
// literally contains a backslash followed by "u2028" is encoded as `\\u2028`,
// and blind replacement would corrupt it into a backslash plus the real
// character.
func unescapeLineSeparators(b []byte) []byte {
	if !bytes.Contains(b, escU2028) && !bytes.Contains(b, escU2029) {
		return b
	}
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); {
		if b[i] == '\\' && i+6 <= len(b) && b[i+1] == 'u' {
			switch {
			case bytes.Equal(b[i:i+6], escU2028):
				out = append(out, "\u2028"...)
				i += 6
				continue
			case bytes.Equal(b[i:i+6], escU2029):
				out = append(out, "\u2029"...)
				i += 6
				continue
			}
		}
		if b[i] == '\\' && i+1 < len(b) {
			out = append(out, b[i], b[i+1])
			i += 2
			continue
		}
		out = append(out, b[i])
		i++
	}
	return out
}

// Stringify is `JSON.stringify(v)`. A value that will not encode yields the
// empty string rather than an error: this is used to build report text, and a
// half-written report is worse than a missing field.
func Stringify(v any) string {
	b, err := encodeJSON(v)
	if err != nil {
		return ""
	}
	return string(b)
}

// StringifyIndent is `JSON.stringify(v, null, 2)`.
func StringifyIndent(v any) string {
	compact := Stringify(v)
	var out bytes.Buffer
	if json.Indent(&out, []byte(compact), "", "  ") != nil {
		return compact
	}
	return out.String()
}

// ── JavaScript value semantics ─────────────────────────────────────────────

// truthy is JavaScript's `if (value)`. The collectors and the summary
// extractors lean on it (`args.command || args.file_path || …`), and getting it
// wrong would make an empty string or a zero read as present.
func truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		return t != 0 && !math.IsNaN(t)
	}
	return true
}

// jsString is JavaScript's `String(value)`, which several summary lines apply
// to a field that is not guaranteed to be a string.
func jsString(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return jsNumber(t)
	case *Args:
		return "[object Object]"
	case []any:
		parts := make([]string, 0, len(t))
		for _, el := range t {
			// Array.prototype.toString renders null and undefined as empty.
			if el == nil {
				parts = append(parts, "")
				continue
			}
			parts = append(parts, jsString(el))
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprint(v)
}

// jsNumber formats a float the way JavaScript does, so a numeric argument
// echoed into a report reads the same in both implementations.
func jsNumber(f float64) string {
	if math.IsNaN(f) {
		return "NaN"
	}
	if math.IsInf(f, 1) {
		return "Infinity"
	}
	if math.IsInf(f, -1) {
		return "-Infinity"
	}
	abs := math.Abs(f)
	if abs != 0 && (abs < 1e-6 || abs >= 1e21) {
		s := strconv.FormatFloat(f, 'e', -1, 64)
		// JavaScript writes 1e+21, Go writes 1e+21 too, but Go pads a single
		// digit exponent to two (1e+05) where JavaScript does not.
		if i := strings.IndexAny(s, "eE"); i >= 0 {
			mant, exp := s[:i], s[i+1:]
			sign := ""
			if exp != "" && (exp[0] == '+' || exp[0] == '-') {
				sign, exp = string(exp[0]), exp[1:]
			}
			exp = strings.TrimLeft(exp, "0")
			if exp == "" {
				exp = "0"
			}
			return mant + "e" + sign + exp
		}
		return s
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// str reads a field as a string, the shape most collectors want: present and a
// string, or nothing.
func (a *Args) str(key string) (string, bool) {
	v, ok := a.Get(key)
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return s, ok
}
