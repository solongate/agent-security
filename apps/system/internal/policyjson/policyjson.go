// Package policyjson is JSON the way JavaScript does it, for the two places in
// the policy endpoints where that difference is load-bearing.
//
// A policy's hash is SHA-256 over `JSON.stringify(policy)`, and that hash is
// stored, listed, and handed to the guard. Nothing about it is decorative: two
// implementations that serialise the same policy differently produce two
// different hashes for one policy, and the dashboard then shows a version
// changing every time anything re-saves it. This is the same class of bug that
// made sgshared necessary — a hash computed over UTF-16 code units in one
// implementation and bytes in another — so it is written down rather than
// assumed.
//
// Three differences from encoding/json matter and each one changes bytes:
//
//   - KEY ORDER. Go sorts a map's keys; JavaScript keeps insertion order. A
//     policy round-tripped through map[string]any comes back reordered and
//     hashes to something else.
//   - HTML ESCAPING. Go rewrites < > & as \u00xx by default. JSON.stringify
//     does not, and policy rules are full of all three.
//   - NUMBERS. Go's %v and JavaScript's Number::toString disagree at the
//     edges (1e21, 1e-7). Rare in a policy, and rare is exactly when a hash
//     mismatch is hardest to explain.
//
// And one thing encoding/json cannot express at all: JSON.stringify's ARRAY
// replacer. `JSON.stringify(body, Object.keys(body).sort())` — which is how
// POST /policies and PUT /policies/{id} hash a policy — is not "sort the keys".
// It is a property ALLOW-LIST, applied at every level of the object, in the
// order the list gives. A rule nested inside `rules` is filtered down to
// whichever of its own fields happen to share a name with a top-level key of
// the policy. That is surprising, it is what the live app has always done, and
// reproducing it is the whole reason Stringify takes a property list.
package policyjson

import (
	"bytes"
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Undefined is a property whose value is JavaScript's `undefined`.
//
// It is not the same as null and the difference is visible: JSON.stringify
// OMITS an object property whose value is undefined, and writes `null` for an
// undefined array element. normalizeRules produces exactly this — it sets
// `permission: undefined` on a rule whose permission list covered everything —
// and a policy that stored `"permission": null` there instead would be a policy
// the guard reads as "scoped to no permission at all".
type Undefined struct{}

var undef = Undefined{}

// Undef is the singleton, so a caller can write policyjson.Undef.
var Undef any = undef

// Object is a JSON object that remembers the order its keys arrived in.
//
// The zero value is unusable; use NewObject or Parse. Methods take a pointer
// because Set mutates.
type Object struct {
	keys []string
	vals map[string]any
}

func NewObject() *Object { return &Object{vals: map[string]any{}} }

// Keys is Object.keys: every own key, in insertion order, including any whose
// value is Undefined. Object.keys does not skip those either, which matters
// because the property list POST /policies hashes with is built from it.
func (o *Object) Keys() []string {
	if o == nil {
		return nil
	}
	out := make([]string, len(o.keys))
	copy(out, o.keys)
	return out
}

// SortedKeys is `Object.keys(v).sort()`.
//
// The comparison is JavaScript's default sort on strings, which orders by
// UTF-16 code unit. Go's sort.Strings orders by byte, and the two agree for
// every character below U+10000 and disagree only for astral-plane characters
// against U+E000..U+FFFF — a policy key would have to be an emoji for it to
// matter. Named here so the next person does not have to re-derive that.
func (o *Object) SortedKeys() []string {
	keys := o.Keys()
	sort.Strings(keys)
	return keys
}

// Get returns a property, or nil when it is absent. An absent property and one
// explicitly set to JSON null are both nil here; Has separates them.
func (o *Object) Get(key string) any {
	if o == nil {
		return nil
	}
	return o.vals[key]
}

func (o *Object) Has(key string) bool {
	if o == nil {
		return false
	}
	_, ok := o.vals[key]
	return ok
}

// Set is JavaScript assignment: an existing key keeps its POSITION and takes
// the new value, a new key is appended. `{...rule, enabled: true}` on a rule
// that already has an `enabled` field must not move it to the end, because the
// stored bytes — and therefore the hash — would change for a policy nobody
// edited.
func (o *Object) Set(key string, v any) {
	if _, exists := o.vals[key]; !exists {
		o.keys = append(o.keys, key)
	}
	o.vals[key] = v
}

// Clone is the object spread `{...o}`: a shallow copy that keeps the order.
// Nested values are shared, which is safe here because nothing in this package
// mutates a value in place.
func (o *Object) Clone() *Object {
	c := NewObject()
	if o == nil {
		return c
	}
	c.keys = make([]string, len(o.keys))
	copy(c.keys, o.keys)
	for k, v := range o.vals {
		c.vals[k] = v
	}
	return c
}

// ── parsing ─────────────────────────────────────────────────────────────────

// Parse decodes JSON into nil / bool / float64 / string / []any / *Object.
//
// Numbers become float64 because that is what JSON.parse produces, and the
// serialiser has to be able to reproduce what JavaScript would print for the
// SAME value. Keeping the source literal instead would look more faithful and
// would not be: JSON.stringify(JSON.parse("1.50")) is "1.5".
func Parse(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	v, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	return v, nil
}

// ParseObject decodes a value that must be an object. `false` means the input
// was not one — a truncated column, an array, a bare string — which every
// caller here treats the way the TypeScript's `as Record<string,unknown>` plus
// a truthiness check does: as nothing usable.
func ParseObject(b []byte) (*Object, bool) {
	v, err := Parse(b)
	if err != nil {
		return nil, false
	}
	o, ok := v.(*Object)
	return o, ok
}

func decodeValue(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	return decodeFrom(dec, t)
}

func decodeFrom(dec *json.Decoder, t json.Token) (any, error) {
	switch tv := t.(type) {
	case json.Delim:
		switch tv {
		case '{':
			o := NewObject()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := kt.(string)
				if !ok {
					return nil, errBadJSON
				}
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				// A duplicate key takes the LAST value and keeps the FIRST
				// position, which is what a JavaScript object literal does.
				o.Set(key, v)
			}
			if _, err := dec.Token(); err != nil { // closing brace
				return nil, err
			}
			return o, nil
		case '[':
			arr := []any{}
			for dec.More() {
				v, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // closing bracket
				return nil, err
			}
			return arr, nil
		}
		return nil, errBadJSON
	default:
		return t, nil
	}
}

type jsonError string

func (e jsonError) Error() string { return string(e) }

const errBadJSON = jsonError("policyjson: malformed JSON")

// ── serialising ─────────────────────────────────────────────────────────────

// Stringify is JSON.stringify.
//
// props is the array replacer. nil means no replacer — every own property, in
// insertion order. Non-nil means the ALLOW-LIST described in the package note:
// only these properties, in this order, at every level.
func Stringify(v any, props []string) string {
	var b strings.Builder
	if !writeValue(&b, v, dedupe(props)) {
		// Only reachable for a top-level undefined, which JSON.stringify
		// answers with undefined rather than a string. No caller here can
		// produce one; "null" is the safe reading if one ever does.
		return "null"
	}
	return b.String()
}

func dedupe(props []string) []string {
	if props == nil {
		return nil
	}
	seen := make(map[string]bool, len(props))
	out := make([]string, 0, len(props))
	for _, p := range props {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// writeValue reports whether anything was written. False means `undefined`,
// which an object omits and an array renders as null.
func writeValue(b *strings.Builder, v any, props []string) bool {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case Undefined:
		return false
	case bool:
		if t {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		writeQuoted(b, t)
	case float64:
		b.WriteString(NumberString(t))
	case json.Number:
		f, err := t.Float64()
		if err != nil {
			b.WriteString("null")
		} else {
			b.WriteString(NumberString(f))
		}
	case int:
		b.WriteString(NumberString(float64(t)))
	case int64:
		b.WriteString(NumberString(float64(t)))
	case []any:
		b.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if !writeValue(b, item, props) {
				// An undefined element is `null` in an array, not a gap.
				b.WriteString("null")
			}
		}
		b.WriteByte(']')
	case *Object:
		writeObject(b, t, props)
	default:
		// Nothing else can reach here from Parse. Rendering an unknown as null
		// keeps the output valid JSON rather than truncating a policy.
		b.WriteString("null")
	}
	return true
}

func writeObject(b *strings.Builder, o *Object, props []string) {
	if o == nil {
		b.WriteString("null")
		return
	}
	keys := o.keys
	if props != nil {
		keys = props
	}
	b.WriteByte('{')
	first := true
	for _, k := range keys {
		v, exists := o.vals[k]
		if !exists {
			continue
		}
		var vb strings.Builder
		if !writeValue(&vb, v, props) {
			// undefined: the property is omitted entirely.
			continue
		}
		if !first {
			b.WriteByte(',')
		}
		first = false
		writeQuoted(b, k)
		b.WriteByte(':')
		b.WriteString(vb.String())
	}
	b.WriteByte('}')
}

const hexDigits = "0123456789abcdef"

// writeQuoted is QuoteJSONString: escape the quote, the backslash, the five
// named control characters and nothing else.
//
// In particular < > and & are written through. Go's encoder escapes them by
// default and JSON.stringify never has, so escaping them here would change the
// hash of every policy carrying a shell command, a glob or a URL — which is
// most of them.
func writeQuoted(b *strings.Builder, s string) {
	b.WriteByte('"')
	for i := 0; i < len(s); {
		c := s[i]
		if c < utf8.RuneSelf {
			i++
			switch c {
			case '"':
				b.WriteString(`\"`)
			case '\\':
				b.WriteString(`\\`)
			case '\b':
				b.WriteString(`\b`)
			case '\f':
				b.WriteString(`\f`)
			case '\n':
				b.WriteString(`\n`)
			case '\r':
				b.WriteString(`\r`)
			case '\t':
				b.WriteString(`\t`)
			default:
				if c < 0x20 {
					b.WriteString(`\u00`)
					b.WriteByte(hexDigits[c>>4])
					b.WriteByte(hexDigits[c&0xf])
				} else {
					b.WriteByte(c)
				}
			}
			continue
		}
		// Invalid UTF-8 cannot round-trip: JavaScript would be holding a lone
		// surrogate here and Go cannot represent one. It is written as the
		// replacement character, which is what the decode already produced.
		_, size := utf8.DecodeRuneInString(s[i:])
		b.WriteString(s[i : i+size])
		i += size
	}
	b.WriteByte('"')
}

// NumberString is ECMAScript's Number::toString for base 10, which is what
// JSON.stringify writes for a number.
//
// The ranges are the specification's and are not interchangeable with anything
// Go offers: an integer up to 1e21 prints in full, a value down to 1e-6 prints
// with leading zeroes, and only outside those does it become exponential — with
// `e+21`, not Go's `e+21` for some values and `1e+21` for others. NaN and the
// infinities are `null`, because JSON.stringify has no way to write them.
func NumberString(f float64) string {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "null"
	}
	if f == 0 {
		// Covers -0, which ToString renders as "0".
		return "0"
	}
	neg := f < 0
	if neg {
		f = -f
	}

	// The shortest decimal that round-trips, split into digits and exponent.
	sci := strconv.FormatFloat(f, 'e', -1, 64)
	ePos := strings.IndexByte(sci, 'e')
	digits := strings.Replace(sci[:ePos], ".", "", 1)
	exp, err := strconv.Atoi(sci[ePos+1:])
	if err != nil {
		return strconv.FormatFloat(f, 'g', -1, 64)
	}

	k := len(digits)
	n := exp + 1 // value == 0.<digits> * 10^n

	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		e := n - 1
		sign := "+"
		if e < 0 {
			sign = "-"
			e = -e
		}
		if k == 1 {
			s = digits + "e" + sign + strconv.Itoa(e)
		} else {
			s = digits[:1] + "." + digits[1:] + "e" + sign + strconv.Itoa(e)
		}
	}
	if neg {
		s = "-" + s
	}
	return s
}

// ── the helpers the policy routes need on a decoded value ───────────────────

// Truthy is JavaScript's `!!v`, for the `if (!body.id || !body.name)` guards
// the routes open with. An empty string and 0 are falsy; an empty array and an
// empty object are not.
func Truthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case Undefined:
		return false
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && !math.IsNaN(t)
	}
	return true
}

// Str is `String(v)` for a value that must already be a string, and "" for
// anything else. The policy routes only ever read string fields with it — an id
// or a name — and stringifying a stray number into one of those would store a
// value nobody typed.
func Str(v any) string {
	s, _ := v.(string)
	return s
}

// Array returns v as a JSON array, or (nil, false). `Array.isArray` in the
// original, and the same non-array-is-not-an-array strictness.
func Array(v any) ([]any, bool) {
	a, ok := v.([]any)
	return a, ok
}

// AllPermissions is src/lib/security.ts's ALL_PERMISSIONS, in its order.
var AllPermissions = []string{"READ", "WRITE", "EXECUTE", "NETWORK"}

// NormalizeRules is src/lib/security.ts's normalizeRules.
//
// It does two things and both are storage decisions rather than tidying. A
// permission list that covers every permission becomes UNDEFINED, so the rule
// stops being scoped by permission at all rather than carrying a list the guard
// then has to match four ways. And `enabled` is written explicitly, because a
// rule with no `enabled` field is read as ENABLED by the fallback evaluator and
// as DISABLED by the Rego compiler — see guard-go's rego.go, which preserves
// that split rather than reconciling it. Writing the field on save is what keeps
// a saved policy out of that ambiguity.
func NormalizeRules(rules []any) []any {
	out := make([]any, 0, len(rules))
	for _, item := range rules {
		r, ok := item.(*Object)
		if !ok {
			// The original does `{...r}` on whatever is here, which throws for
			// null and silently produces `{permission: undefined, enabled:
			// true}` for a string or a number. Passing it through unchanged is
			// narrower: a malformed entry stays malformed instead of becoming a
			// rule with no conditions, which is a catch-all.
			out = append(out, item)
			continue
		}
		// ABSENT and NULL are different here and the difference is stored. A
		// rule with no `permission` field spreads to `{...r, permission:
		// undefined}`, which JSON.stringify omits — so the saved policy still
		// has no permission field. Reading an absent key as null instead would
		// write `"permission": null` into every rule that never had one, which
		// is a different policy, a different hash, and a diff on every version.
		var perm any = undef
		if r.Has("permission") {
			perm = r.Get("permission")
		}
		if arr, isArr := perm.([]any); isArr {
			if len(arr) >= len(AllPermissions) && coversAllPermissions(arr) {
				perm = undef
			} else if len(arr) == 1 {
				perm = arr[0]
			}
		}
		n := r.Clone()
		n.Set("permission", perm)
		// `r.enabled !== false` — strictly not the boolean false, so a missing
		// field, a null and the string "false" all mean enabled.
		n.Set("enabled", r.Get("enabled") != any(false))
		out = append(out, n)
	}
	return out
}

func coversAllPermissions(arr []any) bool {
	have := make(map[string]bool, len(arr))
	for _, v := range arr {
		if s, ok := v.(string); ok {
			have[s] = true
		}
	}
	for _, p := range AllPermissions {
		if !have[p] {
			return false
		}
	}
	return true
}
