package main

import (
	"bytes"
	"encoding/json"
	"math"
	"strings"
)

// The JavaScript-shaped values this slice cannot avoid.
//
// The ORDERED-JSON half of that problem lives in internal/policyjson and is
// used from here rather than reimplemented: an object that remembers its key
// order, JSON.stringify with its array replacer, and JavaScript's number
// formatting. Two endpoints in this tree round-trip somebody else's JSON — the
// audit POST re-serialises the tool arguments, and block/whitelist store a
// policy with one rule prepended — and both have to put back what they were
// given, in the order they were given it. A second implementation of that
// serialiser would produce a second answer for the same policy's hash, which is
// the bug class the policyjson package note and sgshared both exist because of.
//
// What is left here is the untyped-BODY half, which policyjson deliberately
// does not do: the live audit route reads its fields through `String(x || '')`,
// `Number(x) || 0` and `Boolean(x)`, so a client sending a number where a name
// was expected gets it stringified rather than rejected. Two deployed clients
// do exactly that, so these coercions are behaviour, not sloppiness.

// marshalNoEscape is apiauth.JSON's encoder for a value going into a database
// column rather than a response: HTML escaping off, no trailing newline, for
// the reason in apiauth.JSON — JSON.stringify does not rewrite < > & and the
// guard hashes the bytes it receives.
func marshalNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// jsString is `String(v)` for the values JSON can carry.
//
// It is NOT policyjson.Str, which returns the empty string for anything that is
// not already a string, and the difference is deliberate — each is right where
// it is used. A policy id that arrived as a number is a policy nobody meant to
// write, so the policy routes refuse to stringify it. Coercing an audit body
// field with String() is what the live route does, and rejecting a client that
// reports `agent_id: 3` would be a new 400 on an endpoint that has never
// returned one.
//
// An object or array returns the empty string rather than JavaScript's
// "[object Object]". Every call site guards the result before storing it, so
// the difference shows only for a caller sending an object where a name was
// expected — and storing "[object Object]" as a tool name helps nobody.
func jsString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return formatJSNumber(t)
	case json.Number:
		return t.String()
	}
	return ""
}

// formatJSNumber matches Number.prototype.toString for a double, which is what
// encoding/json's float encoder was written to do.
func formatJSNumber(f float64) string {
	b, err := json.Marshal(f)
	if err != nil {
		return "0"
	}
	return string(b)
}

// jsTruthy is `!!v`.
func jsTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && !math.IsNaN(t)
	case json.Number:
		f, err := t.Float64()
		return err == nil && f != 0
	case nil:
		return false
	}
	return true
}

// jsNumber is `Number(v)`, reporting whether the result is a usable number.
// A non-numeric string is NaN, which every call site turns into 0 via `|| 0`.
func jsNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, !math.IsNaN(t)
	case json.Number:
		f, err := t.Float64()
		return f, err == nil && !math.IsNaN(f)
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		s := strings.TrimSpace(t)
		if s == "" {
			return 0, true // Number("") is 0.
		}
		var f float64
		if err := json.Unmarshal([]byte(s), &f); err != nil {
			return 0, false
		}
		return f, !math.IsNaN(f)
	case nil:
		return 0, true // Number(null) is 0.
	}
	return 0, false
}

// clamp01 is `Math.max(0, Math.min(1, Number(v) || 0))`, the clamp every
// prompt-injection score goes through before it is stored.
func clamp01(v any) float64 {
	f, ok := jsNumber(v)
	if !ok {
		f = 0
	}
	return math.Max(0, math.Min(1, f))
}

// nullable renders a string column the way drizzle does: the empty string
// becomes JSON null.
//
// The store flattens a NULL text column to "", so this is the inverse and it
// matters to a deployed client. The dashboard branches on `entry.reason` being
// null; an empty string is falsy too, so the rendering agrees — but `null` is
// what a year of stored responses contain and what the CLI's types declare.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// rawOrNull turns a stored JSON string into a response value, or null when it
// is absent or unparseable.
//
// Unparseable is not an error here. arguments_summary is TRUNCATED on write —
// the live route cuts it at 16384 characters, mid-token if that is where 16384
// lands — so a fragment is an expected state of that column and the live route
// answers it with `null` from a catch block.
func rawOrNull(s string) json.RawMessage {
	if s == "" {
		return nil
	}
	if !json.Valid([]byte(s)) {
		return nil
	}
	return json.RawMessage(s)
}
