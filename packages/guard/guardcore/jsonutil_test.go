// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package guardcore

import (
	"encoding/json"
	"testing"
)

func TestRawFields(t *testing.T) {
	cases := []struct {
		name string
		in   json.RawMessage
		want map[string]string
	}{
		{"a plain object", json.RawMessage(`{"a":"1","b":2}`), map[string]string{"a": `"1"`, "b": "2"}},
		{"an empty object", json.RawMessage(`{}`), map[string]string{}},
		{"empty input", nil, map[string]string{}},
		{"malformed json", json.RawMessage(`{not json`), map[string]string{}},
		{"a json array", json.RawMessage(`[1,2,3]`), map[string]string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RawFields(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("got %d fields, want %d: %v", len(got), len(c.want), got)
			}
			for k, v := range c.want {
				if string(got[k]) != v {
					t.Errorf("field %q = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestJsOrRaw(t *testing.T) {
	f := map[string]json.RawMessage{
		"empty":    json.RawMessage(`""`),
		"zero":     json.RawMessage(`0`),
		"falseVal": json.RawMessage(`false`),
		"nullVal":  json.RawMessage(`null`),
		"text":     json.RawMessage(`"hi"`),
		"obj":      json.RawMessage(`{"x":1}`),
		"bad":      json.RawMessage(`{not json`),
	}

	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"first key is truthy", []string{"text"}, `"hi"`},
		{"first key falsy string falls through to next", []string{"empty", "text"}, `"hi"`},
		{"zero number is falsy", []string{"zero", "text"}, `"hi"`},
		{"false bool is falsy", []string{"falseVal", "text"}, `"hi"`},
		{"null is falsy", []string{"nullVal", "text"}, `"hi"`},
		{"missing key is skipped", []string{"missing", "text"}, `"hi"`},
		{"malformed value is skipped", []string{"bad", "text"}, `"hi"`},
		{"an object is truthy", []string{"obj"}, `{"x":1}`},
		{"nothing matches", []string{"missing", "empty", "zero"}, ""},
		{"no keys at all", nil, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := JsOrRaw(f, c.keys...)
			if string(got) != c.want {
				t.Errorf("JsOrRaw(%v) = %q, want %q", c.keys, got, c.want)
			}
		})
	}
}

func TestJsOrString(t *testing.T) {
	f := map[string]json.RawMessage{
		"empty": json.RawMessage(`""`),
		"text":  json.RawMessage(`"hi"`),
		"num":   json.RawMessage(`42`),
		"flag":  json.RawMessage(`true`),
		"arr":   json.RawMessage(`["a","b"]`),
		"bad":   json.RawMessage(`{not json`),
	}

	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"a string value", []string{"text"}, "hi"},
		{"a falsy string is skipped", []string{"empty", "text"}, "hi"},
		{"a number is stringified", []string{"num"}, "42"},
		{"a bool is stringified", []string{"flag"}, "true"},
		{"an array is joined", []string{"arr"}, "a,b"},
		{"a malformed value is skipped", []string{"bad", "text"}, "hi"},
		{"nothing matches", []string{"missing", "empty"}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := JsOrString(f, c.keys...); got != c.want {
				t.Errorf("JsOrString(%v) = %q, want %q", c.keys, got, c.want)
			}
		})
	}
}