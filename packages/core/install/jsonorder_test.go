// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJSONObjectSetGetHasDelete(t *testing.T) {
	o := newJSONObject()
	if o.has("a") {
		t.Error("has(a) = true on an empty object")
	}
	o.set("a", json.RawMessage(`1`))
	o.set("b", json.RawMessage(`2`))
	if !o.has("a") || !o.has("b") {
		t.Fatal("has() should be true for keys just set")
	}
	if string(o.get("a")) != "1" {
		t.Errorf("get(a) = %s, want 1", o.get("a"))
	}
	if string(o.get("missing")) != "" {
		t.Errorf("get(missing) = %q, want empty", o.get("missing"))
	}

	o.delete("a")
	if o.has("a") {
		t.Error("has(a) = true after delete")
	}
	if len(o.keys) != 1 || o.keys[0] != "b" {
		t.Errorf("keys = %v, want [b] after deleting a", o.keys)
	}

	o.delete("not-there")
	if len(o.keys) != 1 {
		t.Errorf("deleting a missing key changed keys: %v", o.keys)
	}
}

func TestJSONObjectSetOverwriteKeepsOriginalPosition(t *testing.T) {
	o := newJSONObject()
	o.set("a", json.RawMessage(`1`))
	o.set("b", json.RawMessage(`2`))
	o.set("c", json.RawMessage(`3`))
	o.set("a", json.RawMessage(`100`))

	want := []string{"a", "b", "c"}
	if len(o.keys) != len(want) {
		t.Fatalf("keys = %v, want %v", o.keys, want)
	}
	for i, k := range want {
		if o.keys[i] != k {
			t.Errorf("keys[%d] = %q, want %q", i, o.keys[i], k)
		}
	}
	if string(o.get("a")) != "100" {
		t.Errorf("get(a) after overwrite = %s, want 100", o.get("a"))
	}
}

func TestJSONObjectSetValue(t *testing.T) {
	o := newJSONObject()
	if err := o.setValue("n", 42); err != nil {
		t.Fatalf("setValue() error: %v", err)
	}
	if string(o.get("n")) != "42" {
		t.Errorf("get(n) = %s, want 42", o.get("n"))
	}

	if err := o.setValue("bad", make(chan int)); err == nil {
		t.Error("setValue() with an unmarshalable value should return an error")
	}
}

func TestParseJSONObjectValid(t *testing.T) {
	o, ok := parseJSONObject([]byte(`{"z":1,"a":2,"m":3}`))
	if !ok {
		t.Fatal("parseJSONObject() ok = false for valid JSON")
	}
	want := []string{"z", "a", "m"}
	if len(o.keys) != len(want) {
		t.Fatalf("keys = %v, want %v", o.keys, want)
	}
	for i, k := range want {
		if o.keys[i] != k {
			t.Errorf("keys[%d] = %q, want %q (insertion order must be preserved)", i, o.keys[i], k)
		}
	}
}

func TestParseJSONObjectRejectsNonObjects(t *testing.T) {
	cases := []string{
		`[1,2,3]`,
		`"a string"`,
		`42`,
		`not json`,
		``,
		`{"a":}`,
	}
	for _, in := range cases {
		if _, ok := parseJSONObject([]byte(in)); ok {
			t.Errorf("parseJSONObject(%q) ok = true, want false", in)
		}
	}
}

func TestJSONObjectEncodeEmpty(t *testing.T) {
	o := newJSONObject()
	b, err := o.encode()
	if err != nil {
		t.Fatalf("encode() error: %v", err)
	}
	if string(b) != "{}" {
		t.Errorf("encode() = %q, want {}", b)
	}
}

func TestJSONObjectEncodePreservesOrderAndIndents(t *testing.T) {
	o := newJSONObject()
	o.set("first", json.RawMessage(`1`))
	o.set("second", json.RawMessage(`{"nested":true}`))

	b, err := o.encode()
	if err != nil {
		t.Fatalf("encode() error: %v", err)
	}
	s := string(b)
	if strings.Index(s, "first") > strings.Index(s, "second") {
		t.Errorf("encode() did not preserve key order: %s", s)
	}
	if !strings.Contains(s, "\n  \"first\"") {
		t.Errorf("encode() did not indent top-level keys by two spaces: %s", s)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("encode() produced invalid JSON: %v", err)
	}
}

func TestJSONObjectEncodeFileAppendsTrailingNewline(t *testing.T) {
	o := newJSONObject()
	o.set("a", json.RawMessage(`1`))
	b, err := o.encodeFile()
	if err != nil {
		t.Fatalf("encodeFile() error: %v", err)
	}
	if !strings.HasSuffix(string(b), "\n") {
		t.Errorf("encodeFile() = %q, want a trailing newline", b)
	}
	if strings.HasSuffix(string(b), "\n\n") {
		t.Errorf("encodeFile() = %q, want exactly one trailing newline", b)
	}
}

func TestMarshalJSDoesNotEscapeHTMLAndTrimsNewline(t *testing.T) {
	b, err := marshalJS("<a & b>")
	if err != nil {
		t.Fatalf("marshalJS() error: %v", err)
	}
	if !strings.Contains(string(b), "<a & b>") {
		t.Errorf("marshalJS() = %s, want the literal string preserved unescaped", b)
	}
	if strings.HasSuffix(string(b), "\n") {
		t.Errorf("marshalJS() = %q, want no trailing newline", b)
	}
}

func TestMarshalJSPropagatesEncodeErrors(t *testing.T) {
	if _, err := marshalJS(make(chan int)); err == nil {
		t.Error("marshalJS() with an unmarshalable value should return an error")
	}
}