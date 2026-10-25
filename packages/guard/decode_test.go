// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"reflect"
	"testing"
)

func TestNeutralizeArgsRenamesAliases(t *testing.T) {
	args := map[string]interface{}{"CommandLine": "ls -l", "targetFile": "/a"}
	order := []string{"CommandLine", "targetFile"}
	out := neutralizeArgs(args, order)
	if out["command"] != "ls -l" {
		t.Errorf("command = %v, want the aliased CommandLine value", out["command"])
	}
	if out["file_path"] != "/a" {
		t.Errorf("file_path = %v, want the aliased targetFile value", out["file_path"])
	}
	if _, has := out["CommandLine"]; has {
		t.Error("the original alias key should not survive")
	}
}

func TestNeutralizeArgsFirstWriterWins(t *testing.T) {
	// "cmd" and "commandline" both alias to "command"; order determines
	// which value is kept when both are present.
	args := map[string]interface{}{"cmd": "first", "commandline": "second"}
	out := neutralizeArgs(args, []string{"cmd", "commandline"})
	if out["command"] != "first" {
		t.Errorf("command = %v, want %q (the first key in order)", out["command"], "first")
	}
}

func TestNeutralizeArgsLeavesUnaliasedKeysAlone(t *testing.T) {
	args := map[string]interface{}{"timeout": 30, "description": "x"}
	out := neutralizeArgs(args, []string{"timeout", "description"})
	if out["timeout"] != 30 || out["description"] != "x" {
		t.Errorf("out = %v", out)
	}
}

func TestNeutralizeArgsWithEmptyOrderFallsBackToSortedKeys(t *testing.T) {
	args := map[string]interface{}{"b": 1, "a": 2}
	out := neutralizeArgs(args, nil)
	if out["a"] != 2 || out["b"] != 1 {
		t.Errorf("out = %v", out)
	}
}

func TestNeutralizeArgsSkipsOrderKeysMissingFromArgs(t *testing.T) {
	args := map[string]interface{}{"a": 1}
	out := neutralizeArgs(args, []string{"a", "ghost"})
	if len(out) != 1 || out["a"] != 1 {
		t.Errorf("out = %v, want only a=1", out)
	}
}

func TestDecodeObject(t *testing.T) {
	m, order := decodeObject([]byte(`{"b":1,"a":2}`))
	if m["b"] != float64(1) || m["a"] != float64(2) {
		t.Errorf("m = %v", m)
	}
	if !reflect.DeepEqual(order, []string{"b", "a"}) {
		t.Errorf("order = %v, want key insertion order preserved", order)
	}
}

func TestDecodeObjectWithEmptyInput(t *testing.T) {
	m, order := decodeObject(nil)
	if m == nil || len(m) != 0 {
		t.Errorf("m = %v, want an empty non-nil map", m)
	}
	if order != nil {
		t.Errorf("order = %v, want nil", order)
	}
}

func TestDecodeObjectWithMalformedJSON(t *testing.T) {
	m, order := decodeObject([]byte(`{not json`))
	if len(m) != 0 {
		t.Errorf("m = %v, want empty on malformed input", m)
	}
	if order != nil {
		t.Errorf("order = %v, want nil on malformed input", order)
	}
}

func TestDecodeObjectWithANonObjectValue(t *testing.T) {
	m, order := decodeObject([]byte(`[1,2,3]`))
	if len(m) != 0 {
		t.Errorf("m = %v, want empty for a json array", m)
	}
	if order != nil {
		t.Errorf("order = %v, want nil for a json array", order)
	}
}

func TestDecodeObjectWithNestedValues(t *testing.T) {
	m, order := decodeObject([]byte(`{"nested":{"x":1},"list":[1,2],"n":null,"s":"hi"}`))
	if len(order) != 4 {
		t.Fatalf("order = %v, want 4 keys", order)
	}
	nested, ok := m["nested"].(map[string]interface{})
	if !ok || nested["x"] != float64(1) {
		t.Errorf("nested = %v", m["nested"])
	}
	if s, ok := m["n"]; !ok || s != nil {
		t.Errorf("n = %v, want explicit nil", m["n"])
	}
}

func TestClientArgNamesMapsBackToOriginalNames(t *testing.T) {
	// Seed argOriginals via a real neutralizeArgs call, as production code does.
	neutralizeArgs(map[string]interface{}{"absolutePath": "/x"}, []string{"absolutePath"})

	patch := map[string]interface{}{"file_path": "/y"}
	out := clientArgNames(patch)
	if out["absolutePath"] != "/y" {
		t.Errorf("out = %v, want the patch mapped back to absolutePath", out)
	}
	if _, has := out["file_path"]; has {
		t.Errorf("the neutral key should not remain once mapped back: %v", out)
	}
}

func TestClientArgNamesLeavesUnmappedKeysAlone(t *testing.T) {
	out := clientArgNames(map[string]interface{}{"some_unaliased_key": "v"})
	if out["some_unaliased_key"] != "v" {
		t.Errorf("out = %v", out)
	}
}

func TestClientArgNamesWithEmptyPatch(t *testing.T) {
	if out := clientArgNames(nil); out != nil {
		t.Errorf("clientArgNames(nil) = %v, want nil", out)
	}
	if out := clientArgNames(map[string]interface{}{}); len(out) != 0 {
		t.Errorf("clientArgNames({}) = %v, want empty", out)
	}
}