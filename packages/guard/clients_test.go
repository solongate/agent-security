// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

// captureOutput swaps os.Stdout and os.Stderr for the duration of fn and
// returns whatever each captured.
func captureOutput(t *testing.T, fn func()) (stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr

	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = outW, errW

	fn()

	outW.Close()
	errW.Close()
	os.Stdout, os.Stderr = origOut, origErr

	outBytes, _ := io.ReadAll(outR)
	errBytes, _ := io.ReadAll(errR)
	return string(outBytes), string(errBytes)
}

func TestIsJSONish(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"an object", `{"a":1}`, true},
		{"an array", `[1,2]`, true},
		{"leading whitespace before an object", "  \t\n{}", true},
		{"a string", `"hello"`, false},
		{"a number", `42`, false},
		{"empty input", "", false},
		{"only whitespace", "   ", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isJSONish(json.RawMessage(c.in)); got != c.want {
				t.Errorf("isJSONish(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestDropArgKeys(t *testing.T) {
	args := map[string]interface{}{"Cwd": "/tmp", "command": "ls", "Tool": "Bash"}
	order := []string{"Tool", "Cwd", "command"}

	out, keys := dropArgKeys(args, order, "cwd")
	if _, ok := out["Cwd"]; ok {
		t.Error("the dropped key survived in the output map (case-insensitively)")
	}
	if len(out) != 2 {
		t.Errorf("got %d remaining keys, want 2: %v", len(out), out)
	}
	for _, k := range keys {
		if strings.EqualFold(k, "cwd") {
			t.Errorf("the dropped key is still present in the order slice: %v", keys)
		}
	}
	if len(keys) != 2 {
		t.Errorf("order has %d entries, want 2: %v", len(keys), keys)
	}
}

func TestDropArgKeysDropsMultiple(t *testing.T) {
	args := map[string]interface{}{"a": 1, "b": 2, "c": 3}
	out, keys := dropArgKeys(args, []string{"a", "b", "c"}, "A", "C")
	if len(out) != 1 || out["b"] != 2 {
		t.Errorf("got %v, want only b=2", out)
	}
	if len(keys) != 1 || keys[0] != "b" {
		t.Errorf("got keys %v, want [b]", keys)
	}
}

func TestParseFlatPayload(t *testing.T) {
	raw := []byte(`{
		"tool_name": "Bash",
		"tool_input": {"command": "ls -la", "file_path": "/tmp/x"},
		"cwd": "/home/u/project",
		"session_id": "sess-1",
		"tool_response": {"ok": true}
	}`)
	p := parseFlatPayload(raw)
	if p.Tool != "Bash" {
		t.Errorf("Tool = %q, want Bash", p.Tool)
	}
	if p.Cwd != "/home/u/project" {
		t.Errorf("Cwd = %q", p.Cwd)
	}
	if p.SessionID != "sess-1" {
		t.Errorf("SessionID = %q", p.SessionID)
	}
	if p.Command != "ls -la" {
		t.Errorf("Command = %q, want %q", p.Command, "ls -la")
	}
	if p.Args["command"] != "ls -la" || p.Args["file_path"] != "/tmp/x" {
		t.Errorf("Args = %v", p.Args)
	}
	if ok, _ := p.Response["ok"].(bool); !ok {
		t.Errorf("Response = %v, want ok=true", p.Response)
	}
}

func TestParseFlatPayloadAcceptsAlternateKeyNames(t *testing.T) {
	raw := []byte(`{
		"toolName": "Write",
		"toolInput": {"file_path": "/x"},
		"sessionId": "s2",
		"toolResponse": {"done": true}
	}`)
	p := parseFlatPayload(raw)
	if p.Tool != "Write" {
		t.Errorf("Tool = %q, want Write", p.Tool)
	}
	if p.SessionID != "s2" {
		t.Errorf("SessionID = %q, want s2", p.SessionID)
	}
	if p.Args["file_path"] != "/x" {
		t.Errorf("Args = %v", p.Args)
	}
}

func TestParseFlatPayloadFallsBackToParams(t *testing.T) {
	raw := []byte(`{"tool_name":"Edit","params":{"file_path":"/a"}}`)
	p := parseFlatPayload(raw)
	if p.Args["file_path"] != "/a" {
		t.Errorf("Args = %v, want file_path=/a from params", p.Args)
	}
}

func TestParseFlatPayloadFallsBackToConversationID(t *testing.T) {
	raw := []byte(`{"tool_name":"Edit","conversation_id":"conv-9"}`)
	p := parseFlatPayload(raw)
	if p.SessionID != "conv-9" {
		t.Errorf("SessionID = %q, want conv-9", p.SessionID)
	}
}

func TestEmitHookSpecificDeny(t *testing.T) {
	out, errOut := captureOutput(t, func() {
		if got := emitHookSpecific(decision{Type: "deny", Reason: "nope"}); got != 2 {
			t.Errorf("exit code = %d, want 2", got)
		}
	})
	var parsed struct {
		HookSpecificOutput struct {
			HookEventName            string `json:"hookEventName"`
			PermissionDecision       string `json:"permissionDecision"`
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("stdout is not valid json: %v (%q)", err, out)
	}
	if parsed.HookSpecificOutput.PermissionDecision != "deny" {
		t.Errorf("permissionDecision = %q, want deny", parsed.HookSpecificOutput.PermissionDecision)
	}
	if parsed.HookSpecificOutput.PermissionDecisionReason != "nope" {
		t.Errorf("reason = %q, want nope", parsed.HookSpecificOutput.PermissionDecisionReason)
	}
	if !strings.Contains(errOut, "nope") {
		t.Errorf("stderr = %q, want it to contain the reason", errOut)
	}
}

func TestEmitHookSpecificDenyDefaultsMessage(t *testing.T) {
	out, _ := captureOutput(t, func() {
		emitHookSpecific(decision{Type: "deny"})
	})
	if !strings.Contains(out, "Blocked by policy") {
		t.Errorf("empty reason did not fall back to a default message: %q", out)
	}
}

func TestEmitHookSpecificRewrite(t *testing.T) {
	patch := map[string]interface{}{"command": "ls -l"}
	out, _ := captureOutput(t, func() {
		if got := emitHookSpecific(decision{Type: "rewrite", Patch: patch}); got != 0 {
			t.Errorf("exit code = %d, want 0", got)
		}
	})
	var parsed struct {
		HookSpecificOutput struct {
			PermissionDecision string                 `json:"permissionDecision"`
			UpdatedInput       map[string]interface{} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("stdout is not valid json: %v (%q)", err, out)
	}
	if parsed.HookSpecificOutput.PermissionDecision != "allow" {
		t.Errorf("permissionDecision = %q, want allow", parsed.HookSpecificOutput.PermissionDecision)
	}
	if parsed.HookSpecificOutput.UpdatedInput["command"] != "ls -l" {
		t.Errorf("updatedInput = %v", parsed.HookSpecificOutput.UpdatedInput)
	}
}

func TestEmitHookSpecificRewriteWithNilPatch(t *testing.T) {
	out, _ := captureOutput(t, func() {
		emitHookSpecific(decision{Type: "rewrite"})
	})
	if !strings.Contains(out, `"updatedInput":{}`) {
		t.Errorf("a nil patch should be emitted as an empty object: %q", out)
	}
}

func TestEmitHookSpecificUnknownTypeIsSilent(t *testing.T) {
	out, errOut := captureOutput(t, func() {
		if got := emitHookSpecific(decision{Type: "allow"}); got != 0 {
			t.Errorf("exit code = %d, want 0", got)
		}
	})
	if out != "" || errOut != "" {
		t.Errorf("expected no output for an allow decision, got stdout=%q stderr=%q", out, errOut)
	}
}

func TestParseAntigravity(t *testing.T) {
	raw := []byte(`{
		"toolCall": {"name": "run_command", "args": {"command": "echo hi", "Cwd": "/proj"}},
		"session_id": "s1"
	}`)
	p := parseAntigravity(raw)
	if p.Tool != "run_command" {
		t.Errorf("Tool = %q, want run_command", p.Tool)
	}
	if p.Cwd != "/proj" {
		t.Errorf("Cwd = %q, want /proj (from args.Cwd)", p.Cwd)
	}
	if p.Command != "echo hi" {
		t.Errorf("Command = %q", p.Command)
	}
	if p.SessionID != "s1" {
		t.Errorf("SessionID = %q", p.SessionID)
	}
	if _, has := p.Args["cwd"]; has {
		t.Error("cwd should have been dropped from args since it is lifted into Cwd separately")
	}
}

func TestParseAntigravityCwdFromTopLevel(t *testing.T) {
	raw := []byte(`{"toolCall":{"name":"x","args":{}},"cwd":"/top"}`)
	p := parseAntigravity(raw)
	if p.Cwd != "/top" {
		t.Errorf("Cwd = %q, want /top", p.Cwd)
	}
}

func TestParseAntigravityCwdFromWorkspacePaths(t *testing.T) {
	raw := []byte(`{"toolCall":{"name":"x","args":{}},"workspacePaths":["/ws/one","/ws/two"]}`)
	p := parseAntigravity(raw)
	if p.Cwd != "/ws/one" {
		t.Errorf("Cwd = %q, want /ws/one (first workspace path)", p.Cwd)
	}
}

func TestParseAntigravityToolNameFallsBackToToolCallName(t *testing.T) {
	raw := []byte(`{"toolCall":{"name":"inner_tool","args":{}}}`)
	p := parseAntigravity(raw)
	if p.Tool != "inner_tool" {
		t.Errorf("Tool = %q, want inner_tool", p.Tool)
	}
}

func TestParseAntigravityPrefersTopLevelToolName(t *testing.T) {
	raw := []byte(`{"tool_name":"outer_tool","toolCall":{"name":"inner_tool","args":{}}}`)
	p := parseAntigravity(raw)
	if p.Tool != "outer_tool" {
		t.Errorf("Tool = %q, want outer_tool", p.Tool)
	}
}

func TestParseGenericDispatchesByShape(t *testing.T) {
	agy := []byte(`{"toolCall":{"name":"x","args":{"command":"c"}}}`)
	if p := parseGeneric(agy); p.Tool != "x" {
		t.Errorf("expected antigravity-shaped payload to parse as antigravity, got Tool=%q", p.Tool)
	}

	flat := []byte(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	if p := parseGeneric(flat); p.Tool != "Bash" {
		t.Errorf("expected flat payload to parse as flat, got Tool=%q", p.Tool)
	}
}

func TestDecodeArray(t *testing.T) {
	cases := []struct {
		name string
		in   string
		ok   bool
		n    int
	}{
		{"empty input", "", false, 0},
		{"a valid array", `["a","b","c"]`, true, 3},
		{"an empty array", `[]`, true, 0},
		{"malformed json", `[1,`, false, 0},
		{"a json object, not an array", `{"a":1}`, false, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := decodeArray(json.RawMessage(c.in))
			if ok != c.ok {
				t.Errorf("ok = %v, want %v", ok, c.ok)
			}
			if len(got) != c.n {
				t.Errorf("len = %d, want %d", len(got), c.n)
			}
		})
	}
}

func TestEmitAntigravityDeny(t *testing.T) {
	out, _ := captureOutput(t, func() {
		if got := emitAntigravity(decision{Type: "deny", Reason: "blocked"}); got != 0 {
			t.Errorf("exit code = %d, want 0", got)
		}
	})
	var parsed agyDeny
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("stdout is not valid json: %v (%q)", err, out)
	}
	if parsed.Decision != "deny" || parsed.AllowTool {
		t.Errorf("parsed = %+v", parsed)
	}
	if !strings.Contains(parsed.Reason, "blocked") || !strings.Contains(parsed.DenyReason, "blocked") {
		t.Errorf("reason fields do not carry the message: %+v", parsed)
	}
}

func TestEmitAntigravityRewriteWithCommand(t *testing.T) {
	out, _ := captureOutput(t, func() {
		emitAntigravity(decision{Type: "rewrite", Patch: map[string]interface{}{"command": "ls -l", "other": "x"}})
	})
	var parsed agyRewrite
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("stdout is not valid json: %v (%q)", err, out)
	}
	if parsed.Overwrite["CommandLine"] != "ls -l" {
		t.Errorf("Overwrite = %v, want CommandLine=ls -l", parsed.Overwrite)
	}
	if _, has := parsed.Overwrite["other"]; has {
		t.Errorf("non-command keys should be dropped when a command patch is present: %v", parsed.Overwrite)
	}
	if !parsed.AllowTool || parsed.Decision != "allow" {
		t.Errorf("parsed = %+v", parsed)
	}
}

func TestEmitAntigravityRewriteWithoutCommand(t *testing.T) {
	out, _ := captureOutput(t, func() {
		emitAntigravity(decision{Type: "rewrite", Patch: map[string]interface{}{"file_path": "/a", "mode": "0644"}})
	})
	var parsed agyRewrite
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("stdout is not valid json: %v (%q)", err, out)
	}
	if parsed.Overwrite["file_path"] != "/a" || parsed.Overwrite["mode"] != "0644" {
		t.Errorf("Overwrite = %v", parsed.Overwrite)
	}
}

func TestEmitAntigravityDefaultIsAllow(t *testing.T) {
	out, _ := captureOutput(t, func() {
		if got := emitAntigravity(decision{Type: ""}); got != 0 {
			t.Errorf("exit code = %d, want 0", got)
		}
	})
	var parsed agyAllow
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("stdout is not valid json: %v (%q)", err, out)
	}
	if parsed.Decision != "allow" || !parsed.AllowTool {
		t.Errorf("parsed = %+v", parsed)
	}
}

func TestWriteJSON(t *testing.T) {
	out, errOut := captureOutput(t, func() {
		writeJSON(map[string]interface{}{"a": 1})
	})
	if errOut != "" {
		t.Errorf("unexpected stderr: %q", errOut)
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("stdout is not valid json: %v (%q)", err, out)
	}
	if m["a"] != float64(1) {
		t.Errorf("m = %v", m)
	}
}

func TestWriteJSONOnMarshalFailureWritesToStderrNotStdout(t *testing.T) {
	out, errOut := captureOutput(t, func() {
		writeJSON(map[string]interface{}{"bad": func() {}})
	})
	if out != "" {
		t.Errorf("expected no stdout on a marshal failure, got %q", out)
	}
	if !strings.Contains(errOut, "could not be encoded") {
		t.Errorf("stderr = %q, want a could-not-be-encoded message", errOut)
	}
}

func TestIsJSSpace(t *testing.T) {
	spaces := []rune{'\t', '\n', '\v', '\f', '\r', ' ', 0x00a0, 0x1680, 0x2005, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff}
	for _, r := range spaces {
		if !isJSSpace(r) {
			t.Errorf("isJSSpace(%U) = false, want true", r)
		}
	}
	notSpaces := []rune{'a', 'Z', '0', '-', '.', 0x1fff}
	for _, r := range notSpaces {
		if isJSSpace(r) {
			t.Errorf("isJSSpace(%U) = true, want false", r)
		}
	}
}

func TestSplitJSLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"newline separated", "a\nb\nc", []string{"a", "b", "c"}},
		{"carriage return separated", "a\rb", []string{"a", "b"}},
		{"line separator U+2028", "a b", []string{"a", "b"}},
		{"paragraph separator U+2029", "a b", []string{"a", "b"}},
		{"consecutive separators collapse", "a\n\nb", []string{"a", "b"}},
		{"plain spaces are not line breaks", "a b c", []string{"a b c"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := splitJSLines(c.in)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("splitJSLines(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestPatchTarget(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"surrounded by whitespace", "  foo/bar.txt  ", "foo/bar.txt"},
		{"no surrounding whitespace", "foo.txt", "foo.txt"},
		{"empty string", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := patchTarget(c.in); got != c.want {
				t.Errorf("patchTarget(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestApplyPatchTargetsWithNoMarker(t *testing.T) {
	if got := applyPatchTargets("just some text"); len(got) != 0 {
		t.Errorf("got %v, want no targets without a '*** ' marker", got)
	}
}

func TestApplyPatchTargetsAddUpdateDelete(t *testing.T) {
	patch := "*** Begin Patch\n*** Add File: a.txt\nsome content\n*** Update File: b.txt\n*** Delete File: c.txt\n*** End Patch"
	got := applyPatchTargets(patch)
	want := []string{"a.txt", "b.txt", "c.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestApplyPatchTargetsMove(t *testing.T) {
	patch := "*** Begin Patch\n*** Update File: old.txt\n*** Move to: new.txt\n*** End Patch"
	got := applyPatchTargets(patch)
	// File-pattern matches come before Move-pattern matches, by regex order.
	want := []string{"old.txt", "new.txt"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestLiftFreeformPatchPathsIgnoresUnrelatedCalls(t *testing.T) {
	c := &neutralCall{call: call{Tool: "Bash", Command: "echo hi", Args: map[string]interface{}{"command": "echo hi"}}}
	before := len(c.Args)
	liftFreeformPatchPaths(c)
	if len(c.Args) != before {
		t.Errorf("args were modified for an unrelated call: %v", c.Args)
	}
}

func TestLiftFreeformPatchPathsSetsFilePathAndEdits(t *testing.T) {
	cmd := "*** Begin Patch\n*** Add File: foo.txt\nhello\n*** End Patch"
	c := &neutralCall{call: call{Tool: "apply_patch", Command: cmd, Args: map[string]interface{}{}}}
	liftFreeformPatchPaths(c)
	if c.Args["file_path"] != "foo.txt" {
		t.Errorf("file_path = %v, want foo.txt", c.Args["file_path"])
	}
	edits, ok := c.Args["edits"].([]interface{})
	if !ok || len(edits) != 1 {
		t.Fatalf("edits = %v, want one entry", c.Args["edits"])
	}
	entry, ok := edits[0].(map[string]interface{})
	if !ok || entry["file_path"] != "foo.txt" {
		t.Errorf("edits[0] = %v", edits[0])
	}
}

func TestLiftFreeformPatchPathsDoesNotOverwriteExistingFilePath(t *testing.T) {
	cmd := "*** Begin Patch\n*** Add File: foo.txt\n*** End Patch"
	c := &neutralCall{call: call{Tool: "apply_patch", Command: cmd, Args: map[string]interface{}{"file_path": "already-set.txt"}}}
	liftFreeformPatchPaths(c)
	if c.Args["file_path"] != "already-set.txt" {
		t.Errorf("file_path = %v, want it left untouched", c.Args["file_path"])
	}
}

func TestLiftFreeformPatchPathsDoesNotOverwriteExistingEdits(t *testing.T) {
	cmd := "*** Begin Patch\n*** Add File: foo.txt\n*** End Patch"
	existing := []interface{}{map[string]interface{}{"file_path": "keep-me.txt"}}
	c := &neutralCall{call: call{Tool: "apply_patch", Command: cmd, Args: map[string]interface{}{"edits": existing}}}
	liftFreeformPatchPaths(c)
	edits, ok := c.Args["edits"].([]interface{})
	if !ok || len(edits) != 1 {
		t.Fatalf("edits = %v", c.Args["edits"])
	}
	if entry := edits[0].(map[string]interface{}); entry["file_path"] != "keep-me.txt" {
		t.Errorf("existing edits were overwritten: %v", edits)
	}
}

func TestLiftFreeformPatchPathsRecognizesFreeformBeginPatch(t *testing.T) {
	cmd := "*** Begin Patch\n*** Add File: freeform.txt\n*** End Patch"
	c := &neutralCall{call: call{Tool: "shell", Command: cmd, Args: map[string]interface{}{}}}
	liftFreeformPatchPaths(c)
	if c.Args["file_path"] != "freeform.txt" {
		t.Errorf("a freeform apply-patch-shaped command through a non apply_patch tool was not lifted: %v", c.Args)
	}
}

func TestLiftFreeformPatchPathsWithNoExtractableTargetsLeavesArgsAlone(t *testing.T) {
	c := &neutralCall{call: call{Tool: "apply_patch", Command: "not a real patch", Args: map[string]interface{}{"x": 1}}}
	liftFreeformPatchPaths(c)
	if len(c.Args) != 1 || c.Args["x"] != 1 {
		t.Errorf("args were modified even though no patch targets could be found: %v", c.Args)
	}
}

func TestClientFor(t *testing.T) {
	for _, name := range []string{"claude-code", "codex", "opencode", "antigravity", "generic"} {
		if got := clientFor(name); got != clients[name] {
			t.Errorf("clientFor(%q) did not return the registered client", name)
		}
	}

	if got := clientFor("some-unknown-agent"); got != clients["generic"] {
		t.Errorf("clientFor of an unknown agent did not return the generic client")
	}
}

func TestNormalizeToolCall(t *testing.T) {
	raw := []byte(`{
		"tool_name": "Bash",
		"tool_input": {"command": "ls"},
		"cwd": "/explicit/cwd",
		"session_id": "s1",
		"tool_use_id": "call-123"
	}`)
	nc := normalizeToolCall(clients["generic"], "claude-code", raw)
	if nc.Tool != "Bash" {
		t.Errorf("Tool = %q, want Bash", nc.Tool)
	}
	if nc.Cwd != "/explicit/cwd" {
		t.Errorf("Cwd = %q, want /explicit/cwd", nc.Cwd)
	}
	if nc.CallID != "call-123" {
		t.Errorf("CallID = %q, want call-123", nc.CallID)
	}
	if nc.Client != "claude-code" {
		t.Errorf("Client = %q, want claude-code", nc.Client)
	}
	if nc.Permission == "" {
		t.Error("Permission was not derived")
	}
	if nc.Response == nil {
		t.Error("Response should default to an empty map, not nil")
	}
	if string(nc.Raw) != string(raw) {
		t.Error("Raw did not retain the original payload")
	}
}

func TestNormalizeToolCallFallsBackToRealCwdWhenMissing(t *testing.T) {
	raw := []byte(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`)
	nc := normalizeToolCall(clients["generic"], "generic", raw)
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if nc.Cwd != wd {
		t.Errorf("Cwd = %q, want the real working directory %q", nc.Cwd, wd)
	}
}

func TestNormalizeToolCallArgsDefaultToEmptyMap(t *testing.T) {
	raw := []byte(`{"tool_name":"Bash"}`)
	nc := normalizeToolCall(clients["generic"], "generic", raw)
	if nc.Args == nil {
		t.Error("Args should default to an empty map, not nil")
	}
}

func TestNormalizeToolCallLiftsApplyPatchTargets(t *testing.T) {
	cmd := "*** Begin Patch\n*** Add File: lifted.txt\n*** End Patch"
	raw, err := json.Marshal(map[string]interface{}{
		"tool_name":  "apply_patch",
		"tool_input": map[string]interface{}{"command": cmd},
	})
	if err != nil {
		t.Fatal(err)
	}
	nc := normalizeToolCall(clients["generic"], "codex", raw)
	if nc.Args["file_path"] != "lifted.txt" {
		t.Errorf("normalizeToolCall did not lift the patch target: %v", nc.Args)
	}
}