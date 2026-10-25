// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package auditcmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solongate/agent-security/packages/shared"
)

func TestIsString(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want bool
	}{
		{"non-empty string", "x", true},
		{"empty string", "", false},
		{"nil", nil, false},
		{"not a string", 5, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isString(c.in); got != c.want {
				t.Errorf("isString(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestIsArray(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want bool
	}{
		{"an array", []interface{}{1, 2}, true},
		{"an empty array", []interface{}{}, true},
		{"nil", nil, false},
		{"a string", "x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := isArray(c.in); got != c.want {
				t.Errorf("isArray(%v) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

func TestCloneMap(t *testing.T) {
	orig := map[string]interface{}{"a": 1, "b": "x"}
	clone := cloneMap(orig)
	clone["a"] = 2
	clone["c"] = "new"

	if orig["a"] != 1 {
		t.Errorf("mutating the clone changed the original: orig[a] = %v", orig["a"])
	}
	if _, ok := orig["c"]; ok {
		t.Error("mutating the clone added a key to the original")
	}
	if clone["b"] != "x" {
		t.Errorf("clone lost an untouched field: clone[b] = %v", clone["b"])
	}
}

func TestExtractOutputText(t *testing.T) {
	cases := []struct {
		name         string
		toolResponse interface{}
		toolOutput   string
		wantNil      bool
		want         string
	}{
		{"string response", "hello", "", false, "hello"},
		{"map stdout", map[string]interface{}{"stdout": "out-text"}, "", false, "out-text"},
		{"map content string", map[string]interface{}{"content": "content-text"}, "", false, "content-text"},
		{"map file.content", map[string]interface{}{"file": map[string]interface{}{"content": "file-text"}}, "", false, "file-text"},
		{
			"map content array of text parts",
			map[string]interface{}{"content": []interface{}{
				map[string]interface{}{"type": "text", "text": "part1"},
				map[string]interface{}{"type": "text", "text": "part2"},
				map[string]interface{}{"type": "other", "text": "ignored"},
			}},
			"", false, "part1\npart2",
		},
		{
			"map filenames array",
			map[string]interface{}{"filenames": []interface{}{"a.txt", "b.txt"}},
			"", false, "a.txt\nb.txt",
		},
		{"toolOutput fallback", nil, "fallback", false, "fallback"},
		{"nothing at all", nil, "", true, ""},
		{
			"file.content returns even when empty, taking precedence over toolOutput",
			map[string]interface{}{"file": map[string]interface{}{"content": ""}},
			"ignored", false, "",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := extractOutputText(c.toolResponse, c.toolOutput)
			if c.wantNil {
				if got != nil {
					t.Errorf("extractOutputText() = %q, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("extractOutputText() = nil, want %q", c.want)
			}
			if *got != c.want {
				t.Errorf("extractOutputText() = %q, want %q", *got, c.want)
			}
		})
	}
}

func TestCompactJSON(t *testing.T) {
	in := []byte(`{ "a" : 1 , "b" : [1,2,3] }`)
	want := `{"a":1,"b":[1,2,3]}`
	if got := compactJSON(in); got != want {
		t.Errorf("compactJSON() = %q, want %q", got, want)
	}

	invalid := []byte(`not json`)
	if got := compactJSON(invalid); got != string(invalid) {
		t.Errorf("compactJSON(invalid) = %q, want %q (the raw input unchanged)", got, string(invalid))
	}
}

func TestCallFingerprintIsStableAndDiscriminating(t *testing.T) {
	a1 := callFingerprint("abc")
	a2 := callFingerprint("abc")
	if a1 != a2 {
		t.Errorf("callFingerprint is not stable: %q vs %q", a1, a2)
	}
	if a1 == "" {
		t.Error("callFingerprint returned an empty string for a non-empty input")
	}

	b := callFingerprint("a very different string entirely")
	if a1 == b {
		t.Errorf("callFingerprint gave the same value for two different inputs: %q", a1)
	}

	if got := callFingerprint(""); got == "" {
		t.Error("callFingerprint(\"\") returned an empty string")
	}
}

// --- Run ---

func withAuditIO(t *testing.T, stdin string) (stdoutCapture func() string) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn := os.Stdin
	os.Stdin = r
	if _, err := w.WriteString(stdin); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	ro, wo, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldOut := os.Stdout
	os.Stdout = wo

	t.Cleanup(func() {
		os.Stdin = oldIn
	})

	return func() string {
		os.Stdout = oldOut
		wo.Close()
		out, _ := io.ReadAll(ro)
		return string(out)
	}
}

func readLastAuditLogEntry(t *testing.T) map[string]interface{} {
	t.Helper()
	path := filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading audit log: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	var entry map[string]interface{}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &entry); err != nil {
		t.Fatalf("unmarshaling last entry: %v", err)
	}
	return entry
}

func auditLogExists() bool {
	_, err := os.Stat(filepath.Join(shared.SGDir(), "local-logs", "solongate-audit.jsonl"))
	return err == nil
}

func TestRunBashToolWithAuditLogsInInputIsSkipped(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stdin := `{"tool_name":"Bash","tool_input":{"command":"cat ~/.solongate/local-logs/audit-logs/x"}}`
	finish := withAuditIO(t, stdin)
	code := Run(nil, func(string) bool { return true })
	finish()

	if code != 0 {
		t.Fatalf("Run() = %d, want 0", code)
	}
	if auditLogExists() {
		t.Error("a Bash call referencing audit-logs still produced a log entry")
	}
}

func TestRunBasicAllowDecision(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	stdin := `{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"tool_response":{"content":"hello world"},"session_id":"sess1"}`
	finish := withAuditIO(t, stdin)
	code := Run(nil, func(string) bool { return true })
	finish()

	if code != 0 {
		t.Fatalf("Run() = %d, want 0", code)
	}
	entry := readLastAuditLogEntry(t)
	if entry["tool"] != "Read" || entry["decision"] != "ALLOW" || entry["session_id"] != "sess1" {
		t.Errorf("entry = %v, want tool=Read decision=ALLOW session_id=sess1", entry)
	}
	if entry["agent_id"] != "claude-code" || entry["agent_name"] != "Claude Code" {
		t.Errorf("entry defaults = %v, want claude-code/Claude Code", entry)
	}
}

func TestRunGuardDeniedViaGenericLastDenyFlag(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := shared.ProjectFlagDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	flag := map[string]interface{}{
		"tool": "Read",
		"ts":   float64(time.Now().UnixMilli()),
		"id":   "",
		"fp":   "",
	}
	b, _ := json.Marshal(flag)
	if err := os.WriteFile(filepath.Join(dir, ".last-deny"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	stdin := `{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"tool_response":{"content":"ok"},"session_id":"s2"}`
	finish := withAuditIO(t, stdin)
	code := Run(nil, func(string) bool { return true })
	finish()

	if code != 0 {
		t.Fatalf("Run() = %d, want 0", code)
	}
	entry := readLastAuditLogEntry(t)
	if entry["decision"] != "DENY" || entry["reason"] != "blocked by policy guard" {
		t.Errorf("entry = %v, want decision=DENY reason='blocked by policy guard'", entry)
	}
}

func TestRunGuardDeniedViaMatchingCallID(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	dir := shared.ProjectFlagDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	flag := map[string]interface{}{
		"tool": "Read",
		"ts":   float64(time.Now().UnixMilli()),
		"id":   "call-123",
	}
	b, _ := json.Marshal(flag)
	if err := os.WriteFile(filepath.Join(dir, ".last-deny"), b, 0o600); err != nil {
		t.Fatal(err)
	}

	stdin := `{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"tool_response":{"content":"ok"},"session_id":"s2","tool_use_id":"call-123"}`
	finish := withAuditIO(t, stdin)
	code := Run(nil, func(string) bool { return true })
	finish()

	if code != 0 {
		t.Fatalf("Run() = %d, want 0", code)
	}
	entry := readLastAuditLogEntry(t)
	if entry["decision"] != "DENY" || entry["reason"] != "blocked by policy guard" {
		t.Errorf("entry = %v, want decision=DENY reason='blocked by policy guard'", entry)
	}
}

func TestRunHasErrorDetection(t *testing.T) {
	cases := []struct {
		name  string
		stdin string
	}{
		{
			"tool_response.error truthy",
			`{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"tool_response":{"error":true},"session_id":"s"}`,
		},
		{
			"tool_response.exitCode > 0",
			`{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_response":{"exitCode":2},"session_id":"s"}`,
		},
		{
			"tool_response.isError truthy",
			`{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"tool_response":{"isError":true},"session_id":"s"}`,
		},
		{
			`tool_output contains "error"`,
			`{"tool_name":"Bash","tool_input":{"command":"ls"},"tool_output":"{\"error\":\"oops\"}","session_id":"s"}`,
		},
		{
			`result_json contains "error"`,
			`{"tool_name":"Bash","tool_input":{"command":"ls"},"result_json":"{\"error\":true}","session_id":"s"}`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("HOME", home)

			finish := withAuditIO(t, c.stdin)
			code := Run(nil, func(string) bool { return true })
			finish()

			if code != 0 {
				t.Fatalf("Run() = %d, want 0", code)
			}
			entry := readLastAuditLogEntry(t)
			if entry["decision"] != "DENY" || entry["reason"] != "tool returned error" {
				t.Errorf("entry = %v, want decision=DENY reason='tool returned error'", entry)
			}
		})
	}
}

// writeLocalPolicyWithDLPRedact writes an unsigned local policy.json under
// $HOME/.solongate enabling DLP redaction for the given patterns, matching
// the envelope shape guardcore.LoadLocalPolicyFile expects.
func writeLocalPolicyWithDLPRedact(t *testing.T, patterns []string) {
	t.Helper()
	sgDir := shared.SGDir()
	if err := os.MkdirAll(sgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	patJSON, _ := json.Marshal(patterns)
	doc := fmt.Sprintf(`{"policy":{"id":"p1","name":"n","mode":"observe","rules":{}},"security":{"dlpRedact":{"patterns":%s}}}`, patJSON)
	if err := os.WriteFile(filepath.Join(sgDir, "policy.json"), []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRunEmittedPayloadGatedByRedactsOutputCallback(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	stdin := fmt.Sprintf(`{"tool_name":"Read","tool_input":{"file_path":"/tmp/x"},"tool_response":{"stdout":"my key is %s end"},"session_id":"s3"}`, secret)

	t.Run("redaction allowed, stdout carries the redacted payload", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		writeLocalPolicyWithDLPRedact(t, []string{"AWS access key"})

		finish := withAuditIO(t, stdin)
		code := Run(nil, func(string) bool { return true })
		out := finish()

		if code != 0 {
			t.Fatalf("Run() = %d, want 0", code)
		}
		if out == "" {
			t.Fatal("expected a redacted payload on stdout, got nothing")
		}
		if !strings.Contains(out, "hookSpecificOutput") {
			t.Errorf("stdout = %q, want it to contain hookSpecificOutput", out)
		}
		if strings.Contains(out, secret) {
			t.Errorf("the secret leaked into stdout: %q", out)
		}
	})

	t.Run("redaction disallowed, stdout stays empty", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		writeLocalPolicyWithDLPRedact(t, []string{"AWS access key"})

		finish := withAuditIO(t, stdin)
		code := Run(nil, func(string) bool { return false })
		out := finish()

		if code != 0 {
			t.Fatalf("Run() = %d, want 0", code)
		}
		if out != "" {
			t.Errorf("stdout = %q, want empty since redactsOutput returned false", out)
		}
	})
}