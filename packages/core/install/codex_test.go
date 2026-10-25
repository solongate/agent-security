// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func codexTestPaths(dir string) Paths {
	return Paths{
		HooksDir: filepath.Join(dir, ".solongate", "hooks"),

		CodexDir:        dir,
		CodexHooksPath:  filepath.Join(dir, "hooks.json"),
		CodexBackupPath: filepath.Join(dir, "hooks.solongate.bak"),
		CodexConfigPath: filepath.Join(dir, "config.toml"),
	}
}

func TestIsJSONString(t *testing.T) {
	cases := []struct {
		name string
		in   json.RawMessage
		want bool
	}{
		{"string", json.RawMessage(`"hi"`), true},
		{"number", json.RawMessage(`42`), false},
		{"empty", json.RawMessage(``), false},
		{"object", json.RawMessage(`{}`), false},
	}
	for _, tc := range cases {
		if got := isJSONString(tc.in); got != tc.want {
			t.Errorf("isJSONString(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestDecodeArray(t *testing.T) {
	arr, ok := decodeArray(json.RawMessage(`[1,2,3]`))
	if !ok || len(arr) != 3 {
		t.Fatalf("decodeArray(array) = (%v, %v), want 3 elements and ok", arr, ok)
	}

	if _, ok := decodeArray(json.RawMessage(`{"a":1}`)); ok {
		t.Error("decodeArray(object) = ok, want not-ok")
	}
	if _, ok := decodeArray(json.RawMessage(``)); ok {
		t.Error("decodeArray(empty) = ok, want not-ok")
	}
	if _, ok := decodeArray(json.RawMessage(`[1,`)); ok {
		t.Error("decodeArray(invalid array) = ok, want not-ok")
	}
}

func TestIsOurCodexGroup(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want bool
	}{
		{"ours", `{"hooks":[{"command":"/bin/sh ~/.solongate/hooks/sg-run.sh guard"}]}`, true},
		{"foreign", `{"hooks":[{"command":"/usr/bin/other-tool"}]}`, false},
		{"invalid json", `not json`, false},
		{"no hooks", `{}`, false},
	}
	for _, tc := range cases {
		if got := isOurCodexGroup(json.RawMessage(tc.raw)); got != tc.want {
			t.Errorf("isOurCodexGroup(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestReadCodexHooksMissingFile(t *testing.T) {
	f := readCodexHooks(filepath.Join(t.TempDir(), "missing.json"))
	if len(f.events) != 0 || len(f.groups) != 0 {
		t.Errorf("readCodexHooks(missing) = %+v, want an empty codexFile", f)
	}
}

func TestReadCodexHooksSeparatesEventsDescriptionAndRest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	body := `{
		"description": "my codex hooks",
		"customField": 123,
		"hooks": {
			"PreToolUse": [{"hooks":[{"command":"a"}]}]
		},
		"PostToolUse": [{"hooks":[{"command":"b"}]}]
	}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	f := readCodexHooks(path)
	if string(f.description) != `"my codex hooks"` {
		t.Errorf("description = %s, want %q", f.description, `"my codex hooks"`)
	}
	if !f.rest.has("customField") {
		t.Error("customField should be preserved in rest")
	}
	if len(f.groups["PreToolUse"]) != 1 {
		t.Errorf("PreToolUse groups = %d, want 1", len(f.groups["PreToolUse"]))
	}
	if len(f.groups["PostToolUse"]) != 1 {
		t.Errorf("PostToolUse groups = %d, want 1", len(f.groups["PostToolUse"]))
	}

	seen := map[string]bool{}
	for _, ev := range f.events {
		seen[ev] = true
	}
	if !seen["PreToolUse"] || !seen["PostToolUse"] {
		t.Errorf("events = %v, want both PreToolUse and PostToolUse", f.events)
	}
}

func TestCodexFileEncodeOmitsEmptyGroupsAndBlankDescription(t *testing.T) {
	f := newCodexFile()
	f.setGroups("PreToolUse", nil)
	f.description = json.RawMessage(`""`)

	b, err := f.encode()
	if err != nil {
		t.Fatalf("encode() error: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("encode() produced invalid JSON: %v", err)
	}
	if _, ok := decoded["description"]; ok {
		t.Error("blank description should be omitted")
	}
	var hooks map[string]json.RawMessage
	if err := json.Unmarshal(decoded["hooks"], &hooks); err != nil {
		t.Fatalf("hooks is not an object: %v", err)
	}
	if _, ok := hooks["PreToolUse"]; ok {
		t.Error("an event with zero groups should not appear in the encoded hooks")
	}
}

func TestCodexFileAppendGroups(t *testing.T) {
	f := newCodexFile()
	f.appendGroups("Stop", []json.RawMessage{json.RawMessage(`{"a":1}`)})
	f.appendGroups("Stop", []json.RawMessage{json.RawMessage(`{"a":2}`)})
	if len(f.groups["Stop"]) != 2 {
		t.Fatalf("groups[Stop] = %d entries, want 2", len(f.groups["Stop"]))
	}
	if len(f.events) != 1 || f.events[0] != "Stop" {
		t.Errorf("events = %v, want [Stop] exactly once", f.events)
	}
}

func TestReadCodexHooksEncodeRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	body := `{"description":"d","hooks":{"PreToolUse":[{"hooks":[{"command":"a"}]}]}}`
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f := readCodexHooks(path)
	encoded, err := f.encode()
	if err != nil {
		t.Fatalf("encode() error: %v", err)
	}

	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	f2 := readCodexHooks(path)
	if string(f2.description) != `"d"` {
		t.Errorf("round-tripped description = %s, want %q", f2.description, `"d"`)
	}
	if len(f2.groups["PreToolUse"]) != 1 {
		t.Errorf("round-tripped PreToolUse groups = %d, want 1", len(f2.groups["PreToolUse"]))
	}
}

func TestPlanCodexAddsOurGroupToEveryEvent(t *testing.T) {
	p := codexTestPaths(t.TempDir())
	reg, err := planCodex(p)
	if err != nil {
		t.Fatalf("planCodex() error: %v", err)
	}
	if reg.path != p.CodexHooksPath || reg.dir != p.CodexDir || reg.backupPath != p.CodexBackupPath {
		t.Errorf("registration fields = %+v, want paths from Paths", reg)
	}

	if err := os.WriteFile(p.CodexHooksPath, reg.content, 0o644); err != nil {
		t.Fatal(err)
	}
	f := readCodexHooks(p.CodexHooksPath)
	for _, ev := range codexEvents {
		found := false
		for _, g := range f.groups[ev] {
			if isOurCodexGroup(g) {
				found = true
			}
		}
		if !found {
			t.Errorf("event %q has no SolonGate group after planCodex", ev)
		}
	}
}

func TestPlanCodexReplacesOurPreviousGroupWithoutDuplicating(t *testing.T) {
	p := codexTestPaths(t.TempDir())

	reg1, err := planCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.CodexHooksPath, reg1.content, 0o644); err != nil {
		t.Fatal(err)
	}

	reg2, err := planCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.CodexHooksPath, reg2.content, 0o644); err != nil {
		t.Fatal(err)
	}

	f := readCodexHooks(p.CodexHooksPath)
	for _, ev := range codexEvents {
		count := 0
		for _, g := range f.groups[ev] {
			if isOurCodexGroup(g) {
				count++
			}
		}
		if count != 1 {
			t.Errorf("event %q has %d SolonGate groups after re-planning, want exactly 1", ev, count)
		}
	}
}

func TestPlanCodexPreservesForeignGroups(t *testing.T) {
	p := codexTestPaths(t.TempDir())
	body := `{"hooks":{"PreToolUse":[{"hooks":[{"command":"/usr/bin/other-tool"}]}]}}`
	if err := os.WriteFile(p.CodexHooksPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := planCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reg.content), "/usr/bin/other-tool") {
		t.Errorf("a foreign hook group was dropped by planCodex: %s", reg.content)
	}
}

func TestRemoveCodexRegistration(t *testing.T) {
	p := codexTestPaths(t.TempDir())

	if err := removeCodexRegistration(p); err != nil {
		t.Errorf("removeCodexRegistration() with no file: %v, want nil", err)
	}

	reg, err := planCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.CodexHooksPath, reg.content, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := removeCodexRegistration(p); err != nil {
		t.Fatalf("removeCodexRegistration() error: %v", err)
	}
	f := readCodexHooks(p.CodexHooksPath)
	for _, ev := range codexEvents {
		for _, g := range f.groups[ev] {
			if isOurCodexGroup(g) {
				t.Errorf("event %q still has a SolonGate group after removal", ev)
			}
		}
	}
}

func TestCodexGuardInstalledAndDetected(t *testing.T) {
	home := t.TempDir()
	codexHome := filepath.Join(t.TempDir(), "codex-home")
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", codexHome)

	if CodexGuardInstalled() {
		t.Error("CodexGuardInstalled() = true before anything is registered")
	}
	if CodexDetected() {
		t.Error("CodexDetected() = true before the codex dir exists")
	}

	if err := os.MkdirAll(codexHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if !CodexDetected() {
		t.Error("CodexDetected() = false after the codex dir was created")
	}

	p := GlobalPaths()
	reg, err := planCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.CodexHooksPath, reg.content, 0o644); err != nil {
		t.Fatal(err)
	}
	if !CodexGuardInstalled() {
		t.Error("CodexGuardInstalled() = false after planCodex was committed")
	}
}

func TestCodexRegisteredCommand(t *testing.T) {
	p := codexTestPaths(t.TempDir())
	if got := codexRegisteredCommand(p); got != "" {
		t.Errorf("codexRegisteredCommand() with no file = %q, want empty", got)
	}

	reg, err := planCodex(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.CodexHooksPath, reg.content, 0o644); err != nil {
		t.Fatal(err)
	}
	got := codexRegisteredCommand(p)
	if !strings.Contains(got, ".solongate") {
		t.Errorf("codexRegisteredCommand() = %q, want a command referencing .solongate", got)
	}
}

func TestCodexHooksStatus(t *testing.T) {
	home := t.TempDir()
	codexHome := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", codexHome)

	st := CodexHooksStatus()
	if st.Registered || st.Trusted || st.Disabled {
		t.Errorf("CodexHooksStatus() with nothing set up = %+v, want all false", st)
	}

	configPath := filepath.Join(codexHome, "config.toml")
	if err := os.WriteFile(configPath, []byte("trusted_hash = \"abc\"\n[features]\nhooks = false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	st = CodexHooksStatus()
	if !st.Trusted {
		t.Error("CodexHooksStatus().Trusted = false, want true when trusted_hash is present")
	}
	if !st.Disabled {
		t.Error("CodexHooksStatus().Disabled = false, want true when hooks = false is present")
	}
}

func TestCodexDisabledRegexOnlyMatchesHooksAssignment(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"disabled", "hooks = false\n", true},
		{"disabled with indentation", "  hooks = false  \n", true},
		{"enabled", "hooks = true\n", false},
		{"unrelated mention", "# hooks = false is the default\n", false},
	}
	for _, tc := range cases {
		if got := codexDisabledRe.MatchString(tc.body); got != tc.want {
			t.Errorf("codexDisabledRe.MatchString(%q) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

func TestCodexHookCommandReferencesKindAndClient(t *testing.T) {
	p := codexTestPaths(t.TempDir())
	got := codexHookCommand(p, auditKind)
	if !strings.Contains(got, "audit") || !strings.Contains(got, "codex") || !strings.Contains(got, "Codex") {
		t.Errorf("codexHookCommand(audit) = %q, want it to mention audit, codex and Codex", got)
	}
}