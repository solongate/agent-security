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

func clientTestPaths(dir string) Paths {
	return Paths{
		HooksDir: filepath.Join(dir, ".solongate", "hooks"),

		ClaudeDir:    filepath.Join(dir, "claude"),
		SettingsPath: filepath.Join(dir, "claude", "settings.json"),
		BackupPath:   filepath.Join(dir, "claude", "settings.solongate.bak"),

		AntigravityDir:        filepath.Join(dir, "gemini"),
		AntigravityHooksPath:  filepath.Join(dir, "gemini", "hooks.json"),
		AntigravityBackupPath: filepath.Join(dir, "gemini", "hooks.solongate.bak"),

		OpencodeDir:        filepath.Join(dir, "opencode"),
		OpencodePluginDir:  filepath.Join(dir, "opencode", "plugins"),
		OpencodePluginPath: filepath.Join(dir, "opencode", "plugins", "solongate.js"),
	}
}

func TestMatcherReturnsPointerToValue(t *testing.T) {
	m := matcher("abc")
	if m == nil || *m != "abc" {
		t.Fatalf("matcher(%q) = %v, want pointer to %q", "abc", m, "abc")
	}
}

func TestCallPrefixOnThisPlatform(t *testing.T) {
	if got := callPrefix(); got != "" {
		t.Errorf("callPrefix() = %q, want empty string on this platform", got)
	}
}

func TestRegistrationCommitWritesFileAndCreatesDir(t *testing.T) {
	dir := t.TempDir()
	r := registration{
		path:    filepath.Join(dir, "nested", "settings.json"),
		dir:     filepath.Join(dir, "nested"),
		content: []byte(`{"a":1}`),
	}
	if err := r.commit(); err != nil {
		t.Fatalf("commit() error: %v", err)
	}
	got, err := os.ReadFile(r.path)
	if err != nil {
		t.Fatalf("reading committed file: %v", err)
	}
	if string(got) != `{"a":1}` {
		t.Errorf("committed content = %q, want %q", got, `{"a":1}`)
	}
}

func TestRegistrationCommitWritesBackupOnceOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	backup := filepath.Join(dir, "settings.bak")

	r := registration{
		path:       path,
		backupPath: backup,
		original:   []byte("original content"),
		content:    []byte("new content"),
	}
	if err := r.commit(); err != nil {
		t.Fatalf("commit() error: %v", err)
	}
	b, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("reading backup: %v", err)
	}
	if string(b) != "original content" {
		t.Errorf("backup content = %q, want %q", b, "original content")
	}

	r2 := registration{
		path:       path,
		backupPath: backup,
		original:   []byte("a different original"),
		content:    []byte("second commit"),
	}
	if err := r2.commit(); err != nil {
		t.Fatalf("second commit() error: %v", err)
	}
	b2, err := os.ReadFile(backup)
	if err != nil {
		t.Fatalf("reading backup after second commit: %v", err)
	}
	if string(b2) != "original content" {
		t.Errorf("backup was overwritten: got %q, want the first-ever original preserved", b2)
	}
}

func TestReadIfPresent(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	b, err := readIfPresent(missing)
	if err != nil || b != nil {
		t.Errorf("readIfPresent(missing) = (%v, %v), want (nil, nil)", b, err)
	}

	present := filepath.Join(dir, "present.json")
	if err := os.WriteFile(present, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err = readIfPresent(present)
	if err != nil || string(b) != "hello" {
		t.Errorf("readIfPresent(present) = (%q, %v), want (\"hello\", nil)", b, err)
	}
}

func TestClaudeHooksValueMapsEventsToKinds(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	values := claudeHooksValue(p)

	cases := []struct {
		event string
		kind  string
	}{
		{"PreToolUse", guardKind},
		{"PostToolUse", auditKind},
		{"Stop", tokensKind},
	}
	for _, tc := range cases {
		groups, ok := values[tc.event]
		if !ok || len(groups) != 1 || len(groups[0].Hooks) != 1 {
			t.Fatalf("values[%q] = %+v, want exactly one group with one hook", tc.event, groups)
		}
		cmd := groups[0].Hooks[0].Command
		if !strings.Contains(cmd, " "+tc.kind+" ") {
			t.Errorf("values[%q] command %q does not reference kind %q", tc.event, cmd, tc.kind)
		}
		if !strings.Contains(cmd, "claude-code") || !strings.Contains(cmd, "Claude Code") {
			t.Errorf("values[%q] command %q does not reference the claude-code client", tc.event, cmd)
		}
	}
}

func TestPlanClaudeFreshSettings(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	reg, err := planClaude(p)
	if err != nil {
		t.Fatalf("planClaude() error: %v", err)
	}
	if reg.path != p.SettingsPath || reg.dir != p.ClaudeDir || reg.backupPath != p.BackupPath {
		t.Errorf("registration fields = %+v, want paths/dir/backup from Paths", reg)
	}
	if reg.original != nil {
		t.Errorf("original = %q, want nil for a missing settings file", reg.original)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(reg.content, &decoded); err != nil {
		t.Fatalf("content is not valid JSON: %v, content: %s", err, reg.content)
	}
	hooksRaw, ok := decoded["hooks"]
	if !ok {
		t.Fatalf("content has no \"hooks\" key: %s", reg.content)
	}
	var hooks map[string][]hookGroup
	if err := json.Unmarshal(hooksRaw, &hooks); err != nil {
		t.Fatalf("hooks is not the expected shape: %v", err)
	}
	for _, ev := range []string{"PreToolUse", "PostToolUse", "Stop"} {
		if len(hooks[ev]) == 0 {
			t.Errorf("hooks[%q] is empty", ev)
		}
	}
}

func TestPlanClaudePreservesExistingKeysBeforeHooks(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SettingsPath, []byte(`{"foo":"bar"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := planClaude(p)
	if err != nil {
		t.Fatalf("planClaude() error: %v", err)
	}
	content := string(reg.content)
	fooIdx := strings.Index(content, `"foo"`)
	hooksIdx := strings.Index(content, `"hooks"`)
	if fooIdx == -1 || hooksIdx == -1 || fooIdx > hooksIdx {
		t.Errorf("expected pre-existing key to be kept and precede hooks, got: %s", content)
	}
	if string(reg.original) != `{"foo":"bar"}` {
		t.Errorf("original = %q, want the pre-existing file content", reg.original)
	}
}

func TestPlanClaudeInvalidJSONStartsFresh(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SettingsPath, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := planClaude(p)
	if err != nil {
		t.Fatalf("planClaude() error: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(reg.content, &decoded); err != nil {
		t.Fatalf("content is not valid JSON: %v", err)
	}
	if len(decoded) != 1 {
		t.Errorf("decoded = %+v, want only the hooks key when starting from invalid JSON", decoded)
	}
}

func TestRemoveClaudeRegistration(t *testing.T) {
	p := clientTestPaths(t.TempDir())

	if err := removeClaudeRegistration(p); err != nil {
		t.Errorf("removeClaudeRegistration() with no settings file: %v, want nil", err)
	}

	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SettingsPath, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeClaudeRegistration(p); err != errUnparseableSettings {
		t.Errorf("removeClaudeRegistration() with invalid JSON = %v, want errUnparseableSettings", err)
	}

	ours := `{"type":"command","command":"/bin/sh \"/home/u/.solongate/hooks/sg-run.sh\" guard claude-code \"Claude Code\""}`
	if err := os.WriteFile(p.SettingsPath, []byte(`{"hooks":{"PreToolUse":[{"matcher":"","hooks":[`+ours+`]}]},"other":2}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeClaudeRegistration(p); err != nil {
		t.Fatalf("removeClaudeRegistration() error: %v", err)
	}
	b, err := os.ReadFile(p.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "hooks") {
		t.Errorf("settings still contain hooks after removing the only registered ones: %s", b)
	}
	if !strings.Contains(string(b), "other") {
		t.Errorf("settings lost the unrelated \"other\" key: %s", b)
	}
}

// foreignClaudeSettings is a settings.json that already carries hooks from
// other tools, plus a SolonGate handler sharing a group with one of them.
const foreignClaudeSettings = `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "/usr/local/bin/lint-bash", "timeout": 5}]},
      {"matcher": "", "hooks": [
        {"type": "command", "command": "/usr/local/bin/notify"},
        {"type": "command", "command": "/bin/sh \"/old/.solongate/hooks/sg-run.sh\" guard claude-code \"Claude Code\""}
      ]}
    ],
    "Notification": [{"hooks": [{"type": "command", "command": "say done && echo <ok>"}]}]
  }
}`

func readClaudeHooks(t *testing.T, content []byte) map[string][]hookGroup {
	t.Helper()
	var s struct {
		Hooks map[string][]hookGroup `json:"hooks"`
	}
	if err := json.Unmarshal(content, &s); err != nil {
		t.Fatalf("settings are not valid JSON: %v, content: %s", err, content)
	}
	return s.Hooks
}

func claudeCommands(groups []hookGroup) (ours, foreign []string) {
	for _, g := range groups {
		for _, h := range g.Hooks {
			if strings.Contains(h.Command, ".solongate") {
				ours = append(ours, h.Command)
			} else {
				foreign = append(foreign, h.Command)
			}
		}
	}
	return ours, foreign
}

func TestPlanClaudeKeepsUnrelatedHooks(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SettingsPath, []byte(foreignClaudeSettings), 0o644); err != nil {
		t.Fatal(err)
	}

	reg, err := planClaude(p)
	if err != nil {
		t.Fatalf("planClaude() error: %v", err)
	}
	hooks := readClaudeHooks(t, reg.content)

	pre := hooks["PreToolUse"]
	if len(pre) != 3 {
		t.Fatalf("PreToolUse = %+v, want the two existing groups plus ours", pre)
	}
	if pre[0].Matcher == nil || *pre[0].Matcher != "Bash" || len(pre[0].Hooks) != 1 ||
		pre[0].Hooks[0].Command != "/usr/local/bin/lint-bash" || pre[0].Hooks[0].Timeout != 5 {
		t.Errorf("unrelated Bash group changed: %+v", pre[0])
	}
	if len(pre[1].Hooks) != 1 || pre[1].Hooks[0].Command != "/usr/local/bin/notify" {
		t.Errorf("shared group = %+v, want only the unrelated notify handler left in it", pre[1])
	}
	ours, _ := claudeCommands(pre)
	if len(ours) != 1 || ours[0] != claudeHookCommand(p, guardKind) {
		t.Errorf("PreToolUse SolonGate handlers = %q, want only the current guard command", ours)
	}

	for _, ev := range []string{"PostToolUse", "Stop"} {
		if ours, foreign := claudeCommands(hooks[ev]); len(ours) != 1 || len(foreign) != 0 {
			t.Errorf("%s = %+v, want exactly one SolonGate handler", ev, hooks[ev])
		}
	}

	if _, foreign := claudeCommands(hooks["Notification"]); len(foreign) != 1 || foreign[0] != "say done && echo <ok>" {
		t.Errorf("Notification = %+v, want the unrelated handler kept verbatim", hooks["Notification"])
	}
	if !strings.Contains(string(reg.content), `"model": "opus"`) {
		t.Errorf("unrelated top-level key lost: %s", reg.content)
	}
}

func TestPlanClaudeIsIdempotent(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SettingsPath, []byte(foreignClaudeSettings), 0o644); err != nil {
		t.Fatal(err)
	}

	first, err := planClaude(p)
	if err != nil {
		t.Fatalf("planClaude() error: %v", err)
	}
	if err := first.commit(); err != nil {
		t.Fatal(err)
	}
	second, err := planClaude(p)
	if err != nil {
		t.Fatalf("second planClaude() error: %v", err)
	}
	if string(second.content) != string(first.content) {
		t.Errorf("reinstalling changed settings.json:\nfirst:  %s\nsecond: %s", first.content, second.content)
	}
}

func TestRemoveClaudeRegistrationKeepsUnrelatedHooks(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SettingsPath, []byte(foreignClaudeSettings), 0o644); err != nil {
		t.Fatal(err)
	}
	reg, err := planClaude(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := reg.commit(); err != nil {
		t.Fatal(err)
	}

	if err := removeClaudeRegistration(p); err != nil {
		t.Fatalf("removeClaudeRegistration() error: %v", err)
	}
	b, err := os.ReadFile(p.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), ".solongate") {
		t.Errorf("a SolonGate handler survived removal: %s", b)
	}
	hooks := readClaudeHooks(t, b)
	for _, ev := range []string{"PostToolUse", "Stop"} {
		if _, ok := hooks[ev]; ok {
			t.Errorf("%s should be gone once its only handler was ours: %s", ev, b)
		}
	}
	if _, foreign := claudeCommands(hooks["PreToolUse"]); len(foreign) != 2 {
		t.Errorf("PreToolUse = %+v, want both unrelated handlers kept", hooks["PreToolUse"])
	}
	if _, foreign := claudeCommands(hooks["Notification"]); len(foreign) != 1 {
		t.Errorf("Notification = %+v, want the unrelated handler kept", hooks["Notification"])
	}
	if !strings.Contains(string(b), `"model": "opus"`) {
		t.Errorf("unrelated top-level key lost: %s", b)
	}
}

func TestRemoveClaudeRegistrationLeavesForeignOnlySettingsUntouched(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/local/bin/lint-bash"}]}]}}`
	if err := os.WriteFile(p.SettingsPath, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeClaudeRegistration(p); err != nil {
		t.Fatalf("removeClaudeRegistration() error: %v", err)
	}
	b, err := os.ReadFile(p.SettingsPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != body {
		t.Errorf("settings with no SolonGate hooks were rewritten:\ngot:  %s\nwant: %s", b, body)
	}
}

func TestClaudeGuardInstalled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if ClaudeGuardInstalled() {
		t.Error("ClaudeGuardInstalled() = true with no settings file")
	}

	claudeDir := filepath.Join(home, ".claude")
	if err := os.MkdirAll(claudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	settingsPath := filepath.Join(claudeDir, "settings.json")

	if err := os.WriteFile(settingsPath, []byte(`{"hooks":null}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if ClaudeGuardInstalled() {
		t.Error("ClaudeGuardInstalled() = true with null hooks")
	}

	if err := os.WriteFile(settingsPath, []byte(`{"hooks":{"PreToolUse":[{"hooks":[{"command":"/bin/sh ~/.solongate/hooks/sg-run.sh guard"}]}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if !ClaudeGuardInstalled() {
		t.Error("ClaudeGuardInstalled() = false with a .solongate hook command present")
	}
}

func TestClaudeRegisteredCommand(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if got := claudeRegisteredCommand(p); got != "" {
		t.Errorf("claudeRegisteredCommand() with no file = %q, want empty", got)
	}

	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	want := `/bin/sh "/home/u/.solongate/hooks/sg-run.sh" guard claude-code "Claude Code"`
	settings := struct {
		Hooks map[string][]hookGroup `json:"hooks"`
	}{
		Hooks: map[string][]hookGroup{
			"PreToolUse": {{Hooks: []hookHandler{{Type: "command", Command: want}}}},
		},
	}
	body, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.SettingsPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := claudeRegisteredCommand(p); got != want {
		t.Errorf("claudeRegisteredCommand() = %q, want %q", got, want)
	}
}

func TestAntigravityHookCommandsReferenceTheirKind(t *testing.T) {
	p := clientTestPaths(t.TempDir())

	cases := []struct {
		name string
		got  string
		kind string
	}{
		{"guard", antigravityHookCommand(p), guardKind},
		{"audit", antigravityAuditCommand(p), auditKind},
		{"tokens", antigravityTokensCommand(p), tokensKind},
	}
	for _, tc := range cases {
		if !strings.Contains(tc.got, tc.kind) {
			t.Errorf("%s command %q does not reference kind %q", tc.name, tc.got, tc.kind)
		}
		if !strings.Contains(tc.got, "antigravity") || !strings.Contains(tc.got, "Antigravity") {
			t.Errorf("%s command %q does not reference the antigravity client", tc.name, tc.got)
		}
	}
}

func TestPlanAntigravityFresh(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	reg, err := planAntigravity(p)
	if err != nil {
		t.Fatalf("planAntigravity() error: %v", err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(reg.content, &decoded); err != nil {
		t.Fatalf("content is not valid JSON: %v", err)
	}
	groupRaw, ok := decoded[antigravityGroup]
	if !ok {
		t.Fatalf("content has no %q key: %s", antigravityGroup, reg.content)
	}
	var group map[string][]hookGroup
	if err := json.Unmarshal(groupRaw, &group); err != nil {
		t.Fatalf("group is not the expected shape: %v", err)
	}
	for _, ev := range []string{"PreToolUse", "PostToolUse", "Stop"} {
		if len(group[ev]) == 0 {
			t.Errorf("group[%q] is empty", ev)
		}
	}
}

func TestRemoveAntigravityRegistration(t *testing.T) {
	p := clientTestPaths(t.TempDir())

	if err := removeAntigravityRegistration(p); err != nil {
		t.Errorf("removeAntigravityRegistration() with no file: %v, want nil", err)
	}

	if err := os.MkdirAll(p.AntigravityDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.AntigravityHooksPath, []byte(`{"other":1}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeAntigravityRegistration(p); err != nil {
		t.Fatalf("removeAntigravityRegistration() on a file without our group: %v", err)
	}

	reg, err := planAntigravity(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.AntigravityHooksPath, reg.content, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := removeAntigravityRegistration(p); err != nil {
		t.Fatalf("removeAntigravityRegistration() error: %v", err)
	}
	b, err := os.ReadFile(p.AntigravityHooksPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), antigravityGroup) {
		t.Errorf("antigravity group still present after removal: %s", b)
	}
}

func TestAntigravityRegisteredCommand(t *testing.T) {
	p := clientTestPaths(t.TempDir())
	if got := antigravityRegisteredCommand(p); got != "" {
		t.Errorf("antigravityRegisteredCommand() with no file = %q, want empty", got)
	}

	if err := os.MkdirAll(p.AntigravityDir, 0o755); err != nil {
		t.Fatal(err)
	}
	reg, err := planAntigravity(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.AntigravityHooksPath, reg.content, 0o644); err != nil {
		t.Fatal(err)
	}
	got := antigravityRegisteredCommand(p)
	if !strings.Contains(got, ".solongate") {
		t.Errorf("antigravityRegisteredCommand() = %q, want a command referencing .solongate", got)
	}
}

func TestInstallAndRemoveOpencodePlugin(t *testing.T) {
	p := clientTestPaths(t.TempDir())

	if err := installOpencodePlugin(p, []byte("plugin body")); err != nil {
		t.Fatalf("installOpencodePlugin() error: %v", err)
	}
	b, err := os.ReadFile(p.OpencodePluginPath)
	if err != nil {
		t.Fatalf("reading installed plugin: %v", err)
	}
	if string(b) != "plugin body" {
		t.Errorf("plugin content = %q, want %q", b, "plugin body")
	}

	if err := removeOpencodePlugin(p); err != nil {
		t.Fatalf("removeOpencodePlugin() error: %v", err)
	}
	if Exists(p.OpencodePluginPath) {
		t.Error("plugin still exists after removeOpencodePlugin()")
	}

	if err := removeOpencodePlugin(p); err != nil {
		t.Errorf("removeOpencodePlugin() on an already-removed plugin: %v, want nil", err)
	}
}

func TestOpencodeGuardInstalledAndDetected(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")

	if OpencodeGuardInstalled() {
		t.Error("OpencodeGuardInstalled() = true before anything is installed")
	}
	if OpencodeDetected() {
		t.Error("OpencodeDetected() = true before the opencode dir exists")
	}

	p := GlobalPaths()
	if err := os.MkdirAll(p.OpencodePluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.OpencodePluginPath, []byte("export const x = tool.execute.before;"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !OpencodeGuardInstalled() {
		t.Error("OpencodeGuardInstalled() = false after writing a plugin that hooks tool.execute.before")
	}
	if !OpencodeDetected() {
		t.Error("OpencodeDetected() = false after the opencode dir was created")
	}
}