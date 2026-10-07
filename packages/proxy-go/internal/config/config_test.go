// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// The expected hashes come from running the hooks' own projectKey (the function
// in packages/proxy/hooks/audit.mjs, unchanged) over the same paths. They are
// pinned here rather than recomputed, because "both implementations run the
// same algorithm" is exactly the claim that has to be tested, and a test that
// re-derives the answer proves nothing about it.
func TestProjectKeyMatchesTheHooks(t *testing.T) {
	cases := map[string]string{
		"/home/me/proj":       "d8c3495e",
		"/":                   "2a0c975e",
		"":                    "811c9dc5",
		`C:\Users\me\proj`:    "2ba5a1a5",
		"/home/müşteri/proj":  "98d8e9fc",
		"/home/日本/x":          "c4141884",
		"/home/me/\U0001F600": "b4bb03b0",
	}
	for path, want := range cases {
		if got := ProjectKey(path); got != want {
			t.Errorf("ProjectKey(%q) = %s, the hooks say %s", path, got, want)
		}
	}
}

// packages/guard-go hashes bytes where the hooks hash UTF-16 units. This test
// exists to catch the day someone "aligns" the two by copying the byte version
// over: it would pass every ASCII case and quietly break every machine whose
// home directory is not ASCII.
func TestProjectKeyIsNotBytewise(t *testing.T) {
	var h uint32 = 0x811c9dc5
	const path = "/home/müşteri/proj"
	for i := 0; i < len(path); i++ {
		h ^= uint32(path[i])
		h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))
	}
	if got := ProjectKey(path); got == "1ec69c96" {
		t.Fatalf("ProjectKey has reverted to hashing bytes (%s); the hooks hash UTF-16 units", got)
	}
}

func TestAgentKeyMatchesTheHooks(t *testing.T) {
	cases := map[string]string{
		"claude-code":  "claude-code",
		"codex":        "codex",
		"":             "default",
		"a b/c":        "a_b_c",
		"anti.gravity": "anti_gravity",
		// One emoji is two UTF-16 units, so the hooks' per-unit replace writes
		// two underscores.
		"x\U0001F600": "x__",
	}
	for agent, want := range cases {
		if got := AgentKey(agent); got != want {
			t.Errorf("AgentKey(%q) = %q, want %q", agent, got, want)
		}
	}
}

// FIVE TESTS OF THE ACCOUNT LAYER STOOD HERE, and they were good tests of a thing
// this build does not have:
//
//	TestResolvePrecedence                      env, then the active-key file, then a
//	                                           .env — the order a key was resolved in
//	TestAPIURLOverrideDoesNotLeak              a --api-url must not be written to disk
//	TestViewOverrideNeverTouchesDisk           reading as one account while another
//	                                           enforces changes no file
//	TestListAccountsSeedsFromTheActiveKey      the enforcing account appears in the
//	                                           list even if only the active-key file
//	                                           holds it
//	TestSetActiveAccountPreservesUnknownFields a newer version's fields survive a
//	                                           write by an older one
//	TestClearActiveCredentialRemovesThePhantom signing out of the last account does
//	                                           not leave it re-seeding itself
//
// There is no Resolver, no accounts.json and no active account — see credentials.go
// for what the last callers of each were doing, and which of them was a bug. What
// still has a test is what still exists: IsRealKey, below.

// A key that will not work must not be treated as a key. The guard reads an
// unusable one as "no project selected", which means allow, so a placeholder
// left in a config file would silently disarm it.
func TestIsRealKey(t *testing.T) {
	real := []string{"sg_live_0123456789abcdef", "sg_test_ABCDEF0123456789ff"}
	fake := []string{
		"", "nope", "sg_live_", "sg_live_short",
		"sg_live_your_key_here_0000000000", "sg_live_placeholder000000000",
		"sg_live_example00000000000000", "sg_live_not-hex-at-all-here!!",
	}
	for _, k := range real {
		if !IsRealKey(k) {
			t.Errorf("IsRealKey(%q) = false, want true", k)
		}
	}
	for _, k := range fake {
		if IsRealKey(k) {
			t.Errorf("IsRealKey(%q) = true, want false", k)
		}
	}
}

// writePolicy puts a policy document on the machine the test is pretending to be —
// the same file the guard, the hooks and the CLI all read.
func writePolicy(t *testing.T, body string) {
	t.Helper()
	if err := os.MkdirAll(Dir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(Dir(), "policy.json"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// WHERE the local log goes, resolved the way the HOOKS resolve it.
//
// These used to seed a policy CACHE, because that is where a service's answer was
// kept. Nothing writes one, so every case fell through to "off, default folder" — and
// `off` is not cosmetic: Live SKIPS READING THE LOG when it is told off, so the guard
// wrote entries no viewer would ever show, on every machine.
//
// Enabled is now always true, and that is the honest answer rather than a
// simplification: both writers record unconditionally and the setting chooses only the
// folder. A `false` here used to mean "the entries go to the service instead"; with
// nowhere to send them it would mean "lose them".
func TestLocalLogsSetting(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	t.Run("no policy file: recording, in the default folder", func(t *testing.T) {
		s := LocalLogsSetting()
		if !s.Enabled {
			t.Error("recording is unconditional — a machine with no policy still keeps its log")
		}
		if s.File != DefaultLocalLogFile() {
			t.Errorf("file = %s, want the default", s.File)
		}
	})

	t.Run("a policy naming no folder uses the default", func(t *testing.T) {
		writePolicy(t, `{"security":{"localLogs":{"enabled":true,"path":"  "}}}`)
		s := LocalLogsSetting()
		if !s.Enabled || !s.UsableHere || s.File != DefaultLocalLogFile() {
			t.Errorf("got %+v", s)
		}
	})

	t.Run("a folder from another OS falls back rather than dropping", func(t *testing.T) {
		writePolicy(t, `{"security":{"localLogs":{"enabled":true,"path":"C:/logs/"}}}`)
		s := LocalLogsSetting()
		if s.UsableHere {
			t.Errorf("a Windows path should not be usable on this host: %+v", s)
		}
		if s.File != DefaultLocalLogFile() {
			t.Errorf("entries must still land somewhere: %+v", s)
		}
		if s.ConfiguredPath != "C:/logs/" {
			t.Errorf("the configured folder should be reported verbatim: %+v", s)
		}
	})

	t.Run("an existing folder is used", func(t *testing.T) {
		dir := t.TempDir()
		writePolicy(t, `{"security":{"localLogs":{"enabled":true,"path":"`+dir+`/"}}}`)
		s := LocalLogsSetting()
		want := filepath.Join(dir, "solongate-audit.jsonl")
		if !s.Enabled || !s.UsableHere || s.File != want {
			t.Errorf("got %+v, want file %s", s, want)
		}
	})

	// BOTH SPELLINGS. A policy document carrying `security` inside it is how one
	// exported from elsewhere arrives, and every other reader on this machine accepts
	// it — a viewer that did not would read a different folder than the hooks write to.
	t.Run("security inside the policy document is found", func(t *testing.T) {
		dir := t.TempDir()
		writePolicy(t, `{"id":"p1","name":"P","mode":"denylist","rules":[],`+
			`"security":{"localLogs":{"enabled":true,"path":"`+dir+`"}}}`)
		s := LocalLogsSetting()
		if want := filepath.Join(dir, "solongate-audit.jsonl"); s.File != want {
			t.Errorf("file = %s, want %s", s.File, want)
		}
	})

	// `enabled: false` NO LONGER TURNS RECORDING OFF, only the folder choice stands.
	// The writers ignore the flag, so a viewer that honoured it would refuse to read a
	// file that is being written.
	t.Run("enabled:false still reads the log", func(t *testing.T) {
		dir := t.TempDir()
		writePolicy(t, `{"security":{"localLogs":{"enabled":false,"path":"`+dir+`"}}}`)
		s := LocalLogsSetting()
		if !s.Enabled {
			t.Error("a viewer that refuses to read a file the guard writes shows nothing")
		}
		if want := filepath.Join(dir, "solongate-audit.jsonl"); s.File != want {
			t.Errorf("file = %s, want the folder the policy names (%s)", s.File, want)
		}
	})

	// An unreadable policy must not move the log. The guard falls back to the default
	// folder for the same file, so a viewer that did anything else would look in the
	// wrong place at exactly the moment somebody is debugging.
	t.Run("half a policy file reads the default folder", func(t *testing.T) {
		writePolicy(t, `{"security":{"localLogs":{`)
		s := LocalLogsSetting()
		if !s.Enabled || s.File != DefaultLocalLogFile() {
			t.Errorf("got %+v", s)
		}
	})
}

// TestLocalLogsSkipsCachesWithNoAnswer and TestPolicyCacheDistinguishesNullSecurity
// stood here. The first held a real hazard — an older agent's cache carrying no
// localLogs field must not out-vote a newer one that did — and the second held the
// line between `security: null` (an answer) and an absent field. Both were about a
// cache nothing writes; the null-versus-absent distinction that mattered lives on in
// internal/api's TestNullPolicyInAnEnvelopeKeepsTheLayers, against the file.

// TUI notifications default ON, so an absent field must not read as off.
func TestTUIConfigDefaults(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}

	if cfg := LoadTUIConfig(); !cfg.Notifications {
		t.Error("no file should mean notifications on")
	}
	if err := os.WriteFile(TUIConfigPath(), []byte(`{"accent":"cyan"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := LoadTUIConfig()
	if !cfg.Notifications {
		t.Error("an absent notifications field should mean on")
	}
	if cfg.Accent != "cyan" {
		t.Errorf("accent = %q", cfg.Accent)
	}
	if err := os.WriteFile(TUIConfigPath(), []byte(`{"notifications":false,"pollMs":500}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if cfg := LoadTUIConfig(); cfg.Notifications || cfg.PollMs != 500 {
		t.Errorf("explicit settings ignored: %+v", cfg)
	}
}

// writeCred and writeCache stood here: one seeded the active-key file for the
// resolution tests, the other a per-agent .policy-cache-<agent>.json. Neither file is
// written by anything now, and what a test seeds instead is the POLICY — writePolicy,
// above.

func chdir(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })
}
