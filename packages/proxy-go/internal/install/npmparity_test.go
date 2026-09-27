package install

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// The registration this package writes has to be the one the npm package writes.
//
// Both implementations stay installed on the same machines, and they identify
// each other's entries by shape: the `hooks` key, a named Antigravity group, a
// Codex command pointing into ~/.solongate. If the two disagreed about the
// content of an entry, a machine with both would end up with each install
// rewriting the other's file forever — and, worse, one of them could fail to
// recognise the other's registration and leave a second, stale one behind.
//
// So this test does not assert against a fixture someone typed out. It runs the
// REAL npm installer (packages/proxy/dist/global-install.js) into one throwaway
// home, runs this one into another seeded identically, and compares the files.
// It skips when the npm package is not built next to this module, because the
// Go build must not require a Node toolchain.
func TestRegistrationsMatchTheNpmPackage(t *testing.T) {
	dist := npmGlobalInstall(t)
	if dist == "" {
		t.Skip("packages/proxy/dist/global-install.js is not built; nothing to compare against")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH")
	}

	root := t.TempDir()
	tsHome := filepath.Join(root, "ts")
	goHome := filepath.Join(root, "go")
	seedClientConfigs(t, tsHome)
	seedClientConfigs(t, goHome)

	// A URL nothing answers on: both installers warm the policy cache by spawning
	// the guard, and neither test run should reach the real API to do it.
	env := []string{
		"SOLONGATE_API_KEY=sg_live_0123456789abcdef",
		"SOLONGATE_API_URL=http://127.0.0.1:1",
		"SOLONGATE_NO_OS_LOCK=1",
	}

	cmd := exec.Command(node, "--input-type=module", "-e",
		"const m = await import('file://"+dist+"'); const r = m.installGlobalQuiet(); if (!r.ok) { console.error(r.message); process.exit(1); }")
	cmd.Env = append(append(os.Environ(), env...), "HOME="+tsHome)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the npm installer did not run: %v\n%s", err, out)
	}

	for _, kv := range env {
		k, v, _ := splitEnv(kv)
		t.Setenv(k, v)
	}
	t.Setenv("HOME", goHome)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	if r := Install(); !r.OK {
		t.Fatalf("install: %s", r.Message)
	}

	// Every file whose CONTENT is a contract with a client, plus the backups,
	// which are the record of what the machine looked like before either
	// implementation touched it.
	for _, rel := range []string{
		filepath.Join(".claude", "settings.json"),
		filepath.Join(".claude", "settings.solongate.bak"),
		filepath.Join(".gemini", "config", "hooks.json"),
		filepath.Join(".gemini", "config", "hooks.solongate.bak"),
		filepath.Join(".codex", "hooks.json"),
		filepath.Join(".codex", "hooks.solongate.bak"),
		filepath.Join(".config", "opencode", "plugins", "solongate.js"),
		filepath.Join(".solongate", "hooks", GuardHookName),
		filepath.Join(".solongate", "hooks", auditHookName),
		filepath.Join(".solongate", "hooks", stopHookName),
		filepath.Join(".solongate", "hooks", conversationHookName),
		filepath.Join(".solongate", "hooks", shieldHookName),
		// The launcher. Every hook command in every file above runs through it,
		// so a byte of difference between the two implementations is one of them
		// rewriting the other's on every install — and the two node search orders
		// silently diverging after that.
		filepath.Join(".solongate", "hooks", LauncherName),
	} {
		want, err := os.ReadFile(filepath.Join(tsHome, rel))
		if err != nil {
			t.Fatalf("the npm installer wrote no %s: %v", rel, err)
		}
		got, err := os.ReadFile(filepath.Join(goHome, rel))
		if err != nil {
			t.Fatalf("%s was not written: %v", rel, err)
		}
		// The two installs ran in different home directories, and every
		// registration names absolute paths under one of them. That difference is
		// the test setup, not a divergence.
		want = bytes.ReplaceAll(want, []byte(tsHome), []byte("$HOME"))
		got = bytes.ReplaceAll(got, []byte(goHome), []byte("$HOME"))
		if string(got) != string(want) {
			t.Errorf("%s differs from what the npm package writes:\n--- npm ---\n%s\n--- go ---\n%s",
				rel, clip(want), clip(got))
		}
	}

	// cloud-guard.json is compared by VALUE, not by bytes: this side writes it
	// through config.SetActiveAccount, which merges into the existing file rather
	// than replacing it, so a key written by a newer version is not dropped by an
	// install. Both must name the same account and the same API.
	tsCred := readCredential(t, filepath.Join(tsHome, ".solongate", "cloud-guard.json"))
	goCred := readCredential(t, filepath.Join(goHome, ".solongate", "cloud-guard.json"))
	if tsCred["apiKey"] != goCred["apiKey"] || tsCred["apiUrl"] != goCred["apiUrl"] {
		t.Errorf("credential differs: npm %v, go %v", tsCred, goCred)
	}
}

// seedClientConfigs writes the state a real machine is in before an install:
// settings that already carry unrelated keys (and a hooks key from an older
// install), another tool's Antigravity group, and a Codex file with a user hook,
// an unknown top-level key, AND a stray top-level event — the shape Codex itself
// would refuse to load.
func seedClientConfigs(t *testing.T, home string) {
	t.Helper()
	write := func(rel, body string) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(filepath.Join(".claude", "settings.json"), `{
  "model": "opus",
  "hooks": {
    "PreToolUse": [{"matcher":"","hooks":[{"type":"command","command":"an older install"}]}]
  },
  "env": { "URL": "https://example.test/?a=1&b=2<3>" }
}
`)
	write(filepath.Join(".gemini", "config", "hooks.json"), `{
  "someone-elses-group": { "PreToolUse": [{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}] }
}
`)
	write(filepath.Join(".codex", "hooks.json"), `{
  "description": "my hooks",
  "PostToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"echo top-level"}]}],
  "hooks": {
    "PreToolUse": [{"matcher":"*","hooks":[{"type":"command","command":"echo user"}]}],
    "SessionStart": [{"hooks":[{"type":"command","command":"echo start"}]}]
  },
  "extra": {"keep": true}
}
`)
	// OpenCode's config dir exists on a machine that has ever run it; the plugin
	// folder is the installer's to create.
	if err := os.MkdirAll(filepath.Join(home, ".config", "opencode"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func npmGlobalInstall(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 8; i++ {
		p := filepath.Join(dir, "packages", "proxy", "dist", "global-install.js")
		if Exists(p) {
			return p
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

func readCredential(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no credential at %s: %v", path, err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("credential at %s is not JSON: %v", path, err)
	}
	return m
}

func splitEnv(kv string) (string, string, bool) {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i], kv[i+1:], true
		}
	}
	return kv, "", false
}

// clip keeps a failure readable: the guard bundle is 300 KB and printing it
// would bury the one line that differs.
func clip(b []byte) string {
	const max = 2000
	if len(b) <= max {
		return string(b)
	}
	return string(b[:max]) + "\n… (" + itoa(len(b)-max) + " more bytes)"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for n > 0 {
		d = append([]byte{byte('0' + n%10)}, d...)
		n /= 10
	}
	return string(d)
}
