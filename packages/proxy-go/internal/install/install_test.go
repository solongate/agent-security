package install

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// sandbox points every path this package resolves at a throwaway home, and
// leaves the working directory somewhere with no npm package above it — which is
// also how a test asks for "this build cannot find its hook sources".
func sandbox(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("SOLONGATE_API_KEY", "")
	// Nothing answers here, so the policy warm-up fails instantly instead of
	// reaching the real API from a test.
	t.Setenv("SOLONGATE_API_URL", "http://127.0.0.1:1")
	t.Setenv("SOLONGATE_NO_OS_LOCK", "1")
	t.Setenv("SOLONGATE_HOOKS_DIR", "")

	// UNPIN THE WHOLE TREE BEFORE t.TempDir() TRIES TO REMOVE IT.
	//
	// On Linux the install's lock is `chattr +i`, and where that takes — a
	// privileged container, and a GitHub runner — an immutable file cannot be
	// unlinked by anyone, so TempDir's cleanup fails with
	// "unlinkat …/.solongate: directory not empty" and the test reports a
	// failure that has nothing to do with what it was testing.
	//
	// UnlockProtected would seem to be the answer and is not: it walks
	// protectedTargets(), a fixed list, and a list is exactly the thing that
	// goes stale the next time the installer writes one more file. So this
	// clears the bit on everything under the sandbox instead. Best effort by
	// design — on a machine where chattr never took there is nothing to clear,
	// and the errors from that are noise.
	//
	// Registered AFTER TempDir, which means it runs BEFORE it: t.Cleanup is
	// LIFO.
	t.Cleanup(func() { unpinTree(home) })
	return home
}

// unpinTree clears the OS-level lock from every file under root.
func unpinTree(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// A directory this cannot read is one it cannot unpin either, and
			// stopping here would leave the rest pinned.
			return nil
		}
		switch runtime.GOOS {
		case "darwin":
			_ = exec.Command("chflags", "nouchg", path).Run()
		case "windows":
			// The lock is an ACL there and the temp directory is the test
			// framework's business; nothing to do.
		default:
			_ = exec.Command("chattr", "-i", path).Run()
		}
		if !info.IsDir() {
			_ = os.Chmod(path, 0o644)
		}
		return nil
	})
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(b)
}

func haveHookSources(t *testing.T) {
	t.Helper()
	if _, ok := hookSourceDir(); !ok {
		t.Skip("the npm package's hooks folder is not next to this module")
	}
}

// An install that cannot finish must leave the machine in the state it was
// already in. Half-registered is worse than not installed: a settings file
// naming hooks that are not there makes a client fail on every tool call, and
// nothing would say why.
func TestAFailedInstallChangesNothing(t *testing.T) {
	home := sandbox(t)
	t.Setenv("SOLONGATE_API_KEY", "sg_live_0123456789abcdef")
	// No npm package above the working directory, so there are no hook sources
	// and no hooks already installed to fall back on.
	t.Chdir(t.TempDir())

	settings := filepath.Join(home, ".claude", "settings.json")
	const before = "{\n  \"model\": \"opus\"\n}\n"
	writeFile(t, settings, before)

	r := Install()
	if r.OK {
		t.Fatal("an install with no guard to install must not report success")
	}
	if !strings.Contains(r.Message, "npx @solongate/proxy repair") {
		t.Errorf("the failure has to point at the implementation that still works: %q", r.Message)
	}
	if got := readFile(t, settings); got != before {
		t.Errorf("the settings file was rewritten by a failed install:\n%s", got)
	}
	if Exists(filepath.Join(home, ".solongate", "hooks")) {
		t.Error("a hooks directory was created by an install that could not install any")
	}
	if Exists(filepath.Join(home, ".gemini")) || Exists(filepath.Join(home, ".codex")) {
		t.Error("another client's config directory was created by a failed install")
	}
}

// No credential is not a fault, and it must not half-arm the machine either.
func TestInstallWithoutALoginChangesNothing(t *testing.T) {
	home := sandbox(t)
	haveHookSources(t)

	r := Install()
	if r.OK || r.Message != ErrNoLogin.Error() {
		t.Fatalf("expected the no-login refusal, got %+v", r)
	}
	if Exists(filepath.Join(home, ".claude", "settings.json")) {
		t.Error("a settings file was written for a device with no account")
	}
	if Exists(filepath.Join(home, ".solongate", "hooks", GuardHookName)) {
		t.Error("a guard was installed for a device with no account")
	}
}

// The commonest repair is a deleted REGISTRATION with the hooks still on disk.
// A build with no packaged hooks can still fix that, and refusing to would leave
// a machine unguarded to protect a rule about where files came from — but it has
// to say that it did not replace the hook programs themselves.
func TestRepairReRegistersWhenOnlyTheRegistrationIsGone(t *testing.T) {
	home := sandbox(t)
	t.Chdir(t.TempDir()) // no packaged hooks to install
	hooks := filepath.Join(home, ".solongate", "hooks")
	const guardBody = "const HOOK_VERSION = 31;\n"
	writeFile(t, filepath.Join(hooks, GuardHookName), guardBody)
	writeFile(t, filepath.Join(hooks, auditHookName), "// audit\n")
	writeFile(t, filepath.Join(hooks, stopHookName), "// stop\n")
	writeFile(t, filepath.Join(home, ".solongate", "cloud-guard.json"),
		`{"apiKey":"sg_live_0123456789abcdef","apiUrl":"http://127.0.0.1:1"}`)

	rep := Repair()
	if !rep.OK {
		t.Fatalf("repair: %s", rep.Message)
	}
	if !ClaudeGuardInstalled() {
		t.Error("the guard was not registered for Claude Code")
	}
	if !CodexGuardInstalled() {
		t.Error("the guard was not registered for Codex")
	}
	if got := readFile(t, filepath.Join(hooks, GuardHookName)); got != guardBody {
		t.Errorf("the guard file was rewritten from nothing: %q", got)
	}
	var said bool
	for _, n := range rep.Notes {
		if strings.Contains(n, "NOT rewritten") {
			said = true
		}
	}
	if !said {
		t.Errorf("a repair that could not replace the hook programs has to say so: %v", rep.Notes)
	}
	// The report reads the files back rather than trusting the install, so the
	// before/after listing cannot claim something the disk does not show.
	if rep.Before[2].OK {
		t.Error("the before listing should have shown Claude Code as unregistered")
	}
	if !rep.After[1].OK {
		t.Error("the after listing should have shown Claude Code as registered")
	}
}

// Uninstall removes OUR entries. Everything else in those files belongs to
// someone: another tool's hook group, the user's own Codex hook, the rest of
// their Claude settings.
func TestUninstallTakesOnlyOurRegistrations(t *testing.T) {
	home := sandbox(t)
	haveHookSources(t)
	t.Setenv("SOLONGATE_API_KEY", "sg_live_0123456789abcdef")

	writeFile(t, filepath.Join(home, ".claude", "settings.json"), `{"model":"opus"}`)
	writeFile(t, filepath.Join(home, ".gemini", "config", "hooks.json"),
		`{"someone-elses-group":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo hi"}]}]}}`)
	writeFile(t, filepath.Join(home, ".codex", "hooks.json"),
		`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"echo user"}]}]}}`)

	if r := Install(); !r.OK {
		t.Fatalf("install: %s", r.Message)
	}
	if !ClaudeGuardInstalled() || !CodexGuardInstalled() || !OpencodeGuardInstalled() {
		t.Fatal("the install did not register the guard everywhere")
	}

	if r := Uninstall(); !r.OK {
		t.Fatalf("uninstall: %s", r.Message)
	}

	settings := readFile(t, filepath.Join(home, ".claude", "settings.json"))
	if strings.Contains(settings, "hooks") {
		t.Errorf("the Claude registration survived the uninstall:\n%s", settings)
	}
	if !strings.Contains(settings, `"model": "opus"`) {
		t.Errorf("the uninstall took the user's own settings with it:\n%s", settings)
	}

	agy := readFile(t, filepath.Join(home, ".gemini", "config", "hooks.json"))
	if strings.Contains(agy, antigravityGroup) {
		t.Errorf("our Antigravity group survived the uninstall:\n%s", agy)
	}
	if !strings.Contains(agy, "someone-elses-group") {
		t.Errorf("the uninstall took another tool's hook group with it:\n%s", agy)
	}

	codex := readFile(t, filepath.Join(home, ".codex", "hooks.json"))
	if strings.Contains(codex, ".solongate") {
		t.Errorf("our Codex entry survived the uninstall:\n%s", codex)
	}
	if !strings.Contains(codex, "echo user") {
		t.Errorf("the uninstall took the user's own Codex hook with it:\n%s", codex)
	}

	if Exists(GlobalPaths().OpencodePluginPath) {
		t.Error("the OpenCode plugin survived the uninstall — the file IS the registration")
	}
	// The hooks and the credential stay. Removing the guard from the clients is
	// not the same request as logging the device out.
	if !Exists(GlobalPaths().GuardPath()) {
		t.Error("the uninstall deleted the hook files")
	}
	if !Exists(GlobalPaths().ConfigPath) {
		t.Error("the uninstall deleted the account credential")
	}
}

// Re-registering has to be idempotent: two installs in a row must leave one
// entry per client, or a machine that runs both implementations accumulates them.
func TestASecondInstallDoesNotDuplicateAnything(t *testing.T) {
	home := sandbox(t)
	haveHookSources(t)
	t.Setenv("SOLONGATE_API_KEY", "sg_live_0123456789abcdef")

	if r := Install(); !r.OK {
		t.Fatalf("first install: %s", r.Message)
	}
	first := readFile(t, filepath.Join(home, ".codex", "hooks.json"))
	if r := Install(); !r.OK {
		t.Fatalf("second install: %s", r.Message)
	}
	second := readFile(t, filepath.Join(home, ".codex", "hooks.json"))
	if first != second {
		t.Errorf("a repeated install changed the Codex file:\n--- first ---\n%s\n--- second ---\n%s", first, second)
	}
	// Counted by the status message rather than by ".solongate", which now
	// appears TWICE in every command: once for the launcher and once for the
	// hook it runs. One status message is one group of ours.
	if n := strings.Count(second, `"statusMessage": "SolonGate`); n != len(codexEvents) {
		t.Errorf("expected one entry per Codex event (%d), got %d:\n%s", len(codexEvents), n, second)
	}
}

// The one-time backup is the record of what the machine looked like before
// SolonGate touched it. A second install must not overwrite it with a copy of
// our own registration.
func TestTheBackupIsTakenOnceAndKeepsThePreInstallFile(t *testing.T) {
	home := sandbox(t)
	haveHookSources(t)
	t.Setenv("SOLONGATE_API_KEY", "sg_live_0123456789abcdef")

	const original = `{"model":"opus"}`
	writeFile(t, filepath.Join(home, ".claude", "settings.json"), original)

	for i := 0; i < 2; i++ {
		if r := Install(); !r.OK {
			t.Fatalf("install %d: %s", i, r.Message)
		}
	}
	if got := readFile(t, filepath.Join(home, ".claude", "settings.solongate.bak")); got != original {
		t.Errorf("the backup is no longer the pre-install file: %q", got)
	}
}

// A Codex file with a top-level event key is one Codex itself would refuse to
// load — deny_unknown_fields makes it drop every hook in the file, ours
// included. The installer folds those keys into `hooks` rather than leaving a
// registration that cannot run.
func TestCodexTopLevelEventsAreFoldedIn(t *testing.T) {
	home := sandbox(t)
	haveHookSources(t)
	t.Setenv("SOLONGATE_API_KEY", "sg_live_0123456789abcdef")
	writeFile(t, filepath.Join(home, ".codex", "hooks.json"),
		`{"PreToolUse":[{"hooks":[{"type":"command","command":"echo user"}]}],"extra":{"keep":true}}`)

	if r := Install(); !r.OK {
		t.Fatalf("install: %s", r.Message)
	}
	body := readFile(t, filepath.Join(home, ".codex", "hooks.json"))

	var file struct {
		Extra map[string]bool `json:"extra"`
		Hooks map[string][]struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		} `json:"hooks"`
		TopLevel json.RawMessage `json:"PreToolUse"`
	}
	if err := json.Unmarshal([]byte(body), &file); err != nil {
		t.Fatalf("the file no longer parses: %v\n%s", err, body)
	}
	if len(file.TopLevel) != 0 {
		t.Errorf("the stray top-level event was left where Codex would choke on it:\n%s", body)
	}
	if !file.Extra["keep"] {
		t.Errorf("an unknown top-level key was dropped:\n%s", body)
	}
	groups := file.Hooks["PreToolUse"]
	if len(groups) != 2 {
		t.Fatalf("expected the user's folded group plus ours, got %d:\n%s", len(groups), body)
	}
	if groups[0].Hooks[0].Command != "echo user" {
		t.Errorf("the user's hook lost its place in the order:\n%s", body)
	}
	if !strings.Contains(groups[1].Hooks[0].Command, ".solongate") {
		t.Errorf("our entry is not the last one:\n%s", body)
	}
}

// The sweep runs over the user's whole home directory on an explicit repair, so
// what it will and will not delete is the safety of the whole feature.
func TestTheSweepTakesOnlyOurOwnFiles(t *testing.T) {
	home := sandbox(t)

	ours := filepath.Join(home, "proj", ".solongate")
	writeFile(t, filepath.Join(ours, ".last-eval"), "{}")
	writeFile(t, filepath.Join(ours, ".eval-ring.jsonl"), "{}\n")

	shared := filepath.Join(home, "other", ".solongate")
	writeFile(t, filepath.Join(shared, ".last-deny"), "{}")
	writeFile(t, filepath.Join(shared, "notes.txt"), "someone else's file")

	// The real store has the same name and must never be a candidate.
	writeFile(t, filepath.Join(home, ".solongate", "cloud-guard.json"), "{}")

	if n := SweepStrayScratchDirs(home); n != 1 {
		t.Fatalf("expected exactly the emptied folder to be removed, got %d", n)
	}
	if Exists(ours) {
		t.Error("a folder holding only our own files was left behind")
	}
	if !Exists(filepath.Join(shared, "notes.txt")) {
		t.Error("a file that is not ours was deleted")
	}
	if Exists(filepath.Join(shared, ".last-deny")) {
		t.Error("our own file was left behind in a folder that could not be removed")
	}
	if !Exists(filepath.Join(home, ".solongate", "cloud-guard.json")) {
		t.Fatal("the sweep walked into the real store")
	}
}
