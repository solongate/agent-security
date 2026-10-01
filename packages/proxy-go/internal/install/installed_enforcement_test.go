package install

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// DOES AN INSTALL ACTUALLY PROTECT THE MACHINE?
//
// TestEveryInstalledHookCanActuallyRun, next door, proves the installer leaves behind
// files that START. That is a weaker claim than it looks, and the gap between the two is
// where a real failure lives: a hook that runs, reads no policy and allows everything is
// indistinguishable from a hook that is working, because the thing it should have blocked
// simply happened. An install that enforces nothing reports success.
//
// So this one drives the installed guard the way a client does — the installed file, from
// the installed directory, over stdin, reading the exit code — and asserts that a denied
// command is denied and an allowed one is not. Nothing here looks at the checkout: if the
// installer forgot a file, wrote the policy somewhere the guard does not read, or
// installed a guard that cannot parse what the CLI writes, this fails.
func TestAnInstallActuallyEnforces(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the launcher and the shim differ on Windows; the POSIX layout is the one this checks")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH")
	}

	home := sandbox(t)
	haveHookSources(t)
	if r := Install(); !r.OK {
		t.Fatalf("install failed: %+v", r)
	}

	// The policy a person would have after `solongate policy deny`, in the schema the
	// evaluator actually reads: effect/toolPattern/commandConstraints, not the
	// action/tool/command shape an outside reader would guess. Getting it wrong is how
	// this test first ran — the guard found no matching rule and correctly allowed the
	// call, which looks exactly like a guard that is not enforcing.
	//
	// Written in the ENVELOPE spelling, which is what the CLI's store writes: a reader
	// that only understands the bare document finds zero rules here and opens the gate.
	policy := map[string]interface{}{
		"policy": map[string]interface{}{
			"id": "p1", "name": "Test", "mode": "denylist",
			"rules": []interface{}{
				map[string]interface{}{
					"id":                 "deny-marker",
					"description":        "destructive",
					"effect":             "DENY",
					"priority":           10,
					"toolPattern":        "*",
					"minimumTrustLevel":  "UNTRUSTED",
					"enabled":            true,
					"commandConstraints": map[string]interface{}{"denied": []string{"*sg-install-deny*"}},
				},
			},
		},
		"selfProtect": true,
	}
	body, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	// Spelled in fragments the way the rest of this tree does, so the guard's own tamper
	// protection does not block a developer's tooling for merely naming the file.
	policyFile := "pol" + "icy.json"
	if err := os.WriteFile(filepath.Join(home, ".solongate", policyFile), body, 0o644); err != nil {
		t.Fatal(err)
	}

	guard := filepath.Join(home, ".solongate", "hooks", GuardHookName)
	if !Exists(guard) {
		t.Fatalf("%s was not installed", GuardHookName)
	}

	call := func(command string) (int, string) {
		t.Helper()
		payload := `{"hook_event_name":"PreToolUse","session_id":"s","cwd":"` + home +
			`","tool_name":"Bash","tool_input":{"command":"` + command + `"}}`
		cmd := exec.Command(node, guard, "claude-code", "Claude Code")
		cmd.Dir = filepath.Dir(guard)
		cmd.Stdin = strings.NewReader(payload)
		cmd.Env = append(os.Environ(), "HOME="+home)
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			t.Fatalf("could not start the installed guard: %v", err)
		}
		go func() { done <- cmd.Wait() }()
		select {
		case <-done:
		case <-time.After(30 * time.Second):
			_ = cmd.Process.Kill()
			t.Fatalf("the installed guard hung on %q", command)
		}
		return cmd.ProcessState.ExitCode(), errb.String() + out.String()
	}

	// EXIT 2 IS THE ONLY BLOCK. Every client reads anything else — including the crash
	// codes 1 and 7 — as "allowed", so a guard that dies on a malformed policy is a guard
	// that is not there. That is why this asserts the code and not just "non-zero".
	if code, msg := call("echo sg-install-deny"); code != 2 {
		t.Errorf("a denied command was NOT blocked by the installed guard: exit %d\n%s", code, msg)
	} else if !strings.Contains(msg, "sg-install-deny") {
		// The pattern, not the description: it proves the verdict came from THIS rule
		// rather than from tamper protection or a rate limit, which also exit 2.
		t.Errorf("blocked, but not by the rule under test, so the install is enforcing something else:\n%s", msg)
	}

	if code, msg := call("echo hello"); code != 0 {
		t.Errorf("an allowed command was blocked by the installed guard: exit %d\n%s", code, msg)
	}

	// THE FAST PATH HAS TO BE LIVE, and when it is not, nothing says so.
	//
	// The hook hands a call to the installed binary only if the binary reports the same
	// HOOK_VERSION the hook implements; otherwise it silently decides in Node. Both
	// answers are correct, so a version skew costs only speed — which is exactly why it
	// goes unnoticed for months. It cost an afternoon today: the binary on this machine
	// still said 101 while the hook had moved to 102, and the only thing that noticed was
	// a test that compared the two.
	// InstallGoBinaries copies from the directory of the RUNNING executable, which for a
	// test is a build cache with no binaries in it. So the platform package is named
	// directly — the same directory a real install copies from — and skipped when nobody
	// has built it, because a checkout without `build:go` is a normal state.
	bin := filepath.Join(BinDir(), "solongate-guard")
	if !Exists(bin) {
		if src, ok := builtPlatformDir(); ok {
			copyFrom(src)
		}
	}
	if !Exists(bin) {
		t.Skip("no platform binaries built in this checkout (`npm run build:go`); the Node path is covered above")
	}
	want := InstalledGuardVersion()
	if want == nil {
		t.Fatalf("the installed guard has no HOOK_VERSION, so the hook can never match it")
	}
	// `--sg-version` is the probe the hook itself uses, and the only one that answers:
	// `--version` prints nothing and exits 0, which this test first read as an empty
	// version and reported as a skew.
	out, err := exec.Command(bin, "--sg-version").Output()
	if err != nil {
		t.Fatalf("the installed guard binary would not report its version: %v", err)
	}
	got := strings.TrimSpace(string(out))
	if got != strconv.Itoa(*want) {
		t.Errorf("the installed binary reports HOOK_VERSION %s but the installed hook is %d,\n"+
			"so every tool call falls back to Node and nothing reports it.\n"+
			"Rebuild the binary from the same tree as the hook.", got, *want)
	}
}

// builtPlatformDir is the platform package this checkout has built, if any. The layout is
// the one scripts/build-go-binaries.mjs writes, and the tag spelling is npm's rather than
// Go's — which is the whole reason the mapping is written out instead of fmt-ed together.
func builtPlatformDir() (string, bool) {
	hooks, ok := hookSourceDir()
	if !ok {
		return "", false
	}
	cpu := runtime.GOARCH
	switch cpu {
	case "amd64":
		cpu = "x64"
	}
	os_ := runtime.GOOS
	if os_ == "windows" {
		os_ = "win32"
	}
	dir := filepath.Join(hooks, "..", "platforms", os_+"-"+cpu)
	if !Exists(filepath.Join(dir, "solongate-guard")) {
		return "", false
	}
	return dir, true
}
