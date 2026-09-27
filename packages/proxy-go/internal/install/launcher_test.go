package install

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The launcher, tested the way it failed.
//
// A Mac reported that nothing was intercepted and no logs arrived, while every
// status this CLI printed said the guard was registered. It was. The command it
// was registered with named a node path that resolveNode had produced by
// calling filepath.EvalSymlinks on /opt/homebrew/bin/node — so what went into
// the config was /opt/homebrew/Cellar/node/<version>/bin/node, and `brew
// upgrade` deleted it.
//
// So every test here starts from a DEAD pinned path, which is the state the
// machine was actually in.

const deadPin = "/opt/homebrew/Cellar/node/22.0.0/bin/node"

func writeLauncher(t *testing.T, pin string) (home, launcher string) {
	t.Helper()
	home = t.TempDir()
	hooks := filepath.Join(home, ".solongate", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher = filepath.Join(hooks, LauncherName)
	if err := os.WriteFile(launcher, []byte(launcherScript(pin)), 0o755); err != nil {
		t.Fatal(err)
	}
	return home, launcher
}

// runLauncher gives it an environment with nothing in it but HOME and a PATH,
// which is closer to what a client hands a hook than the test process's own.
func runLauncher(t *testing.T, home, launcher string, args []string, extra ...string) (string, string, int) {
	t.Helper()
	cmd := exec.Command("/bin/sh", append([]string{launcher}, args...)...)
	cmd.Env = append([]string{"HOME=" + home, "PATH=/usr/bin:/bin"}, extra...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("could not run the launcher: %v", err)
	}
	return out.String(), errb.String(), code
}

func TestTheLauncherSurvivesADeadPinnedNode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows names node directly; there is no launcher there")
	}
	home, launcher := writeLauncher(t, deadPin)

	out, errOut, code := runLauncher(t, home, launcher, []string{"--sg-doctor"})
	node := strings.TrimSpace(out)
	if code != 0 || node == "" {
		t.Fatalf("resolved nothing after the pinned path was gone: code=%d stderr=%s", code, errOut)
	}
	if !Exists(node) {
		t.Errorf("named %q, which does not exist", node)
	}
}

func TestTheLauncherRunsAHookWithItsArgumentsIntact(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no launcher on Windows")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("no node to run a hook with")
	}
	home, launcher := writeLauncher(t, deadPin)

	probe := filepath.Join(home, ".solongate", "hooks", "probe.mjs")
	if err := os.WriteFile(probe, []byte("console.log(JSON.stringify(process.argv.slice(2)));\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := runLauncher(t, home, launcher, []string{probe, "claude-code", "Claude Code"})
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	// The label is two words. Quoted wrong it arrives as two arguments and every
	// audit row is attributed to a client called "Claude".
	if got := strings.TrimSpace(out); got != `["claude-code","Claude Code"]` {
		t.Errorf("arguments = %s, want the client name and a two-word label unsplit", got)
	}
}

// The beat is the only evidence that a CLIENT invoked the hook, as opposed to a
// config file saying it would.
func TestTheLauncherLeavesABeat(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no launcher on Windows")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("no node to run a hook with")
	}
	home, launcher := writeLauncher(t, deadPin)
	probe := filepath.Join(home, ".solongate", "hooks", "probe.mjs")
	if err := os.WriteFile(probe, []byte("\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, errOut, _ := runLauncher(t, home, launcher, []string{probe})

	// The beat directory does not exist on the first call, and a redirect into a
	// missing directory is reported by the SHELL rather than by the command — so
	// suppressing the command's stderr alone does not catch it. Claude Code
	// shows a hook's stderr to the person using it.
	if errOut != "" {
		t.Errorf("the first run wrote to stderr: %q", errOut)
	}

	beat := filepath.Join(home, ".solongate", BeatDirName, "probe.mjs")
	body, err := os.ReadFile(beat)
	if err != nil {
		t.Fatalf("no beat was left: %v", err)
	}
	if !strings.HasSuffix(strings.TrimSpace(string(body)), "node") {
		t.Errorf("beat = %q, want the node that ran the hook", strings.TrimSpace(string(body)))
	}
}

// With no node at all the guard must refuse and everything else must not.
//
// The launcher finds /usr/bin/node even with an empty PATH — that is the fix
// working, and it means this branch cannot be reached by emptying the
// environment. So it is reached directly: the shipped script with resolve_node
// forced to fail and every other line untouched.
func TestWithNoNodeTheGuardFailsClosedAndTheRestDoNot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no launcher on Windows")
	}
	home := t.TempDir()
	hooks := filepath.Join(home, ".solongate", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(hooks, LauncherName)
	broken := strings.Replace(launcherScript("/nope/node"), "resolve_node() {", "resolve_node() { return 1", 1)
	if err := os.WriteFile(launcher, []byte(broken), 0o755); err != nil {
		t.Fatal(err)
	}

	_, errOut, code := runLauncher(t, home, launcher, []string{filepath.Join(hooks, GuardHookName), "claude-code"})
	if code != 2 {
		t.Errorf("the guard exited %d, want 2 — it is fail-closed", code)
	}
	if !strings.Contains(errOut, "fail-closed") {
		t.Errorf("stderr = %q, want it to say why the call was refused", errOut)
	}

	_, _, code = runLauncher(t, home, launcher, []string{filepath.Join(hooks, auditHookName), "claude-code"})
	if code != 0 {
		t.Errorf("the audit hook exited %d, want 0 — a log that cannot be written must not block a tool call", code)
	}

	body, err := os.ReadFile(filepath.Join(home, ".solongate", BeatDirName, auditHookName))
	if err != nil || strings.TrimSpace(string(body)) != "no-node" {
		t.Errorf("beat = %q (err %v), want it to name node as the thing missing", string(body), err)
	}
}

// The launcher runs under `set -u`, and its candidate list mentions $NVM_DIR.
// Written as a bare $NVM_DIR that is an unbound variable on every machine
// WITHOUT nvm — most of them — and the script would abort before resolving
// anything, turning a fix for some Macs into a break for all of them.
func TestAnEmptyEnvironmentDoesNotAbortTheLauncher(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no launcher on Windows")
	}
	home, launcher := writeLauncher(t, deadPin)

	cmd := exec.Command("/bin/sh", launcher, "--sg-doctor")
	cmd.Env = []string{"HOME=" + home} // no PATH, no NVM_DIR, nothing
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("aborted with an empty environment: %v", err)
	}
	if strings.TrimSpace(string(out)) == "" {
		t.Error("resolved nothing with an empty environment")
	}
}

func TestSolongateNodeOverridesEverything(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no launcher on Windows")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("no node on PATH to point at")
	}
	home, launcher := writeLauncher(t, deadPin)

	out, _, _ := runLauncher(t, home, launcher, []string{"--sg-doctor"}, "SOLONGATE_NODE="+node)
	if got := strings.TrimSpace(out); got != node {
		t.Errorf("resolved %q, want the node it was told to use (%q)", got, node)
	}
}

// The registration has to name the launcher, not a node binary. This is the
// assertion that fails if somebody puts the absolute path back.
func TestHookCommandsGoThroughTheLauncher(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows names node directly, on purpose")
	}
	p := GlobalPaths()
	cmd := hookCommand(p, "/usr/bin/node", GuardHookName, "claude-code", "Claude Code")

	if !strings.Contains(cmd, LauncherName) {
		t.Errorf("command = %q, want it to run through the launcher", cmd)
	}
	if strings.Contains(cmd, "/usr/bin/node") {
		t.Errorf("command = %q, still names a node binary — that path is what goes stale", cmd)
	}
	if !strings.HasPrefix(cmd, "/bin/sh ") {
		t.Errorf("command = %q, want /bin/sh so the launcher needs no executable bit", cmd)
	}
}
