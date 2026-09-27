package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Ghost rewrites a listing so hidden entries are filtered out of its own output.
// It used to EMIT that rewrite, which ends the process — so the DLP argument
// scan, the rate limit and the POLICY never ran for any call ghost touched.
//
// Under a whitelist that was a hole with a wide mouth: `ls` in a project with a
// ghost route was allowed whatever the policy said, because ghost answered
// first. Measured live on Codex, against a whitelist that allowed only `git *`
// and one directory.
//
// The rewrite is held to the end now. This drives the built binary rather than
// the functions, because what is being checked is the ORDER of the layers and
// which one gets to end the process.
func TestGhostRewriteDoesNotDecideTheCall(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "guard")
	build := exec.Command("go", "build", "-o", bin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("cannot build the guard here: %v\n%s", err, out)
	}

	// A whitelist with one ALLOW that this call does not match: without the
	// policy running, the call is allowed; with it, the default deny stands.
	policy := map[string]any{
		"id": "p", "name": "P", "mode": "whitelist",
		"rules": []any{map[string]any{
			"id": "allow-git", "toolPattern": "*", "effect": "ALLOW", "priority": 1, "enabled": true,
			"commandConstraints": map[string]any{"allowed": []any{"git *"}},
		}},
	}
	security := map[string]any{"ghost": map[string]any{"patterns": []any{"*payroll.csv"}}}

	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	cache, _ := json.Marshal(map[string]any{
		"_ts": nowMillisForTest(), "policy": policy, "selfProtect": false, "security": security,
	})
	name := ".policy" + "-cache-" + "claude-code" + ".json"
	if err := os.WriteFile(filepath.Join(home, ".solongate", name), cache, 0o644); err != nil {
		t.Fatal(err)
	}

	run := func(command string) int {
		payload, _ := json.Marshal(map[string]any{
			"tool_name": "Bash", "tool_input": map[string]any{"command": command},
			"session_id": "t", "tool_use_id": "t1", "cwd": home,
		})
		cmd := exec.Command(bin, "claude-code", "Claude")
		cmd.Stdin = strings.NewReader(string(payload))
		// A key has to be present or the guard allows everything and this test
		// passes for the wrong reason: without one there is no project to enforce
		// against, which is the documented behaviour. The cache below is fresh
		// enough that nothing is ever fetched with it.
		cmd.Env = append(os.Environ(), "HOME="+home, "SOLONGATE_AGENT_ID=claude-code",
			"SOLONGATE_API_KEY=sg_test_"+strings.Repeat("a", 32))
		_ = cmd.Run()
		return cmd.ProcessState.ExitCode()
	}

	// `ls -la` is what ghost rewrites, and nothing in the whitelist allows it.
	if code := run("ls -la"); code != 2 {
		t.Errorf("a listing ghost rewrites was allowed past the policy: exit %d, want 2", code)
	}
	// The control: the same policy, a command it does allow.
	if code := run("git status --short"); code != 0 {
		t.Errorf("an allowed command was blocked: exit %d, want 0", code)
	}
}

func nowMillisForTest() int64 { return 1 << 42 }
