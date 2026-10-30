// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tamper

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

func TestUnderProtected(t *testing.T) {
	norm := []string{"/a/b", "/a/c/d"}
	cases := []struct {
		name, raw, want string
	}{
		{"empty raw", "", ""},
		{"blank raw", "   ", ""},
		{"exact match", "/a/b", "/a/b"},
		{"nested under a protected prefix", "/a/b/secret.txt", "/a/b"},
		{"a deeper protected prefix", "/a/c/d/e.txt", "/a/c/d"},
		{"a sibling is not a match", "/a/bb", ""},
		{"no match at all", "/x/y", ""},
		{"dot segments are cleaned before comparing", "/a/./b/../b/x", "/a/b"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := underProtected(c.raw, norm); got != c.want {
				t.Errorf("underProtected(%q)=%q, want %q", c.raw, got, c.want)
			}
		})
	}
}

func TestProtectedReason(t *testing.T) {
	if got := protectedReason("/a/b", "/a/b"); !strings.Contains(got, `"/a/b" cannot be read, written or deleted`) {
		t.Errorf("an exact-match reason is missing its shape: %q", got)
	}
	if strings.Contains(protectedReason("/a/b", "/a/b"), "is inside") {
		t.Errorf("an exact match should not claim to be nested: %q", protectedReason("/a/b", "/a/b"))
	}

	got := protectedReason("/a/b/secret.txt", "/a/b")
	if !strings.Contains(got, `"/a/b/secret.txt" is inside "/a/b"`) {
		t.Errorf("a nested reason is missing its shape: %q", got)
	}
}

func TestUserProtectedCheckWithNoProtectedPaths(t *testing.T) {
	args := map[string]interface{}{"file_path": "/anything"}
	if got := UserProtectedCheck("Read", args, nil, ""); got != "" {
		t.Errorf("a nil security gave %q, want empty", got)
	}
	if got := UserProtectedCheck("Read", args, &shared.Security{}, ""); got != "" {
		t.Errorf("no protected paths at all gave %q, want empty", got)
	}
	if got := UserProtectedCheck("Read", args, &shared.Security{ProtectedPaths: []string{"", "   "}}, ""); got != "" {
		t.Errorf("only blank protected paths gave %q, want empty", got)
	}
}

func TestUserProtectedCheckBlocksAnExactTargetPath(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "secret.env")
	sec := &shared.Security{ProtectedPaths: []string{protected}}

	got := UserProtectedCheck("Read", map[string]interface{}{"file_path": protected}, sec, "")
	if got == "" {
		t.Fatal("reading a protected path was allowed")
	}
	if !strings.Contains(got, protected) {
		t.Errorf("the refusal does not name the path: %q", got)
	}
}

func TestUserProtectedCheckBlocksAPathNestedUnderAProtectedDirectory(t *testing.T) {
	dir := t.TempDir()
	sec := &shared.Security{ProtectedPaths: []string{dir}}

	nested := filepath.Join(dir, "sub", "file.txt")
	got := UserProtectedCheck("Write", map[string]interface{}{"file_path": nested}, sec, "")
	if got == "" {
		t.Fatal("writing under a protected directory was allowed")
	}
	if !strings.Contains(got, "is inside") {
		t.Errorf("a nested hit should say so: %q", got)
	}
}

func TestUserProtectedCheckLetsUnrelatedPathsThrough(t *testing.T) {
	dir := t.TempDir()
	sec := &shared.Security{ProtectedPaths: []string{filepath.Join(dir, "protected")}}

	other := filepath.Join(dir, "other", "file.txt")
	if got := UserProtectedCheck("Read", map[string]interface{}{"file_path": other}, sec, ""); got != "" {
		t.Errorf("an unrelated path was refused: %q", got)
	}
}

func TestUserProtectedCheckCatchesPathsOutsideItsOwnKnownFields(t *testing.T) {
	// "target" is not one of tamper's own path fields, so this only
	// succeeds via the policy.ExtractPaths fallback.
	dir := t.TempDir()
	protected := filepath.Join(dir, "secret.env")
	sec := &shared.Security{ProtectedPaths: []string{protected}}

	got := UserProtectedCheck("SomeCustomTool", map[string]interface{}{"target": protected}, sec, "")
	if got == "" {
		t.Fatal("a protected path reached only through the generic path extractor was allowed")
	}
}

func TestUserProtectedCheckCatchesProtectedPathsInShellCommands(t *testing.T) {
	dir := t.TempDir()
	protected := filepath.Join(dir, "secret.env")
	sec := &shared.Security{ProtectedPaths: []string{protected}}

	cmd := "rm -rf " + protected
	got := UserProtectedCheck("Bash", map[string]interface{}{"command": cmd}, sec, "")
	if got == "" {
		t.Fatalf("a shell command removing a protected path was allowed: %s", cmd)
	}
}

func TestUserProtectedCheckExecCommandSubstringBranch(t *testing.T) {
	// A bare filename with no slash or leading dot is not extracted as a
	// path by either ExtractTargetPaths or policy.ExtractPaths, so this
	// only matches through the exec-command substring sweep.
	sec := &shared.Security{ProtectedPaths: []string{"secrets.env"}}

	got := UserProtectedCheck("Bash", map[string]interface{}{"command": "cat secrets.env"}, sec, "")
	if got == "" {
		t.Fatal("an exec command naming a protected basename was allowed")
	}
	if !strings.Contains(got, "secrets.env") {
		t.Errorf("the refusal does not name the protected path: %q", got)
	}

	// A non-exec tool must not trigger the command sweep at all.
	if got := UserProtectedCheck("SomeCustomTool", map[string]interface{}{"command": "cat secrets.env"}, sec, ""); got != "" {
		t.Errorf("a non-exec tool triggered the command sweep: %q", got)
	}
}

// Issue #187: protect stores absolute paths, and an agent naming the same
// file relative to its working directory used to get straight past them.
func TestUserProtectedCheckResolvesRelativePathsAgainstCwd(t *testing.T) {
	project := t.TempDir()
	protected := filepath.Join(project, "secrets.env")
	sec := &shared.Security{ProtectedPaths: []string{protected, filepath.Join(project, "vault")}}

	refused := []struct {
		name, tool, cwd string
		args            map[string]interface{}
	}{
		{"a bare relative file", "Read", project, map[string]interface{}{"file_path": "secrets.env"}},
		{"a dot-relative file", "Write", project, map[string]interface{}{"file_path": "./secrets.env"}},
		{"a file under a protected directory", "Edit", project, map[string]interface{}{"file_path": "vault/key.pem"}},
		{"a path climbing out of a subdirectory", "Read", filepath.Join(project, "src"), map[string]interface{}{"file_path": "../secrets.env"}},
		{"a field only the generic extractor knows", "SomeCustomTool", project, map[string]interface{}{"target": "./secrets.env"}},
		{"a relative path in a shell command", "Bash", project, map[string]interface{}{"command": "cat ./secrets.env"}},
		{"a relative directory in a shell command", "Bash", project, map[string]interface{}{"command": "rm -rf vault/"}},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			if got := UserProtectedCheck(c.tool, c.args, sec, c.cwd); got == "" {
				t.Errorf("%s %v from %s was allowed", c.tool, c.args, c.cwd)
			}
		})
	}

	allowed := []struct {
		name, cwd string
		args      map[string]interface{}
	}{
		{"an unrelated relative file", project, map[string]interface{}{"file_path": "main.go"}},
		{"the same name somewhere else", t.TempDir(), map[string]interface{}{"file_path": "secrets.env"}},
		{"a sibling sharing a prefix", project, map[string]interface{}{"file_path": "vault2/key.pem"}},
		{"no cwd to resolve against", "", map[string]interface{}{"file_path": "secrets.env"}},
	}
	for _, c := range allowed {
		t.Run(c.name, func(t *testing.T) {
			if got := UserProtectedCheck("Read", c.args, sec, c.cwd); got != "" {
				t.Errorf("Read %v from %q was refused: %q", c.args, c.cwd, got)
			}
		})
	}
}

func TestUserProtectedCheckNamesTheRelativePathItWasGiven(t *testing.T) {
	project := t.TempDir()
	protected := filepath.Join(project, "secrets.env")
	sec := &shared.Security{ProtectedPaths: []string{protected}}

	got := UserProtectedCheck("Read", map[string]interface{}{"file_path": "secrets.env"}, sec, project)
	if !strings.Contains(got, `"secrets.env"`) || !strings.Contains(got, NormPath(protected)) {
		t.Errorf("the refusal should name both what the agent asked for and what it hit: %q", got)
	}
}

func TestSandboxRequiredWithNoRequirement(t *testing.T) {
	if got := SandboxRequired(nil); got != "" {
		t.Errorf("a nil security gave %q, want empty", got)
	}
	if got := SandboxRequired(&shared.Security{RequireSandbox: false}); got != "" {
		t.Errorf("RequireSandbox=false gave %q, want empty", got)
	}
}

func TestSandboxRequiredWithNoSandboxMarkerAtAll(t *testing.T) {
	t.Setenv(shared.SandboxEnv, "x")
	os.Unsetenv(shared.SandboxEnv)

	got := SandboxRequired(&shared.Security{RequireSandbox: true})
	if got == "" {
		t.Fatal("an unmarked process was allowed through a RequireSandbox policy")
	}
	if !strings.Contains(got, "solongate run") || strings.Contains(got, "no way to confirm") || strings.Contains(got, "kernel says") {
		t.Errorf("got the wrong refusal shape for a missing marker: %q", got)
	}
}

func TestSandboxRequiredIsInconclusiveWithNothingToProbe(t *testing.T) {
	t.Setenv(shared.SandboxEnv, shared.SandboxMarker(shared.SandboxModeRun, "1.0.0"))

	sec := &shared.Security{RequireSandbox: true, ProtectedPaths: []string{filepath.Join(t.TempDir(), "never-created")}}
	got := SandboxRequired(sec)
	if got == "" {
		t.Fatal("an inconclusive probe was allowed through")
	}
	if !strings.Contains(got, "no way to confirm") {
		t.Errorf("an inconclusive probe should say it cannot confirm: %q", got)
	}
}

func TestSandboxRequiredCatchesAForgedMarker(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "protected.txt")
	if err := os.WriteFile(readable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(shared.SandboxEnv, shared.SandboxMarker(shared.SandboxModeRun, "9.9.9"))

	sec := &shared.Security{RequireSandbox: true, ProtectedPaths: []string{readable}}
	got := SandboxRequired(sec)
	if got == "" {
		t.Fatal("a forged sandbox marker on an unconfined process was allowed through")
	}
	if !strings.Contains(got, "kernel says otherwise") {
		t.Errorf("a forged marker should say the kernel disagrees: %q", got)
	}
}

func TestSandboxRequiredPassesAVerifiedSandbox(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("mode bits do not deny the owner on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file, so there is nothing to deny here")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "locked.txt")
	if err := os.WriteFile(locked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o600) })

	t.Setenv(shared.SandboxEnv, shared.SandboxMarker(shared.SandboxModeRun, "1.0.0"))
	sec := &shared.Security{RequireSandbox: true, ProtectedPaths: []string{locked}}
	if got := SandboxRequired(sec); got != "" {
		t.Errorf("a verified confinement was still refused: %q", got)
	}
}