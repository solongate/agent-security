// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

//go:build !windows

package maintenance

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/core/config"
)

// Scope note: verifyTagSignature, fetchTagSig, httpGet, RunUpdate, and
// moveToNewestRelease all reach the network (directly or by calling the
// above), so none of them are exercised here. That is a deliberate boundary
// of this pass, not an oversight.

func TestShInterpreter(t *testing.T) {
	want := "sh"
	if info, err := os.Stat("/bin/sh"); err == nil && !info.IsDir() {
		want = "/bin/sh"
	}
	if got := shInterpreter(); got != want {
		t.Errorf("shInterpreter() = %q, want %q", got, want)
	}
}

func TestAsExitErrorWithARealExitError(t *testing.T) {
	err := exec.Command("sh", "-c", "exit 2").Run()
	if err == nil {
		t.Fatal("expected the command to exit non-zero")
	}
	var exit *exec.ExitError
	if !asExitError(err, &exit) {
		t.Fatal("asExitError() = false for a real *exec.ExitError")
	}
	if exit == nil {
		t.Fatal("asExitError() = true but did not populate out")
	}
	if exit.ExitCode() != 2 {
		t.Errorf("asExitError() populated exit code %d, want 2", exit.ExitCode())
	}
}

func TestAsExitErrorWithANonExitError(t *testing.T) {
	var exit *exec.ExitError
	if asExitError(errors.New("boom"), &exit) {
		t.Error("asExitError() = true for a plain error, want false")
	}
	if exit != nil {
		t.Error("asExitError() populated out for a non-ExitError, want nil")
	}
}

func TestGitOutputOnARealRepo(t *testing.T) {
	requireGit(t)
	dir := newGitRepo(t)

	out, ok := gitOutput(dir, "rev-parse", "HEAD")
	if !ok {
		t.Fatal("gitOutput(rev-parse HEAD) ok = false, want true")
	}
	if len(out) != 40 {
		t.Errorf("gitOutput(rev-parse HEAD) = %q (len %d), want a 40-character hash", out, len(out))
	}
}

func TestGitOutputFailingInvocation(t *testing.T) {
	requireGit(t)
	dir := newGitRepo(t)

	if _, ok := gitOutput(dir, "not-a-real-git-subcommand"); ok {
		t.Error("gitOutput() with an invalid subcommand ok = true, want false")
	}
}

func TestDetached(t *testing.T) {
	requireGit(t)
	dir := newGitRepo(t)

	if detached(dir) {
		t.Error("detached() = true on the initial branch checkout, want false")
	}

	runGit(t, dir, "checkout", "--detach", "HEAD")
	if !detached(dir) {
		t.Error("detached() = false after `git checkout --detach HEAD`, want true")
	}
}

func TestDefaultBranchFromOriginHEAD(t *testing.T) {
	requireGit(t)
	bare := newBareRepoOnBranch(t, "feature-branch")
	work := newGitRepoOnBranch(t, "feature-branch")
	runGit(t, work, "remote", "add", "origin", bare)
	runGit(t, work, "push", "-q", "origin", "feature-branch")
	runGit(t, work, "remote", "set-head", "origin", "feature-branch")

	if got := defaultBranch(work); got != "feature-branch" {
		t.Errorf("defaultBranch() = %q, want %q", got, "feature-branch")
	}
}

func TestDefaultBranchFallsBackToMain(t *testing.T) {
	requireGit(t)
	dir := newGitRepoOnBranch(t, "feature-branch")

	if got := defaultBranch(dir); got != "main" {
		t.Errorf("defaultBranch() = %q, want the hardcoded fallback %q", got, "main")
	}
}

func TestParseGitHubRepoSlug(t *testing.T) {
	tests := []struct {
		name      string
		remoteURL string
		wantOwner string
		wantRepo  string
		wantOK    bool
	}{
		{"ssh", "git@github.com:owner/repo.git", "owner", "repo", true},
		{"https with dot git", "https://github.com/owner/repo.git", "owner", "repo", true},
		{"https without dot git", "https://github.com/owner/repo", "owner", "repo", true},
		{"non-github remote", "https://gitlab.com/owner/repo.git", "", "", false},
		{"empty remote", "", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			owner, repo, ok := parseGitHubRepoSlug(tc.remoteURL)
			if ok != tc.wantOK || owner != tc.wantOwner || repo != tc.wantRepo {
				t.Errorf("parseGitHubRepoSlug(%q) = (%q, %q, %v), want (%q, %q, %v)",
					tc.remoteURL, owner, repo, ok, tc.wantOwner, tc.wantRepo, tc.wantOK)
			}
		})
	}
}

func TestRangeOneLiner(t *testing.T) {
	if got := rangeOneLiner(config.UpdateRangeShort); !strings.Contains(got, "every commit") {
		t.Errorf("rangeOneLiner(short) = %q, want it to mention every commit", got)
	}
	if got := rangeOneLiner(config.UpdateRangeLong); got != "tagged releases only" {
		t.Errorf("rangeOneLiner(long) = %q, want %q", got, "tagged releases only")
	}
	if got := rangeOneLiner("whatever-else"); got != "tagged releases only" {
		t.Errorf("rangeOneLiner(unknown) = %q, want the long-range default %q", got, "tagged releases only")
	}
}

func TestContainsPath(t *testing.T) {
	list := []string{"a", "b", "c"}
	if !containsPath(list, "b") {
		t.Error("containsPath(list, \"b\") = false, want true")
	}
	if containsPath(list, "z") {
		t.Error("containsPath(list, \"z\") = true, want false")
	}
	if containsPath(nil, "a") {
		t.Error("containsPath(nil, \"a\") = true, want false")
	}
}

func TestNoSourceToUpdateFrom(t *testing.T) {
	var code int
	out := captureStderrFD(t, func() {
		code = noSourceToUpdateFrom()
	})
	if code != 1 {
		t.Errorf("noSourceToUpdateFrom() = %d, want 1", code)
	}
	if !strings.Contains(out, "git clone") {
		t.Errorf("noSourceToUpdateFrom() output should mention git clone, got: %s", out)
	}
}

func TestQuietStepSuccess(t *testing.T) {
	dir := t.TempDir()
	var code int
	captureStderrFD(t, func() {
		code = quietStep(dir, "doing a thing", "true")
	})
	if code != 0 {
		t.Errorf("quietStep() with `true` = %d, want 0", code)
	}
}

func TestQuietStepFailure(t *testing.T) {
	dir := t.TempDir()
	var code int
	out := captureStderrFD(t, func() {
		code = quietStep(dir, "doing a thing", "sh", "-c", "exit 3")
	})
	if code != 3 {
		t.Errorf("quietStep() with `exit 3` = %d, want 3", code)
	}
	if !strings.Contains(out, "FAILED") {
		t.Errorf("quietStep() failure output should contain the FAILED marker, got: %s", out)
	}
}

func TestStepSuccess(t *testing.T) {
	dir := t.TempDir()
	var code int
	out := captureStderrFD(t, func() {
		code = step(dir, "doing a thing", "true")
	})
	if code != 0 {
		t.Errorf("step() with `true` = %d, want 0", code)
	}
	if !strings.Contains(out, "doing a thing") {
		t.Errorf("step() should print its label, got: %s", out)
	}
}

func TestStepFailureReturnsTheExitCode(t *testing.T) {
	dir := t.TempDir()
	var code int
	captureStderrFD(t, func() {
		code = step(dir, "doing a thing", "sh", "-c", "exit 5")
	})
	if code != 5 {
		t.Errorf("step() with `exit 5` = %d, want 5", code)
	}
}

func TestSpinNonTerminal(t *testing.T) {
	out := captureStderrFD(t, func() {
		stop := spin("waiting")
		stop()
	})
	if !strings.Contains(out, "waiting") {
		t.Errorf("spin() non-terminal output should mention the label, got: %s", out)
	}
}

func TestTypeOutNonTerminal(t *testing.T) {
	out := captureStderrFD(t, func() {
		typeOut("hello world")
	})
	if strings.TrimSpace(out) != "hello world" {
		t.Errorf("typeOut() non-terminal output = %q, want %q", out, "hello world")
	}
}

func TestMarkOK(t *testing.T) {
	out := captureStderrFD(t, func() { markOK("all good") })
	if !strings.Contains(out, "OK") {
		t.Errorf("markOK() output should contain an OK marker, got: %s", out)
	}
	if !strings.Contains(out, "all good") {
		t.Errorf("markOK() output should contain the message, got: %s", out)
	}
}

func TestMarkNo(t *testing.T) {
	out := captureStderrFD(t, func() { markNo("broke it") })
	if !strings.Contains(out, "FAILED") {
		t.Errorf("markNo() output should contain a FAILED marker, got: %s", out)
	}
	if !strings.Contains(out, "broke it") {
		t.Errorf("markNo() output should contain the message, got: %s", out)
	}
}

func TestRestoreInstallArtifactsCleanTreeIsANoop(t *testing.T) {
	requireGit(t)
	dir := newGitRepo(t)

	if code := restoreInstallArtifacts(dir); code != 0 {
		t.Errorf("restoreInstallArtifacts() on a clean tree = %d, want 0", code)
	}
}

func TestRestoreInstallArtifactsIgnoresUntrackedFiles(t *testing.T) {
	requireGit(t)
	dir := newGitRepo(t)
	if err := os.WriteFile(dir+"/scratch.tmp", []byte("junk"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code := restoreInstallArtifacts(dir); code != 0 {
		t.Errorf("restoreInstallArtifacts() with only untracked files = %d, want 0", code)
	}
}

func TestRestoreInstallArtifactsStopsOnForeignChanges(t *testing.T) {
	requireGit(t)
	dir := newGitRepo(t)
	if err := os.WriteFile(dir+"/f.txt", []byte("changed by the user"), 0o644); err != nil {
		t.Fatal(err)
	}

	var code int
	out := captureStderrFD(t, func() {
		code = restoreInstallArtifacts(dir)
	})
	if code != 1 {
		t.Errorf("restoreInstallArtifacts() with a dirty tracked file = %d, want 1", code)
	}
	if !strings.Contains(out, "local changes") {
		t.Errorf("restoreInstallArtifacts() should explain it stopped for local changes, got: %s", out)
	}
}

// newFastForwardableClone sets up an origin bare repo, a work tree tracking
// it on branch, and a second clone that pushes one extra commit to origin --
// so pulling in work can fast-forward without ever touching the network.
func newFastForwardableClone(t *testing.T, branch string) (work string) {
	t.Helper()
	bare := newBareRepoOnBranch(t, branch)
	work = newGitRepoOnBranch(t, branch)
	runGit(t, work, "remote", "add", "origin", bare)
	runGit(t, work, "push", "-q", "-u", "origin", branch)

	second := t.TempDir()
	runGit(t, second, "clone", "-q", bare, ".")
	runGit(t, second, "config", "user.email", "test2@example.com")
	runGit(t, second, "config", "user.name", "Test2")
	if err := os.WriteFile(second+"/f.txt", []byte("one\ntwo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, second, "commit", "-q", "-am", "second commit")
	runGit(t, second, "push", "-q", "origin", branch)
	return work
}

func TestMoveToBranchTipFastForwardsWhenOnTheBranch(t *testing.T) {
	requireGit(t)
	work := newFastForwardableClone(t, "main")
	before, _ := gitOutput(work, "rev-parse", "HEAD")

	var code int
	captureStderrFD(t, func() {
		code = moveToBranchTip(work)
	})
	if code != 0 {
		t.Fatalf("moveToBranchTip() = %d, want 0", code)
	}
	after, _ := gitOutput(work, "rev-parse", "HEAD")
	if after == before {
		t.Error("moveToBranchTip() left HEAD unchanged, want it to fast-forward to the new commit")
	}
	if detached(work) {
		t.Error("moveToBranchTip() left the repo detached after a fast-forward on the branch")
	}
}

func TestMoveToBranchTipReturnsFromDetachedHeadFirst(t *testing.T) {
	requireGit(t)
	work := newFastForwardableClone(t, "main")
	runGit(t, work, "checkout", "--detach", "HEAD")
	if !detached(work) {
		t.Fatal("test setup: expected the repo to be detached before calling moveToBranchTip")
	}

	var code int
	captureStderrFD(t, func() {
		code = moveToBranchTip(work)
	})
	if code != 0 {
		t.Fatalf("moveToBranchTip() = %d, want 0", code)
	}
	if detached(work) {
		t.Error("moveToBranchTip() should return to the tracked branch, but the repo is still detached")
	}
}

func TestMoveToBranchTipFailsOnDivergentHistory(t *testing.T) {
	requireGit(t)
	work := newFastForwardableClone(t, "main")
	// A local commit that was never pushed makes work's history diverge
	// from origin/main, so a --ff-only pull cannot succeed.
	if err := os.WriteFile(work+"/local-only.txt", []byte("local"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, work, "add", "local-only.txt")
	runGit(t, work, "commit", "-q", "-m", "local divergent commit")

	var code int
	out := captureStderrFD(t, func() {
		code = moveToBranchTip(work)
	})
	if code != 1 {
		t.Errorf("moveToBranchTip() with diverged history = %d, want 1", code)
	}
	if !strings.Contains(out, "pull failed") {
		t.Errorf("moveToBranchTip() should explain the pull failed, got: %s", out)
	}
}