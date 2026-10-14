//go:build linux

// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// frozenBelow is the whole safety of the two-regime grant: it decides whether a
// directory on the way to a protected path is granted whole or entry by entry.
// Answer it wrong in the permissive direction and the protected file is handed
// over, so every case here is about where it must say no.
func TestFrozenBelow(t *testing.T) {
	set := func(paths ...string) map[string]bool {
		m := map[string]bool{}
		for _, p := range paths {
			m[p] = true
		}
		return m
	}

	cases := []struct {
		name    string
		dir     string
		denied  map[string]bool
		frozen  map[string]bool
		want    bool
		because string
	}{
		{
			name:    "the only denied child is frozen",
			dir:     "/home/u/p",
			denied:  set("/home/u/p/game.c"),
			frozen:  set("/home/u/p/game.c"),
			want:    true,
			because: "nothing under this directory can be written anyway",
		},
		{
			name:    "the only denied child is not frozen",
			dir:     "/home/u/p",
			denied:  set("/home/u/p/game.c"),
			frozen:  set(),
			want:    false,
			because: "a wide grant would reach it",
		},
		{
			name:    "two children, one frozen",
			dir:     "/home/u/p",
			denied:  set("/home/u/p/a.c", "/home/u/p/b.c"),
			frozen:  set("/home/u/p/a.c"),
			want:    false,
			because: "every denied child must be frozen, not any",
		},
		{
			name:    "two children, both frozen",
			dir:     "/home/u/p",
			denied:  set("/home/u/p/a.c", "/home/u/p/b.c"),
			frozen:  set("/home/u/p/a.c", "/home/u/p/b.c"),
			want:    true,
			because: "the whole subtree is held below the LSM",
		},
		{
			name:    "an unfrozen path deeper down",
			dir:     "/home/u",
			denied:  set("/home/u/p/deep/x.c"),
			frozen:  set(),
			want:    false,
			because: "the test is over the subtree, not one level",
		},
		{
			name:    "a frozen path deeper down",
			dir:     "/home/u",
			denied:  set("/home/u/p/deep/x.c"),
			frozen:  set("/home/u/p/deep/x.c"),
			want:    true,
			because: "depth does not change the question",
		},
		{
			name:    "nothing denied beneath this directory",
			dir:     "/var/log",
			denied:  set("/home/u/p/game.c"),
			frozen:  set("/home/u/p/game.c"),
			want:    false,
			because: "no denied children must not read as all of them being safe",
		},
		{
			name:    "the directory is itself denied and frozen",
			dir:     "/home/u/secrets",
			denied:  set("/home/u/secrets"),
			frozen:  set("/home/u/secrets"),
			want:    true,
			because: "a denied directory counts as its own child",
		},
		{
			name:    "a sibling prefix must not count as a child",
			dir:     "/home/u/p",
			denied:  set("/home/u/prod/game.c"),
			frozen:  set(),
			want:    false,
			because: "/home/u/p must not match /home/u/prod, which shares its prefix",
		},
		{
			name:    "root with everything frozen",
			dir:     "/",
			denied:  set("/home/u/p/game.c"),
			frozen:  set("/home/u/p/game.c"),
			want:    true,
			because: "the root join must not produce a double slash and miss",
		},
	}

	for _, c := range cases {
		if got := frozenBelow(c.dir, c.denied, c.frozen); got != c.want {
			t.Errorf("%s: frozenBelow(%q)=%v, want %v, because %s",
				c.name, c.dir, got, c.want, c.because)
		}
	}
}

// AND THE SIBLING PREFIX CASE AGAIN, AT THE RULE LEVEL, because getting it
// wrong is a silent widening rather than a crash: /home/u/p and /home/u/prod
// share nine characters and a prefix test without the separator treats the
// second as living inside the first.
func TestAllowRulesSiblingPrefixDoesNotWiden(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "p")
	prod := filepath.Join(root, "prod")
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(prod, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(prod, "game.c")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// prod/game.c is denied and NOT frozen, so prod must be narrow. root is an
	// ancestor of prod, so root must be narrow too.
	_, walked, narrow, err := allowRules([]string{target}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(narrow, prod) {
		t.Errorf("the directory holding an unfrozen denied path is not narrow: %v", narrow)
	}
	if !contains(narrow, root) {
		t.Errorf("an ancestor of an unfrozen denied path is not narrow: %v", narrow)
	}
	if !contains(walked, root) || !contains(walked, prod) {
		t.Errorf("walked is missing an ancestor: %v", walked)
	}
}

// The regime switch, which is the fix for the one standing cost of `run`.
func TestAllowRulesFrozenPathWidensItsAncestors(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "work")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "game.c")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, _, narrowWithout, err := allowRules([]string{target}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(narrowWithout, dir) {
		t.Fatalf("without an immutable flag the directory must be narrow, got %v", narrowWithout)
	}

	_, _, narrowWith, err := allowRules([]string{target}, []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if contains(narrowWith, dir) {
		t.Errorf("with the path frozen the directory must be granted whole, got narrow %v", narrowWith)
	}
	if len(narrowWith) != 0 {
		t.Errorf("every walked directory should be wide when the only denied path is frozen, got %v", narrowWith)
	}
}

// AN IMMUTABLE ENTRY FOR A PATH THAT IS NOT DENIED MUST DO NOTHING. Otherwise a
// caller could widen a directory on the strength of a file this layer was never
// asked to protect, which is the one way this feature could be turned into a
// hole from outside the package.
func TestAllowRulesIgnoresImmutablePathsThatAreNotDenied(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "work")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(dir, "game.c")
	other := filepath.Join(dir, "unrelated.c")
	for _, f := range []string{denied, other} {
		if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// `other` is claimed immutable; `denied` is the protected one and is not.
	_, _, narrow, err := allowRules([]string{denied}, []string{other})
	if err != nil {
		t.Fatal(err)
	}
	if !contains(narrow, dir) {
		t.Errorf("an immutable claim about an undenied path widened the directory: narrow=%v", narrow)
	}
}

func TestAllowRulesRefusesToDenyRoot(t *testing.T) {
	if _, _, _, err := allowRules([]string{"/"}, nil); err == nil {
		t.Fatal(`denying "/" must be refused: it is not a sandbox, it is a brick`)
	}
}

func TestAllowRulesWithNothingDeniedStillMakesADomain(t *testing.T) {
	// An empty deny list is not "no confinement": entering a Landlock domain
	// at all blocks arbitrary mounts, which is worth having on its own.
	rules, walked, narrow, err := allowRules(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) == 0 {
		t.Error("an empty deny list produced no rules, so no domain is entered")
	}
	if len(walked) != 0 || len(narrow) != 0 {
		t.Errorf("nothing is walked when nothing is denied, got walked=%v narrow=%v", walked, narrow)
	}
}

// Preview is what the user is told before anything is applied, and it must
// describe the regime that will actually be in force. It used to state the cost
// unconditionally, which is now wrong for a properly locked path.
func TestPreviewDescribesTheRegimeInForce(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "work")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "game.c")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	narrow := strings.Join(Preview(Plan{Deny: []string{target}}), " ")
	if !strings.Contains(narrow, "entry by") {
		t.Errorf("the narrow regime must say the grant is entry by entry, got: %s", narrow)
	}
	if !strings.Contains(narrow, "sudo") {
		t.Errorf("the narrow regime must say how to get out of it, got: %s", narrow)
	}

	wide := strings.Join(Preview(Plan{Deny: []string{target}, Immutable: []string{target}}), " ")
	if strings.Contains(wide, "entry by") {
		t.Errorf("the wide regime must not report the narrow cost, got: %s", wide)
	}
	if !strings.Contains(wide, "writable immediately") {
		t.Errorf("the wide regime must say a new file is writable, got: %s", wide)
	}
}

// END TO END, AND IT NEEDS A FLAG ONLY ROOT CAN SET.
//
// Everything above is the decision. This is the consequence, and it is the only
// thing that proves the decision was worth making: with the inode frozen, a file
// created in the protected file's own directory can be written, and the
// protected file still cannot be.
//
// Skipped without CAP_LINUX_IMMUTABLE, which an ordinary user does not have. CI
// runs as root on the runner, so this runs there.
func TestFrozenRegimeEndToEnd(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("chattr +i needs CAP_LINUX_IMMUTABLE; this is measured as root in CI")
	}
	if _, err := exec.LookPath("chattr"); err != nil {
		t.Skip("chattr is not on PATH")
	}

	root := t.TempDir()
	dir := filepath.Join(root, "work")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "game.c")
	if err := os.WriteFile(target, []byte("int main(){return 0;}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("chattr", "+i", target).CombinedOutput(); err != nil {
		t.Skipf("chattr +i failed, the filesystem may not support it: %v: %s", err, out)
	}
	// Cleared before TempDir cleanup, which cannot remove an immutable file.
	t.Cleanup(func() { _ = exec.Command("chattr", "-i", target).Run() })

	// The flag is real, so even this unconfined test process cannot write it.
	if err := os.WriteFile(target, []byte("overwritten"), 0o644); err == nil {
		t.Fatal("chattr +i reported success but the file is still writable, " +
			"so the premise of the wide grant does not hold on this filesystem")
	}

	_, _, narrow, err := allowRules([]string{target}, []string{target})
	if err != nil {
		t.Fatal(err)
	}
	if len(narrow) != 0 {
		t.Errorf("a genuinely immutable path still produced narrow directories: %v", narrow)
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}