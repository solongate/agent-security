// SPDX-License-Identifier: Apache-2.0

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// WHAT A PROFILE BUG LOOKS LIKE.
//
// Seatbelt reads this text and does what it says. There is no type checker
// between the string and the kernel, so a missing rule is not an error, it is a
// profile that confines less than the one the user was shown. The three shapes
// that matter: a rule written against a name the kernel will not match, a quote
// that ends the profile early, and a deny that takes an unrelated neighbour
// down with it.
//
// These tests run everywhere because the generator is untagged. They assert the
// text, not the kernel's reading of it, which is the half that can be checked
// off a Mac.

func mustContain(t *testing.T, profile, want, why string) {
	t.Helper()
	if !strings.Contains(profile, want) {
		t.Errorf("profile is missing %q\n  %s", want, why)
	}
}

func TestSeatbeltProfileHeader(t *testing.T) {
	// `(allow default)` is the deny-list regime: everything permitted, then the
	// protected paths taken away. Losing this line inverts the sandbox into one
	// that denies everything, and the symptom is an agent that cannot run.
	p, _ := seatbeltProfile(nil)
	mustContain(t, p, "(version 1)", "SBPL requires a version and refuses the profile without one")
	mustContain(t, p, "(allow default)", "the deny-list regime starts from allow; without it the profile denies everything")
}

func TestSeatbeltProfileDeniesBothReadAndWrite(t *testing.T) {
	dir := t.TempDir()
	secret := filepath.Join(dir, "game.c")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, got := seatbeltProfile([]string{secret})
	if len(got) != 1 || got[0] != secret {
		t.Fatalf("the path was not written into the profile: %v", got)
	}

	// Four rules per path, and all four are load bearing. A literal rule does
	// not cover a tree and a subpath rule does not cover the directory's own
	// inode, so a path that is a directory needs both; and read without write
	// is a file an agent can destroy but not look at.
	for _, want := range []string{
		`(deny file-read* (literal "` + secret + `"))`,
		`(deny file-write* (literal "` + secret + `"))`,
		`(deny file-read* (subpath "` + secret + `"))`,
		`(deny file-write* (subpath "` + secret + `"))`,
	} {
		mustContain(t, p, want, "each of the four rules covers a case the others do not")
	}
}

// THE NEIGHBOUR THAT DISAPPEARS.
//
// Resolving any path stats every directory above it. Deny a tree without
// re-allowing metadata on its ancestors and the files NEXT TO the protected one
// become unreachable too, which reads as the sandbox being broken rather than
// as a rule doing slightly too much.
func TestSeatbeltProfileKeepsAncestorsReadable(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(nested, "secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, _ := seatbeltProfile([]string{secret})
	for d := filepath.Dir(secret); d != "/" && d != "."; d = filepath.Dir(d) {
		mustContain(t, p, `(allow file-read-metadata (literal "`+d+`"))`,
			"without metadata on "+d+", every sibling of the denied path is unreachable too")
	}
}

// THE DELETE THAT NEVER NAMES THE FILE.
//
// `rm /path/to/secret` unlinks by that literal path, which the rules above
// already deny. `cd /path/to && rm secret`, and `find /path/to -delete`,
// resolve the directory once and remove the entry through it, so the path
// Seatbelt is asked to check is the directory's own, not secret's - a case
// the literal/subpath denies on secret itself cannot see no matter which
// canonical form they are written against.
func TestSeatbeltProfileDeniesUnlinkThroughAncestorDirectories(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "a", "b")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(nested, "secret.txt")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	p, _ := seatbeltProfile([]string{secret})
	for d := filepath.Dir(secret); d != "/" && d != "."; d = filepath.Dir(d) {
		mustContain(t, p, `(deny file-write-unlink (literal "`+d+`"))`,
			"a delete routed through "+d+" as an already-open directory names "+d+", not "+secret+", to the kernel")
	}
}

// A PATH THAT DOES NOT EXIST IS REPORTED, NOT DROPPED.
//
// filepath.Abs succeeds on a name that is not there, so the path still reaches
// the profile; what cannot happen is canonicalisation, and the returned list is
// how Preview tells the user which rules are written against the literal name
// only. Silently dropping it would be the dangerous reading: a user who asked
// for protection and got a profile without it.
func TestSeatbeltProfileReportsWhatMadeIt(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "here.txt")
	if err := os.WriteFile(real, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "not-here.txt")

	p, got := seatbeltProfile([]string{real, missing})
	if len(got) != 2 {
		t.Errorf("got %d paths back, want both: %v", len(got), got)
	}
	mustContain(t, p, missing, "a path that does not exist yet is still worth a rule")
}

// THE SYMLINK THAT WALKS AROUND THE RULE.
//
// Seatbelt matches what the kernel resolves. A rule naming only the path the
// user typed is bypassed by reading the file through a link, so both forms go
// in.
func TestSeatbeltProfileDeniesTheCanonicalFormToo(t *testing.T) {
	dir := t.TempDir()
	realDir := filepath.Join(dir, "real")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(realDir, "secret.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(realDir, link); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}

	viaLink := filepath.Join(link, "secret.txt")
	p, _ := seatbeltProfile([]string{viaLink})
	mustContain(t, p, viaLink, "the name the user typed must be denied")

	resolved, err := filepath.EvalSymlinks(viaLink)
	if err != nil {
		t.Fatal(err)
	}
	if resolved != viaLink {
		mustContain(t, p, resolved, "the kernel matches the resolved path, so a rule on the typed name alone is walked around")
	}
}

// THE QUOTE THAT ENDS THE PROFILE EARLY.
//
// SBPL is a Scheme dialect and the profile is one string. A filename containing
// a quote closes the rule mid-path, and everything after it is read as
// something else entirely: in the deny-list regime that is a profile whose
// remaining denies vanish, which fails open and looks like nothing happened.
func TestSbplStringEscapes(t *testing.T) {
	cases := []struct{ in, want string }{
		{`/a/b`, `"/a/b"`},
		{`/a/"b`, `"/a/\"b"`},
		{`/a/\b`, `"/a/\\b"`},
		{`/a/"; (allow default) ;"`, `"/a/\"; (allow default) ;\""`},
	}
	for _, c := range cases {
		if got := sbplString(c.in); got != c.want {
			t.Errorf("sbplString(%q)=%s, want %s", c.in, got, c.want)
		}
	}
}

func TestSeatbeltWorkspaceProfileRefusesWhatConfinesNothing(t *testing.T) {
	// Each of these produces a profile that is valid SBPL and useless, which is
	// worse than an error because the user is told they are sandboxed.
	cases := []struct{ name, ws string }{
		{"a relative path", "projects/x"},
		{"the root", "/"},
		{"empty", ""},
	}
	for _, c := range cases {
		if _, err := seatbeltWorkspaceProfile(Plan{Workspace: c.ws}); err == nil {
			t.Errorf("%s was accepted as a workspace", c.name)
		}
	}

	// The home directory contains ~/.ssh and every other project, which is the
	// precise thing this mode exists to keep out.
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home directory on this machine")
	}
	if _, err := seatbeltWorkspaceProfile(Plan{Workspace: home}); err == nil {
		t.Error("the home directory was accepted as a workspace")
	}
	if _, err := seatbeltWorkspaceProfile(Plan{Workspace: home + "/"}); err == nil {
		t.Error("the home directory with a trailing slash slipped past the check")
	}
}

func TestSeatbeltWorkspaceProfileShape(t *testing.T) {
	ws := t.TempDir()
	readable := t.TempDir()
	writable := t.TempDir()

	p, err := seatbeltWorkspaceProfile(Plan{
		Workspace:    ws,
		RuntimeRead:  []string{readable, ""},
		RuntimeWrite: []string{writable, ""},
	})
	if err != nil {
		t.Fatal(err)
	}

	// `(deny default)` is the whole allowlist regime. Nothing else in the
	// profile says "and nothing else".
	mustContain(t, p, "(deny default)", "without a default deny this is an allow-list of things already allowed")

	// Four grants the process cannot start without. Their absence does not read
	// as a missing permission, it reads as the sandbox being broken: no sysctl
	// means no page size, no mach lookup means no dyld.
	for _, want := range []string{
		"(allow process-fork)",
		"(allow sysctl-read)",
		"(allow mach-lookup)",
		"(allow file-read-metadata)",
	} {
		mustContain(t, p, want, "the process cannot reach main() without it")
	}

	mustContain(t, p, `(allow file* (subpath "`+ws+`"))`, "the workspace is the one writable tree")
	mustContain(t, p, `(allow file* (subpath "`+writable+`"))`, "a runtime write path was asked for and must be granted")
	mustContain(t, p, `(allow file-read* (subpath "`+readable+`"))`, "a read path was asked for")

	// THE ASYMMETRY THAT IS THE POINT. Read paths get process-exec because the
	// agent has to run its own interpreter and /usr/bin; the write set does not,
	// or the agent could write a binary outside the workspace and then run it.
	mustContain(t, p, `(allow process-exec (subpath "`+readable+`"))`, "the agent must be able to run its own interpreter")
	mustContain(t, p, `(allow process-exec (subpath "`+ws+`"))`, "a project that cannot run its own build scripts is not a workspace")
	if strings.Contains(p, `(allow process-exec (subpath "`+writable+`"))`) {
		t.Error("a writable-but-not-workspace path got process-exec: the agent can write a binary there and then run it")
	}

	// An empty string in either list must not become a rule. A grant on "" is a
	// grant on a path that quotes to nothing, and what SBPL does with it is not
	// something to find out in production.
	if strings.Contains(p, `(subpath "")`) {
		t.Error("an empty path became a rule")
	}
}

func TestSeatbeltWorkspaceProfileGrantsTheRuntimeDevices(t *testing.T) {
	// /dev/null and its siblings are WRITABLE on purpose, and they come from the
	// shared default rather than from the caller: a sandbox where `2>/dev/null`
	// fails is one every user turns off.
	p, err := seatbeltWorkspaceProfile(Plan{Workspace: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range DefaultRuntimeDevices() {
		if d == "" {
			continue
		}
		mustContain(t, p, `(allow file* (subpath "`+filepath.Clean(d)+`"))`,
			d+" is a device the runtime writes to; denying it breaks ordinary commands")
	}
}

func TestCanonicalFormsDeduplicates(t *testing.T) {
	dir := t.TempDir()
	if got := canonicalForms(dir); len(got) != 1 || got[0] != dir {
		// A path that is already canonical must not be written twice: duplicate
		// rules are harmless to the kernel and make the profile unreadable to
		// the person auditing it.
		t.Errorf("canonicalForms(%q)=%v, want just the one path", dir, got)
	}

	link := filepath.Join(dir, "link")
	target := filepath.Join(dir, "target")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("this filesystem will not make a symlink: %v", err)
	}
	got := canonicalForms(link)
	if len(got) != 2 || got[0] != link {
		t.Fatalf("canonicalForms(%q)=%v, want the literal and the resolved form", link, got)
	}
}

func TestCanonicalFormsKeepsAPathThatIsNotThereYet(t *testing.T) {
	// EvalSymlinks fails on a path that does not exist. Returning nothing would
	// drop the rule entirely, so the literal has to survive on its own.
	missing := filepath.Join(t.TempDir(), "not", "created", "yet")
	got := canonicalForms(missing)
	if len(got) != 1 || got[0] != missing {
		t.Errorf("canonicalForms(%q)=%v, want the literal path", missing, got)
	}
}