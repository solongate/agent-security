// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package sandbox

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustContain(t *testing.T, profile, want, why string) {
	t.Helper()
	if !strings.Contains(profile, want) {
		t.Errorf("profile is missing %q\n  %s", want, why)
	}
}

func TestSeatbeltProfileHeader(t *testing.T) {

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

	for _, want := range []string{
		`(deny file-read* (literal "` + secret + `"))`,
		`(deny file-write* (literal "` + secret + `"))`,
		`(deny file-read* (subpath "` + secret + `"))`,
		`(deny file-write* (subpath "` + secret + `"))`,
	} {
		mustContain(t, p, want, "each of the four rules covers a case the others do not")
	}
}

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

	mustContain(t, p, "(deny default)", "without a default deny this is an allow-list of things already allowed")

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

	mustContain(t, p, `(allow process-exec (subpath "`+readable+`"))`, "the agent must be able to run its own interpreter")
	mustContain(t, p, `(allow process-exec (subpath "`+ws+`"))`, "a project that cannot run its own build scripts is not a workspace")
	if strings.Contains(p, `(allow process-exec (subpath "`+writable+`"))`) {
		t.Error("a writable-but-not-workspace path got process-exec: the agent can write a binary there and then run it")
	}

	if strings.Contains(p, `(subpath "")`) {
		t.Error("an empty path became a rule")
	}
}

func TestSeatbeltWorkspaceProfileGrantsTheRuntimeDevices(t *testing.T) {

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

	missing := filepath.Join(t.TempDir(), "not", "created", "yet")
	got := canonicalForms(missing)
	if len(got) != 1 || got[0] != missing {
		t.Errorf("canonicalForms(%q)=%v, want the literal path", missing, got)
	}
}