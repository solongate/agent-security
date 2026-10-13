// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

// REDACTION IS THE ONE PATH WHERE A BUG LEAKS THE SECRET ITSELF.
//
// Everywhere else in this product a mistake refuses a call that should have
// been allowed, or allows one that should have been refused, and the secret
// stays where it was. Here the output is handed back to the agent, so a pattern
// that does not fire, a replacement that silently produces an empty string, or
// a copy written to a readable path puts the value in the transcript.
//
// The values below are the published example keys, not real ones, and they are
// split across concatenations so this file does not itself read as a document
// containing a credential.

func dlpAll() *shared.DLPConfig {
	cfg := &shared.DLPConfig{}
	for i := 0; i < shared.DLPPatternCount(); i++ {
		name, _ := shared.DLPPatternAt(i)
		cfg.Patterns = append(cfg.Patterns, name)
	}
	return cfg
}

func TestDlpRedactTextMasksTheValueAndNamesIt(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	out := dlpRedactText("my key is "+secret+" ok", dlpAll())

	if strings.Contains(out, secret) {
		t.Fatalf("the secret survived redaction: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:") {
		t.Fatalf("nothing was marked as redacted: %q", out)
	}
	// The NAME travels with the marker. A bare [REDACTED] tells the person
	// reading the transcript that something was removed and not what, which is
	// the difference between a usable audit trail and a blank.
	if !strings.Contains(out, "AWS access key") {
		t.Errorf("the marker does not name the pattern: %q", out)
	}
	// And the surrounding text is untouched: redaction must not rewrite the
	// agent's own words.
	if !strings.HasPrefix(out, "my key is ") || !strings.HasSuffix(out, " ok") {
		t.Errorf("text around the secret was altered: %q", out)
	}
}

func TestDlpRedactTextMasksEveryOccurrence(t *testing.T) {
	// ReplaceAll, not Replace. A file that names the same key twice and gets one
	// of them masked has leaked it.
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	out := dlpRedactText(secret+" and again "+secret, dlpAll())
	if strings.Contains(out, secret) {
		t.Errorf("a second occurrence was left in place: %q", out)
	}
	if n := strings.Count(out, "[REDACTED:"); n != 2 {
		t.Errorf("got %d markers for 2 occurrences: %q", n, out)
	}
}

func TestDlpRedactTextOnlyMasksEnabledPatterns(t *testing.T) {
	// The config is a list of names, and a name missing from it is a pattern the
	// user turned off. Masking it anyway would make the setting a lie; the cost
	// is stated here rather than assumed.
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	off := &shared.DLPConfig{Patterns: []string{"GitHub token"}}
	if out := dlpRedactText(secret, off); !strings.Contains(out, secret) {
		t.Errorf("a disabled pattern still redacted: %q", out)
	}
}

func TestDlpRedactTextWithNoConfigReturnsTheTextUnchanged(t *testing.T) {
	// A nil config is "DLP is not configured", and the caller hands the result
	// back as the file's contents. Returning "" here would silently empty a file
	// the agent asked to read.
	in := "nothing special"
	if out := dlpRedactText(in, nil); out != in {
		t.Errorf("a nil config changed the text: %q", out)
	}
	if out := dlpRedactText("", dlpAll()); out != "" {
		t.Errorf("empty text came back as %q", out)
	}
}

// A PATTERN NAME IS NOT A REPLACEMENT TEMPLATE.
//
// The marker is built from the pattern's own name, and a custom name containing
// `$1` would be expanded as a capture-group reference by ReplaceAllString: the
// marker comes out mangled or empty, and an empty marker reads as "nothing was
// redacted". ReplaceAllLiteralString is what stops that, and this is the test
// that would notice if it were changed back.
func TestDlpRedactTextTreatsThePatternNameAsLiteral(t *testing.T) {
	cfg := &shared.DLPConfig{
		Custom: []shared.DLPCustom{{Name: "team $1 key", Re: "*SUPERSECRET*"}},
	}
	out := dlpRedactText("x SUPERSECRET y", cfg)
	if strings.Contains(out, "SUPERSECRET") {
		t.Fatalf("the custom pattern did not fire: %q", out)
	}
	if !strings.Contains(out, "team $1 key") {
		t.Errorf("the name was expanded as a capture reference instead of written literally: %q", out)
	}
}

func TestDlpRedactTextCustomPatterns(t *testing.T) {
	cfg := &shared.DLPConfig{
		Custom: []shared.DLPCustom{
			{Name: "", Re: "*COMPANYSECRET*"},
			// A pattern that does not compile. One bad entry must not stop the
			// rest being masked, or a typo in a settings file turns redaction
			// off wholesale and nothing says so.
			{Name: "broken", Re: "["},
			{Name: "named", Re: "*OTHERSECRET*"},
		},
	}
	out := dlpRedactText("a COMPANYSECRET b OTHERSECRET c", cfg)
	if strings.Contains(out, "COMPANYSECRET") || strings.Contains(out, "OTHERSECRET") {
		t.Fatalf("a custom pattern was skipped: %q", out)
	}
	// An unnamed custom pattern still gets a marker, because the marker is what
	// tells the reader something was removed.
	if !strings.Contains(out, "[REDACTED:custom]") {
		t.Errorf("an unnamed custom pattern produced no usable marker: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:named]") {
		t.Errorf("a named custom pattern lost its name: %q", out)
	}
}

// THE COPY IS A FILE THAT EXISTS BECAUSE THE ORIGINAL HELD A SECRET.
func TestDlpRedactCopyWritesARedactedFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	src := filepath.Join(dir, "config.env")
	if err := os.WriteFile(src, []byte("KEY="+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	tmp := dlpRedactCopy(src, dlpAll())
	if tmp == redactSkip || tmp == redactClean || tmp == redactFailed {
		t.Fatalf("a file holding a secret produced %q instead of a copy", tmp)
	}

	got, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), secret) {
		t.Error("the copy the agent is pointed at still contains the secret")
	}
	if !strings.Contains(string(got), "[REDACTED:") {
		t.Errorf("the copy is not a redaction: %q", got)
	}

	// 0600. The copy is derived from a file that held a credential, so a mode
	// that lets another account on the machine read it hands the shape of the
	// secret, and its filename, to anybody logged in.
	st, err := os.Stat(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("the redacted copy is mode %o, want 600", perm)
	}
	// And the directory holding them, because a listable directory of redacted
	// copies names, by filename, every file found to hold a secret.
	if dst, err := os.Stat(filepath.Dir(tmp)); err == nil {
		if perm := dst.Mode().Perm(); perm != 0o700 {
			t.Errorf("the redacted-copy directory is mode %o, want 700", perm)
		}
	}
}

// TWO FILES WITH THE SAME BASENAME MUST NOT SHARE A COPY.
//
// Without the hash prefix, reading ~/a/.env and then ~/b/.env serves the first
// file's redaction for the second: the agent is handed the wrong file's
// contents, which is a correctness bug on top of a disclosure one.
func TestDlpRedactCopyDoesNotCollideOnBasename(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	var copies []string
	for _, sub := range []string{"a", "b"} {
		d := filepath.Join(home, "projects", sub)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(d, ".env")
		if err := os.WriteFile(f, []byte(sub+"="+secret), 0o600); err != nil {
			t.Fatal(err)
		}
		c := dlpRedactCopy(f, dlpAll())
		if c == redactSkip || c == redactClean || c == redactFailed {
			t.Fatalf("%s produced %q", f, c)
		}
		copies = append(copies, c)
	}
	if copies[0] == copies[1] {
		t.Fatalf("both files share one copy at %q, so one of them is served the other's contents", copies[0])
	}
	for i, c := range copies {
		b, err := os.ReadFile(c)
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"a=", "b="}[i]
		if !strings.Contains(string(b), want) {
			t.Errorf("copy %d does not hold its own file's contents: %q", i, b)
		}
	}
}

func TestDlpRedactCopySentinels(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// CLEAN: a file with no secret in it is not copied at all. Copying every
	// file an agent reads would double every read and fill the directory with
	// files that are not redactions of anything.
	clean := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(clean, []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dlpRedactCopy(clean, dlpAll()); got != redactClean {
		t.Errorf("a file with no secret gave %q, want %q", got, redactClean)
	}

	// SKIP: nothing to read. Each of these would otherwise be an error path that
	// stalls the call rather than letting it through unchanged.
	for _, c := range []struct{ name, path string }{
		{"empty path", ""},
		{"a path that is not there", filepath.Join(home, "missing")},
		{"a directory", home},
	} {
		if got := dlpRedactCopy(c.path, dlpAll()); got != redactSkip {
			t.Errorf("%s gave %q, want %q", c.name, got, redactSkip)
		}
	}

	// And the ceiling: above it the file is left alone rather than read into
	// memory to decide one tool call. The trade is that a secret in a file over
	// the ceiling is not caught here, and it is the trade the scan path already
	// makes.
	big := filepath.Join(home, "big.bin")
	f, err := os.OpenFile(big, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(dlpMaxFileBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	if got := dlpRedactCopy(big, dlpAll()); got != redactSkip {
		t.Errorf("a file over the ceiling gave %q, want %q", got, redactSkip)
	}
}

func TestDlpExpandGlob(t *testing.T) {
	// THE CLASSIC DODGE. A filename rule cannot match `staging.e*` against
	// `*.env`, and a redacted-copy swap cannot stat a path with a literal `*` in
	// it, so a bare `cat staging.e*` would read the secret unredacted.
	dir := t.TempDir()
	for _, n := range []string{"staging.env", "prod.env", "readme.md"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got := dlpExpandGlob(filepath.Join(dir, "*.env"))
	if len(got) != 2 {
		t.Errorf("a glob matching two files expanded to %d: %v", len(got), got)
	}

	// A non-glob path comes back unchanged so the caller can treat both the
	// same way.
	plain := filepath.Join(dir, "readme.md")
	if g := dlpExpandGlob(plain); len(g) != 1 || g[0] != plain {
		t.Errorf("a plain path was rewritten: %v", g)
	}
	if g := dlpExpandGlob(""); len(g) != 0 {
		t.Errorf("an empty path expanded to %v", g)
	}
}

// THE DEFECT THIS FILE FOUND.
//
// Patterns ran in sequence over one string, so a later pattern matched inside a
// marker an earlier one had already written. A custom pattern of `[` was enough:
// `[REDACTED:custom]` came back as `[REDACTED:broken]REDACTED:custom]`. The
// secret was gone in both cases, so nothing leaked; what was lost was the record
// of what had been removed, which is the half of redaction anybody reads.
//
// The Node twin already stashed its markers behind placeholders. The Go side did
// not, so the same file read on two clients came back masked differently, which
// is the one thing these two functions exist to prevent.
func TestDlpRedactTextDoesNotLetOnePatternEatAnothersMarker(t *testing.T) {
	cfg := &shared.DLPConfig{
		Custom: []shared.DLPCustom{
			{Name: "first", Re: "*COMPANYSECRET*"},
			// Matches the opening bracket of the marker the line above writes.
			{Name: "second", Re: "*[*"},
			// And the word itself, which is the worst version: every marker in
			// the file becomes unreadable at once.
			{Name: "third", Re: "*REDACTED*"},
		},
	}
	out := dlpRedactText("x COMPANYSECRET y", cfg)

	if strings.Contains(out, "COMPANYSECRET") {
		t.Fatalf("the secret survived: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:first]") {
		t.Errorf("the marker was rewritten by a later pattern: %q", out)
	}
	// Exactly one marker: the later patterns had nothing of their own to match
	// once the placeholder was in place.
	if n := strings.Count(out, "[REDACTED:"); n != 1 {
		t.Errorf("got %d markers for one secret: %q", n, out)
	}
	if out != "x [REDACTED:first] y" {
		t.Errorf("got %q, want %q", out, "x [REDACTED:first] y")
	}
}

func TestDlpRedactTextLeavesAForgedPlaceholderEmpty(t *testing.T) {
	// The placeholder is NUL-delimited, and text that already contains one is
	// text an agent could have written. Resolving it would let a file's contents
	// address the label table; out of range comes back empty instead, which is
	// what the Node twin's `labels[+i] || ""` does.
	out := dlpRedactText("before \x0099\x00 after", dlpAll())
	if strings.Contains(out, "99") {
		t.Errorf("a forged placeholder survived into the output: %q", out)
	}
	if out != "before  after" {
		t.Errorf("got %q, want %q", out, "before  after")
	}
}
