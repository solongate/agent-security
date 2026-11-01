// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package dlp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

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
	out := RedactText("my key is "+secret+" ok", dlpAll())

	if strings.Contains(out, secret) {
		t.Fatalf("the secret survived redaction: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:") {
		t.Fatalf("nothing was marked as redacted: %q", out)
	}

	if !strings.Contains(out, "AWS access key") {
		t.Errorf("the marker does not name the pattern: %q", out)
	}

	if !strings.HasPrefix(out, "my key is ") || !strings.HasSuffix(out, " ok") {
		t.Errorf("text around the secret was altered: %q", out)
	}
}

func TestDlpRedactTextMasksEveryOccurrence(t *testing.T) {

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	out := RedactText(secret+" and again "+secret, dlpAll())
	if strings.Contains(out, secret) {
		t.Errorf("a second occurrence was left in place: %q", out)
	}
	if n := strings.Count(out, "[REDACTED:"); n != 2 {
		t.Errorf("got %d markers for 2 occurrences: %q", n, out)
	}
}

func TestDlpRedactTextOnlyMasksEnabledPatterns(t *testing.T) {

	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	off := &shared.DLPConfig{Patterns: []string{"GitHub token"}}
	if out := RedactText(secret, off); !strings.Contains(out, secret) {
		t.Errorf("a disabled pattern still redacted: %q", out)
	}
}

func TestDlpRedactTextWithNoConfigReturnsTheTextUnchanged(t *testing.T) {

	in := "nothing special"
	if out := RedactText(in, nil); out != in {
		t.Errorf("a nil config changed the text: %q", out)
	}
	if out := RedactText("", dlpAll()); out != "" {
		t.Errorf("empty text came back as %q", out)
	}
}

func TestDlpRedactTextTreatsThePatternNameAsLiteral(t *testing.T) {
	cfg := &shared.DLPConfig{
		Custom: []shared.DLPCustom{{Name: "team $1 key", Re: "*SUPERSECRET*"}},
	}
	out := RedactText("x SUPERSECRET y", cfg)
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

			{Name: "broken", Re: "["},
			{Name: "named", Re: "*OTHERSECRET*"},
		},
	}
	out := RedactText("a COMPANYSECRET b OTHERSECRET c", cfg)
	if strings.Contains(out, "COMPANYSECRET") || strings.Contains(out, "OTHERSECRET") {
		t.Fatalf("a custom pattern was skipped: %q", out)
	}

	if !strings.Contains(out, "[REDACTED:custom]") {
		t.Errorf("an unnamed custom pattern produced no usable marker: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:named]") {
		t.Errorf("a named custom pattern lost its name: %q", out)
	}
}

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

	st, err := os.Stat(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if perm := st.Mode().Perm(); perm != 0o600 {
		t.Errorf("the redacted copy is mode %o, want 600", perm)
	}

	if dst, err := os.Stat(filepath.Dir(tmp)); err == nil {
		if perm := dst.Mode().Perm(); perm != 0o700 {
			t.Errorf("the redacted-copy directory is mode %o, want 700", perm)
		}
	}
}

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

	clean := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(clean, []byte("ordinary text"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := dlpRedactCopy(clean, dlpAll()); got != redactClean {
		t.Errorf("a file with no secret gave %q, want %q", got, redactClean)
	}

	for _, c := range []struct{ name, path string }{
		{"empty path", ""},
		{"a path that is not there", filepath.Join(home, "missing")},
		{"a directory", home},
	} {
		if got := dlpRedactCopy(c.path, dlpAll()); got != redactSkip {
			t.Errorf("%s gave %q, want %q", c.name, got, redactSkip)
		}
	}

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

	plain := filepath.Join(dir, "readme.md")
	if g := dlpExpandGlob(plain); len(g) != 1 || g[0] != plain {
		t.Errorf("a plain path was rewritten: %v", g)
	}
	if g := dlpExpandGlob(""); len(g) != 0 {
		t.Errorf("an empty path expanded to %v", g)
	}
}

func TestDlpRedactTextDoesNotLetOnePatternEatAnothersMarker(t *testing.T) {
	cfg := &shared.DLPConfig{
		Custom: []shared.DLPCustom{
			{Name: "first", Re: "*COMPANYSECRET*"},

			{Name: "second", Re: "*[*"},

			{Name: "third", Re: "*REDACTED*"},
		},
	}
	out := RedactText("x COMPANYSECRET y", cfg)

	if strings.Contains(out, "COMPANYSECRET") {
		t.Fatalf("the secret survived: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:first]") {
		t.Errorf("the marker was rewritten by a later pattern: %q", out)
	}

	if n := strings.Count(out, "[REDACTED:"); n != 1 {
		t.Errorf("got %d markers for one secret: %q", n, out)
	}
	if out != "x [REDACTED:first] y" {
		t.Errorf("got %q, want %q", out, "x [REDACTED:first] y")
	}
}

func TestDlpRedactTextLeavesAForgedPlaceholderEmpty(t *testing.T) {

	out := RedactText("before \x0099\x00 after", dlpAll())
	if strings.Contains(out, "99") {
		t.Errorf("a forged placeholder survived into the output: %q", out)
	}
	if out != "before  after" {
		t.Errorf("got %q, want %q", out, "before  after")
	}
}

func TestDlpRedactTextStashPlaceholderCollision(t *testing.T) {
	cfg := &shared.DLPConfig{
		Custom: []shared.DLPCustom{
			{Name: "first", Re: "*AAA*"},
			{Name: "second", Re: "*0*"},
		},
	}
	out := RedactText("xx AAA yy", cfg)
	if strings.Contains(out, "second") {
		t.Fatalf("placeholder collided with second pattern: %q", out)
	}
	if !strings.Contains(out, "[REDACTED:first]") {
		t.Fatalf("expected [REDACTED:first], got: %q", out)
	}
	if out != "xx [REDACTED:first] yy" {
		t.Fatalf("got %q, want %q", out, "xx [REDACTED:first] yy")
	}
}

func TestDlpRedactTextHighScaleSequentialPatterns(t *testing.T) {
	custom := []shared.DLPCustom{
		{Name: "token_0", Re: "*SECRET_TOKEN*"},
	}
	// Add 30 patterns that match digits like *1*, *2*, ... *9*, *0*
	for i := 0; i < 30; i++ {
		custom = append(custom, shared.DLPCustom{
			Name: "digit_rule",
			Re:   "*[0-9]*",
		})
	}
	cfg := &shared.DLPConfig{Custom: custom}
	out := RedactText("key: SECRET_TOKEN suffix", cfg)
	if !strings.Contains(out, "[REDACTED:token_0]") {
		t.Fatalf("expected [REDACTED:token_0] to be preserved, got: %q", out)
	}
	if strings.Contains(out, "digit_rule") {
		t.Fatalf("digit rules should not have matched redacted token marker: %q", out)
	}
	if out != "key: [REDACTED:token_0] suffix" {
		t.Fatalf("unexpected output: %q", out)
	}
}