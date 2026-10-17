// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"strings"
	"testing"
)

func allPatterns() *DLPConfig { return &DLPConfig{Patterns: DLPPatternNames()} }

func TestDLPPatternCountMatchesNames(t *testing.T) {
	if got, want := DLPPatternCount(), len(DLPPatternNames()); got != want {
		t.Fatalf("DLPPatternCount()=%d but DLPPatternNames() has %d entries", got, want)
	}

	if got := DLPPatternCount(); got != 70 {
		t.Fatalf("pattern count is %d, README and the three other copies say 70", got)
	}
}

func TestDLPPatternNamesAreUniqueAndIndexable(t *testing.T) {
	seen := map[string]bool{}
	for i, name := range DLPPatternNames() {
		if seen[name] {

			t.Errorf("duplicate pattern name %q", name)
		}
		seen[name] = true
		if DLPPatternIndex(name) != i {
			t.Errorf("DLPPatternIndex(%q)=%d, want %d", name, DLPPatternIndex(name), i)
		}
		if gotName, re := DLPPatternAt(i); gotName != name || re == nil {
			t.Errorf("DLPPatternAt(%d)=(%q,%v), want (%q, non-nil)", i, gotName, re, name)
		}
	}
	if DLPPatternIndex("a name no pattern has") != -1 {
		t.Error("DLPPatternIndex must return -1 for an unknown name")
	}
}

func TestDLPScanFindsAKnownSecret(t *testing.T) {
	cfg := allPatterns()

	cases := []struct {
		name, text string
	}{
		{"AWS access key", "AKIAIOSFODNN7EXAMPLE"},
		{"GitHub token", "ghp_" + strings.Repeat("a", 36)},
		{"Slack token", "xoxb-000000000000-000000000000-" + strings.Repeat("A", 24)},
		{"private key header", "-----BEGIN RSA PRIVATE KEY-----"},
	}
	for _, c := range cases {
		if hit := DLPScan(c.text, cfg); hit == "" {
			t.Errorf("%s: DLPScan found nothing in %q", c.name, c.text)
		}
	}
}

func TestDLPScanIgnoresOrdinaryText(t *testing.T) {
	cfg := allPatterns()

	clean := []string{
		"func main() { fmt.Println(\"hello\") }",
		"git commit -m \"fix the thing\"",
		"SELECT id, name FROM users WHERE active = true",
		"https://github.com/solongate/agent-security",
		"",
	}
	for _, text := range clean {
		if hit := DLPScan(text, cfg); hit != "" {
			t.Errorf("DLPScan reported %q in ordinary text %q", hit, text)
		}
	}
}

func TestDLPScanNilConfigFindsNothing(t *testing.T) {

	if hit := DLPScan("AKIAIOSFODNN7EXAMPLE", nil); hit != "" {
		t.Errorf("a nil config reported %q; off must find nothing", hit)
	}
}

func TestDLPScanRespectsTheEnabledList(t *testing.T) {

	cfg := &DLPConfig{Patterns: []string{"Slack token"}}
	if hit := DLPScan("AKIAIOSFODNN7EXAMPLE", cfg); hit != "" {
		t.Errorf("a disabled pattern fired: %q", hit)
	}
	cfg = &DLPConfig{Patterns: []string{"AWS access key"}}
	if hit := DLPScan("AKIAIOSFODNN7EXAMPLE", cfg); hit == "" {
		names := strings.Join(DLPPatternNames(), ", ")
		t.Fatalf("the AWS pattern did not fire when enabled by name; names are: %s", names)
	}
}

func TestDLPScanViewsSeesThroughQuoting(t *testing.T) {
	cfg := allPatterns()
	split := `printf AKIA""IOSFODNN7EXAMPLE`

	if hit := DLPScan(split, cfg); hit != "" {
		t.Errorf("single-view DLPScan found %q in a split secret; it is not supposed to, "+
			"and callers that need it caught must use DLPScanViews", hit)
	}
	if hit := DLPScanViews(split, cfg); hit == "" {
		t.Fatalf("DLPScanViews missed a secret split across a quote: %s", split)
	}
}

func TestDLPScanViewsSeesThroughBase64(t *testing.T) {
	cfg := allPatterns()

	encoded := "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	if hit := DLPScanViews("echo "+encoded, cfg); hit == "" {
		t.Fatalf("DLPScanViews missed a base64-encoded secret")
	}
}

func TestDLPScanViewsStillIgnoresOrdinaryText(t *testing.T) {
	cfg := allPatterns()

	clean := []string{
		"git show 4f8d3a2b1c9e7f6a5b4c3d2e1f0a9b8c7d6e5f4a",
		"id = 550e8400-e29b-41d4-a716-446655440000",
		"const averyLongIdentifierNameThatGoesOnAndOn = 1",
		"npm install @solongate/agent-security --save-exact",
	}
	for _, text := range clean {
		if hit := DLPScanViews(text, cfg); hit != "" {
			t.Errorf("DLPScanViews reported %q in ordinary text %q", hit, text)
		}
	}
}

func TestDLPScanViewsNilConfigFindsNothing(t *testing.T) {
	if hit := DLPScanViews(`printf AKIA""IOSFODNN7EXAMPLE`, nil); hit != "" {
		t.Errorf("a nil config reported %q from the multi-view scan", hit)
	}
}

func TestDLPHitRankOrdersByTheEnabledList(t *testing.T) {
	cfg := allPatterns()
	names := DLPPatternNames()
	first, last := names[0], names[len(names)-1]
	if DLPHitRank(first, cfg) >= DLPHitRank(last, cfg) {
		t.Errorf("rank of %q (%d) must sort before %q (%d)",
			first, DLPHitRank(first, cfg), last, DLPHitRank(last, cfg))
	}
	if DLPHitRank("not a pattern", cfg) < DLPHitRank(last, cfg) {
		t.Error("an unknown name must rank after every known one")
	}
}

func TestGlobToRegexp(t *testing.T) {

	cases := []struct {
		glob, text string
		match      bool
	}{
		{"*.env", "config.env", true},
		{"*.env", "config.env.example", true},
		{"*.env", ".env", true},
		{"*.env", "config.yaml", false},
		{"secret*", "secrets.txt", true},
		{"secret*", "my-secret.txt", true},
		{"secret*", "public.txt", false},
		{"*", "anything at all", true},
		{"*key*", "my_KEY_file", true},

		{"**.env", "config.env", true},
		{"a***b", "aXXXb", true},

		{"a.b", "a.b", true},
		{"a.b", "axb", false},
		{"cost(+)", "cost(+)", true},
	}
	for _, c := range cases {
		re, err := GlobToRegexp(c.glob)
		if err != nil {
			t.Errorf("GlobToRegexp(%q): %v", c.glob, err)
			continue
		}
		if got := re.MatchString(c.text); got != c.match {
			t.Errorf("GlobToRegexp(%q).MatchString(%q)=%v, want %v (pattern: %s)",
				c.glob, c.text, got, c.match, re.String())
		}
	}
}