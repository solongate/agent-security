// SPDX-License-Identifier: Apache-2.0

// The first tests in this repository, and the reason they are here rather than
// in a check script.
//
// There were four shell checks and no _test.go anywhere. The checks drive two
// real binaries through real policy files, which is the only way to answer "do
// the two implementations agree" and "is the box closed", and it is the wrong
// instrument for a pure function: a shell check cannot reach DLPScanViews, so
// the one divergence that mattered most this round, an argument scan reading one
// view where its twin read three, was invisible until somebody wrote a case that
// happened to split a secret across a quote.
//
// So the division is deliberate. Pure decisions are tested here, where a case
// costs microseconds and can be exhaustive. End to end behaviour stays in the
// check scripts, where it needs a kernel.
package shared

import (
	"strings"
	"testing"
)

// allPatterns is the configuration the product ships with every pattern on,
// which is what a user who never opened the DLP editor is running.
func allPatterns() *DLPConfig { return &DLPConfig{Patterns: DLPPatternNames()} }

func TestDLPPatternCountMatchesNames(t *testing.T) {
	if got, want := DLPPatternCount(), len(DLPPatternNames()); got != want {
		t.Fatalf("DLPPatternCount()=%d but DLPPatternNames() has %d entries", got, want)
	}
	// 70 is a number in the README and in four byte-identical copies of this
	// table. A pattern added on one side and not the others is the shape of
	// every parity bug here, so the count is pinned rather than derived.
	if got := DLPPatternCount(); got != 70 {
		t.Fatalf("pattern count is %d, README and the three other copies say 70", got)
	}
}

func TestDLPPatternNamesAreUniqueAndIndexable(t *testing.T) {
	seen := map[string]bool{}
	for i, name := range DLPPatternNames() {
		if seen[name] {
			// Names are the on-disk identity of an enabled pattern. Two
			// patterns sharing one means enabling either enables both and
			// disabling either disables neither.
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
	// Example keys, published as examples by the vendors whose formats they
	// are. None of them is live, and that is why they are safe to commit: a
	// test fixture that is a real credential is a credential in a public
	// repository.
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
	// The half that finds walls. A detector that fires on ordinary source is
	// worse than none: it gets turned off, and then nothing is detected.
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
	// A nil config is how `off` reaches this function. It must not be read as
	// "no patterns, therefore nothing enabled, therefore scan everything".
	if hit := DLPScan("AKIAIOSFODNN7EXAMPLE", nil); hit != "" {
		t.Errorf("a nil config reported %q; off must find nothing", hit)
	}
}

func TestDLPScanRespectsTheEnabledList(t *testing.T) {
	// One pattern on, and it is not the one the text matches.
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

// THE CASE THAT FOUND THE SEVENTH DIVERGENCE.
//
// DLPScanViews reads three views of the same text: raw, the text with shell
// quoting stripped, and the concatenated decode of its base64-looking tokens.
// DLPScan reads one. The argument scan in the Go guard called the single-view
// form while the file-content scans beside it called the multi-view one, so a
// secret split across a quote boundary was refused by the Node guard and allowed
// by this one.
//
// Both forms are kept because both are correct for something: a hot path that
// scans every tool argument of every call does not want three passes over a
// megabyte of diff when one will do. What is not correct is choosing the cheap
// one where the twin chose the thorough one.
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
	// "AKIAIOSFODNN7EXAMPLE" base64-encoded. An agent that cannot send a
	// secret can still send its encoding, and the decode view is what reads it.
	encoded := "QUtJQUlPU0ZPRE5ON0VYQU1QTEU="
	if hit := DLPScanViews("echo "+encoded, cfg); hit == "" {
		t.Fatalf("DLPScanViews missed a base64-encoded secret")
	}
}

func TestDLPScanViewsStillIgnoresOrdinaryText(t *testing.T) {
	cfg := allPatterns()
	// Three views mean three chances to be wrong, and the decode view is the
	// dangerous one: any long run of base64-shaped characters decodes to
	// something. A commit hash, a UUID and a long identifier must all survive.
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
	// UNANCHORED, AND THAT IS THE POINT. This compiles a CUSTOM DLP PATTERN,
	// not a filename matcher: the question it answers is "does this text
	// contain the thing" and a secret in the middle of a diff is still a
	// secret. So `*.env` matching "config.env.example" is correct here and
	// would be a bug in a path matcher. The two uses are easy to confuse,
	// which is why it is written down in a case rather than left to the
	// reader.
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
		{"*key*", "my_KEY_file", true}, // case-insensitive by construction
		// A run of stars collapses to one. The answer is the same here and
		// must be: the JavaScript twin compiles ** to two adjacent unbounded
		// quantifiers and backtracks catastrophically, so both sides
		// normalise or the pair can disagree.
		{"**.env", "config.env", true},
		{"a***b", "aXXXb", true},
		// Regexp metacharacters in a glob are literals.
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