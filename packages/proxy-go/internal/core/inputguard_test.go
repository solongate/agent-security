package core

import (
	"encoding/json"
	"os"
	"sort"
	"testing"
)

// A differential test, not a hand-written one.
//
// Every expectation in testdata/input-guard.json was produced by running the
// SHIPPED npm implementation (packages/proxy/dist/lib.js) over the same corpus.
// That is the only way to know a regex survived the move from JavaScript to
// RE2: the two engines agree on most things and disagree on exactly the ones
// that matter here — `$` in multiline mode, lazy repetition, and what a
// character class means once `(?i)` is applied. Asserting against my own
// reading of the patterns would have tested the reading, not the port.
//
// Regenerate with scripts/gen-input-guard-fixture.mjs when the TypeScript
// detectors change, and expect the diff to show which detector moved.
type guardRow struct {
	Value          string   `json:"value"`
	PathTraversal  bool     `json:"pathTraversal"`
	ShellInjection bool     `json:"shellInjection"`
	WildcardAbuse  bool     `json:"wildcardAbuse"`
	SSRF           bool     `json:"ssrf"`
	SQLInjection   bool     `json:"sqlInjection"`
	Exfiltration   bool     `json:"exfiltration"`
	BoundaryEscape bool     `json:"boundaryEscape"`
	LengthOK       bool     `json:"lengthOK"`
	EntropyOK      bool     `json:"entropyOK"`
	Threats        []string `json:"threats"`
}

func loadRows(t *testing.T) []guardRow {
	t.Helper()
	b, err := os.ReadFile("testdata/input-guard.json")
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var rows []guardRow
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("fixture is empty")
	}
	return rows
}

func TestDetectorsMatchNodeImplementation(t *testing.T) {
	for i, row := range loadRows(t) {
		checks := []struct {
			name string
			got  bool
			want bool
		}{
			{"pathTraversal", DetectPathTraversal(row.Value), row.PathTraversal},
			{"shellInjection", DetectShellInjection(row.Value), row.ShellInjection},
			{"wildcardAbuse", DetectWildcardAbuse(row.Value), row.WildcardAbuse},
			{"ssrf", DetectSSRF(row.Value), row.SSRF},
			{"sqlInjection", DetectSQLInjection(row.Value), row.SQLInjection},
			{"exfiltration", DetectExfiltration(row.Value), row.Exfiltration},
			{"boundaryEscape", DetectBoundaryEscape(row.Value), row.BoundaryEscape},
			{"lengthOK", CheckLengthLimits(row.Value, InputGuardMaxLength), row.LengthOK},
			{"entropyOK", CheckEntropyLimits(row.Value), row.EntropyOK},
		}
		for _, c := range checks {
			if c.got != c.want {
				t.Errorf("row %d %s: %s(%s) = %v, npm says %v",
					i, c.name, c.name, short(row.Value), c.got, c.want)
			}
		}
	}
}

// The detectors agreeing one at a time is not the same as sanitizeInput
// agreeing: a threat can be detected and then dropped by a config flag, or
// reported under the wrong type.
func TestSanitizeInputMatchesNodeImplementation(t *testing.T) {
	cfg := DefaultInputGuardConfig()
	for i, row := range loadRows(t) {
		res := SanitizeInput("f", row.Value, cfg)
		got := make([]string, 0, len(res.Threats))
		for _, th := range res.Threats {
			got = append(got, string(th.Type))
		}
		sort.Strings(got)
		want := append([]string{}, row.Threats...)
		sort.Strings(want)
		if !equalStrings(got, want) {
			t.Errorf("row %d threats for %s: got %v, npm says %v", i, short(row.Value), got, want)
		}
		if res.Safe != (len(want) == 0) {
			t.Errorf("row %d safe for %s: got %v with %d threats", i, short(row.Value), res.Safe, len(want))
		}
	}
}

// Nested values have to be walked, and the field path is what tells a user
// WHICH argument tripped the guard.
func TestSanitizeWalksNestedArguments(t *testing.T) {
	args := map[string]any{
		"plain": "hello",
		"nested": map[string]any{
			"path": "../etc/passwd",
		},
		"list":   []any{"fine", "http://169.254.169.254/latest/meta-data"},
		"number": 42.0,
	}
	res := SanitizeArguments(args, DefaultInputGuardConfig())
	if res.Safe {
		t.Fatal("expected the nested traversal and the metadata URL to be found")
	}
	fields := map[string]bool{}
	for _, th := range res.Threats {
		fields[th.Field] = true
	}
	if !fields["arguments.nested.path"] {
		t.Errorf("nested object field not reported, got fields %v", fields)
	}
	if !fields["arguments.list[1]"] {
		t.Errorf("array element field not reported, got fields %v", fields)
	}
}

// Map iteration in Go is randomised. The threat list has to come out the same
// on every run or two reports of the same input cannot be compared.
func TestSanitizeIsDeterministic(t *testing.T) {
	args := map[string]any{
		"a": "../x", "b": "ls; rm", "c": "http://127.0.0.1", "d": "' OR '1'='1",
		"e": "[USER_INPUT_START]", "f": "**/*", "g": "/etc/shadow",
	}
	first := fieldsOf(SanitizeArguments(args, DefaultInputGuardConfig()))
	for i := 0; i < 50; i++ {
		if !equalStrings(first, fieldsOf(SanitizeArguments(args, DefaultInputGuardConfig()))) {
			t.Fatalf("threat order changed between runs (run %d)", i)
		}
	}
}

func TestBoundaryTaggingRoundTrips(t *testing.T) {
	args := map[string]any{
		"text": "hello",
		"deep": map[string]any{"inner": []any{"a", 1.0}},
	}
	tagged := TagUserInput(args)
	if tagged["text"] != BoundaryPrefix+"hello"+BoundarySuffix {
		t.Errorf("string not tagged: %v", tagged["text"])
	}
	inner := tagged["deep"].(map[string]any)["inner"].([]any)
	if inner[0] != BoundaryPrefix+"a"+BoundarySuffix {
		t.Errorf("nested array string not tagged: %v", inner[0])
	}
	if inner[1] != 1.0 {
		t.Errorf("non-string value was altered: %v", inner[1])
	}
	if got := StripBoundaryTags(tagged["text"].(string)); got != "hello" {
		t.Errorf("strip did not undo tag: %q", got)
	}
}

func fieldsOf(r SanitizationResult) []string {
	out := make([]string, 0, len(r.Threats))
	for _, th := range r.Threats {
		out = append(out, th.Field+"/"+string(th.Type))
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) <= 60 {
		return "`" + s + "`"
	}
	return "`" + s[:57] + "…`"
}
