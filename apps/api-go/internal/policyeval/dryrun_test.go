package policyeval

import (
	"encoding/json"
	"testing"

	"github.com/codeyevsky/solongate/api/internal/policyjson"
)

func rules(t *testing.T, src string) []Rule {
	t.Helper()
	v, err := policyjson.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	r, ok := ParseRules(v)
	if !ok {
		t.Fatal("that is an array")
	}
	return r
}

func args(t *testing.T, src string) *policyjson.Object {
	t.Helper()
	o, ok := policyjson.ParseObject([]byte(src))
	if !ok {
		t.Fatal("that is an object")
	}
	return o
}

// A DENY rule fires when its constraints are VIOLATED; an ALLOW rule fires only
// when they are met. Getting that backwards makes every denylist preview report
// zero impact.
func TestDenyMatchesOnViolationAndAllowOnCompliance(t *testing.T) {
	deny := rules(t, `[{"id":"no-rm","effect":"DENY","priority":1,"toolPattern":"*",
		"commandConstraints":{"denied":["rm *"]}}]`)

	hit := Input{Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED",
		Args: args(t, `{"command":"rm -rf /"}`)}
	if v := EvaluateCandidate(deny, ModeDenylist, hit); v.Effect != "DENY" || v.RuleID != "no-rm" {
		t.Errorf("verdict = %+v, want DENY by no-rm", v)
	}

	miss := Input{Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED",
		Args: args(t, `{"command":"ls"}`)}
	if v := EvaluateCandidate(deny, ModeDenylist, miss); v.Effect != "ALLOW" || v.RuleID != "" {
		t.Errorf("verdict = %+v, want the denylist default ALLOW with no rule", v)
	}
}

// A call that carries no candidate value cannot violate a constraint on that
// value. Without this, a DENY rule scoped to paths would fire on every call
// that touches no path at all.
func TestAConstraintWithNoCandidatesIsSatisfied(t *testing.T) {
	deny := rules(t, `[{"id":"paths","effect":"DENY","priority":1,"toolPattern":"*",
		"pathConstraints":{"denied":["/etc/*"]}}]`)
	in := Input{Tool: "WebFetch", Permission: "NETWORK", TrustLevel: "UNTRUSTED",
		Args: args(t, `{"url":"https://example.com"}`)}
	if v := EvaluateCandidate(deny, ModeDenylist, in); v.Effect != "ALLOW" {
		t.Errorf("verdict = %+v, want ALLOW — nothing here is a path", v)
	}
}

func TestWhitelistModeDeniesWhatNoRuleMatched(t *testing.T) {
	allow := rules(t, `[{"id":"only-ls","effect":"ALLOW","priority":1,"toolPattern":"Bash",
		"commandConstraints":{"allowed":["ls*"]}}]`)
	in := Input{Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED",
		Args: args(t, `{"command":"curl evil.example"}`)}
	if v := EvaluateCandidate(allow, ModeWhitelist, in); v.Effect != "DENY" {
		t.Errorf("verdict = %+v, want DENY — whitelist mode is the default for an unmatched call", v)
	}
}

// `a.priority ?? 100` and a STABLE sort. Two rules at the same priority keep the
// order the request listed them in, and that order decides which rule the
// preview blames for a change.
func TestPriorityOrderIsStableAndDefaultsTo100(t *testing.T) {
	r := rules(t, `[
		{"id":"first","effect":"DENY","toolPattern":"*"},
		{"id":"second","effect":"ALLOW","toolPattern":"*"},
		{"id":"early","effect":"ALLOW","priority":1,"toolPattern":"*"}
	]`)
	in := Input{Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED"}
	if v := EvaluateCandidate(r, ModeDenylist, in); v.RuleID != "early" {
		t.Errorf("matched %q, want the priority-1 rule", v.RuleID)
	}

	noEarly := rules(t, `[
		{"id":"first","effect":"DENY","toolPattern":"*"},
		{"id":"second","effect":"ALLOW","toolPattern":"*"}
	]`)
	if v := EvaluateCandidate(noEarly, ModeDenylist, in); v.RuleID != "first" {
		t.Errorf("matched %q, want the first listed rule at the shared default priority", v.RuleID)
	}
}

// An unrecognised minimumTrustLevel is UNREACHABLE, not zero: `TRUST_ORDER[x]
// ?? Infinity`. A typo in a rule therefore makes it never fire rather than
// always fire.
func TestAnUnknownRequiredTrustLevelNeverMatches(t *testing.T) {
	r := rules(t, `[{"id":"typo","effect":"DENY","priority":1,"toolPattern":"*","minimumTrustLevel":"VERIFED"}]`)
	in := Input{Tool: "Bash", Permission: "EXECUTE", TrustLevel: "TRUSTED"}
	if v := EvaluateCandidate(r, ModeDenylist, in); v.RuleID != "" {
		t.Errorf("matched %q, want no match", v.RuleID)
	}
}

func TestDisabledRulesAreSkipped(t *testing.T) {
	r := rules(t, `[{"id":"off","effect":"DENY","priority":1,"toolPattern":"*","enabled":false}]`)
	in := Input{Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED"}
	if v := EvaluateCandidate(r, ModeDenylist, in); v.RuleID != "" {
		t.Errorf("matched %q, want no match", v.RuleID)
	}
}

// dry-run compares the recorded decision with `=== 'ALLOW'` and backtest
// upper-cases it first. Both behaviours are live and a row written as "allow"
// by an older client is counted differently by the two. Pinned so the
// difference is a decision rather than an accident.
func TestTheTwoRoutesDisagreeAboutALowercaseDecision(t *testing.T) {
	r := rules(t, `[{"id":"deny","effect":"DENY","priority":1,"toolPattern":"*"}]`)
	in := []Input{{ID: "1", Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED", Decision: "allow"}}

	dry := RunDryRun(r, ModeDenylist, in)
	if dry.NewlyBlocked != 0 || dry.Unchanged != 1 {
		t.Errorf("dry run = %+v, want the lowercase decision read as a denial already", dry)
	}
	back := RunBacktest(r, ModeDenylist, in)
	if back.Summary.NewlyBlocked != 1 {
		t.Errorf("backtest = %+v, want the lowercase decision upper-cased to ALLOW", back.Summary)
	}
}

func TestBacktestBreakdownsAndSamples(t *testing.T) {
	r := rules(t, `[{"id":"no-curl","effect":"DENY","priority":1,"toolPattern":"*",
		"commandConstraints":{"denied":["curl*"]}}]`)
	in := []Input{
		{ID: "1", Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED", Decision: "ALLOW",
			Args: args(t, `{"command":"curl https://evil.example/x"}`), Agent: "claude", HasAgent: true,
			CreatedAtMS: 1_700_000_000_000},
		{ID: "2", Tool: "Bash", Permission: "EXECUTE", TrustLevel: "UNTRUSTED", Decision: "ALLOW",
			Args: args(t, `{"command":"ls"}`), CreatedAtMS: 1_700_000_000_000},
	}
	res := RunBacktest(r, ModeDenylist, in)

	if res.Summary.Evaluated != 2 || res.Summary.NewlyBlocked != 1 || res.Summary.Unchanged != 1 {
		t.Errorf("summary = %+v", res.Summary)
	}
	if len(res.PerRule) != 1 || res.PerRule[0].RuleID != "no-curl" || res.PerRule[0].NewlyBlocked != 1 {
		t.Errorf("per_rule = %+v", res.PerRule)
	}
	if len(res.PerAgent) != 2 {
		t.Fatalf("per_agent = %+v, want the named agent and the unknown bucket", res.PerAgent)
	}
	if len(res.Samples) != 1 || res.Samples[0].Agent == nil || *res.Samples[0].Agent != "claude" {
		t.Errorf("samples = %+v", res.Samples)
	}
	if res.Samples[0].Preview != "curl https://evil.example/x" {
		t.Errorf("preview = %q", res.Samples[0].Preview)
	}
	// The bucket is MILLISECONDS truncated to a day; the page feeds it to
	// `new Date(bucket)` and seconds would draw every point in 1970.
	if len(res.Timeseries) != 1 || res.Timeseries[0].Bucket%dayMS != 0 || res.Timeseries[0].Bucket < 1_600_000_000_000 {
		t.Errorf("timeseries = %+v", res.Timeseries)
	}
}

// Every collection is an ARRAY on the wire, never null: the dashboard iterates
// them without a guard.
func TestEmptyResultsMarshalAsArrays(t *testing.T) {
	dry, err := json.Marshal(RunDryRun(nil, ModeDenylist, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"sample_newly_blocked":[]`, `"sample_newly_allowed":[]`, `"truncated_args":0`} {
		if !contains(string(dry), want) {
			t.Errorf("dry-run body %s is missing %s", dry, want)
		}
	}
	back, err := json.Marshal(RunBacktest(nil, ModeDenylist, nil))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"per_rule":[]`, `"per_tool":[]`, `"per_agent":[]`, `"timeseries":[]`, `"samples":[]`} {
		if !contains(string(back), want) {
			t.Errorf("backtest body %s is missing %s", back, want)
		}
	}
}

// The dry-run preview falls back to ANY string argument; the backtest preview
// does not. The difference is in the originals and is visible in two pages.
func TestPreviewsDifferOnAnUnlistedArgumentKey(t *testing.T) {
	a := args(t, `{"unlisted":"something"}`)
	if got := DryRunPreview("Bash", a); got != "something" {
		t.Errorf("DryRunPreview = %q, want the argument", got)
	}
	if got := BacktestPreview("Bash", a); got != "Bash" {
		t.Errorf("BacktestPreview = %q, want the tool name", got)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || indexOf(haystack, needle) >= 0
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
