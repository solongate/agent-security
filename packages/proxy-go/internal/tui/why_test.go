package tui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A BIG TOOL CALL USED TO OPEN ONTO ITS ARGUMENTS AND NOTHING ELSE.
//
// The row's Detail field is the arguments OR the reason, whichever exists, so a
// call with arguments — every real one — took the first branch and the guard's
// explanation was dropped before it reached the screen. What was left was a
// screen of JSON and a rule id in the header.
func TestTheInspectorShowsWhyACallWasRefused(t *testing.T) {
	p := newLiveForTest(streamItem{
		ID: "l:1", At: 1_700_000_000_000, Tool: "Bash", Decision: "DENY",
		Rule:   "rule-7",
		Reason: "Blocked by policy: path \"/private/key\" matches \"/private/*\"",
		Args:   json.RawMessage(`{"command":"cat /private/key","description":"read it"}`),
		Detail: `{"command":"cat /private/key","description":"read it"}`,
	})

	out := p.View(PanelContext{Cols: 120, Rows: 40, Now: time.Unix(1_700_000_000, 0)})
	if !strings.Contains(out, "matches") {
		t.Fatal("the inspector did not show the reason, so the arguments are the only answer on screen")
	}
	if !strings.Contains(out, "rule-7") {
		t.Error("the rule that refused the call is not named in the body")
	}
	if !strings.Contains(out, "cat /private/key") {
		t.Error("the arguments are gone — the reason was meant to go ABOVE them, not replace them")
	}
}

// A RATE LIMIT IS NOT A RULE DENIAL, and looking for a rule id to explain one is
// exactly what makes it confusing.
func TestTheInspectorNamesTheLayerThatRefused(t *testing.T) {
	cases := []struct {
		name string
		item streamItem
		want string
	}{
		{
			"a rate-limit burst",
			streamItem{Decision: "DENY", Burst: true, Reason: "Security layer (rate limit): exceeded 60 calls per minute"},
			"rate limit",
		},
		{
			"a DLP hit names the pattern",
			streamItem{Decision: "DENY", DLP: true, DLPNames: []string{"Anthropic key"},
				Reason: "Security layer (DLP): blocked - arguments contain a Anthropic key"},
			"Anthropic key",
		},
		{
			"detect mode allowed it, and says so",
			streamItem{Decision: "ALLOW", DLP: true, DLPNames: []string{"AWS access key"},
				Reason: "Security layer (DLP): detected - arguments contain a AWS access key"},
			"flagged",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.item.ID, c.item.At, c.item.Tool = "l:1", 1_700_000_000_000, "Bash"
			p := newLiveForTest(c.item)
			out := p.View(PanelContext{Cols: 120, Rows: 40, Now: time.Unix(1_700_000_000, 0)})
			if !strings.Contains(out, c.want) {
				t.Errorf("the inspector never says %q, so the entry does not explain itself", c.want)
			}
		})
	}
}

// AN ORDINARY ALLOW HAS NOTHING TO EXPLAIN. A block above every entry would push
// the arguments down a line for no reason on the common case.
func TestAnUnremarkableAllowGetsNoWhyBlock(t *testing.T) {
	if got := whyBlock("ALLOW", "", "rule-1", nil, false, 80); got != nil {
		t.Errorf("an allow with no reason, no DLP and no burst produced %q", got)
	}
}

// The structured dlp field is not always there. The reason always is — it is
// written at block time and never redacted — so the pattern name is read back
// out of it rather than shown as a bare "DLP".
func TestTheDLPPatternIsRecoveredFromTheReasonWhenTheFieldIsMissing(t *testing.T) {
	p := &Live{}
	p.ingestLocal([]localLogLine{{
		At: 1_700_000_000_000, Tool: "Read", Decision: "DENY",
		Reason: "Security layer (DLP): blocked - arguments contain a GitHub token",
	}})
	if len(p.local) != 1 {
		t.Fatalf("ingested %d rows, want 1", len(p.local))
	}
	got := p.local[0].DLPNames
	if len(got) != 1 || got[0] != "GitHub token" {
		t.Fatalf("recovered %v from the reason, want [GitHub token]", got)
	}
}

// newLiveForTest mounts the console straight into its inspector on one row, so
// the test reads what a person sees after pressing enter.
func newLiveForTest(e streamItem) *Live {
	on := true
	p := &Live{}
	p.localOn = &on
	p.local = []streamItem{e}
	p.merged = []streamItem{e}
	p.mode = "inspect"
	p.inspect = &e
	return p
}
