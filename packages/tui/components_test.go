// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package tui

import (
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
)

var hhmmssShape = regexp.MustCompile(`^\d{2}:\d{2}:\d{2}$`)
var ymdShape = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func TestHhmmss(t *testing.T) {
	if got := Hhmmss(0); got != "--:--:--" {
		t.Errorf("Hhmmss(0) = %q, want --:--:--", got)
	}
	if got := Hhmmss(-1); got != "--:--:--" {
		t.Errorf("Hhmmss(-1) = %q, want --:--:--", got)
	}
	got := Hhmmss(time.Now().UnixMilli())
	if !hhmmssShape.MatchString(got) {
		t.Errorf("Hhmmss(now) = %q, want HH:MM:SS shaped", got)
	}
}

func TestYmd(t *testing.T) {
	if got := ymd(0); got != "----------" {
		t.Errorf("ymd(0) = %q, want ----------", got)
	}
	if got := ymd(-1); got != "----------" {
		t.Errorf("ymd(-1) = %q, want ----------", got)
	}
	got := ymd(time.Now().UnixMilli())
	if !ymdShape.MatchString(got) {
		t.Errorf("ymd(now) = %q, want YYYY-MM-DD shaped", got)
	}
}

func TestPaneTitleIncludesLabelAndExtra(t *testing.T) {
	out := PaneTitle("Audit", "", 60)
	if !strings.Contains(out, "▎Audit") {
		t.Errorf("PaneTitle() = %q, want it to contain the label marker", out)
	}

	out = PaneTitle("Audit", "3 events", 60)
	if !strings.Contains(out, "3 events") {
		t.Errorf("PaneTitle() with extra = %q, want it to contain the extra text", out)
	}
}

func TestPaneTitleRespectsWidth(t *testing.T) {
	out := PaneTitle("A very long label that will not fit", "", 10)
	if w := lipgloss.Width(out); w > 10 {
		t.Errorf("PaneTitle() width = %d, want <= 10", w)
	}
}

func evalPtr(v float64) *float64 { return &v }

func TestStreamLineDefaultsAgentToDash(t *testing.T) {
	line := StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash"}, false, false, 200)
	if !strings.Contains(line, "-") {
		t.Errorf("StreamLine() with no agent = %q, want it to contain the \"-\" placeholder", line)
	}
}

func TestStreamLineNoEvalMsShowsPlaceholder(t *testing.T) {
	line := StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash"}, false, false, 200)
	if !strings.Contains(line, ", ") {
		t.Errorf("StreamLine() with nil EvalMs = %q, want the \", \" placeholder", line)
	}
}

func TestStreamLineFormatsEvalMs(t *testing.T) {
	line := StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash", EvalMs: evalPtr(12.5)}, false, false, 200)
	if !strings.Contains(line, "12.5ms") {
		t.Errorf("StreamLine() with EvalMs=12.5 = %q, want it to contain 12.5ms", line)
	}
}

func TestStreamLineDLPAndBurstFlags(t *testing.T) {
	line := StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash", DLP: true, Burst: true}, false, false, 200)
	if !strings.Contains(line, "dlp:yes") || !strings.Contains(line, "rl:yes") {
		t.Errorf("StreamLine() with DLP+Burst = %q, want dlp:yes and rl:yes", line)
	}
	line = StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash"}, false, false, 200)
	if !strings.Contains(line, "dlp:no") || !strings.Contains(line, "rl:no") {
		t.Errorf("StreamLine() without DLP/Burst = %q, want dlp:no and rl:no", line)
	}
}

func TestStreamLineOmitsRuleWhenAllowed(t *testing.T) {
	line := StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash", Rule: "no-rm-rf", Detail: "ok"}, false, false, 200)
	if strings.Contains(line, "no-rm-rf") {
		t.Errorf("StreamLine() for an ALLOW decision = %q, want the rule omitted", line)
	}
}

func TestStreamLineIncludesRuleWhenDenied(t *testing.T) {
	line := StreamLine(StreamRow{Decision: "DENY", Tool: "bash", Rule: "no-rm-rf", Detail: "blocked"}, false, false, 200)
	if !strings.Contains(line, "no-rm-rf") {
		t.Errorf("StreamLine() for a DENY decision = %q, want the rule included", line)
	}
}

func TestStreamLineDateFlagAddsDate(t *testing.T) {
	at := time.Now().UnixMilli()
	withoutDate := StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash", At: at}, false, false, 200)
	withDate := StreamLine(StreamRow{Decision: "ALLOW", Tool: "bash", At: at}, false, true, 200)
	if lipgloss.Width(withDate) <= lipgloss.Width(withoutDate) {
		t.Errorf("StreamLine(date=true) width = %d, want it wider than date=false (%d)",
			lipgloss.Width(withDate), lipgloss.Width(withoutDate))
	}
}

func TestDataViewPriority(t *testing.T) {
	body := []string{"row1", "row2"}

	if out := DataView(true, errors.New("boom"), false, "", 80, body); len(out) != 1 || !strings.Contains(out[0], "boom") {
		t.Errorf("DataView() with an error = %v, want a single line mentioning the error", out)
	}
	if out := DataView(true, nil, false, "", 80, body); len(out) != 1 || !strings.Contains(out[0], "loading") {
		t.Errorf("DataView() while loading = %v, want a single loading line", out)
	}
	if out := DataView(false, nil, true, "", 80, body); len(out) != 1 || !strings.Contains(out[0], "No data.") {
		t.Errorf("DataView() empty with no custom text = %v, want the default \"No data.\"", out)
	}
	if out := DataView(false, nil, true, "Nothing here", 80, body); len(out) != 1 || !strings.Contains(out[0], "Nothing here") {
		t.Errorf("DataView() empty with custom text = %v, want the custom text", out)
	}
	out := DataView(false, nil, false, "", 80, body)
	if len(out) != len(body) || out[0] != body[0] || out[1] != body[1] {
		t.Errorf("DataView() with data = %v, want the body passed through unchanged (%v)", out, body)
	}
}

func TestKeyHintsJoinsPairsWithSeparator(t *testing.T) {
	out := keyHints([][2]string{{"↑/↓", "move"}, {"enter", "select"}}, 200)
	if !strings.Contains(out, "↑/↓") || !strings.Contains(out, "move") {
		t.Errorf("keyHints() = %q, want it to contain the first hint", out)
	}
	if !strings.Contains(out, "enter") || !strings.Contains(out, "select") {
		t.Errorf("keyHints() = %q, want it to contain the second hint", out)
	}
	if !strings.Contains(out, "   ") {
		t.Errorf("keyHints() = %q, want hints separated by three spaces", out)
	}
}

func TestHelpBlockStructure(t *testing.T) {
	groups := []HelpGroup{
		{Title: "Navigation", Keys: [][2]string{{"up", "move up"}, {"down", "move down"}}},
		{Title: "Actions", Keys: [][2]string{{"q", "quit"}}},
	}
	out := HelpBlock(groups, 10, 200)

	wantLines := (1 + 2 + 1) + (1 + 1 + 1)
	if len(out) != wantLines {
		t.Fatalf("HelpBlock() produced %d lines, want %d", len(out), wantLines)
	}
	if !strings.Contains(out[0], "Navigation") {
		t.Errorf("HelpBlock() first line = %q, want the group title", out[0])
	}
	if !strings.Contains(out[1], "up") || !strings.Contains(out[1], "move up") {
		t.Errorf("HelpBlock() key line = %q, want the key and its description", out[1])
	}
	if out[3] != "" {
		t.Errorf("HelpBlock() group separator = %q, want a blank line between groups", out[3])
	}
}

func TestWhyBlockEmptyWhenNothingToShow(t *testing.T) {
	if out := WhyBlock("ALLOW", "", "", nil, false, 80); out != nil {
		t.Errorf("WhyBlock() with no reason/dlp/burst = %v, want nil", out)
	}
}

func TestWhyBlockBurstAndDLP(t *testing.T) {
	out := WhyBlock("DENY", "", "", []string{"credit card"}, true, 80)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "rate limit") || !strings.Contains(joined, "DLP: credit card") {
		t.Errorf("WhyBlock(burst+dlp) = %q, want both rate limit and DLP mentioned", joined)
	}
}

// TestWhyBlockRuleAloneIsRendered guards against a regression where WhyBlock
// dropped a DENY's rule entirely when reason, dlp, and burst were all unset.
func TestWhyBlockRuleAloneIsRendered(t *testing.T) {
	out := WhyBlock("DENY", "", "no-rm-rf", nil, false, 80)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "no-rm-rf") {
		t.Errorf("WhyBlock(rule only, no reason) = %q, want the rule mentioned", joined)
	}
}

func TestWhyBlockRuleWithReasonIncludesBoth(t *testing.T) {
	out := WhyBlock("DENY", "blocked", "no-rm-rf", nil, false, 80)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "rule") || !strings.Contains(joined, "no-rm-rf") {
		t.Errorf("WhyBlock(rule+reason) = %q, want the rule mentioned", joined)
	}
	if !strings.Contains(joined, "blocked") {
		t.Errorf("WhyBlock(rule+reason) = %q, want the reason mentioned too", joined)
	}
}

func TestWhyBlockReasonOnly(t *testing.T) {
	out := WhyBlock("DENY", "because the path is protected", "", nil, false, 80)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "because the path is protected") {
		t.Errorf("WhyBlock(reason only) = %q, want the reason included even with no \"what\"", joined)
	}
}

func TestWhyBlockAllowFlaggedByBurstOrDLP(t *testing.T) {
	out := WhyBlock("ALLOW", "", "", []string{"secret"}, false, 80)
	joined := strings.Join(out, "\n")
	if !strings.Contains(joined, "flagged") {
		t.Errorf("WhyBlock(ALLOW but dlp-flagged) = %q, want the \"flagged\" key", joined)
	}
}

func TestWhyColor(t *testing.T) {
	cases := []struct {
		name     string
		decision string
		burst    bool
		dlp      []string
		want     lipgloss.TerminalColor
	}{
		{"plain allow is dim", " allow ", false, nil, Theme.Dim},
		{"flagged allow is warn (burst)", "ALLOW", true, nil, Theme.Warn},
		{"flagged allow is warn (dlp)", "ALLOW", false, []string{"x"}, Theme.Warn},
		{"deny is bad", "DENY", false, nil, Theme.Bad},
		{"anything else is bad", "weird", false, nil, Theme.Bad},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := WhyColor(tc.decision, tc.burst, tc.dlp); got != tc.want {
				t.Errorf("WhyColor(%q, %v, %v) = %v, want %v", tc.decision, tc.burst, tc.dlp, got, tc.want)
			}
		})
	}
}