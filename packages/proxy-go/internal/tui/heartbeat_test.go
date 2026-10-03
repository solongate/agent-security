package tui

import (
	"strings"
	"testing"
)

// THE HEARTBEAT TRACE ADVANCES WITH THE CLOCK, NOT WITH THE DATA.
//
// The chart used to be drawn straight from `eval`, which gains an entry per decision. On
// a machine nobody was driving it was a still picture under a live console — and a still
// picture is what a hung program looks like, so the one pane that should answer "is this
// running?" was the pane that could not.
func TestTheTraceMovesWhileNothingIsHappening(t *testing.T) {
	p := &Live{}

	for i := 0; i < 5; i++ {
		p.beat(int64(1_000 + i))
	}

	if len(p.pulse) != 5 {
		t.Fatalf("five ticks produced %d samples; an idle console draws no trace and "+
			"looks identical to a frozen one", len(p.pulse))
	}
	for i, v := range p.pulse {
		if v != 0 {
			t.Errorf("sample %d is %d; an idle tick has no decision to report", i, v)
		}
	}
}

// A decision seen between two ticks lands in the next sample, and only in that one.
func TestADecisionShowsUpOnceAndThenTheTraceGoesFlat(t *testing.T) {
	p := &Live{}

	p.pulsePending = 42
	p.beat(1_000)
	if len(p.pulse) != 1 || p.pulse[0] != 42 {
		t.Fatalf("pulse = %v, want the 42ms decision in the first sample", p.pulse)
	}

	// CONSUMED, not carried. A sample that kept its value would draw a plateau for as
	// long as the machine stayed idle, which reads as a guard permanently taking 42ms.
	p.beat(1_000)
	if len(p.pulse) != 2 || p.pulse[1] != 0 {
		t.Errorf("pulse = %v; the second tick should be flat, not a repeat of the first", p.pulse)
	}
}

// Several decisions inside one tick collapse to the WORST of them.
//
// At two ticks a second a busy machine puts several decisions in every column, and the
// slow one is the sample worth seeing — taking the last would hide a spike behind
// whatever happened to arrive after it.
func TestABusyTickReportsItsSlowestDecision(t *testing.T) {
	p := &Live{}
	for _, ms := range []int{12, 95, 14} {
		if ms > p.pulsePending {
			p.pulsePending = ms
		}
	}
	p.beat(1_000)
	if p.pulse[0] != 95 {
		t.Errorf("a tick holding 12, 95 and 14ms reported %d, want the slowest", p.pulse[0])
	}
}

// The trace is bounded, or a console left open overnight grows without limit.
func TestTheTraceDoesNotGrowForever(t *testing.T) {
	p := &Live{}
	for i := 0; i < 1000; i++ {
		p.beat(int64(1_000 + i))
	}
	if len(p.pulse) > 400 {
		t.Errorf("after 1000 ticks the trace holds %d samples, which is unbounded growth "+
			"in a view people leave running", len(p.pulse))
	}
}

// THE BEAT WRITES ITS NUMBERS DOWN, because the chart cannot carry them.
//
// A column of a certain height says "slower than the others" and nothing more: not how
// slow, and not whether the machine was busy or idle while it happened. Those are the two
// things worth knowing about a beat, so each one leaves a line saying the cost of the
// slowest decision in that second and how many calls there were to decide.
func TestEachBeatRecordsItsCostAndItsCalls(t *testing.T) {
	p := &Live{}

	// A second with three decisions, the slowest of them 95ms.
	p.pulsePending, p.pulseCalls = 95, 3
	p.beat(1_000)

	last := p.events[len(p.events)-1]
	if last.level != "beat" {
		t.Fatalf("the beat wrote a %q line, not a beat", last.level)
	}
	if !strings.Contains(last.msg, "95ms") {
		t.Errorf("the line is %q, with no cost in it", last.msg)
	}
	if !strings.Contains(last.msg, "3 call") {
		t.Errorf("the line is %q, with no call count in it", last.msg)
	}

	// AND A QUIET SECOND SAYS SO. An idle beat with a cost of zero would read as a
	// decision that took no time, which is a different and much more alarming claim.
	p.beat(2_000)
	if msg := p.events[len(p.events)-1].msg; msg != "idle" {
		t.Errorf("a second with no calls reported %q", msg)
	}

	// The counters are consumed, or the next second inherits this one's numbers.
	if p.pulsePending != 0 || p.pulseCalls != 0 {
		t.Errorf("after a beat the counters are %dms / %d calls, want both cleared",
			p.pulsePending, p.pulseCalls)
	}
}
