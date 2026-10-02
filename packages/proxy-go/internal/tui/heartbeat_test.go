package tui

import "testing"

// THE HEARTBEAT TRACE ADVANCES WITH THE CLOCK, NOT WITH THE DATA.
//
// The chart used to be drawn straight from `eval`, which gains an entry per decision. On
// a machine nobody was driving it was a still picture under a live console — and a still
// picture is what a hung program looks like, so the one pane that should answer "is this
// running?" was the pane that could not.
func TestTheTraceMovesWhileNothingIsHappening(t *testing.T) {
	p := &Live{}

	for i := 0; i < 5; i++ {
		p.beat()
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
	p.beat()
	if len(p.pulse) != 1 || p.pulse[0] != 42 {
		t.Fatalf("pulse = %v, want the 42ms decision in the first sample", p.pulse)
	}

	// CONSUMED, not carried. A sample that kept its value would draw a plateau for as
	// long as the machine stayed idle, which reads as a guard permanently taking 42ms.
	p.beat()
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
	p.beat()
	if p.pulse[0] != 95 {
		t.Errorf("a tick holding 12, 95 and 14ms reported %d, want the slowest", p.pulse[0])
	}
}

// The trace is bounded, or a console left open overnight grows without limit.
func TestTheTraceDoesNotGrowForever(t *testing.T) {
	p := &Live{}
	for i := 0; i < 1000; i++ {
		p.beat()
	}
	if len(p.pulse) > 400 {
		t.Errorf("after 1000 ticks the trace holds %d samples, which is unbounded growth "+
			"in a view people leave running", len(p.pulse))
	}
}
