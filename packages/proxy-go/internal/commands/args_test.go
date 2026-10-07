// SPDX-License-Identifier: Apache-2.0

package commands

import "testing"

func TestParseSplitsFlagsFromPositionals(t *testing.T) {
	p := parse([]string{"allow", "pol-1", "--command", "curl *", "--json"})
	if got := p.positional(0); got != "allow" {
		t.Fatalf("positional 0 = %q", got)
	}
	if got := p.positional(1); got != "pol-1" {
		t.Fatalf("positional 1 = %q", got)
	}
	if got := p.flagStr("command"); got != "curl *" {
		t.Fatalf("--command = %q", got)
	}
	if !p.flagBool("json") {
		t.Fatal("a trailing --json is a boolean flag")
	}
}

func TestParseAcceptsEqualsForm(t *testing.T) {
	p := parse([]string{"--re=^sk-[a-z]+$", "--json=true"})
	if got := p.flagStr("re"); got != "^sk-[a-z]+$" {
		t.Fatalf("--re= lost its value: %q", got)
	}
	// A script writing its arguments out programmatically produces --json=true
	// rather than a bare flag, and it means the same thing.
	if !p.flagBool("json") {
		t.Fatal("--json=true must read as true")
	}
}

func TestFlagBeforeAnotherFlagIsBoolean(t *testing.T) {
	p := parse([]string{"--all", "--limit", "5"})
	if !p.flagBool("all") {
		t.Fatal("--all followed by another flag is boolean")
	}
	if got := p.flagNum("limit"); got != 5 {
		t.Fatalf("--limit = %d", got)
	}
	// A bare flag has no value, and reading one as the string "true" would send
	// a filter for a tool named true.
	if got := p.flagStr("all"); got != "" {
		t.Fatalf("a boolean flag has no string value, got %q", got)
	}
}

func TestFlagNumOKSeparatesAbsentFromZero(t *testing.T) {
	// This is the one that matters: `ratelimit set --minute oops` must not be
	// read as a limit of zero calls a minute, which would block every request on
	// the project from a typo.
	p := parse([]string{"set", "--minute", "oops"})
	if n, ok := p.flagNumOK("minute"); ok {
		t.Fatalf("an unparseable number must not count as given (got %d)", n)
	}
	p = parse([]string{"set", "--minute", "0"})
	if n, ok := p.flagNumOK("minute"); !ok || n != 0 {
		t.Fatalf("an explicit zero is a value: got %d, ok=%v", n, ok)
	}
	p = parse([]string{"set"})
	if _, ok := p.flagNumOK("minute"); ok {
		t.Fatal("an absent flag is not given")
	}
}

func TestRestJoinsRemainingPositionals(t *testing.T) {
	p := parse([]string{"create", "My", "Team", "Policy"})
	if got := p.rest(1); got != "My Team Policy" {
		t.Fatalf("a name with spaces must survive: %q", got)
	}
	if got := p.rest(9); got != "" {
		t.Fatalf("past the end is empty, got %q", got)
	}
}
