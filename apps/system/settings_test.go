package main

import (
	"testing"
)

// The settings slice's tests.
//
// They cover the coercions rather than the SQL, because the coercions are where
// this slice can be wrong in a way that reads as working: a value stored a
// factor of ten out still saves and still lists.

// TestSettingsRoutesAreClaimed is the first thing to fail if a method is
// dropped in a merge. Every path in the table under /v1/settings has to be
// served by this slice; a stub left behind answers 501 to a dashboard that has
// no other way to reach the setting.
func TestSettingsRoutesAreClaimed(t *testing.T) {
	for _, rt := range routes {
		if len(rt.path) < 17 || rt.path[:17] != "/api/v1/settings/" {
			continue
		}
		for _, m := range rt.methods {
			if _, ok := routeHandlers[m+" "+rt.path]; !ok {
				t.Errorf("%s %s is still a stub", m, rt.path)
			}
		}
	}
}

// parseInt is not strconv.ParseInt, and a stricter reading would answer 400
// where the deployed dashboard gets a 200.
func TestJSParseInt10(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"1785697770423", 1785697770423, true},
		{"  42  ", 42, true},
		{"42abc", 42, true},
		{"-7", -7, true},
		{"+7", 7, true},
		{"0x10", 0, true}, // radix 10: parsing stops at the x
		{"", 0, false},
		{"abc", 0, false},
		{"-", 0, false},
		{"1e3", 1, true}, // parseInt does not read exponents
	}
	for _, c := range cases {
		got, ok := jsParseInt10(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("jsParseInt10(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// guard-status answers "is the guard registered", which is what `doctor` and
// `repair` answer. A device that reports a client list is believed about its own
// files; one that reports none falls back to the older "has called in" signal,
// so an un-updated machine degrades to a weaker answer rather than to "missing".
func TestGuardRegisteredPrefersTheReportedClients(t *testing.T) {
	devices := []guardDevice{
		{ID: "new", Clients: []string{"claude-code"}, Agents: map[string]int64{"codex": 5}},
		{ID: "old", Agents: map[string]int64{"antigravity": 9}},
	}

	if !guardRegistered(devices, "claude-code") {
		t.Error("a client in a device's reported list is registered")
	}
	if guardRegistered(devices, "codex") {
		t.Error("a device that reports its clients must not fall back to agents: the user removed codex")
	}
	if !guardRegistered(devices, "antigravity") {
		t.Error("a device with no reported list falls back to agents")
	}
	if guardRegistered(devices, "opencode") {
		t.Error("nothing reported opencode")
	}

	// last_seen comes from `agents` whatever `clients` says, and is null for a
	// client that is registered but has never run.
	if got := guardLastSeen(devices, "claude-code"); got != nil {
		t.Errorf("last_seen = %v, want null for a client that has not called in", got)
	}
	if got := guardLastSeen(devices, "antigravity"); got == nil || *got != 9 {
		t.Errorf("last_seen = %v, want 9", got)
	}
}
