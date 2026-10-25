// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package ratelimit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

func TestRateLimitRecordWidth(t *testing.T) {
	if rlStamp != 13 {
		t.Errorf("rlStamp is %d; 13 is the digits in a millisecond epoch and will be until 2286", rlStamp)
	}
	if rlRecord != rlStamp+rlToken+1 {
		t.Errorf("rlRecord is %d, want stamp+token+newline = %d", rlRecord, rlStamp+rlToken+1)
	}

	if rlRecord != 24 {
		t.Errorf("rlRecord is %d; the Node twin computes 24 from 13 + 10 + 1", rlRecord)
	}
}

func TestRateLimitWindowsAreOrderedWidestFirst(t *testing.T) {

	if len(rlWindows) != 3 {
		t.Fatalf("expected three windows, got %d", len(rlWindows))
	}
	for i := 1; i < len(rlWindows); i++ {
		if rlWindows[i-1].Ms <= rlWindows[i].Ms {
			t.Errorf("window %q (%d ms) is not wider than %q (%d ms)",
				rlWindows[i-1].Key, rlWindows[i-1].Ms, rlWindows[i].Key, rlWindows[i].Ms)
		}
	}
	if rlWindows[0].Ms != dayMs || dayMs != 86400000 {
		t.Errorf("the widest window is %d ms, want a day", rlWindows[0].Ms)
	}
}

func TestRlLimitFor(t *testing.T) {
	r := &shared.RateLimit{PerMinute: 1, PerHour: 2, PerDay: 3}
	for key, want := range map[string]int{"perMinute": 1, "perHour": 2, "perDay": 3} {
		if got := rlLimitFor(r, key); got != want {
			t.Errorf("rlLimitFor(%q)=%d, want %d", key, got, want)
		}
	}

	if got := rlLimitFor(r, "perFortnight"); got != 0 {
		t.Errorf("an unknown window returned %d; it must be 0", got)
	}
	for _, w := range rlWindows {
		if rlLimitFor(&shared.RateLimit{PerMinute: 7, PerHour: 7, PerDay: 7}, w.Key) == 0 {
			t.Errorf("window %q is in rlWindows and rlLimitFor does not know it, so it is never enforced", w.Key)
		}
	}
}

func TestRlNewTokenIsTheRecordWidth(t *testing.T) {

	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		tok := rlNewToken()
		if len(tok) != rlToken {
			t.Fatalf("token %q is %d characters, want %d", tok, len(tok), rlToken)
		}
		if strings.ContainsAny(tok, "\n\r ") {
			t.Fatalf("token %q contains whitespace, which would break the fixed width", tok)
		}
		seen[tok] = true
	}

	if len(seen) < 190 {
		t.Errorf("200 tokens produced only %d distinct values", len(seen))
	}
}

func TestRateLimitCheckCountsAndRefuses(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	limits := &shared.RateLimit{Mode: "block", PerMinute: 3}
	agent := "test-agent"

	var refusals []string
	for i := 0; i < 6; i++ {
		if r := Check(agent, limits); r != "" {
			refusals = append(refusals, r)
		}
	}

	if len(refusals) != 3 {
		t.Fatalf("a limit of 3 over 6 calls refused %d; want 3. refusals: %v", len(refusals), refusals)
	}
	if !strings.Contains(refusals[0], "minute") {
		t.Errorf("the refusal does not name the window that was exceeded: %q", refusals[0])
	}

	var logs []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err == nil && info != nil && !info.IsDir() && strings.Contains(p, "ratelimit") {
			logs = append(logs, p)
		}
		return nil
	})
	if len(logs) == 0 {
		t.Fatal("no counter file was written, so nothing was counted")
	}
	for _, f := range logs {
		st, err := os.Stat(f)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size()%int64(rlRecord) != 0 {
			t.Errorf("%s is %d bytes, not a multiple of the %d-byte record", f, st.Size(), rlRecord)
		}
	}
}

func TestRateLimitCheckWithNoLimitsAllowsEverything(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	for _, limits := range []*shared.RateLimit{
		nil,
		{Mode: "block"},
		{Mode: "block", PerMinute: 0, PerHour: 0, PerDay: 0},
	} {
		for i := 0; i < 5; i++ {
			if r := Check("no-limit-agent", limits); r != "" {
				t.Fatalf("a zero limit refused a call: %q", r)
			}
		}
	}
}

func TestRateLimitPerAgentCountersDoNotShare(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)

	limits := &shared.RateLimit{Mode: "block", PerMinute: 2}

	for _, agent := range []string{"agent-a", "agent-b"} {
		for i := 0; i < 2; i++ {
			if r := Check(agent, limits); r != "" {
				t.Errorf("%s call %d was refused under its own limit of 2: %q", agent, i+1, r)
			}
		}
	}
	if r := Check("agent-a", limits); r == "" {
		t.Error("agent-a's third call was allowed under a limit of 2")
	}
}