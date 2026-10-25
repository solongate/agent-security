// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package dlp

import (
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

func TestScanTextWithNilOrEmptyInputsReturnsNoHits(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"

	if hits := ScanText(secret, nil); hits != nil {
		t.Errorf("a nil config produced hits: %v", hits)
	}
	if hits := ScanText(secret, &shared.DLPConfig{}); hits != nil {
		t.Errorf("a config with no patterns produced hits: %v", hits)
	}
	if hits := ScanText("", dlpAll()); hits != nil {
		t.Errorf("empty text produced hits: %v", hits)
	}
}

func TestScanTextOnlyReportsEnabledPatterns(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"

	on := &shared.DLPConfig{Patterns: []string{"AWS access key"}}
	hits := ScanText(secret, on)
	if len(hits) != 1 || hits[0] != "AWS access key" {
		t.Errorf("an enabled pattern did not fire: %v", hits)
	}

	off := &shared.DLPConfig{Patterns: []string{"GitHub token"}}
	if hits := ScanText(secret, off); hits != nil {
		t.Errorf("a disabled pattern fired anyway: %v", hits)
	}
}

func TestScanTextCustomGlobPatterns(t *testing.T) {
	cfg := &shared.DLPConfig{
		Patterns: []string{"AWS access key"},
		Custom: []shared.DLPCustom{
			{Name: "", Re: "*COMPANYSECRET*"},
			{Name: "broken", Re: "["},
			{Name: "named", Re: "*OTHERSECRET*"},
		},
	}
	hits := ScanText("a COMPANYSECRET b OTHERSECRET c", cfg)

	found := map[string]bool{}
	for _, h := range hits {
		found[h] = true
	}
	if !found["custom"] {
		t.Errorf("the unnamed custom pattern did not report as 'custom': %v", hits)
	}
	if !found["named"] {
		t.Errorf("the named custom pattern lost its name: %v", hits)
	}
	if len(hits) != 2 {
		t.Errorf("got %d hits, want 2 (the broken pattern must be skipped): %v", len(hits), hits)
	}
}

func TestScanTextCustomPatternsFireEvenWithNoBuiltinPatternsEnabled(t *testing.T) {
	// Regression: a DLPConfig built from only custom rules (no built-in
	// Patterns entries) must still be scanned, the same way RedactText
	// already treats Custom independently of Patterns.
	cfg := &shared.DLPConfig{
		Custom: []shared.DLPCustom{{Name: "team key", Re: "*COMPANYSECRET*"}},
	}
	hits := ScanText("x COMPANYSECRET y", cfg)
	if len(hits) != 1 || hits[0] != "team key" {
		t.Errorf("a custom-only config produced %v, want a single 'team key' hit", hits)
	}
}

func TestScanTextCapsAtFiveHits(t *testing.T) {
	text := strings.Join([]string{
		"AKIA" + "IOSFODNN7EXAMPLE",                     // AWS access key, index 0
		"ghp_" + "ABCDEFGHIJ1234567890",                 // GitHub token, index 4
		"glpat-" + "ABCDEFGHIJ1234567890",               // GitLab token, index 6
		"xoxb-" + "1234567890123",                       // Slack token, index 7
		"sk_live_" + "ABCDEFGHIJ1234567890",             // Stripe key, index 8
		"npm_" + "ABCDEFGHIJ1234567890ABCDEFGHIJ123456", // npm token, index 11
	}, " ")

	hits := ScanText(text, dlpAll())
	if len(hits) != 5 {
		t.Fatalf("got %d hits, want the cap of 5: %v", len(hits), hits)
	}
	for _, name := range []string{"AWS access key", "GitHub token", "GitLab token", "Slack token", "Stripe key"} {
		found := false
		for _, h := range hits {
			if h == name {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %q among the first five pattern-order hits, got %v", name, hits)
		}
	}
	for _, h := range hits {
		if h == "npm token" {
			t.Errorf("the sixth match should have been cut off by the cap, but npm token is present: %v", hits)
		}
	}
}

func TestLoadRedactCfg(t *testing.T) {
	redact := &shared.DLPConfig{Patterns: []string{"redact"}}
	block := &shared.DLPConfig{Patterns: []string{"block"}}

	cases := []struct {
		name string
		sec  *shared.Security
		want *shared.DLPConfig
	}{
		{"nil security", nil, nil},
		{"only redact", &shared.Security{DLPRedact: redact}, redact},
		{"only block", &shared.Security{DLPBlock: block}, block},
		{"redact wins over block", &shared.Security{DLPRedact: redact, DLPBlock: block}, redact},
		{"neither set", &shared.Security{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LoadRedactCfg(c.sec); got != c.want {
				t.Errorf("LoadRedactCfg() = %p, want %p", got, c.want)
			}
		})
	}
}

func TestLoadScanCfg(t *testing.T) {
	redact := &shared.DLPConfig{Patterns: []string{"redact"}}
	block := &shared.DLPConfig{Patterns: []string{"block"}}
	observe := &shared.DLPConfig{Patterns: []string{"observe"}}

	cases := []struct {
		name string
		sec  *shared.Security
		want *shared.DLPConfig
	}{
		{"nil security", nil, nil},
		{"only redact", &shared.Security{DLPRedact: redact}, redact},
		{"only block", &shared.Security{DLPBlock: block}, block},
		{"only observe", &shared.Security{DLPObserve: observe}, observe},
		{"redact wins over block and observe", &shared.Security{DLPRedact: redact, DLPBlock: block, DLPObserve: observe}, redact},
		{"block wins over observe", &shared.Security{DLPBlock: block, DLPObserve: observe}, block},
		{"none set", &shared.Security{}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := LoadScanCfg(c.sec); got != c.want {
				t.Errorf("LoadScanCfg() = %p, want %p", got, c.want)
			}
		})
	}
}