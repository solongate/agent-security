// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"strings"
	"testing"
)

// Issue #200: "OpenAI key"'s regex (sk-(proj-)?[A-Za-z0-9_-]{20,}) also matches
// OpenRouter's sk-or-v1-<64 hex> shape, and it ran first, so OpenRouter keys
// were mislabeled. OpenRouter is now declared first, and the more specific
// pattern wins.
func TestDLPScanLabelsOpenRouterKeysCorrectly(t *testing.T) {
	secret := "sk-or-v1-" + strings.Repeat("a", 64)
	cfg := &DLPConfig{Patterns: DLPPatternNames()}
	hit := DLPScan(secret, cfg)
	if hit != "OpenRouter key" {
		t.Errorf("DLPScan(%q) = %q, want OpenRouter key", secret, hit)
	}
}

func TestDLPScanStillCatchesOpenAIKeys(t *testing.T) {
	secret := "sk-proj-" + strings.Repeat("b", 30)
	cfg := &DLPConfig{Patterns: DLPPatternNames()}
	if hit := DLPScan(secret, cfg); hit != "OpenAI key" {
		t.Errorf("DLPScan(%q) = %q, want OpenAI key", secret, hit)
	}
}

func TestDisablingOpenAIStillBlocksOpenRouterUnderItsOwnName(t *testing.T) {
	secret := "sk-or-v1-" + strings.Repeat("a", 64)
	cfg := &DLPConfig{Patterns: []string{"OpenRouter key"}}
	if hit := DLPScan(secret, cfg); hit != "OpenRouter key" {
		t.Errorf("got %q, want OpenRouter key (with OpenAI disabled)", hit)
	}
	if hit := DLPScan("sk-proj-"+strings.Repeat("b", 30), cfg); hit != "" {
		t.Errorf("OpenAI disabled but still matched: %q", hit)
	}
}
