// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"github.com/solongate/agent-security/packages/shared"
)

func dlpScanText(text string, cfg *shared.DLPConfig) []string {
	if cfg == nil || len(cfg.Patterns) == 0 || text == "" {
		return nil
	}
	enabled := make(map[string]bool, len(cfg.Patterns))
	for _, n := range cfg.Patterns {
		enabled[n] = true
	}
	var hits []string
	for i := 0; i < shared.DLPPatternCount(); i++ {
		name, re := shared.DLPPatternAt(i)
		if !enabled[name] {
			continue
		}
		if re.MatchString(text) {
			hits = append(hits, name)
			if len(hits) >= 5 {
				return hits
			}
		}
	}
	for _, c := range cfg.Custom {
		re, err := shared.GlobToRegexp(c.Re)
		if err != nil {
			continue
		}
		name := c.Name
		if name == "" {
			name = "custom"
		}
		if re.MatchString(text) {
			hits = append(hits, name)
			if len(hits) >= 5 {
				return hits
			}
		}
	}
	return hits
}

func loadDlpRedactCfg(sec *shared.Security) *shared.DLPConfig {
	if sec == nil {
		return nil
	}
	if sec.DLPRedact != nil {
		return sec.DLPRedact
	}
	return sec.DLPBlock
}

func loadDlpScanCfg(sec *shared.Security) *shared.DLPConfig {
	if sec == nil {
		return nil
	}
	if sec.DLPRedact != nil {
		return sec.DLPRedact
	}
	if sec.DLPBlock != nil {
		return sec.DLPBlock
	}
	return sec.DLPObserve
}