// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/solongate/agent-security/packages/shared"
)

func securityInsidePolicy(doc []byte) (*shared.Security, bool) {
	if len(doc) == 0 {
		return nil, false
	}
	var probe struct {
		Security json.RawMessage `json:"security"`
	}
	if json.Unmarshal(doc, &probe) != nil || len(probe.Security) == 0 || string(probe.Security) == "null" {
		return nil, false
	}
	var sec shared.Security
	if json.Unmarshal(probe.Security, &sec) != nil {
		return nil, false
	}
	return &sec, true
}

func loadLocalPolicyFile(cwd string) *shared.PolicyCache {
	if cwd == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}
	own := filepath.Join(shared.SGDir(), "policy.json")
	for _, p := range []string{own, filepath.Join(cwd, "policy.json")} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var env *shared.PolicyCache
		var probe struct {
			Policy json.RawMessage `json:"policy"`
		}

		isEnvelope := json.Unmarshal(b, &probe) == nil && len(probe.Policy) > 0
		if isEnvelope {
			var e shared.PolicyCache
			if json.Unmarshal(b, &e) != nil {
				continue
			}

			if !e.HasSecurity {
				if inner, ok := securityInsidePolicy(probe.Policy); ok {
					e.Security, e.HasSecurity = inner, true
				}
			}
			env = &e
		} else {
			var pol shared.Policy
			if json.Unmarshal(b, &pol) != nil {
				continue
			}
			env = &shared.PolicyCache{Policy: &pol}
			if inner, ok := securityInsidePolicy(b); ok {
				env.Security, env.HasSecurity = inner, true
			}
		}

		if p != own {
			env.Security, env.HasSecurity, env.SelfProtect = nil, false, nil
		}
		return env
	}
	return nil
}