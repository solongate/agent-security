// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	pcrypto "github.com/solongate/agent-security/packages/crypto"
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

// errPolicyTampered is returned when the home policy.json carries a
// signature that fails verification against this machine's recorded key -
// a direct rewrite that bypassed SolonGate entirely. Project-local policy
// files are never signature-checked: loadLocalPolicyFile already strips
// their Security/SelfProtect fields below, so they carry no trust to forge.
var errPolicyTampered = errors.New("policy.json failed signature verification: " +
	"it was modified outside SolonGate; refusing to trust it")

func loadLocalPolicyFile(cwd string) (*shared.PolicyCache, error) {
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
		if p == own {
			kp, kerr := pcrypto.LoadOrCreateKeyPair(filepath.Join(shared.SGDir(), "crypto"))
			if kerr == nil {
				if _, signed, valid, verr := pcrypto.VerifyDocument(b, kp.Public); verr == nil && signed && !valid {
					return nil, errPolicyTampered
				}
			}
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
		return env, nil
	}
	return nil, nil
}