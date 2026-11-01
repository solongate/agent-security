// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package guardcore

import (
	"encoding/json"
	"errors"
	"fmt"
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

// ErrPolicyTampered is returned when the home policy.json cannot be shown to be
// the file SolonGate wrote: the signature is missing on a machine that has a
// signing key, does not verify against this machine's key, cannot be decoded,
// or cannot be checked at all. Every one of those cases used to fall through to
// "no verification required" and load the file anyway, which let anyone who
// could rewrite policy.json - or merely strip its signature - have an
// untrusted policy enforced. Project-local policy files are never
// signature-checked: LoadLocalPolicyFile already strips their Security/
// SelfProtect fields below, so they carry no trust to forge.
var ErrPolicyTampered = errors.New("policy.json failed signature verification: " +
	"it was modified outside SolonGate; refusing to trust it. " +
	"Fix: run `solongate policy create <name>` to make a new signed policy, " +
	"then `solongate policy allow/deny` to rebuild its rules. " +
	"Do not hand edit, cp, or restore policy.json from a backup, those stay unsigned")

// verifyHomePolicy fails closed: the only outcomes that let the home policy be
// applied are a signature that verifies against this machine's key, or an
// unsigned file on a machine that has no signing identity yet - a policy written
// before signatures existed. A key that exists but cannot be loaded, a signature
// that cannot be decoded, a signature that does not verify, and a stripped
// signature on a keyed machine are all treated as tampering.
func verifyHomePolicy(b []byte) error {
	dir := filepath.Join(shared.SGDir(), "crypto")
	if !pcrypto.HasKeyPair(dir) {
		// Reading a policy must not create keys. LoadOrCreateKeyPair would make
		// the first run key this install, and then its own unsigned policy would
		// be rejected on the second run.
		_, signed, _, verr := pcrypto.VerifyDocument(b, nil)
		switch {
		case signed:
			// Signed by something, and there is no key here to check it against.
			// That is not a legacy file, so it is not ours.
			return fmt.Errorf("%w (it carries a signature, but this machine has no signing key to check it with)", ErrPolicyTampered)
		case verr != nil:
			return fmt.Errorf("%w (it is not a readable policy document: %v)", ErrPolicyTampered, verr)
		}
		return nil
	}

	kp, err := pcrypto.LoadOrCreateKeyPair(dir)
	if err != nil {
		return fmt.Errorf("%w (the machine signing key could not be loaded: %v)", ErrPolicyTampered, err)
	}
	_, signed, valid, verr := pcrypto.VerifyDocument(b, kp.Public)
	switch {
	case verr != nil:
		return fmt.Errorf("%w (the signature could not be checked: %v)", ErrPolicyTampered, verr)
	case signed && !valid:
		return ErrPolicyTampered
	case !signed:
		return fmt.Errorf("%w (it carries no signature, and this machine already has a signing key)", ErrPolicyTampered)
	}
	return nil
}

func LoadLocalPolicyFile(cwd string) (*shared.PolicyCache, error) {
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
			if err := verifyHomePolicy(b); err != nil {
				return nil, err
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
