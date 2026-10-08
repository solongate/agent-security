// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/solongate/agent-security/packages/sgshared"
)

// Everything on disk the guard reads, in the shapes the Node hook already
// writes. This port shares those files rather than inventing its own: both
// implementations have to be installable side by side while one is being
// verified against the other.

// loadCredential and loadPolicyCache lived here, and both are gone.
//
// loadCredential read ~/.solongate/cloud-guard.json, let SOLONGATE_API_KEY override it
// for anyone not in a fleet, filtered the result through IsRealKey so a malformed key
// could not be mistaken for a working one, and defaulted the URL to this machine. Its
// last consumer was accountMark, which hashed the key into an `acct` stamp on each
// local log line so a machine paired to two accounts could tell whose calls were
// whose. Nothing pairs and nothing read the stamp.
//
// loadPolicyCache read .policy-cache-<agent>.json. Nothing has written that file
// since the refresh was removed, and nothing called this — it was dead code reading a
// file that cannot exist.
//
// The Node hook dropped the identical pair at the same time (hooks/guard.mjs). Both
// read a file per call before any rule was evaluated.

// loadLocalPolicy is the fallback when the cloud cache holds no policy.
//
// A cache MISS is not only "the file is absent": a cache that parses but
// carries `policy: null` is the same thing, which is the state a machine is in
// on its first tool call after install, after the cache is cleared, or on a
// project whose cloud policy is unset. Without this the guard consults nothing
// at all in that window and allows everything, while the wizard's starter
// policy sits on disk unread.
//
// Order matches the Node hook: the wizard's ~/.solongate/policy.json first,
// then a per-project policy.json beside the working directory.
// A MANAGED machine reads neither of them. The second path is a file inside
// whatever repository the agent is working in, which is a file the agent can
// write: on a machine under somebody else's policy, "the cloud said nothing, so
// read the file in this checkout" is a one-line escape. A guest whose cache is
// empty enforces nothing local and waits for the cloud, which is what every
// machine did before a local policy existed.
// securityInsidePolicy pulls a `security` block out of a policy document.
//
// The second return is what separates "this document says nothing about the
// layers" from "this document turns everything off" — the same distinction
// store.SecurityLayersIn draws, and for the same reason: guessing a default here
// would quietly overwrite a configuration somebody wrote.
func securityInsidePolicy(doc []byte) (*sgshared.Security, bool) {
	if len(doc) == 0 {
		return nil, false
	}
	var probe struct {
		Security json.RawMessage `json:"security"`
	}
	if json.Unmarshal(doc, &probe) != nil || len(probe.Security) == 0 || string(probe.Security) == "null" {
		return nil, false
	}
	var sec sgshared.Security
	if json.Unmarshal(probe.Security, &sec) != nil {
		return nil, false
	}
	return &sec, true
}

// It answers a PolicyCache rather than a Policy because the file is allowed to
// be written in the shape the service answers in, and that shape carries the
// three things a machine with no service had no way to set at all: the rate
// limit, the egress rules and the DLP scanner arrive in `security`, and the
// tamper flag in `selfProtect`.
//
//	{"policy": {…}, "security": {…}, "selfProtect": true}   what the service sends
//	{"mode": "denylist", "rules": [ … ]}                     the policy on its own
//
// Both are accepted. A `policy` key is what tells them apart, so a bare policy
// keeps working and nobody has to rewrite a file that already exists.
// It took a `managed bool` and returned nil for a managed machine — no policy file at
// all, not even this machine's own. See main.go for why that is gone.
func loadLocalPolicyFile(cwd string) *sgshared.PolicyCache {
	if cwd == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}
	own := filepath.Join(sgshared.SGDir(), "policy.json")
	for _, p := range []string{own, filepath.Join(cwd, "policy.json")} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var env *sgshared.PolicyCache
		var probe struct {
			Policy json.RawMessage `json:"policy"`
		}
		// The PRESENCE of a `policy` key is what makes it the envelope, even when
		// its value is null — an absent key decodes to a nil RawMessage and a null
		// one to the four bytes "null", so the two are distinguishable here and
		// have to be. A file with layers and no rules is a real configuration (DLP
		// on, nothing forbidden), and requiring a non-null policy threw the whole
		// file away, layers included. The hook accepts it, so this has to.
		isEnvelope := json.Unmarshal(b, &probe) == nil && len(probe.Policy) > 0
		if isEnvelope {
			var e sgshared.PolicyCache
			if json.Unmarshal(b, &e) != nil {
				continue
			}
			// A policy DOCUMENT may carry `security` inside it — that is how the
			// service stores it (store.SecurityLayersIn reads exactly that), so
			// it is the shape a policy exported from one arrives in. Reading the
			// envelope only would make a hand-copied policy's DLP configuration
			// a silent no-op. The envelope wins when both are there: it is the
			// outer, more specific statement.
			if !e.HasSecurity {
				if inner, ok := securityInsidePolicy(probe.Policy); ok {
					e.Security, e.HasSecurity = inner, true
				}
			}
			env = &e
		} else {
			var pol sgshared.Policy
			if json.Unmarshal(b, &pol) != nil {
				continue
			}
			env = &sgshared.PolicyCache{Policy: &pol}
			if inner, ok := securityInsidePolicy(b); ok {
				env.Security, env.HasSecurity = inner, true
			}
		}
		// Only THIS MACHINE's own file is trusted with more than rules. The
		// second path is a file inside whatever repository the agent is working
		// in, which is a file the agent can write: `selfProtect: false` there
		// would be a one-line disarm of the tamper guard, and a `security` block
		// would switch the DLP scanner off from inside the checkout. It may add
		// rules, and nothing else.
		if p != own {
			env.Security, env.HasSecurity, env.SelfProtect = nil, false, nil
		}
		return env
	}
	return nil
}
