package main

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/codeyevsky/solongate/sgshared"
)

// Everything on disk the guard reads, in the shapes the Node hook already
// writes. This port shares those files rather than inventing its own: both
// implementations have to be installable side by side while one is being
// verified against the other.

// loadCredential reads the paired credential, with one environment override
// that a managed machine does not get.
//
// SOLONGATE_API_KEY is how somebody points a machine at a different project
// while working on SolonGate itself, and it stays exactly that for everyone not
// in a fleet. For a guest it is an escape hatch and nothing else: the key IS
// the project selector, so exporting one of their own would have their guard
// enforce THEIR policy on a machine their host is answerable for, and nothing
// anywhere compared the two.
//
// managed is read from ~/.solongate/.fleet.json rather than from the policy
// cache, because the cache's filename is chosen by SOLONGATE_AGENT_ID and a
// fresh agent name would otherwise be a fresh unmanaged machine.
func loadCredential(managed bool) sgshared.Credential {
	var c sgshared.Credential
	b, err := os.ReadFile(filepath.Join(sgshared.SGDir(), "cloud-guard.json"))
	if err == nil {
		_ = json.Unmarshal(b, &c)
	}
	if env := os.Getenv("SOLONGATE_API_KEY"); !managed && sgshared.IsRealKey(env) {
		c.APIKey = env
	}
	if !sgshared.IsRealKey(c.APIKey) {
		c.APIKey = ""
	}
	// The default is THIS MACHINE, and that is not a preference.
	//
	// It was a hosted service, which is the wrong fallback for a program whose
	// ordinary deployment is local: a stray credential in a .env would have sent an
	// audit record to a host the person running this does not operate. README has
	// documented 127.0.0.1:3002 as the default all along — the port apps/system
	// listens on — so the code was the half that disagreed.
	if c.APIURL == "" {
		c.APIURL = "http://127.0.0.1:3002"
	}
	return c
}

func loadPolicyCache(agent string) *sgshared.PolicyCache {
	b, err := os.ReadFile(filepath.Join(sgshared.SGDir(), ".policy-cache-"+sgshared.AgentKey(agent)+".json"))
	if err != nil {
		return nil
	}
	var c sgshared.PolicyCache
	if err := json.Unmarshal(b, &c); err != nil {
		return nil
	}
	return &c
}

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
func loadLocalPolicyFile(cwd string, managed bool) *sgshared.PolicyCache {
	if managed {
		return nil
	}
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
		if json.Unmarshal(b, &probe) == nil && len(probe.Policy) > 0 && string(probe.Policy) != "null" {
			var e sgshared.PolicyCache
			if json.Unmarshal(b, &e) != nil || e.Policy == nil {
				continue
			}
			env = &e
		} else {
			var pol sgshared.Policy
			if json.Unmarshal(b, &pol) != nil {
				continue
			}
			env = &sgshared.PolicyCache{Policy: &pol}
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
