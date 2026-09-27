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
	if c.APIURL == "" {
		c.APIURL = "https://api.solongate.com"
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
func loadLocalPolicy(cwd string, managed bool) *sgshared.Policy {
	if managed {
		return nil
	}
	if cwd == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}
	for _, p := range []string{
		filepath.Join(sgshared.SGDir(), "policy.json"),
		filepath.Join(cwd, "policy.json"),
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var pol sgshared.Policy
		if json.Unmarshal(b, &pol) == nil {
			return &pol
		}
	}
	return nil
}
