package proxy

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/core"
	"github.com/codeyevsky/solongate/sgpolicy"
	"github.com/codeyevsky/solongate/sgshared"
)

// sharedEvaluator is the MCP proxy decided by the SAME engine the guard hooks
// decide with.
//
// That sameness is the whole point and it used to be impossible: the engine
// lived in packages/guard-go, which is `package main` in its own module, so
// this runtime had the entire pipeline and nothing to put in the middle of it.
// It now lives in packages/sgpolicy and both import it, which means a rule
// cannot mean one thing to a hook and another to the proxy — there is one
// compiler, one set of extractors and one mode table.
//
// It compiles on LOAD rather than on every call. A proxy handles a stream of
// tool calls against one policy, and the compile is the expensive half (640µs
// against 14µs to decide), so paying it per call would be paying it for
// nothing.
type sharedEvaluator struct {
	mu     sync.RWMutex
	policy *sgshared.Policy
}

// NewSharedEvaluator returns an evaluator with no policy loaded.
//
// With none loaded it denies, and that is deliberate: an evaluator that allowed
// until someone remembered to call LoadPolicySet would make "the policy failed
// to load" indistinguishable from "the policy permits this".
func NewSharedEvaluator() *sharedEvaluator { return &sharedEvaluator{} }

func (e *sharedEvaluator) LoadPolicySet(ps core.PolicySet) error {
	// Round-tripping through JSON rather than mapping field by field: the engine
	// reads the rules as raw JSON precisely so a field this binary does not know
	// about survives, and hand-mapping would quietly drop whatever the API
	// added since this version was built.
	rules, err := json.Marshal(ps.Rules)
	if err != nil {
		return err
	}
	mode := "denylist"
	if m := policySetMode(ps); m != "" {
		mode = m
	}
	e.mu.Lock()
	e.policy = &sgshared.Policy{ID: ps.ID, Name: ps.Name, Mode: mode, Rules: rules}
	e.mu.Unlock()
	return nil
}

// policySetMode reads the mode off a PolicySet.
//
// core.PolicySet has no Mode field — the MCP lineage never carried one — so a
// policy that arrived from the API keeps its mode in the rules payload. Reading
// it back is what stops a whitelist policy being enforced as a denylist here
// while the hooks enforce it correctly.
func policySetMode(ps core.PolicySet) string {
	raw, err := json.Marshal(ps)
	if err != nil {
		return ""
	}
	var probe struct {
		Mode string `json:"mode"`
	}
	if json.Unmarshal(raw, &probe) != nil {
		return ""
	}
	return probe.Mode
}

func (e *sharedEvaluator) Evaluate(req core.ExecutionRequest) core.PolicyDecision {
	started := time.Now()

	e.mu.RLock()
	pol := e.policy
	e.mu.RUnlock()

	decide := func(effect core.PolicyEffect, reason string) core.PolicyDecision {
		return core.PolicyDecision{
			Effect:           effect,
			Reason:           reason,
			Timestamp:        started.UTC().Format(time.RFC3339Nano),
			EvaluationTimeMs: float64(time.Since(started).Microseconds()) / 1000,
		}
	}

	if pol == nil {
		return decide(core.EffectDeny, "No policy loaded. Default action: DENY.")
	}

	// EvaluatePolicy returns the reason a call is blocked, or "" to allow it —
	// the same answer, from the same code, that the guard hook acts on.
	if reason := sgpolicy.EvaluatePolicy(pol, req.Arguments, req.ToolName, ""); reason != "" {
		return decide(core.EffectDeny, reason)
	}
	return decide(core.EffectAllow, "")
}
