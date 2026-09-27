package main

import (
	"io"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyeval"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/policysynth"
)

// POST /api/v1/policies/learn — the port of
// src/app/api/v1/policies/learn/route.ts.
//
// Learn Mode: read what this project's agents have actually been doing and
// propose a whitelist that would have allowed it. The generator is in
// internal/policysynth and the "what would this break" pass is the same
// estimator the dry-run route uses, run against the same sample the rules were
// derived from — which is why the response calls it `self_consistent` rather
// than "safe". A rule set that blocks nothing in its own training data is the
// weakest possible statement about it, and the field says so by name.
//
// The route WRITES NOTHING. It is a proposal: no policy version, no rule row,
// no activation. Saving is a separate, deliberate POST to /v1/policies, which is
// the difference between "here is a policy you might want" and an endpoint that
// silently rewrites enforcement from traffic an attacker could have generated.
//
// It is project-scoped on the only side it has: the sample comes from the key's
// project and nothing in the body can widen it. `agent_id` narrows within that
// project and cannot escape it — see store.LearnSample.

func init() {
	Register("POST /api/v1/policies/learn", func(s *server) http.Handler {
		// RATE_LIMITS.validation, as the live route passes. Two hundred a minute
		// per key: this endpoint reads five thousand rows and synthesises over
		// them, so it is the most expensive thing a valid key can ask for in a
		// loop.
		return s.auth.WithAuthLimit(apiauth.LimitValidation, s.policiesLearn)
	})
}

// learnRuleView is a synthesised rule as the response carries it: the rule, then
// the two timestamps the original spreads on afterwards.
//
// Embedding rather than copying the fields keeps the KEY ORDER the original
// produces — id, description, effect, priority, toolPattern, permission,
// minimumTrustLevel, enabled, the constraint sets, then createdAt and updatedAt.
// The order is not cosmetic: a caller that saves this policy has its bytes
// hashed by POST /v1/policies, and a reordered object is a different hash for
// the same policy.
type learnRuleView struct {
	policysynth.Rule
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// learnPolicyView is the proposed policy. The id is the literal string
// "learned-policy" in the original — every response carries the same one,
// because this policy does not exist in the database and the dashboard uses the
// value as a react key rather than as an identifier.
type learnPolicyView struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Mode        string          `json:"mode"`
	Rules       []learnRuleView `json:"rules"`
}

// learnRuleMeta is where _sampleCount and _lowConfidence go now that they are
// off the rule. The page reads these to badge a rule that was learned from one
// or two calls.
type learnRuleMeta struct {
	ID            string `json:"id"`
	SampleCount   int    `json:"sampleCount"`
	LowConfidence bool   `json:"lowConfidence"`
}

// learnValidation is FIVE of the estimator's fields, not all of them. The
// original picks these by hand and the rest of the dry-run result is not in the
// response; adding them here would be inventing numbers the page has never
// shown.
type learnValidation struct {
	NewlyBlocked       int                 `json:"newly_blocked"`
	NewlyAllowed       int                 `json:"newly_allowed"`
	WouldDeny          int                 `json:"would_deny"`
	SampleNewlyBlocked []policyeval.Change `json:"sample_newly_blocked"`
	SelfConsistent     bool                `json:"self_consistent"`
}

type learnResponse struct {
	Tightness   string                  `json:"tightness"`
	Policy      learnPolicyView         `json:"policy"`
	RulesMeta   []learnRuleMeta         `json:"rules_meta"`
	Stats       policysynth.Stats       `json:"stats"`
	DenySummary []policysynth.DenyGroup `json:"deny_summary"`
	Validation  learnValidation         `json:"validation"`
}

func (s *server) policiesLearn(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	// `await request.json().catch(() => ({}))` — an absent, truncated or
	// malformed body is an EMPTY one here, not a 400. The dashboard's "learn"
	// button posts nothing at all, and every field below has a default.
	raw, _ := io.ReadAll(r.Body)
	body, _ := policyjson.ParseObject(raw)

	tightness := policysynth.ParseTightness(body.Get("tightness"))
	limit := learnLimit(body.Get("limit"))
	agentID := learnAgentID(body.Get("agent_id"))

	rows, err := s.store.LearnSample(r.Context(), key.ProjectID, agentID, limit)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// One parse of arguments_summary per row, shared by the synthesiser and the
	// estimator. The original parses it twice — once for each — and the two
	// parses cannot disagree, so this is the same input built once.
	synthInputs := make([]policysynth.Input, 0, len(rows))
	dryInputs := make([]policyeval.Input, 0, len(rows))
	for _, row := range rows {
		var args *policyjson.Object
		if row.ArgumentsSummary != "" {
			// A summary that will not parse is null args, not an error. The column
			// is truncated on write, so a fragment is an expected state of it.
			if parsed, isObj := policyjson.ParseObject([]byte(row.ArgumentsSummary)); isObj {
				args = parsed
			}
		}
		permission := policyFirstNonEmpty(row.Permission, "EXECUTE")
		trust := policyFirstNonEmpty(row.TrustLevel, "UNTRUSTED")

		synthInputs = append(synthInputs, policysynth.Input{
			Tool:       row.ToolName,
			Permission: permission,
			TrustLevel: trust,
			Decision:   row.Decision,
			Args:       args,
		})
		dryInputs = append(dryInputs, policyeval.Input{
			ID:         row.ID,
			Tool:       row.ToolName,
			Permission: permission,
			TrustLevel: trust,
			Args:       args,
			Decision:   row.Decision,
			// The column is UNIX seconds and everything downstream of
			// `new Date(x)` works in milliseconds; seconds here would date every
			// sample to 1970.
			CreatedAtMS: row.CreatedAt * 1000,
		})
	}

	synth := policysynth.Synthesize(synthInputs, tightness)
	denySummary := policysynth.SummarizeDenies(synthInputs)

	// The candidate policy replayed against the sample it came from. `whitelist`
	// is hard-coded in the original, and it has to be: the proposed rules are all
	// ALLOWs, so evaluating them as a denylist would report that nothing changes
	// no matter what the rules say.
	validation := policyeval.RunDryRun(learnEvalRules(synth.Rules), policyeval.ModeWhitelist, dryInputs)

	// `new Date().toISOString()` once, so every rule in one response carries the
	// same stamp. Milliseconds are real rather than .000, which is what
	// toISOString writes and what store.ISO cannot give — that one renders a
	// stored second.
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	out := learnResponse{
		Tightness: tightness,
		Policy: learnPolicyView{
			ID:          "learned-policy",
			Name:        "Learned policy (" + tightness + ")",
			Description: "Generated by Learn Mode from the last " + strconv.Itoa(len(rows)) + " calls",
			Mode:        "whitelist",
			Rules:       make([]learnRuleView, 0, len(synth.Rules)),
		},
		RulesMeta:   make([]learnRuleMeta, 0, len(synth.Rules)),
		Stats:       synth.Stats,
		DenySummary: denySummary,
		Validation: learnValidation{
			NewlyBlocked:       validation.NewlyBlocked,
			NewlyAllowed:       validation.NewlyAllowed,
			WouldDeny:          validation.WouldDeny,
			SampleNewlyBlocked: validation.SampleNewlyBlocked,
			// `newly_blocked === 0`: every call in the sample that was allowed is
			// still allowed by the proposed rules. It says nothing about calls the
			// sample does not contain, which is the whole risk of Learn Mode.
			SelfConsistent: validation.NewlyBlocked == 0,
		},
	}
	for _, rule := range synth.Rules {
		out.Policy.Rules = append(out.Policy.Rules, learnRuleView{Rule: rule, CreatedAt: now, UpdatedAt: now})
		out.RulesMeta = append(out.RulesMeta, learnRuleMeta{
			ID: rule.ID, SampleCount: rule.SampleCount, LowConfidence: rule.LowConfidence,
		})
	}

	apiauth.JSON(w, http.StatusOK, out)
}

// learnLimit is `Math.min(Math.max(Number(body.limit) || 1000, 1), 5000)`.
//
// The `|| 1000` swallows both NaN and zero, so `limit: 0` samples a thousand
// rows rather than none — the same reading POST /policies/dry-run applies to the
// same expression. The ceiling is what keeps this endpoint from being a way to
// stream audit_logs with a valid key.
func learnLimit(v any) int {
	if n, ok := policyJSNumber(v); ok && n != 0 && !math.IsNaN(n) {
		return int(math.Min(math.Max(n, 1), 5000))
	}
	return 1000
}

// learnAgentID is `body.agent_id ? String(body.agent_id) : null`.
//
// A truthy value that has no useful string form — an object, an array — becomes
// the string JavaScript would have produced, which matches no agent and returns
// an empty sample. The alternative, treating it as absent, would drop the filter
// and answer with the whole project's history for a request that asked for one
// agent's.
func learnAgentID(v any) string {
	if !policyjson.Truthy(v) {
		return ""
	}
	if s := jsString(v); s != "" {
		return s
	}
	return "[object Object]"
}

// learnEvalRules is the original's mapping of a synthesised rule onto the
// estimator's rule shape. It is a direct construction rather than a round trip
// through JSON: the fields are the same nine the original copies by name.
func learnEvalRules(rules []policysynth.Rule) []policyeval.Rule {
	out := make([]policyeval.Rule, 0, len(rules))
	for _, r := range rules {
		er := policyeval.Rule{
			ID:                r.ID,
			Effect:            r.Effect,
			Enabled:           r.Enabled,
			Priority:          float64(r.Priority),
			ToolPattern:       r.ToolPattern,
			MinimumTrustLevel: r.MinimumTrustLevel,
			Path:              learnConstraint(r.PathConstraints),
			Command:           learnConstraint(r.CommandConstraints),
			URL:               learnConstraint(r.URLConstraints),
		}
		// `if (rule.permission)` — a synthesised rule always has one, and the
		// truthiness test is kept so an empty permission would leave the rule
		// unscoped by permission rather than scoped to "".
		if r.Permission != "" {
			er.HasPermission = true
			er.Permissions = []string{r.Permission}
		}
		out = append(out, er)
	}
	return out
}

// learnConstraint carries "the rule has no such constraint" across, which the
// estimator reads as `if (!c) continue` — an absent constraint does not narrow
// the rule, an empty one would.
func learnConstraint(c *policysynth.Constraint) policyeval.ConstraintSet {
	if c == nil {
		return policyeval.ConstraintSet{}
	}
	return policyeval.ConstraintSet{Allowed: c.Allowed, Present: true}
}
