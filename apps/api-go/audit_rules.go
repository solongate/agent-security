package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/policycompile"
	"github.com/codeyevsky/solongate/api/internal/policyjson"
	"github.com/codeyevsky/solongate/api/internal/store"
)

// /api/v1/audit-logs/{id}/block and /whitelist — turning one entry in the
// audit log into a policy rule.
//
// They are symmetric: whitelist takes a DENY and adds an ALLOW so the call
// stops being refused; block takes an ALLOW and adds a DENY so it starts being.
// Both write a NEW policy version rather than editing one, because
// policy_versions is append-only and the version history is what /rollback is
// built on.
//
// Both authenticate on an API key, and the project is the key's. There used to
// be a second path here: an `x-manage-admin` header matching a shared secret let
// a hosted admin console act on ANY project, taking the project id from the
// request body. It was the one place in this service where a caller named the
// tenant it was writing to, and it is gone along with the console that called
// it — a cross-tenant policy write behind a single env var is not something to
// leave in a build nobody is operating that console for.

func init() {
	Register("POST /api/v1/audit-logs/{id}/block", buildAuditBlock)
	Register("POST /api/v1/audit-logs/{id}/whitelist", buildAuditWhitelist)
}

// grantKind is which of the two routes is running. The pair differ in more than
// the effect they write — see findDuplicate — so this is a mode rather than a
// string substitution.
type grantKind int

const (
	grantDeny grantKind = iota
	grantAllow
)

func (g grantKind) effect() string {
	if g == grantDeny {
		return "DENY"
	}
	return "ALLOW"
}

func (g grantKind) rulePrefix() string {
	if g == grantDeny {
		return "deny-"
	}
	return "allow-"
}

func (g grantKind) description() string {
	if g == grantDeny {
		return "Human-blocked from audit log"
	}
	return "Human-approved from audit log"
}

func (g grantKind) dedupeMessage() string {
	if g == grantDeny {
		return "Equivalent DENY rule already present — policy unchanged."
	}
	return "Equivalent ALLOW rule already present — policy unchanged."
}

func (g grantKind) reasonVerb() string {
	if g == grantDeny {
		return "Block"
	}
	return "Whitelist"
}

func buildAuditBlock(s *server) http.Handler     { return s.grantHandler(grantDeny) }
func buildAuditWhitelist(s *server) http.Handler { return s.grantHandler(grantAllow) }

type grantBody struct {
	Scope string `json:"scope"`
}

func (s *server) grantHandler(kind grantKind) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditID := r.PathValue("id")

		// An unreadable body is an empty one, which is what the route has always
		// done: the only field in it is optional.
		var body grantBody
		if !apiauth.DecodeJSON(w, r, &body, true) {
			return
		}
		scope := "exact"
		if body.Scope == "tool" {
			scope = "tool"
		}

		s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
			s.doGrant(w, r.Context(), kind, auditID, scope, key.ProjectID, key.OwnerID)
		}).ServeHTTP(w, r)
	})
}

// grantResponse is the body both routes answer with. The two shapes the live
// route returns differ only in which trailing fields are present, which is what
// omitempty gives here.
type grantResponse struct {
	OK            bool            `json:"ok"`
	Deduped       bool            `json:"deduped"`
	Rule          json.RawMessage `json:"rule"`
	Scope         string          `json:"scope"`
	PolicyID      string          `json:"policy_id"`
	PolicyVersion int64           `json:"policy_version,omitempty"`
	OpaCompiled   *bool           `json:"opa_compiled,omitempty"`
	Message       string          `json:"message,omitempty"`
}

func (s *server) doGrant(w http.ResponseWriter, ctx context.Context, kind grantKind,
	auditID, scope, projectID, ownerID string) {

	audit, err := s.store.AuditLogByID(ctx, projectID, auditID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apiauth.Error(w, http.StatusNotFound, "ERROR", "Audit log entry not found")
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}

	// The precondition differs between the two, and not symmetrically: block
	// refuses an entry that is ALREADY denied, whitelist accepts only "DENY"
	// exactly — not "DENIED". That asymmetry is the live route's and it is
	// reproduced rather than tidied, because an entry written as DENIED by an
	// older client is one somebody may already have decided not to allow here.
	if kind == grantDeny {
		if audit.Decision == "DENY" || audit.Decision == "DENIED" {
			apiauth.BadRequest(w, "Entry was already denied")
			return
		}
	} else if audit.Decision != "DENY" {
		apiauth.BadRequest(w, "Only DENY entries can be whitelisted")
		return
	}

	versions, err := s.store.PolicyVersionsForSelection(ctx, projectID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if len(versions) == 0 {
		apiauth.Error(w, http.StatusNotFound, "ERROR", "No policies exist in this project")
		return
	}
	latest := latestPerPolicyID(versions)

	// The same rule as GET /policies/active: an explicit "no active policy" is
	// not "pick something". A project that deliberately enforces nothing must
	// not have a rule granted into a policy the guard is not reading, because
	// the rule would appear to have been applied and would do nothing.
	override := s.store.ActivePolicyOverride(ctx, projectID)
	if override == store.ActivePolicyNone {
		apiauth.Error(w, http.StatusConflict, "ERROR",
			"No active policy — rule not added. Activate a policy first.")
		return
	}

	var picked *policyChoice
	if override != "" {
		if row, ok := latest.get(override); ok {
			picked = &policyChoice{policyID: override, data: row.PolicyData}
		}
	}
	if picked == nil {
		picked = pickPolicyForAgent(latest, audit.AgentID)
	}
	if picked == nil {
		apiauth.Error(w, http.StatusNotFound, "ERROR",
			"No active policy applies to this agent — rule not added.")
		return
	}

	policy, ok := policyjson.ParseObject(picked.data)
	if !ok {
		// A policy_data that is not an object is a row nothing can edit, and
		// answering 400 here would be blaming the caller's request for it.
		apiauth.Internal(w, "api", errors.New("policy_data is not a JSON object"))
		return
	}
	existingRules, _ := policyjson.Array(policy.Get("rules"))

	target := extractTarget(audit.ArgumentsSummary)
	// A request for an exact rule with nothing to be exact ABOUT becomes a
	// tool-wide rule. The alternative is a rule with no constraint that reads as
	// exact, which would block or allow far more than the person clicking meant.
	effectiveScope := scope
	if scope == "exact" && target == nil {
		effectiveScope = "tool"
	}

	if dup := findDuplicate(kind, existingRules, audit.ToolName, target, effectiveScope); dup != nil {
		apiauth.JSON(w, http.StatusOK, grantResponse{
			OK:       true,
			Deduped:  true,
			Rule:     json.RawMessage(policyjson.Stringify(dup, nil)),
			Scope:    effectiveScope,
			PolicyID: picked.policyID,
			Message:  kind.dedupeMessage(),
		})
		return
	}

	newRule := buildGrantRule(kind, audit.ToolName, target, effectiveScope)

	// `{...policy, rules: [newRule, ...rules]}`. Set keeps an existing key in
	// its POSITION, so a policy that already had a rules array comes back with
	// its fields in the order they were written — a policy whose keys shuffled
	// is a diff nobody made, and its hash would change with them.
	updatedPolicy := policy.Clone()
	updatedPolicy.Set("rules", append([]any{newRule}, existingRules...))
	updated := json.RawMessage(policyjson.Stringify(updatedPolicy, nil))

	hash := policyHash(updatedPolicy)
	nextVersion := latest.maxVersionOf(picked.policyID) + 1
	rego, wasm, compiled := compilePolicy(ctx, updated)

	// policy_versions.rego_source and wasm_bundle are added by the runtime
	// migrations rather than by drizzle, so this is where `await schemaReady`
	// went in the live route. It is a no-op after the first success.
	if err := s.store.EnsureRuntimeTables(ctx); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if err := s.store.InsertPolicyVersion(ctx, store.PolicyVersion{
		ID:         uuid.NewString(),
		ProjectID:  projectID,
		Version:    nextVersion,
		PolicyData: updated,
		Hash:       hash,
		Reason: kind.reasonVerb() + " from audit " + auditID +
			" (scope=" + effectiveScope + ", tool=" + audit.ToolName + ")",
		CreatedBy:  ownerID,
		RegoSource: rego,
		WasmBundle: wasm,
		CreatedAt:  store.Now(),
	}); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusOK, grantResponse{
		OK:            true,
		Deduped:       false,
		Rule:          json.RawMessage(policyjson.Stringify(newRule, nil)),
		Scope:         effectiveScope,
		PolicyID:      picked.policyID,
		PolicyVersion: nextVersion,
		OpaCompiled:   &compiled,
	})
}

// ── choosing the policy to write into ───────────────────────────────────────

type policyChoice struct {
	policyID string
	data     json.RawMessage
}

// policyIndex is the newest version of each distinct policy, in the order the
// rows arrived.
//
// The ORDER is load-bearing and is the reason this is not a Go map. The live
// app iterates a JavaScript Map, which preserves insertion order, and every
// tie-break in pickPolicyForAgent is a strict `>` — so on equal timestamps the
// FIRST policy inserted wins. Iterating a Go map here would pick a different
// policy on different requests for the same project, and the person clicking
// "allow this" would watch their rule land somewhere new each time.
type policyIndex struct {
	order []string
	rows  map[string]indexedPolicy
}

type indexedPolicy struct {
	store.ActivePolicyRow
	// id is policy_data.id, which is the policy's LOGICAL identity. It is not a
	// column: a policy id lives inside the JSON, and every version of one policy
	// shares it.
	id string
}

const anonymousPolicyID = "__anonymous__"

func latestPerPolicyID(rows []store.ActivePolicyRow) *policyIndex {
	idx := &policyIndex{rows: map[string]indexedPolicy{}}
	for _, row := range rows {
		id := policyDataID(row.PolicyData)
		key := id
		if key == "" {
			key = anonymousPolicyID
		}
		existing, seen := idx.rows[key]
		if seen && row.Version <= existing.Version {
			continue
		}
		if !seen {
			idx.order = append(idx.order, key)
		}
		idx.rows[key] = indexedPolicy{ActivePolicyRow: row, id: id}
	}
	return idx
}

func (p *policyIndex) get(key string) (store.ActivePolicyRow, bool) {
	row, ok := p.rows[key]
	return row.ActivePolicyRow, ok
}

// maxVersionOf is the highest version number belonging to one logical policy.
//
// The live app asks SQLite for it with json_extract over policy_data, which is
// a scan of every version in the project. The rows are already in hand here, so
// the same number comes out of memory — and it comes out the same way in the
// one odd case: an anonymous policy matches no row, MAX is NULL, and the next
// version is 1. That reuses a version number, which is what the live app does
// today and what the version history already contains.
func (p *policyIndex) maxVersionOf(policyID string) int64 {
	var max int64
	for _, row := range p.rows {
		if row.id == policyID && row.Version > max {
			max = row.Version
		}
	}
	return max
}

// policyDataID reads policy_data.id without decoding the policy.
func policyDataID(data json.RawMessage) string {
	var head struct {
		ID any `json:"id"`
	}
	if json.Unmarshal(data, &head) != nil {
		return ""
	}
	return jsString(head.ID)
}

// pickPolicyForAgent chooses which policy a granted rule joins: a policy whose
// own id IS the agent id, then one that names the agent, then a wildcard one.
//
// The `else if` in the wildcard branch is the live app's and is kept: a policy
// that matches the agent specifically is never also considered as the wildcard
// candidate, so a project whose only agent-specific policy loses the tie-break
// falls through to a DIFFERENT policy rather than to itself. Straightening that
// would move rules into a policy the live app would not have chosen.
func pickPolicyForAgent(idx *policyIndex, agentID string) *policyChoice {
	var direct, specific, wildcard *indexedPolicy
	var directKey, specificKey, wildcardKey string

	for _, key := range idx.order {
		row := idx.rows[key]
		if len(row.PolicyData) == 0 {
			continue
		}
		agents := policyAgents(row.PolicyData)

		if agentID != "" && row.id == agentID {
			if direct == nil || row.CreatedAt > direct.CreatedAt {
				r := row
				direct, directKey = &r, key
			}
			continue
		}
		matchesSpecific := agentID != "" && containsAgent(agents, agentID)
		matchesWildcard := containsAgent(agents, "*")

		switch {
		case matchesSpecific:
			if specific == nil || row.CreatedAt > specific.CreatedAt {
				r := row
				specific, specificKey = &r, key
			}
		case matchesWildcard:
			if wildcard == nil || row.CreatedAt > wildcard.CreatedAt {
				r := row
				wildcard, wildcardKey = &r, key
			}
		}
	}

	switch {
	case direct != nil:
		return &policyChoice{policyID: directKey, data: direct.PolicyData}
	case specific != nil:
		return &policyChoice{policyID: specificKey, data: specific.PolicyData}
	case wildcard != nil:
		return &policyChoice{policyID: wildcardKey, data: wildcard.PolicyData}
	}
	return nil
}

// containsAgent is a membership test on the policy's agent list.
func containsAgent(agents []string, want string) bool {
	for _, a := range agents {
		if a == want {
			return true
		}
	}
	return false
}

// policyAgents is the policy's agent list, defaulting to ["*"].
//
// An EMPTY list also means "*", which is the live app's `length > 0` test.
// Reading an empty list as "no agents" would make a policy that applies to
// everything look like one that applies to nothing.
func policyAgents(data json.RawMessage) []string {
	var head struct {
		Agents []string `json:"agents"`
	}
	if json.Unmarshal(data, &head) != nil || len(head.Agents) == 0 {
		return []string{"*"}
	}
	return head.Agents
}

// ── the rule ────────────────────────────────────────────────────────────────

// ruleTarget is what the new rule constrains: the command that ran, the file it
// touched, or the URL it fetched.
type ruleTarget struct {
	kind  string // command | filename | url
	value string
}

// extractTarget reads the target out of the stored arguments, in the live
// route's order of preference.
//
// The arguments column can be a TRUNCATED fragment — it is cut at 16384
// characters on write — so a parse failure is "no target", which downgrades an
// exact rule to a tool-wide one rather than failing the request. That is the
// live behaviour and the safer of the two: a tool-wide rule is visible in the
// policy, a silently-wrong exact rule is not.
func extractTarget(argumentsSummary string) *ruleTarget {
	if argumentsSummary == "" {
		return nil
	}
	var args map[string]any
	if json.Unmarshal([]byte(argumentsSummary), &args) != nil {
		return nil
	}

	if cmd := strings.TrimSpace(firstNonEmpty(jsString(args["command"]), jsString(args["cmd"]))); cmd != "" {
		return &ruleTarget{kind: "command", value: cmd}
	}
	if fp := strings.TrimSpace(firstNonEmpty(jsString(args["file_path"]), jsString(args["path"]))); fp != "" {
		// The BASENAME, not the path. A rule naming somebody's home directory
		// would not match the same file on another machine, and these rules are
		// project-wide.
		base := fp
		if i := strings.LastIndexAny(fp, `/\`); i >= 0 {
			if tail := fp[i+1:]; tail != "" {
				base = tail
			}
		}
		return &ruleTarget{kind: "filename", value: base}
	}
	if u := strings.TrimSpace(jsString(args["url"])); u != "" {
		return &ruleTarget{kind: "url", value: u}
	}
	return nil
}

func constraintKey(kind string) string {
	switch kind {
	case "command":
		return "commandConstraints"
	case "filename":
		return "filenameConstraints"
	default:
		return "urlConstraints"
	}
}

// buildGrantRule assembles the new rule, in the live literal's field order.
//
// priority 1 is not decoration: the generated Rego is a priority-ordered else
// chain, lower first, and the rules a policy is written with default to 100. A
// granted rule at 1 therefore wins over the broad rule that caused the entry —
// which is the entire point of clicking the button.
func buildGrantRule(kind grantKind, toolName string, target *ruleTarget, scope string) *policyjson.Object {
	pattern := toolName
	if pattern == "" {
		pattern = "*"
	}

	rule := policyjson.NewObject()
	rule.Set("id", kind.rulePrefix()+strconv.FormatInt(time.Now().UnixMilli(), 10))
	rule.Set("toolPattern", pattern)
	rule.Set("effect", kind.effect())
	rule.Set("priority", float64(1))
	rule.Set("enabled", true)
	rule.Set("description", kind.description()+" ("+scope+")")

	if scope != "tool" && target != nil {
		listKey := "denied"
		if kind == grantAllow {
			listKey = "allowed"
		}
		constraint := policyjson.NewObject()
		constraint.Set(listKey, []any{target.value})
		rule.Set(constraintKey(target.kind), constraint)
	}
	return rule
}

// findDuplicate returns the existing rule that already says this, or nil.
//
// The tool-scope test is DIFFERENT between the two routes and the difference is
// deliberate. Block asks whether a rule has no DENIED lists; whitelist asks
// whether it has no constraint objects at all. So a rule carrying only an
// `allowed` list counts as an unconstrained DENY for block's purposes and does
// not count as an unconstrained ALLOW for whitelist's. Making them agree would
// change which clicks are no-ops on policies that already exist.
func findDuplicate(kind grantKind, rules []any, toolName string, target *ruleTarget, scope string) *policyjson.Object {
	pattern := toolName
	if pattern == "" {
		pattern = "*"
	}

	for _, item := range rules {
		r, ok := item.(*policyjson.Object)
		if !ok {
			continue
		}
		if policyjson.Str(r.Get("effect")) != kind.effect() {
			continue
		}
		// `r.enabled === false` — only the literal false. A rule with no
		// `enabled` field is not disabled, and neither is one set to null.
		if enabled, isBool := r.Get("enabled").(bool); isBool && !enabled {
			continue
		}
		rulePattern := policyjson.Str(r.Get("toolPattern"))
		if rulePattern == "" {
			rulePattern = "*"
		}
		if rulePattern != pattern {
			continue
		}

		if scope == "tool" {
			if kind == grantDeny {
				// `!r.commandConstraints?.denied` for each of the three. An
				// EMPTY array is truthy in JavaScript, so `denied: []` counts as
				// having a denied list and is not an unconstrained rule.
				if !hasList(r, "commandConstraints", "denied") &&
					!hasList(r, "filenameConstraints", "denied") &&
					!hasList(r, "urlConstraints", "denied") {
					return r
				}
				continue
			}
			// Whitelist asks about the constraint OBJECTS, not their lists.
			if !policyjson.Truthy(r.Get("commandConstraints")) &&
				!policyjson.Truthy(r.Get("filenameConstraints")) &&
				!policyjson.Truthy(r.Get("urlConstraints")) {
				return r
			}
			continue
		}

		if target == nil {
			continue
		}
		listKey := "denied"
		if kind == grantAllow {
			listKey = "allowed"
		}
		if listContains(r, constraintKey(target.kind), listKey, target.value) {
			return r
		}
	}
	return nil
}

// hasList is `r[constraint]?.[list]` as a truthiness test, which is what the
// live check is: an empty array counts, a missing one does not.
func hasList(rule *policyjson.Object, constraint, list string) bool {
	c, ok := rule.Get(constraint).(*policyjson.Object)
	if !ok {
		return false
	}
	return policyjson.Truthy(c.Get(list))
}

// listContains is `r[constraint]?.[list]?.includes(value)`.
func listContains(rule *policyjson.Object, constraint, list, value string) bool {
	c, ok := rule.Get(constraint).(*policyjson.Object)
	if !ok {
		return false
	}
	items, ok := policyjson.Array(c.Get(list))
	if !ok {
		return false
	}
	for _, item := range items {
		if s, isStr := item.(string); isStr && s == value {
			return true
		}
	}
	return false
}

// policyHash is the stored hash of a policy version, quirk included.
//
// `computeHash(JSON.stringify(updated, Object.keys(updated).sort()))` — an
// ARRAY second argument to JSON.stringify is a property ALLOW-LIST applied at
// every level, not a sort. See internal/policyjson, which reproduces it, and
// which is used here rather than reimplemented so that a policy hashed by this
// route and the same policy hashed by POST /policies come out identical. They
// write to the same table.
func policyHash(policy *policyjson.Object) string {
	sum := sha256.Sum256([]byte(policyjson.Stringify(policy, policy.SortedKeys())))
	return hex.EncodeToString(sum[:])
}

// ── compiling the new version ───────────────────────────────────────────────

// compilePolicy is internal/policycompile, and it is CALLED rather than
// reimplemented.
//
// There is exactly one json-to-rego generator in this repository that matters —
// the one apps/api compiles every saved policy with, ported once into
// internal/policycompile and mirrored in packages/guard-go. A second copy here
// would be a second answer to "what does this rule do", and the two would
// disagree in ways that surface only as a rule somebody swears is not working.
//
// A failure is not fatal and does not fail the request. The live route stores
// NULL for both columns and answers `opa_compiled: false` whenever its own
// compiler returns null, which on a box without the OPA binary is always — so a
// policy version with no compiled forms is a state that already exists in this
// database. Nothing on the enforcement path reads these columns either: GET
// /policies/active serves the policy JSON and the guard compiles it locally.
func compilePolicy(ctx context.Context, policy json.RawMessage) (rego, wasm string, compiled bool) {
	res, ok := policycompile.Compile(ctx, policy)
	if !ok {
		return "", "", false
	}
	// WasmUnavailable keeps the Rego: /policies/{id}/rego is still worth
	// answering even when the bundle could not be built.
	return res.RegoSource, res.WasmBundleB64, true
}
