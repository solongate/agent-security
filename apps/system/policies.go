package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policycompile"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// The policy endpoints: src/app/api/v1/policies/**.
//
// These are the routes with clients that will not be redeployed alongside this
// binary. The dashboard reads them, the CLI reads them, and — for
// /policies/active — every installed guard polls them on a loop. A response
// shape here is not an implementation detail; it is the interface a program on
// somebody else's laptop was compiled against.
//
// Three things in this file are contracts rather than choices, and each has its
// own note where it happens:
//
//   - policy_versions is APPEND-ONLY. Every write below inserts version N+1;
//     nothing updates a policy in place. That is what makes /versions and
//     /rollback possible and what makes a hash stable once it is issued.
//   - The HASH is SHA-256 over JavaScript's serialisation of the policy, which
//     is not Go's. internal/policyjson exists for that and the two spellings of
//     it here — with and without a property list — are both the live app's.
//   - The REGO is compiled with internal/policycompile, which is a
//     transcription of packages/guard-go/rego.go. A guard evaluating locally
//     and a guard evaluating this service's bundle have to reach the same
//     verdict, so those two files move together or not at all.

func init() {
	Register("GET /api/v1/policies", buildPolicyHandler((*server).policiesList))
	Register("POST /api/v1/policies", buildPolicyHandler((*server).policiesCreate))

	Register("GET /api/v1/policies/{id}", buildPolicyHandler((*server).policyGet))
	Register("PUT /api/v1/policies/{id}", buildPolicyHandler((*server).policyUpdate))
	Register("DELETE /api/v1/policies/{id}", buildPolicyHandler((*server).policyDelete))

	Register("POST /api/v1/policies/{id}/rules", buildPolicyHandler((*server).policyAddRule))
	Register("DELETE /api/v1/policies/{id}/rules/{ruleId}", buildPolicyHandler((*server).policyRevokeRule))

	Register("GET /api/v1/policies/{id}/versions", buildPolicyHandler((*server).policyVersions))
	Register("POST /api/v1/policies/{id}/rollback", buildPolicyHandler((*server).policyRollback))
	Register("GET /api/v1/policies/{id}/rego", buildPolicyHandler((*server).policyRego))

	Register("GET /api/v1/policies/active", buildPolicyHandler((*server).policyActiveGet))
	Register("POST /api/v1/policies/active", buildPolicyHandler((*server).policyActiveSet))

	// The two replay endpoints run at the VALIDATION limit rather than the
	// standard one, as the live app's `RATE_LIMITS.validation` argument does.
	// They are the expensive routes in this group — each one reads up to five
	// thousand audit rows — and they are also the ones the dashboard fires on
	// every keystroke in the rule editor, so the higher ceiling is deliberate
	// and not an oversight to tighten.
	Register("POST /api/v1/policies/dry-run", buildPolicyLimited(apiauth.LimitValidation, (*server).policyDryRun))
	Register("POST /api/v1/policies/backtest", buildPolicyLimited(apiauth.LimitValidation, (*server).policyBacktest))
}

// buildPolicyHandler wraps a method in withAuth at the standard limit. Every
// route in this group authenticates — there is no anonymous policy read — and
// the project every query is scoped to comes from the KEY, never from the
// request.
func buildPolicyHandler(fn func(*server, http.ResponseWriter, *http.Request, apiauth.KeyInfo)) func(*server) http.Handler {
	return buildPolicyLimited(apiauth.LimitStandard, fn)
}

func buildPolicyLimited(cfg apiauth.Config, fn func(*server, http.ResponseWriter, *http.Request, apiauth.KeyInfo)) func(*server) http.Handler {
	return func(s *server) http.Handler {
		return s.auth.WithAuthLimit(cfg, func(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
			fn(s, w, r, key)
		})
	}
}

// ── GET /api/v1/policies ────────────────────────────────────────────────────

func (s *server) policiesList(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	rows, err := s.store.ListPolicies(r.Context(), key.ProjectID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// Built as raw JSON rather than through a struct because `rules` is the
	// policy's own array, passed through untouched. Decoding it into a typed
	// rule would drop every field this version does not know about, and the
	// dashboard's rule editor round-trips what it reads straight back into a
	// PUT.
	var b strings.Builder
	b.WriteString(`{"policies":[`)
	for i, row := range rows {
		if i > 0 {
			b.WriteByte(',')
		}
		policy, _ := policyjson.ParseObject(row.PolicyData)

		entry := policyjson.NewObject()
		// `{id: policy.id, name: policy.name}` on a policy missing one of them
		// puts `undefined` there, which JSON.stringify OMITS. Emitting null
		// instead would hand the dashboard a policy whose name is the string
		// "null"; see policyFieldOrUndefined.
		entry.Set("id", policyFieldOrUndefined(policy, "id"))
		entry.Set("name", policyFieldOrUndefined(policy, "name"))
		if rules, ok := policyjson.Array(policy.Get("rules")); ok {
			entry.Set("rules", rules)
		} else {
			entry.Set("rules", []any{})
		}
		mode := policy.Get("mode")
		if !policyjson.Truthy(mode) {
			mode = "denylist"
		}
		entry.Set("mode", mode)
		entry.Set("version", float64(row.Version))
		entry.Set("hash", row.Hash)
		entry.Set("created_by", policyFirstNonEmpty(row.CreatorName, row.CreatorEmail, row.CreatedBy, "System"))
		entry.Set("created_at", store.ISO(row.CreatedAt))
		b.WriteString(policyjson.Stringify(entry, nil))
	}
	b.WriteString(`]}`)

	apiauth.JSON(w, http.StatusOK, json.RawMessage(b.String()))
}

func policyFirstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// policyFieldOrUndefined keeps "the policy has no such field" distinct from
// "the field is null". Reading one JavaScript object's property onto another is
// how `undefined` gets there, and an undefined property is omitted from the
// output rather than written as null.
func policyFieldOrUndefined(o *policyjson.Object, key string) any {
	if !o.Has(key) {
		return policyjson.Undef
	}
	return o.Get(key)
}

// ── POST /api/v1/policies ───────────────────────────────────────────────────

func (s *server) policiesCreate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body, ok := policyReadObject(w, r)
	if !ok {
		return
	}

	// The live guard is `!body.id || !body.name || !body.rules`, which is a
	// TRUTHINESS test: an empty string fails it and an empty rules ARRAY passes
	// it, because [] is truthy in JavaScript. A policy with no rules is a legal
	// thing to save — it is how somebody clears one out.
	if !policyjson.Truthy(body.Get("id")) || !policyjson.Truthy(body.Get("name")) || !policyjson.Truthy(body.Get("rules")) {
		apiauth.BadRequest(w, "Missing required fields: id, name, rules")
		return
	}
	rules, isArr := policyjson.Array(body.Get("rules"))
	if !isArr {
		// normalizeRules calls .map on this and throws, which the route's catch
		// turns into a 500. Same answer, without the panic.
		apiauth.Internal(w, "api", errors.New("policies: rules is not an array"))
		return
	}
	body.Set("rules", policyjson.NormalizeRules(rules))

	reason := store.Clip(policyJSString(body.Get("description"), "New policy created"), 500)
	s.policyWriteVersion(w, r, key, policyWrite{
		policy:    body,
		policyID:  policyjson.Str(body.Get("id")),
		reason:    func(int64) string { return reason },
		createdBy: policyProjectOwner(r.Context(), s, key.ProjectID),
		status:    http.StatusCreated,
		// See policyCarriesBundle: the property-list hash would drop a
		// variant's security block, and two policies that differ only there
		// would hash the same.
		hashWithAll: !policyCarriesBundle(body),
	})
}

// ── PUT /api/v1/policies/{id} ───────────────────────────────────────────────

func (s *server) policyUpdate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	body, ok := policyReadObject(w, r)
	if !ok {
		return
	}
	if !policyjson.Truthy(body.Get("rules")) {
		apiauth.BadRequest(w, "Missing required field: rules")
		return
	}
	rules, isArr := policyjson.Array(body.Get("rules"))
	if !isArr {
		apiauth.Internal(w, "api", errors.New("policies: rules is not an array"))
		return
	}
	body.Set("rules", policyjson.NormalizeRules(rules))

	// The path wins over the body. Without this a caller could PUT to one
	// policy's URL and write a version of ANOTHER policy — same project, but a
	// different logical policy than the one the dashboard thinks it is editing.
	body.Set("id", policyID)

	s.policyWriteVersion(w, r, key, policyWrite{
		policy:   body,
		policyID: policyID,
		reason: func(v int64) string {
			return fmt.Sprintf("Policy updated to version %d", v)
		},
		createdBy:   policyProjectOwner(r.Context(), s, key.ProjectID),
		status:      http.StatusOK,
		hashWithAll: !policyCarriesBundle(body),
	})
}

// policyWrite is one append to policy_versions.
//
// hashWithAll picks between the two hashes the live app computes, and they are
// NOT the same function. POST and PUT hash `JSON.stringify(body,
// Object.keys(body).sort())` — an array replacer, which is a property
// allow-list applied at every level, not a sort. The rules routes and rollback
// hash `JSON.stringify(x)` with no replacer. Both are in front of stored data,
// so both are reproduced; see internal/policyjson.
type policyWrite struct {
	policy   *policyjson.Object
	policyID string
	// reason is a function of the version being written, because two of the
	// four callers name that version in the text. The counter is read ONCE per
	// write; reading it twice would let two concurrent saves agree on the same
	// next version.
	reason      func(version int64) string
	createdBy   string
	status      int
	hashWithAll bool
}

func (s *server) policyWriteVersion(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo, pw policyWrite) {
	saved, err := s.policyAppend(r.Context(), key, pw)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	out := pw.policy.Clone()
	out.Set("_version", float64(saved.Version))
	out.Set("_hash", saved.Hash)
	// `_opa_compiled` is `opaResult !== null` in the original: whether a
	// compilation happened at all. A Rego build that succeeded while the WASM
	// one failed still counts, because that is the value the dashboard shows as
	// "compiled" and the policy IS compiled — just not to a bundle.
	out.Set("_opa_compiled", saved.Compiled)
	apiauth.JSON(w, pw.status, json.RawMessage(policyjson.Stringify(out, nil)))
}

// policyAppended is what a write reports back: the version that was assigned
// and the hash that was stored, so a handler renders exactly what is in the
// row rather than recomputing either.
type policyAppended struct {
	Version  int64
	Hash     string
	Compiled bool
}

// policyAppend is the one place a row is added to policy_versions.
//
// Every write route funnels through it — create, update, add-rule,
// revoke-rule — so the version counter is read once, the two hash spellings
// live in one branch, and no route can save a policy without compiling it.
func (s *server) policyAppend(ctx context.Context, key apiauth.KeyInfo, pw policyWrite) (policyAppended, error) {
	next, err := s.store.MaxVersionByID(ctx, key.ProjectID, pw.policyID)
	if err != nil {
		return policyAppended{}, err
	}
	version := next + 1

	stored := policyjson.Stringify(pw.policy, nil)
	hash := policySHA256(stored)
	if pw.hashWithAll {
		hash = policySHA256(policyjson.Stringify(pw.policy, pw.policy.SortedKeys()))
	}

	// Compiled BEFORE the insert, so a version never exists without the Rego
	// that was built from it — /policies/{id}/rego would otherwise compile it
	// again on the first read and pay for the same work twice.
	opa, compiled := policycompile.Compile(ctx, json.RawMessage(stored))

	id := policyNewID()
	if id == "" {
		return policyAppended{}, errors.New("policies: could not generate an id")
	}
	err = s.store.InsertPolicyVersion(ctx, store.PolicyVersion{
		ID:         id,
		ProjectID:  key.ProjectID,
		Version:    version,
		PolicyData: json.RawMessage(stored),
		Hash:       hash,
		Reason:     pw.reason(version),
		CreatedBy:  pw.createdBy,
		RegoSource: opa.RegoSource,
		WasmBundle: opa.WasmBundleB64,
		CreatedAt:  store.Now(),
	})
	if err != nil {
		return policyAppended{}, err
	}
	return policyAppended{Version: version, Hash: hash, Compiled: compiled}, nil
}

// ── GET /api/v1/policies/{id} ───────────────────────────────────────────────

func (s *server) policyGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	version := r.URL.Query().Get("version")
	ctx := r.Context()

	if policyID == "default" {
		// `default` here is not a policy named "default": it is "whatever this
		// project's newest policy is", which is what a freshly paired CLI asks
		// for before it knows any policy ids.
		latest, err := s.store.LatestPolicyVersion(ctx, key.ProjectID)
		if errors.Is(err, store.ErrNotFound) {
			apiauth.JSON(w, http.StatusOK, json.RawMessage(policyDefaultDenyPolicy))
			return
		}
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		s.policyRespondWithMeta(w, latest)
		return
	}

	var row store.PolicyVersion
	var err error
	if version != "" {
		row, err = s.store.PolicyVersionAt(ctx, key.ProjectID, policyID, policyParseInt(version))
		if errors.Is(err, store.ErrNotFound) {
			apiauth.Error(w, http.StatusNotFound, "ERROR", "Policy version not found")
			return
		}
	} else {
		row, err = s.store.LatestPolicyByID(ctx, key.ProjectID, policyID)
		if errors.Is(err, store.ErrNotFound) {
			apiauth.Error(w, http.StatusNotFound, "ERROR", "Policy not found")
			return
		}
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	s.policyRespondWithMeta(w, row)
}

// policyRespondWithMeta is `{...policy, rules: normalizeRules(policy.rules),
// _version, _hash, _created_at}`.
//
// The three underscore fields are appended, so they land AFTER the policy's own
// keys — which is what the CLI's PolicyDetail embeds a PolicySet in and reads
// alongside. `rules` is replaced in place and keeps its position.
func (s *server) policyRespondWithMeta(w http.ResponseWriter, row store.PolicyVersion) {
	policy, ok := policyjson.ParseObject(row.PolicyData)
	if !ok {
		apiauth.Internal(w, "api", errors.New("policies: stored policy is not an object"))
		return
	}
	rules, isArr := policyjson.Array(policy.Get("rules"))
	if !isArr {
		// normalizeRules(undefined) throws in the original and the catch answers
		// 500. Reporting it the same way keeps a corrupt row visible rather than
		// serving a policy with the rules quietly missing.
		apiauth.Internal(w, "api", errors.New("policies: stored policy has no rules array"))
		return
	}
	out := policy.Clone()
	out.Set("rules", policyjson.NormalizeRules(rules))
	out.Set("_version", float64(row.Version))
	out.Set("_hash", row.Hash)
	out.Set("_created_at", store.ISO(row.CreatedAt))
	apiauth.JSON(w, http.StatusOK, json.RawMessage(policyjson.Stringify(out, nil)))
}

// ── DELETE /api/v1/policies/{id} ────────────────────────────────────────────

// policyDelete removes every version of one logical policy.
//
// It answers `{deleted: true}` whether or not anything matched, which is the
// live behaviour and is worth keeping rather than "improving" to a 404: the
// dashboard deletes a policy and then refetches the list, and a 404 on a second
// click — or on a retry after a dropped response — would surface as an error
// for an operation that has already succeeded.
func (s *server) policyDelete(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	if _, err := s.store.DeletePolicyByID(r.Context(), key.ProjectID, policyID); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"deleted": true, "policy_id": policyID})
}

// ── POST /api/v1/policies/{id}/rules ────────────────────────────────────────

// ruleSpec is the body the dashboard's "allow this / block this" buttons post:
// one constraint, copied out of an audit entry into the live policy.
type ruleSpec struct {
	ToolPattern string `json:"toolPattern"`
	Kind        string `json:"kind"`
	Value       string `json:"value"`
	Effect      string `json:"effect"`
	// Permission scopes the rule to a class of call. Absent means every class,
	// which is what a rule without it has always meant and has to keep meaning.
	Permission []string `json:"permission"`
}

func (s *server) policyAddRule(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	ctx := r.Context()

	// `.catch(() => ({}))` in the original: an unparseable body is an empty
	// spec, which builds a bare ALLOW rule for `*`. That is a real request the
	// dashboard makes — "allow this tool" with no constraint at all.
	var spec ruleSpec
	if !apiauth.DecodeJSON(w, r, &spec, true) {
		return
	}

	latest, err := s.store.LatestPolicyByID(ctx, key.ProjectID, policyID)
	if errors.Is(err, store.ErrNotFound) {
		apiauth.Error(w, http.StatusNotFound, "ERROR", "Policy not found")
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	policy, ok := policyjson.ParseObject(latest.PolicyData)
	if !ok {
		apiauth.Internal(w, "api", errors.New("policies: stored policy is not an object"))
		return
	}
	rules, _ := policyjson.Array(policy.Get("rules"))

	isDeny := spec.Effect == "DENY"
	effect := "ALLOW"
	verb := "human-approved"
	if isDeny {
		effect = "DENY"
		verb = "human-blocked"
	}

	if policyRuleAlreadyPresent(rules, spec) {
		// Deduped is a 200 with `deduped: true`, not an error. The dashboard
		// shows the message; treating a second click as a failure would be a
		// red toast for a policy that already says what the user asked for.
		apiauth.JSON(w, http.StatusOK, map[string]any{
			"ok":        true,
			"deduped":   true,
			"policy_id": policyID,
			"message":   "Equivalent " + effect + " rule already present in this policy.",
		})
		return
	}

	newRule := policyBuildRule(spec, isDeny)
	updated := policy.Clone()
	updated.Set("rules", append([]any{newRule}, rules...))

	tool := spec.ToolPattern
	if tool == "" {
		tool = "*"
	}

	// created_by is the KEY's owner here, not the project's — the original
	// passes apiKeyInfo.ownerId, so a rule copied in from the dashboard is
	// attributed to whoever was holding the key.
	saved, err := s.policyAppend(ctx, key, policyWrite{
		policy:   updated,
		policyID: policyID,
		reason: func(int64) string {
			return "Copied " + verb + " rule into policy (tool=" + tool + ")"
		},
		createdBy: key.OwnerID,
	})
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, json.RawMessage(`{"ok":true,"deduped":false,"rule":`+
		policyjson.Stringify(newRule, nil)+`,"policy_id":`+policyjson.Stringify(policyID, nil)+
		`,"policy_version":`+strconv.FormatInt(saved.Version, 10)+`}`))
}

// policyBuildRule is the original's buildRule, key order included: the
// generated id encodes the effect and the millisecond it was created, which is
// what makes two rules copied in the same second collide — and why `duplicate`
// runs first rather than relying on the id.
func policyBuildRule(spec ruleSpec, isDeny bool) *policyjson.Object {
	side := "allowed"
	prefix := "allow"
	effect := "ALLOW"
	word := "Human-approved"
	if isDeny {
		side = "denied"
		prefix = "deny"
		effect = "DENY"
		word = "Human-blocked"
	}
	tool := spec.ToolPattern
	if tool == "" {
		tool = "*"
	}

	rule := policyjson.NewObject()
	rule.Set("id", prefix+"-"+strconv.FormatInt(time.Now().UnixMilli(), 10))
	rule.Set("toolPattern", tool)
	rule.Set("effect", effect)
	rule.Set("priority", float64(1))
	rule.Set("enabled", true)
	rule.Set("description", word+" (copied to this policy)")
	// Written before the constraint so the field order matches what the editor
	// and the dashboard produce for the same rule.
	if len(spec.Permission) > 0 {
		perms := make([]any, 0, len(spec.Permission))
		for _, p := range spec.Permission {
			perms = append(perms, p)
		}
		rule.Set("permission", perms)
	}

	if spec.Value != "" {
		constraint := policyjson.NewObject()
		constraint.Set(side, []any{spec.Value})
		// `path` writes pathConstraints, not filenameConstraints. Those are
		// different matchers and the difference is the whole rule: a path
		// constraint names a DIRECTORY and everything under it, a filename
		// constraint matches the last segment only.
		//
		// This wrote filenameConstraints until 0.83.36, which meant every
		// `solongate policy deny --path '*secrets*'` produced a rule that missed
		// `secrets/session.key` -- the file is in the directory the operator
		// named, and its NAME contains no "secrets" for the constraint to match.
		// The rule appeared in `policy show`, looked right, and enforced nothing.
		switch spec.Kind {
		case "command":
			rule.Set("commandConstraints", constraint)
		case "path":
			rule.Set("pathConstraints", constraint)
		case "filename":
			rule.Set("filenameConstraints", constraint)
		case "url":
			rule.Set("urlConstraints", constraint)
		}
	}
	return rule
}

// policySamePermission reports whether a stored rule's permission scoping is
// the one being asked for.
//
// Order does not matter -- READ,WRITE and WRITE,READ scope identically -- and an
// absent list, an empty list and a null all mean "every class", which is what a
// rule without the field has always meant.
func policySamePermission(stored any, want []string) bool {
	have := map[string]bool{}
	if arr, ok := policyjson.Array(stored); ok {
		for _, v := range arr {
			if s := policyjson.Str(v); s != "" {
				have[strings.ToUpper(s)] = true
			}
		}
	}
	if len(have) != len(want) {
		return false
	}
	for _, w := range want {
		if !have[strings.ToUpper(w)] {
			return false
		}
	}
	return true
}

// policyRuleAlreadyPresent is the original's `duplicate`.
//
// A rule with no constraint at all ("allow this tool") is a duplicate of any
// other unconstrained rule for the same tool and effect. A constrained one is a
// duplicate only when the exact value is already listed on the matching side.
// Disabled rules do not count, so re-adding something previously turned off
// writes a new enabled rule rather than silently doing nothing.
func policyRuleAlreadyPresent(rules []any, spec ruleSpec) bool {
	isDeny := spec.Effect == "DENY"
	side := "allowed"
	want := "ALLOW"
	if isDeny {
		side = "denied"
		want = "DENY"
	}
	tool := spec.ToolPattern
	if tool == "" {
		tool = "*"
	}

	for _, item := range rules {
		r, ok := item.(*policyjson.Object)
		if !ok {
			continue
		}
		if policyjson.Str(r.Get("effect")) != want || r.Get("enabled") == any(false) {
			continue
		}
		// Two rules over the same target that are scoped to DIFFERENT classes of
		// call are not the same rule, and treating them as duplicates is worse
		// than a wasted write: the second one is silently not created, the CLI
		// reports success, and the policy keeps enforcing the scope the user has
		// just replaced. Deny a path for WRITE, then deny the same path for
		// EXECUTE, and you would still have only the WRITE rule.
		if !policySamePermission(r.Get("permission"), spec.Permission) {
			continue
		}
		rTool := policyjson.Str(r.Get("toolPattern"))
		if rTool == "" {
			rTool = "*"
		}
		if rTool != tool {
			continue
		}
		if spec.Kind == "tool" || spec.Value == "" {
			// pathConstraints belongs in this list for the same reason the other
			// three do: a rule carrying one is CONSTRAINED, and treating it as
			// unconstrained would make a bare `deny <tool>` dedupe against it and
			// silently do nothing.
			if !policyConstraintHas(r, "commandConstraints", side) &&
				!policyConstraintHas(r, "pathConstraints", side) &&
				!policyConstraintHas(r, "filenameConstraints", side) &&
				!policyConstraintHas(r, "urlConstraints", side) {
				return true
			}
			continue
		}
		switch spec.Kind {
		case "command":
			if policyConstraintLists(r, "commandConstraints", side, spec.Value) {
				return true
			}
		case "path":
			if policyConstraintLists(r, "pathConstraints", side, spec.Value) {
				return true
			}
		case "filename":
			if policyConstraintLists(r, "filenameConstraints", side, spec.Value) {
				return true
			}
		case "url":
			if policyConstraintLists(r, "urlConstraints", side, spec.Value) {
				return true
			}
		}
	}
	return false
}

// policyConstraintHas is `r.xConstraints?.[side]` as a truthiness test: an
// ABSENT list and an EMPTY one are different here, because `[]` is truthy in
// JavaScript. A rule carrying `{denied: []}` therefore counts as constrained
// and does not dedupe against an unconstrained one.
func policyConstraintHas(r *policyjson.Object, field, side string) bool {
	c, ok := r.Get(field).(*policyjson.Object)
	if !ok {
		return false
	}
	return policyjson.Truthy(c.Get(side))
}

func policyConstraintLists(r *policyjson.Object, field, side, value string) bool {
	c, ok := r.Get(field).(*policyjson.Object)
	if !ok {
		return false
	}
	arr, isArr := policyjson.Array(c.Get(side))
	if !isArr {
		return false
	}
	for _, v := range arr {
		if s, isStr := v.(string); isStr && s == value {
			return true
		}
	}
	return false
}

// ── DELETE /api/v1/policies/{id}/rules/{ruleId} ─────────────────────────────

func (s *server) policyRevokeRule(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	// ServeMux unescapes a wildcard's value, which is the decodeURIComponent
	// the original does by hand. A rule id carrying a slash therefore arrives
	// whole rather than splitting the route.
	ruleID := r.PathValue("ruleId")
	ctx := r.Context()

	latest, err := s.store.LatestPolicyByID(ctx, key.ProjectID, policyID)
	if errors.Is(err, store.ErrNotFound) {
		apiauth.Error(w, http.StatusNotFound, "ERROR", "Policy not found")
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	policy, ok := policyjson.ParseObject(latest.PolicyData)
	if !ok {
		apiauth.Internal(w, "api", errors.New("policies: stored policy is not an object"))
		return
	}
	rules, _ := policyjson.Array(policy.Get("rules"))

	// `rules.filter(r => r && r.id !== decodedRuleId)`: a null entry is dropped
	// by the leading truthiness test, and anything else that is not an object
	// has no id to match and survives.
	kept := make([]any, 0, len(rules))
	for _, item := range rules {
		if item == nil {
			continue
		}
		if o, isObj := item.(*policyjson.Object); isObj && policyjson.Str(o.Get("id")) == ruleID {
			continue
		}
		kept = append(kept, item)
	}
	if len(kept) == len(rules) {
		apiauth.Error(w, http.StatusNotFound, "ERROR",
			`Rule "`+ruleID+`" not found in policy`)
		return
	}

	updated := policy.Clone()
	updated.Set("rules", kept)

	saved, err := s.policyAppend(ctx, key, policyWrite{
		policy:    updated,
		policyID:  policyID,
		reason:    func(int64) string { return "Revoked rule " + ruleID },
		createdBy: key.OwnerID,
	})
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, struct {
		OK            bool   `json:"ok"`
		Revoked       string `json:"revoked"`
		PolicyID      string `json:"policy_id"`
		PolicyVersion int64  `json:"policy_version"`
	}{true, ruleID, policyID, saved.Version})
}

// ── GET /api/v1/policies/{id}/versions ──────────────────────────────────────

type policyVersionEntry struct {
	Version    int64   `json:"version"`
	Hash       string  `json:"hash"`
	Reason     *string `json:"reason"`
	CreatedBy  *string `json:"created_by"`
	CreatedAt  string  `json:"created_at"`
	RulesCount int     `json:"rules_count"`
}

func (s *server) policyVersions(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	q := r.URL.Query()

	// `Math.min(Math.max(parseInt(x) || 50, 1), 200)`. The `|| 50` catches NaN
	// AND zero, so `?limit=0` is fifty rather than nothing — which looks like a
	// bug and is the deployed behaviour, and a client asking for zero rows is
	// not a client anyone is trying to satisfy.
	limit := policyParseIntDefault(q.Get("limit"), 50)
	if limit == 0 {
		limit = 50
	}
	if limit < 1 {
		limit = 1
	}
	if limit > 200 {
		limit = 200
	}
	offset := policyParseIntDefault(q.Get("offset"), 0)
	if offset < 0 {
		offset = 0
	}

	rows, total, err := s.store.PolicyVersionPage(r.Context(), key.ProjectID, policyID, int(limit), int(offset))
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	versions := make([]policyVersionEntry, 0, len(rows))
	for _, row := range rows {
		count := 0
		if policy, ok := policyjson.ParseObject(row.PolicyData); ok {
			if rules, isArr := policyjson.Array(policy.Get("rules")); isArr {
				count = len(rules)
			}
		}
		versions = append(versions, policyVersionEntry{
			Version:    row.Version,
			Hash:       row.Hash,
			Reason:     policyNullableString(row.Reason),
			CreatedBy:  policyNullableString(row.CreatedBy),
			CreatedAt:  store.ISO(row.CreatedAt),
			RulesCount: count,
		})
	}

	apiauth.JSON(w, http.StatusOK, struct {
		Versions   []policyVersionEntry `json:"versions"`
		Pagination struct {
			Total  int64 `json:"total"`
			Limit  int64 `json:"limit"`
			Offset int64 `json:"offset"`
		} `json:"pagination"`
	}{
		Versions: versions,
		Pagination: struct {
			Total  int64 `json:"total"`
			Limit  int64 `json:"limit"`
			Offset int64 `json:"offset"`
		}{Total: total, Limit: limit, Offset: offset},
	})
}

// ── POST /api/v1/policies/{id}/rollback ─────────────────────────────────────

func (s *server) policyRollback(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	ctx := r.Context()

	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	parsed, err := policyjson.Parse(raw)
	if err != nil {
		// `await request.json()` with no catch: a malformed body lands in the
		// route's try/catch and answers 500, not 400. Kept, because a client
		// that has been handling a 500 here for a year is not helped by a new
		// status code.
		apiauth.Internal(w, "api", err)
		return
	}
	body, _ := parsed.(*policyjson.Object)
	target, isNumber := body.Get("version").(float64)
	if !isNumber {
		// `typeof body.version !== 'number'` — a string "3" is refused, which
		// is stricter than it looks and is what stops a rollback to whatever
		// SQLite decides "3abc" compares equal to.
		apiauth.BadRequest(w, "Missing required field: version (number)")
		return
	}

	row, err := s.store.PolicyVersionAt(ctx, key.ProjectID, policyID, policyNumberArg(target))
	if errors.Is(err, store.ErrNotFound) {
		apiauth.Error(w, http.StatusNotFound, "ERROR",
			"Version "+policyjson.NumberString(target)+" not found for this policy")
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	next, err := s.store.MaxVersionForPolicy(ctx, key.ProjectID, policyID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	newVersion := next + 1

	// The rolled-back policy is re-serialised rather than copied byte for byte,
	// because the original hashes `JSON.stringify(targetEntry.policyData)` —
	// the DECODED column, put back through the serialiser. For a row this
	// service wrote the two are identical; for one written with whitespace they
	// are not, and the hash has to match what the live app would have computed.
	restored, ok := policyjson.ParseObject(row.PolicyData)
	if !ok {
		apiauth.Internal(w, "api", errors.New("policies: stored policy is not an object"))
		return
	}
	stored := policyjson.Stringify(restored, nil)
	hash := policySHA256(stored)

	opa, _ := policycompile.Compile(ctx, json.RawMessage(stored))

	id := policyNewID()
	if id == "" {
		apiauth.Internal(w, "api", errors.New("policies: could not generate an id"))
		return
	}
	err = s.store.InsertPolicyVersion(ctx, store.PolicyVersion{
		ID:         id,
		ProjectID:  key.ProjectID,
		Version:    newVersion,
		PolicyData: json.RawMessage(stored),
		Hash:       hash,
		Reason:     "Rolled back to version " + policyjson.NumberString(target),
		// The literal string "api", not a user id. It is what the live app
		// writes and what the version list shows for a rollback.
		CreatedBy:  "api",
		RegoSource: opa.RegoSource,
		WasmBundle: opa.WasmBundleB64,
		CreatedAt:  store.Now(),
	})
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusCreated, json.RawMessage(
		`{"version":`+strconv.FormatInt(newVersion, 10)+
			`,"rolled_back_from":`+policyjson.NumberString(target)+
			`,"policy_id":`+policyjson.Stringify(policyID, nil)+
			`,"hash":`+policyjson.Stringify(hash, nil)+`}`))
}

// ── GET /api/v1/policies/{id}/rego ──────────────────────────────────────────

// policyRego serves the policy as Rego source.
//
// It is the sibling of /wasm, for a guard that embeds OPA rather than
// instantiating a compiled bundle on every tool call. Both come from the same
// compile step and the same two columns, so the two routes cannot describe
// different policies — and the compiler behind them is a transcription of the
// one guard-go uses locally, so neither can describe a different policy from
// the one the laptop is enforcing.
func (s *server) policyRego(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	ctx := r.Context()

	rego := ""
	var version int64

	row, err := s.store.LatestCompiledRego(ctx, key.ProjectID, policyID)
	switch {
	case err == nil:
		rego, version = row.RegoSource, row.Version
	case !errors.Is(err, store.ErrNotFound):
		apiauth.Internal(w, "api", err)
		return
	}

	if rego == "" {
		// Nothing compiled: build the newest version on demand and store BOTH
		// forms, so whichever of /rego and /wasm is asked first fills in the
		// other. The write is best-effort — a policy that compiles but cannot
		// be cached is still a policy worth answering with.
		latest, err := s.store.LatestPolicyByID(ctx, key.ProjectID, policyID)
		if err == nil {
			if opa, ok := policycompile.Compile(ctx, latest.PolicyData); ok {
				if err := s.store.SetCompiledForms(ctx, key.ProjectID, latest.ID,
					opa.RegoSource, opa.WasmBundleB64); err != nil {
					log.Printf("[API:api] could not cache the compiled policy: %v", err)
				}
				rego, version = opa.RegoSource, latest.Version
			}
		} else if !errors.Is(err, store.ErrNotFound) {
			apiauth.Internal(w, "api", err)
			return
		}
	}

	if rego == "" {
		apiauth.Error(w, http.StatusNotFound, "ERROR",
			"No Rego source for this policy, and on-demand compilation is unavailable. Re-save the policy to trigger it.")
		return
	}

	// text/plain, not JSON: the CLI writes this straight to a .rego file and
	// OPA parses it. X-Policy-Version is how a caller knows which revision it
	// received without a second request.
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Policy-Version", strconv.FormatInt(version, 10))
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, rego)
}

// ── shared helpers ──────────────────────────────────────────────────────────

// policyReadObject reads the request body as a JavaScript-shaped JSON value.
//
// It does NOT go through apiauth.DecodeJSON, and the reason is the hash: a
// policy has to be serialised back in the key order it arrived in, and
// json.Unmarshal into a map loses that. The body is already bounded by the
// MaxBytesReader in middleware.go.
func policyReadObject(w http.ResponseWriter, r *http.Request) (*policyjson.Object, bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return nil, false
	}
	v, err := policyjson.Parse(raw)
	if err != nil {
		// `await request.json()` throws into the route's catch, which answers
		// 500 with INTERNAL_ERROR. Not 400 — see the note in policyRollback.
		apiauth.Internal(w, "api", err)
		return nil, false
	}
	o, ok := v.(*policyjson.Object)
	if !ok {
		// A body that parses but is not an object reads every field as
		// undefined, which the required-field guard then rejects. An empty
		// object reaches the same place.
		o = policyjson.NewObject()
	}
	return o, true
}

func policySHA256(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// policyNewID mints the UUIDv4 `crypto.randomUUID()` produces.
//
// crypto/rand, and an empty string on failure rather than a clock-derived
// fallback: these ids address rows in a shared table, and a predictable one is
// a row an outsider can reference before it exists. auth.go carries the same
// eight lines; they belong in one helper once the port stops moving.
func policyNewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Printf("api: could not read random bytes for a policy id: %v", err)
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func policyProjectOwner(ctx context.Context, s *server, projectID string) string {
	owner, err := s.store.ProjectOwner(ctx, projectID)
	if err != nil {
		// `project[0]?.ownerId || null` — a project row that cannot be read
		// leaves created_by NULL rather than failing the save. The policy is
		// what matters; the attribution is not worth refusing a write over.
		return ""
	}
	return owner
}

// policyNullableString keeps a NULL column NULL on the wire. `reason` and
// `created_by` are both nullable in policy_versions and the CLI types them as
// optional, so an empty string would be a value where there was none.
func policyNullableString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// policyParseInt is JavaScript's parseInt(x, 10): leading whitespace and sign,
// then digits, then stop. "12abc" is 12 and "abc" is NaN — which reaches SQL as
// a value no version equals, so the route 404s rather than matching something.
func policyParseInt(s string) any {
	n, ok := policyParseIntOK(s)
	if !ok {
		// NaN. Bound as a string that cannot equal any integer version, so the
		// comparison fails in the database rather than being skipped here.
		return "NaN"
	}
	return n
}

func policyParseIntDefault(s string, def int64) int64 {
	n, ok := policyParseIntOK(s)
	if !ok {
		return def
	}
	return n
}

func policyParseIntOK(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	i := 0
	neg := false
	if i < len(s) && (s[i] == '+' || s[i] == '-') {
		neg = s[i] == '-'
		i++
	}
	start := i
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	if i == start {
		return 0, false
	}
	n, err := strconv.ParseInt(s[start:i], 10, 64)
	if err != nil {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

// policyNumberArg binds a JSON number the way SQLite will compare it. An
// integral value goes as an integer so `version = 3` matches a column written
// as 3; a fractional one goes as a float and matches nothing, which is correct.
func policyNumberArg(f float64) any {
	if f == float64(int64(f)) {
		return int64(f)
	}
	return f
}

// policyJSString is `String(v || fallback)` for the values a policy field can
// hold. An object stringifies to "[object Object]" in JavaScript and does so
// here, because the result is stored as a version's reason and a Go-shaped
// rendering would put a different string in the history.
func policyJSString(v any, fallback string) string {
	if !policyjson.Truthy(v) {
		return fallback
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return policyjson.NumberString(t)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, policyJSString(item, ""))
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

// policyDefaultDenyPolicy is src/lib/security.ts's createDefaultDenyPolicy,
// written out rather than built, because the ORDER of its keys is part of what
// a caller receives and a Go struct would be one more place to get that wrong.
//
// It is what GET /policies/default answers for a project that has never saved a
// policy: three ALLOW rules for a VERIFIED caller at priority 100, three DENY
// rules at priority 10000. Note what it does NOT contain — a NETWORK rule — so
// a network permission falls through to no match at all.
const policyDefaultDenyPolicy = `{"id":"default-deny","name":"Default Policy","description":"Allows verified users to read and execute tools. Denies untrusted access and write operations.","version":1,"rules":[` +
	`{"id":"allow-verified-read","description":"Allow verified users to read","effect":"ALLOW","priority":100,"toolPattern":"*","permission":"READ","minimumTrustLevel":"VERIFIED","enabled":true},` +
	`{"id":"allow-verified-execute","description":"Allow verified users to execute tools","effect":"ALLOW","priority":100,"toolPattern":"*","permission":"EXECUTE","minimumTrustLevel":"VERIFIED","enabled":true},` +
	`{"id":"allow-verified-write","description":"Allow verified users to write","effect":"ALLOW","priority":100,"toolPattern":"*","permission":"WRITE","minimumTrustLevel":"VERIFIED","enabled":true},` +
	`{"id":"deny-all-execute","description":"Deny all tool executions by default","effect":"DENY","priority":10000,"toolPattern":"*","permission":"EXECUTE","minimumTrustLevel":"UNTRUSTED","enabled":true},` +
	`{"id":"deny-all-write","description":"Deny all write operations by default","effect":"DENY","priority":10000,"toolPattern":"*","permission":"WRITE","minimumTrustLevel":"UNTRUSTED","enabled":true},` +
	`{"id":"deny-all-read","description":"Deny all read operations by default","effect":"DENY","priority":10000,"toolPattern":"*","permission":"READ","minimumTrustLevel":"UNTRUSTED","enabled":true}` +
	`]}`
