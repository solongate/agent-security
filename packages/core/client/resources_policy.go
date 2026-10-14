// SPDX-License-Identifier: Apache-2.0

package client

// One type per namespace, each method the one the commands and the TUI were
// already written against. Every one of them used to be an HTTP call; the names,
// the signatures and the types are unchanged, and what is underneath is two files
// on this machine. See localstore.go.
//
// The TypeScript twin is packages/proxy/src/api-client/*, and the two have to
// agree: they read and write the SAME files, and so does the guard.
//
// ONE FILE MEANS ONE POLICY, and that is the only place the shape of this shows
// its history. A service held many and pinned one as active; a machine holds the
// one it enforces. List answers with it or with nothing, and the operations that
// only make sense among several say so plainly rather than pretending.
//
// Split across resources_policy.go (this file, /policies), resources_settings.go
// (/settings), resources_stats.go (/stats) and resources_audit.go (/audit-logs) —
// same rationale, one section per file instead of one file for all four.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

// ── /policies ──────────────────────────────────────────────────────────────

type Policies struct{ c *Client }

func (p Policies) List(ctx context.Context) ([]PolicyListEntry, error) {
	s, err := readStore()
	if err != nil || s.Policy == nil {
		return []PolicyListEntry{}, err
	}
	return []PolicyListEntry{{
		ID:        s.Policy.ID,
		Name:      s.Policy.Name,
		Rules:     s.Policy.Rules,
		Mode:      policyMode(s.Policy),
		Version:   localVersion,
		Hash:      hashOf(s.Policy),
		CreatedBy: "this machine",
		CreatedAt: time.UnixMilli(0).UTC().Format(time.RFC3339Nano),
	}}, nil
}

func policyMode(p *PolicySet) PolicyMode {
	if p.Mode == ModeWhitelist {
		return ModeWhitelist
	}
	return ModeDenylist
}

func detailOf(p *PolicySet) PolicyDetail {
	cp := *p
	cp.Mode = policyMode(p)
	return PolicyDetail{
		PolicySet:   cp,
		VersionMeta: localVersion,
		Hash:        hashOf(p),
		CreatedAtV:  time.UnixMilli(0).UTC().Format(time.RFC3339Nano),
	}
}

// Get fetches the policy. version is ignored: there is no history to read.
func (p Policies) Get(ctx context.Context, id string, version int) (PolicyDetail, error) {
	s, err := readStore()
	if err != nil {
		return PolicyDetail{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return PolicyDetail{}, err
	}
	return detailOf(s.Policy), nil
}

// Create refuses when the machine already has a policy, rather than merging or
// overwriting: this is the command somebody runs when they think the machine has
// nothing, and the rules it would replace are being enforced right now.
func (p Policies) Create(ctx context.Context, policy PolicySet) (PolicyDetail, error) {
	s, err := readStore()
	if err != nil {
		return PolicyDetail{}, err
	}
	if s.Policy != nil {
		return PolicyDetail{}, errors.New(
			"this machine already has a policy. `solongate policy show local` prints it, " +
				"`solongate policy delete local` removes it.")
	}
	next := policy
	if next.ID == "" {
		next.ID = "local"
	}
	if next.Name == "" {
		next.Name = "local"
	}
	next.Mode = policyMode(&next)
	s.Policy = &next
	s.absent = false
	if err := writeStore(s); err != nil {
		return PolicyDetail{}, err
	}
	return detailOf(&next), nil
}

func (p Policies) Update(ctx context.Context, id string, policy PolicySet) (PolicyDetail, error) {
	s, err := readStore()
	if err != nil {
		return PolicyDetail{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return PolicyDetail{}, err
	}
	next := policy
	next.ID = s.Policy.ID
	next.Mode = policyMode(&next)
	s.Policy = &next

	// THE LAYERS ARE MIRRORED UP TO THE TOP-LEVEL BLOCK, and without this the
	// TUI's DLP and rate-limit editors wrote to a place nothing enforces.
	//
	// There are two shapes on disk for the same configuration. The POLICY
	// carries `security` inside it, per variant, which is what the editor reads
	// and writes and what an exported policy arrives in. The FILE carries a
	// top-level `security` block, and that is the one the guard reads on every
	// tool call, both implementations of it, and `doctor`, and the CLI.
	//
	// The TUI only ever wrote the first. `Policies.Update` is its one
	// layer-writing path (see the save in tui/panels/policies.go, which fills
	// PolicySet.Security and PolicyVariant.Security and calls nothing else), so
	// a DLP mode set in the panel landed in the policy document and the guard
	// went on reading the top-level block that nobody had touched. The panel
	// printed a tick. `doctor` then read the nested block back through
	// `guardSecurity`, which has no field for `dlp` at all and whose rateLimit
	// has no `mode`, so DLP vanished and the rate limit survived as a non-nil
	// block with every window at zero, which toLayers reads as block mode and
	// doctor prints as StateOK: "rate limit: block · no window set".
	//
	// Mirrored here rather than fixed in the panel, for the same reason
	// mirrorRulesIntoDefaultVariant lives in writeStore: this is the one
	// function both surfaces go through, and a mirror maintained by each caller
	// is a mirror that is wrong as soon as there is a third.
	//
	// The ACTIVE variant's layers win, because that is the variant being
	// enforced. A policy with no layers at all leaves the block alone, an
	// empty editor is not a statement that this machine configures nothing, and
	// clearing DLP from under somebody by saving a rule is the bug in the other
	// direction.
	if lay := activeVariantLayers(&next); lay != nil {
		s.Security = fromLayers(*lay, s.Security)
	}

	if err := writeStore(s); err != nil {
		return PolicyDetail{}, err
	}
	return detailOf(&next), nil
}

// activeVariantLayers is the layers of the variant this policy says is in
// force, or nil when it carries none.
//
// DefaultVariant names it; a policy with no variants carries its layers at the
// top of its own document. Falling back to the first variant matches
// mirrorRulesIntoDefaultVariant, so the rules and the layers that get mirrored
// are always from the same variant, two mirrors disagreeing about which
// variant is live would enforce one variant's rules with another's DLP.
func activeVariantLayers(p *PolicySet) *SecurityLayers {
	if p == nil {
		return nil
	}
	if len(p.Variants) == 0 {
		return p.Security
	}
	i := 0
	if p.DefaultVariant != "" {
		for j, v := range p.Variants {
			if v.ID == p.DefaultVariant {
				i = j
				break
			}
		}
	}
	if p.Variants[i].Security != nil {
		return p.Variants[i].Security
	}
	return p.Security
}

// Remove deletes the rules. THE LAYERS SURVIVE: a rate limit and a DLP
// configuration are not part of the rule list, and deleting rules must not
// quietly switch the DLP scanner off.
func (p Policies) Remove(ctx context.Context, id string) error {
	s, err := readStore()
	if err != nil {
		return err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return err
	}
	if !s.Security.empty() || s.SelfProtect != nil {
		s.Policy = nil
		return writeStore(s)
	}
	if err := os.Remove(PolicyPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// RuleSpec is the shorthand a caller sends, deny this command, allow this path,
// and this expands it into a full rule, so two callers cannot produce differently
// shaped rules for the same request.
type RuleSpec struct {
	ToolPattern string   `json:"toolPattern,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Value       string   `json:"value,omitempty"`
	Effect      string   `json:"effect,omitempty"`
	Permission  []string `json:"permission,omitempty"`
}

// RuleMutation is the answer to any call that adds or changes a rule. Deduped
// says the rule was already there, which is a success, not a failure.
type RuleMutation struct {
	OK            bool        `json:"ok"`
	Deduped       bool        `json:"deduped"`
	Rule          *PolicyRule `json:"rule,omitempty"`
	PolicyID      string      `json:"policy_id"`
	PolicyVersion int         `json:"policy_version,omitempty"`
	Message       string      `json:"message,omitempty"`
}

// permissionKey is a rule's permission scope, order-insensitive, so READ,WRITE
// and WRITE,READ are one scope rather than two rules that shadow each other.
// Empty means unscoped, which is its own distinct value: it matches every class.
func permissionKey(r PolicyRule) string {
	perms := r.Permissions()
	if len(perms) == 0 {
		return ""
	}
	parts := make([]string, 0, len(perms))
	for _, p := range perms {
		parts = append(parts, string(p))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func constraintsOf(r PolicyRule) string {
	raw, _ := json.Marshal([]any{r.CommandConstraints, r.PathConstraints, r.FilenameConstraints, r.URLConstraints})
	return string(raw)
}

func describeRule(effect string, spec RuleSpec) string {
	verb := "Block"
	if effect == "ALLOW" {
		verb = "Allow"
	}
	switch {
	case spec.Kind == "tool" && spec.Value != "":
		return verb + " the " + spec.Value + " tool"
	case spec.Kind != "" && spec.Value != "":
		return verb + " " + spec.Kind + " " + spec.Value
	default:
		pattern := spec.ToolPattern
		if pattern == "" {
			pattern = "*"
		}
		return verb + " " + pattern
	}
}

func (p Policies) AddRule(ctx context.Context, id string, spec RuleSpec) (RuleMutation, error) {
	// SURROUNDING WHITESPACE IS NOT PART OF THE PATTERN, and leaving it in produces
	// the worst kind of rule: one that reads correctly everywhere and enforces
	// nothing. `policy show` prints `curl *` whether or not there is a space after
	// it, the TUI lists it the same way, and the glob never matches a command
	// that does not end in one.
	//
	// It is the same failure the permission check already refuses a typo for, a
	// rule that looks right and is silently inert, and it is easier to produce,
	// because a trailing space is invisible in the editor that made it.
	//
	// HERE RATHER THAN IN EACH CALLER. Three places build a RuleSpec: this CLI, the
	// TUI's whitelist key, and the whitelist helper below. Trimming in one of
	// them is how two of them end up wrong.
	spec.Value = strings.TrimSpace(spec.Value)
	spec.ToolPattern = strings.TrimSpace(spec.ToolPattern)

	// An empty pattern is refused rather than stored. What it would mean depends on
	// which field it landed in, everything, or nothing, and neither is what
	// somebody who typed only spaces was asking for.
	if spec.Value == "" && spec.Kind != "" && spec.Kind != "tool" {
		return RuleMutation{}, errors.New("the " + spec.Kind + " pattern is empty")
	}

	s, err := readStore()
	if err != nil {
		return RuleMutation{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return RuleMutation{}, err
	}
	rules := append([]PolicyRule(nil), s.Policy.Rules.Items...)

	effect := spec.Effect
	if effect == "" {
		effect = "DENY"
	}
	toolPattern := spec.ToolPattern
	if spec.Kind == "tool" && spec.Value != "" {
		toolPattern = spec.Value
	}
	if toolPattern == "" {
		toolPattern = "*"
	}
	// Highest first, and above whatever is already there: a rule somebody just
	// added is the one they expect to decide the next call.
	priority := 10
	for _, r := range rules {
		if r.Priority >= priority {
			priority = r.Priority + 1
		}
	}

	rule := PolicyRule{
		ID:                nextRuleID(rules),
		Description:       describeRule(effect, spec),
		Effect:            effect,
		Priority:          priority,
		ToolPattern:       toolPattern,
		MinimumTrustLevel: "UNTRUSTED",
		Enabled:           true,
	}
	if len(spec.Permission) > 0 {
		raw, err := json.Marshal(spec.Permission)
		if err != nil {
			return RuleMutation{}, err
		}
		rule.Permission = raw
	}
	if spec.Kind != "" && spec.Kind != "tool" && spec.Value != "" {
		side := "denied"
		if effect == "ALLOW" {
			side = "allowed"
		}
		c := &Constraint{}
		if side == "allowed" {
			c.Allowed = []string{spec.Value}
		} else {
			c.Denied = []string{spec.Value}
		}
		switch spec.Kind {
		case "command":
			rule.CommandConstraints = c
		case "path":
			rule.PathConstraints = &PathConstraint{Allowed: c.Allowed, Denied: c.Denied}
		case "filename":
			rule.FilenameConstraints = c
		case "url":
			rule.URLConstraints = c
		default:
			return RuleMutation{}, fmt.Errorf("unknown rule kind %q", spec.Kind)
		}
	}

	// Deduped by what the rule DOES, not by its generated id.
	//
	// THE PERMISSION SCOPE IS PART OF WHAT A RULE DOES. It was missing here, and
	// the omission was worse than a no-op: adding the same constraint once for
	// READ and once for WRITE reported "Equivalent rule already present" for the
	// second, so the rule set LOOKED complete while the write half had been
	// thrown away. A scoped rule and an unscoped one over the same constraint
	// are not the same rule either -- one covers every tool class, the other one.
	for i := range rules {
		if rules[i].Effect == rule.Effect && rules[i].ToolPattern == rule.ToolPattern &&
			permissionKey(rules[i]) == permissionKey(rule) &&
			constraintsOf(rules[i]) == constraintsOf(rule) {
			existing := rules[i]
			return RuleMutation{OK: true, Deduped: true, Rule: &existing, PolicyID: s.Policy.ID, PolicyVersion: localVersion}, nil
		}
	}

	rules = append(rules, rule)
	// Raw is cleared on purpose: it holds the bytes that ARRIVED, and they no
	// longer describe this list. Keeping them would write the old rules back.
	s.Policy.Rules = Rules{Items: rules}
	if err := writeStore(s); err != nil {
		return RuleMutation{}, err
	}
	return RuleMutation{OK: true, Rule: &rule, PolicyID: s.Policy.ID, PolicyVersion: localVersion}, nil
}

func (p Policies) RevokeRule(ctx context.Context, id, ruleID string) (RuleMutation, error) {
	s, err := readStore()
	if err != nil {
		return RuleMutation{}, err
	}
	if err := resolveID(id, s.Policy); err != nil {
		return RuleMutation{}, err
	}
	kept := make([]PolicyRule, 0, len(s.Policy.Rules.Items))
	found := false
	for _, r := range s.Policy.Rules.Items {
		if r.ID == ruleID {
			found = true
			continue
		}
		kept = append(kept, r)
	}
	if !found {
		return RuleMutation{}, fmt.Errorf("no rule %s in this policy. `solongate policy show local` lists them.", ruleID)
	}
	s.Policy.Rules = Rules{Items: kept}
	if err := writeStore(s); err != nil {
		return RuleMutation{}, err
	}
	return RuleMutation{OK: true, PolicyID: s.Policy.ID, PolicyVersion: localVersion}, nil
}

// Active is what the guard would enforce on the next call, read from the same
// file it reads, so this is not a report about what should happen, it is the
// input to what does.
func (p Policies) Active(ctx context.Context, agentID string) (ActivePolicy, error) {
	s, err := readStore()
	if err != nil {
		return ActivePolicy{}, err
	}
	l := toLayers(s.Security)
	out := ActivePolicy{
		Policy:                s.Policy,
		Version:               localVersion,
		MatchedBy:             "pinned",
		SelfProtectionEnabled: s.SelfProtect == nil || *s.SelfProtect,
		Security:              &ActivePolicySecurity{},
	}
	if s.Policy != nil {
		out.Hash = hashOf(s.Policy)
	}
	nums := &RateLimitSettings{PerMinute: l.RateLimit.PerMinute, PerHour: l.RateLimit.PerHour, PerDay: l.RateLimit.PerDay}
	switch l.RateLimit.Mode {
	case LayerBlock:
		out.Security.RateLimit = nums
	case LayerDetect:
		out.Security.RateLimitObserve = nums
	}
	custom := make([]json.RawMessage, 0, len(l.DLP.Custom))
	for _, c := range l.DLP.Custom {
		if raw, err := json.Marshal(c); err == nil {
			custom = append(custom, raw)
		}
	}
	// One key per mode, the same shape the guard reads off disk. `mode != off`
	// used to fill DLPRedact for every mode, which is the line that made detect
	// redact: every reader downstream saw a redact config and did redact things
	// with it.
	rules := &DLPSettings{Patterns: l.DLP.Patterns, Custom: custom}
	switch l.DLP.Mode {
	case LayerBlock:
		out.Security.DLPBlock = rules
		out.Security.DLPRedact = rules
	case LayerRedact:
		out.Security.DLPRedact = rules
	case LayerDetect:
		out.Security.DLPObserve = rules
	}
	if s.Security != nil && s.Security.LocalLogs != nil {
		if raw, err := json.Marshal(s.Security.LocalLogs); err == nil {
			out.Security.LocalLogs = raw
		}
	}
	return out, nil
}

// SetActive has nothing to pin. A service kept several policies and chose one;
// the file IS the choice. Saying so beats accepting the call and changing
// nothing, which is what a no-op would do to `solongate policy activate`.
func (p Policies) SetActive(ctx context.Context, policyID string) error {
	if policyID == "" {
		return errors.New(
			"nothing to switch off: enforcement is this machine's policy file. " +
				"`solongate policy delete local` stops it, or set every rule to disabled.")
	}
	s, err := readStore()
	if err != nil {
		return err
	}
	return resolveID(policyID, s.Policy)
}