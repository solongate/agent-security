// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

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

	if lay := activeVariantLayers(&next); lay != nil {
		s.Security = fromLayers(*lay, s.Security)
	}

	if err := writeStore(s); err != nil {
		return PolicyDetail{}, err
	}
	return detailOf(&next), nil
}

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

type RuleSpec struct {
	ToolPattern string   `json:"toolPattern,omitempty"`
	Kind        string   `json:"kind,omitempty"`
	Value       string   `json:"value,omitempty"`
	Effect      string   `json:"effect,omitempty"`
	Permission  []string `json:"permission,omitempty"`
}

type RuleMutation struct {
	OK            bool        `json:"ok"`
	Deduped       bool        `json:"deduped"`
	Rule          *PolicyRule `json:"rule,omitempty"`
	PolicyID      string      `json:"policy_id"`
	PolicyVersion int         `json:"policy_version,omitempty"`
	Message       string      `json:"message,omitempty"`
}

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

	spec.Value = strings.TrimSpace(spec.Value)
	spec.ToolPattern = strings.TrimSpace(spec.ToolPattern)

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

	for i := range rules {
		if rules[i].Effect == rule.Effect && rules[i].ToolPattern == rule.ToolPattern &&
			permissionKey(rules[i]) == permissionKey(rule) &&
			constraintsOf(rules[i]) == constraintsOf(rule) {
			existing := rules[i]
			return RuleMutation{OK: true, Deduped: true, Rule: &existing, PolicyID: s.Policy.ID, PolicyVersion: localVersion}, nil
		}
	}

	rules = append(rules, rule)

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