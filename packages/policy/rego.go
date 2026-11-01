// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type ListConstraints struct {
	Allowed []string `json:"allowed"`
	Denied  []string `json:"denied"`
}

type PathConstraintSet struct {
	Allowed       []string `json:"allowed"`
	Denied        []string `json:"denied"`
	RootDirectory string   `json:"rootDirectory"`
}

type PolicyRule struct {
	ID                  string                 `json:"id"`
	Description         string                 `json:"description"`
	Effect              string                 `json:"effect"`
	Priority            float64                `json:"priority"`
	ToolPattern         string                 `json:"toolPattern"`
	Permission          interface{}            `json:"permission"`
	MinimumTrustLevel   string                 `json:"minimumTrustLevel"`
	ArgumentConstraints map[string]interface{} `json:"argumentConstraints"`
	PathConstraints     *PathConstraintSet     `json:"pathConstraints"`
	CommandConstraints  *ListConstraints       `json:"commandConstraints"`
	FilenameConstraints *ListConstraints       `json:"filenameConstraints"`
	URLConstraints      *ListConstraints       `json:"urlConstraints"`
	Enabled             *bool                  `json:"enabled"`
}

func (r PolicyRule) enabledForRego() bool {
	return r.Enabled != nil && *r.Enabled
}

func (r PolicyRule) enabledForFallback() bool {
	return r.Enabled == nil || *r.Enabled
}

func EscapeRegoString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

func normPathPattern(s string) string {
	return EscapeRegoString("(?i)" + PathPatternRegex(s))
}

func normPathLiteral(s string) string {
	return EscapeRegoString(strings.ReplaceAll(s, `\`, "/"))
}

func JSTruthy(v interface{}) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		return t != 0
	default:
		return true
	}
}

func jsNumber(f float64) string {
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func JSToString(v interface{}) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return jsNumber(t)
	case []interface{}:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, JSToString(item))
		}
		return strings.Join(parts, ",")
	default:
		return fmt.Sprintf("%v", t)
	}
}

func permissionList(v interface{}) []string {
	if !JSTruthy(v) {
		return nil
	}
	if arr, ok := v.([]interface{}); ok {
		out := make([]string, 0, len(arr))
		for _, p := range arr {
			out = append(out, JSToString(p))
		}
		return out
	}
	return []string{JSToString(v)}
}

func quotedList(items []string, norm func(string) string) string {
	parts := make([]string, 0, len(items))
	for _, p := range items {
		parts = append(parts, `"`+norm(p)+`"`)
	}
	return strings.Join(parts, ", ")
}

var reGlobRegexEscape = regexp.MustCompile(`[.+^${}()|\[\]\\]`)

func ListGlobToRegex(patterns []string) string {
	parts := make([]string, 0, len(patterns))
	for _, p := range patterns {
		q := strings.ToLower(p)
		q = reGlobRegexEscape.ReplaceAllString(q, `\${0}`)
		q = strings.ReplaceAll(q, "*", ".*")
		q = strings.ReplaceAll(q, "?", ".")
		parts = append(parts, q)
	}
	return "^(?:" + strings.Join(parts, "|") + ")$"
}

func ConvertRulesToRego(rules []PolicyRule) string {
	sorted := make([]PolicyRule, len(rules))
	copy(sorted, rules)

	sort.SliceStable(sorted, func(i, j int) bool {
		di, dj := sorted[i].Effect == "DENY", sorted[j].Effect == "DENY"
		if di != dj {
			return di
		}
		return sorted[i].Priority < sorted[j].Priority
	})

	lines := []string{
		`package solongate.policy`,
		``,
		`import rego.v1`,
		``,
		`# Trust level numeric ordering`,
		`trust_levels := {"UNTRUSTED": 0, "VERIFIED": 1, "TRUSTED": 2}`,
		``,
		`# Helper: check if a path matches any pattern in a list`,
		`# The patterns are compiled regexes with segment semantics, not globs:`,
		`# a directory rule must not fire on a file whose NAME contains the word.`,
		`path_matches_any(p, patterns) if {`,
		`    some pattern in patterns`,
		`    regex.match(pattern, p)`,
		`}`,
		``,

		`# Default decision: DENY (no matching rule)`,
		`default decision := {"effect": "DENY", "reason": "No matching policy rule found. Default action: DENY.", "matched_rule": null}`,
		``,
	}

	emittedHead := false
	for _, rule := range sorted {
		if !rule.enabledForRego() {
			continue
		}
		conds := generateConditions(rule)
		desc := strings.TrimSpace(rule.Description)
		if desc == "" {
			desc = SummarizeRule(rule)
		}
		reason := EscapeRegoString(`Matched rule "` + rule.ID + `": ` + desc)
		ruleID := EscapeRegoString(rule.ID)
		head := fmt.Sprintf(`{"effect": "%s", "reason": "%s", "matched_rule": "%s"}`, rule.Effect, reason, ruleID)

		if !emittedHead {
			lines = append(lines, fmt.Sprintf(`# Rule: %s (priority %s)`, rule.ID, jsNumber(rule.Priority)))
			lines = append(lines, `decision := `+head+` if {`)
			emittedHead = true
		} else {
			lines = append(lines, `} else := `+head+` if {`)
			lines = append(lines, fmt.Sprintf(`    # Rule: %s (priority %s)`, rule.ID, jsNumber(rule.Priority)))
		}
		for _, c := range conds {
			lines = append(lines, `    `+c)
		}
	}

	if emittedHead {
		lines = append(lines, `}`)
	}
	lines = append(lines, ``)
	return strings.Join(lines, "\n")
}

func SummarizeRule(rule PolicyRule) string {
	tool := "any tool"
	if rule.ToolPattern != "" && rule.ToolPattern != "*" {
		tool = rule.ToolPattern
	}
	verb := "Allowed"
	if rule.Effect == "DENY" {
		verb = "Denied"
	}

	var parts []string
	add := func(label string, denied, allowed []string) {
		switch {
		case len(denied) > 0:
			parts = append(parts, label+" matching "+strings.Join(denied, ", "))
		case len(allowed) > 0:
			parts = append(parts, label+" outside "+strings.Join(allowed, ", "))
		}
	}
	if c := rule.CommandConstraints; c != nil {
		add("command", c.Denied, c.Allowed)
	}

	if c := rule.FilenameConstraints; c != nil {
		add("path", c.Denied, c.Allowed)
	} else if c := rule.PathConstraints; c != nil {
		add("path", c.Denied, c.Allowed)
	}
	if c := rule.URLConstraints; c != nil {
		add("URL", c.Denied, c.Allowed)
	}

	s := verb + " " + tool
	if perms := permissionList(rule.Permission); len(perms) > 0 {
		s += " [" + strings.Join(perms, "/") + "]"
	}
	if len(parts) > 0 {
		s += ": " + strings.Join(parts, "; ")
	}
	return s
}

func generateConditions(rule PolicyRule) []string {
	var conds []string

	conds = append(conds, generateToolPatternCondition(rule.ToolPattern)...)

	if perms := permissionList(rule.Permission); len(perms) == 1 {
		conds = append(conds, fmt.Sprintf(`input.permission == "%s"`, EscapeRegoString(perms[0])))
	} else if len(perms) > 1 {
		quoted := make([]string, 0, len(perms))
		for _, p := range perms {
			quoted = append(quoted, `"`+EscapeRegoString(p)+`"`)
		}
		conds = append(conds, fmt.Sprintf(`input.permission in {%s}`, strings.Join(quoted, ", ")))
	}

	if rule.MinimumTrustLevel != "" {
		conds = append(conds, fmt.Sprintf(`trust_levels[input.trust_level] >= trust_levels["%s"]`, EscapeRegoString(rule.MinimumTrustLevel)))
	}

	if rule.ArgumentConstraints != nil {
		conds = append(conds, generateArgumentConstraintConditions(rule.ArgumentConstraints)...)
	}
	if rule.PathConstraints != nil {
		conds = append(conds, generatePathConstraintConditions(rule.PathConstraints, rule.Effect)...)
	}
	if rule.CommandConstraints != nil {
		conds = append(conds, generateListConstraintConditions(rule.CommandConstraints, "input.commands", rule.Effect)...)
	}
	if rule.FilenameConstraints != nil {
		conds = append(conds, generateListConstraintConditions(rule.FilenameConstraints, "input.filenames", rule.Effect)...)
	}
	if rule.URLConstraints != nil {
		conds = append(conds, generateListConstraintConditions(rule.URLConstraints, "input.urls", rule.Effect)...)
	}

	if len(conds) == 0 {
		conds = append(conds, "true")
	}
	return conds
}

func generateToolPatternCondition(pattern string) []string {
	if pattern == "*" || pattern == "" {
		return []string{"# Matches all tools"}
	}
	startsWithStar := strings.HasPrefix(pattern, "*")
	endsWithStar := strings.HasSuffix(pattern, "*")

	switch {
	case startsWithStar && endsWithStar:
		infix := pattern[1 : len(pattern)-1]
		return []string{fmt.Sprintf(`contains(input.tool_name, "%s")`, EscapeRegoString(infix))}
	case endsWithStar:
		return []string{fmt.Sprintf(`startswith(input.tool_name, "%s")`, EscapeRegoString(pattern[:len(pattern)-1]))}
	case startsWithStar:
		return []string{fmt.Sprintf(`endswith(input.tool_name, "%s")`, EscapeRegoString(pattern[1:]))}
	}
	return []string{fmt.Sprintf(`input.tool_name == "%s"`, EscapeRegoString(pattern))}
}

func generateArgumentConstraintConditions(constraints map[string]interface{}) []string {
	var conds []string
	keys := make([]string, 0, len(constraints))
	for k := range constraints {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, key := range keys {
		constraint := constraints[key]
		argRef := fmt.Sprintf(`input.arguments["%s"]`, EscapeRegoString(key))

		if s, ok := constraint.(string); ok {
			if s == "*" {
				conds = append(conds, argRef)
			} else {
				conds = append(conds, fmt.Sprintf(`%s == "%s"`, argRef, EscapeRegoString(s)))
			}
			continue
		}

		ops, ok := constraint.(map[string]interface{})
		if !ok {
			continue
		}
		strOp := func(name, format string) {
			if v, ok := ops[name].(string); ok {
				conds = append(conds, fmt.Sprintf(format, argRef, EscapeRegoString(v)))
			}
		}
		numOp := func(name, op string) {
			if v, ok := ops[name].(float64); ok {
				conds = append(conds, fmt.Sprintf(`%s %s %s`, argRef, op, jsNumber(v)))
			}
		}
		setOp := func(name string, negate bool) {
			arr, ok := ops[name].([]interface{})
			if !ok {
				return
			}
			parts := make([]string, 0, len(arr))
			for _, v := range arr {
				if s, ok := v.(string); ok {
					parts = append(parts, `"`+EscapeRegoString(s)+`"`)
				} else {
					parts = append(parts, JSToString(v))
				}
			}
			expr := fmt.Sprintf(`%s in {%s}`, argRef, strings.Join(parts, ", "))
			if negate {
				expr = "not " + expr
			}
			conds = append(conds, expr)
		}

		strOp("$contains", `contains(%s, "%s")`)
		strOp("$notContains", `not contains(%s, "%s")`)
		strOp("$startsWith", `startswith(%s, "%s")`)
		strOp("$endsWith", `endswith(%s, "%s")`)
		setOp("$in", false)
		setOp("$notIn", true)
		numOp("$gt", ">")
		numOp("$lt", "<")
		numOp("$gte", ">=")
		numOp("$lte", "<=")
	}
	return conds
}

func generatePathConstraintConditions(c *PathConstraintSet, effect string) []string {
	var conds []string

	if effect == "DENY" {
		if c.RootDirectory != "" {
			conds = append(conds, `some p in input.paths`)
			conds = append(conds, fmt.Sprintf(`not startswith(p, "%s")`, normPathLiteral(c.RootDirectory)))
		}
		if len(c.Denied) > 0 {
			conds = append(conds, `some p in input.paths`)
			conds = append(conds, fmt.Sprintf(`path_matches_any(p, [%s])`, quotedList(c.Denied, normPathPattern)))
		}
		return conds
	}

	if c.RootDirectory != "" {
		conds = append(conds, `count(input.paths) > 0`)
		conds = append(conds, fmt.Sprintf(`every p in input.paths { startswith(p, "%s") }`, normPathLiteral(c.RootDirectory)))
	}
	for _, pattern := range c.Denied {
		conds = append(conds, fmt.Sprintf(`every p in input.paths { not regex.match("%s", p) }`, normPathPattern(pattern)))
	}
	if len(c.Allowed) > 0 {
		conds = append(conds, `count(input.paths) > 0`)
		conds = append(conds, fmt.Sprintf(`every p in input.paths { path_matches_any(p, [%s]) }`, quotedList(c.Allowed, normPathPattern)))
	}
	return conds
}

func generateListConstraintConditions(c *ListConstraints, inputField, effect string) []string {
	var conds []string

	if effect == "DENY" {
		if len(c.Denied) > 0 {
			conds = append(conds, fmt.Sprintf(`some item in %s`, inputField))
			conds = append(conds, fmt.Sprintf(`regex.match("%s", lower(item))`, EscapeRegoString(ListGlobToRegex(c.Denied))))
		}
		return conds
	}

	if len(c.Denied) > 0 {
		conds = append(conds, fmt.Sprintf(`every item in %s { not regex.match("%s", lower(item)) }`,
			inputField, EscapeRegoString(ListGlobToRegex(c.Denied))))
	}
	if len(c.Allowed) > 0 {
		conds = append(conds, fmt.Sprintf(`count(%s) > 0`, inputField))
		conds = append(conds, fmt.Sprintf(`every item in %s { regex.match("%s", lower(item)) }`,
			inputField, EscapeRegoString(ListGlobToRegex(c.Allowed))))
	}
	return conds
}

func ParsePolicyRules(raw json.RawMessage) ([]PolicyRule, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, false
	}
	rules := make([]PolicyRule, 0, len(items))
	for _, item := range items {
		var r PolicyRule
		if err := json.Unmarshal(item, &r); err == nil {
			rules = append(rules, r)
			continue
		}

		if salvaged, ok := salvageRule(item); ok {
			rules = append(rules, salvaged)
		}
	}
	return rules, true
}

func salvageRule(item json.RawMessage) (PolicyRule, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item, &fields); err != nil {
		return PolicyRule{}, false
	}
	var r PolicyRule
	constraintsSeen, constraintsKept := 0, 0
	str := func(key string, dst *string) {
		if v, ok := fields[key]; ok {
			_ = json.Unmarshal(v, dst)
		}
	}
	list := func(key string, dst **ListConstraints) {
		v, ok := fields[key]
		if !ok {
			return
		}
		constraintsSeen++
		var c ListConstraints
		if json.Unmarshal(v, &c) == nil {
			*dst = &c
			constraintsKept++
		}
	}
	str("id", &r.ID)
	str("description", &r.Description)
	str("effect", &r.Effect)
	str("toolPattern", &r.ToolPattern)
	str("minimumTrustLevel", &r.MinimumTrustLevel)
	if v, ok := fields["priority"]; ok {
		_ = json.Unmarshal(v, &r.Priority)
	}
	if v, ok := fields["permission"]; ok {
		_ = json.Unmarshal(v, &r.Permission)
	}
	if v, ok := fields["enabled"]; ok {
		var b bool
		if json.Unmarshal(v, &b) == nil {
			r.Enabled = &b
		}
	}
	if v, ok := fields["argumentConstraints"]; ok {
		constraintsSeen++
		if json.Unmarshal(v, &r.ArgumentConstraints) == nil {
			constraintsKept++
		}
	}
	if v, ok := fields["pathConstraints"]; ok {
		constraintsSeen++
		var c PathConstraintSet
		if json.Unmarshal(v, &c) == nil {
			r.PathConstraints = &c
			constraintsKept++
		}
	}
	list("commandConstraints", &r.CommandConstraints)
	list("filenameConstraints", &r.FilenameConstraints)
	list("urlConstraints", &r.URLConstraints)

	if r.Effect == "" {
		return PolicyRule{}, false
	}

	if constraintsSeen > 0 && constraintsKept == 0 {
		return PolicyRule{}, false
	}
	return r, true
}
