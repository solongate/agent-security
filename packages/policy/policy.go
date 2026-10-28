// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/solongate/agent-security/packages/shared"
)

func sortRulesByPriority(rules []PolicyRule) {
	effective := func(r PolicyRule) float64 {
		if r.Priority == 0 {
			return 100
		}
		return r.Priority
	}
	sort.SliceStable(rules, func(i, j int) bool { return effective(rules[i]) < effective(rules[j]) })
}

var accessFields = map[string]bool{
	"file_path": true, "path": true, "target_file": true, "notebook_path": true,
	"filename": true, "dest": true, "destination": true, "source": true, "src": true,
	"from": true, "to": true, "directory": true, "dir": true, "folder": true,
	"url": true, "urls": true, "uri": true, "href": true, "link": true, "endpoint": true,
	"absolutepath": true, "targetfile": true, "filepath": true,
}

type Input struct {
	ToolName   string                 `json:"tool_name"`
	Permission string                 `json:"permission"`
	TrustLevel string                 `json:"trust_level"`
	Arguments  map[string]interface{} `json:"arguments"`
	Paths      []string               `json:"paths"`
	Commands   []string               `json:"commands"`
	URLs       []string               `json:"urls"`
	Filenames  []string               `json:"filenames"`
}

func BuildPolicyInput(args map[string]interface{}, toolName, cwd string) Input {
	isExec := IsExecTool(toolName)

	expanded := make(map[string]interface{}, len(args)+1)
	for k, v := range args {
		expanded[k] = v
	}

	if isExec {
		for _, ref := range ReadReferencedFiles(args, cwd) {
			var kept []string
			for _, line := range strings.Split(ref.Content, "\n") {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") {
					kept = append(kept, line)
				}
			}
			if len(kept) == 0 {
				continue
			}
			extra := strings.Join(kept, "; ")
			if cmd, ok := expanded["command"].(string); ok {
				expanded["command"] = cmd + "; " + extra
			} else {
				expanded["command"] = extra
			}
		}
	}

	accessArgs := expanded
	if !isExec {
		accessArgs = map[string]interface{}{}
		for k, v := range expanded {
			if accessFields[strings.ToLower(k)] {
				accessArgs[k] = v
			}
		}
	}

	in := Input{
		ToolName:   toolName,
		Permission: shared.GuessPermission(toolName),

		TrustLevel: "TRUSTED",
		Arguments:  expanded,
		Paths:      ExtractPaths(accessArgs, isExec),
		Commands:   ExtractCommands(expanded),
		URLs:       ExtractURLs(accessArgs),
		Filenames:  ExtractFilenames(accessArgs),
	}

	if abs := AbsolutizePaths(in.Paths, cwd); len(abs) > 0 {
		in.Paths = append(in.Paths, abs...)
	}

	if isExec {
		for _, gp := range ExpandCommandGlobs(expanded, cwd) {
			in.Paths = append(in.Paths, gp)
			if idx := strings.LastIndex(gp, "/"); idx >= 0 {
				if bn := gp[idx+1:]; bn != "" {
					in.Filenames = append(in.Filenames, bn)
				}
			} else if gp != "" {
				in.Filenames = append(in.Filenames, gp)
			}
		}
	}

	for _, sp := range ExpandSearchRoots(toolName, accessArgs, cwd) {
		in.Paths = append(in.Paths, sp)
		if idx := strings.LastIndex(sp, "/"); idx >= 0 {
			if bn := sp[idx+1:]; bn != "" {
				in.Filenames = append(in.Filenames, bn)
			}
		} else if sp != "" {
			in.Filenames = append(in.Filenames, sp)
		}
	}

	if in.Paths == nil {
		in.Paths = []string{}
	}
	if in.Commands == nil {
		in.Commands = []string{}
	}
	if in.URLs == nil {
		in.URLs = []string{}
	}
	if in.Filenames == nil {
		in.Filenames = []string{}
	}
	return in
}

func EvaluatePolicy(pol *shared.Policy, args map[string]interface{}, toolName, cwd string) string {
	if pol == nil {
		return ""
	}
	rules, ok := ParsePolicyRules(pol.Rules)
	if !ok {
		return ""
	}
	mode := "denylist"
	if pol.Mode == "whitelist" {
		mode = "whitelist"
	}

	if reason, decided := evaluateWithOPA(rules, mode, args, toolName, cwd); decided {
		return reason
	}

	return FallbackEvaluate(rules, mode, args, toolName)
}

func evaluateWithOPA(rules []PolicyRule, mode string, args map[string]interface{}, toolName, cwd string) (string, bool) {
	src := ConvertRulesToRego(rules)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	query, err := rego.New(
		rego.Query("data.solongate.policy.decision"),
		rego.Module("policy.rego", src),
	).PrepareForEval(ctx)
	if err != nil {
		return "", false
	}

	rs, err := query.Eval(ctx, rego.EvalInput(BuildPolicyInput(args, toolName, cwd)))
	if err != nil || len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return "", false
	}
	decision, _ := rs[0].Expressions[0].Value.(map[string]interface{})
	effect, _ := decision["effect"].(string)
	if effect == "" {

		return "", true
	}
	reason, _ := decision["reason"].(string)
	matched := decision["matched_rule"] != nil

	if mode == "denylist" {
		if effect == "DENY" && matched {
			return opaReason(reason, "Blocked by policy"), true
		}
		return "", true
	}

	switch {
	case effect == "DENY" && matched:
		return opaReason(reason, "Blocked by policy"), true
	case effect == "REVIEW" && matched:
		return "", true
	case effect == "ALLOW" && matched:
		return "", true
	}
	return opaReason(reason, "Blocked by policy: no ALLOW rule matched"), true
}

func opaReason(reason, fallback string) string {
	if reason == "" {
		reason = fallback
	}
	return "[SolonGate OPA] " + reason
}

// matchToolPattern mirrors generateToolPatternCondition's case-sensitive
// semantics: a single leading and/or trailing "*" is a wildcard, anything
// else must match input.tool_name exactly. Tool names are case-sensitive
// identifiers (Bash, Read, Edit), unlike the filename/url/command patterns
// MatchGlob is used for, so this does not fold case.
func matchToolPattern(toolName, pattern string) bool {
	startsWithStar := strings.HasPrefix(pattern, "*")
	endsWithStar := strings.HasSuffix(pattern, "*")

	switch {
	case startsWithStar && endsWithStar:
		return strings.Contains(toolName, pattern[1:len(pattern)-1])
	case endsWithStar:
		return strings.HasPrefix(toolName, pattern[:len(pattern)-1])
	case startsWithStar:
		return strings.HasSuffix(toolName, pattern[1:])
	}
	return toolName == pattern
}

func MatchGlob(str, pattern string) bool {
	if pattern == "*" {
		return true
	}
	s := strings.ToLower(str)
	p := strings.ToLower(pattern)
	if s == p {
		return true
	}
	if !strings.Contains(p, "*") {
		return false
	}

	parts := strings.Split(p, "*")

	if parts[0] != "" {
		if !strings.HasPrefix(s, parts[0]) {
			return false
		}
		s = s[len(parts[0]):]
	}

	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue
		}
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}

	if last := parts[len(parts)-1]; last != "" {
		return strings.HasSuffix(s, last)
	}
	return true
}

func PathPatternRegex(pattern string) string {
	g := strings.ToLower(strings.ReplaceAll(pattern, `\`, "/"))
	leading := strings.HasPrefix(g, "*")
	trailing := strings.HasSuffix(g, "*")
	core := strings.Trim(g, "*")

	if leading {
		core = strings.TrimPrefix(core, "/")
	}
	core = strings.TrimSuffix(core, "/")
	if core == "" {
		return `^.*$`
	}

	var b strings.Builder
	if leading {
		b.WriteString(`(?:^|.*/)`)
	} else {
		b.WriteString(`^`)
	}
	for _, r := range core {
		switch {
		case r == '*':
			b.WriteString(`[^/]*`)
		case r == '?':
			b.WriteString(`[^/]`)
		case strings.ContainsRune(`\.+()|[]{}^$`, r):
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	if trailing {
		b.WriteString(`(?:/.*)?$`)
	} else {
		b.WriteString(`$`)
	}
	return b.String()
}

var (
	pathRegexMu    sync.Mutex
	pathRegexCache = map[string]*regexp.Regexp{}
)

func pathRegexFor(pattern string) *regexp.Regexp {
	pathRegexMu.Lock()
	defer pathRegexMu.Unlock()
	if re, ok := pathRegexCache[pattern]; ok {
		return re
	}
	re, err := regexp.Compile(PathPatternRegex(pattern))
	if err != nil {
		re = nil
	}
	pathRegexCache[pattern] = re
	return re
}

func MatchPathGlob(path, pattern string) bool {
	re := pathRegexFor(pattern)
	if re == nil {
		return false
	}
	return re.MatchString(strings.ToLower(strings.ReplaceAll(path, `\`, "/")))
}

func permissionApplies(rule PolicyRule, toolName string) bool {
	if !JSTruthy(rule.Permission) {
		return true
	}
	var perms []string
	switch t := rule.Permission.(type) {
	case string:
		perms = []string{t}
	case []interface{}:
		for _, v := range t {
			perms = append(perms, JSToString(v))
		}
	default:
		perms = []string{JSToString(rule.Permission)}
	}
	if len(perms) == 0 {
		return true
	}
	guessed := shared.GuessPermission(toolName)
	for _, p := range perms {
		if p == guessed {
			return true
		}
	}
	return false
}

func patternsOf(c *ListConstraints) []string {
	if c == nil {
		return nil
	}
	if len(c.Denied) > 0 {
		return c.Denied
	}
	if len(c.Allowed) > 0 {
		return c.Allowed
	}
	return nil
}

func pathPatternsOf(c *PathConstraintSet) []string {
	if c == nil {
		return nil
	}
	if len(c.Denied) > 0 {
		return c.Denied
	}
	if len(c.Allowed) > 0 {
		return c.Allowed
	}
	return nil
}

type ruleHit struct{ kind, value, pattern string }

func ruleMatches(rule PolicyRule, args map[string]interface{}, isExec bool, toolName string) *ruleHit {
	// ToolPattern scopes the rule to a tool, with the same glob semantics the
	// Rego path generates (generateToolPatternCondition): * at either end is a
	// wildcard, otherwise an exact tool name. Empty or "*" matches all tools.
	// Without this gate the fallback path fired rules for tools they were
	// never scoped to — an ALLOW rule for Read could authorize Bash (#208).
	if rule.ToolPattern != "" && rule.ToolPattern != "*" && !matchToolPattern(toolName, rule.ToolPattern) {
		return nil
	}
	if pats := patternsOf(rule.FilenameConstraints); pats != nil {
		for _, fn := range ExtractFilenames(args) {
			for _, pat := range pats {
				if MatchGlob(fn, pat) {
					return &ruleHit{"filename", fn, pat}
				}
			}
		}
	}
	if pats := patternsOf(rule.URLConstraints); pats != nil {
		for _, u := range ExtractURLs(args) {
			for _, pat := range pats {
				if MatchGlob(u, pat) {
					return &ruleHit{"URL", u, pat}
				}
			}
		}
	}
	if pats := patternsOf(rule.CommandConstraints); pats != nil {
		for _, cmd := range ExtractCommands(args) {
			for _, pat := range pats {
				if MatchGlob(cmd, pat) {
					v := cmd
					if len(v) > 60 {
						v = v[:60]
					}
					return &ruleHit{"command", v, pat}
				}
			}
		}
	}
	if pats := pathPatternsOf(rule.PathConstraints); pats != nil {
		for _, p := range ExtractPaths(args, isExec) {
			for _, pat := range pats {
				if MatchPathGlob(p, pat) {
					return &ruleHit{"path", p, pat}
				}
			}
		}
	}
	return nil
}

func FallbackEvaluate(rules []PolicyRule, mode string, args map[string]interface{}, toolName string) string {
	isExec := IsExecTool(toolName)

	var denyRules []PolicyRule
	for _, r := range rules {
		if r.enabledForFallback() && r.Effect == "DENY" && permissionApplies(r, toolName) {
			denyRules = append(denyRules, r)
		}
	}
	sortRulesByPriority(denyRules)
	for _, rule := range denyRules {
		if m := ruleMatches(rule, args, isExec, toolName); m != nil {
			return "Blocked by policy: " + m.kind + ` "` + m.value + `" matches "` + m.pattern + `"`
		}
	}

	if mode != "whitelist" {
		return ""
	}

	var allowRules []PolicyRule
	for _, r := range rules {
		if r.enabledForFallback() && r.Effect == "ALLOW" && permissionApplies(r, toolName) {
			allowRules = append(allowRules, r)
		}
	}
	if len(allowRules) == 0 {
		name := toolName
		if name == "" {
			name = "this tool"
		}
		return "Blocked by policy: strict whitelist mode is on and no ALLOW rule applies to " + name
	}
	for _, rule := range allowRules {
		if ruleMatches(rule, args, isExec, toolName) != nil {
			return ""
		}
	}
	return "Blocked by policy: strict whitelist mode, request does not match any ALLOW rule"
}
