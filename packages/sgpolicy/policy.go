package sgpolicy

// Policy evaluation: the decision itself.
//
// Shape of the contract, unchanged from the Node hook so both implementations
// answer identically for the same call:
//
//	input  {tool_name, permission, trust_level, arguments, paths[], commands[],
//	        urls[], filenames[]}
//	result {effect, matched_rule, reason}
//
// and the policy's MODE decides the default — denylist allows unless a DENY
// matched, whitelist denies unless an ALLOW did.

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/sgshared"
	"github.com/open-policy-agent/opa/v1/rego"
)

// The fallback evaluator reads a missing priority as 100, not as 0 — an
// unprioritised rule sorts with the ordinary ones rather than ahead of every
// explicit priority anyone has set.
func sortRulesByPriority(rules []PolicyRule) {
	effective := func(r PolicyRule) float64 {
		if r.Priority == 0 {
			return 100
		}
		return r.Priority
	}
	sort.SliceStable(rules, func(i, j int) bool { return effective(rules[i]) < effective(rules[j]) })
}

// For a tool that does NOT execute its arguments, only these fields are an
// access. Everything else — a question, a description, a file body — is data.
// Writing a document that mentions `.env` is not reading one, and matching body
// text against filename rules is how that became a block.
//
// The url-bearing names are in here for a reason of their own: strip them and a
// non-exec network tool (Fetch, WebFetch) loses its only access target,
// input.urls comes out empty, and every urlConstraints DENY rule stops firing.
// The camelCase names are Antigravity's, lowercased on the way in.
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

// buildPolicyInput turns a tool call into the document the policy is evaluated
// against. Two decisions here carry most of the weight, and both hang on
// whether the tool EXECUTES what it is handed.
func BuildPolicyInput(args map[string]interface{}, toolName, cwd string) Input {
	isExec := IsExecTool(toolName)

	expanded := make(map[string]interface{}, len(args)+1)
	for k, v := range args {
		expanded[k] = v
	}

	// A script the call would RUN is part of the call. `bash deploy.sh` executes
	// whatever deploy.sh contains, so its lines are appended to the command and
	// the same deterministic extractors see them — no model needed to notice that
	// the dangerous part was one file away. Only for exec tools: for a read or a
	// write the file is data, and inlining it there blocks reading a script that
	// merely documents `rm -rf`.
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

	// Access targets come from the whole command for an exec tool, and from the
	// explicit target fields only for everything else.
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
		Permission: sgshared.GuessPermission(toolName),
		// Fixed to TRUSTED, as the Node hook fixes it: minimumTrustLevel has never
		// been evaluated against a real trust signal, and inventing one here would
		// silently change which rules fire.
		TrustLevel: "TRUSTED",
		Arguments:  expanded,
		Paths:      ExtractPaths(accessArgs, isExec),
		Commands:   ExtractCommands(expanded),
		URLs:       ExtractURLs(accessArgs),
		Filenames:  ExtractFilenames(accessArgs),
	}

	// Resolve globbed tokens to the files they actually name, so `cut
	// staging.e*` is matched by the same rule that catches `cat staging.env`.
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

	// A content-returning search reads every file under its root and names none
	// of them, so the root has to stand in for what it will reach. Without this
	// a path rule holds against the read tool and is walked past by the search
	// tool beside it.
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

// evaluatePolicy returns the reason a call is blocked, or "" to allow it.
func EvaluatePolicy(pol *sgshared.Policy, args map[string]interface{}, toolName, cwd string) string {
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

	// OPA produced no decision at all — a policy that will not compile. The Node
	// hook runs its deterministic evaluator here rather than allowing, and so
	// does this. A policy we cannot compile must not quietly disarm the guard:
	// slow-but-guarded, never fast-but-unguarded.
	return FallbackEvaluate(rules, mode, args, toolName)
}

// evaluateWithOPA returns (reason, decided). decided=false means the engine
// could not answer and the caller must fall back.
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
		// A decision with no effect is not a denial. The Node hook allows here.
		return "", true
	}
	reason, _ := decision["reason"].(string)
	matched := decision["matched_rule"] != nil

	// The generated Rego always defaults to DENY, which is whitelist semantics.
	// Mode is re-applied HERE so a denylist policy keeps its default-ALLOW:
	// under denylist, a DENY only blocks when a rule ACTUALLY matched — a
	// default DENY means "nothing matched", which is exactly the case denylist
	// exists to allow.
	//
	// REVIEW is an escalation to a judge, and cloud routing is binary — there is
	// no judge to escalate to. Under denylist an unresolved REVIEW is an allow;
	// under whitelist it is not an ALLOW match, so the default-deny stands.
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

// MORE THAN ONE WILDCARD IS A PATTERN, not a literal asterisk.
//
// This used to branch on where the stars were: one at each end meant "contains", one at
// the start meant "ends with", one at the end meant "begins with", and exactly one in the
// middle meant prefix-plus-suffix. Any other arrangement fell through to a comparison
// against the pattern WITH THE ASTERISK STILL IN IT, so these matched nothing at all:
//
//	https://*.github.com/*     written to allow GitHub; allowed nothing
//	git push * --force*        written to block force-pushes; blocked nothing
//
// Both read correctly in `policy show`, which is the whole problem: a rule that enforces
// nothing is indistinguishable from one that enforces something until the day it was
// supposed to stop a call and did not. The second of those two is a rule somebody wrote
// precisely because they did not trust themselves to remember.
//
// The implementation is a scan rather than a compiled regexp, deliberately. These
// patterns come out of a policy file, a star run like `a***b` is a sequence somebody
// types by accident, and a backtracking engine turns that into a stall in the one code
// path that runs before every tool call. This walks the string once per segment and can
// do no worse.
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

	// The first segment is anchored to the start unless the pattern opened with a star.
	if parts[0] != "" {
		if !strings.HasPrefix(s, parts[0]) {
			return false
		}
		s = s[len(parts[0]):]
	}

	// Each middle segment must appear, in order, after the one before it. Earliest match
	// wins: a later one can only make the remaining suffix shorter, never longer, so
	// taking the first occurrence never loses a match that a later one would have found.
	for _, part := range parts[1 : len(parts)-1] {
		if part == "" {
			continue // a run of stars is one star
		}
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}

	// And the last is anchored to the end unless the pattern closed with a star.
	if last := parts[len(parts)-1]; last != "" {
		return strings.HasSuffix(s, last)
	}
	return true
}

// PathPatternRegex compiles a path pattern to an anchored regular expression
// with SEGMENT semantics: the pattern names directories, and the wildcards say
// where that directory may sit, not which characters may surround it.
//
//	*secrets*   a directory called secrets anywhere, and everything under it
//	secrets*    only a top-level secrets, and everything under it
//	*secrets    a directory called secrets anywhere, the directory itself
//	secrets     only a top-level secrets, the directory itself
//
// `my-secrets-notes.txt` and `mysecret/` match NONE of them, which is the whole
// point: a substring matcher blocks files whose names merely mention the word,
// and misses the directory the rule was written for when the path arrives
// relative. Both were live behaviours before this.
//
// A `*` INSIDE the pattern keeps its ordinary meaning, bounded by the separator
// (`[^/]*`), so `**/*.env` is still every .env file at any depth while `*.env`
// is a file named exactly `.env`. Leading and trailing runs of `*` are the
// nesting markers and are consumed as such; `?` matches one non-separator
// character.
//
// The expression is built from a lowercased pattern and carries no case flag —
// callers either lowercase the subject (Go) or compile case-insensitively (the
// generated Rego prefixes `(?i)`).
func PathPatternRegex(pattern string) string {
	g := strings.ToLower(strings.ReplaceAll(pattern, `\`, "/"))
	leading := strings.HasPrefix(g, "*")
	trailing := strings.HasSuffix(g, "*")
	core := strings.Trim(g, "*")
	// A separator left behind by the stripped wildcard is punctuation, not an
	// absolute-path anchor: `**/secrets/**` and `*secrets*` are the same rule.
	// Without a leading wildcard the separator IS the anchor, so `/etc/**` stays
	// rooted at /etc.
	if leading {
		core = strings.TrimPrefix(core, "/")
	}
	core = strings.TrimSuffix(core, "/")
	if core == "" {
		return `^.*$` // the pattern was nothing but wildcards
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

// Compiled patterns are cached: one guard process evaluates the same handful of
// rules against every path a call touches, and compiling per path showed up in
// the hook's own timing before this existed.
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
		re = nil // an uncompilable pattern matches nothing rather than everything
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

// A rule with a permission set applies only to calls in that category; an empty
// one applies to all of them.
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
	guessed := sgshared.GuessPermission(toolName)
	for _, p := range perms {
		if p == guessed {
			return true
		}
	}
	return false
}

// Each constraint keeps its patterns in `denied` or `allowed` depending on which
// effect the rule was created with in the dashboard. Both are the same pattern
// list here; the rule's EFFECT decides what a match means.
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

func ruleMatches(rule PolicyRule, args map[string]interface{}, isExec bool) *ruleHit {
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

	// DENY pass — runs in both modes. A DENY always wins over an ALLOW.
	var denyRules []PolicyRule
	for _, r := range rules {
		if r.enabledForFallback() && r.Effect == "DENY" && permissionApplies(r, toolName) {
			denyRules = append(denyRules, r)
		}
	}
	sortRulesByPriority(denyRules)
	for _, rule := range denyRules {
		if m := ruleMatches(rule, args, isExec); m != nil {
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
		if ruleMatches(rule, args, isExec) != nil {
			return ""
		}
	}
	return "Blocked by policy: strict whitelist mode — request does not match any ALLOW rule"
}
