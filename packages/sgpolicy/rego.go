package sgpolicy

// The policy compiler: a SolonGate policy (JSON, as the dashboard writes it)
// becomes Rego source here, in this process, on every call.
//
// The API can already do this — `/policies/:id/rego` exists and works — and
// fetching it would be less code. Compiling locally is the point: it takes the
// network off the decision path entirely. A guard that has to ask a server what
// the rules are is a guard that fails differently depending on the wifi, and
// this one now decides the same way on a plane as in an office.
//
// WHICH GENERATOR THIS PORTS, because there are two and only one of them is
// real: apps/api/src/lib/opa/json-to-rego.ts. That is what opa-compiler.ts
// compiles every saved policy with, so it is what the served WASM does, so it
// is what the Node hook actually evaluates. The near-identical copy at
// packages/proxy/src/policy-engine/opa/json-to-rego.ts is the MCP-proxy
// lineage; nothing compiles policies with it any more, and it differs in four
// ways that each silently change a decision — see the marked sites below.
//
// The generated Rego is a priority-ordered `else` chain, so the first matching
// rule wins, and it always ends with a `default decision` of DENY. That default
// is NOT the policy's default — mode is re-applied after evaluation (see
// policy.go). Confusing those two makes every denylist policy block everything.

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

// The Rego compiler treats a missing `enabled` as disabled; the fallback
// evaluator treats it as enabled. That difference is inherited from the Node
// implementation, where the two paths were written years apart, and it is
// preserved rather than reconciled — picking either answer here would change
// which rules fire on somebody's live policy, which is not a change to make
// while porting.
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

// Path patterns compile to an anchored regular expression with SEGMENT
// semantics (see PathPatternRegex), not to a glob. `(?i)` carries the case
// insensitivity the Go-side matcher gets by lowercasing its subject.
//
// glob.match was what this used to emit, and it could not express the rule
// people were actually writing: with ["/"] as the delimiter a `*` never crosses
// a separator, so `*secrets*` matched the file `my-secrets-notes.txt` and
// missed the directory `app/secrets/`.
func normPathPattern(s string) string {
	return EscapeRegoString("(?i)" + PathPatternRegex(s))
}

// rootDirectory is a literal prefix rather than a pattern — it is fed to
// startswith, not to the matcher — so it only needs its separators normalised.
func normPathLiteral(s string) string {
	return EscapeRegoString(strings.ReplaceAll(s, `\`, "/"))
}

// jsTruthy mirrors the `if (rule.permission)` guards in the original. A field
// that is absent, empty or false generates no condition; anything else does.
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

// jsToString mirrors JavaScript template interpolation for the values that can
// reach a generated literal.
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

// permissionList flattens `permission`, which the dashboard writes as a STRING
// when one box is ticked and an ARRAY when several are.
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

// Command, filename and URL patterns compile to ONE anchored alternation
// regex, not to per-pattern glob matches.
//
// This is the difference between the two generators that matters most. OPA
// reads an EMPTY glob delimiter list as ["."], so under the proxy lineage `*`
// does not cross a dot and `curl*` never matches `curl evil.example.com/x`.
// Compiled to `^(?:curl.*)$` it does. Porting the wrong one here would have
// left every command, filename and URL rule quietly weaker than the dashboard
// shows it to be, and only for targets containing a dot — which is most of the
// interesting ones.
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

// convertRulesToRego is the port of convertPolicySetToRego.
func ConvertRulesToRego(rules []PolicyRule) string {
	sorted := make([]PolicyRule, len(rules))
	copy(sorted, rules)
	// DENY FIRST, THEN BY PRIORITY. The chain this emits decides on the first rule
	// that matches, so ordering IS the semantics — and sorting by priority alone
	// let an ALLOW written above a DENY of the same priority win.
	//
	// Which made this engine disagree with the other two about a real policy. The
	// Node hook runs a DENY pass over every deny rule before it considers an
	// ALLOW ("DENY wins over ALLOW", in both modes) and so does FallbackEvaluate
	// twenty lines below. Measured before this: whitelist mode, `ALLOW *` above
	// `DENY *secret*` at the same priority, `cat secret` — the hook blocked it and
	// the binary allowed it, in denylist mode too. A machine runs whichever of the
	// two it has.
	//
	// It also meant REORDERING RULES CHANGED WHAT WAS ENFORCED, silently, with no
	// priority anywhere to explain why.
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
		`# Helper: check if an item matches any pattern in a list`,
		`list_matches_any(item, patterns) if {`,
		`    some pattern in patterns`,
		`    glob.match(pattern, [], item)`,
		`}`,
		``,
		`# Default decision: DENY (no matching rule)`,
		`default decision := {"effect": "DENY", "reason": "No matching policy rule found. Default action: DENY.", "matched_rule": null}`,
		``,
	}

	// The original keys the head-vs-else choice off the loop index, so a policy
	// whose FIRST rule is disabled emits a chain that opens with `} else :=` —
	// not parseable Rego. Keying it off "have we emitted a head yet" produces
	// byte-identical output for every policy the original compiles, and valid
	// output for the one it does not.
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

// The reason shown to the model when a rule carries no description of its own.
// It stands in for "Matched rule "x": DENY", so it has to say what the rule
// actually did rather than just naming the effect.
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
	// filenameConstraints wins over pathConstraints when both are present: the
	// original uses `??`, which falls through only on null/undefined.
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

	// One permission is an equality; several are a set membership. The proxy
	// lineage interpolated the array straight into a string literal, producing
	// `input.permission == "READ,WRITE"` — a value no input can ever equal — so
	// a rule scoped to two permissions silently stopped enforcing entirely.
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

	// A rule with no conditions at all is a catch-all; Rego needs a body.
	if len(conds) == 0 {
		conds = append(conds, "true")
	}
	return conds
}

// The tool selector is internal and fixed to "*" in the shipped product — no UI
// or CLI exposes it. Kept general for the engine.
func generateToolPatternCondition(pattern string) []string {
	if pattern == "*" {
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
				conds = append(conds, argRef) // just assert it exists
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

// Path constraints are asymmetric on purpose. A DENY rule matches when the
// constraints are VIOLATED — that is what makes it a denial. An ALLOW rule
// matches only when EVERY path satisfies them, so one bad path in a batch
// cannot ride along with the good ones.
//
// The `count(...) > 0` guards are load-bearing, not defensive: in Rego an
// `every` over an EMPTY collection is vacuously true, so without them an ALLOW
// rule scoped to paths matches any call that touches no paths at all. Under
// whitelist mode that is a blanket allow for exactly the calls nobody wrote a
// rule for.
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

// Same asymmetry for commands, filenames and URLs, compiled to one anchored
// alternation regex rather than to per-pattern glob matches.
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

// parsePolicyRules decodes the rule array ONE RULE AT A TIME.
//
// Decoding it in a single Unmarshal meant one wrongly-typed field anywhere in
// the policy — a `denied` written as a bare string, a quoted priority,
// `enabled: 1` — failed the whole decode, and a policy that would not decode
// was being read as NO policy, i.e. allow everything. A hand-edited or uploaded
// policy JSON could disarm the guard completely while the dashboard still
// showed its rules as active. That is the one failure direction this port is
// not allowed to have.
//
// A rule that will not decode at all is salvaged field by field, and only what
// is well typed survives — which is what the Node hook effectively does by
// guarding each constraint with Array.isArray and ignoring the rest.
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
		// One bad constraint must not cost the rule its other constraints, and
		// losing a DENY rule is the dangerous direction.
		if salvaged, ok := salvageRule(item); ok {
			rules = append(rules, salvaged)
		}
	}
	return rules, true
}

// salvageRule decodes whatever of a rule is well typed and discards the rest.
//
// A rule can only ever come out of here NARROWER than it was written, never
// wider. Dropping a constraint that will not decode would otherwise leave a
// rule with no conditions at all, and a rule with no conditions compiles to a
// catch-all — so a single mistyped `denied` would turn one DENY rule into "deny
// everything". The Node hook reaches the same end by a different route: its
// constraint reader returns nothing for a non-array, and a rule with nothing to
// match on never matches.
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

	// A rule with no effect cannot decide anything.
	if r.Effect == "" {
		return PolicyRule{}, false
	}
	// The rule was scoped to something, and none of that scope survived. Keeping
	// it would compile it to a catch-all, which is the opposite of what it says.
	if constraintsSeen > 0 && constraintsKept == 0 {
		return PolicyRule{}, false
	}
	return r, true
}
