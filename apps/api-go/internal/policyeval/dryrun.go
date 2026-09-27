// Package policyeval is the port of src/lib/dry-run.ts and src/lib/backtest.ts:
// the estimator behind POST /policies/dry-run and POST /policies/backtest.
//
// It is NOT the policy engine. It is a deliberately cheaper approximation that
// replays a project's own audit history against a set of candidate rules to
// answer "what would this change break", and the backtest route says so on the
// wire: `engine: "estimate"`. Where it and the real evaluator disagree — this
// one reads a fixed list of argument keys, the guard runs four extractors over
// the whole argument tree — the guard is right and this is a preview.
//
// Reproducing its quirks is still the job, because the dashboard's Policy Dry
// Run page and the CLI's `solongate policy backtest` both render these numbers
// and a change of one is a change in what somebody was told before they hit
// save. The two that look like bugs and are not: an empty candidate list
// satisfies every constraint (a call that touches no paths cannot violate a
// path rule), and dry-run compares the recorded decision with `=== 'ALLOW'`
// while backtest upper-cases it first.
package policyeval

import (
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/codeyevsky/solongate/api/internal/policyjson"
)

// Mode is the policy's default when no rule matches. It is applied AFTER
// evaluation, which is why a denylist policy with no matching rule allows.
const (
	ModeDenylist  = "denylist"
	ModeWhitelist = "whitelist"
)

// ParseMode is `body.mode === 'whitelist' ? 'whitelist' : 'denylist'`. Anything
// unrecognised is a denylist, which is the permissive answer — and is the live
// behaviour, so a typo in the request does not silently make the preview look
// far more restrictive than the policy is.
func ParseMode(v any) string {
	if s, ok := v.(string); ok && s == ModeWhitelist {
		return ModeWhitelist
	}
	return ModeDenylist
}

// ConstraintSet is a rule's allowed/denied pair for one kind of value.
type ConstraintSet struct {
	Allowed []string
	Denied  []string
	Present bool
}

// Rule is one candidate rule as the request carries it. Every field is
// optional, because the dashboard sends partial rules while the editor is open.
type Rule struct {
	ID                string
	Effect            string
	Enabled           bool
	Priority          float64
	ToolPattern       string
	Permissions       []string
	HasPermission     bool
	MinimumTrustLevel string

	Path     ConstraintSet
	Command  ConstraintSet
	Filename ConstraintSet
	URL      ConstraintSet
}

// Input is one historical call, replayed.
type Input struct {
	ID         string
	Tool       string
	Permission string
	TrustLevel string
	Args       *policyjson.Object
	Decision   string
	Agent      string
	HasAgent   bool
	// CreatedAtMS is the call's timestamp in milliseconds. The original passes
	// a Date through `new Date(x).toISOString()` and `getTime()`, so
	// milliseconds is the unit both the sample's created_at and the
	// timeseries bucket are derived from.
	CreatedAtMS int64
}

// ParseRules decodes the request's `rules` array. A non-array is (nil, false),
// which every caller answers with the VALIDATION_ERROR the routes send.
func ParseRules(v any) ([]Rule, bool) {
	arr, ok := policyjson.Array(v)
	if !ok {
		return nil, false
	}
	out := make([]Rule, 0, len(arr))
	for _, item := range arr {
		o, isObj := item.(*policyjson.Object)
		if !isObj {
			// The original would read every field off a non-object as
			// undefined, producing a rule with no effect that matches
			// everything and decides nothing. Dropping it is narrower and
			// cannot invent a decision.
			continue
		}
		out = append(out, ruleFrom(o))
	}
	return out, true
}

func ruleFrom(o *policyjson.Object) Rule {
	r := Rule{
		ID:                policyjson.Str(o.Get("id")),
		Effect:            policyjson.Str(o.Get("effect")),
		ToolPattern:       policyjson.Str(o.Get("toolPattern")),
		MinimumTrustLevel: policyjson.Str(o.Get("minimumTrustLevel")),
		// `r.enabled === false` is the only disabling value; a missing field
		// leaves the rule enabled.
		Enabled: o.Get("enabled") != any(false),
		// `a.priority ?? 100` — null and absent both take 100, and a stored 0
		// stays 0.
		Priority: 100,
	}
	if p, ok := o.Get("priority").(float64); ok {
		r.Priority = p
	}
	if perm := o.Get("permission"); policyjson.Truthy(perm) {
		r.HasPermission = true
		if arr, isArr := policyjson.Array(perm); isArr {
			for _, v := range arr {
				r.Permissions = append(r.Permissions, policyjson.Str(v))
			}
		} else {
			r.Permissions = []string{policyjson.Str(perm)}
		}
	}
	r.Path = constraintFrom(o.Get("pathConstraints"))
	r.Command = constraintFrom(o.Get("commandConstraints"))
	r.Filename = constraintFrom(o.Get("filenameConstraints"))
	r.URL = constraintFrom(o.Get("urlConstraints"))
	return r
}

func constraintFrom(v any) ConstraintSet {
	o, ok := v.(*policyjson.Object)
	if !ok {
		// `if (!c) continue` — a constraint that is not an object is not a
		// constraint, and the rule is simply not scoped by that kind.
		return ConstraintSet{}
	}
	c := ConstraintSet{Present: true}
	if arr, isArr := policyjson.Array(o.Get("allowed")); isArr {
		for _, s := range arr {
			c.Allowed = append(c.Allowed, policyjson.Str(s))
		}
	}
	if arr, isArr := policyjson.Array(o.Get("denied")); isArr {
		for _, s := range arr {
			c.Denied = append(c.Denied, policyjson.Str(s))
		}
	}
	return c
}

// ── matching ────────────────────────────────────────────────────────────────

var trustOrder = map[string]int{"UNTRUSTED": 0, "VERIFIED": 1, "TRUSTED": 2}

func toolPatternMatches(pattern, tool string) bool {
	if pattern == "" || pattern == "*" {
		return true
	}
	s := strings.HasPrefix(pattern, "*")
	e := strings.HasSuffix(pattern, "*")
	switch {
	case s && e:
		m := pattern[1 : len(pattern)-1]
		return m != "" && strings.Contains(tool, m)
	case e:
		return strings.HasPrefix(tool, pattern[:len(pattern)-1])
	case s:
		return strings.HasSuffix(tool, pattern[1:])
	}
	return pattern == tool
}

// trustMeets is `(TRUST_ORDER[actual] ?? -1) >= (TRUST_ORDER[minimum] ?? Infinity)`.
//
// The two fallbacks are opposite on purpose: an unrecognised ACTUAL level is
// the lowest possible, an unrecognised REQUIRED level is unreachable. So a
// typo in a rule's minimumTrustLevel makes the rule never fire rather than
// always fire, which for a DENY rule is the weaker answer and for an ALLOW rule
// is the safer one. It is the live behaviour either way.
func trustMeets(actual, minimum string) bool {
	if minimum == "" {
		return true
	}
	a, ok := trustOrder[actual]
	if !ok {
		a = -1
	}
	m, ok := trustOrder[minimum]
	if !ok {
		return false
	}
	return a >= m
}

// globToRegex is dry-run.ts's own glob, which is NOT the one the Rego compiler
// uses: `?` is ESCAPED here and becomes `.` there, and this one is
// case-insensitive by flag rather than by lower-casing both sides. Both
// differences are preserved — the preview has always been an approximation of
// the engine and quietly aligning them would change numbers the dashboard has
// been showing.
func globToRegex(glob string) (*regexp.Regexp, bool) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for _, r := range glob {
		switch r {
		case '*':
			b.WriteString(".*")
		case '.', '+', '?', '^', '$', '{', '}', '(', ')', '|', '[', ']', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		// `catch { return false }` — a pattern that will not compile matches
		// nothing rather than failing the whole request.
		return nil, false
	}
	return re, true
}

func matchesAnyGlob(value string, globs []string) bool {
	for _, g := range globs {
		if re, ok := globToRegex(g); ok && re.MatchString(value) {
			return true
		}
	}
	return false
}

// The argument keys each constraint kind reads. This is the shallow, fixed list
// the estimator uses; the guard's extractors walk the whole argument tree, so a
// path buried inside a nested object is invisible here and enforced there.
var argKeys = map[string][]string{
	"path":     {"file_path", "path", "notebook_path", "dir", "directory"},
	"command":  {"command", "cmd", "script"},
	"filename": {"file_path", "path", "notebook_path", "filename", "file"},
	"url":      {"url", "uri", "endpoint", "href"},
}

func collect(args *policyjson.Object, kind string) []string {
	if args == nil {
		return nil
	}
	var out []string
	for _, k := range argKeys[kind] {
		if s, ok := args.Get(k).(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// constraintSatisfied is `candidates.every(...)` over a possibly EMPTY list,
// and the empty case returning true is load-bearing: a call that carries no
// path cannot violate a path constraint, so a DENY rule scoped to paths does
// not fire on it. Without the early return the `every` would still be vacuously
// true; the line is explicit because it is the first thing anyone reading a
// surprising preview will question.
func constraintSatisfied(candidates []string, c ConstraintSet) bool {
	if len(candidates) == 0 {
		return true
	}
	for _, val := range candidates {
		if len(c.Denied) > 0 && matchesAnyGlob(val, c.Denied) {
			return false
		}
		if len(c.Allowed) > 0 && !matchesAnyGlob(val, c.Allowed) {
			return false
		}
	}
	return true
}

func ruleMatches(r Rule, in Input) bool {
	if !r.Enabled {
		return false
	}
	if r.HasPermission {
		found := false
		for _, p := range r.Permissions {
			if p == in.Permission {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if !toolPatternMatches(r.ToolPattern, in.Tool) {
		return false
	}
	if !trustMeets(in.TrustLevel, r.MinimumTrustLevel) {
		return false
	}

	checks := []struct {
		kind string
		c    ConstraintSet
	}{
		{"path", r.Path}, {"command", r.Command}, {"filename", r.Filename}, {"url", r.URL},
	}
	for _, ch := range checks {
		if !ch.c.Present {
			continue
		}
		satisfied := constraintSatisfied(collect(in.Args, ch.kind), ch.c)
		// A DENY rule fires when its constraints are VIOLATED; an ALLOW rule
		// fires only when they are met.
		if r.Effect == "DENY" {
			if satisfied {
				return false
			}
		} else if !satisfied {
			return false
		}
	}
	return true
}

// Verdict is one evaluated call. RuleID is empty when nothing matched and the
// mode default decided; the routes render that as JSON null.
type Verdict struct {
	Effect string
	RuleID string
}

// EvaluateCandidate is dry-run.ts's evaluateCandidate: priority order, first
// match wins, mode decides the rest.
func EvaluateCandidate(rules []Rule, mode string, in Input) Verdict {
	enabled := make([]Rule, 0, len(rules))
	for _, r := range rules {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	// Stable, because Array.prototype.sort is: two rules at the same priority
	// keep the order the request listed them in, and that order decides which
	// one the preview blames.
	sort.SliceStable(enabled, func(i, j int) bool { return enabled[i].Priority < enabled[j].Priority })

	for _, r := range enabled {
		if ruleMatches(r, in) {
			return Verdict{Effect: r.Effect, RuleID: r.ID}
		}
	}
	if mode == ModeWhitelist {
		return Verdict{Effect: "DENY"}
	}
	return Verdict{Effect: "ALLOW"}
}

// ── previews ────────────────────────────────────────────────────────────────

var previewKeys = []string{"command", "cmd", "script", "file_path", "path", "notebook_path", "url", "pattern", "query"}

// DryRunPreview is argPreview: the named keys first, then ANY string argument.
// The second pass is why the preview needs an ordered args object — "any
// string" means the first one in the order the hook wrote them, and a Go map
// would answer with a different one on every request.
func DryRunPreview(tool string, args *policyjson.Object) string {
	if args == nil {
		return tool
	}
	if s, ok := firstPreviewable(args, previewKeys); ok {
		return s
	}
	for _, k := range args.Keys() {
		if s, ok := previewable(args.Get(k)); ok {
			return s
		}
	}
	return tool
}

// BacktestPreview is previewOf, which has only the first pass. The two
// functions differ by that loop in the original and the difference is visible:
// a call whose only argument is an unlisted key previews as its own tool name
// in the backtest and as the argument in the dry run.
func BacktestPreview(tool string, args *policyjson.Object) string {
	if args == nil {
		return tool
	}
	if s, ok := firstPreviewable(args, previewKeys); ok {
		return s
	}
	return tool
}

func firstPreviewable(args *policyjson.Object, keys []string) (string, bool) {
	for _, k := range keys {
		if s, ok := previewable(args.Get(k)); ok {
			return s, true
		}
	}
	return "", false
}

func previewable(v any) (string, bool) {
	s, ok := v.(string)
	if !ok || strings.TrimSpace(s) == "" {
		return "", false
	}
	line := strings.TrimSpace(s)
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	return clipUTF16(line, 100), true
}

// clipUTF16 is `s.length > 100 ? s.slice(0, 100) + '…' : s`.
//
// JavaScript measures and slices in UTF-16 code units, so a preview full of
// CJK is cut at a different point than a rune count would give and one full of
// emoji at a different point again. The ellipsis is U+2026, one character, as
// the original writes it.
func clipUTF16(s string, max int) string {
	units := utf16.Encode([]rune(s))
	if len(units) <= max {
		return s
	}
	return string(utf16.Decode(units[:max])) + "…"
}
