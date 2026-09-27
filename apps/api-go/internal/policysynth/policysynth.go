// Package policysynth is the port of src/lib/policy-synth.ts: the rule
// generator behind POST /v1/policies/learn.
//
// It reads a project's own audit history and proposes a whitelist — one ALLOW
// rule per (tool, permission) pair that was observed being allowed, scoped by
// the paths, commands and URLs those calls actually touched. Nothing here writes
// anything; the route hands the result back for a person to look at.
//
// The rules it emits are the shape packages/sgpolicy compiles: id, description,
// effect, priority, toolPattern, permission, minimumTrustLevel, enabled and the
// three constraint sets, spelled exactly as sgpolicy.PolicyRule's json tags
// spell them. That is not a coincidence to preserve loosely — a learned policy
// is meant to be saved through POST /v1/policies and then compiled to Rego, and
// a renamed field would be a rule the compiler reads as empty, which for an
// ALLOW rule in a whitelist means "matches nothing" and for the policy as a
// whole means "denies everything".
//
// Two behaviours look like bugs and are the original's. A DENIED call
// contributes nothing to the rules — Learn Mode proposes what was allowed and
// summarises what was not, separately. And `loose` emits NO constraints at all
// rather than looser ones, so a loose policy is scoped by tool and permission
// only.
package policysynth

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/codeyevsky/solongate/api/internal/policyjson"
)

// Tightness is how far a constraint is generalised from the values observed.
const (
	Tight    = "tight"
	Balanced = "balanced"
	Loose    = "loose"
)

// ParseTightness is `['tight','balanced','loose'].includes(body.tightness) ?
// body.tightness : 'balanced'`.
//
// Array.prototype.includes compares with ===, so a number, a null or the string
// "TIGHT" all fall through to balanced. The default is the middle setting rather
// than the strictest, which matters: a typo in the request must not quietly
// propose a policy that pins every rule to the exact file paths in the sample.
func ParseTightness(v any) string {
	if s, ok := v.(string); ok {
		switch s {
		case Tight, Balanced, Loose:
			return s
		}
	}
	return Balanced
}

// Input is one observed call. Args is the parsed arguments_summary, or nil when
// the column was empty or held something that is not a JSON object — which is a
// normal state of that column, since it is truncated on write.
//
// Permission and TrustLevel are expected to carry the route's defaults already
// (EXECUTE and UNTRUSTED); they are defaulted again here because the original
// does it in both places and a caller that skips it must not produce a rule
// scoped to the empty permission.
type Input struct {
	Tool       string
	Permission string
	TrustLevel string
	Decision   string
	Args       *policyjson.Object
}

// Constraint is a rule's allowed list for one kind of value. Only `allowed` is
// ever produced here — Learn Mode builds a whitelist, so there is nothing to
// deny — and the field is omitted when empty rather than written as `[]`,
// because an empty allowed list in the evaluator means "no constraint" while an
// absent one means the same thing more cheaply.
type Constraint struct {
	Allowed []string `json:"allowed,omitempty"`
}

// Rule is one synthesised rule, and its json tags are the wire contract with
// both the dashboard's Learn Mode page and the policy compiler.
//
// SampleCount and LowConfidence are NOT serialised. The original carries them as
// `_sampleCount` and `_lowConfidence` on the same object and strips them with a
// destructure before the policy goes out, precisely so a policy saved straight
// from this response does not carry two fields the compiler would ignore and the
// hash would include. They travel to the caller in `rules_meta` instead.
type Rule struct {
	ID                 string      `json:"id"`
	Description        string      `json:"description"`
	Effect             string      `json:"effect"`
	Priority           int         `json:"priority"`
	ToolPattern        string      `json:"toolPattern"`
	Permission         string      `json:"permission"`
	MinimumTrustLevel  string      `json:"minimumTrustLevel"`
	Enabled            bool        `json:"enabled"`
	PathConstraints    *Constraint `json:"pathConstraints,omitempty"`
	CommandConstraints *Constraint `json:"commandConstraints,omitempty"`
	URLConstraints     *Constraint `json:"urlConstraints,omitempty"`

	SampleCount   int  `json:"-"`
	LowConfidence bool `json:"-"`
}

// Stats is the summary the page shows above the proposed rules. The keys are
// camelCase because the original's object literal is.
type Stats struct {
	Sampled            int `json:"sampled"`
	AllowSampled       int `json:"allowSampled"`
	DenySampled        int `json:"denySampled"`
	RulesGenerated     int `json:"rulesGenerated"`
	LowConfidenceRules int `json:"lowConfidenceRules"`
	DistinctTools      int `json:"distinctTools"`
}

// Policy is synthesizePolicy's return. `mode` is not carried: it is the constant
// "whitelist" and the route writes it into the response itself, as the original
// does.
type Policy struct {
	Rules []Rule
	Stats Stats
}

// The argument keys each constraint kind reads. They are policy-synth.ts's own
// lists and they are NOT the same as the estimator's in internal/policyeval —
// that one also has a `filename` kind, this one does not. Aligning them would
// change which rules Learn Mode proposes.
var (
	pathKeys = []string{"file_path", "path", "notebook_path", "dir", "directory"}
	cmdKeys  = []string{"command", "cmd", "script"}
	urlKeys  = []string{"url", "uri", "endpoint", "href"}
)

// collect pulls the string arguments under a set of keys, TRIMMED.
//
// The trim is the difference from policyeval's collect, which takes the value as
// it is. It matters at both ends: a path with a trailing newline becomes a
// constraint with a trailing newline here, and the estimator then matches the
// untrimmed value against it.
func collect(args *policyjson.Object, keys []string) []string {
	if args == nil {
		return nil
	}
	var out []string
	for _, k := range keys {
		if s, ok := args.Get(k).(string); ok {
			if t := strings.TrimSpace(s); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

// dirGlob is the directory of a path plus `/**`.
//
// `idx <= 0` returns the path untouched, which covers both "no slash at all" and
// a path that begins with one — "/etc" would otherwise generalise to "/**",
// which is every absolute path on the machine. That guard is the original's and
// is the single most consequential line in this file.
func dirGlob(p string) string {
	norm := strings.ReplaceAll(p, `\`, "/")
	idx := strings.LastIndex(norm, "/")
	if idx <= 0 {
		return norm
	}
	return norm[:idx] + "/**"
}

// cmdGlob keeps the executable and wildcards the arguments: `git status`
// becomes `git *`.
func cmdGlob(c string) string {
	if fields := strings.Fields(c); len(fields) > 0 {
		return fields[0] + " *"
	}
	return strings.TrimSpace(c) + " *"
}

// urlGlob keeps the origin and wildcards the path.
//
// `new URL(u)` throws for anything without a scheme and the original falls back
// to the raw value, so the equivalent test here is Scheme != "" — Go's url.Parse
// accepts a bare path and would otherwise turn "docs/index.html" into "//*".
//
// The host is lower-cased because the URL constructor normalises it and Go does
// not. Two normalisations are NOT reproduced and are written down rather than
// left to be discovered: the default port is stripped by the browser's parser
// ("https://x:443/" gives host "x") and an internationalised host is
// punycoded. Both would produce a slightly narrower glob than the live route
// does, which for an ALLOW rule means refusing a call the original would permit.
func urlGlob(u string) string {
	parsed, err := url.Parse(u)
	if err != nil || parsed.Scheme == "" {
		return u
	}
	return parsed.Scheme + "://" + strings.ToLower(parsed.Host) + "/*"
}

// generalize turns observed values into constraint globs.
//
// `loose` returns nothing at all — see the package note. `tight` keeps the value
// itself with backslashes normalised, and it does that for EVERY kind, including
// commands and URLs, which is why the switch is inside the balanced branch only.
func generalize(values []string, kind string, tightness string) []string {
	if tightness == Loose {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, v := range values {
		g := strings.ReplaceAll(v, `\`, "/")
		if tightness != Tight {
			switch kind {
			case "path":
				g = dirGlob(v)
			case "command":
				g = cmdGlob(v)
			default:
				g = urlGlob(v)
			}
		}
		if !seen[g] {
			seen[g] = true
			out = append(out, g)
		}
	}
	// `[...set].sort()`: JavaScript's default string sort orders by UTF-16 code
	// unit and Go's orders by byte. The two agree for everything below U+10000;
	// see policyjson.SortedKeys, which says the same thing about the same
	// difference.
	sort.Strings(out)
	return out
}

// lowConfidenceThreshold is the sample count below which a rule is flagged. It
// is not enforced anywhere — the rule is still proposed — it is what the page
// puts a warning badge on.
const lowConfidenceThreshold = 3

var trustOrder = map[string]int{"UNTRUSTED": 0, "VERIFIED": 1, "TRUSTED": 2}

var trustName = [3]string{"UNTRUSTED", "VERIFIED", "TRUSTED"}

// group is one (tool, permission) pair's accumulated evidence.
type group struct {
	tool       string
	permission string
	minTrust   int
	paths      []string
	cmds       []string
	urls       []string
	count      int
}

// Synthesize is synthesizePolicy.
//
// The grouping container is a JavaScript Map, so the rules come out in the order
// their first call was seen — and the sample is newest-first, so the tool used
// most recently gets priority 10. That ordering is visible in the proposed
// policy and is preserved rather than sorted into something tidier.
func Synthesize(inputs []Input, tightness string) Policy {
	order := []string{}
	groups := map[string]*group{}
	distinctTools := map[string]bool{}
	allowSampled, denySampled := 0, 0

	for _, in := range inputs {
		// `String(i.decision).toUpperCase() === 'ALLOW'`, so a row written as
		// "allow" by an older client counts as an allow here. The dry-run
		// estimator compares the same column exactly; both behaviours are live.
		if strings.ToUpper(in.Decision) != "ALLOW" {
			denySampled++
			continue
		}
		allowSampled++
		distinctTools[in.Tool] = true

		tool := in.Tool
		if tool == "" {
			tool = "unknown"
		}
		perm := in.Permission
		if perm == "" {
			perm = "EXECUTE"
		}
		perm = strings.ToUpper(perm)

		key := tool + "::" + perm
		g, ok := groups[key]
		if !ok {
			// 99 is the original's sentinel for "no call seen yet"; it is turned
			// back into UNTRUSTED below rather than indexing past the array.
			g = &group{tool: tool, permission: perm, minTrust: 99}
			groups[key] = g
			order = append(order, key)
		}
		g.count++

		trust := in.TrustLevel
		if trust == "" {
			trust = "UNTRUSTED"
		}
		// `?? 0` — an unrecognised trust level is the LOWEST, so a rule derived
		// from calls with a level this build does not know about demands nothing.
		// The alternative would be a rule that no call can satisfy.
		level := trustOrder[strings.ToUpper(trust)]
		if level < g.minTrust {
			g.minTrust = level
		}

		g.paths = append(g.paths, collect(in.Args, pathKeys)...)
		g.cmds = append(g.cmds, collect(in.Args, cmdKeys)...)
		g.urls = append(g.urls, collect(in.Args, urlKeys)...)
	}

	rules := make([]Rule, 0, len(order))
	priority := 10
	lowConfidence := 0
	for _, key := range order {
		g := groups[key]

		minTrust := g.minTrust
		if minTrust == 99 {
			minTrust = 0
		}
		if minTrust < 0 {
			minTrust = 0
		}
		if minTrust > 2 {
			minTrust = 2
		}

		plural := "s"
		if g.count == 1 {
			plural = ""
		}
		r := Rule{
			ID:                ruleID(g.tool, g.permission),
			Description:       fmt.Sprintf("Learned: allow %s (%s) from %d observed call%s", g.tool, g.permission, g.count, plural),
			Effect:            "ALLOW",
			Priority:          priority,
			ToolPattern:       g.tool,
			Permission:        g.permission,
			MinimumTrustLevel: trustName[minTrust],
			Enabled:           true,
			SampleCount:       g.count,
			LowConfidence:     g.count < lowConfidenceThreshold,
		}
		priority++
		if r.LowConfidence {
			lowConfidence++
		}
		if allowed := generalize(g.paths, "path", tightness); len(allowed) > 0 {
			r.PathConstraints = &Constraint{Allowed: allowed}
		}
		if allowed := generalize(g.cmds, "command", tightness); len(allowed) > 0 {
			r.CommandConstraints = &Constraint{Allowed: allowed}
		}
		if allowed := generalize(g.urls, "url", tightness); len(allowed) > 0 {
			r.URLConstraints = &Constraint{Allowed: allowed}
		}
		rules = append(rules, r)
	}

	return Policy{
		Rules: rules,
		Stats: Stats{
			Sampled:            len(inputs),
			AllowSampled:       allowSampled,
			DenySampled:        denySampled,
			RulesGenerated:     len(rules),
			LowConfidenceRules: lowConfidence,
			DistinctTools:      len(distinctTools),
		},
	}
}

// ruleID is `\`learn-${tool}-${perm}\`.toLowerCase().replace(/[^a-z0-9-]/g,'-')`.
//
// The substitution runs over UTF-16 CODE UNITS, not characters, because that is
// what a JavaScript regular expression without the `u` flag does: a tool name
// containing an astral character becomes two dashes, not one. Reproducing that
// matters because this id is what the dashboard sends back when it saves the
// rule, and an id that differs between the two implementations is a rule that
// looks new every time it is re-learned.
func ruleID(tool, permission string) string {
	units := utf16.Encode([]rune(strings.ToLower("learn-" + tool + "-" + permission)))
	for i, u := range units {
		if (u >= 'a' && u <= 'z') || (u >= '0' && u <= '9') || u == '-' {
			continue
		}
		units[i] = '-'
	}
	return string(utf16.Decode(units))
}

// DenyGroup is one entry of the deny summary: what was refused, how often, and
// a few of the values it was refused for.
type DenyGroup struct {
	Tool             string   `json:"tool"`
	Permission       string   `json:"permission"`
	Count            int      `json:"count"`
	SampleReasonKeys []string `json:"sampleReasonKeys"`
}

const (
	denySampleValues = 5
	denyValueChars   = 80
)

// SummarizeDenies is summarizeDenies: what Learn Mode did NOT propose a rule
// for, so the person reading the page can see what a whitelist built from this
// sample would keep refusing.
//
// The grouping key uses the RAW permission while the reported one is
// upper-cased, which is the original's asymmetry: two rows recorded as "execute"
// and "EXECUTE" are two groups that both render as EXECUTE.
func SummarizeDenies(inputs []Input) []DenyGroup {
	order := []string{}
	groups := map[string]*DenyGroup{}
	seen := map[string]map[string]bool{}

	for _, in := range inputs {
		if strings.ToUpper(in.Decision) == "ALLOW" {
			continue
		}
		key := in.Tool + "::" + in.Permission
		g, ok := groups[key]
		if !ok {
			perm := in.Permission
			if perm == "" {
				perm = "EXECUTE"
			}
			g = &DenyGroup{Tool: in.Tool, Permission: strings.ToUpper(perm), SampleReasonKeys: []string{}}
			groups[key] = g
			seen[key] = map[string]bool{}
			order = append(order, key)
		}
		g.Count++

		// Commands first, then paths — the original's concatenation order, and it
		// decides which five values are kept when a group has more.
		for _, v := range append(collect(in.Args, cmdKeys), collect(in.Args, pathKeys)...) {
			v = clipUTF16(v, denyValueChars)
			if seen[key][v] {
				continue
			}
			seen[key][v] = true
			if len(g.SampleReasonKeys) < denySampleValues {
				g.SampleReasonKeys = append(g.SampleReasonKeys, v)
			}
		}
	}

	out := make([]DenyGroup, 0, len(order))
	for _, key := range order {
		out = append(out, *groups[key])
	}
	// Stable, because Array.prototype.sort is: two tools denied the same number
	// of times keep the order they were first seen in.
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

// clipUTF16 is `v.slice(0, 80)`, in the units JavaScript slices by. A byte slice
// would cut a multi-byte character in half and put invalid UTF-8 in a response.
func clipUTF16(s string, max int) string {
	units := utf16.Encode([]rune(s))
	if len(units) <= max {
		return s
	}
	return string(utf16.Decode(units[:max]))
}
