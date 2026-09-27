package main

// ── Prompt Injection Detection (Stage 1: Rule-Based) ──
//
// Ported from the Node hook so the two can be diffed side by side: same
// categories, same patterns in the same order, same weights, same arithmetic.
// Stage 1 is the cheap pass — fixed patterns, no model, no network. It only ever
// produces a score and a verdict; what to do with a blocked verdict belongs to
// the caller.

import (
	"math"
	"regexp"
	"strings"
)

// JS's \s covers every Unicode space character; Go's covers [\t\n\f\r ] and
// nothing else. For a detector whose entire job is spotting evasion that gap is
// a hole: `###<U+00A0>Human:` is the same injection as `### Human:` and the
// ASCII-only class walks straight past it. Every \s in the patterns below is
// therefore expanded to the exact ECMAScript set — WhiteSpace plus
// LineTerminator, i.e. \p{Zs} (which carries NBSP, the ideographic space and the
// en/em quad family), vertical tab, U+2028/U+2029 and the zero-width no-break
// space. U+0085 NEL is absent on purpose: JS does not count it as \s either, and
// widening the port past the original would make the two implementations
// disagree about the same text.
const piSpace = `[\t\n\v\f\r\x{2028}\x{2029}\x{feff}\p{Zs}]`

// piRe compiles one ported pattern, expanding \s on the way through.
//
// The expansion is textual, which is safe only because no pattern here puts \s
// inside a character class — check that before adding one, or the class comes
// out nested and the compile fails.
//
// MustCompile is deliberate: every source below is a constant, so a failure is a
// build-time bug that the conformance suite catches. The alternative — skipping
// whatever will not compile — is a detection that disappears silently, which is
// the one failure mode this layer cannot have.
func piRe(src string) *regexp.Regexp {
	return regexp.MustCompile(strings.ReplaceAll(src, `\s`, piSpace))
}

func piPatterns(srcs ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(srcs))
	for _, s := range srcs {
		out = append(out, piRe(s))
	}
	return out
}

type piCategory struct {
	name     string
	weight   float64
	patterns []*regexp.Regexp
}

// piResult mirrors the object the Node hook returns. A nil *piResult is its
// `null`: nothing matched at all, which a caller has to keep distinguishable
// from a match that merely scored above the threshold.
type piResult struct {
	Score      float64  `json:"score"`
	TrustScore float64  `json:"trustScore"`
	Categories []string `json:"categories"`
	Blocked    bool     `json:"blocked"`
}

// The Node signature defaults to 0.5; Go has no default arguments, so callers
// pass this rather than repeating the literal and drifting from it.
const piDefaultThreshold = 0.5

// A slice, not a map: the order decides the order of `categories` in the result
// and, through the highest weight seen, nothing else — but the audit log stores
// that list verbatim, so a randomised order would make two identical calls
// produce two different log entries.
var piCategories = []piCategory{
	{
		name: "delimiter_injection", weight: 0.95,
		patterns: piPatterns(
			`(?i)</system>`, `(?i)<\|im_end\|>`, `(?i)<\|im_start\|>`, `(?i)<\|endoftext\|>`,
			`(?i)\[INST\]`, `(?i)\[/INST\]`, `(?i)<<SYS>>`, `(?i)<</SYS>>`,
			`(?i)###\s*(Human|Assistant|System)\s*:`, `(?i)<\|user\|>`, `(?i)<\|assistant\|>`,
			`(?i)---\s*END\s*SYSTEM\s*PROMPT\s*---`,
		),
	},
	{
		name: "instruction_override", weight: 0.9,
		patterns: piPatterns(
			`(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|rules?|directives?)\b`,
			`(?i)\bdisregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|prompts?|rules?|guidelines?)\b`,
			`(?i)\bforget\s+(all\s+|everything\s+)?(your|the|previous|prior|above|earlier)\b`,
			`(?i)\boverride\s+(the\s+)?(system|previous|current)\s+(prompt|instructions?|rules?|settings?)\b`,
			`(?i)\bdo\s+not\s+follow\s+(your|the|any)\s+(instructions?|rules?|guidelines?)\b`,
			`(?i)\bcancel\s+(all\s+)?(prior|previous)\s+(directives?|instructions?)\b`,
			`(?i)\bnew\s+instructions?\s+supersede\b`,
			`(?i)\byour\s+(previous\s+)?instructions?\s+are\s+(now\s+)?void\b`,
		),
	},
	{
		name: "role_hijacking", weight: 0.85,
		patterns: piPatterns(
			`(?i)\b(pretend|act|behave)\s+(you\s+are|as\s+if\s+you|like\s+you|to\s+be)\b`,
			`(?i)\byou\s+are\s+now\s+(a|an|the|my|DAN)\b`,
			`(?i)\bsimulate\s+being\b`, `(?i)\bassume\s+the\s+role\s+of\b`,
			`(?i)\benter\s+(developer|admin|debug|god|sudo|unrestricted)\s+mode\b`,
			`(?i)\bswitch\s+to\s+(unrestricted|unfiltered)\s+mode\b`,
			`(?i)\byou\s+are\s+no\s+longer\s+bound\b`,
			`(?i)\bno\s+(safety\s+)?restrictions?\s+(apply|anymore|now)\b`,
		),
	},
	{
		name: "jailbreak_keywords", weight: 0.8,
		patterns: piPatterns(
			`(?i)\bjailbreak\b`, `(?i)\bDAN\s+mode\b`,
			`(?i)\b(system\s+override|admin\s+mode|debug\s+mode|developer\s+mode|maintenance\s+mode)\b`,
			`(?i)\bmaster\s+key\b`, `(?i)\bbackdoor\s+access\b`,
			`(?i)\bsudo\s+mode\b`, `(?i)\bgod\s+mode\b`,
			`(?i)\bsafety\s+filters?\s+(off|disabled?|removed?)\b`,
		),
	},
	{
		name: "encoding_evasion", weight: 0.75,
		patterns: piPatterns(
			`(?i)\b(decode|translate)\s+(this|the\s+following)\s+(base64|rot13|hex)\b`,
			`(?i)\b(base64|rot13)\s*:\s*[A-Za-z0-9+/=]{10,}`,
			`(?i)\bexecute\s+the\s+(reverse|decoded)\b`,
			`(?i)\breverse\s+of\s*:\s*\w{10,}`,
		),
	},
	{
		name: "separator_injection", weight: 0.7,
		patterns: piPatterns(
			`(?i)[-=]{3,}\s*\n\s*(new\s+instructions?|system|instructions?)\s*:`,
			// A Go raw string cannot hold a backtick, hence the join. The pattern is
			// the original's /```\s*\n\s*<\/?system>/i unchanged.
			"(?i)"+"```"+`\s*\n\s*</?system>`,
			// /is in the original: the two halves are routinely split across lines,
			// so `.` has to cross a newline here and only here.
			`(?is)\bEND\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS?)\b.*\bNEW\s+(SYSTEM\s+)?(PROMPT|INSTRUCTIONS?)\b`,
		),
	},
	{
		// The same overrides in the languages the English list would miss entirely.
		// Written against the plain word forms rather than \b-anchored, because \b
		// is ASCII-only on both sides and would refuse to fire next to a Cyrillic
		// or Turkish letter.
		name: "multi_language", weight: 0.7,
		patterns: piPatterns(
			`(?i)ignor(iere|a|e[zs]?)\s+(alle|todas?|toutes?|tüm|все)`,
			`(?i)игнорируйте`, `(?i)yoksay`,
			`(?i)vorherigen?\s+Anweisungen`, `(?i)instrucciones\s+anteriores`,
			`(?i)instructions?\s+pr[eé]c[eé]dentes?`, `(?i)önceki\s+talimatlar`,
		),
	},
}

// piCategorySpec is how a custom category arrives from configuration: patterns
// still as strings. Not in the Node original — there the caller hands over
// RegExp objects it built itself — but JSON has to become something compiled
// before it can match anything. Flags are the author's job: write `(?i)` into
// the pattern, the same way the built-ins above do.
type piCategorySpec struct {
	Name     string   `json:"name"`
	Weight   float64  `json:"weight"`
	Patterns []string `json:"patterns"`
}

// A malformed custom pattern is dropped rather than fatal — the same tolerance
// dlpScan applies to custom DLP patterns, for the same reason: one bad entry in
// a project's config must not take the whole layer down for every call.
//
// A category left with no usable pattern is dropped whole, so it cannot
// contribute a weight through a `matched` entry it can never earn.
//
// Custom sources are compiled verbatim, WITHOUT the \s widening the built-ins
// get: an author's pattern may legitimately carry \s inside a character class,
// and expanding it there would produce a nested class, fail to compile, and
// silently lose their rule.
func piCompileCustom(specs []piCategorySpec) []piCategory {
	out := make([]piCategory, 0, len(specs))
	for _, s := range specs {
		cat := piCategory{name: s.Name, weight: s.Weight}
		for _, src := range s.Patterns {
			re, err := regexp.Compile(src)
			if err != nil {
				continue
			}
			cat.patterns = append(cat.patterns, re)
		}
		if len(cat.patterns) == 0 {
			continue
		}
		out = append(out, cat)
	}
	return out
}

// detectPromptInjection scores text against the built-in categories plus any
// custom ones, and reports nil when nothing matched at all.
//
// Weighting is per CATEGORY, not per pattern: the first hit inside a category
// ends that category's scan, so a text repeating one trick twenty times scores
// the same as one saying it once. Breadth is what raises the score — each extra
// category adds 0.05 on top of the heaviest one matched.
func detectPromptInjection(text string, customCategories []piCategory, threshold float64) *piResult {
	var matched []string
	maxWeight := 0.0
	allCategories := make([]piCategory, 0, len(piCategories)+len(customCategories))
	allCategories = append(allCategories, piCategories...)
	allCategories = append(allCategories, customCategories...)
	for _, cat := range allCategories {
		for _, pat := range cat.patterns {
			if pat.MatchString(text) {
				matched = append(matched, cat.name)
				if cat.weight > maxWeight {
					maxWeight = cat.weight
				}
				break
			}
		}
	}
	if len(matched) == 0 {
		return nil
	}
	score := math.Min(1.0, maxWeight+0.05*float64(len(matched)-1))
	trustScore := 1.0 - score
	// Both sides are scaled by 1000 and rounded before the comparison so a
	// trustScore that lands on the threshold is not decided by the last bit of a
	// float: 1 - (0.85 + 0.05*3) is 0.09999999999999998, not 0.1, and without the
	// rounding a threshold of exactly 0.1 would block it.
	blocked := piRound(trustScore*1000) < piRound(threshold*1000)
	return &piResult{Score: score, TrustScore: trustScore, Categories: matched, Blocked: blocked}
}

// Math.round in Go's terms: nearest integer, ties toward +∞. math.Round is NOT
// that — it breaks ties away from zero, so a negative half rounds the other way.
// trustScore never goes negative, but a threshold arrives from configuration and
// nothing upstream clamps it, so the tie rule is kept faithful rather than
// assumed away.
func piRound(x float64) float64 {
	f := math.Floor(x)
	if x-f >= 0.5 {
		return f + 1
	}
	return f
}
