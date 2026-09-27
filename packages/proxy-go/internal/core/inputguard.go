package core

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// The input guard reads tool arguments and reports what it finds. It is the
// layer that stops an injected instruction from being physically executed:
// traversal out of a working tree, a shell metacharacter smuggled into a
// filename, a URL pointing at the metadata service, an argument carrying an
// encoded payload.
//
// It REPORTS. It does not block. Everything here is a pure function over a
// value, which is what lets the same checks be used to explain a denial in the
// CLI and to make one in the guard without the two drifting.

type ThreatType string

const (
	ThreatPathTraversal   ThreatType = "PATH_TRAVERSAL"
	ThreatShellInjection  ThreatType = "SHELL_INJECTION"
	ThreatWildcardAbuse   ThreatType = "WILDCARD_ABUSE"
	ThreatLengthExceeded  ThreatType = "LENGTH_EXCEEDED"
	ThreatHighEntropy     ThreatType = "HIGH_ENTROPY"
	ThreatSSRF            ThreatType = "SSRF"
	ThreatSQLInjection    ThreatType = "SQL_INJECTION"
	ThreatPromptInjection ThreatType = "PROMPT_INJECTION"
	ThreatExfiltration    ThreatType = "EXFILTRATION"
	ThreatBoundaryEscape  ThreatType = "BOUNDARY_ESCAPE"
)

type DetectedThreat struct {
	Type        ThreatType `json:"type"`
	Field       string     `json:"field"`
	Value       string     `json:"value"`
	Description string     `json:"description"`
}

type SanitizationResult struct {
	Safe    bool             `json:"safe"`
	Threats []DetectedThreat `json:"threats"`
}

// InputGuardConfig switches individual checks off. Every check ships on: a
// caller that wants one disabled has to say so, so a check is never lost by
// forgetting to enable it.
type InputGuardConfig struct {
	PathTraversal  bool
	ShellInjection bool
	WildcardAbuse  bool
	LengthLimit    int
	EntropyLimit   bool
	SSRF           bool
	SQLInjection   bool
	Exfiltration   bool
	BoundaryEscape bool
}

func DefaultInputGuardConfig() InputGuardConfig {
	return InputGuardConfig{
		PathTraversal:  true,
		ShellInjection: true,
		WildcardAbuse:  true,
		LengthLimit:    InputGuardMaxLength,
		EntropyLimit:   true,
		SSRF:           true,
		SQLInjection:   true,
		Exfiltration:   true,
		BoundaryEscape: true,
	}
}

// ── Path traversal ─────────────────────────────────────────────────────────

var pathTraversalPatterns = compileAll(
	`\.\./`,          // ../
	`\.\.\\`,         // ..\
	`(?i)%2e%2e`,     // URL-encoded ..
	`(?i)%2e\.`,      // partially URL-encoded
	`(?i)\.%2e`,      // partially URL-encoded
	`(?i)%252e%252e`, // double URL-encoded
	"\\.\\.\x00",     // null byte variant
)

// Locations that are worth naming outright, because a request that reaches one
// of them is asking for a credential rather than for a file.
var sensitivePaths = compileAll(
	`(?i)/etc/passwd`,
	`(?i)/etc/shadow`,
	`(?i)/proc/self/environ`, // this process's environment
	`(?i)/proc/\d+/environ`,  // any process's environment
	`(?i)/proc/`,
	`(?i)/dev/`,
	`(?i)c:\\windows\\system32`,
	`(?i)c:\\windows\\syswow64`,
	`(?i)/root/`,
	`~/`,
	`(?i)\.env(\.|$)`, // .env, .env.local, .env.production
	`(?i)\.aws/credentials`,
	`(?i)\.ssh/id_`,
	`(?i)\.kube/config`,
	`(?i)wp-config\.php`,
	`(?i)\.git/config`,
	`(?i)\.npmrc`,
	`(?i)\.pypirc`,
)

func DetectPathTraversal(value string) bool {
	return anyMatch(pathTraversalPatterns, value) || anyMatch(sensitivePaths, value)
}

// ── Shell injection ────────────────────────────────────────────────────────

var shellInjectionPatterns = compileAll(
	"[;|&`]", // separators and backtick execution
	`\$\(`,   // command substitution
	`\$\{`,   // variable expansion
	`>\s*`,   // output redirect
	`<\s*`,   // input redirect
	`&&`,     // AND chaining
	`\|\|`,   // OR chaining
	`(?i)\beval\b`,
	`(?i)\bexec\b`,
	`(?i)\bsystem\b`,
	`(?i)%0a`, // URL-encoded newline
	`(?i)%0d`, // URL-encoded carriage return
	`(?i)%09`, // URL-encoded tab
	`\r\n`,    // CRLF injection
	`\n`,      // a newline is a command separator on Unix
	`(?i)\bbash\s+-c\b`,
	`(?i)\bsh\s+-c\b`,
	`(?i)\bzsh\s+-c\b`,
	`(?i)\bsource\s+`,
	`(?i)\bprintenv\b`,
	`(?i)\$'\\x[0-9a-f]`, // hex escape in bash: $'\x72\x6d'
	`(?i)\bxargs\b`,
	`(?i)\bbase64\s+-d\b`,
	`(?i)\bxxd\s+-r\b`,
)

func DetectShellInjection(value string) bool { return anyMatch(shellInjectionPatterns, value) }

// ── Wildcard abuse ─────────────────────────────────────────────────────────

// A recursive glob is refused outright; beyond that it is the COUNT that marks
// a pattern as fishing rather than naming a file.
func DetectWildcardAbuse(value string) bool {
	count := 0
	for i := 0; i < len(value); i++ {
		if value[i] == '*' {
			if i+1 < len(value) && value[i+1] == '*' {
				return true
			}
			count++
			if count > InputGuardMaxWildcards {
				return true
			}
		}
	}
	return false
}

// ── SSRF ───────────────────────────────────────────────────────────────────

// Every one of these is a way of writing "the machine I am running on" or "the
// network it is on". The encodings matter as much as the addresses: a blocklist
// that only knows 127.0.0.1 is defeated by 0x7f000001.
var ssrfPatterns = compileAll(
	`(?i)^https?://localhost\b`,
	`^https?://127\.\d{1,3}\.\d{1,3}\.\d{1,3}`,
	`^https?://0\.0\.0\.0`,
	`^https?://\[::1\]`, // IPv6 loopback
	`^https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}`,
	`^https?://172\.(1[6-9]|2\d|3[01])\.`,
	`^https?://192\.168\.`,
	`^https?://169\.254\.`, // link-local, and the AWS metadata address
	`(?i)metadata\.google\.internal`,
	`(?i)^https?://metadata\b`,
	`(?i)^https?://\[fe80:`,          // IPv6 link-local
	`(?i)^https?://\[fc00:`,          // IPv6 unique local
	`(?i)^https?://\[fd[0-9a-f]{2}:`, // IPv6 unique local, fd00::/8
	`(?i)^https?://\[::ffff:127\.`,   // IPv4-mapped loopback
	`(?i)^https?://\[::ffff:10\.`,    // IPv4-mapped private
	`(?i)^https?://\[::ffff:172\.(1[6-9]|2\d|3[01])\.`,
	`(?i)^https?://\[::ffff:192\.168\.`,
	`(?i)^https?://\[::ffff:169\.254\.`,
	`(?i)^https?://0x[0-9a-f]+\b`, // hex IP: 0x7f000001
	`^https?://0[0-7]{1,3}\.`,     // octal IP: 0177.0.0.1
)

var decimalIPPattern = regexp.MustCompile(`^https?://(\d{8,10})(?:[:/]|$)`)

// A whole IPv4 address written as one decimal number: http://2130706433 is
// 127.0.0.1, and no pattern above catches it.
func detectDecimalIP(value string) bool {
	m := decimalIPPattern.FindStringSubmatch(value)
	if m == nil {
		return false
	}
	decimal, err := strconv.ParseUint(m[1], 10, 64)
	if err != nil || decimal > 0xffffffff {
		return false
	}
	return (decimal >= 0x7f000000 && decimal <= 0x7fffffff) || // 127.0.0.0/8
		(decimal >= 0x0a000000 && decimal <= 0x0affffff) || // 10.0.0.0/8
		(decimal >= 0xac100000 && decimal <= 0xac1fffff) || // 172.16.0.0/12
		(decimal >= 0xc0a80000 && decimal <= 0xc0a8ffff) || // 192.168.0.0/16
		(decimal >= 0xa9fe0000 && decimal <= 0xa9feffff) || // 169.254.0.0/16
		decimal == 0
}

func DetectSSRF(value string) bool {
	return anyMatch(ssrfPatterns, value) || detectDecimalIP(value)
}

// ── SQL injection ──────────────────────────────────────────────────────────

// The repetitions are bounded on purpose. An unbounded `.*` between two quotes
// is a way to hand the regex engine a payload that costs more than the request
// it is checking.
var sqlInjectionPatterns = compileAll(
	`(?i)'\s{0,20}(OR|AND)\s{0,20}'.{0,200}'`,                             // ' OR '1'='1
	`(?i)'\s{0,10};\s{0,10}(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|EXEC)`, // '; DROP TABLE
	`(?i)UNION\s+(ALL\s+)?SELECT`,
	`(?m)--\s*$`,      // comment at end of line
	`/\*.{0,500}?\*/`, // block comment
	`(?i)\bSLEEP\s*\(`,
	`(?i)\bBENCHMARK\s*\(`,
	`(?i)\bWAITFOR\s+DELAY`,
	`(?i)\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b`,
)

func DetectSQLInjection(value string) bool { return anyMatch(sqlInjectionPatterns, value) }

// ── Exfiltration ───────────────────────────────────────────────────────────

var exfiltrationPatterns = compileAll(
	// Base64 in a URL query parameter, at least 20 characters of it.
	`[?&](data|d|q|payload|content|body|msg|token|key|secret)=[A-Za-z0-9+/]{20,}={0,2}`,
	// Hex-encoded data in a URL path, at least 16 bytes of it.
	`(?i)/[0-9a-f]{32,}\b`,
	// DNS exfiltration: a subdomain label long enough to carry a payload.
	`(?i)https?://[a-z0-9]{30,}\.`,
	`(?i)data:[a-z]+/[a-z]+;base64,[A-Za-z0-9+/]{20,}`,
	`(?i)\b(requestbin|hookbin|webhook\.site|burpcollaborator|interact\.sh|pipedream|ngrok)\b`,
	`(?i)\bcurl\b.*\s(-d|--data|--data-binary|--data-urlencode)[\s=]`,
	`(?i)\bwget\b.*--post-(data|file)\b`,
)

func DetectExfiltration(value string) bool { return anyMatch(exfiltrationPatterns, value) }

// ── Boundary escape ────────────────────────────────────────────────────────

// The markers SolonGate wraps user input in. Input that contains them is trying
// to close the wrapper early and have what follows read as system text.
const (
	BoundaryPrefix = "[USER_INPUT_START]"
	BoundarySuffix = "[USER_INPUT_END]"
)

func DetectBoundaryEscape(value string) bool {
	return strings.Contains(value, BoundaryPrefix) || strings.Contains(value, BoundarySuffix)
}

// ── Length and entropy ─────────────────────────────────────────────────────

// Lengths are measured in UTF-16 code units, not bytes and not runes.
//
// That is not a stylistic choice: the Node implementation measures
// `value.length`, which is UTF-16 units, and both implementations have to agree
// on whether a given argument is over the limit. A string of emoji is twice as
// long by this measure as by rune count and a quarter as long as by byte count,
// so any of the three would give a different verdict on the same input.
func utf16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

func CheckLengthLimits(value string, maxLength int) bool {
	if maxLength <= 0 {
		maxLength = InputGuardMaxLength
	}
	return utf16Len(value) <= maxLength
}

// CheckEntropyLimits reports whether the value is BELOW the threshold, i.e.
// whether it is fine. A short string is always fine: entropy over a handful of
// characters says nothing.
func CheckEntropyLimits(value string) bool {
	if utf16Len(value) < InputGuardMinEntropyLength {
		return true
	}
	return shannonEntropy(value) <= InputGuardEntropyThreshold
}

// Shannon entropy per UTF-16 code unit, matching the Node implementation's
// counting. Base64 lands around 6.0 bits; prose sits well under 4.5.
func shannonEntropy(s string) float64 {
	units := utf16.Encode([]rune(s))
	if len(units) == 0 {
		return 0
	}
	freq := make(map[uint16]int, len(units))
	for _, u := range units {
		freq[u]++
	}
	entropy := 0.0
	total := float64(len(units))
	for _, count := range freq {
		p := float64(count) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// truncate cuts at a UTF-16 boundary so the reported value matches what the
// Node implementation reports for the same input.
func truncate(s string, maxLen int) string {
	units := utf16.Encode([]rune(s))
	if len(units) <= maxLen {
		return s
	}
	return string(utf16.Decode(units[:maxLen])) + "..."
}

// ── Entry points ───────────────────────────────────────────────────────────

// SanitizeInput runs every enabled check over one value. Strings are checked;
// objects and arrays are walked and every string inside them is checked.
// Anything else is passed over — a number cannot carry a traversal.
func SanitizeInput(field string, value any, config InputGuardConfig) SanitizationResult {
	s, ok := value.(string)
	if !ok {
		switch v := value.(type) {
		case map[string]any, []any:
			return sanitizeContainer(field, v, config)
		default:
			return SanitizationResult{Safe: true}
		}
	}

	var threats []DetectedThreat
	add := func(t ThreatType, val, desc string) {
		threats = append(threats, DetectedThreat{Type: t, Field: field, Value: val, Description: desc})
	}

	if config.PathTraversal && DetectPathTraversal(s) {
		add(ThreatPathTraversal, truncate(s, 100), "Path traversal pattern detected")
	}
	if config.ShellInjection && DetectShellInjection(s) {
		add(ThreatShellInjection, truncate(s, 100), "Shell injection pattern detected")
	}
	if config.WildcardAbuse && DetectWildcardAbuse(s) {
		add(ThreatWildcardAbuse, truncate(s, 100), "Wildcard abuse pattern detected")
	}
	if !CheckLengthLimits(s, config.LengthLimit) {
		add(ThreatLengthExceeded,
			fmt.Sprintf("[%d chars]", utf16Len(s)),
			fmt.Sprintf("Value exceeds maximum length of %d", config.LengthLimit))
	}
	if config.EntropyLimit && !CheckEntropyLimits(s) {
		add(ThreatHighEntropy, truncate(s, 100), "High entropy string detected - possible encoded payload")
	}
	if config.SSRF && DetectSSRF(s) {
		add(ThreatSSRF, truncate(s, 100),
			"Server-side request forgery pattern detected — internal/metadata URL blocked")
	}
	if config.SQLInjection && DetectSQLInjection(s) {
		add(ThreatSQLInjection, truncate(s, 100), "SQL injection pattern detected")
	}
	if config.Exfiltration && DetectExfiltration(s) {
		add(ThreatExfiltration, truncate(s, 100),
			"Data exfiltration pattern detected — encoded data or exfil service in argument")
	}
	if config.BoundaryEscape && DetectBoundaryEscape(s) {
		add(ThreatBoundaryEscape, truncate(s, 100),
			"Context boundary escape attempt — user input contains boundary markers")
	}

	return SanitizationResult{Safe: len(threats) == 0, Threats: threats}
}

// sanitizeContainer walks an object or array.
//
// Object keys are visited in sorted order rather than in the order they arrived.
// Go map iteration is randomised, so without this the same input produces the
// threat list in a different order on every run — which makes a diff of two
// reports meaningless. Sorting is safe HERE, and only here, because this list is
// tested for emptiness and rendered; it is never concatenated into something
// whose meaning depends on order (see the guard's inlined-script note).
func sanitizeContainer(basePath string, value any, config InputGuardConfig) SanitizationResult {
	var threats []DetectedThreat
	switch v := value.(type) {
	case []any:
		for i, item := range v {
			r := SanitizeInput(fmt.Sprintf("%s[%d]", basePath, i), item, config)
			threats = append(threats, r.Threats...)
		}
	case map[string]any:
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			r := SanitizeInput(basePath+"."+k, v[k], config)
			threats = append(threats, r.Threats...)
		}
	}
	return SanitizationResult{Safe: len(threats) == 0, Threats: threats}
}

// SanitizeArguments checks a whole tool-argument map, which is what callers
// almost always want.
func SanitizeArguments(args map[string]any, config InputGuardConfig) SanitizationResult {
	return sanitizeContainer("arguments", args, config)
}

// ── Context boundary tagging ───────────────────────────────────────────────

// TagUserInput wraps every string in the arguments with the boundary markers so
// a model can tell user input from system data. Objects and arrays are walked;
// anything else is left alone.
func TagUserInput(args map[string]any) map[string]any {
	out := make(map[string]any, len(args))
	for k, v := range args {
		out[k] = tagValue(v)
	}
	return out
}

func tagValue(value any) any {
	switch v := value.(type) {
	case string:
		return BoundaryPrefix + v + BoundarySuffix
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = tagValue(item)
		}
		return out
	case map[string]any:
		return TagUserInput(v)
	default:
		return value
	}
}

// StripBoundaryTags removes the markers again, for anything on its way back to
// the client.
func StripBoundaryTags(text string) string {
	return strings.ReplaceAll(strings.ReplaceAll(text, BoundaryPrefix, ""), BoundarySuffix, "")
}

// ── helpers ────────────────────────────────────────────────────────────────

func compileAll(exprs ...string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, 0, len(exprs))
	for _, e := range exprs {
		out = append(out, regexp.MustCompile(e))
	}
	return out
}

func anyMatch(patterns []*regexp.Regexp, value string) bool {
	for _, p := range patterns {
		if p.MatchString(value) {
			return true
		}
	}
	return false
}
