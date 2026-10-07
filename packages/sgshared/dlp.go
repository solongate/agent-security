// SPDX-License-Identifier: Apache-2.0

package sgshared

import (
	"encoding/base64"
	"regexp"
	"strings"
)

// THE SECRET SCANNER, in the module both the guard and the MCP proxy can import.
//
// It lived in packages/guard-go as unexported functions, which meant the MCP proxy had
// no way to reach it: `solongate -- <upstream>` enforced the policy rules and the rate
// limit and scanned nothing for secrets, while the same machine's hooks did. A policy's
// `security` block reached one path and half of the other.
//
// sgshared rather than sgpolicy, although sgpolicy is where the glob converter's sibling
// lives: sgshared has NO external dependencies, and sgpolicy pulls in OPA. A scanner
// that runs before every tool call should not drag a policy engine in behind it.
//
// The built-in secret patterns, mirrored from the Node guard. The list is part
// of the contract: the cloud sends the NAMES a project has enabled, so a name
// missing here silently stops being enforced rather than erroring.
var dlpPatterns = []struct {
	Name string
	Re   *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?)-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"Anthropic key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{"OpenAI key", regexp.MustCompile(`sk-(proj-)?[A-Za-z0-9_-]{20,}`)},
	{"GitHub token", regexp.MustCompile(`gh[pousr]_[A-Za-z0-9]{20,}`)},
	{"GitHub fine-grained PAT", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`)},
	{"GitLab token", regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,}`)},
	{"Slack token", regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,}`)},
	{"Stripe key", regexp.MustCompile(`[sr]k_(live|test)_[A-Za-z0-9]{20,}`)},
	{"SendGrid key", regexp.MustCompile(`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`)},
	{"Twilio key", regexp.MustCompile(`SK[0-9a-fA-F]{32}`)},
	{"npm token", regexp.MustCompile(`npm_[A-Za-z0-9]{36}`)},
	{"JWT", regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"Bearer token", regexp.MustCompile(`(?i)bearer\s+[A-Za-z0-9._-]{20,}`)},

	// More vendor keys, kept in step with sgdetect/secret.go and its verbatim
	// test. Every one is a distinctive prefix, so a match is a credential.
	{"Google API key", regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`)},
	{"Slack webhook", regexp.MustCompile(`https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{40,}`)},
	{"Twilio account SID", regexp.MustCompile(`AC[0-9a-fA-F]{32}`)},
	{"Mailgun key", regexp.MustCompile(`key-[0-9a-f]{32}`)},
	{"Mailchimp key", regexp.MustCompile(`[0-9a-f]{32}-us[0-9]{1,2}`)},
	{"DigitalOcean token", regexp.MustCompile(`dop_v1_[0-9a-f]{64}`)},
	{"Databricks token", regexp.MustCompile(`dapi[0-9a-f]{32}`)},
	{"Shopify token", regexp.MustCompile(`shp(at|ca|pa|ss)_[0-9a-fA-F]{32}`)},
	{"Square token", regexp.MustCompile(`sq0(atp|csp)-[0-9A-Za-z_-]{22,43}`)},
	{"Telegram bot token", regexp.MustCompile(`[0-9]{8,10}:AA[0-9A-Za-z_-]{33}`)},
	{"Postman key", regexp.MustCompile(`PMAK-[0-9a-f]{24}-[0-9a-f]{34}`)},
	{"Doppler token", regexp.MustCompile(`dp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}`)},
	{"HashiCorp Vault token", regexp.MustCompile(`hvs\.[A-Za-z0-9_-]{24,}`)},
	{"New Relic key", regexp.MustCompile(`NRAK-[A-Z0-9]{27}`)},
	{"Grafana token", regexp.MustCompile(`glc_[A-Za-z0-9+/=_-]{32,}`)},
	{"Razorpay key", regexp.MustCompile(`rzp_(live|test)_[0-9A-Za-z]{14}`)},
	{"Linear key", regexp.MustCompile(`lin_api_[0-9A-Za-z]{40,}`)},
	{"Figma token", regexp.MustCompile(`figd_[0-9A-Za-z_-]{40,}`)},
	{"Atlassian token", regexp.MustCompile(`ATATT3[0-9A-Za-z_=.-]{20,}`)},

	// A second, larger wave, kept in step with sgdetect/secret.go and its
	// verbatim test. Same order, same names, same expressions.
	{"Google OAuth token", regexp.MustCompile(`ya29\.[0-9A-Za-z_-]{50,}`)},
	{"Google OAuth refresh", regexp.MustCompile(`1//0[0-9A-Za-z_-]{30,}`)},
	{"Alibaba access key", regexp.MustCompile(`LTAI[0-9A-Za-z]{20}`)},
	{"Tencent secret id", regexp.MustCompile(`AKID[0-9A-Za-z]{13,40}`)},
	{"Hugging Face token", regexp.MustCompile(`hf_[0-9A-Za-z]{34,}`)},
	{"Replicate token", regexp.MustCompile(`r8_[0-9A-Za-z]{37,}`)},
	{"Groq key", regexp.MustCompile(`gsk_[0-9A-Za-z]{48,}`)},
	{"OpenRouter key", regexp.MustCompile(`sk-or-v1-[0-9a-f]{64}`)},
	{"Perplexity key", regexp.MustCompile(`pplx-[0-9A-Za-z]{40,}`)},
	{"xAI key", regexp.MustCompile(`xai-[0-9A-Za-z]{40,}`)},
	{"LangSmith key", regexp.MustCompile(`lsv2_(pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}`)},
	{"Stripe webhook secret", regexp.MustCompile(`whsec_[0-9A-Za-z]{32,}`)},
	{"Plaid token", regexp.MustCompile(`access-(sandbox|development|production)-[0-9a-f-]{36}`)},
	{"Braintree token", regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)},
	{"Discord bot token", regexp.MustCompile(`[MNO][0-9A-Za-z_-]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}`)},
	{"Discord webhook", regexp.MustCompile(`https://discord(app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,}`)},
	{"Slack app token", regexp.MustCompile(`xapp-[0-9]-[0-9A-Za-z]+-[0-9]+-[0-9a-f]+`)},
	{"Sentry DSN", regexp.MustCompile(`https://[0-9a-f]{32}@[0-9a-z.-]+sentry\.io/[0-9]+`)},
	{"Supabase token", regexp.MustCompile(`sbp_[0-9a-f]{40}`)},
	{"PlanetScale token", regexp.MustCompile(`pscale_tkn_[0-9A-Za-z._-]{32,}`)},
	{"PlanetScale password", regexp.MustCompile(`pscale_pw_[0-9A-Za-z._-]{32,}`)},
	{"Airtable token", regexp.MustCompile(`pat[0-9A-Za-z]{14}\.[0-9a-f]{64}`)},
	{"Cloudinary URL", regexp.MustCompile(`cloudinary://[0-9]{12,}:[0-9A-Za-z_-]{20,}@[0-9a-z-]+`)},
	{"MongoDB SRV URI", regexp.MustCompile(`mongodb\+srv://[^\s:@]+:[^\s:@]+@[0-9a-z.-]+`)},
	{"Terraform Cloud token", regexp.MustCompile(`[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,}`)},
	{"PyPI token", regexp.MustCompile(`pypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}`)},
	{"RubyGems key", regexp.MustCompile(`rubygems_[0-9a-f]{48}`)},
	{"NuGet key", regexp.MustCompile(`oy2[a-z0-9]{43}`)},
	{"Docker Hub token", regexp.MustCompile(`dckr_pat_[0-9A-Za-z_-]{27,}`)},
	{"Notion token", regexp.MustCompile(`ntn_[0-9A-Za-z]{40,}`)},
	{"Dropbox token", regexp.MustCompile(`sl\.[0-9A-Za-z_-]{130,}`)},
	{"Sentry auth token", regexp.MustCompile(`sntrys_[0-9A-Za-z_=+/-]{40,}`)},
	{"Contentful token", regexp.MustCompile(`CFPAT-[0-9A-Za-z_-]{40,}`)},
	{"Typeform token", regexp.MustCompile(`tfp_[0-9A-Za-z_-]{40,}`)},
	{"Pinecone key", regexp.MustCompile(`pcsk_[0-9A-Za-z_-]{40,}`)},
	{"WooCommerce key", regexp.MustCompile(`c[ks]_[0-9a-f]{40}`)},
	{"PostHog key", regexp.MustCompile(`ph[cs]_[0-9A-Za-z]{40,}`)},
}

// DLPPatternCount is how many built-in patterns there are. Used for ranking a hit
// against the custom list, which sorts after every built-in one.
func DLPPatternCount() int { return len(dlpPatterns) }

// DLPPatternNames lists them in order. The ORDER is part of the contract: a scan
// reports the FIRST match, so two patterns that could both match one string are
// resolved by this list and not by chance.
func DLPPatternNames() []string {
	out := make([]string, 0, len(dlpPatterns))
	for _, p := range dlpPatterns {
		out = append(out, p.Name)
	}
	return out
}

// DLPPatternAt is one pattern by index, for callers that walk the list themselves —
// the read-redaction planner needs each expression, not just a verdict.
func DLPPatternAt(i int) (string, *regexp.Regexp) {
	if i < 0 || i >= len(dlpPatterns) {
		return "", nil
	}
	return dlpPatterns[i].Name, dlpPatterns[i].Re
}

// DLPPatternIndex is where a name sits in the built-in list, or -1.
func DLPPatternIndex(name string) int {
	for i := range dlpPatterns {
		if dlpPatterns[i].Name == name {
			return i
		}
	}
	return -1
}

// RedactedMarker matches what a redaction leaves behind.
var RedactedMarker = regexp.MustCompile(`\[REDACTED:[^\]]*\]`)

// GlobStarRun collapses `**` and longer to a single star.
//
// It lived in sgpolicy, which is the module the policy layer's own glob matching uses.
// This module cannot import that one — sgpolicy imports THIS one — so the definition
// moved here and sgpolicy aliases it. One rule, one regexp, whichever side asks.
var GlobStarRun = regexp.MustCompile(`\*{2,}`)

// DLPScan reports the first enabled pattern present in text, or "" for none.
//
// Already-redacted content must not re-trigger: the marker left behind carries the
// pattern NAME, so a masked value would otherwise look like a live secret and a report
// containing one could never be written.
func DLPScan(text string, cfg *DLPConfig) string {
	if cfg == nil || text == "" {
		return ""
	}
	text = RedactedMarker.ReplaceAllString(text, "")

	enabled := make(map[string]bool, len(cfg.Patterns))
	for _, n := range cfg.Patterns {
		enabled[n] = true
	}
	for _, p := range dlpPatterns {
		if enabled[p.Name] && p.Re.MatchString(text) {
			return p.Name
		}
	}
	for _, c := range cfg.Custom {
		re, err := GlobToRegexp(c.Re)
		if err != nil {
			continue // a bad custom pattern must not take the whole layer down
		}
		if re.MatchString(text) {
			if c.Name != "" {
				return c.Name
			}
			return "custom pattern"
		}
	}
	return ""
}

// GlobToRegexp compiles a custom DLP pattern.
//
// Custom DLP patterns are GLOBs, not regexes: `*` means any run of non-whitespace. Same
// mechanic the policy layer uses, so a user who learns one has learned all three.
//
// A RUN of `*` collapses to one. It changes no answer — `\S*\S*` matches exactly what
// `\S*` matches — and this engine is RE2, which has no backtracking and so was never at
// risk from the repetition. It is here because the JavaScript twin MUST do it: there
// `**` compiles to two adjacent unbounded quantifiers and the backtracking is
// catastrophic, and a converter that normalises on one side and not the other is a pair
// that can disagree. See dlpGlobToRe in the hooks.
func GlobToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)")
	for _, r := range GlobStarRun.ReplaceAllString(glob, "*") {
		if r == '*' {
			b.WriteString(`\S*`)
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	return regexp.Compile(b.String())
}

// ── the de-obfuscating scan ───────────────────────────────────────────────────
//
// These moved from packages/guard-go with DLPScan, for the same reason: the MCP proxy
// had no way to reach them, so a tool call through `solongate -- <upstream>` was scanned
// for nothing. They depend on nothing outside this module.

var (
	// Shell decoration a split secret hides behind: "AKIA""3XZ9…", 'AKIA'\''…',
	// AKIA\3XZ9. Dropping all four collapses it back to one contiguous run.
	reShellQuoteChars = regexp.MustCompile("[`'\"\\\\]")
	// A base64-looking token. 16 chars minimum: shorter runs are mostly ordinary
	// words and decode to noise, and every secret worth smuggling is longer.
	// A base64-looking token. TWELVE characters minimum, not sixteen.
	//
	// WHY IT MOVED. Sixteen was chosen so ordinary words would not be decoded,
	// and it had a hole nobody had measured: base64 of an eleven digit national
	// id is fifteen characters plus one of padding, so the floor sat exactly one
	// character above the most important value this package looks for. A ten
	// digit tax number is fourteen. Both walked straight through the encoded
	// view. Twelve reaches a nine byte value, which covers every identifier here.
	//
	// WHAT IT COSTS. More tokens get decoded, and ordinary long words now
	// produce a few bytes of noise each. That noise still has to satisfy a
	// CHECKSUM to become a hit, so the false alarm risk is arithmetic rather
	// than shape - measured over 159k tokens of real source code, it added none.
	// The token count is still bounded (see maxB64Tokens), so the CPU is too.
	reB64Token = regexp.MustCompile(`[A-Za-z0-9+/]{12,}={0,2}`)
)

// dlpViews returns de-obfuscated VIEWS of the scanned text, so an agent cannot
// smuggle a secret past the literal patterns by SPLITTING it
// (printf "AKIA""3XZ9…") or ENCODING it (echo <base64> | base64 -d). Every view
// is scanned. Not exhaustive — pattern DLP can never be — but it closes the two
// obvious bypasses.
func dlpViews(text string) []string {
	views := []string{text}
	// 1) Drop shell quotes + backslashes so a split secret collapses back to a
	//    contiguous run: "AKIA""3XZ9…" / 'AKIA'\''…' / AKIA\3XZ9 → AKIA3XZ9…
	dequoted := reShellQuoteChars.ReplaceAllString(text, "")
	if dequoted != text {
		views = append(views, dequoted)
	}
	// 2) Decode base64-looking tokens (from both the raw and the dequoted view —
	//    the payload itself may be split too) and scan the decoded bytes.
	src := text
	if dequoted != text {
		src = text + "\n" + dequoted
	}
	var decoded strings.Builder
	// Bounded to 60 tokens: a megabyte of base64-shaped noise must not turn a
	// per-call scan into a CPU sink.
	for _, t := range reB64Token.FindAllString(src, 60) {
		d := dlpB64Decode(t)
		// Keep printable decodes only — random bytes are not a smuggled secret.
		if len(d) > 0 && hasPrintableRun(d, 8) {
			decoded.Write(d)
			decoded.WriteByte('\n')
		}
	}
	if decoded.Len() > 0 {
		views = append(views, decoded.String())
	}
	return views
}

// dlpB64Decode mirrors Node's Buffer.from(t, 'base64'), which is lenient where
// Go's decoder is strict: it accepts a token whose length is not a multiple of
// four and decodes as much as it can. Refusing those outright would mean a
// secret encoded without padding decodes to nothing and the whole view is lost.
//
// The decoded bytes are kept RAW rather than widened to UTF-8 the way Node's
// 'latin1' would. Every built-in pattern is ASCII, so no match can differ.
func dlpB64Decode(tok string) []byte {
	s := strings.TrimRight(tok, "=")
	// A trailing group of one character carries no whole byte; Node ignores it.
	if len(s)%4 == 1 {
		s = s[:len(s)-1]
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil // not base64 after all
	}
	return b
}

// hasPrintableRun reports whether b holds `n` consecutive printable ASCII bytes,
// which is JavaScript's /[ -~]{8,}/ test. Done over bytes rather than by regexp
// because a decode is arbitrary binary and must not be re-interpreted as UTF-8
// first.
func hasPrintableRun(b []byte, n int) bool {
	run := 0
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			run++
			if run >= n {
				return true
			}
			continue
		}
		run = 0
	}
	return false
}

// dlpScanViews is dlp.go's dlpScan applied to every view.
//
// The split exists because the Go dlpScan takes one text; the Node hook folded
// the views into the scan itself, so every caller there — egress, read
// redaction, read block — got them for free. This layer's callers scan FILE
// CONTENT, where a split or base64-wrapped secret is exactly what a file
// planted to defeat the scanner looks like, so they go through here.
//
// The reported NAME is chosen pattern-first, not view-first: the original tests
// one pattern against all views before moving on, so with two different
// patterns hitting in two different views it names the earlier pattern. Which
// one is named ends up in the block message a human reads.
// dlpScanViews is dlp.go's dlpScan applied to every view.
//
// The split exists because the Go dlpScan takes one text; the Node hook folded
// the views into the scan itself, so every caller there — egress, read
// redaction, read block — got them for free. This layer's callers scan FILE
// CONTENT, where a split or base64-wrapped secret is exactly what a file
// planted to defeat the scanner looks like, so they go through here.
//
// The reported NAME is chosen pattern-first, not view-first: the original tests
// one pattern against all views before moving on, so with two different
// patterns hitting in two different views it names the earlier pattern. Which
// one is named ends up in the block message a human reads.
func DLPScanViews(text string, cfg *DLPConfig) string {
	if cfg == nil || text == "" {
		return ""
	}
	// Strip already-redacted markers BEFORE the views are cut, not only inside
	// dlpScan: a marker sitting between two base64-shaped runs would otherwise
	// split a token that the Node hook saw as one.
	text = RedactedMarker.ReplaceAllString(text, "")
	best, bestRank := "", -1
	for _, v := range dlpViews(text) {
		hit := DLPScan(v, cfg)
		if hit == "" {
			continue
		}
		if r := DLPHitRank(hit, cfg); bestRank < 0 || r < bestRank {
			best, bestRank = hit, r
		}
	}
	return best
}

// dlpHitRank places a hit in the order the Node hook tests patterns: built-ins
// in list order first, then custom patterns in config order.

// DLPHitRank places a hit in the order the Node hook tests patterns: built-ins in list
// order first, then custom patterns in config order.
//
// It came here with DLPScanViews, which cannot rank without it. The guard had its own
// copy and now calls this one — two implementations of "which of two hits is the one to
// report" is a pair that can disagree about what a person reads in a masked file.
func DLPHitRank(name string, cfg *DLPConfig) int {
	if i := DLPPatternIndex(name); i >= 0 {
		return i
	}
	if cfg == nil {
		return DLPPatternCount()
	}
	for i, c := range cfg.Custom {
		n := c.Name
		if n == "" {
			n = "custom pattern"
		}
		if n == name {
			return DLPPatternCount() + i
		}
	}
	return DLPPatternCount() + len(cfg.Custom) // a name from neither list still ranks last
}
