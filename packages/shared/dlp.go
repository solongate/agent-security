// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shared

import (
	"encoding/base64"
	"regexp"
	"strings"
)

var dlpPatterns = []struct {
	Name string
	Re   *regexp.Regexp
}{
	{"AWS access key", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?)-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"Anthropic key", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
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

	{"Google OAuth token", regexp.MustCompile(`ya29\.[0-9A-Za-z_-]{50,}`)},
	{"Google OAuth refresh", regexp.MustCompile(`1//0[0-9A-Za-z_-]{30,}`)},
	{"Alibaba access key", regexp.MustCompile(`LTAI[0-9A-Za-z]{20}`)},
	{"Tencent secret id", regexp.MustCompile(`AKID[0-9A-Za-z]{13,40}`)},
	{"Hugging Face token", regexp.MustCompile(`hf_[0-9A-Za-z]{34,}`)},
	{"Replicate token", regexp.MustCompile(`r8_[0-9A-Za-z]{37,}`)},
	{"Groq key", regexp.MustCompile(`gsk_[0-9A-Za-z]{48,}`)},
	{"OpenRouter key", regexp.MustCompile(`sk-or-v1-[0-9a-f]{64}`)},
	{"OpenAI key", regexp.MustCompile(`sk-(proj-)?[A-Za-z0-9_-]{20,}`)},
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

func DLPPatternCount() int { return len(dlpPatterns) }

func DLPPatternNames() []string {
	out := make([]string, 0, len(dlpPatterns))
	for _, p := range dlpPatterns {
		out = append(out, p.Name)
	}
	return out
}

func DLPPatternAt(i int) (string, *regexp.Regexp) {
	if i < 0 || i >= len(dlpPatterns) {
		return "", nil
	}
	return dlpPatterns[i].Name, dlpPatterns[i].Re
}

func DLPPatternIndex(name string) int {
	for i := range dlpPatterns {
		if dlpPatterns[i].Name == name {
			return i
		}
	}
	return -1
}

var RedactedMarker = regexp.MustCompile(`\[REDACTED:[^\]]*\]`)

var GlobStarRun = regexp.MustCompile(`\*{2,}`)

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
			continue
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

var (
	reShellQuoteChars = regexp.MustCompile("[`'\"\\\\]")

	reB64Token = regexp.MustCompile(`[A-Za-z0-9+/]{12,}={0,2}`)
)

func dlpViews(text string) []string {
	views := []string{text}

	dequoted := reShellQuoteChars.ReplaceAllString(text, "")
	if dequoted != text {
		views = append(views, dequoted)
	}

	src := text
	if dequoted != text {
		src = text + "\n" + dequoted
	}
	var decoded strings.Builder

	for _, t := range reB64Token.FindAllString(src, 60) {
		d := dlpB64Decode(t)

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

func dlpB64Decode(tok string) []byte {
	s := strings.TrimRight(tok, "=")

	if len(s)%4 == 1 {
		s = s[:len(s)-1]
	}
	b, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

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

func DLPScanViews(text string, cfg *DLPConfig) string {
	if cfg == nil || text == "" {
		return ""
	}

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
	return DLPPatternCount() + len(cfg.Custom)
}
