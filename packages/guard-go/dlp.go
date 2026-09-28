package main

import (
	"regexp"
	"strings"

	"github.com/codeyevsky/solongate/sgshared"
)

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

var redactedMarker = regexp.MustCompile(`\[REDACTED:[^\]]*\]`)

// dlpScan reports the first enabled pattern present in text, or "" for none.
//
// Already-redacted content must not re-trigger: the marker left behind carries
// the pattern NAME, so a masked value would otherwise look like a live secret
// and a report containing one could never be written.
func dlpScan(text string, cfg *sgshared.DLPConfig) string {
	if cfg == nil || text == "" {
		return ""
	}
	text = redactedMarker.ReplaceAllString(text, "")

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
		re, err := globToRegexp(c.Re)
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

// Custom DLP patterns are GLOBs, not regexes: `*` means any run of
// non-whitespace. Same mechanic the policy layer uses, so a user who
// learns one has learned all three.
func globToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)")
	for _, r := range glob {
		if r == '*' {
			b.WriteString(`\S*`)
			continue
		}
		b.WriteString(regexp.QuoteMeta(string(r)))
	}
	return regexp.Compile(b.String())
}
