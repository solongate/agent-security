// SPDX-License-Identifier: Apache-2.0

package api

// The names of the built-in DLP patterns, in order.
//
// The CLI needs this list to offer the patterns a policy may enable — it used to
// arrive from a service as `availablePatterns`, and there is no service. The
// EXPRESSIONS live in packages/guard-go/dlp.go and in the three hooks; only the
// names are a user-facing menu, so only the names are here.
//
// packages/proxy/test/dlp-parity.mjs holds this list against those, name for name
// and in order. A name here that no implementation carries would offer somebody a
// pattern that enforces nothing.
var dlpPatternNames = []string{
	"AWS access key",
	"Private key block",
	"Anthropic key",
	"OpenAI key",
	"GitHub token",
	"GitHub fine-grained PAT",
	"GitLab token",
	"Slack token",
	"Stripe key",
	"SendGrid key",
	"Twilio key",
	"npm token",
	"JWT",
	"Bearer token",
	"Google API key",
	"Slack webhook",
	"Twilio account SID",
	"Mailgun key",
	"Mailchimp key",
	"DigitalOcean token",
	"Databricks token",
	"Shopify token",
	"Square token",
	"Telegram bot token",
	"Postman key",
	"Doppler token",
	"HashiCorp Vault token",
	"New Relic key",
	"Grafana token",
	"Razorpay key",
	"Linear key",
	"Figma token",
	"Atlassian token",
	"Google OAuth token",
	"Google OAuth refresh",
	"Alibaba access key",
	"Tencent secret id",
	"Hugging Face token",
	"Replicate token",
	"Groq key",
	"OpenRouter key",
	"Perplexity key",
	"xAI key",
	"LangSmith key",
	"Stripe webhook secret",
	"Plaid token",
	"Braintree token",
	"Discord bot token",
	"Discord webhook",
	"Slack app token",
	"Sentry DSN",
	"Supabase token",
	"PlanetScale token",
	"PlanetScale password",
	"Airtable token",
	"Cloudinary URL",
	"MongoDB SRV URI",
	"Terraform Cloud token",
	"PyPI token",
	"RubyGems key",
	"NuGet key",
	"Docker Hub token",
	"Notion token",
	"Dropbox token",
	"Sentry auth token",
	"Contentful token",
	"Typeform token",
	"Pinecone key",
	"WooCommerce key",
	"PostHog key",
}

// AvailablePatterns is the menu, copied so a caller cannot reorder the original.
func AvailablePatterns() []string {
	out := make([]string, len(dlpPatternNames))
	copy(out, dlpPatternNames)
	return out
}
