/**
 * THE BUILT-IN SECRET PATTERNS — one list, for the three hooks that scan.
 *
 * There were three copies of this table, one per hook, and they had drifted: the guard
 * carried 70 patterns and each hook carried 14. Which is the wrong 56 to be missing,
 * because the HOOK is what ships as the installed guard — so on a machine without the Go
 * binary, the default, a policy asking for a Google API key or a Slack webhook was
 * enforcing nothing and said so nowhere. test/dlp-parity.mjs was written to catch that
 * by reading all four sources and comparing them; this removes three of the four.
 *
 * SOURCES, NOT COMPILED REGEXES, because the consumers need different flags and the
 * difference is load-bearing:
 *
 *   the guard   TESTS for a match, so no `g`. A `g` regex carries `lastIndex` between
 *               calls, and on a reused object that silently skips every second match.
 *   the others  REPLACE every occurrence, so `g` is mandatory. Without it only the first
 *               secret in a file is masked and the rest reach the model — which is a bug
 *               this repository has already had.
 *
 * So `dlpPatterns(flags)` compiles the list with what the caller needs, fresh each call,
 * and neither consumer can pick up the other's flags by accident.
 *
 * A pattern's OWN flags travel with it. Exactly one has any — `Bearer token` is
 * case-insensitive — and it is carried per entry rather than applied to the list, because
 * a flag that belongs to one expression must not silently become a property of seventy.
 *
 * The ORDER is part of the contract: a scan reports the FIRST match, so two patterns that
 * could both match one string are resolved by this list and not by chance.
 *
 * The Go twin is packages/sgshared/dlp.go, and test/dlp-parity.mjs holds this against it.
 */

/** (name, source, own flags) triples, in the order a scan tests them. */
// The expressions are written WITHOUT escaping `/`. Inside a regex literal that escape is
// mandatory; inside String.raw it is noise -- `\/` and `/` compile to the same thing -- and
// it made every URL pattern here read differently from its Go twin for no reason.
export const DLP_PATTERN_SOURCES = [
  { name: 'AWS access key', source: String.raw`AKIA[0-9A-Z]{16}` },
  { name: 'Private key block', source: String.raw`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----` },
  { name: 'Anthropic key', source: String.raw`sk-ant-[A-Za-z0-9_-]{20,}` },
  { name: 'OpenAI key', source: String.raw`sk-(proj-)?[A-Za-z0-9_-]{20,}` },
  { name: 'GitHub token', source: String.raw`gh[pousr]_[A-Za-z0-9]{20,}` },
  { name: 'GitHub fine-grained PAT', source: String.raw`github_pat_[A-Za-z0-9_]{20,}` },
  { name: 'GitLab token', source: String.raw`glpat-[A-Za-z0-9_-]{20,}` },
  { name: 'Slack token', source: String.raw`xox[baprs]-[A-Za-z0-9-]{10,}` },
  { name: 'Stripe key', source: String.raw`[sr]k_(live|test)_[A-Za-z0-9]{20,}` },
  { name: 'SendGrid key', source: String.raw`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}` },
  { name: 'Twilio key', source: String.raw`SK[0-9a-fA-F]{32}` },
  { name: 'npm token', source: String.raw`npm_[A-Za-z0-9]{36}` },
  { name: 'JWT', source: String.raw`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` },
  { name: 'Bearer token', source: String.raw`bearer\s+[A-Za-z0-9._-]{20,}`, flags: 'i' },
  { name: 'Google API key', source: String.raw`AIza[0-9A-Za-z_-]{35}` },
  { name: 'Slack webhook', source: String.raw`https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{40,}` },
  { name: 'Twilio account SID', source: String.raw`AC[0-9a-fA-F]{32}` },
  { name: 'Mailgun key', source: String.raw`key-[0-9a-f]{32}` },
  { name: 'Mailchimp key', source: String.raw`[0-9a-f]{32}-us[0-9]{1,2}` },
  { name: 'DigitalOcean token', source: String.raw`dop_v1_[0-9a-f]{64}` },
  { name: 'Databricks token', source: String.raw`dapi[0-9a-f]{32}` },
  { name: 'Shopify token', source: String.raw`shp(at|ca|pa|ss)_[0-9a-fA-F]{32}` },
  { name: 'Square token', source: String.raw`sq0(atp|csp)-[0-9A-Za-z_-]{22,43}` },
  { name: 'Telegram bot token', source: String.raw`[0-9]{8,10}:AA[0-9A-Za-z_-]{33}` },
  { name: 'Postman key', source: String.raw`PMAK-[0-9a-f]{24}-[0-9a-f]{34}` },
  { name: 'Doppler token', source: String.raw`dp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}` },
  { name: 'HashiCorp Vault token', source: String.raw`hvs\.[A-Za-z0-9_-]{24,}` },
  { name: 'New Relic key', source: String.raw`NRAK-[A-Z0-9]{27}` },
  { name: 'Grafana token', source: String.raw`glc_[A-Za-z0-9+/=_-]{32,}` },
  { name: 'Razorpay key', source: String.raw`rzp_(live|test)_[0-9A-Za-z]{14}` },
  { name: 'Linear key', source: String.raw`lin_api_[0-9A-Za-z]{40,}` },
  { name: 'Figma token', source: String.raw`figd_[0-9A-Za-z_-]{40,}` },
  { name: 'Atlassian token', source: String.raw`ATATT3[0-9A-Za-z_=.-]{20,}` },
  { name: 'Google OAuth token', source: String.raw`ya29\.[0-9A-Za-z_-]{50,}` },
  { name: 'Google OAuth refresh', source: String.raw`1//0[0-9A-Za-z_-]{30,}` },
  { name: 'Alibaba access key', source: String.raw`LTAI[0-9A-Za-z]{20}` },
  { name: 'Tencent secret id', source: String.raw`AKID[0-9A-Za-z]{13,40}` },
  { name: 'Hugging Face token', source: String.raw`hf_[0-9A-Za-z]{34,}` },
  { name: 'Replicate token', source: String.raw`r8_[0-9A-Za-z]{37,}` },
  { name: 'Groq key', source: String.raw`gsk_[0-9A-Za-z]{48,}` },
  { name: 'OpenRouter key', source: String.raw`sk-or-v1-[0-9a-f]{64}` },
  { name: 'Perplexity key', source: String.raw`pplx-[0-9A-Za-z]{40,}` },
  { name: 'xAI key', source: String.raw`xai-[0-9A-Za-z]{40,}` },
  { name: 'LangSmith key', source: String.raw`lsv2_(pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}` },
  { name: 'Stripe webhook secret', source: String.raw`whsec_[0-9A-Za-z]{32,}` },
  { name: 'Plaid token', source: String.raw`access-(sandbox|development|production)-[0-9a-f-]{36}` },
  { name: 'Braintree token', source: String.raw`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}` },
  { name: 'Discord bot token', source: String.raw`[MNO][0-9A-Za-z_-]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}` },
  { name: 'Discord webhook', source: String.raw`https://discord(app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,}` },
  { name: 'Slack app token', source: String.raw`xapp-[0-9]-[0-9A-Za-z]+-[0-9]+-[0-9a-f]+` },
  { name: 'Sentry DSN', source: String.raw`https://[0-9a-f]{32}@[0-9a-z.-]+sentry\.io/[0-9]+` },
  { name: 'Supabase token', source: String.raw`sbp_[0-9a-f]{40}` },
  { name: 'PlanetScale token', source: String.raw`pscale_tkn_[0-9A-Za-z._-]{32,}` },
  { name: 'PlanetScale password', source: String.raw`pscale_pw_[0-9A-Za-z._-]{32,}` },
  { name: 'Airtable token', source: String.raw`pat[0-9A-Za-z]{14}\.[0-9a-f]{64}` },
  { name: 'Cloudinary URL', source: String.raw`cloudinary://[0-9]{12,}:[0-9A-Za-z_-]{20,}@[0-9a-z-]+` },
  { name: 'MongoDB SRV URI', source: String.raw`mongodb\+srv://[^\s:@]+:[^\s:@]+@[0-9a-z.-]+` },
  { name: 'Terraform Cloud token', source: String.raw`[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,}` },
  { name: 'PyPI token', source: String.raw`pypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}` },
  { name: 'RubyGems key', source: String.raw`rubygems_[0-9a-f]{48}` },
  { name: 'NuGet key', source: String.raw`oy2[a-z0-9]{43}` },
  { name: 'Docker Hub token', source: String.raw`dckr_pat_[0-9A-Za-z_-]{27,}` },
  { name: 'Notion token', source: String.raw`ntn_[0-9A-Za-z]{40,}` },
  { name: 'Dropbox token', source: String.raw`sl\.[0-9A-Za-z_-]{130,}` },
  { name: 'Sentry auth token', source: String.raw`sntrys_[0-9A-Za-z_=+/-]{40,}` },
  { name: 'Contentful token', source: String.raw`CFPAT-[0-9A-Za-z_-]{40,}` },
  { name: 'Typeform token', source: String.raw`tfp_[0-9A-Za-z_-]{40,}` },
  { name: 'Pinecone key', source: String.raw`pcsk_[0-9A-Za-z_-]{40,}` },
  { name: 'WooCommerce key', source: String.raw`c[ks]_[0-9a-f]{40}` },
  { name: 'PostHog key', source: String.raw`ph[cs]_[0-9A-Za-z]{40,}` },
];

/** Every pattern name, in order. */
export const DLP_PATTERN_NAMES = DLP_PATTERN_SOURCES.map((p) => p.name);

/**
 * The list compiled for a caller that either tests or replaces.
 *
 * `extra` is 'g' for anything that replaces and '' for anything that only tests; each
 * pattern's own flags are added to it. Compiled fresh on every call, never cached: a `g`
 * regex holds `lastIndex` between uses, and a shared compiled object is how a scanner
 * starts missing matches it found a moment ago.
 */
export function dlpPatterns(extra) {
  return DLP_PATTERN_SOURCES.map((p) => ({
    name: p.name,
    re: new RegExp(p.source, (extra || '') + (p.flags || '')),
  }));
}

/**
 * Custom DLP patterns are GLOBs: `*` = any run of non-whitespace, the same wildcard
 * mechanic as the policy layer, so a user who learns one has learned all three.
 *
 * A RUN of `*` collapses to one, and that is a HANG fix rather than tidying. `*` becomes
 * `[^\s]*`, so `**` became two unbounded quantifiers over the same class back to back,
 * which backtracks catastrophically: measured on this converter, six stars cost 0.9s and
 * ten cost four minutes — on a pattern somebody types. Collapsing changes nothing about
 * what a glob accepts, because `[^\s]*[^\s]*` matches exactly what `[^\s]*` matches.
 *
 * Go's RE2 has no backtracking and was never at risk, and GlobToRegexp there collapses
 * anyway: a converter that normalises on one side and not the other is a pair that can
 * disagree about what a pattern means.
 */
export function dlpGlobToRe(glob, flags = 'i') {
  let re = '';
  for (const ch of String(glob || '').replace(/\*{2,}/g, '*')) {
    if (ch === '*') re += '[^\\s]*';
    else if ('.+?^${}()|[]\\'.indexOf(ch) !== -1) re += '\\' + ch;
    else re += ch;
  }
  return new RegExp(re, flags);
}
