package store

import (
	"context"
	"encoding/json"
	"math"
	"strconv"
)

// The port of src/lib/security-layers.ts and src/lib/local-logs.ts.
//
// These live in the store package because they ARE system_settings rows, and
// because more than one route slice needs them: /v1/settings/security-layers
// reads and writes them, and GET /v1/policies/active turns them into the
// `security` block the guard enforces. Two implementations of the coercion
// would mean the panel showing one configuration and the guard applying
// another, which is a class of bug that reports as "the rate limit does
// nothing".
//
// The coercion is not tidying-up. It is the compatibility layer for settings
// written by three earlier shapes of this feature (`enabled` booleans, an
// `anomaly` block, a `dlp.block` flag), and dropping a branch silently
// re-interprets somebody's stored configuration.

// DLPPattern is one built-in secret detector. The list and its ORDER are the
// contract: the dashboard shows these names, a project's stored `patterns`
// array holds a subset of them by name, and the guard is handed the names back.
type DLPPattern struct {
	Name string `json:"name"`
	Re   string `json:"re"`
	CI   bool   `json:"ci,omitempty"`
}

// DLPPatterns is the built-in list, and it is packages/guard-go/dlp.go's
// dlpPatterns in the same order under the same names.
//
// IT STARTED AS src/lib/security-layers.ts's FOURTEEN AND THAT WAS A HOLE.
// The guard gates each detector on enabled[p.Name], and the enabled set is
// whatever this service publishes: DLPPatternNames() is the default a fresh
// project is given, it is the filter every stored subset is intersected with in
// normaliseSecurityLayers, and it is the whole of `availablePatterns` in the
// settings payload the CLI draws its checkboxes from. So a pattern the guard
// carries and this list does not name can never be switched on by anybody, by
// any route. The guard grew to seventy while this stayed at fourteen, which
// meant fifty-six detectors shipped on every machine in the fleet and were dead
// on all of them.
//
// A name that disappears from here silently drops that detector from every
// project whose stored subset mentions it, and a name that is spelled
// differently from the guard's is the same silence in the other direction: this
// service would publish it, a project would enable it, and the guard would find
// no pattern by that name to turn on. Neither raises an error anywhere, which
// is why securitylayers_dlp_sync_test.go reads guard-go/dlp.go and fails on any
// disagreement in name or order.
//
// The regular expressions here are this service's OWN, used by the audit signal
// scanner and the stats scanner to re-read a stored summary; the guard compiles
// its own copies. They are kept identical anyway, because two scanners that
// disagree about what a name matches report different things about one event.
var DLPPatterns = []DLPPattern{
	{Name: "AWS access key", Re: `AKIA[0-9A-Z]{16}`},
	{Name: "Private key block", Re: `-----BEGIN [A-Z ]*PRIVATE KEY-----(?s:.*?)-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----`},
	{Name: "Anthropic key", Re: `sk-ant-[A-Za-z0-9_-]{20,}`},
	{Name: "OpenAI key", Re: `sk-(proj-)?[A-Za-z0-9_-]{20,}`},
	{Name: "GitHub token", Re: `gh[pousr]_[A-Za-z0-9]{20,}`},
	{Name: "GitHub fine-grained PAT", Re: `github_pat_[A-Za-z0-9_]{20,}`},
	{Name: "GitLab token", Re: `glpat-[A-Za-z0-9_-]{20,}`},
	{Name: "Slack token", Re: `xox[baprs]-[A-Za-z0-9-]{10,}`},
	{Name: "Stripe key", Re: `[sr]k_(live|test)_[A-Za-z0-9]{20,}`},
	{Name: "SendGrid key", Re: `SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`},
	{Name: "Twilio key", Re: `SK[0-9a-fA-F]{32}`},
	{Name: "npm token", Re: `npm_[A-Za-z0-9]{36}`},
	{Name: "JWT", Re: `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`},
	{Name: "Bearer token", Re: `bearer\s+[A-Za-z0-9._-]{20,}`, CI: true},

	// The vendor keys, in guard-go/dlp.go's order. Every one is a distinctive
	// prefix, so a match is a credential rather than a string that happens to
	// be the right length.
	{Name: "Google API key", Re: `AIza[0-9A-Za-z_-]{35}`},
	{Name: "Slack webhook", Re: `https://hooks\.slack\.com/services/[A-Za-z0-9/_+-]{40,}`},
	{Name: "Twilio account SID", Re: `AC[0-9a-fA-F]{32}`},
	{Name: "Mailgun key", Re: `key-[0-9a-f]{32}`},
	{Name: "Mailchimp key", Re: `[0-9a-f]{32}-us[0-9]{1,2}`},
	{Name: "DigitalOcean token", Re: `dop_v1_[0-9a-f]{64}`},
	{Name: "Databricks token", Re: `dapi[0-9a-f]{32}`},
	{Name: "Shopify token", Re: `shp(at|ca|pa|ss)_[0-9a-fA-F]{32}`},
	{Name: "Square token", Re: `sq0(atp|csp)-[0-9A-Za-z_-]{22,43}`},
	{Name: "Telegram bot token", Re: `[0-9]{8,10}:AA[0-9A-Za-z_-]{33}`},
	{Name: "Postman key", Re: `PMAK-[0-9a-f]{24}-[0-9a-f]{34}`},
	{Name: "Doppler token", Re: `dp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}`},
	{Name: "HashiCorp Vault token", Re: `hvs\.[A-Za-z0-9_-]{24,}`},
	{Name: "New Relic key", Re: `NRAK-[A-Z0-9]{27}`},
	{Name: "Grafana token", Re: `glc_[A-Za-z0-9+/=_-]{32,}`},
	{Name: "Razorpay key", Re: `rzp_(live|test)_[0-9A-Za-z]{14}`},
	{Name: "Linear key", Re: `lin_api_[0-9A-Za-z]{40,}`},
	{Name: "Figma token", Re: `figd_[0-9A-Za-z_-]{40,}`},
	{Name: "Atlassian token", Re: `ATATT3[0-9A-Za-z_=.-]{20,}`},

	// The second, larger wave. Same order, same names, same expressions.
	{Name: "Google OAuth token", Re: `ya29\.[0-9A-Za-z_-]{50,}`},
	{Name: "Google OAuth refresh", Re: `1//0[0-9A-Za-z_-]{30,}`},
	{Name: "Alibaba access key", Re: `LTAI[0-9A-Za-z]{20}`},
	{Name: "Tencent secret id", Re: `AKID[0-9A-Za-z]{13,40}`},
	{Name: "Hugging Face token", Re: `hf_[0-9A-Za-z]{34,}`},
	{Name: "Replicate token", Re: `r8_[0-9A-Za-z]{37,}`},
	{Name: "Groq key", Re: `gsk_[0-9A-Za-z]{48,}`},
	{Name: "OpenRouter key", Re: `sk-or-v1-[0-9a-f]{64}`},
	{Name: "Perplexity key", Re: `pplx-[0-9A-Za-z]{40,}`},
	{Name: "xAI key", Re: `xai-[0-9A-Za-z]{40,}`},
	{Name: "LangSmith key", Re: `lsv2_(pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}`},
	{Name: "Stripe webhook secret", Re: `whsec_[0-9A-Za-z]{32,}`},
	{Name: "Plaid token", Re: `access-(sandbox|development|production)-[0-9a-f-]{36}`},
	{Name: "Braintree token", Re: `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`},
	{Name: "Discord bot token", Re: `[MNO][0-9A-Za-z_-]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}`},
	{Name: "Discord webhook", Re: `https://discord(app)?\.com/api/webhooks/[0-9]{17,20}/[0-9A-Za-z_-]{60,}`},
	{Name: "Slack app token", Re: `xapp-[0-9]-[0-9A-Za-z]+-[0-9]+-[0-9a-f]+`},
	{Name: "Sentry DSN", Re: `https://[0-9a-f]{32}@[0-9a-z.-]+sentry\.io/[0-9]+`},
	{Name: "Supabase token", Re: `sbp_[0-9a-f]{40}`},
	{Name: "PlanetScale token", Re: `pscale_tkn_[0-9A-Za-z._-]{32,}`},
	{Name: "PlanetScale password", Re: `pscale_pw_[0-9A-Za-z._-]{32,}`},
	{Name: "Airtable token", Re: `pat[0-9A-Za-z]{14}\.[0-9a-f]{64}`},
	{Name: "Cloudinary URL", Re: `cloudinary://[0-9]{12,}:[0-9A-Za-z_-]{20,}@[0-9a-z-]+`},
	{Name: "MongoDB SRV URI", Re: `mongodb\+srv://[^\s:@]+:[^\s:@]+@[0-9a-z.-]+`},
	{Name: "Terraform Cloud token", Re: `[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,}`},
	{Name: "PyPI token", Re: `pypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}`},
	{Name: "RubyGems key", Re: `rubygems_[0-9a-f]{48}`},
	{Name: "NuGet key", Re: `oy2[a-z0-9]{43}`},
	{Name: "Docker Hub token", Re: `dckr_pat_[0-9A-Za-z_-]{27,}`},
	{Name: "Notion token", Re: `ntn_[0-9A-Za-z]{40,}`},
	{Name: "Dropbox token", Re: `sl\.[0-9A-Za-z_-]{130,}`},
	{Name: "Sentry auth token", Re: `sntrys_[0-9A-Za-z_=+/-]{40,}`},
	{Name: "Contentful token", Re: `CFPAT-[0-9A-Za-z_-]{40,}`},
	{Name: "Typeform token", Re: `tfp_[0-9A-Za-z_-]{40,}`},
	{Name: "Pinecone key", Re: `pcsk_[0-9A-Za-z_-]{40,}`},
	{Name: "WooCommerce key", Re: `c[ks]_[0-9a-f]{40}`},
	{Name: "PostHog key", Re: `ph[cs]_[0-9A-Za-z]{40,}`},
}

// DLPPatternNames is the same list, names only, in order.
func DLPPatternNames() []string {
	out := make([]string, len(DLPPatterns))
	for i, p := range DLPPatterns {
		out[i] = p.Name
	}
	return out
}

// A layer is off, detect or block. `detect` is not "disabled": it is what
// routes the signal to the audit hook to be observed and recorded without the
// call being stopped.
const (
	LayerOff    = "off"
	LayerDetect = "detect"
	LayerBlock  = "block"
)

type CustomPattern struct {
	Name string `json:"name"`
	Re   string `json:"re"`
}

type RateLimitLayer struct {
	Mode      string `json:"mode"`
	PerMinute int64  `json:"perMinute"`
	PerHour   int64  `json:"perHour"`
	PerDay    int64  `json:"perDay"`
}

type DLPLayer struct {
	Mode     string          `json:"mode"`
	Patterns []string        `json:"patterns"`
	Custom   []CustomPattern `json:"custom"`
}

// SecurityLayers is the stored shape. It is serialised into system_settings
// verbatim, so the json tags are the storage format as well as the wire format
// — a renamed tag orphans every project's saved configuration.
type SecurityLayers struct {
	RateLimit RateLimitLayer `json:"rateLimit"`
	DLP       DLPLayer       `json:"dlp"`
}

// DefaultSecurityLayers is what a project with no stored row gets: rate
// limiting in detect at 120 a minute, DLP in detect with every built-in
// pattern.
func DefaultSecurityLayers() SecurityLayers {
	return SecurityLayers{
		RateLimit: RateLimitLayer{Mode: LayerDetect, PerMinute: 120},
		DLP:       DLPLayer{Mode: LayerDetect, Patterns: DLPPatternNames(), Custom: []CustomPattern{}},
	}
}

// ── the guard's view ────────────────────────────────────────────────────────

// LocalLogsConfig is the `localLogs` member of the security block and the whole
// of GET/PUT /v1/settings/local-logs.
type LocalLogsConfig struct {
	Enabled bool   `json:"enabled"`
	Path    string `json:"path"`
}

// GuardSecurity is the `security` object in GET /v1/policies/active.
//
// Every member is a POINTER because `null` is a meaningful answer here and not
// a missing one: the guard distinguishes `dlpBlock: null` (this project does
// not block on secrets) from the key being absent, and sgshared.PolicyCache
// carries a HasSecurity flag for precisely that reason. Emitting `omitempty`
// on any of these would turn an answer into a silence.
//
// rateLimitObserve is not a duplicate of rateLimit. It carries the same numbers
// in detect mode, where the audit hook records bursts on ALLOW entries without
// blocking; the two are never both set.
type GuardSecurity struct {
	RateLimit        *RateLimitNumbers `json:"rateLimit"`
	RateLimitObserve *RateLimitNumbers `json:"rateLimitObserve"`
	DLPBlock         *DLPRules         `json:"dlpBlock"`
	DLPRedact        *DLPRules         `json:"dlpRedact"`
	LocalLogs        *LocalLogsConfig  `json:"localLogs,omitempty"`
}

type RateLimitNumbers struct {
	PerMinute int64 `json:"perMinute"`
	PerHour   int64 `json:"perHour"`
	PerDay    int64 `json:"perDay"`
}

type DLPRules struct {
	Patterns []string        `json:"patterns"`
	Custom   []CustomPattern `json:"custom"`
}

// GuardEnforcementConfig is src/lib/security-layers.ts's function of the same
// name: the stored configuration reduced to what the guard actually enforces.
//
// dlpRedact is set for BOTH detect and block, deliberately — redaction happens
// whenever DLP is not off, and blocking is the extra step.
func GuardEnforcementConfig(l SecurityLayers) GuardSecurity {
	var g GuardSecurity
	nums := &RateLimitNumbers{PerMinute: l.RateLimit.PerMinute, PerHour: l.RateLimit.PerHour, PerDay: l.RateLimit.PerDay}
	switch l.RateLimit.Mode {
	case LayerBlock:
		g.RateLimit = nums
	case LayerDetect:
		g.RateLimitObserve = nums
	}
	if l.DLP.Mode == LayerBlock {
		g.DLPBlock = &DLPRules{Patterns: l.DLP.Patterns, Custom: l.DLP.Custom}
	}
	if l.DLP.Mode != LayerOff {
		g.DLPRedact = &DLPRules{Patterns: l.DLP.Patterns, Custom: l.DLP.Custom}
	}
	return g
}

// SecurityLayersIn reads a `security` block carried INSIDE a policy document.
//
// A policy used to be a rule list and the DLP and rate-limit configuration was
// a project-wide setting beside it, which meant switching policies changed what
// was allowed and left what was watched exactly as it was. A policy now carries
// its own copy, and this is where that copy is read.
//
// The second return distinguishes "this policy says nothing about the layers"
// from "this policy turns everything off", and those are different answers: the
// first falls back to the project setting, the second is enforced. That is why
// this cannot simply return the default on a miss the way GetSecurityLayers
// does — an unreadable row there is one under-enforced poll, while guessing
// here would silently overwrite a project's configuration with a default.
//
// It goes through the same coercion as a stored row, so a policy written by an
// older dashboard, or by hand, is read the way that dashboard meant it.
func SecurityLayersIn(policyData []byte) (SecurityLayers, bool) {
	if len(policyData) == 0 {
		return SecurityLayers{}, false
	}
	var doc struct {
		Security json.RawMessage `json:"security"`
	}
	if json.Unmarshal(policyData, &doc) != nil {
		return SecurityLayers{}, false
	}
	return SecurityLayersFrom(doc.Security)
}

// SecurityLayersFrom is the same thing for a `security` object already in hand,
// which is what a VARIANT carries. A variant's block beats the policy's, and
// the policy's beats the project's; this is the one reader all three go
// through.
func SecurityLayersFrom(security []byte) (SecurityLayers, bool) {
	if len(security) == 0 {
		return SecurityLayers{}, false
	}
	var raw map[string]any
	if json.Unmarshal(security, &raw) != nil || raw == nil {
		// `"security": null` is not a configuration. It reads as absent rather
		// than as "everything off", because a policy saved by something that
		// nulls unknown keys must not disarm a project's DLP.
		return SecurityLayers{}, false
	}
	return coerceLayers(raw), true
}

// ── read and write ──────────────────────────────────────────────────────────

// GetSecurityLayers reads a project's configuration, coerced.
//
// Errors collapse to the default, as the live app's catch does. That is a
// choice with teeth: an unreadable row means the guard is told "detect", not
// "block" — the poll succeeds and the project is under-enforced for one cycle
// rather than the poll failing and the guard falling back to its cache.
func (s *Store) GetSecurityLayers(ctx context.Context, projectID string) SecurityLayers {
	v, ok, err := s.settingRead(ctx, scopedKey(settingSecurityLayers, projectID))
	if err != nil || !ok || v == "" {
		return coerceLayers(nil)
	}
	var raw map[string]any
	if json.Unmarshal([]byte(v), &raw) != nil {
		return coerceLayers(nil)
	}
	return coerceLayers(raw)
}

// SetSecurityLayers coerces, records a rate-limit history entry when the
// numbers or the mode changed, and stores the result.
//
// The history write is best-effort and precedes the real write, exactly as the
// original orders it: losing a history entry is cosmetic, losing the
// configuration is not.
func (s *Store) SetSecurityLayers(ctx context.Context, projectID string, input map[string]any) (SecurityLayers, error) {
	clean := coerceLayers(input)

	prev := s.GetSecurityLayers(ctx, projectID)
	p, c := prev.RateLimit, clean.RateLimit
	if p.PerMinute != c.PerMinute || p.PerHour != c.PerHour || p.PerDay != c.PerDay || p.Mode != c.Mode {
		// An `off` mode is recorded as zeroes rather than as the numbers still
		// sitting in the form. The history is what the panel draws as "the
		// limit over time", and drawing 10/min for a period when nothing was
		// enforced is a graph that lies.
		eff := RateLimitChange{TS: NowMS()}
		if c.Mode != LayerOff {
			eff.Minute, eff.Hour, eff.Day = c.PerMinute, c.PerHour, c.PerDay
		}
		hist := append(s.RateLimitHistory(ctx, projectID), eff)
		if len(hist) > 50 {
			hist = hist[len(hist)-50:]
		}
		if b, err := json.Marshal(hist); err == nil {
			_ = s.settingWrite(ctx, scopedKey(settingRateLimitHist, projectID), string(b),
				"Rate limit change history")
		}
	}

	b, err := json.Marshal(clean)
	if err != nil {
		return clean, err
	}
	if err := s.settingWrite(ctx, scopedKey(settingSecurityLayers, projectID), string(b),
		"Extra security layers config"); err != nil {
		return clean, err
	}
	return clean, nil
}

// RateLimitChange is one entry in the history. TS is MILLISECONDS: the panel
// feeds it to `new Date(ts)`.
type RateLimitChange struct {
	TS     int64 `json:"ts"`
	Minute int64 `json:"minute"`
	Hour   int64 `json:"hour"`
	Day    int64 `json:"day"`
}

// RateLimitHistory returns the stored entries, or an empty slice. Never nil:
// the endpoint serialises it straight into JSON and a nil slice would emit
// `null` where the dashboard iterates an array.
func (s *Store) RateLimitHistory(ctx context.Context, projectID string) []RateLimitChange {
	v, ok, err := s.settingRead(ctx, scopedKey(settingRateLimitHist, projectID))
	if err != nil || !ok || v == "" {
		return []RateLimitChange{}
	}
	var out []RateLimitChange
	if json.Unmarshal([]byte(v), &out) != nil || out == nil {
		return []RateLimitChange{}
	}
	return out
}

// RemoveRateLimitHistory drops one entry by timestamp, or all of them.
func (s *Store) RemoveRateLimitHistory(ctx context.Context, projectID string, ts int64, all bool) ([]RateLimitChange, error) {
	next := []RateLimitChange{}
	if !all {
		for _, h := range s.RateLimitHistory(ctx, projectID) {
			if h.TS != ts {
				next = append(next, h)
			}
		}
	}
	b, err := json.Marshal(next)
	if err != nil {
		return next, err
	}
	return next, s.settingWrite(ctx, scopedKey(settingRateLimitHist, projectID), string(b),
		"Rate limit change history")
}

// ── local logs ──────────────────────────────────────────────────────────────

// GetLocalLogs reads the local-log destination.
//
// `enabled` is computed rather than trusted: a stored `{enabled:true, path:""}`
// reads as disabled, because a guard told to write logs to nowhere writes them
// nowhere and reports itself as logging.
func (s *Store) GetLocalLogs(ctx context.Context, projectID string) LocalLogsConfig {
	v, ok, err := s.settingRead(ctx, scopedKey(settingLocalLogs, projectID))
	if err != nil || !ok || v == "" {
		return LocalLogsConfig{}
	}
	var raw map[string]any
	if json.Unmarshal([]byte(v), &raw) != nil {
		return LocalLogsConfig{}
	}
	path := Clip(trimAny(raw["path"]), 512)
	return LocalLogsConfig{Enabled: jsTruthy(raw["enabled"]) && path != "", Path: path}
}

// SetLocalLogs writes it back, coerced the same way, and returns what was
// stored so the endpoint echoes the effective value rather than the request.
func (s *Store) SetLocalLogs(ctx context.Context, projectID string, input map[string]any) (LocalLogsConfig, error) {
	path := Clip(trimAny(input["path"]), 512)
	cfg := LocalLogsConfig{Enabled: jsTruthy(input["enabled"]) && path != "", Path: path}
	b, err := json.Marshal(cfg)
	if err != nil {
		return cfg, err
	}
	return cfg, s.settingWrite(ctx, scopedKey(settingLocalLogs, projectID), string(b),
		"Local log storage (path + enabled)")
}

// LocalLogsViewConfig is the dashboard's side of the same feature: whether a
// local viewer is connected and on which port.
type LocalLogsViewConfig struct {
	Connected bool  `json:"connected"`
	Port      int64 `json:"port"`
}

const defaultLocalLogsPort = 8788

func (s *Store) GetLocalLogsView(ctx context.Context, projectID string) LocalLogsViewConfig {
	def := LocalLogsViewConfig{Port: defaultLocalLogsPort}
	v, ok, err := s.settingRead(ctx, scopedKey(settingLocalLogsView, projectID))
	if err != nil || !ok || v == "" {
		return def
	}
	var raw map[string]any
	if json.Unmarshal([]byte(v), &raw) != nil {
		return def
	}
	return LocalLogsViewConfig{Connected: jsTruthy(raw["connected"]), Port: coercePort(raw["port"])}
}

func (s *Store) SetLocalLogsView(ctx context.Context, projectID string, input map[string]any) (LocalLogsViewConfig, error) {
	cfg := LocalLogsViewConfig{Connected: jsTruthy(input["connected"]), Port: coercePort(input["port"])}
	b, err := json.Marshal(cfg)
	if err != nil {
		return cfg, err
	}
	return cfg, s.settingWrite(ctx, scopedKey(settingLocalLogsView, projectID), string(b),
		"Local logs dashboard view (connected + port)")
}

// coercePort keeps a port in range, falling back to the default. The original
// tests Number.isInteger, so a fractional port is rejected rather than
// truncated — 8788.5 is a typo, not a request for 8788.
func coercePort(v any) int64 {
	n, ok := jsNumber(v)
	if !ok || n != math.Trunc(n) || n <= 0 || n >= 65536 {
		return defaultLocalLogsPort
	}
	return int64(n)
}

// ── the coercion ────────────────────────────────────────────────────────────

// coerceLayers is src/lib/security-layers.ts's `coerce`, branch for branch.
//
// The three fallback chains are the compatibility layer described at the top of
// this file. In particular `o.anomaly === undefined → detect` means a stored
// object from before the rate-limit layer existed enables detection, and
// removing that branch would turn detection OFF for every project that has not
// touched the settings page since.
func coerceLayers(o map[string]any) SecurityLayers {
	d := DefaultSecurityLayers()
	if o == nil {
		return d
	}

	rl := subObject(o, "rateLimit")
	anomaly := subObject(o, "anomaly")
	_, hasAnomaly := o["anomaly"]

	rlMode, ok := asMode(rl["mode"])
	if !ok {
		switch {
		case isTrue(rl["enabled"]):
			rlMode = LayerBlock
		case isTrue(anomaly["enabled"]) || !hasAnomaly:
			rlMode = LayerDetect
		default:
			rlMode = LayerOff
		}
	}

	dlp := subObject(o, "dlp")
	dlpMode, ok := asMode(dlp["mode"])
	if !ok {
		switch {
		case isTrue(dlp["block"]):
			dlpMode = LayerBlock
		case isFalse(dlp["enabled"]):
			dlpMode = LayerOff
		default:
			dlpMode = LayerDetect
		}
	}

	// A stored `patterns` array selects a SUBSET of the built-ins, and the
	// filter runs over the built-in list rather than over the stored one: that
	// keeps the canonical order and drops any name that is no longer a
	// detector. Absent means all of them.
	patterns := DLPPatternNames()
	if arr, isArr := dlp["patterns"].([]any); isArr {
		want := map[string]bool{}
		for _, v := range arr {
			if s, isStr := v.(string); isStr {
				want[s] = true
			}
		}
		patterns = []string{}
		for _, n := range DLPPatternNames() {
			if want[n] {
				patterns = append(patterns, n)
			}
		}
	}

	custom := []CustomPattern{}
	if arr, isArr := dlp["custom"].([]any); isArr {
		for _, v := range arr {
			c, isObj := v.(map[string]any)
			if !isObj {
				continue
			}
			name := Clip(trimAny(c["name"]), 60)
			re := Clip(trimAny(c["re"]), 300)
			if name == "" || re == "" {
				continue
			}
			custom = append(custom, CustomPattern{Name: name, Re: re})
			if len(custom) >= 20 {
				break
			}
		}
	}

	// perMinute falls back to the `anomaly` block's number before the default,
	// because that is where it lived first. `??` only falls through on
	// null/undefined, so a stored 0 stays 0.
	perMinute := rl["perMinute"]
	if perMinute == nil {
		perMinute = anomaly["perMinute"]
	}

	return SecurityLayers{
		RateLimit: RateLimitLayer{
			Mode:      rlMode,
			PerMinute: num0(perMinute, d.RateLimit.PerMinute),
			PerHour:   num0(rl["perHour"], d.RateLimit.PerHour),
			PerDay:    num0(rl["perDay"], d.RateLimit.PerDay),
		},
		DLP: DLPLayer{Mode: dlpMode, Patterns: patterns, Custom: custom},
	}
}

func subObject(o map[string]any, key string) map[string]any {
	if o == nil {
		return map[string]any{}
	}
	if m, ok := o[key].(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asMode(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	switch s {
	case LayerOff, LayerDetect, LayerBlock:
		return s, true
	}
	return "", false
}

func isTrue(v any) bool  { b, ok := v.(bool); return ok && b }
func isFalse(v any) bool { b, ok := v.(bool); return ok && !b }

// num0 is the original's clamp: Number(v), non-finite falls back, then
// truncate and bound to 0..1_000_000. The ceiling is what stops a stored limit
// of 1e18 from overflowing whatever the guard multiplies it by.
func num0(v any, fallback int64) int64 {
	n, ok := jsNumber(v)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
		return fallback
	}
	n = math.Trunc(n)
	if n < 0 {
		return 0
	}
	if n > 1_000_000 {
		return 1_000_000
	}
	return int64(n)
}

// jsNumber is JavaScript's Number(), for the values JSON can produce.
//
// The string and boolean cases are not hypothetical: these settings have been
// written by three versions of a form, and a number that arrived as "120" from
// a text input is stored as a string. Number("120") is 120 there and has to be
// 120 here.
func jsNumber(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int64:
		return float64(t), true
	case int:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case string:
		s := trimAny(t)
		if s == "" {
			// Number("") is 0, not NaN.
			return 0, true
		}
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return 0, false
		}
		return f, true
	case nil:
		// An absent key and an explicit null both arrive here, and both must
		// take the caller's FALLBACK rather than becoming 0.
		//
		// The original reaches these fields through `?.` and `??`, so an absent
		// perMinute is `undefined`, Number(undefined) is NaN, and num0 falls
		// back to 120. An explicit null gets there too: `??` treats null and
		// undefined alike. Returning 0 here instead would read "this project
		// has not configured a limit" as "this project's limit is zero", which
		// under block mode means every call refused.
		return 0, false
	}
	return 0, false
}

// jsTruthy is `!!v` for JSON values.
func jsTruthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0 && !math.IsNaN(t)
	case nil:
		return false
	}
	return v != nil
}
