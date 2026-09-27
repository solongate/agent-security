package main

// /v1/settings/denial-alerts: the CRUD half of src/lib/denial-alerts.ts.
//
// An alert rule says "when this many of this signal happen inside this window,
// tell me here". The evaluation and the delivery are in audit_notify.go, on the
// path POST /v1/audit-logs takes; this file is what the settings page edits,
// and the two share one model and one reader so a rule cannot be saved in a
// shape the evaluator then ignores.
//
// The sanitising below is not input tidying. Every field of a rule is either a
// DESTINATION this service will send to — a Slack URL, an email address, a
// Telegram chat — or a bound on how often it will. A rule with a stranger's URL
// and a one-second window is an amplifier pointed wherever its author likes,
// which is why the thresholds are clamped, the targets are capped at one apiece
// and a URL that is not http(s) is dropped rather than stored.

import (
	"math"
	"net/http"
	"regexp"
	"strings"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

func init() {
	Register("GET /api/v1/settings/denial-alerts", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialAlertsList)
	})
	Register("POST /api/v1/settings/denial-alerts", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialAlertsAdd)
	})
	Register("PATCH /api/v1/settings/denial-alerts", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialAlertsUpdate)
	})
	Register("DELETE /api/v1/settings/denial-alerts", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialAlertsRemove)
	})
}

// denialAlertsDescription is the settings row's description column, matching
// what the live app writes for the same key.
const denialAlertsDescription = "Per-project denial alert rules (JSON)"

// alertNoChannel is the one validation message these routes produce, in the
// live app's wording — the dashboard shows it verbatim under the form.
const alertNoChannel = "At least one channel target (Slack, email or Telegram) is required"

// alertMaxTargets is MAX_TARGETS: one destination per channel per rule.
//
// It is a delivery bound, not a UI preference. Every target multiplies what one
// crossed threshold sends, and a rule is editable by anyone holding the
// project's API key.
const alertMaxTargets = 1

// The bounds the live app applies, named rather than repeated at four call
// sites: five to a hundred events, thirty seconds to a day.
const (
	alertThresholdMin, alertThresholdMax, alertThresholdDefault = 5, 100, 5
	alertWindowMin, alertWindowMax, alertWindowDefault          = 30, 86400, 300
)

var (
	alertURLRE     = regexp.MustCompile(`(?i)^https?://`)
	alertEmailRE   = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	alertChatIDRE  = regexp.MustCompile(`^-?\d{3,}$`)
	alertHandleRE  = regexp.MustCompile(`^@[A-Za-z0-9_]{4,}$`)
	alertSignalSet = map[string]bool{"any": true, "deny": true, "dlp": true, "ratelimit": true}
)

// denialAlertsList answers the project's rules.
//
// They are returned UNREDACTED, Slack URLs included, which is the live
// behaviour: the settings page has to render what is configured, and the caller
// already holds the key that could rewrite them.
func (s *server) denialAlertsList(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	rules := s.readAlertRules(r.Context(), key.ProjectID)
	if rules == nil {
		rules = []alertRule{}
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"rules": rules})
}

// denialAlertsAdd creates a rule.
//
// The channel check happens TWICE and the two are not the same check. The
// route's is on the raw body and answers 400; the limit check is on the
// SANITISED rule and answers 409. A body carrying `slackUrl: "not a url"`
// passes the first and sanitises to nothing, and the live app stores that rule
// with no targets — where the parser then hides it on the next read. That is
// preserved rather than fixed: the alternative is a 400 on a request the
// deployed dashboard currently gets a 200 for.
func (s *server) denialAlertsAdd(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body := settingsBody(w, r)

	if !alertBodyHasChannel(body) {
		apiauth.ValidationError(w, alertNoChannel)
		return
	}

	id := authNewID()
	if id == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}

	enabled := body["enabled"] != false
	rule := alertRule{
		ID:            id,
		Name:          alertName(body["name"]),
		Enabled:       &enabled,
		Threshold:     alertClampField(body, "threshold", alertThresholdMin, alertThresholdMax, alertThresholdDefault),
		WindowSeconds: alertClampField(body, "windowSeconds", alertWindowMin, alertWindowMax, alertWindowDefault),
		Signal:        alertCoerceSignal(body["signal"]),
		DenyLayers:    alertDenyLayersFrom(body["denyLayers"]),
		ToolPatterns:  alertToolPatternsFrom(body["toolPatterns"]),
		Developers:    alertIDsFrom(body["developers"]),
		SlackURLs:     alertSanitizeURLs(body["slackUrls"], body["slackUrl"]),
		Emails:        alertSanitizeEmails(body["emails"]),
		Telegram:      alertSanitizeTelegram(body["telegram"]),
		CreatedAt:     store.ISOms(store.NowMS()),
	}

	defer settingsListLock(store.SettingDenialAlerts, key.ProjectID).Unlock()

	rules := s.readAlertRules(r.Context(), key.ProjectID)

	// One rule per channel. The message names the channel because the settings
	// page shows it as-is, and "edit it instead" is the whole instruction: a
	// second Slack rule would double every alert rather than add a new one.
	if ch := alertChannelOf(rule); ch != "" {
		for _, existing := range rules {
			if alertChannelOf(existing) == ch {
				apiauth.Error(w, http.StatusConflict, "LIMIT_REACHED",
					"You already have a "+ch+" alert. Edit it instead of adding another.")
				return
			}
		}
	}

	if err := s.writeAlertRules(r, key.ProjectID, append(rules, rule)); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"rule": rule})
}

// denialAlertsUpdate is PATCH `?id=`.
//
// A body that is exactly `{enabled: ...}` takes a separate path: it flips the
// flag and answers `{ok:true}` without validating the channels, so a rule whose
// targets are no longer valid can still be switched OFF. Making that request go
// through the normal update would leave somebody with an alert they cannot
// silence.
func (s *server) denialAlertsUpdate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	id := r.URL.Query().Get("id")
	if id == "" {
		apiauth.ValidationError(w, "id is required")
		return
	}
	body := settingsBody(w, r)

	if _, onlyEnabled := body["enabled"]; onlyEnabled && len(body) == 1 {
		s.setAlertRuleEnabled(w, r, key.ProjectID, id, body["enabled"] != false)
		return
	}

	// `'slackUrls' in body || ...`: the presence of ANY channel key means the
	// rule's targets are being replaced wholesale, so the replacement has to
	// leave at least one. A body that mentions none of them leaves the existing
	// targets alone and is not asked to have any.
	touchesChannels := false
	for _, k := range []string{"slackUrls", "emails", "slackUrl", "telegram"} {
		if _, present := body[k]; present {
			touchesChannels = true
			break
		}
	}
	if touchesChannels && !alertBodyHasChannel(body) {
		apiauth.ValidationError(w, alertNoChannel)
		return
	}

	defer settingsListLock(store.SettingDenialAlerts, key.ProjectID).Unlock()

	rules := s.readAlertRules(r.Context(), key.ProjectID)
	idx := -1
	for i := range rules {
		if rules[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		apiauth.NotFound(w, "Alert rule not found.")
		return
	}

	next := rules[idx]
	if v, present := body["name"]; present {
		next.Name = alertName(v)
	}
	if v, present := body["enabled"]; present {
		enabled := v != false
		next.Enabled = &enabled
	}
	// The fallback is the PREVIOUS value rather than the default, so an absent
	// key leaves the field alone and an unparseable one does not quietly reset a
	// rule to five events in five minutes.
	next.Threshold = alertClampField(body, "threshold", alertThresholdMin, alertThresholdMax, next.Threshold)
	next.WindowSeconds = alertClampField(body, "windowSeconds", alertWindowMin, alertWindowMax, next.WindowSeconds)
	if v, present := body["signal"]; present {
		next.Signal = alertCoerceSignal(v)
	}
	if v, present := body["denyLayers"]; present {
		next.DenyLayers = alertDenyLayersFrom(v)
	}
	if v, present := body["developers"]; present {
		next.Developers = alertIDsFrom(v)
	}
	if v, present := body["toolPatterns"]; present {
		next.ToolPatterns = alertToolPatternsFrom(v)
	}
	if touchesChannels {
		next.SlackURLs = alertSanitizeURLs(body["slackUrls"], body["slackUrl"])
		next.Emails = alertSanitizeEmails(body["emails"])
		next.Telegram = alertSanitizeTelegram(body["telegram"])
	}

	// The 400 above was on the raw body; this is on what survived sanitising.
	// A rule saved with no target would still be evaluated and would deliver
	// nowhere, which reads as "alerts are broken" rather than as a rejected
	// edit. Both cases answer with the live app's wording.
	if !next.hasTarget() {
		apiauth.NotFound(w, "An alert rule needs at least one channel target.")
		return
	}

	rules[idx] = next
	if err := s.writeAlertRules(r, key.ProjectID, rules); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"rule": next})
}

// setAlertRuleEnabled is the `{enabled}`-only PATCH. An id that matches nothing
// is a 200 with nothing written, as the original's map-over-the-list is.
func (s *server) setAlertRuleEnabled(w http.ResponseWriter, r *http.Request, projectID, id string, enabled bool) {
	defer settingsListLock(store.SettingDenialAlerts, projectID).Unlock()

	rules := s.readAlertRules(r.Context(), projectID)
	for i := range rules {
		if rules[i].ID == id {
			v := enabled
			rules[i].Enabled = &v
		}
	}
	if err := s.writeAlertRules(r, projectID, rules); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// denialAlertsRemove is DELETE `?id=`.
func (s *server) denialAlertsRemove(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	id := r.URL.Query().Get("id")
	if id == "" {
		apiauth.ValidationError(w, "id is required")
		return
	}

	defer settingsListLock(store.SettingDenialAlerts, key.ProjectID).Unlock()

	rules := s.readAlertRules(r.Context(), key.ProjectID)
	kept := make([]alertRule, 0, len(rules))
	for _, rule := range rules {
		if rule.ID != id {
			kept = append(kept, rule)
		}
	}
	if err := s.writeAlertRules(r, key.ProjectID, kept); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// writeAlertRules stores the list.
//
// An empty list is written as `[]` rather than deleting the row, for the reason
// writeDenialWebhooks gives: both read back as no rules, and the store exposes
// no delete because its accessors are a closed set of setting names.
func (s *server) writeAlertRules(r *http.Request, projectID string, rules []alertRule) error {
	if rules == nil {
		rules = []alertRule{}
	}
	value, err := marshalNoEscape(rules)
	if err != nil {
		return err
	}
	return s.store.SetSettingJSON(r.Context(), store.SettingDenialAlerts, projectID,
		string(value), denialAlertsDescription)
}

// ── the body coercions ──────────────────────────────────────────────────────

// alertBodyHasChannel is the route's own check, on the RAW body: a truthy
// `slackUrl`, or a non-empty array in one of the three list fields.
//
// It deliberately does not sanitise first. That is the live order, and the
// difference shows for a body whose targets are all malformed — see
// denialAlertsAdd.
func alertBodyHasChannel(body map[string]any) bool {
	if authJSTruthy(body["slackUrl"]) {
		return true
	}
	for _, k := range []string{"slackUrls", "emails", "telegram"} {
		if arr, isArr := body[k].([]any); isArr && len(arr) > 0 {
			return true
		}
	}
	return false
}

// alertChannelOf is the original's channelOf: which single channel a rule
// belongs to, in this precedence.
func alertChannelOf(r alertRule) string {
	switch {
	case len(r.Telegram) > 0:
		return "telegram"
	case len(r.Emails) > 0:
		return "email"
	case len(r.SlackURLs) > 0:
		return "slack"
	}
	return ""
}

// alertName is `String(v || 'Alert').slice(0, 120)`.
func alertName(v any) string {
	if !authJSTruthy(v) {
		return "Alert"
	}
	return store.Clip(authJSString(v), 120)
}

func alertCoerceSignal(v any) string {
	if s, isStr := v.(string); isStr && alertSignalSet[s] {
		return s
	}
	return "any"
}

// alertClampField is `clampInt(body[key], min, max, dflt)`.
//
// It takes the map rather than the value because ABSENT and null are different
// answers here: `Math.floor(Number(undefined))` is NaN and takes the default,
// while `Number(null)` is 0 and clamps to the MINIMUM. So an absent
// windowSeconds means five minutes and an explicit null means thirty seconds,
// and a Go map lookup that returned only the value could not tell them apart.
//
// That also makes this the whole of the PATCH rule: pass the previous value as
// the default and an absent key leaves the field alone, which is what
// `input.x !== undefined ? clamp(...) : prev.x` says.
func alertClampField(body map[string]any, key string, min, max, def int64) int64 {
	v, present := body[key]
	if !present {
		return def
	}
	n, ok := jsNumber(v)
	if !ok || math.IsNaN(n) || math.IsInf(n, 0) {
		return def
	}
	n = math.Floor(n)
	if n < float64(min) {
		return min
	}
	if n > float64(max) {
		return max
	}
	return int64(n)
}

func alertDenyLayersFrom(v any) []string {
	arr, isArr := v.([]any)
	if !isArr {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		s, _ := e.(string)
		out = append(out, s)
	}
	return alertDenyLayers(out)
}

// alertIDsFrom reads the account list a rule is narrowed to.
//
// Separate from the tool-pattern reader even though both take an array of
// strings, because the two are cleaned by different rules and a reader
// following one to the other would find caps that have nothing to do with the
// values they are being applied to. The cleaning proper is alertDevelopers, on
// the rule, which is where every other per-field bound lives.
func alertIDsFrom(v any) []string {
	arr, isArr := v.([]any)
	if !isArr {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, jsString(e))
	}
	return alertDevelopers(out)
}

func alertToolPatternsFrom(v any) []string {
	arr, isArr := v.([]any)
	if !isArr {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, e := range arr {
		out = append(out, jsString(e))
	}
	return alertToolPatterns(out)
}

// alertSanitizeURLs takes the `slackUrls` array, or the legacy single
// `slackUrl` when the array is absent.
//
// The legacy field is still honoured because a client that has not been
// redeployed sends it, and dropping it would silently save a rule with no Slack
// target while answering 200.
func alertSanitizeURLs(arr any, legacy any) []string {
	raw, isArr := arr.([]any)
	if !isArr {
		if legacy == nil {
			return nil
		}
		raw = []any{legacy}
	}

	out := []string{}
	for _, v := range raw {
		s, isStr := v.(string)
		if !isStr {
			continue
		}
		s = strings.TrimSpace(s)
		if !alertURLRE.MatchString(s) {
			continue
		}
		s = store.Clip(s, 2048)
		if !containsString(out, s) {
			out = append(out, s)
		}
		if len(out) >= alertMaxTargets {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func alertSanitizeEmails(v any) []string {
	arr, isArr := v.([]any)
	if !isArr {
		return nil
	}
	out := []string{}
	for _, e := range arr {
		s := store.Clip(strings.TrimSpace(jsString(e)), 256)
		if !alertEmailRE.MatchString(s) {
			continue
		}
		if !containsString(out, s) {
			out = append(out, s)
		}
		if len(out) >= alertMaxTargets {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// alertSanitizeTelegram accepts a numeric chat id or an @handle, either as an
// array or as a bare value.
//
// A chat id arrives from JSON as a number often enough that stringifying it is
// the behaviour rather than a courtesy: -1001234567890 is a supergroup, and
// refusing it because it was not quoted would be a rule that silently never
// delivers.
func alertSanitizeTelegram(v any) []string {
	arr, isArr := v.([]any)
	if !isArr {
		if v == nil {
			return nil
		}
		arr = []any{v}
	}
	out := []string{}
	for _, e := range arr {
		s := store.Clip(strings.TrimSpace(jsString(e)), 64)
		if !alertChatIDRE.MatchString(s) && !alertHandleRE.MatchString(s) {
			continue
		}
		if !containsString(out, s) {
			out = append(out, s)
		}
		if len(out) >= alertMaxTargets {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func containsString(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
