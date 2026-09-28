package main

// The /v1/settings tree: the eight paths under src/app/api/v1/settings.
//
// Two of them are not a settings page. GET /v1/policies/active reads the same
// two rows this slice writes — security-layers and self-protection — and hands
// them to every installed guard as the `security` block and the
// `self_protection_enabled` flag. So a wrong shape here does not misdraw a
// panel; it changes whether machines enforce anything. That is why nothing in
// this file parses those rows itself: the coercion lives in
// internal/store/securitylayers.go, ported from src/lib/security-layers.ts, and
// both readers go through it. Two readings of one stored object is how the
// panel comes to show one configuration while the guard applies another.
//
// Everything is scoped to KeyInfo.ProjectID. The settings table has no
// project_id column — every row is namespaced by a key of the form
// `<name>:<projectId>` — so the scoping is the key construction, and the store
// is the only place that builds one. A route that could name the setting key
// would be a cross-tenant read with a valid API key attached.

import (
	"net/http"
	"strings"
	"unicode"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

func init() {
	Register("GET /api/v1/settings/security-layers", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsSecurityLayersGet)
	})
	Register("PUT /api/v1/settings/security-layers", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsSecurityLayersPut)
	})
	Register("GET /api/v1/settings/self-protection", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsSelfProtectionGet)
	})
	Register("PUT /api/v1/settings/self-protection", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsSelfProtectionPut)
	})
	Register("GET /api/v1/settings/local-logs", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsLocalLogsGet)
	})
	Register("PUT /api/v1/settings/local-logs", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsLocalLogsPut)
	})
	Register("GET /api/v1/settings/local-logs-view", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsLocalLogsViewGet)
	})
	Register("PUT /api/v1/settings/local-logs-view", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsLocalLogsViewPut)
	})
	Register("GET /api/v1/settings/rate-limit-history", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsRateLimitHistoryGet)
	})
	Register("DELETE /api/v1/settings/rate-limit-history", func(s *server) http.Handler {
		return s.auth.WithAuth(s.settingsRateLimitHistoryDelete)
	})
}

// settingsBody reads a request body the way every route in this tree does:
// `await request.json().catch(() => ({}))`. A body that is absent, empty or not
// an object is an EMPTY object, not a 400 — the dashboard's toggles send
// `{}` for "leave everything at its default", and answering 400 there would be
// a new failure on an endpoint that has never returned one.
//
// A JSON array decodes to nil for the same reason it does in the original: the
// coercions reach their fields through `?.`, and an array has none of them.
func settingsBody(w http.ResponseWriter, r *http.Request) map[string]any {
	var body map[string]any
	_ = apiauth.DecodeJSON(w, r, &body, true)
	return body
}

// ── security layers ─────────────────────────────────────────────────────────

// settingsSecurityLayersGet answers the configuration plus the names of the
// built-in detectors.
//
// availablePatterns is not decoration: the settings page renders one checkbox
// per name and stores back the SUBSET that is ticked, so this list and the
// stored `patterns` array are the same vocabulary. A name missing from here is
// a detector nobody can switch on again.
func (s *server) settingsSecurityLayersGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	apiauth.JSON(w, http.StatusOK, map[string]any{
		"layers":            s.store.GetSecurityLayers(r.Context(), key.ProjectID),
		"availablePatterns": store.DLPPatternNames(),
	})
}

// settingsSecurityLayersPut stores it.
//
// The body may be `{layers: {...}}` or the layers object itself — the live
// route accepts both (`body?.layers ?? body`) because the dashboard sends the
// first and the CLI sends the second. A `layers` that is present but not an
// object falls through to the defaults, which is what `coerce` does with a
// non-object.
//
// Nothing is validated beyond that, deliberately. The store's coercion is the
// validation: it clamps the numbers, filters the pattern names against the
// built-in list and drops malformed custom patterns, and it is the same
// function /v1/policies/active reads through. A second check here that
// disagreed with it would let a value be saved and then ignored.
func (s *server) settingsSecurityLayersPut(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body := settingsBody(w, r)

	next := body
	if v, present := body["layers"]; present && v != nil {
		next, _ = v.(map[string]any)
	}

	layers, err := s.store.SetSecurityLayers(r.Context(), key.ProjectID, next)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	// The response echoes what was STORED rather than what was sent, so a
	// dashboard that posted `perMinute: "60"` renders 60 and not the string it
	// typed — and so a value the coercion dropped is visibly absent instead of
	// appearing to have been saved.
	apiauth.JSON(w, http.StatusOK, map[string]any{"layers": layers})
}

// ── self-protection ─────────────────────────────────────────────────────────

// settingsSelfProtectionGet reports the tamper guard's flag.
//
// The store answers true for a project with no row AND for a read that failed,
// which is the live behaviour and the safe direction: "off" is the answer that
// lets a hook be edited by the agent it is guarding.
func (s *server) settingsSelfProtectionGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	apiauth.JSON(w, http.StatusOK, map[string]any{
		"enabled": s.store.SelfProtectionEnabled(r.Context(), key.ProjectID),
	})
}

// settingsSelfProtectionPut requires a real boolean.
//
// `typeof body?.enabled !== 'boolean'` in the original, and it is stricter than
// the rest of this service on purpose: this endpoint turns the tamper guard
// off, and a string "false" — which JavaScript would find truthy and store as
// ON, or which a laxer reading would store as OFF — must be a 400 rather than
// either guess.
func (s *server) settingsSelfProtectionPut(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body := settingsBody(w, r)

	enabled, isBool := body["enabled"].(bool)
	if !isBool {
		apiauth.ValidationError(w, "enabled (boolean) is required")
		return
	}
	if err := s.store.SetSelfProtectionEnabled(r.Context(), key.ProjectID, enabled); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"enabled": enabled})
}

// ── local logs ──────────────────────────────────────────────────────────────

// settingsLocalLogsGet and its PUT return the config OBJECT, not an object
// wrapping it. Both live routes answer `jsonResponse(await getLocalLogs(...))`
// and the dashboard reads `.enabled` off the top level.
func (s *server) settingsLocalLogsGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	apiauth.JSON(w, http.StatusOK, s.store.GetLocalLogs(r.Context(), key.ProjectID))
}

// settingsLocalLogsPut stores the destination and echoes what was stored.
//
// `enabled` is not taken at face value by the store: a path that is empty after
// trimming reads back as disabled, because a guard told to log to nowhere logs
// nowhere while reporting itself as logging.
func (s *server) settingsLocalLogsPut(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	cfg, err := s.store.SetLocalLogs(r.Context(), key.ProjectID, settingsBody(w, r))
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, cfg)
}

func (s *server) settingsLocalLogsViewGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	apiauth.JSON(w, http.StatusOK, s.store.GetLocalLogsView(r.Context(), key.ProjectID))
}

func (s *server) settingsLocalLogsViewPut(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	cfg, err := s.store.SetLocalLogsView(r.Context(), key.ProjectID, settingsBody(w, r))
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, cfg)
}

// ── rate limit history ──────────────────────────────────────────────────────

// settingsRateLimitHistoryGet lists the recorded changes. The store writes an
// entry from SetSecurityLayers whenever the numbers or the mode moved, so this
// is the audit trail behind "the limit was raised, when".
func (s *server) settingsRateLimitHistoryGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	apiauth.JSON(w, http.StatusOK, map[string]any{
		"history": s.store.RateLimitHistory(r.Context(), key.ProjectID),
	})
}

// settingsRateLimitHistoryDelete drops one entry by its timestamp, or all of
// them with `?all=1`.
//
// `ts` is matched, not indexed: the entry is identified by the millisecond it
// was recorded at, so a stale page deleting an entry that is already gone
// removes nothing and still answers 200 with the current list — which is what
// the panel re-renders from.
func (s *server) settingsRateLimitHistoryDelete(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	q := r.URL.Query()

	// The literal string "1", as the original tests it. `?all=true` is not the
	// documented spelling and must not clear somebody's history by accident.
	all := q.Get("all") == "1"

	var ts int64
	if !all {
		n, ok := jsParseInt10(q.Get("ts"))
		if !ok {
			apiauth.ValidationError(w, "ts or all=1 required")
			return
		}
		ts = n
	}

	history, err := s.store.RemoveRateLimitHistory(r.Context(), key.ProjectID, ts, all)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"history": history})
}

// jsParseInt10 is `parseInt(s, 10)` followed by `Number.isFinite`.
//
// It is not strconv.ParseInt and the difference is the point: parseInt stops at
// the first character that is not a digit and keeps what it had, so "1700000
// (old)" is a number to the live route and an error to a strict parser. A
// stricter reading here would answer 400 where the deployed dashboard gets a
// 200, and the only way to find that out is in production.
//
// Digits beyond what an int64 holds saturate rather than wrap. The value is
// compared against stored timestamps and never used as a length, so a saturated
// one matches nothing — which is the same outcome as JavaScript's float losing
// precision on the same input.
func jsParseInt10(raw string) (int64, bool) {
	s := strings.TrimLeftFunc(raw, unicode.IsSpace)

	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}

	var n int64
	digits := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		digits++
		if n <= (1<<62)/10 {
			n = n*10 + int64(c-'0')
		}
	}
	if digits == 0 {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}
