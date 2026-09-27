package main

// /v1/settings/denial-webhook and its send-test: the CRUD half of
// src/lib/denial-webhook.ts, which audit_notify.go names as this slice's.
//
// The delivery half lives there and is not repeated here. This file reads the
// stored list through the same readDenialWebhooks and writes it back through
// the same struct, because the two halves are one stored value: a save that
// dropped a field the sender reads would stop deliveries with every endpoint
// still answering 200.
//
// A webhook URL is a CREDENTIAL. A Slack incoming-webhook URL is the whole
// authentication for posting into somebody's channel, and so are most of the
// automation endpoints these point at. Hence: the list route redacts the stored
// headers, nothing here logs a URL, and the send-test answers with a boolean
// rather than anything the far end said.

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

func init() {
	Register("GET /api/v1/settings/denial-webhook", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialWebhooksList)
	})
	Register("POST /api/v1/settings/denial-webhook", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialWebhooksAdd)
	})
	Register("PATCH /api/v1/settings/denial-webhook", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialWebhooksUpdate)
	})
	Register("DELETE /api/v1/settings/denial-webhook", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialWebhooksRemove)
	})
	Register("POST /api/v1/settings/denial-webhook/send-test", func(s *server) http.Handler {
		return s.auth.WithAuth(s.denialWebhookSendTest)
	})
}

// denialWebhookDescription is the row's description column, and it has to match
// what the live app writes: both apps upsert this key and the column is how
// somebody reading the table knows what a `denial_webhook:<uuid>` row is.
const denialWebhookDescription = "Per-project denial webhooks (JSON)"

// webhookURLRE is the original's `/^https?:\/\//i` and nothing more.
//
// It is not a URL validator and must not become one. Tightening it here would
// start refusing URLs this service has already stored and is already
// delivering to, and the check that matters — that this is not a `file:` or a
// `javascript:` scheme — is exactly what it does.
var webhookURLRE = regexp.MustCompile(`(?i)^https?://`)

// webhookView is one row of the GET response.
//
// It exists separately from denialWebhook for one reason: `enabled` is a
// concrete boolean here. The stored shape allows the key to be absent and the
// sender treats absent as enabled, but a response with `"enabled":null` would
// leave the settings page's toggle in neither position.
type webhookView struct {
	ID        string            `json:"id"`
	URL       string            `json:"url"`
	Enabled   bool              `json:"enabled"`
	CreatedAt string            `json:"createdAt"`
	Events    string            `json:"events"`
	Headers   map[string]string `json:"headers,omitempty"`
}

// denialWebhooksList answers the configured endpoints with their headers
// REDACTED.
//
// The values are replaced by a fixed mask rather than by their own length: a
// stored `Authorization: Bearer <token>` would otherwise publish how long the
// token is to anyone who can read the settings page. The keys stay visible
// because the page has to show which headers are set.
//
// The URLs are NOT redacted, which looks inconsistent and is the live
// behaviour: the page shows them so a customer can tell two Slack channels
// apart, and the same authenticated caller could read them back from the
// creating response anyway.
func (s *server) denialWebhooksList(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	hooks := s.readDenialWebhooks(r.Context(), key.ProjectID)

	// `[]`, never null: the dashboard maps over this.
	out := make([]webhookView, 0, len(hooks))
	for _, h := range hooks {
		out = append(out, webhookView{
			ID:        h.ID,
			URL:       h.URL,
			Enabled:   h.isEnabled(),
			CreatedAt: h.CreatedAt,
			Events:    h.Events,
			Headers:   redactHeaderValues(h.Headers),
		})
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"webhooks": out})
}

// redactHeaderValues keeps the names and masks the values.
func redactHeaderValues(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k := range in {
		out[k] = "••••••"
	}
	return out
}

// denialWebhooksAdd registers an endpoint.
//
// The duplicate check is by exact URL and answers 409 DUPLICATE. It is not a
// uniqueness constraint anybody depends on — it is there because adding the
// same Slack URL twice means every denial arrives twice, and the second one
// looks like a bug in the guard rather than in the settings page.
func (s *server) denialWebhooksAdd(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body := settingsBody(w, r)

	url := ""
	if v, isStr := body["url"].(string); isStr {
		url = strings.TrimSpace(v)
	}
	if url == "" {
		apiauth.ValidationError(w, "url is required")
		return
	}
	if !webhookURLRE.MatchString(url) {
		apiauth.ValidationError(w, "url must start with http:// or https://")
		return
	}

	id := authNewID()
	if id == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}

	defer settingsListLock(store.SettingDenialWebhook, key.ProjectID).Unlock()

	hooks := s.readDenialWebhooks(r.Context(), key.ProjectID)
	for _, h := range hooks {
		if h.URL == url {
			apiauth.Error(w, http.StatusConflict, "DUPLICATE", "That webhook URL is already added")
			return
		}
	}

	enabled := true
	hook := denialWebhook{
		ID:        id,
		URL:       url,
		Enabled:   &enabled,
		CreatedAt: store.ISOms(store.NowMS()),
		Events:    coerceWebhookEvents(body["events"]),
		Headers:   sanitizeWebhookHeaders(stringMap(body["headers"])),
	}

	if err := s.writeDenialWebhooks(r, key.ProjectID, append(hooks, hook)); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	// The created hook is returned with its headers in the clear, unlike the
	// list. That is the live behaviour and it is defensible exactly once: this
	// is the response to the request that supplied them.
	apiauth.JSON(w, http.StatusOK, map[string]any{"webhook": hook})
}

// denialWebhooksUpdate is PATCH: the enabled flag and the event filter.
//
// The id comes from the BODY here and from the query string on DELETE. That is
// not a tidy pair and it is what the two live routes do; a client already sends
// each of them the way it does.
//
// An id that matches nothing is a 200 with nothing changed, as the original's
// map-over-the-list is. The alternative — 404 — would be a new failure for a
// settings page that patched a webhook another tab had just deleted.
func (s *server) denialWebhooksUpdate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body := settingsBody(w, r)

	id, _ := body["id"].(string)
	if id == "" {
		apiauth.ValidationError(w, "id is required")
		return
	}

	defer settingsListLock(store.SettingDenialWebhook, key.ProjectID).Unlock()

	hooks := s.readDenialWebhooks(r.Context(), key.ProjectID)
	for i := range hooks {
		if hooks[i].ID != id {
			continue
		}
		// `typeof patch.enabled === 'boolean'`: only a real boolean moves the
		// toggle. Anything else leaves it where it was rather than being read as
		// falsy, because "off" is the state in which no alert is delivered.
		if v, isBool := body["enabled"].(bool); isBool {
			hooks[i].Enabled = &v
		}
		// `patch.events !== undefined`: a present-but-null events resets the
		// filter to denials, which is what coerceEvents does with anything it
		// does not recognise.
		if v, present := body["events"]; present {
			hooks[i].Events = coerceWebhookEvents(v)
		}
	}

	if err := s.writeDenialWebhooks(r, key.ProjectID, hooks); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// denialWebhooksRemove is DELETE `?id=`.
func (s *server) denialWebhooksRemove(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	id := r.URL.Query().Get("id")
	if id == "" {
		apiauth.ValidationError(w, "id is required")
		return
	}

	defer settingsListLock(store.SettingDenialWebhook, key.ProjectID).Unlock()

	hooks := s.readDenialWebhooks(r.Context(), key.ProjectID)
	kept := make([]denialWebhook, 0, len(hooks))
	for _, h := range hooks {
		if h.ID != id {
			kept = append(kept, h)
		}
	}

	if err := s.writeDenialWebhooks(r, key.ProjectID, kept); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"ok": true})
}

// writeDenialWebhooks stores the list.
//
// `enabled` is written as a concrete boolean even when the value read back was
// absent, so a save normalises the row instead of carrying a hole forward — the
// sender's "absent means enabled" rule stays the only reading of an old row,
// not of a new one.
//
// An empty list is stored as `[]` rather than deleting the row. The live app
// deletes it; both parse to no webhooks, and the store deliberately exposes no
// delete — its accessors are a closed set of setting NAMES precisely so that
// nothing in a route can address a settings row it was not built for.
func (s *server) writeDenialWebhooks(r *http.Request, projectID string, hooks []denialWebhook) error {
	for i := range hooks {
		enabled := hooks[i].isEnabled()
		hooks[i].Enabled = &enabled
	}
	if hooks == nil {
		hooks = []denialWebhook{}
	}
	value, err := marshalNoEscape(hooks)
	if err != nil {
		return err
	}
	return s.store.SetSettingJSON(r.Context(), store.SettingDenialWebhook, projectID,
		string(value), denialWebhookDescription)
}

// coerceWebhookEvents is the original's `v === 'allowed' || v === 'all' ? v :
// 'denials'`. Anything unrecognised means denials, which is the narrow answer:
// a typo delivers less than intended rather than shipping every allowed call to
// a third party.
func coerceWebhookEvents(v any) string {
	if s, isStr := v.(string); isStr && (s == "allowed" || s == "all") {
		return s
	}
	return "denials"
}

// stringMap pulls a JSON object's string members out of a decoded body.
//
// A non-string value is DROPPED rather than stringified, which is
// sanitizeHeaders' `typeof v !== 'string' → continue`. A header whose value
// arrived as a number is a client bug, and inventing "1" for it would put a
// header on somebody's outbound request that they never configured.
func stringMap(v any) map[string]string {
	obj, isObj := v.(map[string]any)
	if !isObj {
		return nil
	}
	out := make(map[string]string, len(obj))
	for k, raw := range obj {
		if s, isStr := raw.(string); isStr {
			out[k] = s
		}
	}
	return out
}

// ── send-test ───────────────────────────────────────────────────────────────

// denialWebhookSendTest delivers one sample denial to a configured endpoint.
//
// The URL is not taken from the request: the body names a webhook by id and the
// URL comes from this project's stored list. That is what keeps this from being
// an open request forwarder — a caller cannot point it at an address of their
// choosing, only at one they already configured and this service already
// delivers to.
//
// The response is a single boolean. Nothing the far end returned is echoed —
// not its body, not its status — because this endpoint would otherwise report
// on any host the project can name.
func (s *server) denialWebhookSendTest(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body := settingsBody(w, r)
	id, _ := body["id"].(string)

	var hook *denialWebhook
	for _, h := range s.readDenialWebhooks(r.Context(), key.ProjectID) {
		if h.ID == id {
			found := h
			hook = &found
			break
		}
	}
	if hook == nil {
		apiauth.NotFound(w, "Webhook not found")
		return
	}

	requestID := authNewID()
	if requestID == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}

	// The payload is the live route's sample, field for field. It is what a
	// customer builds their Zapier or n8n filter against, so `decision: DENY`
	// and `deny_layer: POLICY` have to be there: a test event that did not look
	// like a denial would let somebody ship a filter that never matches a real
	// one.
	ruleID := "test-rule"
	reason := "SolonGate test event: this is a sample denial payload."
	evalMS := 0.42
	agentID, agentName := "test-agent", "Test Agent"
	ev := denialEvent{
		Event:            "denial",
		Timestamp:        store.ISOms(store.NowMS()),
		RequestID:        "test-" + requestID,
		ProjectID:        key.ProjectID,
		Decision:         "DENY",
		DenyLayer:        "POLICY",
		Tool:             "Bash",
		Permission:       "EXECUTE",
		MatchedRuleID:    &ruleID,
		Reason:           &reason,
		EvaluationTimeMs: &evalMS,
		Agent:            webhookAgent{ID: &agentID, Name: &agentName},
	}

	delivered := postNotifyJSON(r.Context(), hook.URL,
		map[string]string{"X-SolonGate-Event": ev.Event}, hook.Headers, ev)
	apiauth.JSON(w, http.StatusOK, map[string]any{"delivered": delivered})
}
