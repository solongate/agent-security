package main

// GET and POST /v1/keys, PATCH and DELETE /v1/keys/{id}.
//
// The rule this file exists to hold: a key is shown ONCE, in the response to
// the request that created it, and stored only as a SHA-256 hash. There is no
// code path here that reads a key back — the list query does not even select
// key_hash, which is what stops a handler that spreads a row into a response
// from publishing one. The prefix is different: it is the first sixteen
// characters, it is stored in the clear because the lookup indexes on it, and
// it is what the dashboard shows.
//
// Everything is scoped to KeyInfo.ProjectID, never to an id in the request. A
// key id is a UUID a caller can hold from any context; without the project in
// the WHERE, DELETE /v1/keys/{id} is a denial of service against another tenant
// with nothing but a guessed id.

import (
	"net/http"
	"strings"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

func init() {
	Register("GET /api/v1/keys", func(s *server) http.Handler { return s.auth.WithAuth(s.keysList) })
	Register("POST /api/v1/keys", func(s *server) http.Handler { return s.auth.WithAuth(s.keysCreate) })
	Register("PATCH /api/v1/keys/{id}", func(s *server) http.Handler { return s.auth.WithAuth(s.keysRename) })
	Register("DELETE /api/v1/keys/{id}", func(s *server) http.Handler { return s.auth.WithAuth(s.keysRevoke) })
}

// keysMaxNameLen is `.slice(0, 100)` in both write paths.
const keysMaxNameLen = 100

// keyRow is the list shape. The field names are snake_case because that is what
// packages/proxy/src/api-client/keys.ts declares and what the dashboard reads;
// the two timestamps are ISO strings for the reason store.ISO gives.
type keyRow struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	KeyPrefix  string `json:"key_prefix"`
	IsLive     bool   `json:"is_live"`
	LastUsedAt any    `json:"last_used_at"`
	CreatedAt  string `json:"created_at"`
}

// keysList returns the project's live keys, oldest first.
//
// last_used_at stays null for a key nobody has authenticated with. It is not
// collapsed to a date, because "never used" is the answer the dashboard shows
// beside a key somebody is about to revoke.
func (s *server) keysList(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	keys, err := s.store.ListAPIKeys(r.Context(), key.ProjectID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	rows := make([]keyRow, 0, len(keys))
	for _, k := range keys {
		rows = append(rows, keyRow{
			ID:         k.ID,
			Name:       k.Name,
			KeyPrefix:  k.KeyPrefix,
			IsLive:     k.IsLive,
			LastUsedAt: store.ISOPtr(k.LastUsedAt),
			CreatedAt:  store.ISO(k.CreatedAt),
		})
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"keys": rows})
}

// keysCreate mints a key and returns it, once.
//
// The 201 body carries `key`, and that is the only time this service will ever
// produce it. `_warning` is part of the contract rather than decoration — the
// dashboard renders it beside the value.
func (s *server) keysCreate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	var body map[string]any
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}

	// `String(body.name || 'API Key').slice(0, 100)`: a falsy name — absent,
	// null, empty — takes the default, and a non-string is stringified rather
	// than refused.
	name := "API Key"
	if v, ok := body["name"]; ok && authJSTruthy(v) {
		name = authJSString(v)
	}
	name = store.Clip(name, keysMaxNameLen)

	// `body.is_live !== false`: only the literal JSON false opts out. A missing
	// field, a null, even the string "false" means live, which is the deployed
	// behaviour and not something to tighten here — a client that meant "test"
	// and got "live" would notice, and a client that meant "live" and got "test"
	// would silently authenticate against nothing.
	isLive := true
	if v, ok := body["is_live"]; ok {
		if b, isBool := v.(bool); isBool && !b {
			isLive = false
		}
	}

	newKey, err := apiauth.GenerateAPIKey(isLive)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	id := authNewID()
	if id == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}
	if err := s.store.CreateAPIKey(r.Context(), store.APIKey{
		ID:        id,
		ProjectID: key.ProjectID,
		KeyPrefix: newKey[:16],
		KeyHash:   apiauth.HashAPIKey(newKey),
		Name:      name,
		IsLive:    isLive,
		// Issued to whoever asked, not to whoever owns the project. For an
		// owner minting their own key those are the same answer; for a guest
		// they are not, and the difference is the whole of what makes a guest
		// a guest.
		UserID:    key.ActingUser(),
		CreatedAt: store.Now(),
	}); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusCreated, map[string]any{
		"id":         id,
		"name":       name,
		"key":        newKey,
		"key_prefix": newKey[:16],
		"is_live":    isLive,
		"_warning":   "Store this API key securely. It will not be shown again.",
	})
}

// keysRename is PATCH /v1/keys/{id}.
func (s *server) keysRename(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	keyID := r.PathValue("id")

	var body map[string]any
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}

	// `body.name ? String(body.name).trim().slice(0, 100) : null`, and then a
	// 400 for anything that came out empty — which includes a name that was
	// nothing but whitespace.
	name := ""
	if v, ok := body["name"]; ok && authJSTruthy(v) {
		name = store.Clip(strings.TrimSpace(authJSString(v)), keysMaxNameLen)
	}
	if name == "" {
		apiauth.BadRequest(w, "Name is required")
		return
	}

	// The project id is in the UPDATE's WHERE, so "not this project's key" and
	// "no such key" are the same statement and answer the same 404. Checking
	// existence first and updating after would be two round trips and a race.
	renamed, err := s.store.RenameAPIKey(r.Context(), key.ProjectID, keyID, name)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !renamed {
		authBadRequest(w, http.StatusNotFound, "API key not found")
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"id": keyID, "name": name})
}

// keysRevoke is DELETE /v1/keys/{id}. The row stays; revoked_at is stamped, and
// every authenticating query filters on it.
//
// A key that is already revoked answers 404 rather than a second 200. That is a
// small divergence — the live route's existence check does not look at
// revoked_at — and it falls out of doing the check and the write in one
// statement. The list this route is reached from shows live keys only, so the
// case is a double-submit.
func (s *server) keysRevoke(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	revoked, err := s.store.RevokeAPIKey(r.Context(), key.ProjectID, r.PathValue("id"), store.Now())
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !revoked {
		authBadRequest(w, http.StatusNotFound, "API key not found")
		return
	}
	// The authenticator caches a validated key for a few seconds. Without this
	// line a key revoked here keeps working until that expires, which is the
	// one case where "cached for speed" would mean "revoked and still armed".
	s.auth.Forget(r.PathValue("id"))
	apiauth.JSON(w, http.StatusOK, map[string]any{"revoked": true})
}
