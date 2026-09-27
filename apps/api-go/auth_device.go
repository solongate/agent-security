package main

// The device-authorisation flow: POST /v1/auth/device/start, POST
// /v1/auth/device/poll, GET /v1/auth/device/check, POST
// /v1/auth/device/approve.
//
// This is how a machine gets paired. The CLI calls start and polls; the person
// opens the address it prints, which calls check to validate the code it was
// handed and approve to authorise it. The CLI half is INSTALLED on people's
// machines and is not redeployed with this binary, so the field names, the
// status strings and the status codes below are a contract:
//
//   start   → device_code, user_code, verification_uri,
//             verification_uri_complete, expires_in (600), interval (3)
//   poll    → {status: not_found} 404, or {status: expired|pending} 200,
//             or {status: approved, api_key, project{id,name}, user{email,name}}
//   check   → {valid, status}, always 200
//   approve → {ok:true, project{id,name}}, or {ok:true, already:true}
//
// packages/proxy/src/api-client/device-login.ts reads exactly those, treats any
// status it does not recognise as `pending`, and keeps polling — so a wrong
// shape here is not an error the CLI reports, it is a login that never
// finishes.
//
// The timestamps in device_codes are MILLISECONDS. Every other table in this
// database stores seconds; this one is written with Date.now() by the routes
// and read against the CLI's own clock. store.NowMS is the clock for this file.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

func init() {
	Register("POST /api/v1/auth/device/start", func(s *server) http.Handler {
		return authPublic(s, apiauth.LimitAuth, "device-start", s.deviceStart)
	})
	Register("POST /api/v1/auth/device/poll", func(s *server) http.Handler {
		return authPublic(s, apiauth.LimitDevicePoll, "device-poll", s.devicePoll)
	})
	Register("GET /api/v1/auth/device/check", func(s *server) http.Handler {
		return authPublic(s, apiauth.LimitDevicePoll, "device-check", s.deviceCheck)
	})
	Register("POST /api/v1/auth/device/approve", func(s *server) http.Handler {
		return authPublic(s, apiauth.LimitAuth, "device-approve", s.deviceApprove)
	})
}

const (
	// deviceCodeTTLMS is CODE_TTL_MS: ten minutes. `expires_in` is this in
	// seconds and the CLI computes its own deadline from it, so the two have to
	// be the same number.
	deviceCodeTTLMS = 10 * 60 * 1000

	// devicePollIntervalS is what the CLI sleeps between polls. It clamps this
	// to at least two seconds on its side; three is what has been served.
	devicePollIntervalS = 3
)

// deviceDashboardURL is where the person is sent to approve. Read under the
// plain name only, which is the name the live route reads: env() would also
// accept a NEXT_PUBLIC_ spelling, and this value ends up in a CLI's terminal as
// the URL to trust.
func deviceDashboardURL() string {
	if v := strings.TrimSpace(os.Getenv("DASHBOARD_URL")); v != "" {
		return v
	}
	// NO DEFAULT, and the caller has to cope with an empty string.
	//
	// This is the address a CLI prints and asks somebody to open and trust. There
	// is no UI in this repository to point it at, so a built-in value would be
	// either a host that answers nothing or — worse — a host somebody else
	// operates. An installation that has a UI names it in DASHBOARD_URL.
	return ""
}

// deviceUserCodeAlphabet is the original's: no I, L, O, 0 or 1. Those are the
// characters a person misreads off a screen and types into another window,
// which is the entire user interface of this flow.
const deviceUserCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// deviceUserCode mints the short code, formatted XXXX-XXXX.
//
// The alphabet, the length and the hyphen are the contract — the dashboard
// upper-cases and trims what it is given and looks it up verbatim. The
// SELECTION is not: the original takes a random byte modulo 31, which makes the
// first eight letters of the alphabet very slightly more likely than the rest.
// This rejects the bytes that would bias it instead. Nothing observable
// changes; the code just stops leaking a preference to anyone guessing.
func deviceUserCode() (string, error) {
	const n = len(deviceUserCodeAlphabet)
	// 248 = 8 * 31: the largest multiple of the alphabet that fits in a byte.
	// Anything at or above it is drawn again.
	const limit = 256 - (256 % n)

	out := make([]byte, 0, 9)
	buf := make([]byte, 16)
	for len(out) < 9 {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, b := range buf {
			if len(out) == 4 {
				out = append(out, '-')
			}
			if len(out) >= 9 {
				break
			}
			if int(b) >= limit {
				continue
			}
			out = append(out, deviceUserCodeAlphabet[int(b)%n])
		}
	}
	return string(out), nil
}

// deviceCodeSecret is the 32 random bytes the CLI holds and nobody else sees.
//
// It is the only thing standing between an approved pairing and whoever else is
// polling: the user_code is short and typed by a person, so it is the device
// code that has to be unguessable. Sixty-four hex characters, as the original.
func deviceCodeSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// deviceSchemaReady is `await schemaReady`: device_codes is created at runtime
// rather than by the drizzle schema, so a route that touches it has to be sure
// the table exists. main.go runs this at boot; the call here is what makes a
// boot-time failure recoverable instead of permanent.
func (s *server) deviceSchemaReady(ctx context.Context) error {
	return s.store.EnsureRuntimeTables(ctx)
}

// deviceStart issues a pairing. It is unauthenticated by design — there is no
// credential yet, that is what the flow is for — so its only protection is the
// per-IP limit of ten a minute and the fact that a pending row is worth nothing
// until somebody approves it.
func (s *server) deviceStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.deviceSchemaReady(ctx); err != nil {
		authInternal(w, "device/start", err)
		return
	}

	deviceCode, err := deviceCodeSecret()
	if err != nil {
		authInternal(w, "device/start", err)
		return
	}
	userCode, err := deviceUserCode()
	if err != nil {
		authInternal(w, "device/start", err)
		return
	}

	now := store.NowMS()
	if err := s.store.StartDeviceCode(ctx, deviceCode, userCode, now, now+deviceCodeTTLMS); err != nil {
		authInternal(w, "device/start", err)
		return
	}

	out := map[string]any{
		"device_code": deviceCode,
		"user_code":   userCode,
		"expires_in":  deviceCodeTTLMS / 1000,
		"interval":    devicePollIntervalS,
	}
	// The verification URLs are OMITTED when no UI is configured, rather than
	// emitted as a relative path.
	//
	// A CLI opens whatever this says in a browser and asks the person to trust
	// it. With DASHBOARD_URL unset there is nowhere to send them, and building
	// "/cli" out of an empty base produces a string that is not a URL at all —
	// which the CLI would print, or worse hand to `xdg-open`. Absent keys are
	// something a caller can detect; a malformed URL is something it cannot.
	if base := deviceDashboardURL(); base != "" {
		base = strings.TrimRight(base, "/")
		out["verification_uri"] = base + "/cli"
		out["verification_uri_complete"] = base + "/cli?device=" + url.QueryEscape(userCode)
	}
	apiauth.JSON(w, http.StatusOK, out)
}

// devicePoll is the CLI's loop, and the one place a project key leaves this
// service without an API key having been presented.
//
// The claim is an UPDATE with `status = 'approved'` in its WHERE, not a SELECT
// followed by an UPDATE. That is a divergence and it closes a real hole: the
// live route reads the key, then clears it, and two polls arriving in that gap
// BOTH receive it. One pairing would have handed a live project credential to
// two machines, and only one of them is the person who approved it. Here only
// one UPDATE can match; the loser is told `pending`, which is what a consumed
// code answers in the live app too, so the CLI's behaviour is unchanged.
//
// The status read that precedes the claim exists only to tell 404 from 200. It
// does not select api_key.
func (s *server) devicePoll(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.deviceSchemaReady(ctx); err != nil {
		authInternal(w, "device/poll", err)
		return
	}

	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}
	deviceCode := strings.TrimSpace(body.DeviceCode)
	if deviceCode == "" {
		apiauth.BadRequest(w, "Missing device_code")
		return
	}

	status, err := s.store.PollDeviceCode(ctx, deviceCode)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// 404 with a body, not an error envelope: the CLI reads
			// `status` and stops on this one.
			apiauth.JSON(w, http.StatusNotFound, map[string]any{"status": "not_found"})
			return
		}
		authInternal(w, "device/poll", err)
		return
	}

	// An approved code is collectable after its expiry, which is the live
	// behaviour: the deadline is on the PERSON approving, not on the CLI
	// collecting. Only an unapproved code goes stale.
	if status.Status != "approved" && store.NowMS() > status.ExpiresAtMS {
		apiauth.JSON(w, http.StatusOK, map[string]any{"status": "expired"})
		return
	}

	claimed, found, err := s.store.ClaimDeviceCode(ctx, deviceCode)
	if err != nil {
		authInternal(w, "device/poll", err)
		return
	}
	if !found {
		// Not approved yet, or already collected. The CLI cannot tell those
		// apart and never could.
		apiauth.JSON(w, http.StatusOK, map[string]any{"status": "pending"})
		return
	}

	// The key goes into this response and nowhere else. It is not logged, and
	// the row it came out of has already been marked consumed and blanked.
	apiauth.JSON(w, http.StatusOK, map[string]any{
		"status":  "approved",
		"api_key": claimed.APIKey,
		"project": map[string]any{
			"id":   authNullable(claimed.ProjectID),
			"name": authNullable(claimed.ProjectName),
		},
		"user": map[string]any{
			"email": authNullable(claimed.UserEmail),
			"name":  authNullable(claimed.UserName),
		},
	})
}

// deviceCheck is what the dashboard's /cli page asks before it renders the
// approve button: is this code real and still waiting.
//
// It answers 200 for every outcome, including "no such code", and it never
// touches the api_key column. The page branches on `valid` and shows the
// already-authorised state for `approved` and `consumed`, so those two strings
// have to survive verbatim.
func (s *server) deviceCheck(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.deviceSchemaReady(ctx); err != nil {
		authInternal(w, "device/check", err)
		return
	}

	code := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("device")))
	if code == "" {
		apiauth.JSON(w, http.StatusOK, map[string]any{"valid": false, "status": "missing"})
		return
	}

	status, err := s.store.DeviceCodeStatusByUserCode(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apiauth.JSON(w, http.StatusOK, map[string]any{"valid": false, "status": "not_found"})
			return
		}
		authInternal(w, "device/check", err)
		return
	}
	if status.Status != "pending" {
		apiauth.JSON(w, http.StatusOK, map[string]any{"valid": false, "status": status.Status})
		return
	}
	if store.NowMS() > status.ExpiresAtMS {
		apiauth.JSON(w, http.StatusOK, map[string]any{"valid": false, "status": "expired"})
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"valid": true, "status": "pending"})
}

// deviceApprove is the browser's half: it mints a live key for the account the
// page names and attaches it to the pending row.
//
// READ THIS BEFORE CHANGING IT. The endpoint takes an address out of the
// request body and does not verify it — /v1/auth/session does verify, this does
// not — so possession of a pending user_code is the whole authorisation. That
// is the live behaviour and it is reproduced rather than fixed, because the
// deployed dashboard page sends `{user_code, email}` and nothing else: adding a
// required access_token here would break every browser that has the page
// cached. It is written up in the caveats and it is the first thing to close
// once the dashboard can be redeployed alongside this.
//
// What IS enforced here is that the address must already have been decided by
// the person at the browser, that the code must be pending and unexpired, and
// that approving twice is idempotent rather than a second key.
func (s *server) deviceApprove(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.deviceSchemaReady(ctx); err != nil {
		authInternal(w, "device/approve", err)
		return
	}

	var body struct {
		UserCode string `json:"user_code"`
		Email    string `json:"email"`
	}
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}
	code := strings.ToUpper(strings.TrimSpace(body.UserCode))
	email := strings.ToLower(strings.TrimSpace(body.Email))
	if code == "" {
		apiauth.BadRequest(w, "Missing user_code")
		return
	}
	if email == "" {
		apiauth.BadRequest(w, "Missing email")
		return
	}

	existing, err := s.store.DeviceCodeStatusByUserCode(ctx, code)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusNotFound, "Invalid code")
			return
		}
		authInternal(w, "device/approve", err)
		return
	}
	switch {
	case existing.Status == "approved" || existing.Status == "consumed":
		// Idempotent: the page can be reloaded, and a second approval must not
		// mint a second key for a pairing that already has one.
		apiauth.JSON(w, http.StatusOK, map[string]any{"ok": true, "already": true})
		return
	case existing.Status != "pending":
		authBadRequest(w, http.StatusConflict, "Code already used")
		return
	case store.NowMS() > existing.ExpiresAtMS:
		authBadRequest(w, http.StatusGone, "Code expired")
		return
	}

	userID, userName, err := s.authSessionUser(ctx, email, "")
	if err != nil {
		authInternal(w, "device/approve", err)
		return
	}
	// `existingUser[0].name || email.split('@')[0]`: an account stored without a
	// display name still prints something in the CLI after pairing.
	if userName == "" {
		userName = authEmailLocal(email)
	}

	// Unlike /v1/auth/session this does NOT seed a starter policy for a project
	// it creates, and that difference is the original's. It is worth naming
	// because it means a project first created by a CLI pairing starts with no
	// policy — see the caveats.
	project, keyName, err := s.devicePairing(ctx, userID, email)
	if err != nil {
		authInternal(w, "device/approve", err)
		return
	}

	if err := s.store.RevokeAPIKeysNamed(ctx, project.ID, keyName, store.Now()); err != nil {
		authInternal(w, "device/approve", err)
		return
	}
	liveKey, liveKeyID, err := s.authMintKey(ctx, project.ID, userID, keyName)
	if err != nil {
		authInternal(w, "device/approve", err)
		return
	}

	// `AND status = 'pending'` is inside the UPDATE. Two tabs approving the same
	// code would otherwise both mint a key and the second would overwrite the
	// first, leaving a live key nobody will collect and nobody knows to revoke.
	//
	// The loser here has already minted a key, so it is revoked again on the way
	// out rather than left behind.
	attached, err := s.store.ApproveDeviceCode(ctx, code, liveKey, project.ID, project.Name, email, userName)
	if err != nil {
		authInternal(w, "device/approve", err)
		return
	}
	if !attached {
		// By id, not by name: the winner's key carries the same fixed name and
		// revoking by name here would log the machine that DID pair straight
		// back out.
		if _, err := s.store.RevokeAPIKey(ctx, project.ID, liveKeyID, store.Now()); err != nil {
			log.Printf("[API:device/approve] a key minted for a lost race could not be revoked: %v", err)
		}
		apiauth.JSON(w, http.StatusOK, map[string]any{"ok": true, "already": true})
		return
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"project": map[string]any{
			"id":   project.ID,
			"name": project.Name,
		},
	})
}

// devicePairing answers WHICH project this machine is being paired to, and
// under what key name.
//
// For almost everybody it is their own newest project under the one fixed CLI
// key name, which is what it has always been.
//
// For a guest it is the HOST's project, and that is the step the fleet was
// missing. The file at the top of fleetgrants.go says accepting "mints them a
// key on the HOST's project, and from then on their guard polls the host's
// policy because that is whose project their key opens" — and that was true of
// the key the accept route mints and throws nowhere, because the browser
// deliberately discards it and no command ever fetched it. So a guest accepted
// an invitation, the dashboard changed around them, and their laptop went on
// enforcing their own policy and reporting to their own project. Nothing in the
// fleet worked on a real machine.
//
// Pairing is the natural place for it: it is the moment a machine asks which
// project it belongs to, and for a guest the answer is not their own.
//
// The KEY NAME has to differ per person and this is not cosmetic. The revoke
// above clears keys by name on the project being paired to, so if every machine
// paired under the one CLI name, the second person to pair would revoke the
// first one's credential and silently unpair their machine. The
// name carries the address, which is also what makes the host's key list
// readable: they can see whose machine each key is.
func (s *server) devicePairing(ctx context.Context, userID, email string) (store.ProjectSummary, string, error) {
	project, err := s.deviceProject(ctx, userID)
	return project, authCLIKeyName, err
}

// deviceProject returns the account's newest project, creating a bare one if
// there is none. The name and the slug shape are the original's.
func (s *server) deviceProject(ctx context.Context, userID string) (store.ProjectSummary, error) {
	existing, err := s.store.LatestProjectByOwner(ctx, userID)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ProjectSummary{}, err
	}

	projectID, slugSuffix := authNewID(), authNewID()
	if projectID == "" || slugSuffix == "" {
		return store.ProjectSummary{}, authErrNoID
	}
	tokenSecret, err := apiauth.GenerateTokenSecret()
	if err != nil {
		return store.ProjectSummary{}, err
	}

	now := store.Now()
	p := store.Project{
		ID: projectID, OwnerID: userID, Name: "My Project",
		Slug: "my-project-" + slugSuffix[:8], Description: "",
		TokenSecret: tokenSecret, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateProject(ctx, p); err != nil {
		return store.ProjectSummary{}, err
	}
	return store.ProjectSummary{
		ID: p.ID, OwnerID: p.OwnerID, Name: p.Name, Slug: p.Slug,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}
