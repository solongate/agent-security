package main

// Authentication and identity: POST /v1/auth, GET /v1/auth/me, GET and PUT
// /v1/auth/profile, POST /v1/auth/session.
//
// This file also holds the small helpers the rest of this slice — the device
// flow, the key routes and the organisation routes — shares. They are prefixed
// `auth` because four slices are being written into this package at once and an
// unprefixed `newID` is a compile error somebody else has to resolve.
//
// The thing to know about the two provisioning routes here is what they hand
// back. /v1/auth/session returns a LIVE project key for whatever identity it
// decides the caller has, which makes the identity decision the whole security
// of the endpoint — see authSession, and see the caveat about SUPABASE_URL.
// Nothing else in this file mints a credential.
//
// A key is returned exactly once, at creation, and stored only as a SHA-256
// hash. There is no route here or anywhere else that can read one back, no line
// that logs one, and the one comparison of a stored secret (a password hash)
// runs in constant time.

import (
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

func init() {
	Register("POST /api/v1/auth", func(s *server) http.Handler {
		return authPublic(s, apiauth.LimitAuth, "", s.authPassword)
	})
	Register("GET /api/v1/auth/me", func(s *server) http.Handler {
		return s.auth.WithAuth(s.authMe)
	})
	Register("GET /api/v1/auth/profile", func(s *server) http.Handler {
		return s.auth.WithAuth(s.authProfileGet)
	})
	Register("PUT /api/v1/auth/profile", func(s *server) http.Handler {
		return s.auth.WithAuth(s.authProfilePut)
	})
	Register("POST /api/v1/auth/session", func(s *server) http.Handler {
		return authPublic(s, apiauth.LimitSetup, "", s.authSession)
	})
}

// ── the helpers this slice shares ───────────────────────────────────────────

// authPublic is src/lib/auth.ts's withRateLimit: the only gate on the routes
// that have no API key to identify a caller by.
//
// It is a function rather than a method so the registration lines above read as
// one expression, and it exists at all so that a route in this slice cannot be
// registered without a limit — the six public routes in this service are the
// provisioning and pairing endpoints, and an unlimited one is a free way to
// make this process mint rows.
func authPublic(s *server, cfg apiauth.Config, prefix string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auth.LimitByIP(w, r, cfg, prefix) {
			return
		}
		next(w, r)
	})
}

// authErrNoID is what a caller returns when authNewID came back empty. It is a
// 500 with nothing quoted: the only thing that went wrong is that the system
// CSPRNG refused, and there is nothing useful to tell the caller about that.
var authErrNoID = errors.New("could not generate an id")

// authNewID is crypto.randomUUID(): a version 4 UUID from the system CSPRNG.
//
// It returns empty on failure and every caller treats that as a refusal to
// write, rather than falling back to a clock. These ids name API keys,
// organisations and memberships; a predictable one is a row an outsider can
// address before it exists.
func authNewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Printf("api: could not read random bytes for an id: %v", err)
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// authInternal is `errorResponse('Internal server error', 500)`.
//
// The code is "ERROR" and not "INTERNAL_ERROR", which looks like a typo and is
// not: the device routes and /v1/auth/session render their catch through
// errorResponse's default code, while the routes that call handleApiError
// render "INTERNAL_ERROR". Both spellings are already in front of deployed
// clients. apiauth.Internal is the second one; this is the first.
//
// The underlying error goes to the log and never to the caller, for the reason
// apiauth.Internal states: a libsql error quotes the statement, and sometimes
// the DSN.
func authInternal(w http.ResponseWriter, where string, err error) {
	log.Printf("[API:%s] %v", where, err)
	apiauth.Error(w, http.StatusInternalServerError, "ERROR", "Internal server error")
}

// authInternalCtx is authInternal for a step that ran a query, and it separates
// the two things that look identical in a log and are not the same event.
//
// A statement can fail because the database refused it, or because the CALLER
// went away and net/http cancelled the request context underneath it. Both
// surface from the driver as "failed to execute SQL: context canceled", and
// reading a screenshot of that cannot tell you whether the database is in
// trouble or whether a browser was closed mid-request. One is an incident; the
// other is a Tuesday.
//
// The distinction matters more than the wording: a cancelled caller is not a
// 500 to anybody, because there is nobody left to receive it, and writing one
// in the log as though it were makes every real failure harder to see.
func authInternalCtx(w http.ResponseWriter, r *http.Request, where string, err error) {
	if cerr := r.Context().Err(); cerr != nil {
		log.Printf("[API:%s] caller went away after %v: %v", where, cerr, err)
		// Still answered, because net/http needs a response written even when
		// nothing is listening. It goes nowhere.
		apiauth.Error(w, http.StatusInternalServerError, "ERROR", "Internal server error")
		return
	}
	authInternal(w, where, err)
}

// authBadRequest is errorResponse(message, status) at the default code, for the
// statuses apiauth has no named helper for. 403, 409 and 410 all appear in this
// slice and all of them carry the code "ERROR" in the live app — the dashboard
// reads `error.message` off these, not the code.
func authBadRequest(w http.ResponseWriter, status int, message string) {
	apiauth.Error(w, status, "ERROR", message)
}

// authProjectOwner resolves the presented key to the user behind its project.
//
// Nine routes in this slice start with it, and it is one function so that none
// of them can be written without it. The user id is never taken from the
// request: /v1/auth/profile would otherwise be an edit form for any account in
// the database, and every route in orgs.go would answer for any membership.
//
// It returns false with the 404 or the 500 already written.
func (s *server) authProjectOwner(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) (string, bool) {
	ownerID, err := s.store.ProjectOwner(r.Context(), key.ProjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusNotFound, "Project not found")
			return "", false
		}
		apiauth.Internal(w, "api", err)
		return "", false
	}
	return ownerID, true
}

// authEmailRE is the routes' `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`, unchanged.
//
// It is not a good address validator and is not meant to be. It is the one the
// live app applies, and tightening it here would start refusing addresses this
// service has already stored.
var authEmailRE = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// authNullable renders a nullable TEXT column the way drizzle does.
//
// internal/store flattens NULL and the empty string to "" on the way in, and
// for `users.name` the deployed clients see JSON null rather than "" — an
// account created through Supabase before a name was known has a NULL there.
// Emitting "" would be harmless in JavaScript and wrong in the response, and
// the write side never stores an empty name, so the two cannot be confused.
func authNullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// authUTF16Len counts UTF-16 code units, which is what String.prototype.length
// returns.
//
// Every length CHECK in this slice is a check the live app also makes, and the
// two have to refuse the same input. Counting bytes would refuse names the live
// app accepts; counting runes would accept passwords it refuses. This
// repository has already shipped one bug from assuming a JavaScript string
// length was a Go string length, which is why sgshared exists.
func authUTF16Len(s string) int {
	n := 0
	for _, r := range s {
		if r > 0xFFFF {
			n += 2
		} else {
			n++
		}
	}
	return n
}

// authJSString is JavaScript's String(v) for the values JSON can carry.
//
// The routes it serves are written as `String(body.name || 'API Key')`, which
// accepts a number and stringifies it. Decoding those bodies into a typed
// struct would answer 400 where the live app answers 200 with "123" stored, so
// the bodies are decoded into map[string]any and coerced here instead.
func authJSString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// Through the JSON encoder rather than through %v, because Go's float
		// encoder was written to match Number.prototype.toString: it produces
		// "1000000" where %v produces "1e+06".
		b, err := json.Marshal(t)
		if err != nil {
			return "0"
		}
		return string(b)
	case json.Number:
		return t.String()
	case nil:
		return ""
	}
	// An object or an array returns "" rather than JavaScript's
	// "[object Object]". Every call site guards with `v ? String(v) : default`,
	// so the difference shows only for a caller sending an object where a name
	// was expected, and storing "[object Object]" as a key name helps nobody.
	return ""
}

// authJSTruthy is `!!v` for JSON values, which is what `body.name || default`
// tests. An empty string, a zero and a false are all falsy, and all three fall
// through to the default in the live app.
func authJSTruthy(v any) bool {
	switch t := v.(type) {
	case string:
		return t != ""
	case bool:
		return t
	case float64:
		// NaN is falsy in JavaScript, and JSON cannot carry one — but
		// json.Number can produce one on the way through, so the check is here
		// rather than assumed away.
		return t != 0 && !math.IsNaN(t)
	case json.Number:
		f, err := t.Float64()
		return err == nil && f != 0 && !math.IsNaN(f)
	case nil:
		return false
	}
	return v != nil
}

// authSlugify is `name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ”)`.
//
// Each RUN of non-alphanumeric characters collapses to a single hyphen, and
// then one leading and one trailing hyphen are removed — one, because the
// original's second replace has no `+` and the `g` flag only lets it fire once
// at each anchor. A caller's project name reaches this and the result reaches a
// UNIQUE column, so the suffix the callers append is what makes it collide-free,
// not this.
func authSlugify(name string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(name) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevDash = false
			continue
		}
		if !prevDash {
			b.WriteByte('-')
			prevDash = true
		}
	}
	out := strings.TrimSuffix(strings.TrimPrefix(b.String(), "-"), "-")
	return out
}

// authEmailLocal is `email.split('@')[0]`: the default display name.
func authEmailLocal(email string) string {
	local, _, _ := strings.Cut(email, "@")
	return local
}

// authUser is drizzle's `select({id, email, name, createdAt})` over users, which
// is the shape /v1/auth/me and both halves of /v1/auth/profile return.
type authUser struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Name      any    `json:"name"`
	CreatedAt string `json:"createdAt"`
}

func authUserOf(u store.User) authUser {
	return authUser{ID: u.ID, Email: u.Email, Name: authNullable(u.Name), CreatedAt: store.ISO(u.CreatedAt)}
}

// ── passwords ───────────────────────────────────────────────────────────────

// authPBKDF2Iterations is the live app's 100000, and it is a constant here for
// the same reason it is one there: verification re-derives with this number
// rather than with the one stored in the hash string. A stored hash that was
// written with a different count will not verify, which is the existing
// behaviour and not something to quietly repair — changing it would start
// accepting passwords against hashes the live app rejects.
const authPBKDF2Iterations = 100000

// authHashPassword is the route's hashPassword: PBKDF2-HMAC-SHA256, 100000
// iterations, 256 bits, rendered as `pbkdf2:100000:<salt>:<hex>`.
//
// The salt fed to PBKDF2 is the UTF-8 bytes of the HEX STRING, not the sixteen
// bytes it encodes. That is what `encoder.encode(s)` does in the original and
// it doubles the salt length as far as the KDF is concerned; deriving from the
// decoded bytes instead would produce a different digest for every existing
// account in the database.
//
// An empty salt means "mint one", as `salt || …` does. A caller that passes the
// salt out of a stored hash and gets an empty string has a corrupt row, and the
// comparison that follows fails — which is the same answer the live app gives.
func authHashPassword(password, salt string) (string, error) {
	if salt == "" {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return "", err
		}
		salt = hex.EncodeToString(b[:])
	}
	dk, err := pbkdf2.Key(sha256.New, password, []byte(salt), authPBKDF2Iterations, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2:%d:%s:%s", authPBKDF2Iterations, salt, hex.EncodeToString(dk)), nil
}

// authVerifyPassword is the route's verifyPassword, with the string comparison
// made constant-time.
//
// The original compares the two `pbkdf2:…` strings with ===, which stops at the
// first differing byte. The value on the left is derived from the caller's
// input and the value on the right is the stored secret, so that is a timing
// oracle for the digest one byte at a time. The answer is identical either way;
// only the time it takes changes.
func authVerifyPassword(password, stored string) bool {
	parts := strings.Split(stored, ":")
	if len(parts) != 4 || parts[0] != "pbkdf2" {
		return false
	}
	computed, err := authHashPassword(password, parts[2])
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(computed), []byte(stored)) == 1
}

// ── POST /api/v1/auth ───────────────────────────────────────────────────────

// authRegisterNeutralMessage is returned whether or not the address was
// already taken, and the taken branch still spends the PBKDF2 work. Both halves
// of that matter: the message stops the endpoint from being an account
// enumerator, and the wasted derivation stops the response TIME from being one.
const authRegisterNeutralMessage = "If this email is available, your account has been created. Sign in to continue."

// authPassword is POST /v1/auth: register or log in with a password.
//
// Nothing in this repository calls it today — the dashboard signs in through
// Supabase and the CLI through the device flow — but it is deployed, so it is
// ported as it stands rather than removed.
func (s *server) authPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Action   string `json:"action"`
		Email    string `json:"email"`
		Password string `json:"password"`
		Name     string `json:"name"`
	}
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}

	// The validation order is the original's, and order is visible here: a
	// request with no action and no password is told about the action first.
	if body.Action != "login" && body.Action != "register" {
		apiauth.BadRequest(w, `Invalid action. Use "login" or "register".`)
		return
	}
	if body.Email == "" || body.Password == "" {
		apiauth.BadRequest(w, "Missing required fields: email, password")
		return
	}
	if !authEmailRE.MatchString(body.Email) {
		apiauth.BadRequest(w, "Invalid email format")
		return
	}
	if authUTF16Len(body.Password) < 8 {
		apiauth.BadRequest(w, "Password must be at least 8 characters")
		return
	}

	if body.Action == "register" {
		s.authRegister(w, r, body.Email, body.Password, body.Name)
		return
	}
	s.authLogin(w, r, body.Email, body.Password)
}

func (s *server) authRegister(w http.ResponseWriter, r *http.Request, email, password, name string) {
	ctx := r.Context()

	_, err := s.store.UserByEmail(ctx, email)
	switch {
	case err == nil:
		// Taken. Derive anyway and discard the result: without this the
		// difference between a taken and a free address is a hundred thousand
		// iterations of PBKDF2, which is measurable from anywhere.
		_, _ = authHashPassword(password, "")
		apiauth.JSON(w, http.StatusOK, map[string]string{"message": authRegisterNeutralMessage})
		return
	case !errors.Is(err, store.ErrNotFound):
		apiauth.Internal(w, "api", err)
		return
	}

	hash, err := authHashPassword(password, "")
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if name == "" {
		name = authEmailLocal(email)
	}
	id := authNewID()
	if id == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}
	now := store.Now()
	if err := s.store.CreateUser(ctx, store.User{
		ID: id, Email: email, Name: name, PasswordHash: hash, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]string{"message": authRegisterNeutralMessage})
}

func (s *server) authLogin(w http.ResponseWriter, r *http.Request, email, password string) {
	ctx := r.Context()

	u, err := s.store.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			apiauth.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}

	// NO_PASSWORD is deliberately distinguishable from INVALID_CREDENTIALS and
	// stays that way. It is not an enumeration leak worth closing here: the
	// address is already known to be registered by the time this branch is
	// reachable, and the client needs to know that the answer is "sign in
	// somewhere else" rather than "try another password".
	if u.PasswordHash == "" {
		apiauth.Error(w, http.StatusUnauthorized, "NO_PASSWORD",
			"This account uses OAuth or was created via setup. Password login is not available.")
		return
	}
	if !authVerifyPassword(password, u.PasswordHash) {
		apiauth.Error(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	owned, err := s.store.ProjectsByOwner(ctx, u.ID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	type project struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	list := make([]project, 0, len(owned))
	for _, p := range owned {
		list = append(list, project{ID: p.ID, Name: p.Name, Slug: p.Slug})
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{
		"user": map[string]any{
			"id":    u.ID,
			"email": u.Email,
			"name":  authNullable(u.Name),
		},
		"projects": list,
	})
}

// ── GET /api/v1/auth/me ─────────────────────────────────────────────────────

// authMe describes the key that was presented, the project it resolves to and
// that project's owner.
//
// The project id is KeyInfo.ProjectID and never a query parameter, which is
// what makes this a description of the caller rather than a lookup service.
func (s *server) authMe(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()

	project, err := s.store.ProjectSummaryByID(ctx, key.ProjectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// This route's 404 is the NOT_FOUND code, unlike /auth/profile's,
			// because it is written as a jsonResponse rather than an
			// errorResponse. Both are deployed.
			apiauth.NotFound(w, "Project not found")
			return
		}
		apiauth.Internal(w, "auth/me", err)
		return
	}

	// `owner[0] || null`: a project whose owner row is gone answers null rather
	// than failing. A database error is not that case and must not be flattened
	// into it.
	var owner any
	u, err := s.store.UserByID(ctx, project.OwnerID)
	switch {
	case err == nil:
		owner = authUserOf(u)
	case !errors.Is(err, store.ErrNotFound):
		apiauth.Internal(w, "auth/me", err)
		return
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{
		"user": owner,
		"project": map[string]any{
			"id":        project.ID,
			"name":      project.Name,
			"slug":      project.Slug,
			"createdAt": store.ISO(project.CreatedAt),
		},
		// The PREFIX, which is the first sixteen characters and is stored in the
		// clear. Never the key.
		"api_key": map[string]any{
			"prefix":  key.KeyPrefix,
			"is_live": key.IsLive,
		},
	})
}

// ── GET and PUT /api/v1/auth/profile ────────────────────────────────────────

func (s *server) authProfileGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()

	ownerID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}

	u, err := s.store.UserByID(ctx, ownerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusNotFound, "User not found")
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"user": authUserOf(u)})
}

// authProfilePut writes the display name.
//
// It does NOT write the address, and that is a deliberate divergence from the
// live route rather than an omission. The address on a `users` row is the
// identity Supabase vouches for and the value /v1/auth/session matches on:
// changing it here would repoint an account at somebody else's address and, on
// the next sign-in, provision a live key for whoever actually owns it. The
// format check is still applied so that a caller sending a malformed address
// gets the same 400 it gets today, and no caller in this repository sends the
// field at all — the dashboard's api-client declares it and nothing calls it.
func (s *server) authProfilePut(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()

	var body map[string]any
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}

	ownerID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}

	name := ""
	writeName := false
	if v, present := body["name"]; present {
		given, isString := v.(string)
		if !isString || authUTF16Len(given) > 100 {
			apiauth.BadRequest(w, "Name must be a string under 100 characters")
			return
		}
		name, writeName = given, true
	}
	if v, present := body["email"]; present {
		addr, isString := v.(string)
		if !isString || !authEmailRE.MatchString(addr) {
			apiauth.BadRequest(w, "Invalid email format")
			return
		}
	}

	if writeName {
		if _, err := s.store.UpdateUserProfile(ctx, ownerID, name, store.Now()); err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
	}

	u, err := s.store.UserByID(ctx, ownerID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusNotFound, "User not found")
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"user": authUserOf(u)})
}

// ── POST /api/v1/auth/session ───────────────────────────────────────────────

// The Supabase side of provisioning: the port of src/lib/supabase-verify.ts.
//
// This endpoint returns a live API key for the identity it is given, so the
// identity has to be proven rather than typed. When SUPABASE_URL is configured
// the caller's access token is presented to Supabase and the address comes back
// from there; the body's `email` is ignored entirely.
//
// When it is NOT configured there is nothing to check against, and the live app
// stays open rather than locking every existing user out. That behaviour is
// reproduced exactly, and it is the sharpest edge in this slice: the variable
// is read from THIS process's environment, so a Go deploy that does not carry
// SUPABASE_URL over from the Node service turns a closed endpoint into an open
// one without anything failing. The warning below is per request for that
// reason — it is meant to be impossible to miss in a log.

func authSupabaseBase() string {
	// SUPABASE_URL first, then the NEXT_PUBLIC_ spelling, which is the live
	// app's order. The shell's env() prefers the public spelling and is not used
	// here so the two implementations cannot disagree about which wins.
	if v := strings.TrimSpace(os.Getenv("SUPABASE_URL")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("NEXT_PUBLIC_SUPABASE_URL"))
}

// authSupabaseClient has a timeout because the default http.Client does not.
// A Supabase that accepts the connection and never answers would otherwise hold
// this handler until the server's write deadline, on the endpoint the whole
// dashboard blocks on at startup.
var authSupabaseClient = &http.Client{Timeout: authVerifyBudget}

// authVerifyBudget is how long token verification may take.
//
// Five seconds, and the number is chosen against the CALLER's patience rather
// than against Supabase's. The dashboard gives this route fifteen seconds and
// then abandons it; verification used to be allowed ten of those, so a slow
// Supabase left four for the four database steps and the request died mid-query
// with the caller already gone. Railway recorded those as 499 at fourteen and
// fifteen seconds, and the database logged cancellations that looked like
// database trouble and were not.
//
// Five leaves the rest of the budget to the work this route exists to do. A
// verification that cannot finish in five seconds is not going to save the
// request anyway.
const authVerifyBudget = 5 * time.Second

// authVerifySlow is when a verification is worth a log line. It is the
// dependency this route cannot proceed without, and it had NO logging at all —
// every failure and every stall returned a bare false, which is why a
// fifteen-second sign-in looked like a database problem for an afternoon.
const authVerifySlow = 750 * time.Millisecond

// authVerified caches a token's verified address for a short window.
//
// The same access token is presented on every sign-in that misses the
// dashboard's keyring, and each one used to be a fresh round trip to Supabase
// on the critical path of every page. The window is deliberately short: this
// stands between a revoked session and a minted API key, and a long cache would
// mean a signed-out token still buying one.
var authVerified = struct {
	sync.Mutex
	at     map[string]authVerifiedEntry
	pruned time.Time
}{at: map[string]authVerifiedEntry{}}

type authVerifiedEntry struct {
	email string
	until time.Time
}

// authVerifyTTL is how long a verified token is trusted without asking again.
const authVerifyTTL = 30 * time.Second

// authVerifyAccessToken asks Supabase who a token belongs to.
//
// Every failure — network, non-2xx, unparseable body, a user with no id — is
// the same (”, false), as the original's `catch { return null }`. The token is
// never logged, and neither is the error: an HTTP client error message quotes
// the URL, and the Authorization header has been known to end up in one.
func authVerifyAccessToken(ctx context.Context, token string) (string, bool) {
	// An on-premise installation verifies against the customer's own identity
	// provider instead; see auth_oidc.go. Selected by configuration rather
	// than by a build tag, so the behaviour can be read off the deployment.
	if oidcConfigured() {
		return authVerifyOIDCToken(ctx, token)
	}

	base := authSupabaseBase()
	if base == "" || token == "" {
		return "", false
	}
	if email, ok := authVerifiedLookup(token); ok {
		return email, true
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		strings.TrimRight(base, "/")+"/auth/v1/user", nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if k := strings.TrimSpace(os.Getenv("SUPABASE_ANON_KEY")); k != "" {
		req.Header.Set("apikey", k)
	}

	started := time.Now()
	resp, err := authSupabaseClient.Do(req)
	if err != nil {
		// Logged, finally. This is the dependency the whole dashboard waits on
		// and it used to fail in silence.
		log.Printf("[auth/session] token verification failed after %s: %v",
			time.Since(started).Round(time.Millisecond), err)
		return "", false
	}
	defer resp.Body.Close()
	if elapsed := time.Since(started); elapsed > authVerifySlow {
		log.Printf("[auth/session] token verification took %s", elapsed.Round(time.Millisecond))
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		log.Printf("[auth/session] token verification refused with status %d", resp.StatusCode)
		return "", false
	}

	var who struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	// Bounded: this is a body from another service and it is read into memory.
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&who); err != nil {
		return "", false
	}
	if who.ID == "" {
		return "", false
	}
	// `user.email ? trim().toLowerCase() : null`, and the route turns a null
	// into the empty string, which it then refuses. A verified session with no
	// address cannot provision.
	email := strings.ToLower(strings.TrimSpace(who.Email))
	authVerifiedRemember(token, email)
	return email, true
}

// authSession is the dashboard's provisioning call: it resolves a Supabase
// session to a user, makes sure that user has a project, and hands back a fresh
// live key for it.
//
// The key is returned once, in this response, and stored hashed. The previous
// "Dashboard Session" key is revoked first, so a browser that provisions twice
// does not leave a working credential behind in a tab nobody has.
func (s *server) authSession(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var body struct {
		Email       string `json:"email"`
		Name        string `json:"name"`
		ProjectName string `json:"project_name"`
		AccessToken string `json:"access_token"`
		// CreateProject is a POINTER because absent and false are two different
		// requests here.
		//
		// Every caller that predates this field — the CLI, the device flow, any
		// deployed dashboard still running — sends no such key, and all of them
		// have to keep getting a project made on first sign-in. A plain bool
		// would read an absent field as false, hand those callers a response
		// with no key in it, and lock every one of them out of an account they
		// could sign in to yesterday.
		//
		// A caller that sends false is saying it would rather have NO project
		// than one nobody asked for. That is the dashboard: an account that has
		// just been created should land on the screen where a workspace is
		// made, not inside a workspace named after them by a route they never
		// saw.
		CreateProject *bool `json:"create_project"`
		// ProjectID is WHICH workspace the caller wants to be in.
		//
		// Without it this route answered with the account's most recent project
		// and nothing else, so an account with two workspaces had one it could
		// reach: making a second one silently moved the whole dashboard into it,
		// the switcher changed a name in the chrome and not a single call under
		// it, and switching back did nothing at all. The machines carried on
		// reporting into the first, which then read as a workspace whose data
		// had disappeared.
		//
		// It is a REQUEST, not an instruction: a project that does not exist, or
		// belongs to somebody else, falls back to the same answer as before
		// rather than failing. An id is not a permission - the owner check
		// below is.
		ProjectID string `json:"project_id"`
	}
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}

	// WHO THIS IS COMES OFF A VERIFIED TOKEN AND FROM NOWHERE ELSE.
	//
	// The gate used to be `if authSupabaseBase() != ""`, which asked the wrong
	// question twice over. A deployment using OIDC has no Supabase, so the
	// branch was skipped and the token was never verified — and with neither
	// configured it logged "running unverified" and provisioned whatever address
	// the REQUEST BODY named. That is a credential for any account, to anybody
	// who can reach the port, and it is the same hole the device-approve
	// endpoint had before it was deleted.
	//
	// So: a provider must be configured, a token must be presented, and the
	// address is the one its claims carry. body.Email is no longer read at all.
	if !authIdentityConfigured() {
		apiauth.Error(w, http.StatusServiceUnavailable, "NO_IDENTITY_PROVIDER",
			"This deployment has no identity provider configured, so a sign-in cannot be verified. "+
				"Set SG_OIDC_ISSUER (or SUPABASE_URL) and restart.")
		return
	}
	if body.AccessToken == "" {
		apiauth.Error(w, http.StatusUnauthorized, "UNVERIFIED", "Missing required field: access_token")
		return
	}
	email, ok := s.verifyToken(ctx, body.AccessToken)
	if !ok {
		apiauth.Error(w, http.StatusUnauthorized, "UNVERIFIED", "Could not verify the session")
		return
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		apiauth.Error(w, http.StatusUnauthorized, "UNVERIFIED",
			"The token carried no address claim (email, upn or preferred_username)")
		return
	}

	// Each step reports under its own name.
	//
	// They all used to log "auth/session", and when this route started failing
	// in production the line said a query had failed and nothing about WHICH:
	// four database steps, one message, and no way to tell a slow user lookup
	// from a slow key revoke without guessing. The names cost nothing and are
	// the difference between reading a log and speculating about one.
	started := time.Now()

	userID, _, err := s.authSessionUser(ctx, email, body.Name)
	if err != nil {
		authInternalCtx(w, r, "auth/session:user", err)
		return
	}

	// Absent means create, which is the behaviour every caller written before
	// this field was added is relying on. See the field.
	project, err := s.authSessionProject(ctx, userID, body.ProjectName,
		body.CreateProject == nil || *body.CreateProject, body.ProjectID)
	if err != nil {
		authInternalCtx(w, r, "auth/session:project", err)
		return
	}

	// Both key steps are SKIPPED when there is no project rather than run with
	// an empty id, and neither would fail loudly if they were. The revoke's
	// WHERE would read `project_id = ''`, which matches nothing today and would
	// match every stray row the moment anything wrote one; the mint would store
	// a live credential belonging to no project, and a key that authenticates
	// into nothing is a key nobody can revoke from any screen.
	var liveKey string
	if project.ID != "" {
		// One statement rather than select-then-update-each: the window in which
		// two "Dashboard Session" keys are both live is the window in which a
		// revoked browser tab still works.
		if err := s.store.RevokeAPIKeysNamed(ctx, project.ID, authSessionKeyName, store.Now()); err != nil {
			authInternalCtx(w, r, "auth/session:revoke", err)
			return
		}

		liveKey, _, err = s.authMintKey(ctx, project.ID, userID, authSessionKeyName)
		if err != nil {
			authInternalCtx(w, r, "auth/session:mint", err)
			return
		}
	}

	// Timed, and logged only when it is slow enough to be the reason somebody
	// is looking at a spinner. A line per sign-in would be noise; a line when
	// the route takes longer than a person waits is the record that was missing
	// while this was being diagnosed from screenshots.
	if elapsed := time.Since(started); elapsed > authSessionSlow {
		// The subject is spelled out rather than interpolated as a bare id
		// because there may not be one: a line that trails off after "for
		// project" reads as a truncated log rather than as the state it is
		// reporting, and this line is only ever read by somebody already
		// looking for a reason.
		subject := "project " + project.ID
		if project.ID == "" {
			subject = "an account with no project"
		}
		log.Printf("[auth/session] took %s for %s", elapsed.Round(time.Millisecond), subject)
	}

	// A null project and a null api_key, not a 404 and not a 400: the sign-in
	// SUCCEEDED. The account exists, the session was verified, and the only
	// thing missing is a workspace the caller expressly asked not to be given.
	// Refusing here would put a person who has done nothing wrong in front of an
	// error page on the one screen that can fix it.
	//
	// Both fields keep the name and the type they have always had for every
	// caller that does get a project, so nothing on the wire has to learn a new
	// shape to go on working.
	var projectJSON any
	if project.ID != "" {
		projectJSON = map[string]any{
			"id":   project.ID,
			"name": project.Name,
			"slug": project.Slug,
		}
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{
		"api_key": authNullable(liveKey),
		"project": projectJSON,
	})
}

// authVerifiedLookup answers from the short cache, and sweeps it while it is
// holding the lock anyway.
func authVerifiedLookup(token string) (string, bool) {
	now := time.Now()
	authVerified.Lock()
	defer authVerified.Unlock()

	// Swept on read rather than on a timer: entries live thirty seconds, the map
	// is only touched on a sign-in, and a goroutine to remove a handful of
	// strings would be more machinery than the thing it maintains.
	if now.Sub(authVerified.pruned) > authVerifyTTL {
		for k, v := range authVerified.at {
			if now.After(v.until) {
				delete(authVerified.at, k)
			}
		}
		authVerified.pruned = now
	}

	e, ok := authVerified.at[token]
	if !ok || now.After(e.until) {
		return "", false
	}
	return e.email, true
}

// authVerifiedRemember records a token Supabase has just vouched for.
func authVerifiedRemember(token, email string) {
	if token == "" || email == "" {
		return
	}
	authVerified.Lock()
	defer authVerified.Unlock()
	authVerified.at[token] = authVerifiedEntry{email: email, until: time.Now().Add(authVerifyTTL)}
}

// The fixed names the two mints use. They are the WHERE clause of the revoke
// that precedes each mint, so a typo in either would leave the old key live.
//
// SIGN-IN and PAIRING are separate names because they are separate acts on
// separate schedules: /auth/session issues one when somebody signs in through
// their identity provider, and switching workspace re-issues the other. A single
// name would make each of them revoke the other's key, and the symptom is a
// machine that silently stops being able to call the API after somebody signs in
// on it again.
// authSessionSlow is when a sign-in is worth a log line. Two seconds is well
// past anything this route does when the database is healthy — four indexed
// statements — and well under the dashboard's own fifteen-second patience, so a
// line here means somebody waited and the next one may not get an answer.
const authSessionSlow = 2 * time.Second

const (
	authSessionKeyName = "Sign-in"
	// The name a paired machine's credential carries in the account's list.
	authCLIKeyName = "CLI (device pairing)"
)

// authSessionUser finds or creates the account for an address, and returns the
// stored display name with it.
//
// The name comes back because the device-approve flow writes it into the
// pairing row for the CLI to print, and fetching the row twice to get it would
// be a second round trip to Turso inside a login. An existing account with no
// name returns the empty string; the caller decides what to fall back to,
// because the two callers fall back differently.
func (s *server) authSessionUser(ctx context.Context, email, name string) (userID, userName string, err error) {
	u, err := s.store.UserByEmail(ctx, email)
	if err == nil {
		return u.ID, u.Name, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return "", "", err
	}

	if name == "" {
		name = authEmailLocal(email)
	}
	id := authNewID()
	if id == "" {
		return "", "", authErrNoID
	}
	now := store.Now()
	// No password hash: an account that arrives through Supabase signs in
	// through Supabase, and /v1/auth answers NO_PASSWORD for it rather than
	// pretending the password was wrong.
	if err := s.store.CreateUser(ctx, store.User{
		ID: id, Email: email, Name: name, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return "", "", err
	}
	return id, name, nil
}

// authSessionProject returns the user's newest project, creating one — with a
// policy — if they have none and the caller wants one made.
//
// The starter policy is written in the same request as the project, and that is
// the point of it: a project with no policy means an installed guard that
// permits everything while the person believes they are protected. The rate
// limit is seeded with its MODE for the same class of reason — a limit stored
// with the mode left at its default reads as "10 a minute" in the panel and
// enforces nothing.
//
// Both seeds are best-effort in the original. The policy is not treated that
// way here: if the policy insert fails the project would exist unprotected and
// nothing would ever retry, so the failure is returned and the caller sees a
// 500. The rate limit stays best-effort, because the policy is what protects.
//
// create is what a caller opts out of. It only ever suppresses CREATION: an
// account that already has a project gets it back whether or not the caller
// would have accepted a new one, because that is the project their existing
// keys, agents and audit rows are attached to.
func (s *server) authSessionProject(ctx context.Context, userID, requestedName string, create bool, wantID string) (store.ProjectSummary, error) {
	// THE ONE THE CALLER ASKED FOR, IF IT IS THEIRS.
	//
	// The owner check is the whole of the authorisation here: an id in a request
	// body is a wish, and this route is reached with a verified session, so the
	// question is not "is this id real" but "is this id yours". A project that
	// is not falls through to the account's own, which is the answer this route
	// gave before anybody could ask.
	if id := strings.TrimSpace(wantID); id != "" {
		asked, err := s.store.ProjectSummaryByID(ctx, id)
		switch {
		case err == nil && asked.OwnerID == userID:
			return asked, nil
		case err != nil && !errors.Is(err, store.ErrNotFound):
			return store.ProjectSummary{}, err
		}
	}

	existing, err := s.store.LatestProjectByOwner(ctx, userID)
	if err == nil {
		return existing, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return store.ProjectSummary{}, err
	}
	// The zero summary, and no error. Having never made a workspace is not a
	// failure and must not be reported as one: returning store.ErrNotFound here
	// would reach the caller as a 500 on the route the whole dashboard signs in
	// through, for the ordinary state of an account thirty seconds old.
	if !create {
		return store.ProjectSummary{}, nil
	}

	// Two ids: one names the project, the other's first eight characters are the
	// slug's uniqueness suffix. That is `crypto.randomUUID().slice(0, 8)` in the
	// original, and the suffix is what keeps a UNIQUE column from rejecting the
	// second person to call their project "My Project".
	projectID, slugSuffix := authNewID(), authNewID()
	if projectID == "" || slugSuffix == "" {
		return store.ProjectSummary{}, authErrNoID
	}
	name := requestedName
	if name == "" {
		name = "My Project"
	}
	slug := authSlugify(name) + "-" + slugSuffix[:8]

	tokenSecret, err := apiauth.GenerateTokenSecret()
	if err != nil {
		return store.ProjectSummary{}, err
	}

	now := store.Now()
	if err := s.store.CreateProject(ctx, store.Project{
		ID: projectID, OwnerID: userID, Name: name, Slug: slug,
		Description: "", TokenSecret: tokenSecret, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return store.ProjectSummary{}, err
	}

	if err := s.authSeedStarterPolicy(ctx, projectID, userID); err != nil {
		return store.ProjectSummary{}, err
	}

	if _, err := s.store.SetSecurityLayers(ctx, projectID, map[string]any{
		"rateLimit": map[string]any{"mode": "block", "perMinute": 10, "perHour": 0, "perDay": 0},
	}); err != nil {
		log.Printf("[API:auth/session] rate limit not seeded for a new project: %v", err)
	}

	return store.ProjectSummary{
		ID: projectID, OwnerID: userID, Name: name, Slug: slug,
		Description: "", CreatedAt: now, UpdatedAt: now,
	}, nil
}

// authMintKey creates a live key and returns the plaintext to its ONE caller,
// with the row id beside it.
//
// The plaintext exists in this process for as long as the response takes to
// write and is stored only as a SHA-256 hash. It is not logged here and must
// not be logged by a caller: the return value of this function is the only copy
// the service will ever have.
//
// The id is returned so a caller that decides not to hand the key out can
// revoke exactly the row it just wrote. Revoking by NAME instead would retire
// the key a concurrent request had just minted under the same fixed name, which
// is how an unlucky second browser tab logs the first one out.
func (s *server) authMintKey(ctx context.Context, projectID, userID, name string) (key, keyID string, err error) {
	key, err = apiauth.GenerateAPIKey(true)
	if err != nil {
		return "", "", err
	}
	keyID = authNewID()
	if keyID == "" {
		return "", "", authErrNoID
	}
	if err := s.store.CreateAPIKey(ctx, store.APIKey{
		ID:        keyID,
		ProjectID: projectID,
		KeyPrefix: key[:16],
		KeyHash:   apiauth.HashAPIKey(key),
		Name:      name,
		IsLive:    true,
		UserID:    userID,
		CreatedAt: store.Now(),
	}); err != nil {
		return "", "", err
	}
	return key, keyID, nil
}
