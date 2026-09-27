package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"unicode/utf16"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// POST /api/v1/setup — the port of src/app/api/v1/setup/route.ts.
//
// This is the most exposed endpoint in the service. There is no API key: the
// only thing between an anonymous request and a new user, a new project and two
// new API keys is a per-IP limit of five a minute, and that limit is keyed on a
// header the caller sets (see apiauth.ClientIP). So the validation below IS the
// endpoint's security, and every refusal in the live route is reproduced here
// rather than tidied:
//
//   - both fields must be present and TRUTHY, so `{"email":""}` is refused;
//   - the address must match the live regular expression;
//   - the project name must be 2..50 characters, measured as JavaScript
//     measures a string;
//   - the derived slug must be free, or the answer is 409.
//
// Nothing here is stricter than the original either, which is the other half of
// the same rule: a client that provisions successfully against the Node app has
// to keep provisioning successfully against this one.
//
// Two things it deliberately does NOT do, both because the live route does not.
// It does not lower-case the address — /v1/auth/session does, this does not, and
// making them agree here would create a second account for an address that
// already has one with different capitalisation. And it does not seed a starter
// policy, so a project created this way has no policy until something writes
// one; /v1/auth/session's provisioning path is the one that seeds.
//
// The two keys it returns are the only copies that will ever exist. They are
// returned once, stored as SHA-256 hashes, and never logged — not here, not
// truncated, not "just the prefix".

func init() {
	Register("POST /api/v1/setup", func(s *server) http.Handler {
		// withRateLimit(request) with no arguments: RATE_LIMITS.setup, five a
		// minute, and no bucket prefix — so this endpoint shares an IP's budget
		// with /v1/auth/session, exactly as the live app does.
		return authPublic(s, apiauth.LimitSetup, "", s.setup)
	})
}

const setupKeyWarning = "Store these API keys securely. They will not be shown again."

// setupResponse is the 201 body, in the original's key order.
type setupResponse struct {
	Project setupProject `json:"project"`
	APIKeys setupKeys    `json:"api_keys"`
	Warning string       `json:"_warning"`
}

type setupProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// setupKeys carries plaintext keys. It exists for exactly one response and
// nothing else in this process may hold it — in particular it must never reach
// a log line, which is why there is no String method and no struct tag anybody
// would be tempted to reuse for a debug print.
type setupKeys struct {
	Live string `json:"live"`
	Test string `json:"test"`
}

func (s *server) setup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// The live route parses inside its try, so a malformed body is a 500 there
	// and a 400 here — the difference apiauth.DecodeJSON explains. A body this
	// service cannot parse is the caller's error.
	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}

	email := setupValue(body["email"])
	projectName := setupValue(body["project_name"])

	// `if (!body.email || !body.project_name)` — one message for both, because
	// that is the string the onboarding page matches on.
	if !jsTruthy(email) || !jsTruthy(projectName) {
		apiauth.BadRequest(w, "Missing required fields: email, project_name")
		return
	}

	address := jsString(email)
	if !setupValidEmail(address) {
		apiauth.BadRequest(w, "Invalid email format")
		return
	}

	// A developer working under somebody else's policy cannot mint their way
	// out of it here.
	//
	// This route is UNAUTHENTICATED — it takes an address and hands back a
	// project and two live keys — so every refusal written into apiauth for a
	// guest is worth nothing if the same person can simply create a project
	// they own and point their machine at it. That is not a theoretical gap:
	// re-pairing is one command, and the guard reads whichever project its key
	// opens.
	//
	// `body.project_name.length` — UTF-16 code units, and an ARRAY has a length
	// too, so `["ab","cd","ef"]` passes this check in the live route and throws
	// on the next line. Both branches are reproduced below rather than collapsed,
	// because the one thing that must not happen is a non-string project name
	// reaching the insert.
	if n, measurable := setupLength(projectName); measurable && (n < 2 || n > 50) {
		apiauth.BadRequest(w, "Project name must be 2-50 characters")
		return
	}
	name, isString := projectName.(string)
	if !isString {
		// `.toLowerCase()` on a non-string is a TypeError, which the live route's
		// catch renders as handleApiError's 500. The value is not echoed and not
		// logged; the caller sent it and the log does not need it.
		apiauth.Internal(w, "api", errors.New("project_name is not a string"))
		return
	}

	// The slug is the name reduced to [a-z0-9-] plus eight hex characters, and
	// the suffix is what keeps `projects.slug` — a UNIQUE column — from rejecting
	// the second person to call their project "My Project".
	suffix := authNewID()
	projectID := authNewID()
	if suffix == "" || projectID == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}
	slug := authSlugify(name) + "-" + suffix[:8]

	// Checked before the insert so a collision is a 409 rather than a constraint
	// violation rendered as a 500. It is not a lock: two requests can pass this
	// and the second's INSERT still fails, which the live route has the same way
	// round. The eight random characters are what make that vanishingly rare.
	taken, err := s.store.ProjectSlugTaken(ctx, slug)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if taken {
		apiauth.Error(w, http.StatusConflict, "ERROR", "Project with this name already exists")
		return
	}

	userID, err := s.setupUser(ctx, address, body["name"])
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	tokenSecret, err := apiauth.GenerateTokenSecret()
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	now := store.Now()
	if err := s.store.CreateProject(ctx, store.Project{
		ID:      projectID,
		OwnerID: userID,
		Name:    name,
		Slug:    slug,
		// `body.description || ''` — the same falsy fallback as the name.
		Description: setupTruthyString(setupValue(body["description"])),
		TokenSecret: tokenSecret,
		CreatedAt:   now,
		UpdatedAt:   now,
	}); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// The keys are minted after the project exists, so a failure here leaves a
	// project with no key rather than keys pointing at a row that is not there.
	// The live route writes both in one statement and this cannot; the order is
	// what makes the difference recoverable — the caller retries setup and gets a
	// new project, and the abandoned one has no credential that can reach it.
	liveKey, err := s.setupKey(ctx, projectID, userID, true, "Default Live Key")
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	testKey, err := s.setupKey(ctx, projectID, userID, false, "Default Test Key")
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusCreated, setupResponse{
		Project: setupProject{ID: projectID, Name: name, Slug: slug},
		APIKeys: setupKeys{Live: liveKey, Test: testKey},
		Warning: setupKeyWarning,
	})
}

// setupUser finds the account for an address or creates one.
//
// The address is matched EXACTLY, as the live route matches it. The display name
// is `body.name || body.email.split('@')[0]`.
func (s *server) setupUser(ctx context.Context, address string, rawName json.RawMessage) (string, error) {
	u, err := s.store.UserByEmail(ctx, address)
	if err == nil {
		// An existing account is reused and NOT modified. That is the live
		// behaviour and it is also the only safe one: this endpoint is
		// unauthenticated, so a request naming somebody else's address must not
		// be able to change their profile — only to add a project to it, which is
		// the endpoint's whole purpose.
		return u.ID, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return "", err
	}

	// `||`, so a FALSY name — absent, "", 0, false — falls back to the local part
	// of the address. Stringifying first would store the four characters "false"
	// as somebody's display name.
	name := setupTruthyString(setupValue(rawName))
	if name == "" {
		name = authEmailLocal(address)
	}
	id := authNewID()
	if id == "" {
		return "", authErrNoID
	}
	now := store.Now()
	// No password hash: an account created here signs in through the dashboard's
	// Supabase flow, and /v1/auth answers NO_PASSWORD for it rather than
	// pretending the password was wrong.
	if err := s.store.CreateUser(ctx, store.User{
		ID: id, Email: address, Name: name, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return "", err
	}
	return id, nil
}

// setupKey mints one of the two default keys and returns the plaintext.
//
// The return value is the only copy this service will ever have: the row stores
// a SHA-256 hash and the first sixteen characters, and there is no query
// anywhere in this package that can read a key back. Nothing between here and
// the response body may log it.
func (s *server) setupKey(ctx context.Context, projectID, userID string, isLive bool, name string) (string, error) {
	key, err := apiauth.GenerateAPIKey(isLive)
	if err != nil {
		return "", err
	}
	id := authNewID()
	if id == "" {
		return "", authErrNoID
	}
	if err := s.store.CreateAPIKey(ctx, store.APIKey{
		ID:        id,
		ProjectID: projectID,
		KeyPrefix: key[:16],
		KeyHash:   apiauth.HashAPIKey(key),
		Name:      name,
		IsLive:    isLive,
		UserID:    userID,
		CreatedAt: store.Now(),
	}); err != nil {
		return "", err
	}
	return key, nil
}

// setupValue decodes one field of the body into the untyped value the live route
// reads. Absent and unparseable are both nil, which is falsy — the same answer
// `body.missing` gives.
func setupValue(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	return v
}

// setupTruthyString is `x || ”`: the value's string form when it is truthy, and
// the empty string otherwise. It is the pair of coercions the live route applies
// to `name` and `description`, in that order — the truthiness test comes first,
// so `false` never becomes the text "false".
func setupTruthyString(v any) string {
	if !jsTruthy(v) {
		return ""
	}
	return jsString(v)
}

// setupLength is JavaScript's `.length` for the values that have one.
//
// A string measures in UTF-16 code units, which is not the same as Go's byte
// length or its rune count: an emoji is two, a CJK character is one, and a
// fifty-character limit measured in bytes would refuse names the live route
// accepts. An array has a length too. Everything else has none, and in
// JavaScript `undefined < 2` and `undefined > 50` are BOTH false — so the check
// passes and the next line throws, which is why this reports measurability
// rather than defaulting to zero.
func setupLength(v any) (int, bool) {
	switch t := v.(type) {
	case string:
		return len(utf16.Encode([]rune(t))), true
	case []any:
		return len(t), true
	}
	return 0, false
}

// setupValidEmail is the live route's `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`.
//
// authEmailRE is that expression, and it is reused rather than copied so the two
// unauthenticated routes cannot drift apart on what an address is. The extra
// whitespace scan is not redundant with it: Go's `\s` is five ASCII characters
// while JavaScript's also covers U+00A0, the Unicode space separators and
// U+FEFF, so without this an address containing a non-breaking space would be
// accepted here and refused by the live app. On an endpoint that provisions
// without a credential, being MORE permissive than the original is the failure
// mode that matters.
func setupValidEmail(address string) bool {
	if !authEmailRE.MatchString(address) {
		return false
	}
	return strings.IndexFunc(address, isJSSpace) < 0
}

// isJSSpace is the character class JavaScript's `\s` matches, which Go's does
// not: the ASCII five, then the separators the specification adds.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}
