package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/policyjson"
	"github.com/codeyevsky/solongate/api/internal/store"
	"github.com/google/uuid"
)

// The capability-token routes: POST /v1/tokens, POST /v1/tokens/verify and
// POST /v1/validate.
//
// They are the port of src/app/api/v1/tokens/route.ts, tokens/verify/route.ts
// and validate/route.ts, together with the four functions in src/lib/security.ts
// they stand on: generateCapabilityToken, verifyCapabilityToken,
// getProjectPolicy and evaluatePolicy.
//
// A capability token is a thirty-second, single-use HS256 JWT that says one tool
// call was allowed. The MCP proxy asks /validate, gets a decision and a token,
// and the token is what proves downstream that the call came through the policy
// engine rather than around it. Everything that makes it worth anything is in
// this file: the signing, the replay table, and the evaluation that decides
// whether a token is minted at all.
//
// THE TOKEN FORMAT IS A WIRE CONTRACT WITH A SERVICE THAT IS STILL RUNNING.
//
// During the cutover some requests reach the Node app and some reach this
// binary, and a proxy does not know which minted the token it is carrying. So a
// token minted there has to verify here and a token minted here has to verify
// there. That is why the format below is written out by hand rather than handed
// to a JWT library with its own opinions:
//
//   - The protected header is exactly `{"alg":"HS256"}`. jose's
//     setProtectedHeader writes the object it is given and nothing else, so
//     there is no `typ` and no `kid` — one extra header member changes the
//     signing input and every signature with it.
//   - The claims are tool, scope, nonce, projectId, iat, exp, iss IN THAT
//     ORDER. jose builds them by spreading the constructor's payload and then
//     appending iat, exp and iss in the order setIssuedAt / setExpirationTime /
//     setIssuer are called. Order does not change whether a signature verifies
//     — both sides sign the bytes they were given — but it does decide whether
//     two implementations produce the same token for the same input, which is
//     the only way this file can be tested against the original.
//   - The signature is HMAC-SHA256 over `header.payload`, base64url with no
//     padding. Not the double-encoded form packages/proxy-go's TokenIssuer
//     uses: that is the proxy's OWN token, a different format for a different
//     purpose, and confusing the two would produce tokens neither service
//     accepts.
//
// The secret is the PROJECT's token_secret, which arrives on KeyInfo. It is
// never logged, never returned and never compared with anything but hmac.Equal.

const (
	// capabilityTTL is TOKEN_TTL_SECONDS. Thirty seconds is short enough that a
	// stolen token is worth almost nothing and long enough for a tool call to
	// travel; it is also why the replay table can be purged so aggressively.
	capabilityTTL = 30 * time.Second

	// capabilityIssuer is the `iss` claim, checked on the way back in. A token
	// signed with the same secret for another purpose is refused by it.
	capabilityIssuer = "solongate"

	capabilityAlg = "HS256"
)

// capabilityHeader is the one protected header this service issues, encoded
// once. See the file note for why it has no `typ`.
var capabilityHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"` + capabilityAlg + `"}`))

// capabilityClaims is the payload, in jose's key order.
//
// Tool and Scope are `any` because the live route casts rather than validates —
// `body.tool as string` — so a caller that sends a number gets a token with a
// number in it. Reproducing that is not indulgence: the claim comes back out
// through /tokens/verify, and a port that silently stringified it would answer
// with a different value than the token carries.
type capabilityClaims struct {
	Tool      any    `json:"tool"`
	Scope     any    `json:"scope"`
	Nonce     string `json:"nonce"`
	ProjectID string `json:"projectId"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
	Issuer    string `json:"iss"`
}

// mintedCapability is generateCapabilityToken's return: the token, when it
// dies, and the nonce that will be spent when it is presented.
type mintedCapability struct {
	token     string
	expiresAt int64
	nonce     string
}

// mintCapabilityToken is src/lib/security.ts's generateCapabilityToken.
//
// The nonce is a v4 UUID from the system CSPRNG. It is the single-use half of
// the token: a predictable nonce would let somebody pre-spend a token they have
// not seen, which turns the replay table from a defence into a denial of
// service against the legitimate holder.
func mintCapabilityToken(projectID string, tool, scope any, secret string) (mintedCapability, error) {
	now := time.Now().Unix()
	claims := capabilityClaims{
		Tool:      tool,
		Scope:     scope,
		Nonce:     uuid.NewString(),
		ProjectID: projectID,
		IssuedAt:  now,
		ExpiresAt: now + int64(capabilityTTL.Seconds()),
		Issuer:    capabilityIssuer,
	}
	token, err := encodeCapability(claims, secret)
	if err != nil {
		return mintedCapability{}, err
	}
	return mintedCapability{token: token, expiresAt: claims.ExpiresAt, nonce: claims.Nonce}, nil
}

// encodeCapability is the signing itself, separated from the clock and the
// randomness so a test can pin the exact bytes against a token minted by jose.
func encodeCapability(claims capabilityClaims, secret string) (string, error) {
	// marshalNoEscape rather than json.Marshal: Go rewrites < > & as \u00xx and
	// JSON.stringify does not. Both decode to the same claim, so this is not a
	// correctness bug waiting to happen — it is the difference between a token
	// this file produces and the byte-identical one the live service produces
	// for the same input, which is what the golden test compares.
	body, err := marshalNoEscape(claims)
	if err != nil {
		return "", err
	}
	signingInput := capabilityHeader + "." + base64.RawURLEncoding.EncodeToString(body)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(capabilitySignature(signingInput, secret)), nil
}

// capabilitySignature is HMAC-SHA256 over the signing input with the project's
// secret as the key.
//
// jose encodes the secret with a TextEncoder, which is UTF-8 — the same bytes
// Go sees for the same string. A project's token_secret is 32 random bytes as
// hex, so it is ASCII by construction and the two cannot diverge; this is
// written down because the repository has already paid once for assuming that
// about a different string.
func capabilitySignature(signingInput, secret string) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

// ── verification ────────────────────────────────────────────────────────────

// capabilityCheck is verifyCapabilityToken's answer.
//
// failure is the message the route puts on the wire, already spelled the way
// the live app spells it — the route does not translate, so there is one place
// where these strings are decided.
type capabilityCheck struct {
	valid   bool
	failure string
	payload *policyjson.Object
}

func capabilityRefused(failure string) capabilityCheck {
	return capabilityCheck{failure: failure}
}

// capabilityInvalid is the live route's `Invalid token: ${message}` wrapper
// around whatever jose threw.
func capabilityInvalid(joseMessage string) capabilityCheck {
	return capabilityRefused("Invalid token: " + joseMessage)
}

// verifyCapabilityToken is src/lib/security.ts's verifyCapabilityToken, in its
// order: signature, then claims, then project, then replay.
//
// The error return is for DATABASE failures only, and it is a deliberate
// difference from the original. There, the nonce SELECT and INSERT are inside
// the same try as the JWT check, so a Turso outage comes back as
// `{valid:false, error:"Invalid token: <driver message>"}` — a 200 that says
// the caller's token is bad when it is not, with a database error quoted into
// the body. Here a database failure is a 500 with the detail in the log, which
// fails closed without telling a caller anything about the database.
func verifyCapabilityToken(ctx context.Context, st *store.Store, token, secret, projectID string) (capabilityCheck, error) {
	// jose's compactVerify splits on '.' and demands exactly three segments.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return capabilityInvalid("Invalid Compact JWS"), nil
	}

	header, ok := capabilityDecodeJSON(parts[0])
	if !ok {
		return capabilityInvalid("JWS Protected Header is invalid"), nil
	}
	alg, isString := header.Get("alg").(string)
	if !isString || alg == "" {
		return capabilityInvalid(`JWS "alg" (Algorithm) Header Parameter missing or invalid`), nil
	}
	if alg != capabilityAlg {
		// jose, given a symmetric key and no `algorithms` option, would also
		// accept HS384 and HS512. Only HS256 is ever minted — by this file or by
		// the live one — so refusing the other two costs nothing and removes the
		// whole family of algorithm-confusion tricks from a route that gates
		// access. This is the one place this port is STRICTER than the original,
		// and the direction is the safe one: it can refuse a token the live app
		// would have taken, never take one the live app would have refused.
		return capabilityInvalid(`unexpected "alg" (Algorithm) Header Parameter value`), nil
	}
	if header.Has("crit") {
		// jose refuses a `crit` header unless the caller declared which
		// extensions it understands, and this caller declares none. Refusing it
		// here keeps that true rather than quietly ignoring a member the token
		// says must not be ignored.
		return capabilityInvalid("Extension Header Parameter is not recognized"), nil
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return capabilityInvalid("Failed to base64url decode the signature"), nil
	}

	// CONSTANT TIME. hmac.Equal, never bytes.Equal and never ==. A comparison
	// that stops at the first wrong byte tells an attacker how much of a forged
	// signature was right, and a forged signature here is a tool call that
	// claims the policy engine allowed it.
	if !hmac.Equal(capabilitySignature(parts[0]+"."+parts[1], secret), signature) {
		return capabilityInvalid("signature verification failed"), nil
	}

	payload, ok := capabilityDecodeJSON(parts[1])
	if !ok {
		return capabilityInvalid("JWT Claims Set must be a top-level JSON object"), nil
	}

	// The claim checks, in jose's order and with jose's messages. `iss` is
	// checked for PRESENCE first because jwtVerify was given an issuer option,
	// which adds it to the required-claims list.
	if !payload.Has("iss") {
		return capabilityInvalid(`missing required "iss" claim`), nil
	}
	if iss, _ := payload.Get("iss").(string); iss != capabilityIssuer {
		return capabilityInvalid(`unexpected "iss" claim value`), nil
	}
	if payload.Has("iat") {
		if _, isNumber := payload.Get("iat").(float64); !isNumber {
			return capabilityInvalid(`"iat" claim must be a number`), nil
		}
	}
	now := float64(time.Now().Unix())
	if payload.Has("nbf") {
		nbf, isNumber := payload.Get("nbf").(float64)
		if !isNumber {
			return capabilityInvalid(`"nbf" claim must be a number`), nil
		}
		if nbf > now {
			return capabilityInvalid(`"nbf" claim timestamp check failed`), nil
		}
	}
	if payload.Has("exp") {
		exp, isNumber := payload.Get("exp").(float64)
		if !isNumber {
			return capabilityInvalid(`"exp" claim must be a number`), nil
		}
		if exp <= now {
			// The one failure the live route renames: jose throws JWTExpired and
			// the catch answers "Token expired" rather than "Invalid token: ...".
			return capabilityRefused("Token expired"), nil
		}
	}

	// PROJECT SCOPE. A token is only valid for the project whose secret signed
	// it, and the project id comes from the API key, never from the request. A
	// token minted for another tenant that somehow verified would be a
	// cross-tenant capability, which is the worst thing this endpoint could
	// hand out.
	if claimed, _ := payload.Get("projectId").(string); claimed != projectID {
		return capabilityRefused("Project ID mismatch"), nil
	}

	nonce := jsString(payload.Get("nonce"))
	if !jsTruthy(payload.Get("nonce")) || nonce == "" {
		return capabilityRefused("Missing nonce"), nil
	}

	// SINGLE USE. store.SpendNonce inserts and reports whether the row was new,
	// so two presentations of one token that arrive together cannot both find
	// no row and both succeed — which is exactly what the live app's
	// SELECT-then-INSERT allows.
	fresh, err := st.SpendNonce(ctx, nonce, projectID)
	if err != nil {
		return capabilityCheck{}, err
	}
	if !fresh {
		return capabilityRefused("Token already used (replay detected)"), nil
	}

	return capabilityCheck{valid: true, payload: payload}, nil
}

// capabilityDecodeJSON is one base64url segment as a JSON object.
//
// Go's RawURLEncoding is strict where node's Buffer.from(s, 'base64url') is
// lenient about padding and stray characters. The difference only decides WHICH
// error a malformed token gets, never whether it is accepted.
func capabilityDecodeJSON(segment string) (*policyjson.Object, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return nil, false
	}
	return policyjson.ParseObject(raw)
}

// ── the nonce table's housekeeping ──────────────────────────────────────────

var capabilityPurgeOnce sync.Once

// startNoncePurge is src/lib/security.ts's ensureNonceCleanup: a minute timer
// that deletes nonces older than twice a token's life.
//
// Without it used_nonces grows by one row per verified token forever. Twice the
// TTL is the safe cutoff — a token whose nonce is that old cannot pass the exp
// check, so forgetting it cannot enable a replay.
//
// Started once per process, from the route builder, because that is the moment
// this file knows there is a server to purge for. The goroutine has no shutdown
// path, which matches the setInterval it replaces: the work is a DELETE with a
// timeout and the process exiting is what stops it.
func startNoncePurge(s *server) {
	capabilityPurgeOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for range ticker.C {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				if _, err := s.store.PurgeNonces(ctx, store.Now()-2*int64(capabilityTTL.Seconds())); err != nil {
					// Best-effort, as the original's empty catch. A failed purge
					// leaves rows behind; it never refuses a token.
					log.Printf("[API:tokens] nonce cleanup failed: %v", err)
				}
				cancel()
			}
		}()
	})
}

// ── POST /api/v1/tokens ─────────────────────────────────────────────────────

// tokensCreateResponse is the live route's object literal, in its order.
type tokensCreateResponse struct {
	Token     string `json:"token"`
	Tool      any    `json:"tool"`
	Scope     any    `json:"scope"`
	ExpiresAt string `json:"expires_at"`
	Nonce     string `json:"nonce"`
}

// tokensCreate mints a token for a tool the caller names.
//
// It evaluates NO policy. That is the live behaviour and it is worth being
// explicit about: this endpoint is for a service that has already made its own
// decision and wants a token to carry, which is why /validate exists separately
// and why the proxy uses that one. Anyone holding the project's API key can
// mint a token for any tool here.
func (s *server) tokensCreate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body, ok := capabilityReadBody(w, r)
	if !ok {
		return
	}

	tool := body.Get("tool")
	if !jsTruthy(tool) {
		// The default code, "ERROR", not VALIDATION_ERROR. /validate uses the
		// other one; these two routes genuinely differ and a deployed client
		// branching on the code would see the change.
		apiauth.BadRequest(w, "Missing required field: tool")
		return
	}

	// `body.scope || \`EXECUTE:${tool}\`` — a falsy scope, including an empty
	// string, falls back rather than being sent through as given.
	scope := body.Get("scope")
	if !jsTruthy(scope) {
		scope = "EXECUTE:" + capabilityTemplate(tool, false)
	}

	minted, err := mintCapabilityToken(key.ProjectID, tool, scope, key.TokenSecret)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusOK, tokensCreateResponse{
		Token:     minted.token,
		Tool:      tool,
		Scope:     scope,
		ExpiresAt: store.ISO(minted.expiresAt),
		Nonce:     minted.nonce,
	})
}

// ── POST /api/v1/tokens/verify ──────────────────────────────────────────────

// tokensVerifyResponse is both answers. The three claim fields are omitted when
// absent, which is what JSON.stringify does with `result.payload?.tool` on a
// payload that has no tool.
type tokensVerifyResponse struct {
	Valid bool   `json:"valid"`
	Error string `json:"error,omitempty"`
	Tool  any    `json:"tool,omitempty"`
	Scope any    `json:"scope,omitempty"`
	Nonce any    `json:"nonce,omitempty"`
}

// tokensVerify checks a token and SPENDS it.
//
// A caller that verifies a token has consumed it: the second call gets
// "Token already used (replay detected)". That is the point of the endpoint and
// it is why a refusal is a 200 rather than a 4xx — the question "is this token
// good" was answered successfully, and the answer is no.
func (s *server) tokensVerify(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body, ok := capabilityReadBody(w, r)
	if !ok {
		return
	}

	presented := body.Get("token")
	if !jsTruthy(presented) {
		apiauth.BadRequest(w, "Missing required field: token")
		return
	}
	token, isString := presented.(string)
	if !isString {
		// jose refuses a non-string before it looks at anything, and the route
		// turns that into a 200 with valid:false like any other bad token.
		apiauth.JSON(w, http.StatusOK, tokensVerifyResponse{
			Error: "Invalid token: Compact JWS must be a string or Uint8Array",
		})
		return
	}

	// The secret and the project id both come from the KEY. Nothing in the body
	// chooses which project a token is checked against.
	result, err := verifyCapabilityToken(r.Context(), s.store, token, key.TokenSecret, key.ProjectID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !result.valid {
		apiauth.JSON(w, http.StatusOK, tokensVerifyResponse{Error: result.failure})
		return
	}

	apiauth.JSON(w, http.StatusOK, tokensVerifyResponse{
		Valid: true,
		Tool:  result.payload.Get("tool"),
		Scope: result.payload.Get("scope"),
		Nonce: result.payload.Get("nonce"),
	})
}

// ── POST /api/v1/validate ───────────────────────────────────────────────────
//
// The endpoint the proxy calls before every tool call: it evaluates the
// project's policy and, on ALLOW, mints the token for that one call.
//
// Everything in it is ordered the way the original orders it, because the order
// is observable. The audit row is written whatever the decision is and BEFORE
// the response, so a caller that got a decision knows it was recorded. The
// webhook is fired after, and only on DENY, and never waited for.

// validateDecision is the evaluated verdict. Effect is `any` because it is the
// rule's own effect field verbatim — the live code never checks that it says
// ALLOW or DENY, it just compares it — and MatchedRule is the rule OBJECT as it
// was stored, key order and all, because the dashboard renders it.
type validateDecision struct {
	effect        any
	matchedRule   json.RawMessage
	matchedRuleID string
	reason        string
	evaluatedAt   string
}

type validateResponse struct {
	Allowed  bool                 `json:"allowed"`
	Decision validateDecisionBody `json:"decision"`
	// RequestID is what ties this answer to the audit row and to the line in
	// somebody's local log.
	RequestID string `json:"request_id"`
	// Token and TokenExpiresAt appear together or not at all, which is what the
	// original's `...(token && {…})` spread produces.
	Token          string `json:"token,omitempty"`
	TokenExpiresAt *int64 `json:"token_expires_at,omitempty"`
}

type validateDecisionBody struct {
	Effect any `json:"effect"`
	// MatchedRule is a raw message so a nil renders as JSON null, which is what
	// the dashboard distinguishes from a rule id.
	MatchedRule json.RawMessage `json:"matched_rule"`
	Reason      string          `json:"reason"`
	EvaluatedAt string          `json:"evaluated_at"`
}

// validateTrustLevels is the live route's trustLevelMap, all nine keys.
var validateTrustLevels = map[string]string{
	"low": "UNTRUSTED", "untrusted": "UNTRUSTED", "UNTRUSTED": "UNTRUSTED",
	"medium": "VERIFIED", "verified": "VERIFIED", "VERIFIED": "VERIFIED",
	"high": "TRUSTED", "trusted": "TRUSTED", "TRUSTED": "TRUSTED",
}

// validateTrustUnrecognised stands for a lookup that found something on
// Object.prototype instead of a trust level.
//
// `trustLevelMap[raw] || 'VERIFIED'` in JavaScript searches the prototype
// chain, so trust_level: "toString" returns a FUNCTION — truthy, so the
// fallback does not fire — and every rule with a real minimumTrustLevel then
// fails meetsTrustLevel and the call is denied by default. Mapping those names
// to VERIFIED here would allow a call the live service refuses, which is the
// one direction this port must never take. The sentinel is not a valid trust
// level, so it behaves exactly as that function does.
const validateTrustUnrecognised = "\x00unrecognised"

// validateObjectPrototype is what an object literal inherits. Nothing else on
// Object.prototype is enumerable-or-not relevant here: these are the names a
// lookup can find.
var validateObjectPrototype = map[string]bool{
	"constructor": true, "hasOwnProperty": true, "isPrototypeOf": true,
	"propertyIsEnumerable": true, "toLocaleString": true, "toString": true,
	"valueOf": true, "__defineGetter__": true, "__defineSetter__": true,
	"__lookupGetter__": true, "__lookupSetter__": true, "__proto__": true,
}

// validateTrustOrder is meetsTrustLevel's array. An unknown level is -1, which
// is why a rule with a misspelled minimumTrustLevel matches EVERY caller: -1 is
// below all three, and `indexOf(current) >= -1` is always true.
var validateTrustOrder = []string{"UNTRUSTED", "VERIFIED", "TRUSTED"}

func validateTrustIndex(level string) int {
	for i, l := range validateTrustOrder {
		if l == level {
			return i
		}
	}
	return -1
}

func (s *server) validateCall(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	// Both are taken before the body is read, as the original takes them: the
	// evaluation time it reports includes parsing, and the request id is
	// generated even for a request that turns out to be malformed.
	requestID := uuid.NewString()
	start := time.Now()

	body, ok := capabilityReadBody(w, r)
	if !ok {
		return
	}

	rawTool := body.Get("tool")
	if !jsTruthy(rawTool) {
		// VALIDATION_ERROR here, unlike /tokens. The dashboard branches on it.
		apiauth.ValidationError(w, "Missing required field: tool")
		return
	}
	tool, isString := rawTool.(string)
	if !isString {
		// `body.tool as string` is a cast, not a conversion, so the live route
		// carries a number all the way to `tool.includes(...)` or
		// `tool.startsWith(...)` and throws a TypeError into its own catch —
		// a 500. The one shape that does not throw is a policy whose every
		// matching rule uses the bare `*` pattern, and minting a token for a
		// tool nobody can name is not the branch to be generous on.
		apiauth.Internal(w, "api", errors.New("tool is not a string"))
		return
	}

	// `body.arguments || body.args || {}` — hashed, never stored and never
	// logged. The hash is what lets two calls with identical arguments be
	// recognised as the same call without keeping the arguments themselves,
	// which is the whole reason this column is a hash.
	args := body.Get("arguments")
	if !jsTruthy(args) {
		args = body.Get("args")
	}
	if !jsTruthy(args) {
		args = policyjson.NewObject()
	}

	// `body.context?.permission` and `body.context?.trust_level`. A context that
	// is not an object reads as absent, exactly as optional chaining does.
	reqContext, _ := body.Get("context").(*policyjson.Object)

	rawTrust := body.Get("trust_level")
	if v := reqContext.Get("trust_level"); jsTruthy(v) {
		rawTrust = v
	}
	trustLevel := validateTrustLevel(rawTrust)

	// `body.include_token !== false` — a STRICT comparison, so include_token:
	// "false" or 0 still means yes.
	includeToken := true
	if b, isBool := body.Get("include_token").(bool); isBool && !b {
		includeToken = false
	}

	// The permission, and then the inference that only runs when the caller
	// named neither. The substring tests are the original's, in its order:
	// read/get/list/search/fetch/query before write/create/update/delete, so a
	// tool called "update_or_get" is a READ.
	var permission any = "EXECUTE"
	ctxPermission := reqContext.Get("permission")
	bodyPermission := body.Get("permission")
	switch {
	case jsTruthy(ctxPermission):
		permission = ctxPermission
	case jsTruthy(bodyPermission):
		permission = bodyPermission
	default:
		switch {
		case containsAny(tool, "read", "get", "list", "search", "fetch", "query"):
			permission = "READ"
		case containsAny(tool, "write", "create", "update", "delete"):
			permission = "WRITE"
		}
	}

	ctx := r.Context()

	rules, err := s.validatePolicyRules(ctx, key.ProjectID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	decision, err := validateEvaluatePolicy(tool, permission, trustLevel, rules)
	if err != nil {
		// A rule the live evaluator would have thrown on. See
		// validateEvaluatePolicy: the alternative is skipping the broken rule,
		// and a skipped DENY rule is an allowed call.
		apiauth.Internal(w, "api", err)
		return
	}

	evaluationMs := float64(time.Since(start)) / float64(time.Millisecond)

	response := validateResponse{
		Allowed: decision.effect == "ALLOW",
		Decision: validateDecisionBody{
			Effect:      decision.effect,
			MatchedRule: decision.matchedRule,
			Reason:      decision.reason,
			EvaluatedAt: decision.evaluatedAt,
		},
		RequestID: requestID,
	}

	if response.Allowed && includeToken {
		scope := capabilityTemplate(permission, false) + ":" + tool
		minted, err := mintCapabilityToken(key.ProjectID, tool, scope, key.TokenSecret)
		if err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		response.Token = minted.token
		expires := minted.expiresAt
		response.TokenExpiresAt = &expires
	}

	entry := store.AuditLog{
		ID:               uuid.NewString(),
		ProjectID:        key.ProjectID,
		RequestID:        requestID,
		ToolName:         tool,
		Permission:       jsString(permission),
		TrustLevel:       validateTrustLabel(trustLevel),
		Decision:         jsString(decision.effect),
		MatchedRuleID:    decision.matchedRuleID,
		Reason:           decision.reason,
		EvaluationTimeMs: &evaluationMs,
		ArgumentsHash:    validateArgumentsHash(args),
		CreatedAt:        store.Now(),
	}
	if err := s.store.InsertAuditLog(ctx, entry); err != nil {
		// Swallowed and logged, as the original's logAudit catch. A decision
		// that was made must be returned: failing the request because the
		// history could not be written would turn a logging outage into a
		// blocked fleet, and the guard treats a failed /validate as a reason to
		// stop working.
		log.Printf("[API:validate] failed to log audit: %v", err)
	}

	if decision.effect == "DENY" {
		// The shared denialEvent carries an `agent` member the live /validate
		// payload does not, because this route knows no agent. It is two nulls
		// next to fields a consumer routes on, and one event shape for the whole
		// service is worth more than dropping them.
		event := denialEvent{
			Event:            "denial",
			Timestamp:        store.ISOms(time.Now().UnixMilli()),
			RequestID:        requestID,
			ProjectID:        key.ProjectID,
			Decision:         jsString(decision.effect),
			DenyLayer:        classifyDenyLayer(decision.reason),
			Tool:             tool,
			Permission:       jsString(permission),
			MatchedRuleID:    nullable(decision.matchedRuleID),
			Reason:           nullable(decision.reason),
			EvaluationTimeMs: &evaluationMs,
		}
		s.notifyDenial(context.WithoutCancel(ctx), key.ProjectID, event)
	}

	apiauth.JSON(w, http.StatusOK, response)
}

// notifyDenial delivers the denial webhook off the request path.
//
// The live route fires `emitWebhookEvent(...)` without awaiting it, and this
// keeps that promise while adding the ceiling audit_notify.go's comment
// explains: a goroutine per call, on the endpoint a proxy hits before EVERY
// tool call, is how one customer's black-holed webhook becomes everyone's
// outage. The same semaphore and the same budget are used, so /validate and the
// audit route share one ceiling rather than each having their own.
//
// It is deliberately NOT notifyAudit: that also evaluates denial alerts, and
// the live /validate does not. Firing alerts from here would double-count every
// denial that the audit hook also reports.
//
// ctx must already be detached from the request's — the request's is cancelled
// the moment the handler returns, which is before any delivery has sent
// anything.
func (s *server) notifyDenial(ctx context.Context, projectID string, ev denialEvent) {
	select {
	case notifySlots <- struct{}{}:
	default:
		// Dropped rather than queued, as notifyAudit drops: the next denial
		// fires the webhook, and a queue here would only hide the pile-up.
		log.Print("[API:validate] denial webhook skipped: too many in flight")
		return
	}
	go func() {
		defer func() { <-notifySlots }()
		ctx, cancel := context.WithTimeout(ctx, notifyBudget)
		defer cancel()
		s.emitWebhookEvent(ctx, projectID, ev)
	}()
}

// validatePolicyRules is src/lib/security.ts's getProjectPolicy: the newest
// policy version in the PROJECT, or the built-in default-deny document.
//
// The five-second per-project cache the original keeps is not reproduced. It
// exists there to spare Turso on the proxy's hot path, and reproducing it here
// would mean a policy saved through one route staying invisible to this one for
// five seconds with no invalidation hook between the two files. Fresher is the
// safe direction: it can only refuse a call the cache would have allowed.
func (s *server) validatePolicyRules(ctx context.Context, projectID string) ([]any, error) {
	row, err := s.store.LatestPolicyVersion(ctx, projectID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			// createDefaultDenyPolicy. The document lives in policies.go as a
			// single constant so that GET /policies/default and this evaluation
			// cannot drift apart; a second copy here would be a second answer to
			// "what does a project with no policy enforce".
			policy, ok := policyjson.ParseObject([]byte(policyDefaultDenyPolicy))
			if !ok {
				return nil, errors.New("default deny policy is not valid JSON")
			}
			rules, _ := policyjson.Array(policy.Get("rules"))
			return rules, nil
		}
		return nil, err
	}

	policy, ok := policyjson.ParseObject(row.PolicyData)
	if !ok {
		return nil, errors.New("stored policy is not a JSON object")
	}
	rules, isArray := policyjson.Array(policy.Get("rules"))
	if !isArray {
		// `[...policySet.rules]` on a policy with no rules array throws, which
		// the route answers with a 500. A stored document this broken should be
		// looked at, not quietly treated as an empty rule set — an empty rule
		// set is a default DENY, which reads as a policy working.
		return nil, errors.New("stored policy has no rules array")
	}
	return rules, nil
}

// validateEvaluatePolicy is src/lib/security.ts's evaluatePolicy.
//
// Four checks in one order — enabled, tool pattern, permission, trust — and the
// FIRST rule that passes all four decides, whatever its effect. Rules are sorted
// by ascending priority first, so priority 10 beats priority 10000; that is why
// the default-deny document can carry both ALLOW and DENY rules for the same
// pattern.
//
// Three JavaScript details are load-bearing and each one is a rule that would
// otherwise match differently:
//
//   - `rule.enabled === false` is STRICT. A rule with no enabled field, or with
//     enabled: null, is live. Only the literal false disables one.
//   - `if (rule.permission)` is TRUTHY, and an empty array is truthy in
//     JavaScript. A rule with `permission: []` therefore matches NO permission
//     at all rather than every one.
//   - meetsTrustLevel compares indexOf results, so an unrecognised
//     minimumTrustLevel is -1 and the rule matches every caller.
//
// The error return is for a rule the original would have thrown on: a rule that
// is not an object, or whose toolPattern is not a string. There, the TypeError
// reaches the route's catch and the caller gets a 500 with no token. Here it
// does the same. Skipping the rule instead would look more robust and would be
// the dangerous choice — the skipped rule may be the DENY that was holding
// something back.
func validateEvaluatePolicy(tool string, permission any, trustLevel string, rules []any) (validateDecision, error) {
	now := store.ISOms(time.Now().UnixMilli())

	sorted := make([]*policyjson.Object, 0, len(rules))
	priorities := make([]float64, 0, len(rules))
	for _, raw := range rules {
		rule, isObject := raw.(*policyjson.Object)
		if !isObject {
			return validateDecision{}, errors.New("policy rule is not an object")
		}
		priority, isNumber := rule.Get("priority").(float64)
		if !isNumber {
			// `a.priority - b.priority` is NaN for a rule with no priority, and
			// the sort spec turns a NaN comparison into 0 — the rule keeps its
			// position. NaN compares false against everything below, which with
			// a stable sort has the same effect.
			priority = math.NaN()
		}
		sorted = append(sorted, rule)
		priorities = append(priorities, priority)
	}
	// Stable, because JavaScript's Array.prototype.sort has been stable since
	// ES2019 and two rules at the same priority must stay in the order the
	// policy lists them. Which of two equal-priority rules matches first is the
	// difference between an ALLOW and a DENY.
	sort.SliceStable(sorted, func(i, j int) bool {
		return priorities[i] < priorities[j]
	})

	for _, rule := range sorted {
		if enabled, isBool := rule.Get("enabled").(bool); isBool && !enabled {
			continue
		}

		pattern, isString := rule.Get("toolPattern").(string)
		if !isString {
			return validateDecision{}, errors.New("policy rule has no toolPattern string")
		}
		if !validateMatchesPattern(tool, pattern) {
			continue
		}

		if rulePermission := rule.Get("permission"); jsTruthy(rulePermission) {
			if !validatePermissionAllowed(rulePermission, permission) {
				continue
			}
		}

		required, _ := rule.Get("minimumTrustLevel").(string)
		if validateTrustIndex(trustLevel) < validateTrustIndex(required) {
			continue
		}

		return validateDecision{
			effect: rule.Get("effect"),
			// The rule as it was STORED, not a struct rebuilt from it. The
			// dashboard shows the whole object — constraints, description,
			// priority — and policyjson keeps the key order the policy was
			// written in.
			matchedRule:   json.RawMessage(policyjson.Stringify(rule, nil)),
			matchedRuleID: jsString(rule.Get("id")),
			reason:        "Matched rule: " + capabilityTemplate(rule.Get("id"), !rule.Has("id")),
			evaluatedAt:   now,
		}, nil
	}

	return validateDecision{
		effect:      "DENY",
		reason:      "No matching policy rule (default deny)",
		evaluatedAt: now,
	}, nil
}

// validateMatchesPattern is matchesPattern: `*`, a prefix, a suffix, or an
// exact name. Not a glob — `a*b` is an exact match on the literal "a*b",
// because the prefix branch is tested first and only the trailing star is cut.
func validateMatchesPattern(tool, pattern string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(tool, strings.TrimSuffix(pattern, "*"))
	}
	if strings.HasPrefix(pattern, "*") {
		return strings.HasSuffix(tool, strings.TrimPrefix(pattern, "*"))
	}
	return tool == pattern
}

// validatePermissionAllowed is `perms.includes(permission)`.
//
// The comparison is JavaScript's strict equality, which is why it is written
// over `any` rather than over strings: a rule constraining permission to the
// NUMBER 5 must not be matched by a request whose permission is the string "5".
// That is not a hypothetical shape to be tidy about — the permission comes
// straight off the request body with no validation, so both sides of this
// comparison are caller-controlled.
func validatePermissionAllowed(rulePermission, permission any) bool {
	list, isArray := policyjson.Array(rulePermission)
	if !isArray {
		list = []any{rulePermission}
	}
	for _, candidate := range list {
		if validateSameValue(candidate, permission) {
			return true
		}
	}
	return false
}

// validateSameValue is `===` for values that came out of JSON.parse.
func validateSameValue(a, b any) bool {
	switch av := a.(type) {
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case float64:
		bv, ok := b.(float64)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case nil:
		return b == nil
	}
	// Two objects or arrays are equal only when they are the same reference,
	// and a rule's permission never is the request's.
	return false
}

// validateTrustLevel is `trustLevelMap[raw] || 'VERIFIED'`, including the
// prototype-chain case. See validateTrustUnrecognised.
func validateTrustLevel(raw any) string {
	if !jsTruthy(raw) {
		return "VERIFIED"
	}
	key := capabilityTemplate(raw, false)
	if level, known := validateTrustLevels[key]; known {
		return level
	}
	if validateObjectPrototype[key] {
		return validateTrustUnrecognised
	}
	return "VERIFIED"
}

// validateTrustLabel is what goes in the audit row's trust_level column. The
// sentinel is never written there; the raw name is meaningless to a reader, so
// the column gets the level the evaluation actually used, which for the
// sentinel is "none of them".
func validateTrustLabel(trustLevel string) string {
	if trustLevel == validateTrustUnrecognised {
		return "UNRECOGNISED"
	}
	return trustLevel
}

// validateArgumentsHash is computeHash(JSON.stringify(args)): the full 64
// characters, unlike the audit POST route which slices its own to 16.
//
// policyjson.Stringify, not encoding/json: the hash has to be over the bytes
// JavaScript would have produced, and a Go map would sort the keys and escape
// the angle brackets. Two implementations that disagree here fingerprint the
// same call two different ways, which silently breaks any grouping done across
// the cutover.
func validateArgumentsHash(args any) string {
	sum := sha256.Sum256([]byte(policyjson.Stringify(args, nil)))
	return hex.EncodeToString(sum[:])
}

// ── shared helpers ──────────────────────────────────────────────────────────

// capabilityReadBody is `await request.json()` for these three routes.
//
// A body that is not JSON is a 500, not a 400, and that is deliberate: in all
// three live routes the parse happens INSIDE the try, so the throw lands in
// handleApiError and the caller gets INTERNAL_ERROR. A deployed client retries
// on 5xx and gives up on 4xx, so changing which one it is changes behaviour on
// somebody else's machine.
//
// A body that is valid JSON but not an object — `[]`, `"x"`, `7` — is read as
// an empty object, which is what property access on those values yields in
// JavaScript. The routes then answer their own "Missing required field".
func capabilityReadBody(w http.ResponseWriter, r *http.Request) (*policyjson.Object, bool) {
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return nil, false
	}
	parsed, err := policyjson.Parse(raw)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return nil, false
	}
	body, isObject := parsed.(*policyjson.Object)
	if !isObject {
		return policyjson.NewObject(), true
	}
	return body, true
}

// capabilityTemplate is what `${v}` writes for a value that came out of
// JSON.parse. `missing` is JavaScript's undefined, which prints as the word
// rather than as nothing — `Matched rule: undefined` is a real reason string
// the live service has written into audit rows for rules with no id.
func capabilityTemplate(v any, missing bool) string {
	if missing {
		return "undefined"
	}
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		return policyjson.NumberString(t)
	case []any:
		// Array.prototype.join: null and undefined elements render as nothing,
		// so [1,null,2] is "1,,2".
		parts := make([]string, 0, len(t))
		for _, item := range t {
			if item == nil {
				parts = append(parts, "")
				continue
			}
			parts = append(parts, capabilityTemplate(item, false))
		}
		return strings.Join(parts, ",")
	}
	return "[object Object]"
}

// containsAny is the chain of `tool.includes(...)` tests, kept as one call so
// the two lists read as the lists they are.
func containsAny(s string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}

func init() {
	Register("POST /api/v1/tokens", func(s *server) http.Handler {
		return s.auth.WithAuth(s.tokensCreate)
	})
	Register("POST /api/v1/tokens/verify", func(s *server) http.Handler {
		// The only route that writes to used_nonces, so the purge belongs with
		// it. Once per process; see startNoncePurge.
		startNoncePurge(s)
		return s.auth.WithAuth(s.tokensVerify)
	})
	Register("POST /api/v1/validate", func(s *server) http.Handler {
		// RATE_LIMITS.validation, 200 a minute rather than the standard 100.
		// This is the endpoint a proxy calls before every tool call and the
		// standard limit would stop a busy agent.
		return s.auth.WithAuthLimit(apiauth.LimitValidation, s.validateCall)
	})
}
