package sdk

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// TokenIssuer mints the capability token that travels with an allowed call.
//
// The token is what makes an allowed call unforgeable downstream: a tool server
// that checks it knows the call came through the gateway and was granted these
// permissions for this one request. Three properties do the work — a very short
// life, single use, and a scope that names the tool.
//
// There is no JWT library here. The format is a JWT's three dot-separated
// segments, but the only algorithm accepted is HMAC-SHA256 and the header is
// never consulted to choose one. That is deliberate: reading `alg` from the
// token is how "alg: none" happens.
type TokenIssuer struct {
	secret     []byte
	ttl        time.Duration
	issuer     string
	usedJTIs   *ExpiringSet
	revoked    *ExpiringSet
	nowOverrid func() time.Time
}

// TokenVerification is the answer from Verify. Reason is filled in only when
// the token is refused, and it never contains any part of the token.
type TokenVerification struct {
	Valid   bool
	Reason  string
	Payload *core.CapabilityToken
}

func NewTokenIssuer(secret string, ttlSeconds int, issuer string) (*TokenIssuer, error) {
	if len(secret) < core.TokenMinSecretLength {
		return nil, fmt.Errorf("token secret must be at least %d characters", core.TokenMinSecretLength)
	}
	ttl := time.Duration(ttlSeconds) * time.Second
	if ttlSeconds <= 0 {
		ttl = core.TokenDefaultTTLSeconds * time.Second
	}
	// Nonces and revocations only have to outlive the longest token that could
	// still be presented.
	maxAge := core.TokenMaxAgeSeconds * time.Second
	return &TokenIssuer{
		secret:   []byte(secret),
		ttl:      ttl,
		issuer:   issuer,
		usedJTIs: NewExpiringSet(maxAge),
		revoked:  NewExpiringSet(maxAge),
	}, nil
}

func (t *TokenIssuer) now() time.Time {
	if t.nowOverrid != nil {
		return t.nowOverrid()
	}
	return time.Now()
}

// Issue signs a token for one request.
func (t *TokenIssuer) Issue(requestID string, permissions []core.Permission, toolScope []string, serverScope []string, pathScope []string) (string, error) {
	if len(serverScope) == 0 {
		serverScope = []string{"*"}
	}
	jti, err := randomUUID()
	if err != nil {
		return "", err
	}
	now := t.now().Unix()
	payload := core.CapabilityToken{
		JTI:         jti,
		Iss:         t.issuer,
		Sub:         requestID,
		Iat:         now,
		Exp:         now + int64(t.ttl.Seconds()),
		Permissions: permissions,
		ToolScope:   toolScope,
		ServerScope: serverScope,
		PathScope:   pathScope,
	}
	return t.sign(payload)
}

// Verify checks the signature, the expiry, revocation and replay — in that
// order, and it CONSUMES the token's id on success. A second presentation of
// the same token is a replay and is refused.
func (t *TokenIssuer) Verify(token string) TokenVerification {
	parsed := t.parseAndVerify(token)
	if !parsed.Valid || parsed.Payload == nil {
		return parsed
	}
	payload := parsed.Payload

	if payload.Exp <= t.now().Unix() {
		return TokenVerification{Reason: "Token expired"}
	}
	if t.revoked.Has(payload.JTI) {
		return TokenVerification{Reason: "Token has been revoked"}
	}
	if t.usedJTIs.Has(payload.JTI) {
		return TokenVerification{Reason: "Token already used (replay detected)"}
	}
	t.usedJTIs.Add(payload.JTI)

	return TokenVerification{Valid: true, Payload: payload}
}

func (t *TokenIssuer) Revoke(jti string)         { t.revoked.Add(jti) }
func (t *TokenIssuer) IsRevoked(jti string) bool { return t.revoked.Has(jti) }

func (t *TokenIssuer) sign(payload core.CapabilityToken) (string, error) {
	headerJSON, err := json.Marshal(map[string]string{"alg": core.TokenAlgorithm, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	bodyJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	header := base64URLEncode(headerJSON)
	body := base64URLEncode(bodyJSON)
	return header + "." + body + "." + t.computeSignature(header+"."+body), nil
}

func (t *TokenIssuer) parseAndVerify(token string) TokenVerification {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return TokenVerification{Reason: "Invalid token format"}
	}
	expected := t.computeSignature(parts[0] + "." + parts[1])
	// Constant time: a byte-at-a-time comparison leaks how much of a forged
	// signature was right, which is enough to build the rest of it.
	if !hmac.Equal([]byte(expected), []byte(parts[2])) {
		return TokenVerification{Reason: "Invalid token signature"}
	}
	raw, err := base64URLDecode(parts[1])
	if err != nil {
		return TokenVerification{Reason: "Invalid token payload"}
	}
	var payload core.CapabilityToken
	if json.Unmarshal(raw, &payload) != nil {
		return TokenVerification{Reason: "Invalid token payload"}
	}
	return TokenVerification{Valid: true, Payload: &payload}
}

// computeSignature reproduces the npm implementation exactly, including the
// double encoding: the HMAC is rendered as standard base64 and THAT string is
// then base64url-encoded. It is redundant, but it is the wire format tokens are
// already being issued in, and changing it would make a Go gateway's tokens
// unverifiable by a TypeScript server and the other way round.
func (t *TokenIssuer) computeSignature(data string) string {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(data))
	inner := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return base64URLEncode([]byte(inner))
}

func base64URLEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// randomUUID is a version 4 UUID from the system CSPRNG. An error here is a
// failure to read randomness, which must NOT fall back to anything weaker: a
// predictable token id defeats both the replay set and revocation.
func randomUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("could not read secure randomness for a token id: " + err.Error())
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}
