package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// A stand-in identity provider: discovery, a key set, and tokens signed with
// the key it publishes. Enough to prove this service verifies a real signature
// against a real key set rather than trusting whatever it is handed.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey
	kid string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &fakeIdP{key: key, kid: "test-key-1"}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                idp.srv.URL,
			"authorization_endpoint":                idp.srv.URL + "/authorize",
			"token_endpoint":                        idp.srv.URL + "/token",
			"jwks_uri":                              idp.srv.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		n := base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes())
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]string{{
				"kty": "RSA", "alg": "RS256", "use": "sig", "kid": idp.kid, "n": n, "e": e,
			}},
		})
	})

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

// token mints an ID token. Claims override the defaults, so a test can leave
// out an address or sign for the wrong audience.
func (f *fakeIdP) token(t *testing.T, claims map[string]any) string {
	t.Helper()

	base := map[string]any{
		"iss":   f.srv.URL,
		"aud":   "solongate",
		"sub":   "usr-1",
		"email": "ayse@kurum.example",
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	for k, v := range claims {
		if v == nil {
			delete(base, k)
			continue
		}
		base[k] = v
	}

	header, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": f.kid})
	payload, _ := json.Marshal(base)
	signing := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)

	sig, err := signRS256(f.key, signing)
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + sig
}

// resetOIDC clears the once-built verifier so each test configures its own
// issuer. The production path builds it once for the life of the process.
func resetOIDC(t *testing.T, issuer, clientID string) {
	t.Helper()
	oidcOnce = sync.Once{}
	oidcVerifier = nil
	oidcErr = nil
	clearVerifiedCache()

	t.Setenv("SG_OIDC_ISSUER", issuer)
	t.Setenv("SG_OIDC_CLIENT_ID", clientID)

	t.Cleanup(func() {
		oidcOnce = sync.Once{}
		oidcVerifier = nil
		oidcErr = nil
		clearVerifiedCache()
	})
}

func TestOIDCConfiguredSelectsTheOIDCPath(t *testing.T) {
	if oidcConfigured() {
		t.Fatal("SG_OIDC_ISSUER is set in the environment this test runs in")
	}
	t.Setenv("SG_OIDC_ISSUER", "https://sso.corp.example/realms/main")
	if !oidcConfigured() {
		t.Fatal("an issuer is configured and oidcConfigured says otherwise")
	}
}

func TestOIDCVerifiesAGenuineToken(t *testing.T) {
	idp := newFakeIdP(t)
	resetOIDC(t, idp.srv.URL, "solongate")

	email, ok := authVerifyOIDCToken(context.Background(), idp.token(t, nil))
	if !ok {
		t.Fatal("a correctly signed token was refused")
	}
	if email != "ayse@kurum.example" {
		t.Errorf("email = %q", email)
	}
}

// The whole point of verifying locally: a token this provider did not sign must
// not be accepted, however well-formed it is.
func TestOIDCRefusesAForgedToken(t *testing.T) {
	idp := newFakeIdP(t)
	forger := newFakeIdP(t)
	resetOIDC(t, idp.srv.URL, "solongate")

	// Signed by somebody else, but claiming to come from the real issuer.
	forged := forger.token(t, map[string]any{"iss": idp.srv.URL})
	if _, ok := authVerifyOIDCToken(context.Background(), forged); ok {
		t.Fatal("a token signed by another key was accepted")
	}
}

func TestOIDCRefusesTheWrongAudience(t *testing.T) {
	idp := newFakeIdP(t)
	resetOIDC(t, idp.srv.URL, "solongate")

	other := idp.token(t, map[string]any{"aud": "some-other-application"})
	if _, ok := authVerifyOIDCToken(context.Background(), other); ok {
		t.Fatal("a token minted for another application at the same provider was accepted")
	}
}

func TestOIDCRefusesAnExpiredToken(t *testing.T) {
	idp := newFakeIdP(t)
	resetOIDC(t, idp.srv.URL, "solongate")

	expired := idp.token(t, map[string]any{
		"exp": time.Now().Add(-time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})
	if _, ok := authVerifyOIDCToken(context.Background(), expired); ok {
		t.Fatal("an expired token was accepted")
	}
}

// ADFS puts the address in upn, and several providers use preferred_username.
// A directory nobody will reconfigure for us still has to work.
func TestOIDCReadsTheAddressFromWhicheverClaimCarriesIt(t *testing.T) {
	idp := newFakeIdP(t)

	for _, c := range []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"email", nil, "ayse@kurum.example"},
		{"upn", map[string]any{"email": nil, "upn": "Ayse@Kurum.Example"}, "ayse@kurum.example"},
		{"preferred_username", map[string]any{"email": nil, "preferred_username": "ayse@kurum.example"}, "ayse@kurum.example"},
	} {
		t.Run(c.name, func(t *testing.T) {
			resetOIDC(t, idp.srv.URL, "solongate")
			email, ok := authVerifyOIDCToken(context.Background(), idp.token(t, c.claims))
			if !ok {
				t.Fatalf("a token carrying %s was refused", c.name)
			}
			if email != c.want {
				t.Errorf("email = %q, want %q", email, c.want)
			}
		})
	}
}

// A session with no address cannot provision: everything downstream keys on it.
func TestOIDCRefusesATokenWithNoAddress(t *testing.T) {
	idp := newFakeIdP(t)
	resetOIDC(t, idp.srv.URL, "solongate")

	none := idp.token(t, map[string]any{"email": nil})
	if _, ok := authVerifyOIDCToken(context.Background(), none); ok {
		t.Fatal("a token with no address claim was accepted")
	}
}

// Without a client id the audience cannot be checked, and the deployment is
// told so at startup. The token is still verified.
func TestOIDCWithoutAClientIDStillVerifiesTheSignature(t *testing.T) {
	idp := newFakeIdP(t)
	forger := newFakeIdP(t)
	resetOIDC(t, idp.srv.URL, "")

	if _, ok := authVerifyOIDCToken(context.Background(), idp.token(t, map[string]any{"aud": "anything"})); !ok {
		t.Fatal("a genuine token was refused when no client id was configured")
	}
	if _, ok := authVerifyOIDCToken(context.Background(), forger.token(t, map[string]any{"iss": idp.srv.URL})); ok {
		t.Fatal("a forged token was accepted when no client id was configured")
	}
}

// clearVerifiedCache empties the short-lived verified-token cache so one test's
// token is not accepted by the next test's issuer.
func clearVerifiedCache() {
	authVerified.Lock()
	authVerified.at = map[string]authVerifiedEntry{}
	authVerified.Unlock()
}

// signRS256 signs the JWT signing input with the provider's key.
func signRS256(key *rsa.PrivateKey, signing string) (string, error) {
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(sig), nil
}
