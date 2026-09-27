package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeIDToken builds an unsigned JWT with the claims the display path reads.
//
// Unsigned on purpose: nothing in the CLI verifies a token, and a test that
// signed one would be asserting the opposite of what this code promises. The
// service verifies it, against the provider's keys, and that is where the check
// belongs.
func fakeIDToken(claims map[string]any) string {
	body, _ := json.Marshal(claims)
	return "e30." + base64.RawURLEncoding.EncodeToString(body) + ".sig"
}

// idp is a provider that answers the two endpoints the device grant needs.
type idp struct {
	*httptest.Server
	polls int
	// approveOn is the poll that succeeds; every earlier one is pending.
	approveOn int
	idToken   string
	// tokenErr, when set, is returned instead of a token.
	tokenErr string
}

func newIDP(t *testing.T, approveOn int, idToken string) *idp {
	t.Helper()
	p := &idp{approveOn: approveOn, idToken: idToken}
	p.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_, _ = w.Write([]byte(`{
			  "device_authorization_endpoint":"` + p.URL + `/device",
			  "token_endpoint":"` + p.URL + `/token"}`))
		case "/device":
			_, _ = w.Write([]byte(`{"device_code":"dev-code","user_code":"WDJB-MJHT",
			  "verification_uri":"` + p.URL + `/activate",
			  "verification_uri_complete":"` + p.URL + `/activate?user_code=WDJB-MJHT",
			  "interval":1,"expires_in":300}`))
		case "/token":
			p.polls++
			if p.tokenErr != "" {
				// RFC 6749 puts the error in the body with a 400, which is why
				// postForm decodes a non-2xx rather than refusing it.
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"` + p.tokenErr + `"}`))
				return
			}
			if p.polls < p.approveOn {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"id_token":"` + p.idToken + `","token_type":"Bearer"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(p.Close)
	return p
}

// solonGate is the service: it says which provider to use, and trades a token
// for a credential.
func newService(t *testing.T, issuer string, onSession func(token string) (int, string)) (*httptest.Server, *string) {
	t.Helper()
	var sessionAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/config":
			if issuer == "" {
				_, _ = w.Write([]byte(`{"oidc":false}`))
				return
			}
			_, _ = w.Write([]byte(`{"oidc":true,"issuer":"` + issuer + `","client_id":"solongate-cli",
			  "scopes":["openid","profile","email"]}`))
		case "/api/v1/auth/session":
			sessionAuth = r.Header.Get("Authorization")
			var body struct {
				AccessToken string `json:"access_token"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			code, payload := onSession(body.AccessToken)
			w.WriteHeader(code)
			_, _ = w.Write([]byte(payload))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &sessionAuth
}

// The whole flow, on a machine with no credential.
//
// It must send none and must not try to resolve one: a resolution attempt fails
// with "not logged in" on exactly the machine that is trying to log in.
func TestDeviceLoginSignsInAgainstTheProvider(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	token := fakeIDToken(map[string]any{"email": "ada@example.com", "name": "Ada"})
	provider := newIDP(t, 2, token)

	var got string
	svc, sessionAuth := newService(t, provider.URL, func(presented string) (int, string) {
		got = presented
		return 200, `{"api_key":"sg_live_granted000000000","project":{"name":"Acme"}}`
	})

	c := New()
	start, err := c.Device.Start(context.Background(), svc.URL)
	if err != nil {
		t.Fatal(err)
	}

	// The code is what the person types, so it has to survive to the caller.
	if start.UserCode != "WDJB-MJHT" {
		t.Errorf("user code = %q", start.UserCode)
	}
	// Both addresses: the complete one for the browser, the plain one for the
	// line somebody reads off a laptop and types into a phone.
	if !strings.HasSuffix(start.VerifyURL, "/activate?user_code=WDJB-MJHT") {
		t.Errorf("verify url = %q", start.VerifyURL)
	}
	if !strings.HasSuffix(start.VerifyURLPlain, "/activate") {
		t.Errorf("plain verify url = %q", start.VerifyURLPlain)
	}
	// An interval below two seconds is raised to the specification's five.
	if start.Interval != 5*time.Second {
		t.Errorf("interval = %s, want the 5s floor", start.Interval)
	}
	if !start.ExpiresAt.After(time.Now()) {
		t.Error("expiry is in the past")
	}

	if p := c.Device.Poll(context.Background(), svc.URL, start); p.Status != DevicePending {
		t.Fatalf("first poll = %+v, want pending", p)
	}
	p := c.Device.Poll(context.Background(), svc.URL, start)
	if p.Status != DeviceApproved || p.APIKey == "" {
		t.Fatalf("second poll = %+v, want approved with a credential", p)
	}
	if p.Project != "Acme" {
		t.Errorf("project = %q", p.Project)
	}
	// Read out of the token FOR DISPLAY. Nothing here verified it.
	if p.Email != "ada@example.com" || p.User != "Ada" {
		t.Errorf("identity not read for display: %+v", p)
	}

	// The token the provider issued is what reaches the service, and it arrives
	// in the body rather than as a credential of its own.
	if got != token {
		t.Errorf("the service was handed %q, want the provider's id_token", got)
	}
	if *sessionAuth != "" {
		t.Error("the session exchange sent a credential; it runs before there is one")
	}
}

// A dropped connection mid-login reads as "keep waiting", not as a failure: the
// person is in a browser and the expiry is what ends the flow.
func TestDevicePollTreatsTransportFailuresAsPending(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	dead := DeviceStart{deviceCode: "dc", tokenURL: "http://127.0.0.1:1/token", clientID: "cli"}
	if p := New().Device.Poll(context.Background(), "http://127.0.0.1:1", dead); p.Status != DevicePending {
		t.Errorf("poll against a dead provider = %+v, want pending", p)
	}
}

// The provider's terminal answers end the flow; its transient one does not.
func TestDevicePollMapsProviderErrors(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	for _, tc := range []struct {
		oauthErr string
		want     DeviceStatus
	}{
		{"authorization_pending", DevicePending},
		{"slow_down", DevicePending},
		{"expired_token", DeviceExpired},
		{"access_denied", DeviceDenied},
		{"invalid_client", DeviceDenied},
	} {
		provider := newIDP(t, 1, "")
		provider.tokenErr = tc.oauthErr
		svc, _ := newService(t, provider.URL, func(string) (int, string) { return 200, `{}` })

		c := New()
		start, err := c.Device.Start(context.Background(), svc.URL)
		if err != nil {
			t.Fatal(err)
		}
		if got := c.Device.Poll(context.Background(), svc.URL, start); got.Status != tc.want {
			t.Errorf("%s → %s, want %s", tc.oauthErr, got.Status, tc.want)
		}
	}
}

// A service with no provider configured says so, and says it once, rather than
// failing later with a discovery error nobody at the terminal can act on.
func TestDeviceStartRefusesWithoutAProvider(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	svc, _ := newService(t, "", func(string) (int, string) { return 200, `{}` })
	_, err := New().Device.Start(context.Background(), svc.URL)
	if err == nil {
		t.Fatal("a service with no identity provider started a sign-in")
	}
	if !strings.Contains(err.Error(), "SG_OIDC_ISSUER") {
		t.Errorf("the error does not name the variable an operator has to set: %v", err)
	}
}

// The provider signed them in and the SERVICE refused the token. That is
// terminal: polling again cannot change it, and the usual cause is an audience
// mismatch, which is a sentence somebody can act on.
func TestDeviceSessionRefusalIsTerminal(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	provider := newIDP(t, 1, fakeIDToken(map[string]any{"email": "ada@example.com"}))
	svc, _ := newService(t, provider.URL, func(string) (int, string) {
		return 401, `{"error":{"code":"AUTHENTICATION_ERROR","message":"token rejected"}}`
	})

	c := New()
	start, err := c.Device.Start(context.Background(), svc.URL)
	if err != nil {
		t.Fatal(err)
	}
	p := c.Device.Poll(context.Background(), svc.URL, start)
	if p.Status != DeviceDenied {
		t.Fatalf("a refused token = %+v, want denied rather than endless polling", p)
	}
	if p.Message == "" {
		t.Error("the refusal carries no reason")
	}
}

// A sign-in that succeeds but yields no credential must not report success: the
// caller would store an empty key and every later command would 401 with
// nothing explaining why.
func TestDeviceApprovalWithoutACredentialIsRefused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	provider := newIDP(t, 1, fakeIDToken(map[string]any{"email": "ada@example.com"}))
	svc, _ := newService(t, provider.URL, func(string) (int, string) {
		return 200, `{"api_key":null,"project":null}`
	})

	c := New()
	start, _ := c.Device.Start(context.Background(), svc.URL)
	if p := c.Device.Poll(context.Background(), svc.URL, start); p.Status == DeviceApproved {
		t.Error("a sign-in with no credential reported approved")
	}
}
