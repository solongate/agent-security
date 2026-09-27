package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Signing in, from a terminal, against the operator's own identity provider.
//
// THE PROVIDER SHOWS THE PAGE, NOT US. This used to be a device flow against
// SolonGate's own API, finished on a page the hosted dashboard served — and
// that endpoint took the person's address out of the request body without
// verifying it, so possession of a user code was the whole authorisation. It
// worked because the dashboard was its only caller and had already signed
// somebody in. With no dashboard it would have been the only way in and it
// verified nothing.
//
// So the flow is RFC 8628 against the IDENTITY PROVIDER (OAuth 2.0 Device
// Authorization Grant), which is what `gh`, `az` and `gcloud` do and for the
// same reason: a CLI cannot receive a redirect, and a browser is the only place
// a person should ever type a password. The provider authenticates them, the
// provider issues an ID token, and this exchanges that token at /auth/session —
// where the address comes off the VERIFIED token's claims and nothing reads a
// request body. The hole closes by construction rather than by a check.
//
// Nothing here prints. The caller renders the code and drives the poll loop, so
// the dataroom does not have to fight a library writing over its frame.

type DeviceAPI struct{ c *Client }

// DeviceStart is one pairing in flight.
//
// It carries the provider's endpoints because Poll needs them and there is
// nowhere else to keep them: the flow belongs to a screen, not to a process, and
// two dataroom panels could in principle each have one.
type DeviceStart struct {
	// UserCode is what the person types at the provider. It is SHOWN rather
	// than hidden in the URL: verification_uri_complete is a convenience the
	// browser may or may not honour, and somebody reading the code off a laptop
	// to type into a phone needs to be able to see it.
	UserCode string
	// VerifyURL is where they type it. The complete form when the provider
	// offers one, because it saves the typing when the browser does open.
	VerifyURL string
	// VerifyURLPlain is the address without the code in it, for the line that
	// tells somebody where to go when the browser did not open.
	VerifyURLPlain string

	Interval  time.Duration
	ExpiresAt time.Time

	deviceCode string
	tokenURL   string
	clientID   string
}

// Pending reports whether this is a real flight rather than a zero value.
func (d DeviceStart) Pending() bool { return d.deviceCode != "" }

type DeviceStatus string

const (
	DevicePending  DeviceStatus = "pending"
	DeviceApproved DeviceStatus = "approved"
	DeviceExpired  DeviceStatus = "expired"
	DeviceDenied   DeviceStatus = "denied"
)

type DevicePoll struct {
	Status DeviceStatus
	// APIKey is only ever set on approval and is the whole point of the flow.
	// It must not be logged.
	APIKey  string
	Project string
	User    string
	Email   string
	// Message is why a terminal status happened, when the provider said.
	Message string
}

// ErrNoProvider is what Start answers when the service has no identity provider.
//
// It is a named error because it is the one failure with an action attached and
// the action belongs to somebody else: the person at the terminal cannot fix it,
// their operator sets SG_OIDC_ISSUER on the service.
var ErrNoProvider = errors.New(
	"this SolonGate service has no identity provider configured, so there is nobody to sign in against.\n" +
		"  Whoever runs it sets SG_OIDC_ISSUER (and SG_OIDC_CLIENT_ID) and restarts it.")

// authConfig is what the service says about its provider. See the API's
// auth_config.go: none of it is secret.
type authConfig struct {
	OIDC     bool     `json:"oidc"`
	Issuer   string   `json:"issuer"`
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
}

// discovery is the two endpoints this flow needs out of the provider's
// well-known document. Everything else in it is somebody else's business.
type discovery struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
}

// Start opens a pairing request.
//
// It runs BEFORE there is a credential, so the API URL is passed explicitly
// rather than resolved — resolution would fail with "not logged in" on exactly
// the machine that is trying to log in.
func (d DeviceAPI) Start(ctx context.Context, apiURL string) (DeviceStart, error) {
	if apiURL == "" {
		apiURL = config.DefaultAPIURL
	}

	var cfg authConfig
	if err := d.c.Do(ctx, http.MethodGet, "/auth/config", RequestOptions{APIURL: apiURL, Anonymous: true}, &cfg); err != nil {
		return DeviceStart{}, err
	}
	if !cfg.OIDC || cfg.Issuer == "" {
		return DeviceStart{}, ErrNoProvider
	}
	if cfg.ClientID == "" {
		return DeviceStart{}, errors.New(
			"this SolonGate service names an identity provider but no client id, and a device\n" +
				"  sign-in cannot be started without one. Whoever runs it sets SG_OIDC_CLIENT_ID.")
	}

	disco, err := fetchDiscovery(ctx, cfg.Issuer)
	if err != nil {
		return DeviceStart{}, err
	}
	if disco.DeviceAuthorizationEndpoint == "" {
		return DeviceStart{}, fmt.Errorf(
			"the identity provider at %s does not advertise the device authorization grant,\n"+
				"  which is the only sign-in a terminal can complete", cfg.Issuer)
	}

	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	form := url.Values{}
	form.Set("client_id", cfg.ClientID)
	form.Set("scope", strings.Join(scopes, " "))

	var body struct {
		DeviceCode              string  `json:"device_code"`
		UserCode                string  `json:"user_code"`
		VerificationURI         string  `json:"verification_uri"`
		VerificationURIComplete string  `json:"verification_uri_complete"`
		Interval                float64 `json:"interval"`
		ExpiresIn               float64 `json:"expires_in"`
		Error                   string  `json:"error"`
		ErrorDescription        string  `json:"error_description"`
	}
	if err := postForm(ctx, disco.DeviceAuthorizationEndpoint, form, &body); err != nil {
		return DeviceStart{}, err
	}
	if body.Error != "" {
		return DeviceStart{}, fmt.Errorf("the identity provider refused the request: %s", oauthErrText(body.Error, body.ErrorDescription))
	}
	if body.DeviceCode == "" || body.UserCode == "" {
		return DeviceStart{}, errors.New("the identity provider answered the device request without a code")
	}

	verify := body.VerificationURIComplete
	if verify == "" {
		verify = body.VerificationURI
	}

	// Floors, not defaults. RFC 8628 says five seconds when the provider does
	// not say, and a provider asking to be polled faster than two is asking to
	// rate-limit the person signing in.
	interval := body.Interval
	if interval < 2 {
		interval = 5
	}
	expires := body.ExpiresIn
	if expires <= 0 {
		expires = 600
	}

	return DeviceStart{
		UserCode:       body.UserCode,
		VerifyURL:      verify,
		VerifyURLPlain: body.VerificationURI,
		Interval:       time.Duration(interval * float64(time.Second)),
		ExpiresAt:      time.Now().Add(time.Duration(expires * float64(time.Second))),
		deviceCode:     body.DeviceCode,
		tokenURL:       disco.TokenEndpoint,
		clientID:       cfg.ClientID,
	}, nil
}

// Poll asks the provider once whether the person has finished, and on success
// trades what it gets for a SolonGate credential.
//
// A TRANSPORT FAILURE IS PENDING, NOT AN ERROR. The person is in a browser
// during this loop and a dropped frame or a 502 must not end a sign-in they are
// halfway through; DeviceStart.ExpiresAt is what ends it. Only the provider
// saying so ends it early.
func (d DeviceAPI) Poll(ctx context.Context, apiURL string, start DeviceStart) DevicePoll {
	if apiURL == "" {
		apiURL = config.DefaultAPIURL
	}
	if !start.Pending() {
		return DevicePoll{Status: DevicePending}
	}

	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("device_code", start.deviceCode)
	form.Set("client_id", start.clientID)

	var tok struct {
		IDToken          string `json:"id_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := postForm(ctx, start.tokenURL, form, &tok); err != nil {
		return DevicePoll{Status: DevicePending}
	}

	switch tok.Error {
	case "":
		// Nothing to report yet is also spelled as an empty body by a provider
		// or two, so an absent token is pending rather than a failure.
		if tok.IDToken == "" {
			return DevicePending.poll()
		}
	case "authorization_pending", "slow_down":
		// slow_down asks for a longer interval. The caller's tick is already at
		// the provider's stated interval and one extra round trip costs nobody
		// anything, so it is treated as pending rather than as a rate to track.
		return DevicePending.poll()
	case "expired_token":
		return DevicePoll{Status: DeviceExpired}
	case "access_denied":
		return DevicePoll{Status: DeviceDenied, Message: "the sign-in was refused at the identity provider"}
	default:
		return DevicePoll{Status: DeviceDenied, Message: oauthErrText(tok.Error, tok.ErrorDescription)}
	}

	// The provider has vouched for them. THIS SERVICE HAS NOT YET — the token
	// goes to /auth/session, which verifies the signature against the provider's
	// own keys and takes the address from the claims. Nothing this process
	// decoded below is trusted for anything but what it prints.
	var session struct {
		APIKey  *string `json:"api_key"`
		Project *struct {
			Name string `json:"name"`
		} `json:"project"`
	}
	err := d.c.Do(ctx, http.MethodPost, "/auth/session", RequestOptions{
		APIURL:    apiURL,
		Anonymous: true,
		Body:      map[string]any{"access_token": tok.IDToken},
	}, &session)
	if err != nil {
		// The provider said yes and this service said no. That is terminal —
		// polling again cannot change it, and the usual cause is a token minted
		// for a different audience than SG_OIDC_CLIENT_ID names.
		return DevicePoll{Status: DeviceDenied, Message: "the identity provider signed you in, but SolonGate refused the token: " + err.Error()}
	}
	if session.APIKey == nil || *session.APIKey == "" {
		return DevicePoll{Status: DeviceDenied, Message: "SolonGate accepted the sign-in but issued no credential for this account"}
	}

	out := DevicePoll{Status: DeviceApproved, APIKey: *session.APIKey}
	if session.Project != nil {
		out.Project = session.Project.Name
	}
	// For the line that says who just signed in, and for nothing else.
	out.Email, out.User = idTokenDisplayName(tok.IDToken)
	return out
}

// poll is the pending value, written once so the three returns above read the
// same way.
func (s DeviceStatus) poll() DevicePoll { return DevicePoll{Status: s} }

// fetchDiscovery reads the provider's well-known document.
func fetchDiscovery(ctx context.Context, issuer string) (discovery, error) {
	var d discovery
	endpoint := strings.TrimRight(issuer, "/") + "/.well-known/openid-configuration"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return d, err
	}
	res, err := oauthClient.Do(req)
	if err != nil {
		return d, fmt.Errorf("could not reach the identity provider at %s: %w", issuer, err)
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return d, fmt.Errorf("the identity provider at %s answered %d for its discovery document", issuer, res.StatusCode)
	}
	if err := json.NewDecoder(res.Body).Decode(&d); err != nil {
		return d, fmt.Errorf("the identity provider at %s served a discovery document this could not read", issuer)
	}
	return d, nil
}

// oauthClient is the client for the two calls that go to the PROVIDER rather
// than to SolonGate. Its own timeout, because it is a different service with a
// different failure mode, and a short one: both calls are a form post.
var oauthClient = &http.Client{Timeout: 20 * time.Second}

// postForm sends an application/x-www-form-urlencoded request and decodes the
// JSON answer.
//
// A NON-2XX IS DECODED RATHER THAN REFUSED, because RFC 6749 puts the error in
// the body with a 400: `authorization_pending` — the normal state for most of
// this flow — arrives as a 400 with a JSON body, and treating the status as the
// answer would turn every poll into a failure.
func postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	res, err := oauthClient.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	if err := json.NewDecoder(res.Body).Decode(out); err != nil {
		return fmt.Errorf("the identity provider answered %d with something this could not read", res.StatusCode)
	}
	return nil
}

// oauthErrText renders an OAuth error the way a person can act on.
func oauthErrText(code, description string) string {
	if d := strings.TrimSpace(description); d != "" {
		return d + " (" + code + ")"
	}
	return code
}

// idTokenDisplayName reads the address and name out of an ID token FOR DISPLAY.
//
// It does not verify anything and must not be used for anything that decides
// access: the service verified this token against the provider's keys before it
// issued a credential, and that is the check that counts. This exists so the
// line after a sign-in can say who signed in, and a token this cannot parse
// simply produces no name.
func idTokenDisplayName(idToken string) (email, name string) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", ""
	}
	var claims struct {
		Email             string `json:"email"`
		UPN               string `json:"upn"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	if json.Unmarshal(raw, &claims) != nil {
		return "", ""
	}
	// The same order the service reads them in, so the name printed here is the
	// account the credential actually belongs to. See authVerifyOIDCToken.
	for _, c := range []string{claims.Email, claims.UPN, claims.PreferredUsername} {
		if strings.Contains(c, "@") {
			email = c
			break
		}
	}
	name = claims.Name
	if name == "" {
		name = email
	}
	return email, name
}

// OpenBrowser is best-effort. A headless box or a missing opener is not a
// failure: the URL and the code are printed either way and the person can open
// it themselves, or on another device entirely — which is the case the device
// grant exists for.
func OpenBrowser(url string) {
	if strings.TrimSpace(url) == "" {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	if cmd.Start() == nil {
		// Reaped in the background so the opener does not become a zombie for
		// the life of a long TUI session.
		go func() { _ = cmd.Wait() }()
	}
}
