// Package api is the single HTTP layer between the SolonGate CLI and the
// SolonGate Cloud API.
//
// Auth mirrors the rest of the CLI: one device login writes
// ~/.solongate/cloud-guard.json, and every request here sends
// `Authorization: Bearer <key>`. Nothing in this package logs, prints, or
// embeds a key in an error — an API key in a terminal scrollback or a support
// paste is a credential leak, and errors are the surface most likely to be
// copied somewhere else.
//
// This package must never be pulled into the guard's decision path. It is
// loaded by the command and TUI entry points only.
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// DefaultTimeout is the per-attempt budget. Long enough for a cold API, short
// enough that a wedged connection does not look like a hung CLI.
const DefaultTimeout = 15 * time.Second

// Error is every non-2xx response. Code and Message come from the API's
// `{ error: { code, message } }` envelope when there is one; Status is the HTTP
// status, and 0 means the request never got an answer at all.
type Error struct {
	Status  int
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// IsAuth reports the case worth handling separately everywhere: the key is
// there but the cloud will not accept it.
func (e *Error) IsAuth() bool { return e.Status == 401 || e.Status == 403 }

// ErrNotAuthenticated is re-exported so callers do not have to import config
// just to recognise "no key anywhere".
var ErrNotAuthenticated = config.ErrNotAuthenticated

// Client is one process's view of the API.
type Client struct {
	resolver *config.Resolver
	http     *http.Client
	// APIURLOverride comes from a global --api-url flag and beats every stored
	// URL for every request this client makes.
	APIURLOverride string

	Auth     AuthAPI
	Policies PoliciesAPI
	Settings SettingsAPI
	Stats    StatsAPI
	Audit    AuditAPI
}

// New builds a client. The sub-APIs are fields rather than free functions so a
// call site reads like the route it hits (c.Policies.List for /policies) and so
// two clients pointed at two accounts cannot share state.
func New() *Client {
	c := &Client{
		resolver: &config.Resolver{},
		// No global timeout on the http.Client: the deadline is per attempt and
		// lives on the request context, so a retry gets a full budget rather
		// than whatever the first attempt left over.
		http: &http.Client{},
	}
	c.Auth = AuthAPI{c}
	c.Policies = PoliciesAPI{c}
	c.Settings = SettingsAPI{c}
	c.Stats = StatsAPI{c}
	c.Audit = AuditAPI{c}
	return c
}

// SetViewCredentials points this client at another account, or clears the
// override with nil. It never touches disk: the guard hooks keep enforcing with
// the device's real active key whatever the dataroom is looking at.
func (c *Client) SetViewCredentials(cred *config.Credential) { c.resolver.SetView(cred) }

// Invalidate drops the cached credential, for after a write to the active-key
// file.
func (c *Client) Invalidate() { c.resolver.Invalidate() }

// Authenticated reports whether a key can be found without prompting.
func (c *Client) Authenticated() bool { return c.resolver.Authenticated() }

// Credentials resolves the key and URL this client would use. Callers that only
// need the URL or the account identity should use it; nothing should print the
// key it returns.
func (c *Client) Credentials() (config.Credential, error) {
	return c.resolver.Resolve(c.APIURLOverride)
}

// RequestOptions are the per-request knobs. The zero value is a plain request
// with the default timeout.
type RequestOptions struct {
	Query   url.Values
	Body    any
	Timeout time.Duration
	// APIURL overrides the base URL for this one request. Credentials are still
	// resolved and still sent — this changes WHERE the request goes, not who it
	// is from.
	APIURL string
	// Anonymous sends no credential and resolves none.
	//
	// It is separate from APIURL on purpose. The device-login endpoints need
	// both, and folding them into one flag would mean any future caller that
	// only wanted a different host silently stopped authenticating.
	Anonymous bool
	// Raw takes the response body as BYTES rather than decoding it as JSON.
	//
	// For the routes that answer with a document — the report download is
	// markdown or CSV. Without it the decode fails on the first character and
	// the caller is told the API returned something it cannot read, which is
	// true of every JSON parser and false of the answer.
	Raw bool
}

// Query builds a query string, skipping zero values.
//
// An unset filter has to be ABSENT, not sent as an empty string: the API still
// interprets `tool=`, and it interpreted it as a tool named nothing. Go has no
// `undefined`, so a zero number is treated as unset too — none of these
// parameters has a meaningful zero (a limit of 0, a timestamp of 0, version 0),
// and `offset=0` is what the API defaults to anyway. A caller that genuinely
// needs to send a zero sets the value as a string.
func Query(pairs map[string]any) url.Values {
	v := url.Values{}
	for k, raw := range pairs {
		switch t := raw.(type) {
		case nil:
			continue
		case string:
			if t == "" {
				continue
			}
			v.Set(k, t)
		case bool:
			if !t {
				continue
			}
			v.Set(k, "true")
		case int:
			if t == 0 {
				continue
			}
			v.Set(k, strconv.Itoa(t))
		case int64:
			if t == 0 {
				continue
			}
			v.Set(k, strconv.FormatInt(t, 10))
		case float64:
			if t == 0 {
				continue
			}
			v.Set(k, strconv.FormatFloat(t, 'f', -1, 64))
		default:
			v.Set(k, fmt.Sprint(t))
		}
	}
	return v
}

func buildURL(base, path string, query url.Values) string {
	u := base + "/api/v1" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	return u
}

// Do performs a request against the v1 API and decodes a 2xx JSON body into
// out. out may be nil when the body is not needed.
//
// Retries: a transient network failure — a keep-alive socket the OS or a NAT
// dropped during a long idle, a DNS hiccup, a laptop resuming — is retried
// before it is surfaced. A stale connection often needs a couple of attempts to
// re-establish, so GETs get three tries; MUTATIONS ARE NEVER RETRIED, because a
// POST that actually arrived and whose response was lost would be sent twice.
func (c *Client) Do(ctx context.Context, method, path string, opts RequestOptions, out any) error {
	base, key := opts.APIURL, ""
	if !opts.Anonymous {
		creds, err := c.resolver.Resolve(c.APIURLOverride)
		if err != nil {
			return err
		}
		key = creds.APIKey
		if base == "" {
			base = creds.APIURL
		}
	}
	if base == "" {
		base = config.DefaultAPIURL
	}

	endpoint := buildURL(strings.TrimRight(base, "/"), path, opts.Query)

	var bodyBytes []byte
	if opts.Body != nil {
		b, err := json.Marshal(opts.Body)
		if err != nil {
			return &Error{Code: "ENCODE_ERROR", Message: "Could not encode the request body: " + err.Error()}
		}
		bodyBytes = b
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	maxTries := 1
	if method == http.MethodGet {
		maxTries = 3
	}

	var res *http.Response
	var lastErr error
	for attempt := 0; attempt < maxTries; attempt++ {
		r, err := c.attempt(ctx, method, endpoint, key, bodyBytes, timeout)
		if err == nil {
			res = r
			break
		}
		lastErr = err
		// A cancelled parent context is the user pressing Ctrl+C, not a blip.
		if ctx.Err() != nil {
			break
		}
		if attempt < maxTries-1 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(600*(attempt+1)) * time.Millisecond):
			}
		}
	}
	if res == nil {
		return &Error{Code: "NETWORK_ERROR", Message: "Cannot reach SolonGate API: " + scrub(lastErr)}
	}
	defer res.Body.Close()

	text, _ := io.ReadAll(res.Body)

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return apiError(res, text)
	}
	if out == nil || len(bytes.TrimSpace(text)) == 0 {
		return nil
	}
	if opts.Raw {
		if dst, ok := out.(*[]byte); ok {
			*dst = text
			return nil
		}
	}
	if err := json.Unmarshal(text, out); err != nil {
		return &Error{Status: res.StatusCode, Code: "DECODE_ERROR",
			Message: "The API returned something this version cannot read: " + err.Error()}
	}
	return nil
}

func (c *Client) attempt(ctx context.Context, method, endpoint, key string, body []byte, timeout time.Duration) (*http.Response, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(reqCtx, method, endpoint, reader)
	if err != nil {
		cancel()
		return nil, err
	}
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Close, not a Connection header: Go's transport strips hop-by-hop headers,
	// so setting "Connection: close" by hand does nothing. This is the same
	// intent as the Node client's — do not reuse a pooled socket that the OS or
	// a NAT may have silently dropped after hours idle, which is the single
	// biggest cause of the "Cannot reach API" flash on a resumed session.
	req.Close = true

	res, err := c.http.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	// The body is still being read after this returns, so the cancel has to
	// outlive the call; it is attached to the body instead.
	res.Body = &cancelOnClose{ReadCloser: res.Body, cancel: cancel}
	return res, nil
}

type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// apiError turns a non-2xx into the message the user sees.
//
// The standard envelope is `{ error: { code, message } }`; some routes send a
// bare `{ error: "string" }`. When neither is there, 401 and 429 and 5xx get
// wording that says what to do about it, because "HTTP 500" tells the person at
// the terminal nothing.
func apiError(res *http.Response, text []byte) error {
	var envelope struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(text, &envelope) == nil && len(envelope.Error) > 0 {
		switch envelope.Error[0] {
		case '{':
			var obj struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}
			_ = json.Unmarshal(envelope.Error, &obj)
			code, msg := obj.Code, obj.Message
			if code == "" {
				code = "ERROR"
			}
			if msg == "" {
				msg = res.Status
			}
			return &Error{Status: res.StatusCode, Code: code, Message: msg}
		case '"':
			var s string
			if json.Unmarshal(envelope.Error, &s) == nil && s != "" {
				return &Error{Status: res.StatusCode, Code: "ERROR", Message: s}
			}
		}
	}

	switch {
	case res.StatusCode == 401:
		return &Error{Status: 401, Code: "AUTHENTICATION_ERROR",
			Message: "Invalid API key. Run `solongate` and log in from the Accounts panel."}
	case res.StatusCode == 429:
		return &Error{Status: 429, Code: "RATE_LIMITED",
			Message: "Rate limited by the API. Slow down and retry."}
	case res.StatusCode >= 500:
		msg := string(text)
		if strings.TrimSpace(msg) == "" {
			msg = "SolonGate API had a problem (server error). Please try again in a moment."
		}
		return &Error{Status: res.StatusCode, Code: "SERVER_ERROR", Message: msg}
	}
	msg := strings.TrimSpace(string(text))
	if msg == "" {
		msg = res.Status
	}
	if msg == "" {
		msg = "HTTP " + strconv.Itoa(res.StatusCode)
	}
	return &Error{Status: res.StatusCode, Code: "ERROR", Message: msg}
}

// scrub keeps a transport error from carrying a credential into a message that
// gets printed. Go puts the request URL in *url.Error, and while the key
// travels in a header rather than the URL today, a future endpoint that takes
// it as a parameter would leak it through here silently.
func scrub(err error) string {
	if err == nil {
		return "unknown error"
	}
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		return ue.Err.Error()
	}
	return err.Error()
}

// get / post / put / patch / del are the shorthands the resource files use.

func (c *Client) get(ctx context.Context, path string, query url.Values, out any) error {
	return c.Do(ctx, http.MethodGet, path, RequestOptions{Query: query}, out)
}

func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	return c.Do(ctx, http.MethodPost, path, RequestOptions{Body: body}, out)
}

func (c *Client) put(ctx context.Context, path string, body any, out any) error {
	return c.Do(ctx, http.MethodPut, path, RequestOptions{Body: body}, out)
}

func (c *Client) patch(ctx context.Context, path string, query url.Values, body any, out any) error {
	return c.Do(ctx, http.MethodPatch, path, RequestOptions{Query: query, Body: body}, out)
}

func (c *Client) del(ctx context.Context, path string, query url.Values, body any, out any) error {
	return c.Do(ctx, http.MethodDelete, path, RequestOptions{Query: query, Body: body}, out)
}

func esc(s string) string { return url.PathEscape(s) }
