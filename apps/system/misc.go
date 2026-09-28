package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
)

// The routes under src/app/api that belong to no group. One is left:
// /v1/github/token.
//
// The care this file exists for is the credential: this route makes the service
// call somebody else's API with a secret of ours, and that secret may never
// reach a log line, an error body or a response — which is a real risk in Go
// specifically, because a failed request wraps the URL in the error.

func init() {
	Register("POST /api/v1/github/token", func(s *server) http.Handler {
		return s.auth.WithAuth(s.githubToken)
	})
}

// outboundClient is the shared client for the third-party calls. Each
// caller sets its own deadline through the request context; the transport
// limits here are what stop a hung TLS handshake from occupying a handler for
// the whole of the server's write budget.
var outboundClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		ExpectContinueTimeout: time.Second,
	},
}

// ── POST /api/v1/github/token ───────────────────────────────────────────────

// githubToken exchanges an OAuth authorization code for an access token.
//
// The exchange has to happen server-side because it needs GITHUB_CLIENT_SECRET,
// and a secret in a dashboard bundle is a secret in every browser that ever
// loaded it. The token this returns belongs to the user who authorised the app;
// it is written into the response and NOWHERE else — not the log, not an error
// body, not a metric.
func (s *server) githubToken(w http.ResponseWriter, r *http.Request, _ apiauth.KeyInfo) {
	clientID := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_ID"))
	clientSecret := strings.TrimSpace(os.Getenv("GITHUB_CLIENT_SECRET"))
	if clientID == "" || clientSecret == "" {
		// 500 rather than 503, as the live route has it. The message names the
		// two variables and nothing about their values.
		apiauth.Error(w, http.StatusInternalServerError, "ERROR",
			"GitHub OAuth not configured (GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET missing)")
		return
	}

	// `.catch(() => ({}))`: an unparseable body becomes an empty one and falls
	// through to the missing-code check below.
	var body struct {
		Code        string `json:"code"`
		RedirectURI string `json:"redirect_uri"`
	}
	if !apiauth.DecodeJSON(w, r, &body, true) {
		return
	}
	code := strings.TrimSpace(body.Code)
	if code == "" {
		apiauth.ValidationError(w, "Missing code")
		return
	}

	payload := map[string]string{
		"client_id":     clientID,
		"client_secret": clientSecret,
		"code":          code,
	}
	// Only sent when present, matching the original's spread. GitHub compares it
	// against the app's registered callback, so a caller-supplied value cannot
	// redirect the token anywhere the app owner has not allowed.
	if body.RedirectURI != "" {
		payload["redirect_uri"] = body.RedirectURI
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token", bytes.NewReader(encoded))
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := outboundClient.Do(req)
	if err != nil {
		// The error is NOT logged and NOT returned. A transport failure in Go
		// carries the request in its message, and this request's body is a
		// client secret; the URL alone is public but the habit is not worth
		// having on this handler.
		log.Print("[API:github-token] the token exchange request failed")
		apiauth.Error(w, http.StatusBadGateway, "ERROR", "GitHub token exchange failed")
		return
	}
	defer resp.Body.Close()

	// GitHub answers this endpoint in a few hundred bytes. The ceiling is here
	// so a redirected or misconfigured host cannot make this handler read an
	// unbounded response into memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		apiauth.Error(w, http.StatusBadGateway, "ERROR", "GitHub token exchange failed")
		return
	}

	var data struct {
		AccessToken      string `json:"access_token"`
		Scope            string `json:"scope"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	// `.catch(() => ({}))` again: an unparseable body leaves every field empty
	// and falls into the failure branch below.
	_ = json.Unmarshal(raw, &data)

	if resp.StatusCode < 200 || resp.StatusCode > 299 || data.Error != "" || data.AccessToken == "" {
		message := data.ErrorDescription
		if message == "" {
			message = data.Error
		}
		if message == "" {
			message = "GitHub token exchange failed"
		}
		apiauth.Error(w, http.StatusBadGateway, "ERROR", message)
		return
	}

	// access_token and scope only. The rest of GitHub's response — refresh
	// tokens, expiries, the token type — is deliberately not forwarded, because
	// the deployed dashboard reads these two and anything else would be a
	// credential travelling further than it has to.
	apiauth.JSON(w, http.StatusOK, map[string]string{
		"access_token": data.AccessToken,
		"scope":        data.Scope,
	})
}
