package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
)

// The three routes under src/app/api that belong to no group: /v1/github/token,
// /v1/telegram/webhook and /v1/upload.
//
// What they have in common is the only reason they share a file: each one makes
// this service call somebody else's API with a credential of ours, and the
// credential is the thing to be careful with. A GitHub client secret, a Telegram
// bot token and a Cloudflare R2 token pass through here and none of them may
// ever reach a log line, an error body or a response — which is a real risk in
// Go specifically, because a failed request wraps the URL in the error, and two
// of these put the credential in the URL.

func init() {
	Register("POST /api/v1/github/token", func(s *server) http.Handler {
		return s.auth.WithAuth(s.githubToken)
	})
	Register("POST /api/v1/telegram/webhook", func(s *server) http.Handler {
		return http.HandlerFunc(s.telegramWebhook)
	})
}

// outboundClient is the shared client for the three third-party calls. Each
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

// ── POST /api/v1/telegram/webhook ───────────────────────────────────────────

// Telegram's own message texts, verbatim. They are shown to a person setting up
// alerts and the chat id is what they are here to copy.
var telegramWelcome = strings.Join([]string{
	"*Welcome to SolonGate Alerts* 👋",
	"",
	"This bot pings you here when a security signal bursts past a threshold you set (denials, DLP secrets or rate-limit).",
	"",
	"Your chat ID is:\n`%d`",
	"",
	"*Set it up (1 minute):*",
	"1. Copy the chat ID above.",
	"2. Open SolonGate and go to *Alerts*.",
	"3. Add a rule, pick the *Telegram* channel, paste this chat ID, set a threshold and window, then Save.",
	"",
	"That's it. You'll get an alert here whenever your signal bursts.",
}, "\n")

var telegramCommandRe = regexp.MustCompile(`^/(start|help)\b`)

// telegramWebhook is where Telegram delivers messages sent to the bot.
//
// It answers a bare 200 `ok` to EVERYTHING — no token, a wrong secret, a body
// that is not JSON, a message it does not understand. That is deliberate on
// both ends: Telegram retries a webhook that does not return 2xx, so an error
// status turns one bad update into a retry loop; and a prober learns nothing
// about whether a bot is configured here or whether their secret was close.
//
// It is the only route in this service with no API key. The gate is
// TELEGRAM_WEBHOOK_SECRET in a header Telegram sets, compared in constant time.
// If that variable is unset the gate is OPEN — the live route skips the check
// too — and anyone who can guess a chat id can make this service send a message
// to it. Setting the secret is what closes that, and it is worth checking that
// it is set on the deployment rather than assuming.
func (s *server) telegramWebhook(w http.ResponseWriter, r *http.Request) {
	ok := func() {
		// `new Response('ok')` — the Fetch constructor stamps this content type
		// on a string body, and Telegram ignores the body entirely.
		w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}

	token := strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN"))
	if token == "" {
		ok()
		return
	}

	if secret := os.Getenv("TELEGRAM_WEBHOOK_SECRET"); secret != "" {
		presented := r.Header.Get("x-telegram-bot-api-secret-token")
		// Constant time. The comparison is against a shared secret, and a
		// byte-by-byte compare on a value an attacker can send repeatedly is an
		// oracle for guessing it one character at a time.
		if subtle.ConstantTimeCompare([]byte(secret), []byte(presented)) != 1 {
			ok()
			return
		}
	}

	var update struct {
		Message *struct {
			Chat *struct {
				ID *int64 `json:"id"`
			} `json:"chat"`
			Text string `json:"text"`
		} `json:"message"`
		EditedMessage *struct {
			Chat *struct {
				ID *int64 `json:"id"`
			} `json:"chat"`
			Text string `json:"text"`
		} `json:"edited_message"`
	}
	// A body that does not parse leaves `update` zeroed and nothing is sent, as
	// the original's `catch { }` does.
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&update)

	msg := update.Message
	if msg == nil {
		msg = update.EditedMessage
	}
	if msg == nil || msg.Chat == nil || msg.Chat.ID == nil {
		ok()
		return
	}
	chatID := *msg.Chat.ID

	text := telegramWelcome
	if !telegramCommandRe.MatchString(msg.Text) {
		text = "Your chat ID is:\n`%d`\n\nPaste it into SolonGate *Alerts*, *Telegram* channel. Send /start for the full guide."
	}

	// The reply is sent before answering, as the original awaits it. A four
	// second budget, and a failure is swallowed: Telegram would retry the whole
	// update otherwise and the user would get the message twice.
	s.telegramSend(r.Context(), token, chatID, fmt.Sprintf(text, chatID))
	ok()
}

// telegramSend posts one message. Best effort, and silent about why it failed.
//
// The bot token is a path segment of the URL, so the error from a failed
// request contains it. That is why nothing here logs `err` — only that a send
// did not happen. A token in a log file is a bot anybody who reads the log can
// impersonate.
func (s *server) telegramSend(ctx context.Context, token string, chatID int64, text string) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	payload, err := json.Marshal(map[string]any{
		"chat_id":                  chatID,
		"text":                     text,
		"parse_mode":               "Markdown",
		"disable_web_page_preview": true,
	})
	if err != nil {
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(payload))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := outboundClient.Do(req)
	if err != nil {
		log.Printf("[API:telegram] could not deliver a reply to chat %d", chatID)
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
}

// isHeaderSafe rejects a value that cannot go in an HTTP header.
//
// Printable ASCII only: a control character — a carriage return above all — in a
// value copied into an outbound request is request splitting. Go's transport
// would refuse it too, but refusing it here means the caller gets the 400 that
// describes their file rather than a 500 that describes ours.
func isHeaderSafe(v string) bool {
	if v == "" || len(v) > 255 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return false
		}
	}
	return true
}
