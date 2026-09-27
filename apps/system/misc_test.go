package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLeftoverRoutesAreClaimed(t *testing.T) {
	for _, pattern := range []string{
		"POST /api/v1/github/token",
		"POST /api/v1/telegram/webhook",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}
}

// The webhook answers 200 to everything, including a request with no secret and
// no body. Telegram retries anything that is not 2xx, so an error status here
// turns one bad update into a retry loop; and a prober learns nothing about
// whether a bot is configured on this deployment.
func TestTelegramWebhookAlwaysAnswersOK(t *testing.T) {
	// TELEGRAM_BOT_TOKEN is not set in the test environment, which is the first
	// early return. The assertion is that it is still a 200 `ok`.
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/telegram/webhook", strings.NewReader("not json"))
	testServer().routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
	}
}

func TestTelegramRecognisesItsCommands(t *testing.T) {
	welcome := []string{"/start", "/help", "/start@SolonGateBot", "/help now"}
	other := []string{"", "hello", "/startle", "/helpful", " /start", "start"}

	for _, text := range welcome {
		if !telegramCommandRe.MatchString(text) {
			t.Errorf("%q should get the welcome message", text)
		}
	}
	for _, text := range other {
		if telegramCommandRe.MatchString(text) {
			t.Errorf("%q should get the short reply", text)
		}
	}
}

// The extension goes into an object key in a publicly served bucket, so it must
// never carry a slash, a dot or anything else that could change the path.
// The uploaded part's content type is copied into an outbound request header.
// A control character in it is request splitting.
func TestIsHeaderSafe(t *testing.T) {
	safe := []string{"image/png", "image/svg+xml", "image/jpeg; charset=binary"}
	unsafe := []string{"", "image/png\r\nX-Injected: 1", "image/png\n", "image/päng", strings.Repeat("a", 256)}

	for _, v := range safe {
		if !isHeaderSafe(v) {
			t.Errorf("%q should be allowed", v)
		}
	}
	for _, v := range unsafe {
		if isHeaderSafe(v) {
			t.Errorf("%q should be refused", v)
		}
	}
}
