package api

import (
	"context"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The device grant end to end against a REAL provider.
//
// Everything before this ran against a stub that answered the way the
// specification says. This drives Keycloak: its discovery document, its device
// endpoint, its login and consent pages, and its token endpoint — and then the
// product's own /auth/session, so the whole path from "somebody types a code"
// to "this machine holds a credential" is exercised once against software that
// did not read the same specification we did.
//
// Skipped unless SG_TEST_SYSTEM names a running system. It is not part of the
// suite: it needs two containers.
func TestDeviceGrantAgainstRealKeycloak(t *testing.T) {
	svc := os.Getenv("SG_TEST_SYSTEM")
	if svc == "" {
		t.Skip("SG_TEST_SYSTEM is not set; this needs a running system and provider")
	}

	c := New()
	start, err := c.Device.Start(context.Background(), svc)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Logf("user_code = %s", start.UserCode)
	t.Logf("verify    = %s", start.VerifyURLPlain)
	t.Logf("complete  = %s", start.VerifyURL)
	t.Logf("interval  = %s", start.Interval)

	if start.UserCode == "" {
		t.Fatal("no user code")
	}
	// Keycloak offers both forms and they must be told apart: the complete one
	// carries the code, the plain one is what a person reads out loud.
	if !strings.Contains(start.VerifyURL, start.UserCode) {
		t.Errorf("the complete URL does not carry the code: %s", start.VerifyURL)
	}
	if strings.Contains(start.VerifyURLPlain, start.UserCode) {
		t.Errorf("the plain URL carries the code: %s", start.VerifyURLPlain)
	}

	// Nobody has approved it yet. This is the state the flow spends most of its
	// life in, and the provider signals it with a 400 — so it is the assertion
	// that the non-2xx decode is right.
	if p := c.Device.Poll(context.Background(), svc, start); p.Status != DevicePending {
		t.Fatalf("unapproved poll = %s (%q), want pending", p.Status, p.Message)
	}

	// ── be the person at the browser ────────────────────────────────────────
	jar, _ := cookiejar.New(nil)
	browser := &http.Client{Jar: jar}
	approveWithKeycloak(t, browser, start.VerifyURL)

	// ── and now the CLI should finish ───────────────────────────────────────
	//
	// WAITING THE INTERVAL IS PART OF THE PROTOCOL, and Keycloak enforces it:
	// polling again inside it answers `slow_down`, which this maps to pending
	// and which a caller that ignored the interval would spin on forever. Both
	// callers do respect it — tea.Tick in the Go dataroom, setTimeout in the
	// TypeScript one — so this waits the way they do.
	time.Sleep(start.Interval + time.Second)

	p := c.Device.Poll(context.Background(), svc, start)
	if p.Status != DeviceApproved {
		t.Fatalf("approved poll = %s (%q), want approved", p.Status, p.Message)
	}
	if p.APIKey == "" {
		t.Fatal("approved without a credential")
	}
	if !strings.HasPrefix(p.APIKey, "sg_live_") && !strings.HasPrefix(p.APIKey, "sg_test_") {
		t.Errorf("the credential is not a SolonGate key")
	}
	// The address came out of the token Keycloak signed, through the claims the
	// system read — not out of anything this process asserted.
	if p.Email != "ada@example.com" {
		t.Errorf("email = %q, want the address from the provider's claims", p.Email)
	}
	t.Logf("approved: project=%q user=%q email=%q key=%s…", p.Project, p.User, p.Email, p.APIKey[:12])
}

var (
	reAction = regexp.MustCompile(`action="([^"]*)"`)
	reCode   = regexp.MustCompile(`name="code"\s+value="([^"]*)"`)
)

// approveWithKeycloak signs in and consents, the way a person would.
func approveWithKeycloak(t *testing.T, browser *http.Client, verifyURL string) {
	t.Helper()

	page, base := get(t, browser, verifyURL)
	loginAction := absolute(t, base, firstAction(t, page, "authenticate"))

	page, base = post(t, browser, loginAction, url.Values{
		"username": {"ada"},
		"password": {"hunter2"},
	})

	// A first sign-in shows consent; a later one may not.
	consent := firstAction(t, page, "consent")
	if consent == "" {
		t.Log("no consent screen; already granted")
		return
	}
	form := url.Values{"accept": {"Yes"}}
	if m := reCode.FindStringSubmatch(page); m != nil {
		form.Set("code", m[1])
	}
	post(t, browser, absolute(t, base, consent), form)
}

func firstAction(t *testing.T, page, contains string) string {
	t.Helper()
	for _, m := range reAction.FindAllStringSubmatch(page, -1) {
		if strings.Contains(m[1], contains) {
			return html.UnescapeString(m[1])
		}
	}
	return ""
}

func absolute(t *testing.T, base *url.URL, ref string) string {
	t.Helper()
	if ref == "" {
		t.Fatal("no form action to follow")
	}
	u, err := url.Parse(ref)
	if err != nil {
		t.Fatal(err)
	}
	return base.ResolveReference(u).String()
}

func get(t *testing.T, c *http.Client, u string) (string, *url.URL) {
	t.Helper()
	res, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b), res.Request.URL
}

func post(t *testing.T, c *http.Client, u string, form url.Values) (string, *url.URL) {
	t.Helper()
	res, err := c.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return string(b), res.Request.URL
}
