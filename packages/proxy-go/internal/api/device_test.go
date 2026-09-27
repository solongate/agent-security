package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Device login runs on a machine that has no credential yet, so it must send no
// credential and must not try to resolve one. A resolution attempt here fails
// with "not logged in" on exactly the machine that is trying to log in.
func TestDeviceLoginNeedsNoCredential(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	var startAuth, pollAuth string
	var seen int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/auth/device/start":
			startAuth = r.Header.Get("Authorization")
			_, _ = w.Write([]byte(`{"device_code":"dc","verification_uri_complete":"https://x/verify?c=dc","interval":1,"expires_in":300}`))
		case "/api/v1/auth/device/poll":
			pollAuth = r.Header.Get("Authorization")
			seen++
			if seen == 1 {
				_, _ = w.Write([]byte(`{"status":"pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"approved","api_key":"sg_live_granted000000000",
			  "project":{"name":"Acme"},"user":{"email":"a@example.com"}}`))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(srv.Close)

	c := New()
	start, err := c.Device.Start(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if startAuth != "" {
		t.Error("device start sent a credential")
	}
	if start.DeviceCode != "dc" || start.VerifyURL != "https://x/verify?c=dc" {
		t.Errorf("start = %+v", start)
	}
	// An interval below 2s is raised, so the flow cannot be told to poll fast
	// enough to be rate-limited by its own API.
	if start.Interval != 3*time.Second {
		t.Errorf("interval = %s, want the 3s floor", start.Interval)
	}
	if !start.ExpiresAt.After(time.Now()) {
		t.Error("expiry is in the past")
	}

	if p := c.Device.Poll(context.Background(), srv.URL, "dc"); p.Status != DevicePending {
		t.Errorf("first poll = %+v, want pending", p)
	}
	p := c.Device.Poll(context.Background(), srv.URL, "dc")
	if p.Status != DeviceApproved || p.APIKey == "" {
		t.Fatalf("second poll = %+v, want approved with a key", p)
	}
	if p.Project != "Acme" || p.Email != "a@example.com" {
		t.Errorf("identity not read: %+v", p)
	}
	// No name in the payload, so the e-mail stands in as the label.
	if p.User != "a@example.com" {
		t.Errorf("user label = %q", p.User)
	}
	if pollAuth != "" {
		t.Error("device poll sent a credential")
	}
}

// A dropped connection mid-login must read as "keep waiting", not as a failed
// login: the user is in a browser and the expiry is what ends the flow.
func TestDevicePollTreatsFailuresAsPending(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	chdirTemp(t)

	if p := New().Device.Poll(context.Background(), "http://127.0.0.1:1", "dc"); p.Status != DevicePending {
		t.Errorf("poll against a dead server = %+v, want pending", p)
	}
}
