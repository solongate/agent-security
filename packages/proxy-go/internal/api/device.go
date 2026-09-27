package api

import (
	"context"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Device pairing. Usable from a `login` command and from the dataroom's
// Accounts panel, which is why nothing here prints: the caller renders the
// verify URL and drives the poll loop, so the TUI does not have to fight a
// library writing over its frame.

type DeviceAPI struct{ c *Client }

type DeviceStart struct {
	DeviceCode string
	VerifyURL  string
	Interval   time.Duration
	ExpiresAt  time.Time
}

type DeviceStatus string

const (
	DevicePending  DeviceStatus = "pending"
	DeviceApproved DeviceStatus = "approved"
	DeviceExpired  DeviceStatus = "expired"
	DeviceNotFound DeviceStatus = "not_found"
)

type DevicePoll struct {
	Status DeviceStatus
	// APIKey is only ever set on approval and is the whole point of the flow.
	// It must not be logged.
	APIKey  string
	Project string
	User    string
	Email   string
}

// Start opens a pairing request. It runs BEFORE there is a credential, so it
// passes the URL explicitly rather than resolving one — resolution would fail
// with "not logged in" on exactly the machine that is trying to log in.
func (d DeviceAPI) Start(ctx context.Context, apiURL string) (DeviceStart, error) {
	if apiURL == "" {
		apiURL = config.DefaultAPIURL
	}
	var body struct {
		DeviceCode              string  `json:"device_code"`
		VerificationURIComplete string  `json:"verification_uri_complete"`
		VerificationURI         string  `json:"verification_uri"`
		Interval                float64 `json:"interval"`
		ExpiresIn               float64 `json:"expires_in"`
	}
	err := d.c.Do(ctx, http.MethodPost, "/auth/device/start", RequestOptions{APIURL: apiURL, Anonymous: true}, &body)
	if err != nil {
		return DeviceStart{}, err
	}

	verify := body.VerificationURIComplete
	if verify == "" {
		verify = body.VerificationURI
	}
	// Floors, not defaults: a server that asks for a faster poll than 2s is
	// asking to be rate-limited by its own API.
	interval := body.Interval
	if interval < 2 {
		interval = 3
	}
	expires := body.ExpiresIn
	if expires <= 0 {
		expires = 600
	}
	return DeviceStart{
		DeviceCode: body.DeviceCode,
		VerifyURL:  verify,
		Interval:   time.Duration(interval * float64(time.Second)),
		ExpiresAt:  time.Now().Add(time.Duration(expires * float64(time.Second))),
	}, nil
}

// Poll asks once whether the pairing was approved.
//
// Any failure comes back as pending rather than as an error. The user is in a
// browser during this loop and a dropped Wi-Fi frame or a 502 must not end a
// login they are halfway through; the expiry in DeviceStart is what ends it.
func (d DeviceAPI) Poll(ctx context.Context, apiURL, deviceCode string) DevicePoll {
	if apiURL == "" {
		apiURL = config.DefaultAPIURL
	}
	var body struct {
		Status  string `json:"status"`
		APIKey  string `json:"api_key"`
		Project *struct {
			Name string `json:"name"`
		} `json:"project"`
		User *struct {
			Name  string `json:"name"`
			Email string `json:"email"`
		} `json:"user"`
	}
	err := d.c.Do(ctx, http.MethodPost, "/auth/device/poll", RequestOptions{
		APIURL:    apiURL,
		Anonymous: true,
		Body:      map[string]any{"device_code": deviceCode},
	}, &body)
	if err != nil {
		return DevicePoll{Status: DevicePending}
	}

	if body.Status == "approved" && body.APIKey != "" {
		out := DevicePoll{Status: DeviceApproved, APIKey: body.APIKey}
		if body.Project != nil {
			out.Project = body.Project.Name
		}
		if body.User != nil {
			out.Email = body.User.Email
			out.User = body.User.Name
			if out.User == "" {
				out.User = body.User.Email
			}
		}
		return out
	}
	if body.Status == string(DeviceExpired) || body.Status == string(DeviceNotFound) {
		return DevicePoll{Status: DeviceStatus(body.Status)}
	}
	return DevicePoll{Status: DevicePending}
}

// OpenBrowser is best-effort. A headless box or a missing opener is not a
// failure: the URL is printed either way and the user can open it themselves.
func OpenBrowser(url string) {
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
