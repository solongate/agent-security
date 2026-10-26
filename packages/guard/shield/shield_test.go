// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package shield

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/solongate/agent-security/packages/shared"
)

func shieldWritePolicyFile(t *testing.T, home string, sec *shared.Security) {
	t.Helper()
	dir := filepath.Join(home, ".solongate")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	doc := map[string]interface{}{
		"policy": map[string]interface{}{"id": "p", "name": "n", "mode": "advisory", "rules": map[string]interface{}{}},
	}
	if sec != nil {
		doc["security"] = sec
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "policy.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestShieldCommandArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want []string
	}{
		{"a -- separator splits off the command", []string{"shield", "--", "cmd", "arg1"}, []string{"cmd", "arg1"}},
		{"no separator at all", []string{"shield", "cmd"}, nil},
		{"empty args", nil, nil},
		{"the separator with nothing after it", []string{"shield", "--"}, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := shieldCommandArgs(c.args)
			if len(got) != len(c.want) {
				t.Fatalf("shieldCommandArgs(%v) = %v, want %v", c.args, got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("shieldCommandArgs(%v)[%d] = %q, want %q", c.args, i, got[i], c.want[i])
				}
			}
		})
	}
}

func TestShieldPickUpstream(t *testing.T) {
	t.Run("defaults to the real API when nothing is set", func(t *testing.T) {
		t.Setenv("SOLONGATE_SHIELD_UPSTREAM", "")
		t.Setenv("ANTHROPIC_BASE_URL", "")
		u := shieldPickUpstream()
		if u.Host != "api.anthropic.com" {
			t.Errorf("got host %q, want api.anthropic.com", u.Host)
		}
	})

	t.Run("SOLONGATE_SHIELD_UPSTREAM wins over ANTHROPIC_BASE_URL", func(t *testing.T) {
		t.Setenv("SOLONGATE_SHIELD_UPSTREAM", "https://shield.example.com")
		t.Setenv("ANTHROPIC_BASE_URL", "https://base.example.com")
		u := shieldPickUpstream()
		if u.Host != "shield.example.com" {
			t.Errorf("got host %q, want shield.example.com", u.Host)
		}
	})

	t.Run("ANTHROPIC_BASE_URL is used when the shield var is unset", func(t *testing.T) {
		t.Setenv("SOLONGATE_SHIELD_UPSTREAM", "")
		t.Setenv("ANTHROPIC_BASE_URL", "https://base.example.com")
		u := shieldPickUpstream()
		if u.Host != "base.example.com" {
			t.Errorf("got host %q, want base.example.com", u.Host)
		}
	})

	t.Run("a value with no host falls back to the default", func(t *testing.T) {
		t.Setenv("SOLONGATE_SHIELD_UPSTREAM", "not a url")
		t.Setenv("ANTHROPIC_BASE_URL", "")
		u := shieldPickUpstream()
		if u.Host != "api.anthropic.com" {
			t.Errorf("a hostless value should fall back to the default, got %q", u.Host)
		}
	})
}

func TestShieldRedactBodyWithNoConfig(t *testing.T) {
	body := []byte(`{"messages":[{"role":"user","content":"AKIA` + "IOSFODNN7EXAMPLE" + `"}]}`)
	if got := shieldRedactBody(body, nil); !bytes.Equal(got, body) {
		t.Errorf("a nil config changed the body: %s", got)
	}
}

func TestShieldRedactBodyWithInvalidJSON(t *testing.T) {
	cfg := &shared.DLPConfig{Patterns: []string{"AWS access key"}}
	body := []byte(`not json at all`)
	if got := shieldRedactBody(body, cfg); !bytes.Equal(got, body) {
		t.Errorf("invalid JSON was altered: %s", got)
	}
}

func TestShieldRedactBodyLeavesAssistantMessagesAlone(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	cfg := &shared.DLPConfig{Patterns: []string{"AWS access key"}}

	body := []byte(`{"system":"sys ` + secret + `","messages":[` +
		`{"role":"user","content":"user says ` + secret + `"},` +
		`{"role":"assistant","content":"assistant says ` + secret + `"}` +
		`]}`)

	out := shieldRedactBody(body, cfg)

	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("the redacted body is not valid JSON: %v (%s)", err, out)
	}

	if sys, _ := parsed["system"].(string); strings.Contains(sys, secret) || !strings.Contains(sys, "[REDACTED:") {
		t.Errorf("the system field was not redacted: %q", sys)
	}

	msgs, _ := parsed["messages"].([]interface{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(msgs))
	}
	user := msgs[0].(map[string]interface{})
	if c, _ := user["content"].(string); strings.Contains(c, secret) {
		t.Errorf("the user message was not redacted: %q", c)
	}
	assistant := msgs[1].(map[string]interface{})
	if c, _ := assistant["content"].(string); !strings.Contains(c, secret) {
		t.Errorf("the assistant message was redacted, but outbound assistant content must be left alone: %q", c)
	}
}

func TestShieldRedactBodyWithNoMessagesField(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	cfg := &shared.DLPConfig{Patterns: []string{"AWS access key"}}
	body := []byte(`{"foo":"bar ` + secret + `"}`)

	out := shieldRedactBody(body, cfg)
	var parsed map[string]interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v (%s)", err, out)
	}
	if foo, _ := parsed["foo"].(string); strings.Contains(foo, secret) {
		t.Errorf("a body with no messages array was not deep-redacted: %q", foo)
	}
}

func TestShieldRedactBodyWithANonObjectTopLevel(t *testing.T) {
	secret := "AKIA" + "IOSFODNN7EXAMPLE"
	cfg := &shared.DLPConfig{Patterns: []string{"AWS access key"}}
	body := []byte(`["` + secret + `","clean"]`)

	out := shieldRedactBody(body, cfg)
	var parsed []interface{}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("not valid JSON: %v (%s)", err, out)
	}
	if len(parsed) != 2 {
		t.Fatalf("expected 2 elements, got %d", len(parsed))
	}
	if s, _ := parsed[0].(string); strings.Contains(s, secret) {
		t.Errorf("a top-level array was not deep-redacted: %q", s)
	}
	if s, _ := parsed[1].(string); s != "clean" {
		t.Errorf("an unrelated array element was altered: %q", s)
	}
}

func TestShieldLoadDLPConfigWithNoLocalPolicy(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	cfg := shieldLoadDLPConfig()
	if cfg == nil || len(cfg.Patterns) == 0 {
		t.Fatalf("with no local policy, the defaults should apply, got %+v", cfg)
	}
	if len(cfg.Patterns) != len(shared.DLPPatternNames()) {
		t.Errorf("the defaults should be every known pattern, got %d of %d", len(cfg.Patterns), len(shared.DLPPatternNames()))
	}
}

func TestShieldLoadDLPConfigPrefersRedactOverBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shieldWritePolicyFile(t, home, &shared.Security{
		DLPRedact: &shared.DLPConfig{Patterns: []string{"AWS access key"}},
		DLPBlock:  &shared.DLPConfig{Patterns: []string{"GitHub token"}},
	})
	cfg := shieldLoadDLPConfig()
	if cfg == nil || len(cfg.Patterns) != 1 || cfg.Patterns[0] != "AWS access key" {
		t.Errorf("DLPRedact should win over DLPBlock, got %+v", cfg)
	}
}

func TestShieldLoadDLPConfigFallsBackToBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shieldWritePolicyFile(t, home, &shared.Security{
		DLPBlock: &shared.DLPConfig{Patterns: []string{"GitHub token"}},
	})
	cfg := shieldLoadDLPConfig()
	if cfg == nil || len(cfg.Patterns) != 1 || cfg.Patterns[0] != "GitHub token" {
		t.Errorf("with no DLPRedact, DLPBlock should be used, got %+v", cfg)
	}
}

func TestShieldLoadDLPConfigReturnsNilWhenOnlyObserveIsConfigured(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shieldWritePolicyFile(t, home, &shared.Security{
		DLPObserve: &shared.DLPConfig{Patterns: []string{"Slack token"}},
	})
	if cfg := shieldLoadDLPConfig(); cfg != nil {
		t.Errorf("an observe-only policy must not redact outbound traffic, got %+v", cfg)
	}
}

func TestShieldLoadDLPConfigFallsBackToDefaultsWithEmptySecurity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	shieldWritePolicyFile(t, home, &shared.Security{})
	cfg := shieldLoadDLPConfig()
	if cfg == nil || len(cfg.Patterns) != len(shared.DLPPatternNames()) {
		t.Errorf("an empty security block should fall back to the defaults, got %+v", cfg)
	}
}

func TestShieldProxyHandlerForwardsAndRedacts(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	secret := "AKIA" + "IOSFODNN7EXAMPLE"

	var gotPath, gotQuery, gotHost string
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotHost = r.Host
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler := shieldProxyHandler(upstreamURL)

	reqBody := []byte(`{"messages":[` +
		`{"role":"user","content":"my key ` + secret + `"},` +
		`{"role":"assistant","content":"my key ` + secret + `"}` +
		`]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/messages?foo=bar", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusTeapot {
		t.Errorf("status code = %d, want %d", rec.Code, http.StatusTeapot)
	}
	if rec.Header().Get("X-Upstream") != "yes" {
		t.Error("the upstream response header was not relayed back")
	}
	if rec.Body.String() != `{"ok":true}` {
		t.Errorf("the upstream response body was not relayed back, got %q", rec.Body.String())
	}

	if gotPath != "/v1/messages" {
		t.Errorf("upstream saw path %q, want /v1/messages", gotPath)
	}
	if gotQuery != "foo=bar" {
		t.Errorf("upstream saw query %q, want foo=bar", gotQuery)
	}
	if gotHost != upstreamURL.Host {
		t.Errorf("upstream saw Host %q, want %q", gotHost, upstreamURL.Host)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("the body the upstream received is not valid JSON: %v (%s)", err, gotBody)
	}
	msgs, _ := parsed["messages"].([]interface{})
	if len(msgs) != 2 {
		t.Fatalf("expected 2 messages to reach the upstream, got %d", len(msgs))
	}
	user := msgs[0].(map[string]interface{})
	if c, _ := user["content"].(string); strings.Contains(c, secret) {
		t.Errorf("the secret in the user message reached the upstream unredacted: %q", c)
	}
	assistant := msgs[1].(map[string]interface{})
	if c, _ := assistant["content"].(string); !strings.Contains(c, secret) {
		t.Errorf("the assistant message should pass through unredacted, got %q", c)
	}
}

func TestShieldProxyHandlerSkipsRedactionForNonJSONBodies(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	secret := "AKIA" + "IOSFODNN7EXAMPLE"

	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler := shieldProxyHandler(upstreamURL)

	req := httptest.NewRequest(http.MethodPost, "/anything", strings.NewReader(secret))
	req.Header.Set("Content-Type", "text/plain")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if !strings.Contains(string(gotBody), secret) {
		t.Errorf("a non-JSON body should pass through untouched, got %q", gotBody)
	}
}

func TestShieldRunChildReturnsTheExitCode(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want int
	}{
		{"a clean exit", []string{"true"}, 0},
		{"a non-zero exit", []string{"false"}, 1},
		{"a specific exit code", []string{"sh", "-c", "exit 42"}, 42},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shieldRunChild(c.args, ""); got != c.want {
				t.Errorf("shieldRunChild(%v) = %d, want %d", c.args, got, c.want)
			}
		})
	}
}

func TestShieldRunChildReportsSignalDeathsAbove128(t *testing.T) {
	got := shieldRunChild([]string{"sh", "-c", "kill -TERM $$"}, "")
	if got != 128+15 {
		t.Errorf("a process that killed itself with SIGTERM should report %d, got %d", 128+15, got)
	}
}