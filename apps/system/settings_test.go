package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The settings slice's tests.
//
// They cover the coercions rather than the SQL, because the coercions are where
// this slice can be wrong in a way that reads as working: a rule stored with a
// window of thirty seconds instead of five minutes still saves, still lists and
// still fires — just ten times as often as the person who set it asked for.

// TestSettingsRoutesAreClaimed is the first thing to fail if a method is
// dropped in a merge. Every path in the table under /v1/settings has to be
// served by this slice; a stub left behind answers 501 to a dashboard that has
// no other way to reach the setting.
func TestSettingsRoutesAreClaimed(t *testing.T) {
	for _, rt := range routes {
		if len(rt.path) < 17 || rt.path[:17] != "/api/v1/settings/" {
			continue
		}
		for _, m := range rt.methods {
			if _, ok := routeHandlers[m+" "+rt.path]; !ok {
				t.Errorf("%s %s is still a stub", m, rt.path)
			}
		}
	}
}

// Every one of these routes is withAuth in the live app. A settings endpoint
// that answered without a key would publish a project's DLP patterns, its
// webhook URLs and whether its tamper guard is on.
func TestSettingsRoutesRefuseWithoutAKey(t *testing.T) {
	srv := testServer().routes()
	for _, probe := range []struct{ method, path string }{
		{"GET", "/api/v1/settings/security-layers"},
		{"PUT", "/api/v1/settings/security-layers"},
		{"GET", "/api/v1/settings/self-protection"},
		{"PUT", "/api/v1/settings/self-protection"},
		{"GET", "/api/v1/settings/local-logs"},
		{"PUT", "/api/v1/settings/local-logs"},
		{"GET", "/api/v1/settings/local-logs-view"},
		{"PUT", "/api/v1/settings/local-logs-view"},
		{"GET", "/api/v1/settings/guard-status"},
		{"GET", "/api/v1/settings/rate-limit-history"},
		{"DELETE", "/api/v1/settings/rate-limit-history"},
		{"GET", "/api/v1/settings/denial-webhook"},
		{"POST", "/api/v1/settings/denial-webhook"},
		{"PATCH", "/api/v1/settings/denial-webhook"},
		{"DELETE", "/api/v1/settings/denial-webhook"},
		{"POST", "/api/v1/settings/denial-webhook/send-test"},
		{"GET", "/api/v1/settings/denial-alerts"},
		{"POST", "/api/v1/settings/denial-alerts"},
		{"PATCH", "/api/v1/settings/denial-alerts"},
		{"DELETE", "/api/v1/settings/denial-alerts"},
	} {
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, httptest.NewRequest(probe.method, probe.path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s = %d, want 401", probe.method, probe.path, rec.Code)
		}
	}
}

// parseInt is not strconv.ParseInt, and a stricter reading would answer 400
// where the deployed dashboard gets a 200.
func TestJSParseInt10(t *testing.T) {
	cases := []struct {
		in   string
		want int64
		ok   bool
	}{
		{"1785697770423", 1785697770423, true},
		{"  42  ", 42, true},
		{"42abc", 42, true},
		{"-7", -7, true},
		{"+7", 7, true},
		{"0x10", 0, true}, // radix 10: parsing stops at the x
		{"", 0, false},
		{"abc", 0, false},
		{"-", 0, false},
		{"1e3", 1, true}, // parseInt does not read exponents
	}
	for _, c := range cases {
		got, ok := jsParseInt10(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("jsParseInt10(%q) = (%d,%v), want (%d,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// An absent field and an explicit null are different answers, and the
// difference is a factor of ten on how often an alert is allowed to fire.
func TestAlertClampFieldDistinguishesAbsentFromNull(t *testing.T) {
	absent := map[string]any{}
	if got := alertClampField(absent, "windowSeconds", alertWindowMin, alertWindowMax, alertWindowDefault); got != 300 {
		t.Errorf("absent windowSeconds = %d, want the default 300", got)
	}

	null := map[string]any{"windowSeconds": nil}
	if got := alertClampField(null, "windowSeconds", alertWindowMin, alertWindowMax, alertWindowDefault); got != 30 {
		t.Errorf("null windowSeconds = %d, want the minimum 30 — Number(null) is 0", got)
	}

	cases := []struct {
		value any
		want  int64
	}{
		{float64(1000), 100},  // above the ceiling
		{float64(1), 5},       // below the floor
		{"7", 7},              // a text input's string
		{"nonsense", 5},       // NaN takes the default
		{float64(7.9), 7},     // Math.floor, not round
		{true, 5},             // Number(true) is 1, clamped to the floor
		{map[string]any{}, 5}, // NaN again
	}
	for _, c := range cases {
		got := alertClampField(map[string]any{"threshold": c.value},
			"threshold", alertThresholdMin, alertThresholdMax, alertThresholdDefault)
		if got != c.want {
			t.Errorf("threshold %#v = %d, want %d", c.value, got, c.want)
		}
	}
}

// The targets are what this service will send to, so what is refused matters
// more than what is accepted.
func TestAlertTargetSanitising(t *testing.T) {
	urls := alertSanitizeURLs([]any{"  https://hooks.slack.com/a  ", "https://hooks.slack.com/b"}, nil)
	if len(urls) != 1 || urls[0] != "https://hooks.slack.com/a" {
		t.Errorf("urls = %v, want one trimmed target", urls)
	}
	if got := alertSanitizeURLs([]any{"ftp://x", "javascript:alert(1)", "/relative", 5}, nil); got != nil {
		t.Errorf("urls = %v, want nothing that is not http(s)", got)
	}
	// The legacy single-URL field is still honoured, and only when the array is
	// absent: a client that has not been redeployed sends it.
	if got := alertSanitizeURLs(nil, "https://hooks.slack.com/legacy"); len(got) != 1 {
		t.Errorf("legacy slackUrl = %v, want it kept", got)
	}
	if got := alertSanitizeURLs([]any{"https://hooks.slack.com/array"}, "https://hooks.slack.com/legacy"); got[0] != "https://hooks.slack.com/array" {
		t.Errorf("urls = %v, want the array to win over the legacy field", got)
	}

	if got := alertSanitizeEmails([]any{"ada@example.com", "ada@example.com", "two@example.com"}); len(got) != 1 {
		t.Errorf("emails = %v, want one target after de-duplication", got)
	}
	if got := alertSanitizeEmails([]any{"not an address", "@example.com", "a@b"}); got != nil {
		t.Errorf("emails = %v, want none of those", got)
	}
	if got := alertSanitizeEmails("ada@example.com"); got != nil {
		t.Errorf("emails = %v, want nothing for a non-array", got)
	}

	// A chat id arrives as a JSON number often enough that refusing it would be
	// a rule that silently never delivers.
	if got := alertSanitizeTelegram([]any{float64(-1001234567890)}); len(got) != 1 || got[0] != "-1001234567890" {
		t.Errorf("telegram = %v, want the numeric chat id stringified", got)
	}
	if got := alertSanitizeTelegram("@channelname"); len(got) != 1 {
		t.Errorf("telegram = %v, want a bare value accepted", got)
	}
	if got := alertSanitizeTelegram([]any{"@abc", "12", "hello", ""}); got != nil {
		t.Errorf("telegram = %v, want neither a short handle nor a short id", got)
	}
}

// The route's own check runs on the RAW body and a truthy slackUrl passes it,
// even one that sanitises to nothing. That asymmetry is the live behaviour and
// tightening it would 400 a request the dashboard currently gets a 200 for.
func TestAlertBodyHasChannel(t *testing.T) {
	yes := []map[string]any{
		{"slackUrl": "not even a url"},
		{"slackUrls": []any{"https://x"}},
		{"emails": []any{"a@b.c"}},
		{"telegram": []any{"@name"}},
	}
	no := []map[string]any{
		{},
		{"slackUrl": ""},
		{"slackUrls": []any{}},
		{"emails": []any{}},
		{"telegram": "@name"}, // the raw check wants an array here
		{"name": "an alert with nowhere to go"},
	}
	for _, body := range yes {
		if !alertBodyHasChannel(body) {
			t.Errorf("%v should pass the channel check", body)
		}
	}
	for _, body := range no {
		if alertBodyHasChannel(body) {
			t.Errorf("%v should be refused", body)
		}
	}
}

// One rule per channel, in this precedence.
func TestAlertChannelOf(t *testing.T) {
	cases := []struct {
		rule alertRule
		want string
	}{
		{alertRule{Telegram: []string{"@a"}, Emails: []string{"a@b.c"}}, "telegram"},
		{alertRule{Emails: []string{"a@b.c"}, SlackURLs: []string{"https://x"}}, "email"},
		{alertRule{SlackURLs: []string{"https://x"}}, "slack"},
		{alertRule{}, ""},
	}
	for _, c := range cases {
		if got := alertChannelOf(c.rule); got != c.want {
			t.Errorf("channelOf(%+v) = %q, want %q", c.rule, got, c.want)
		}
	}
}

// A stored header value is a credential. The mask is fixed-width so it does not
// even publish the length of the token behind it.
func TestWebhookHeadersAreRedacted(t *testing.T) {
	got := redactHeaderValues(map[string]string{"Authorization": "Bearer a-very-long-token", "X-Short": "a"})
	if len(got) != 2 {
		t.Fatalf("redacted = %v, want both names kept", got)
	}
	if got["Authorization"] != got["X-Short"] {
		t.Error("the mask must not vary with the value's length")
	}
	if got["Authorization"] == "Bearer a-very-long-token" {
		t.Error("the value survived redaction")
	}
	if redactHeaderValues(nil) != nil {
		t.Error("no headers must stay absent, not become an empty object")
	}
}

// Anything unrecognised means denials: a typo delivers LESS than intended
// rather than shipping every allowed call to a third party.
func TestCoerceWebhookEvents(t *testing.T) {
	for _, in := range []any{nil, "", "denials", "bogus", 5, true, "ALL"} {
		if got := coerceWebhookEvents(in); got != "denials" {
			t.Errorf("events %#v = %q, want denials", in, got)
		}
	}
	for _, in := range []string{"all", "allowed"} {
		if got := coerceWebhookEvents(in); got != in {
			t.Errorf("events %q = %q, want it kept", in, got)
		}
	}
}

// guard-status answers "is the guard registered", which is what `doctor` and
// `repair` answer. A device that reports a client list is believed about its own
// files; one that reports none falls back to the older "has called in" signal,
// so an un-updated machine degrades to a weaker answer rather than to "missing".
func TestGuardRegisteredPrefersTheReportedClients(t *testing.T) {
	devices := []guardDevice{
		{ID: "new", Clients: []string{"claude-code"}, Agents: map[string]int64{"codex": 5}},
		{ID: "old", Agents: map[string]int64{"antigravity": 9}},
	}

	if !guardRegistered(devices, "claude-code") {
		t.Error("a client in a device's reported list is registered")
	}
	if guardRegistered(devices, "codex") {
		t.Error("a device that reports its clients must not fall back to agents: the user removed codex")
	}
	if !guardRegistered(devices, "antigravity") {
		t.Error("a device with no reported list falls back to agents")
	}
	if guardRegistered(devices, "opencode") {
		t.Error("nothing reported opencode")
	}

	// last_seen comes from `agents` whatever `clients` says, and is null for a
	// client that is registered but has never run.
	if got := guardLastSeen(devices, "claude-code"); got != nil {
		t.Errorf("last_seen = %v, want null for a client that has not called in", got)
	}
	if got := guardLastSeen(devices, "antigravity"); got == nil || *got != 9 {
		t.Errorf("last_seen = %v, want 9", got)
	}
}

// The response's optional members have to be absent rather than null: the
// settings page tests for the key, and `"telegram":null` is not an empty list.
func TestAlertRuleOmitsTheChannelsItHasNot(t *testing.T) {
	enabled := true
	b, err := marshalNoEscape(alertRule{
		ID: "r1", Name: "Alert", Enabled: &enabled, Threshold: 5, WindowSeconds: 300,
		Signal: "any", SlackURLs: []string{"https://hooks.slack.com/a"}, CreatedAt: "1970-01-01T00:00:00.000Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"emails", "telegram", "denyLayers", "toolPatterns", "lastTriggeredAt"} {
		if _, present := got[absent]; present {
			t.Errorf("%q should be omitted when it is empty", absent)
		}
	}
	for _, required := range []string{"id", "name", "enabled", "threshold", "windowSeconds", "signal", "createdAt"} {
		if _, present := got[required]; !present {
			t.Errorf("%q is part of the stored shape and must always be written", required)
		}
	}
}
