package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/codeyevsky/solongate/api/internal/store"
)

func TestProjectSessionToolRoutesAreClaimed(t *testing.T) {
	for _, pattern := range []string{
		"GET /api/v1/projects",
		"GET /api/v1/projects/{id}",
		"PUT /api/v1/projects/{id}",
		"DELETE /api/v1/projects/{id}",
		"GET /api/v1/project-config",
		"GET /api/v1/sessions",
		"DELETE /api/v1/sessions",
		"GET /api/v1/sessions/{id}",
		"GET /api/v1/tools",
		"POST /api/v1/tools",
		"GET /api/v1/tools/{name}",
		"PUT /api/v1/tools/{name}",
		"DELETE /api/v1/tools/{name}",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}
}

// The list's `owner_name` is what the project selector labels a row with, and
// the fallback chain is what keeps it from saying "undefined" for an account
// that never set a display name.
func TestProjectListOwnerLabelFallsBack(t *testing.T) {
	name, email, empty := "Ada", "ada@example.com", ""
	cases := []struct {
		name  *string
		email *string
		want  string
	}{
		{&name, &email, "Ada"},
		{nil, &email, "ada@example.com"},
		{&empty, &email, "ada@example.com"},
		{nil, nil, "Unknown"},
		{&empty, &empty, "Unknown"},
	}
	for _, c := range cases {
		got := projectToListView(store.ProjectListRow{OwnerName: c.name, OwnerEmail: c.email})
		if got.OwnerLabel != c.want {
			t.Errorf("owner_name = %q, want %q", got.OwnerLabel, c.want)
		}
	}
}

// A NULL column is null on the wire. The dashboard branches on
// `description === null`, and a project with no description has read as null
// for as long as this endpoint has existed.
func TestProjectViewKeepsNullsNull(t *testing.T) {
	raw, err := json.Marshal(projectToView(store.ProjectRow{ID: "p1", Name: "Demo", Slug: "demo"}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"description", "orgId", "piEnabled", "piThreshold",
		"piMode", "piWhitelist", "piToolConfig", "piCustomPatterns", "piWebhookUrl"} {
		v, present := got[field]
		if !present {
			t.Errorf("%s is missing from the response", field)
			continue
		}
		if v != nil {
			t.Errorf("%s = %v, want null for a NULL column", field, v)
		}
	}
	// The timestamps are ISO-8601, not integers; see store.ISO.
	if got["createdAt"] != "1970-01-01T00:00:00.000Z" {
		t.Errorf("createdAt = %v, want an ISO-8601 instant", got["createdAt"])
	}
}

func TestPiThresholdClampsAndKeepsNaNNull(t *testing.T) {
	cases := []struct {
		json string
		want *float64
	}{
		{`0.25`, ptr(0.25)},
		{`"0.9"`, ptr(0.9)},
		{`-3`, ptr(0)},
		{`7`, ptr(1)},
		{`true`, ptr(1)},
		{`null`, ptr(0)}, // Number(null) is 0.
		// Number("abc") is NaN, which the live route writes and SQLite stores as
		// NULL. nil is how that column value is reproduced.
		{`"abc"`, nil},
	}
	for _, c := range cases {
		got := piThreshold(json.RawMessage(c.json))
		switch {
		case c.want == nil && got != nil:
			t.Errorf("piThreshold(%s) = %v, want nil (NaN becomes NULL)", c.json, *got)
		case c.want != nil && got == nil:
			t.Errorf("piThreshold(%s) = nil, want %v", c.json, *c.want)
		case c.want != nil && *got != *c.want:
			t.Errorf("piThreshold(%s) = %v, want %v", c.json, *got, *c.want)
		}
	}
}

func ptr(f float64) *float64 { return &f }

func TestPiModeIsAClosedSet(t *testing.T) {
	cases := map[string]string{
		`"block"`:    "block",
		`"log-only"`: "log-only",
		`"BLOCK"`:    "block", // includes() is case-sensitive, so this is not a mode.
		`"nonsense"`: "block",
		`null`:       "block",
		`1`:          "block",
	}
	for in, want := range cases {
		if got := piMode(json.RawMessage(in)); got != want {
			t.Errorf("piMode(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestStoredJSONColumnsFallBack(t *testing.T) {
	if got := string(storedJSON("", "[]")); got != "[]" {
		t.Errorf("empty column = %s, want []", got)
	}
	// arguments the settings form wrote before it validated them: not JSON.
	if got := string(storedJSON("{truncated", "{}")); got != "{}" {
		t.Errorf("unparseable column = %s, want {}", got)
	}
	if got := string(storedJSON(`["a"]`, "[]")); got != `["a"]` {
		t.Errorf("stored column = %s, want it passed through", got)
	}
}

// JSON.stringify semantics, which is why policyjson does the serialising: key
// order survives and < > & are not escaped. A re-ordered piToolConfig is a diff
// on every save of a setting nobody touched.
func TestPiColumnsSerialiseLikeJSONStringify(t *testing.T) {
	if got := stringifyObjectOrEmpty(json.RawMessage(`{"z":1,"a":2}`)); got != `{"z":1,"a":2}` {
		t.Errorf("piToolConfig = %s, want the key order preserved", got)
	}
	if got := stringifyObjectOrEmpty(json.RawMessage(`null`)); got != "{}" {
		t.Errorf("falsy piToolConfig = %s, want {}", got)
	}
	if got := stringifyArrayOrEmpty(json.RawMessage(`["<b>&x</b>"]`)); got != `["<b>&x</b>"]` {
		t.Errorf("piWhitelist = %s, want no HTML escaping", got)
	}
	if got := stringifyArrayOrEmpty(json.RawMessage(`{"a":1}`)); got != "[]" {
		t.Errorf("non-array piWhitelist = %s, want []", got)
	}
}

func TestPiCustomPatternsNormalises(t *testing.T) {
	rec := httptest.NewRecorder()
	got, ok := piCustomPatterns(rec, json.RawMessage(
		`[{"extra":1,"pattern":"AKIA[0-9]+","weight":0,"name":""},"loose",{"pattern":"x","weight":9}]`))
	if !ok {
		t.Fatalf("refused a valid list: %s", rec.Body.String())
	}
	want := `[{"extra":1,"pattern":"AKIA[0-9]+","weight":0.5,"name":"custom"},"loose",` +
		`{"pattern":"x","weight":1,"name":"custom"}]`
	if got != want {
		t.Errorf("patterns = %s\nwant       %s", got, want)
	}
}

func TestPiCustomPatternsRefusals(t *testing.T) {
	long := `[{"pattern":"`
	for i := 0; i < 513; i++ {
		long += "a"
	}
	long += `"}]`

	cases := []struct {
		name string
		body string
		want string
	}{
		{"too long", long, "Regex pattern too long (max 512 chars)"},
		{"unparseable", `[{"pattern":"foo("}]`, "Invalid regex pattern: foo("},
		// The scanner runs this over every argument of every call, so a pattern
		// that backtracks is a denial of service with a valid key attached.
		{"nested quantifiers", `[{"pattern":"(a+)+b"}]`, "Unsafe regex pattern (nested quantifiers): (a+)+b"},
	}
	for _, c := range cases {
		rec := httptest.NewRecorder()
		if _, ok := piCustomPatterns(rec, json.RawMessage(c.body)); ok {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if rec.Code != 400 {
			t.Errorf("%s: status = %d, want 400", c.name, rec.Code)
		}
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body is not JSON: %v", c.name, err)
		}
		if body.Error.Message != c.want {
			t.Errorf("%s: message = %q, want %q", c.name, body.Error.Message, c.want)
		}
		if body.Error.Code != "ERROR" {
			t.Errorf("%s: code = %q, want ERROR (errorResponse's default)", c.name, body.Error.Code)
		}
	}
}

// The webhook is fetched by this service, from inside its own network. The host
// list is the only thing between that and a caller reading the cloud metadata
// endpoint through it.
func TestPiWebhookURLRefusesPrivateTargets(t *testing.T) {
	refused := []string{
		"http://example.com/hook",
		"https://169.254.169.254/latest/meta-data",
		"https://metadata.google.internal/x",
		"https://10.1.2.3/hook",
		"https://192.168.0.1/hook",
		"https://172.16.0.1/hook",
		"https://localhost/hook",
		"https://127.0.0.1/hook",
		"https://[fd00::1]/hook",
		"https://svc.internal/hook",
		"https://printer.local/hook",
		"not a url",
	}
	for _, target := range refused {
		rec := httptest.NewRecorder()
		body, _ := json.Marshal(target)
		if _, ok := piWebhookURL(rec, body); ok {
			t.Errorf("%s was accepted", target)
		}
		if rec.Code != 400 {
			t.Errorf("%s: status = %d, want 400", target, rec.Code)
		}
	}

	// A falsy value clears the column rather than failing.
	rec := httptest.NewRecorder()
	got, ok := piWebhookURL(rec, json.RawMessage(`null`))
	if !ok || got != nil {
		t.Errorf("null = (%v, %v), want (nil, true) — the column is cleared", got, ok)
	}

	// `new URL(x).toString()` lowercases the host and gives an empty path a "/".
	rec = httptest.NewRecorder()
	got, ok = piWebhookURL(rec, json.RawMessage(`"HTTPS://Hooks.Example.COM"`))
	if !ok {
		t.Fatalf("rejected a public https URL: %s", rec.Body.String())
	}
	if *got != "https://hooks.example.com/" {
		t.Errorf("stored = %q, want the WHATWG normalisation", *got)
	}
}
