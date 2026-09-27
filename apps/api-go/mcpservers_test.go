package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeyevsky/solongate/api/internal/store"
)

func TestMcpRoutesAreClaimed(t *testing.T) {
	for _, pattern := range []string{
		"GET /api/v1/mcp-servers",
		"POST /api/v1/mcp-servers",
		"POST /api/v1/mcp-servers/check",
		"GET /api/v1/mcp-servers/{id}",
		"PUT /api/v1/mcp-servers/{id}",
		"DELETE /api/v1/mcp-servers/{id}",
	} {
		if _, ok := routeHandlers[pattern]; !ok {
			t.Errorf("%s is not registered", pattern)
		}
	}
}

// /mcp-servers/check is a literal path and /mcp-servers/{id} is a wildcard. If
// the wildcard ever won, the dashboard's reachability button would be answered
// by the single-server route with a 404 for a server called "check".
func TestCheckBeatsTheIDWildcard(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/v1/mcp-servers/check", nil)
	testServer().routes().ServeHTTP(rec, req)

	// No key, so 401 — the point is that it resolved to something rather than
	// falling through to the 404 handler.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (the route resolved and asked for a key)", rec.Code)
	}
}

// The wire shape the CLI, the proxy and the dashboard all read.
func TestMcpViewMatchesTheLiveShape(t *testing.T) {
	row := store.McpServer{
		ID:        "srv_1",
		ProjectID: "proj_1",
		Name:      "local tools",
		URL:       "stdio://node server.js",
		Status:    "active",
		Command:   "node server.js",
		Args:      "--port 9000",
		CreatedAt: 1_754_000_000,
		UpdatedAt: 1_754_000_600,
	}

	raw, err := json.Marshal(mcpToView(row))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	for _, field := range []string{"id", "name", "url", "status", "command", "args", "created_at", "updated_at"} {
		if _, ok := got[field]; !ok {
			t.Errorf("%s is missing; a deployed client reads it", field)
		}
	}
	// drizzle hands a timestamp column to JSON as a Date, which stringifies to
	// ISO-8601. An integer here lands every dashboard date in 1970.
	if got["created_at"] != "2025-07-31T22:13:20.000Z" {
		t.Errorf("created_at = %v, want an ISO-8601 instant", got["created_at"])
	}

	// A NULL command is null on the wire, not "". The column is nullable and
	// the write side stores an empty command as NULL, so the two are the same
	// value and flattening one into the other would invent a stdio server.
	empty := row
	empty.Command = ""
	empty.Args = ""
	raw, _ = json.Marshal(mcpToView(empty))
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["command"] != nil || got["args"] != nil {
		t.Errorf("command = %v, args = %v; both should be null", got["command"], got["args"])
	}
}

func TestJsTruthyString(t *testing.T) {
	cases := []struct {
		json   string
		want   string
		truthy bool
	}{
		{`"hello"`, "hello", true},
		{`""`, "", false},
		{`null`, "", false},
		{`0`, "", false},
		{`7`, "7", true},
		{`1.5`, "1.5", true},
		{`false`, "", false},
		{`true`, "true", true},
		{`{"a":1}`, "", false},
		{`[]`, "", false},
	}
	for _, c := range cases {
		got, truthy := jsTruthyString(json.RawMessage(c.json))
		if got != c.want || truthy != c.truthy {
			t.Errorf("jsTruthyString(%s) = (%q, %v), want (%q, %v)", c.json, got, truthy, c.want, c.truthy)
		}
	}
	// An absent key is falsy, which is what `!body.name` sees.
	if got, truthy := jsTruthyString(nil); got != "" || truthy {
		t.Errorf("jsTruthyString(absent) = (%q, %v), want (\"\", false)", got, truthy)
	}
}

func TestReasonPhraseRecoversStatusText(t *testing.T) {
	cases := []struct {
		status string
		code   int
		want   string
	}{
		{"200 OK", 200, "OK"},
		{"404 Not Found", 404, "Not Found"},
		{"503 Service Unavailable", 503, "Service Unavailable"},
		// HTTP/2 carries no reason phrase; Go synthesises one and so does a
		// browser's fetch, so the two agree.
		{"", 204, "No Content"},
	}
	for _, c := range cases {
		got := reasonPhrase(&http.Response{Status: c.status, StatusCode: c.code})
		if got != c.want {
			t.Errorf("reasonPhrase(%q, %d) = %q, want %q", c.status, c.code, got, c.want)
		}
	}
}
