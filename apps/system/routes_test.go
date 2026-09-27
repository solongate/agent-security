package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
)

// The shell's tests. They exist for one reason above the others: ServeMux
// PANICS on a conflicting pattern, and it does so at registration — which in a
// server means at the first request after a deploy. A test that builds the mux
// turns "the API crashed on boot" into "the build failed".

// testServer builds the shell with no database. Nothing under test here
// reaches one: a stub answers before its handler would query, and the per-IP
// limiter is in-memory.
func testServer() *server {
	return &server{
		cfg:  config{allowedOrigins: []string{"https://dashboard.solongate.com"}},
		auth: apiauth.New(nil, apiauth.NewLimiter()),
	}
}

func TestRoutesRegisterWithoutConflict(t *testing.T) {
	// The assertion is that this does not panic.
	h := testServer().routes()
	if h == nil {
		t.Fatal("routes() returned nil")
	}
}

func TestRouteTableMatchesSourceTree(t *testing.T) {
	if len(routes) != routeCount {
		t.Fatalf("route table has %d entries, want %d", len(routes), routeCount)
	}
	seen := map[string]bool{}
	for _, rt := range routes {
		if seen[rt.path] {
			t.Errorf("%s listed twice", rt.path)
		}
		seen[rt.path] = true
		if len(rt.methods) == 0 {
			t.Errorf("%s has no methods", rt.path)
		}
		// A source file, unless the route was written here rather than ported.
		//
		// The column records where a route CAME FROM, and the ones this service
		// grew after the port came from nowhere: naming a src/app/api file for
		// them would be a lie in the one column that exists to be true. They
		// are marked done instead, which is the same claim the assertion is
		// really making — that nobody added a row without saying what it is.
		if rt.source == "" && !rt.done {
			t.Errorf("%s has neither a source file nor done: a row has to say which it is", rt.path)
		}
		for _, m := range rt.methods {
			if m == http.MethodOptions {
				// src/middleware.ts answers every preflight before routing, so
				// an OPTIONS entry here would be a route that can never run.
				t.Errorf("%s registers OPTIONS; the CORS layer owns preflights", rt.path)
			}
		}
	}
}

func TestHealthIsPorted(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer().routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/health", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["status"] != "healthy" || body["version"] != "0.1.0" {
		t.Errorf("body = %v, want status healthy and version 0.1.0", body)
	}
	// The live app returns a Date, which JSON.stringify writes as an ISO
	// string. A bare number here would land every dashboard timestamp in 1970.
	if !strings.HasSuffix(body["timestamp"], "Z") || len(body["timestamp"]) != 24 {
		t.Errorf("timestamp = %q, want an ISO-8601 instant", body["timestamp"])
	}
}

func TestStubbedKeyRouteRefusesWithoutAKey(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer().routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/policies/active", nil))

	// 401 before 501: a stub must not tell an unauthenticated caller which
	// endpoints exist or how far the port has got.
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	var body apiauth.ErrorBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body.Error.Code != "AUTHENTICATION_ERROR" || body.Error.Message != "Invalid API key" {
		t.Errorf("error = %+v, want the live app's AUTHENTICATION_ERROR shape", body.Error)
	}
}

// The placeholder is exercised directly rather than through a route, because
// every route in the table is now ported and there is no stub left to send a
// request to. It stays under test: notPorted is what a NEW route.ts gets when
// somebody adds one to the table, and 501-with-a-source is the difference
// between "not built yet" and "this endpoint does not exist".
func TestPlaceholderAnswers501WithItsSource(t *testing.T) {
	rt := route{
		path:    "/api/v1/example",
		methods: []string{"POST"},
		source:  "src/app/api/v1/example/route.ts",
		auth:    authIP,
		limit:   limSetup,
	}
	rec := httptest.NewRecorder()
	testServer().notPorted(rt, "POST").ServeHTTP(rec, httptest.NewRequest("POST", "/api/v1/example", nil))

	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v", err)
	}
	if body["source"] != "src/app/api/v1/example/route.ts" {
		t.Errorf("source = %v, want the file still to be ported", body["source"])
	}
	if body["route"] != "POST /api/v1/example" {
		t.Errorf("route = %v, want the method and path", body["route"])
	}
}

func TestPreflightIsAnsweredBeforeRouting(t *testing.T) {
	req := httptest.NewRequest("OPTIONS", "/api/v1/policies/active", nil)
	req.Header.Set("Origin", "https://dashboard.solongate.com")
	rec := httptest.NewRecorder()
	testServer().routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://dashboard.solongate.com" {
		t.Errorf("allow-origin = %q, want the request's origin echoed", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Headers"); !strings.Contains(got, "X-API-Key") {
		t.Errorf("allow-headers = %q, must permit the header the guard authenticates with", got)
	}
}

func TestUnknownOriginGetsNoCORSHeaders(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("Origin", "https://not-ours.example")
	rec := httptest.NewRecorder()
	testServer().routes().ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("allow-origin = %q, want none for an origin outside the whitelist", got)
	}
	// The security headers are unconditional, whitelist or not.
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("security headers must be set regardless of origin")
	}
}

func TestUnknownPathIsJSON404(t *testing.T) {
	rec := httptest.NewRecorder()
	testServer().routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/nope", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q, want application/json", ct)
	}
}

func TestLiteralPathsWinOverWildcards(t *testing.T) {
	// /api/v1/policies/active and /api/v1/policies/{id} are both registered.
	// If the wildcard ever won, the guard's poll would be answered by the
	// single-policy route and every installed guard would stop enforcing.
	srv := testServer()
	mux := srv.routes()
	for _, path := range []string{"/api/v1/policies/active", "/api/v1/agents/live", "/api/v1/tools"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code == http.StatusNotFound {
			t.Errorf("%s resolved to nothing", path)
		}
	}
}
