package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/hookbundle"
)

func TestEveryHookHasARoute(t *testing.T) {
	for _, name := range hookbundle.Names() {
		if _, ok := routeHandlers["GET /api/v1/hooks/"+name]; !ok {
			t.Errorf("%s is served by internal/hookbundle but no route reaches it", name)
		}
	}
	// The route table lists exactly four. A hook added to the generator without
	// a table entry still gets a route (routes.go registers extras) but should
	// be noticed here first.
	if got := len(hookbundle.Names()); got != 4 {
		t.Errorf("serving %d hooks, the route table lists 4", got)
	}
}

// The hook endpoints are the update channel for every installed guard, and an
// unauthenticated one would let anyone pull the guard's source. This is the
// same 401 shape everything else in the service answers with, because the
// installed hook treats a non-2xx as "nothing to do" and gives up quietly.
func TestHookBundleNeedsAKey(t *testing.T) {
	for _, name := range hookbundle.Names() {
		rec := httptest.NewRecorder()
		testServer().routes().ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1/hooks/"+name, nil))

		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s: status = %d, want 401", name, rec.Code)
		}
		var body apiauth.ErrorBody
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: body is not JSON: %v", name, err)
		}
		if body.Error.Code != "AUTHENTICATION_ERROR" {
			t.Errorf("%s: error code = %q, want AUTHENTICATION_ERROR", name, body.Error.Code)
		}
	}
}

// The hook reads three fields off the response and refuses the bundle if any of
// them is missing or the wrong JSON type. version in particular is checked with
// `typeof data.version !== 'number'`, so a version serialised as a string stops
// every machine in the fleet from updating — silently.
func TestBundleSerialisesTheWayTheHookParsesIt(t *testing.T) {
	bundle, ok := hookbundle.Get("guard")
	if !ok {
		t.Fatal("no guard bundle")
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, isNumber := decoded["version"].(float64); !isNumber {
		t.Errorf("version is %T, the hook requires a JSON number", decoded["version"])
	}
	if _, isString := decoded["sha256"].(string); !isString {
		t.Errorf("sha256 is %T, the hook requires a string", decoded["sha256"])
	}
	if _, isString := decoded["content"].(string); !isString {
		t.Errorf("content is %T, the hook requires a string", decoded["content"])
	}
	if len(decoded) != 3 {
		t.Errorf("bundle has %d fields; the three the hook reads are version, sha256, content", len(decoded))
	}
}
