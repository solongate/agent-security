package commands

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

// ghostStub serves one security-layers document and records what a PUT sent
// back, which is the only thing these tests need to know.
func ghostStub(t *testing.T, doc string, sent *api.SecurityLayers, put *bool) *api.Client {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/settings/security-layers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			if put != nil {
				*put = true
			}
			var body struct {
				Layers api.SecurityLayers `json:"layers"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			if sent != nil {
				*sent = body.Layers
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"layers": body.Layers})
			return
		}
		_, _ = w.Write([]byte(doc))
	})
	return stubClient(t, mux)
}

const ghostDoc = `{"layers":{"rateLimit":{"mode":"block","perMinute":10,"perHour":100,"perDay":1000},
  "dlp":{"mode":"block","patterns":["AWS access key"],"custom":[{"name":"ACME","re":"ACME-*"}]},
  "ghost":{"mode":"on","patterns":["*payroll.csv"]}},"availablePatterns":["AWS access key"]}`

// A route of `*` expands to `\S*`, which matches every path the guard is ever
// handed. Saving it makes the whole filesystem invisible to the agent, and the
// symptom is "the agent says none of my files exist" rather than anything that
// points at ghost.
func TestGhostAddRefusesARouteThatWouldHideEverything(t *testing.T) {
	for _, blanket := range []string{"*", "**", "  *  ", "***"} {
		t.Run(blanket, func(t *testing.T) {
			var put bool
			c := ghostStub(t, ghostDoc, nil, &put)

			_, e := capture(t, func() {
				code, err := runGhost(context.Background(), c, parse([]string{"add", blanket}))
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if code != 1 {
					t.Fatalf("a blanket route has to fail loudly, got exit %d", code)
				}
			})
			if put {
				t.Fatal("a route that hides every path was saved")
			}
			if !strings.Contains(e, "would hide every path") {
				t.Fatalf("the refusal has to say why, got %q", e)
			}
		})
	}
}

// The endpoint REPLACES the layers document, so a command that sends back only
// its own layer switches the other two off on the way past.
func TestGhostAddKeepsTheOtherLayers(t *testing.T) {
	var sent api.SecurityLayers
	c := ghostStub(t, ghostDoc, &sent, nil)

	if _, e := capture(t, func() {
		if code, err := runGhost(context.Background(), c, parse([]string{"add", "*internal/*.pem"})); err != nil || code != 0 {
			t.Fatalf("ghost add: code=%d err=%v", code, err)
		}
	}); e == "" {
		t.Fatal("the confirmation line is missing")
	}

	if len(sent.Ghost.Patterns) != 2 || sent.Ghost.Patterns[1] != "*internal/*.pem" {
		t.Fatalf("route not appended: %+v", sent.Ghost.Patterns)
	}
	if sent.Ghost.Patterns[0] != "*payroll.csv" {
		t.Fatalf("the existing route was dropped: %+v", sent.Ghost.Patterns)
	}
	if sent.RateLimit.PerMinute != 10 || sent.RateLimit.Mode != api.LayerBlock {
		t.Fatalf("editing ghost reset the rate limit: %+v", sent.RateLimit)
	}
	if sent.DLP.Mode != api.LayerBlock || len(sent.DLP.Patterns) != 1 || len(sent.DLP.Custom) != 1 {
		t.Fatalf("editing ghost disarmed DLP: %+v", sent.DLP)
	}
}

// A runbook that adds its routes on every run must not fail on its second run,
// and must not accumulate duplicates either.
func TestGhostAddIsIdempotent(t *testing.T) {
	var put bool
	c := ghostStub(t, ghostDoc, nil, &put)

	if _, e := capture(t, func() {
		if code, err := runGhost(context.Background(), c, parse([]string{"add", "*payroll.csv"})); err != nil || code != 0 {
			t.Fatalf("re-adding an existing route: code=%d err=%v", code, err)
		}
	}); !strings.Contains(e, "already hidden") {
		t.Fatalf("want the already-hidden line, got %q", e)
	}
	if put {
		t.Fatal("re-adding an existing route rewrote the document")
	}
}

func TestGhostRemoveReportsARouteThatIsNotThere(t *testing.T) {
	var put bool
	c := ghostStub(t, ghostDoc, nil, &put)

	_, e := capture(t, func() {
		code, err := runGhost(context.Background(), c, parse([]string{"remove", "*nothing.csv"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if code != 1 {
			t.Fatalf("removing a route that is not there has to fail, got exit %d", code)
		}
	})
	if put {
		t.Fatal("a no-op removal rewrote the document")
	}
	// The current list is printed so a typo is obvious without a second command.
	if !strings.Contains(e, "*payroll.csv") {
		t.Fatalf("the refusal should list what IS hidden, got %q", e)
	}
}

func TestGhostRemoveDropsOnlyTheNamedRoute(t *testing.T) {
	var sent api.SecurityLayers
	c := ghostStub(t, ghostDoc, &sent, nil)

	if _, e := capture(t, func() {
		if code, err := runGhost(context.Background(), c, parse([]string{"remove", "*payroll.csv"})); err != nil || code != 0 {
			t.Fatalf("ghost remove: code=%d err=%v", code, err)
		}
	}); e == "" {
		t.Fatal("the confirmation line is missing")
	}
	if len(sent.Ghost.Patterns) != 0 {
		t.Fatalf("route not removed: %+v", sent.Ghost.Patterns)
	}
	if sent.Ghost.Mode != "on" {
		t.Fatalf("removing a route changed the mode: %q", sent.Ghost.Mode)
	}
}

// Switching the layer off keeps the routes. That is what the dataroom does, and
// it is why `ghost show` says so: a stored list is not a hidden file.
func TestGhostOffKeepsTheRoutes(t *testing.T) {
	var sent api.SecurityLayers
	c := ghostStub(t, ghostDoc, &sent, nil)

	if _, e := capture(t, func() {
		if code, err := runGhost(context.Background(), c, parse([]string{"off"})); err != nil || code != 0 {
			t.Fatalf("ghost off: code=%d err=%v", code, err)
		}
	}); e == "" {
		t.Fatal("the confirmation line is missing")
	}
	if sent.Ghost.Mode != "off" {
		t.Fatalf("mode not applied: %q", sent.Ghost.Mode)
	}
	if len(sent.Ghost.Patterns) != 1 {
		t.Fatalf("switching ghost off deleted the routes: %+v", sent.Ghost.Patterns)
	}
}

// Routes stored while the layer is off hide nothing, and the command has to say
// so or the next thing that happens is a test that passes when it should not.
func TestGhostShowSaysWhenStoredRoutesAreInert(t *testing.T) {
	const off = `{"layers":{"rateLimit":{"mode":"off","perMinute":0,"perHour":0,"perDay":0},
	  "dlp":{"mode":"off","patterns":[],"custom":[]},
	  "ghost":{"mode":"off","patterns":["*payroll.csv"]}},"availablePatterns":[]}`
	c := ghostStub(t, off, nil, nil)

	_, e := capture(t, func() {
		if code, err := runGhost(context.Background(), c, parse([]string{"show"})); err != nil || code != 0 {
			t.Fatalf("ghost show: code=%d err=%v", code, err)
		}
	})
	if !strings.Contains(e, "nothing is hidden") {
		t.Fatalf("a stored-but-inert route has to be called out, got %q", e)
	}
}
