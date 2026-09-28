package commands

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// stubClient points a real client at a stub API, with a real credential on a
// throwaway HOME.
//
// HOME is redirected for a second reason beyond the credential: doctor reads
// this machine's actual guard registration out of ~/.claude, ~/.codex and
// ~/.config/opencode, and a test that ran against the developer's own home
// directory would pass or fail depending on which agents they happen to have
// installed.
func stubClient(t *testing.T, h http.Handler) *api.Client {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SOLONGATE_API_KEY", "")
	t.Setenv("SOLONGATE_API_URL", "")
	t.Setenv("CODEX_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")

	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	b, err := json.Marshal(config.Credential{APIKey: "sg_live_0123456789abcdef", APIURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.CredentialPath(), b, 0o644); err != nil {
		t.Fatal(err)
	}

	// A working directory with no .env, so the last credential source cannot
	// supply a key this test did not put there.
	prev, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(prev) })

	return api.New()
}

func jsonHandler(t *testing.T, routes map[string]any) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	for path, body := range routes {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(b)
		})
	}
	return mux
}

func TestPolicyListJSONPutsNothingButJSONOnStdout(t *testing.T) {
	c := stubClient(t, jsonHandler(t, map[string]any{
		"/api/v1/policies": map[string]any{"policies": []map[string]any{
			{"id": "pol-1", "name": "Default", "mode": "denylist", "rules": []any{}, "created_by": "someone"},
		}},
	}))

	o, e := capture(t, func() {
		code, err := runPolicy(context.Background(), c, parse([]string{"list", "--json"}))
		if err != nil || code != 0 {
			t.Fatalf("policy list --json: code=%d err=%v", code, err)
		}
	})
	if e != "" {
		t.Fatalf("--json must leave stderr empty for a successful read, got %q", e)
	}
	var back []map[string]any
	if err := json.Unmarshal([]byte(o), &back); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, o)
	}
	if len(back) != 1 || back[0]["id"] != "pol-1" {
		t.Fatalf("unexpected document: %s", o)
	}
}

func TestPolicyListHumanOutputStaysOffStdout(t *testing.T) {
	c := stubClient(t, jsonHandler(t, map[string]any{
		"/api/v1/policies": map[string]any{"policies": []map[string]any{
			{"id": "pol-1", "name": "Default", "mode": "whitelist", "rules": []any{1, 2, 3}},
		}},
	}))
	o, e := capture(t, func() {
		if code, err := runPolicy(context.Background(), c, parse([]string{"list"})); err != nil || code != 0 {
			t.Fatalf("policy list: code=%d err=%v", code, err)
		}
	})
	if o != "" {
		t.Fatalf("the human table belongs on stderr, stdout got %q", o)
	}
	plain := ansi.ReplaceAllString(e, "")
	if !strings.Contains(plain, "pol-1") || !strings.Contains(plain, "whitelist") {
		t.Fatalf("table is missing content: %q", plain)
	}
	// The rule count comes from the array the API sent, not from the rules this
	// version managed to decode.
	if !strings.Contains(plain, " 3 ") {
		t.Fatalf("rule count not rendered: %q", plain)
	}
}

func TestRateLimitSetKeepsTheWindowsItWasNotGiven(t *testing.T) {
	var sent api.SecurityLayers
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/settings/security-layers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			var body struct {
				Layers api.SecurityLayers `json:"layers"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			sent = body.Layers
			_ = json.NewEncoder(w).Encode(map[string]any{"layers": body.Layers})
			return
		}
		_, _ = w.Write([]byte(`{"layers":{"rateLimit":{"mode":"block","perMinute":10,"perHour":100,"perDay":1000},
		  "dlp":{"mode":"detect","patterns":["AWS access key"],"custom":[]}},"availablePatterns":["AWS access key"]}`))
	})
	c := stubClient(t, mux)

	if _, e := capture(t, func() {
		if code, err := runRateLimit(context.Background(), c, parse([]string{"set", "--minute", "25"})); err != nil || code != 0 {
			t.Fatalf("ratelimit set: code=%d err=%v", code, err)
		}
	}); e == "" {
		t.Fatal("the confirmation line is missing")
	}

	if sent.RateLimit.PerMinute != 25 {
		t.Fatalf("perMinute not applied: %d", sent.RateLimit.PerMinute)
	}
	// The endpoint REPLACES the layers document. Sending only the rate limit
	// would switch DLP off on the way past.
	if sent.RateLimit.PerHour != 100 || sent.RateLimit.PerDay != 1000 {
		t.Fatalf("untouched windows were reset: %+v", sent.RateLimit)
	}
	if sent.DLP.Mode != api.LayerDetect || len(sent.DLP.Patterns) != 1 {
		t.Fatalf("editing the rate limit disarmed DLP: %+v", sent.DLP)
	}
}

func TestRateLimitSetRefusesAnUnparseableNumber(t *testing.T) {
	var put bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/settings/security-layers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			put = true
		}
		_, _ = w.Write([]byte(`{"layers":{"rateLimit":{"mode":"block","perMinute":10,"perHour":100,"perDay":1000},
		  "dlp":{"mode":"off","patterns":[],"custom":[]}},"availablePatterns":[]}`))
	})
	c := stubClient(t, mux)

	_, e := capture(t, func() {
		code, err := runRateLimit(context.Background(), c, parse([]string{"set", "--minute", "oops"}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if code != 1 {
			t.Fatalf("a typo has to fail loudly, got exit %d", code)
		}
	})
	if put {
		t.Fatal("a limit of zero was saved from a typo")
	}
	if !strings.Contains(e, "Usage:") {
		t.Fatalf("want the usage line, got %q", e)
	}
}

func TestDLPRefusesAPatternTheCloudDoesNotOffer(t *testing.T) {
	var put bool
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/settings/security-layers", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			put = true
		}
		_, _ = w.Write([]byte(`{"layers":{"rateLimit":{"mode":"off","perMinute":0,"perHour":0,"perDay":0},
		  "dlp":{"mode":"block","patterns":[],"custom":[]}},
		  "availablePatterns":["AWS access key","GitHub token"]}`))
	})
	c := stubClient(t, mux)

	_, e := capture(t, func() {
		code, _ := runDLP(context.Background(), c, parse([]string{"enable", "AWS Access Key"}))
		if code != 1 {
			t.Fatalf("an unknown pattern must fail, got %d", code)
		}
	})
	if put {
		t.Fatal("a pattern name the guard cannot look up was saved anyway")
	}
	if !strings.Contains(e, "AWS access key") {
		t.Fatalf("the available list has to be shown, got %q", e)
	}
}

func TestAuditWhitelistDefaultsToTheNarrowScope(t *testing.T) {
	var gotScope string
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/audit-logs/log-1/whitelist", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Scope string `json:"scope"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		gotScope = body.Scope
		_, _ = w.Write([]byte(`{"ok":true,"policy_id":"pol-1","policy_version":4}`))
	})
	c := stubClient(t, mux)

	_, e := capture(t, func() {
		if code, err := runAudit(context.Background(), c, parse([]string{"whitelist", "log-1"})); err != nil || code != 0 {
			t.Fatalf("audit whitelist: code=%d err=%v", code, err)
		}
	})
	// A whitelist that widened to the whole tool by default would be a very
	// quiet way to disarm a policy.
	if gotScope != "exact" {
		t.Fatalf("default scope = %q, want exact", gotScope)
	}
	if !strings.Contains(ansi.ReplaceAllString(e, ""), "pol-1 v4") {
		t.Fatalf("the resulting policy version is part of the confirmation: %q", e)
	}
}

func TestUnknownCommandIsNotSilent(t *testing.T) {
	_, e := capture(t, func() {
		if code := Run("nonesuch", nil); code != 1 {
			t.Fatalf("want exit 1, got %d", code)
		}
	})
	if !strings.Contains(e, "Unknown command: nonesuch") {
		t.Fatalf("got %q", e)
	}
}

// The SUBcommand equivalent of the test above, which only covered the top
// level. A mistyped subcommand used to print the usage block and nothing else,
// which reads as though the command has no default rather than as an error.
//
// `dlp -g` is the shape that made it obvious: parse() treats only `--x` as a
// flag, so a single-dash token arrives as a subcommand and gets here.
func TestUnknownSubcommandNamesWhatWasTyped(t *testing.T) {
	for _, tc := range []struct{ command, sub string }{
		{"dlp", "-g"},
		{"policy", "activat"},
		{"ratelimit", "nonesuch"},
		{"stats", "nonesuch"},
		{"alerts", "nonesuch"},
		{"webhooks", "nonesuch"},
	} {
		t.Run(tc.command+" "+tc.sub, func(t *testing.T) {
			_, e := capture(t, func() {
				if code, _ := unknownSub(tc.command, tc.sub, "USAGE-BLOCK"); code != 1 {
					t.Fatalf("want exit 1, got %d", code)
				}
			})
			if !strings.Contains(e, tc.sub) {
				t.Errorf("the refusal does not name what was typed: %q", e)
			}
			if !strings.Contains(e, tc.command) {
				t.Errorf("the refusal does not name the command: %q", e)
			}
			if !strings.Contains(e, "USAGE-BLOCK") {
				t.Errorf("the usage block is gone: %q", e)
			}
		})
	}
}

// A command invoked with only a flag has no token to name, and a line reading
// `Unknown subcommand: ""` would be worse than none.
func TestUnknownSubcommandWithNothingTypedJustShowsUsage(t *testing.T) {
	_, e := capture(t, func() {
		if code, _ := unknownSub("dlp", "", "USAGE-BLOCK"); code != 1 {
			t.Fatalf("want exit 1, got %d", code)
		}
	})
	if strings.Contains(e, "Unknown") {
		t.Errorf("named a subcommand that was never typed: %q", e)
	}
	if !strings.Contains(e, "USAGE-BLOCK") {
		t.Errorf("the usage block is gone: %q", e)
	}
}

func TestNamesAndHandlersAgree(t *testing.T) {
	h := handlers()
	for _, n := range Names {
		if _, ok := h[n]; !ok {
			t.Fatalf("%q is advertised but not wired", n)
		}
	}
	if len(h) != len(Names) {
		t.Fatalf("%d handlers for %d advertised names", len(h), len(Names))
	}
}

// A permission the guard has no name for would be stored, never match, and
// leave a rule that reads correctly in `policy show` and enforces nothing. So a
// typo is refused rather than dropped.
func TestPolicyPermissionFlagRefusesWhatTheGuardCannotMatch(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
		bad  string
	}{
		{in: "READ", want: []string{"READ"}},
		{in: "read,write", want: []string{"READ", "WRITE"}},
		{in: " Execute , NETWORK ", want: []string{"EXECUTE", "NETWORK"}},
		{in: "READ,READ", want: []string{"READ"}},
		{in: "", want: nil},
		{in: "READ,ADMIN", bad: "ADMIN"},
		{in: "reed", bad: "reed"},
	} {
		got, bad := parsePermissions(tc.in)
		if bad != tc.bad {
			t.Errorf("parsePermissions(%q) bad = %q, want %q", tc.in, bad, tc.bad)
			continue
		}
		if tc.bad != "" {
			if got != nil {
				t.Errorf("parsePermissions(%q) returned %v alongside a refusal", tc.in, got)
			}
			continue
		}
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("parsePermissions(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
