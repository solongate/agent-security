package logsserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// sandbox points ~/.solongate at a temporary directory. Every test here reads
// or writes real files, and a test that touched the developer's own
// ~/.solongate could disable their logs service or overwrite their state.
func sandbox(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

// writePolicyCache plants the file the guard hooks write, which is where the
// configured local-log folder comes from.
func writePolicyCache(t *testing.T, home, path string) {
	t.Helper()
	body := `{"_ts":1,"security":{"localLogs":{"enabled":true,"path":` + mustJSON(t, path) + `}}}`
	f := filepath.Join(home, ".solongate", ".policy-cache-default.json")
	if err := os.WriteFile(f, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func get(t *testing.T, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler().ServeHTTP(rec, req)
	return rec
}

// The origin list is the only thing between a random page the developer has
// open and this machine's audit trail, so an unlisted origin must get NO
// Access-Control-Allow-Origin at all.
func TestOriginAllowListIsExact(t *testing.T) {
	sandbox(t)
	cases := []struct {
		origin string
		want   bool
	}{
		{"https://dashboard.solongate.com", true},
		{"http://localhost:3000", true},
		{"http://127.0.0.1:3005", true},
		{"https://evil.example.com", false},
		// A prefix and a suffix of a listed origin, which a substring or a
		// wildcard check would admit.
		{"https://dashboard.solongate.com.evil.example", false},
		{"https://evil.example/https://dashboard.solongate.com", false},
		{"http://localhost:3001", false},
	}
	for _, c := range cases {
		rec := get(t, "/health", map[string]string{"Origin": c.origin})
		got := rec.Header().Get("Access-Control-Allow-Origin")
		if c.want && got != c.origin {
			t.Errorf("origin %q: allow-origin = %q, want it echoed", c.origin, got)
		}
		if !c.want && got != "" {
			t.Errorf("origin %q: allow-origin = %q, want none", c.origin, got)
		}
	}
}

func TestExtraOriginFromEnv(t *testing.T) {
	sandbox(t)
	t.Setenv("SOLONGATE_DASHBOARD_ORIGIN", " http://localhost:4321 , ")
	rec := get(t, "/health", map[string]string{"Origin": "http://localhost:4321"})
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:4321" {
		t.Fatalf("allow-origin = %q, want the configured extra origin", got)
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Fatalf("Vary = %q, want Origin", got)
	}
}

// Credentialed CORS would let a page read this with the browser's cookies
// attached. Nothing here is behind a credential and nothing should ask for one.
func TestNeverAllowsCredentials(t *testing.T) {
	sandbox(t)
	rec := get(t, "/health", map[string]string{"Origin": "https://dashboard.solongate.com"})
	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got != "" {
		t.Fatalf("allow-credentials = %q, want it absent", got)
	}
}

func TestPreflightAndMethods(t *testing.T) {
	sandbox(t)

	req := httptest.NewRequest(http.MethodOptions, "/local-logs", nil)
	req.Header.Set("Origin", "https://dashboard.solongate.com")
	req.Header.Set("Access-Control-Request-Private-Network", "true")
	rec := httptest.NewRecorder()
	handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS = %d, want 204", rec.Code)
	}
	if got := rec.Header().Get("Access-Control-Allow-Private-Network"); got != "true" {
		t.Fatalf("private-network = %q, want true — Chrome refuses the loopback call without it", got)
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got != "GET, OPTIONS" {
		t.Fatalf("allow-methods = %q", got)
	}

	// The private-network header is answered only when asked for.
	rec = get(t, "/health", nil)
	if got := rec.Header().Get("Access-Control-Allow-Private-Network"); got != "" {
		t.Fatalf("private-network = %q on a plain request, want absent", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/local-logs", nil)
	rec = httptest.NewRecorder()
	handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", rec.Code)
	}

	if rec := get(t, "/anything-else", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown route = %d, want 404", rec.Code)
	}
}

func TestServesTheConfiguredLog(t *testing.T) {
	home := sandbox(t)
	dir := t.TempDir()
	writePolicyCache(t, home, dir)
	file := filepath.Join(dir, "solongate-audit.jsonl")
	if err := os.WriteFile(file, []byte("{\"a\":1}\n{\"a\":2}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := get(t, "/local-logs", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if rec.Body.String() != "{\"a\":1}\n{\"a\":2}\n" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	if got := rec.Header().Get("X-Solongate-Exists"); got != "1" {
		t.Fatalf("exists header = %q, want 1", got)
	}

	lastMod := rec.Header().Get("Last-Modified")
	if lastMod == "" {
		t.Fatal("no Last-Modified, so the dashboard would re-transfer the whole log on every poll")
	}
	again := get(t, "/local-logs", map[string]string{"If-Modified-Since": lastMod})
	if again.Code != http.StatusNotModified {
		t.Fatalf("conditional GET = %d, want 304", again.Code)
	}

	older := time.Now().Add(-2 * time.Hour).UTC().Format(http.TimeFormat)
	fresh := get(t, "/local-logs", map[string]string{"If-Modified-Since": older})
	if fresh.Code != http.StatusOK {
		t.Fatalf("stale conditional GET = %d, want 200", fresh.Code)
	}
}

func TestHealthReportsWhereItIsReading(t *testing.T) {
	home := sandbox(t)
	dir := t.TempDir()
	writePolicyCache(t, home, dir)
	file := filepath.Join(dir, "solongate-audit.jsonl")
	if err := os.WriteFile(file, []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rec := get(t, "/health", nil)
	var body health
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if !body.OK || body.Agent != "solongate-logs-server" {
		t.Fatalf("health = %+v", body)
	}
	if body.ConfiguredPath == nil || *body.ConfiguredPath != dir {
		t.Fatalf("configuredPath = %v, want %q", body.ConfiguredPath, dir)
	}
	if body.File == nil || *body.File != file {
		t.Fatalf("file = %v, want %q", body.File, file)
	}
	if body.ResolvedDir == nil || *body.ResolvedDir != dir {
		t.Fatalf("resolvedDir = %v, want %q", body.ResolvedDir, dir)
	}
	if !body.Exists || body.Size != 2 {
		t.Fatalf("exists=%v size=%d, want true/2", body.Exists, body.Size)
	}
	if body.MTime == nil {
		t.Fatal("mtime is null for a file that exists")
	}
}

// A machine with local logging off must be told apart from one with an empty
// log: the dashboard shows a different thing for each, and answering the wrong
// one tells the user to enable something already on, or the reverse.
func TestUnconfiguredIsDistinctFromEmpty(t *testing.T) {
	home := sandbox(t)

	rec := get(t, "/local-logs", nil)
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("status=%d body=%q, want an empty 200", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Solongate-Configured"); got != "0" {
		t.Fatalf("configured header = %q, want 0", got)
	}

	var body health
	if err := json.Unmarshal(get(t, "/health", nil).Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.ConfiguredPath != nil || body.File != nil || body.ResolvedDir != nil {
		t.Fatalf("health names a path with nothing configured: %+v", body)
	}

	// Configured, folder present, no entries yet.
	dir := t.TempDir()
	writePolicyCache(t, home, dir)
	rec = get(t, "/local-logs", nil)
	if got := rec.Header().Get("X-Solongate-Exists"); got != "0" {
		t.Fatalf("exists header = %q, want 0", got)
	}
	if got := rec.Header().Get("X-Solongate-Configured"); got != "" {
		t.Fatalf("configured header = %q on a configured machine, want absent", got)
	}
}

// The service reads the file the guard writes, and nothing else. A path handed
// in by the caller must not select it.
func TestServesNothingTheRequestNames(t *testing.T) {
	home := sandbox(t)
	dir := t.TempDir()
	writePolicyCache(t, home, dir)
	if err := os.WriteFile(filepath.Join(dir, "solongate-audit.jsonl"), []byte("audit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{
		"/local-logs?file=" + secret,
		"/local-logs/../secret.txt",
		"/" + secret,
		"/health/../../etc/passwd",
	} {
		rec := get(t, path, nil)
		if rec.Body.String() == "secret\n" {
			t.Fatalf("%s served a file the request named", path)
		}
	}
}

func TestChosenPort(t *testing.T) {
	cases := []struct {
		name string
		env  string
		args []string
		want int
	}{
		{"default", "", nil, DefaultPort},
		{"flag", "", []string{"--port", "9100"}, 9100},
		{"flag with nothing after it", "", []string{"--port"}, DefaultPort},
		{"env wins", "9200", []string{"--port", "9100"}, 9200},
		// The Node chain is Number(env || flag || default) || default, so a
		// present-but-unusable env selects the default outright rather than
		// falling through to the flag.
		{"unusable env does not fall through to the flag", "abc", []string{"--port", "9100"}, DefaultPort},
		{"out of range", "70000", nil, DefaultPort},
		{"zero", "0", nil, DefaultPort},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("SOLONGATE_LOGS_PORT", c.env)
			if got := chosenPort(c.args); got != c.want {
				t.Fatalf("chosenPort = %d, want %d", got, c.want)
			}
		})
	}
}

// Stopping has to DISABLE. Ensure resurrects anything still marked desired on
// every CLI run, so a stop that only killed the process would be undone by the
// user's next command.
func TestStopDisablesAndEnsureRespectsIt(t *testing.T) {
	sandbox(t)

	if err := config.SaveLogsServerState(config.LogsServerState{Desired: "on", Port: 8788}); err != nil {
		t.Fatal(err)
	}
	if st := CurrentStatus(); st.Desired != "on" {
		t.Fatalf("desired = %q, want on", st.Desired)
	}

	st := Stop()
	if st.Desired != "off" || st.Running {
		t.Fatalf("Stop returned %+v", st)
	}
	if got := config.LoadLogsServerState().Desired; got != "off" {
		t.Fatalf("desired on disk = %q, want off", got)
	}

	// Ensure must not bring it back after a stop. If it did it would spawn a
	// process, so this also asserts nothing was spawned.
	Ensure()
	after := config.LoadLogsServerState()
	if after.Desired != "off" || after.Pid != 0 {
		t.Fatalf("Ensure resurrected a disabled service: %+v", after)
	}
}

func TestStatusDefaultsPortWhenStateHasNone(t *testing.T) {
	sandbox(t)
	if err := config.SaveLogsServerState(config.LogsServerState{Desired: "on"}); err != nil {
		t.Fatal(err)
	}
	if st := CurrentStatus(); st.Port != DefaultPort {
		t.Fatalf("port = %d, want the default the dashboard looks for", st.Port)
	}
}
