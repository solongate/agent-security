package selfupdate

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// sandbox points ~/.solongate at a temp directory. Every test here writes state
// files, and a test that wrote into the developer's real home would rewrite the
// throttle of the CLI they use.
func sandbox(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home) // os.UserHomeDir reads this one on Windows
	if err := os.MkdirAll(config.HooksDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestNewer(t *testing.T) {
	cases := []struct {
		b, a string
		want bool
	}{
		{"0.83.21", "0.83.20", true},
		{"0.83.20", "0.83.20", false},
		{"0.83.19", "0.83.20", false},
		{"0.84.0", "0.83.99", true},
		{"1.0.0", "0.99.99", true},
		// A `.99` patch is followed by a minor bump, never by .100 — the two
		// implementations have to order those the same way or one of them
		// announces an update the other says is already installed.
		{"0.83.100", "0.84.0", false},
		// An unstamped development build parses as 0.0.0, so the comparison
		// orders it below everything. Acting on that is refused separately, by
		// VersionKnown — see the test below.
		{"0.83.20", "dev", true},
		// parseInt semantics: a prerelease suffix is ignored on both sides, so
		// these compare equal rather than one being "newer".
		{"0.83.20-rc.1", "0.83.20", false},
		{"0.83.21-rc.1", "0.83.20", true},
		// A missing component is zero, not "unknown".
		{"1", "0.99.99", true},
		{"", "0.0.1", false},
	}
	for _, c := range cases {
		if got := Newer(c.b, c.a); got != c.want {
			t.Errorf("Newer(%q, %q) = %v, want %v", c.b, c.a, got, c.want)
		}
	}
}

func TestNeedsAdminMatchesNpmsWords(t *testing.T) {
	refusals := []string{
		"npm ERR! code EACCES",
		"npm ERR! code EPERM",
		"Error: EACCES: permission denied, mkdir '/usr/local/lib/node_modules'",
		"operation not permitted",
	}
	for _, s := range refusals {
		if !needsAdminRe.MatchString(s) {
			t.Errorf("npm refusal not recognised as needing admin: %q", s)
		}
	}
	// A transient failure must NOT be memoised as needing admin: the memo stops
	// the version from ever being retried, and a registry blip is exactly the
	// case that should be retried.
	blips := []string{
		"npm ERR! code ETARGET",
		"npm ERR! network request to https://registry.npmjs.org failed",
		"npm ERR! code E404",
	}
	for _, s := range blips {
		if needsAdminRe.MatchString(s) {
			t.Errorf("transient npm failure misread as needing admin: %q", s)
		}
	}
}

func TestLatestVersionRefusesAVersionItCannotInstall(t *testing.T) {
	// dist-tags moved to a version whose metadata has not propagated yet. Right
	// after a publish this is a real state, and announcing it burns the six-hour
	// retry slot on an install npm rejects with ETARGET.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dist-tags": map[string]string{"latest": "0.83.21"},
			"versions":  map[string]any{"0.83.20": map[string]any{}},
		})
	}))
	defer srv.Close()
	registryBase = srv.URL + "/"
	defer func() { registryBase = "https://registry.npmjs.org/" }()

	if v, ok := LatestVersion(context.Background()); ok {
		t.Fatalf("announced a version that is not installable yet: %q", v)
	}
}

func TestLatestVersionAcceptsAnInstallableVersion(t *testing.T) {
	var gotAccept, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAccept, gotPath = r.Header.Get("Accept"), r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dist-tags": map[string]string{"latest": "0.83.21"},
			"versions": map[string]any{
				"0.83.20": map[string]any{},
				"0.83.21": map[string]any{},
			},
		})
	}))
	defer srv.Close()
	registryBase = srv.URL + "/"
	defer func() { registryBase = "https://registry.npmjs.org/" }()

	v, ok := LatestVersion(context.Background())
	if !ok || v != "0.83.21" {
		t.Fatalf("LatestVersion = %q, %v; want 0.83.21, true", v, ok)
	}
	// The abbreviated packument is what `npm install` itself resolves against.
	// Asking for the full one would answer a different question, slowly.
	if gotAccept != "application/vnd.npm.install-v1+json" {
		t.Errorf("Accept = %q", gotAccept)
	}
	if gotPath != "/"+pkgName {
		t.Errorf("path = %q, want /%s", gotPath, pkgName)
	}
}

func TestSetAutoClearsTheNeedsAdminMemo(t *testing.T) {
	sandbox(t)
	s := config.SelfUpdateState{NeedsAdmin: "0.83.21"}
	if err := config.SaveSelfUpdateState(s); err != nil {
		t.Fatal(err)
	}
	// The user may have just fixed the ownership of their global folder. A memo
	// that survived would keep the updater from ever trying that version again.
	SetAuto(true)
	if got := config.LoadSelfUpdateState(); got.NeedsAdmin != "" || !got.Auto {
		t.Fatalf("after SetAuto(true): %+v", got)
	}
	// Turning it off must NOT clear the memo: nothing was fixed by switching a
	// setting off.
	if err := config.SaveSelfUpdateState(config.SelfUpdateState{Auto: true, NeedsAdmin: "0.83.21"}); err != nil {
		t.Fatal(err)
	}
	SetAuto(false)
	if got := config.LoadSelfUpdateState(); got.NeedsAdmin != "0.83.21" || got.Auto {
		t.Fatalf("after SetAuto(false): %+v", got)
	}
}

func TestAutoUpdateEnvOverride(t *testing.T) {
	sandbox(t)
	if err := config.SaveSelfUpdateState(config.SelfUpdateState{Auto: true}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"0", "off", "false", "no", "OFF"} {
		t.Setenv("SOLONGATE_AUTO_UPDATE", v)
		if AutoEnabled() {
			t.Errorf("SOLONGATE_AUTO_UPDATE=%q did not turn the updater off", v)
		}
		if !AutoForcedByEnv() {
			t.Errorf("SOLONGATE_AUTO_UPDATE=%q is deciding but is not reported as forced", v)
		}
	}
	// A value nothing acts on must not be reported as forcing anything, or the
	// dataroom shows a row as overridden while the stored setting is what is
	// actually in effect.
	t.Setenv("SOLONGATE_AUTO_UPDATE", "maybe")
	if AutoForcedByEnv() {
		t.Error("an unrecognised value was reported as forcing the setting")
	}
	if !AutoEnabled() {
		t.Error("an unrecognised value overrode the stored setting")
	}
}

// A build with no version stamp compares itself as 0.0.0 and therefore looks
// out of date against everything ever published. Every path that installs has to
// refuse it.
//
// This is not hypothetical: TestStubsDoNotReportSuccess in the root package
// called `update` on an unstamped test binary and it ran a real
// `npm install -g` against the developer's global node_modules.
func TestAnUnstampedBuildNeverInstallsAnything(t *testing.T) {
	sandbox(t)
	defer func(v string) { Version = v }(Version)

	for _, v := range []string{"dev", "", "0.0.0", "not-a-version"} {
		Version = v
		if VersionKnown() {
			t.Errorf("Version %q was treated as a known version", v)
		}
		// Registry lookups and installs both hang off these three. Each one has
		// to stop before it reaches npm; if any did not, this test would install
		// a package while running.
		if code := RunUpdateCommand(nil); code == 0 {
			t.Errorf("`update` on version %q reported success", v)
		}
		if got := UpdateNow(context.Background()); got.Kind != KindFailed {
			t.Errorf("UpdateNow on version %q returned %q", v, got.Kind)
		}
		said := false
		TUIFlow(context.Background(), func(Status) { said = true })
		if said {
			t.Errorf("the dataroom flow reported a status on version %q", v)
		}
		notifyOnce(func(string) { said = true })
		if said {
			t.Errorf("the startup notice fired on version %q", v)
		}
	}

	Version = "0.83.20"
	if !VersionKnown() {
		t.Error("a stamped build was refused")
	}
}

func TestUpdateAutoOnlyChangesTheSetting(t *testing.T) {
	sandbox(t)
	t.Setenv("SOLONGATE_AUTO_UPDATE", "")

	// `update auto` with nothing after it REPORTS. It must not be read as a
	// request to change anything, or asking what the setting is would change it.
	if code := RunUpdateCommand([]string{"auto"}); code != 0 {
		t.Errorf("`update auto` exited %d", code)
	}
	if config.LoadSelfUpdateState().Auto {
		t.Error("`update auto` with no argument turned the updater on")
	}

	if code := RunUpdateCommand([]string{"auto", "on"}); code != 0 {
		t.Errorf("`update auto on` exited %d", code)
	}
	if !config.LoadSelfUpdateState().Auto {
		t.Error("`update auto on` did not turn the updater on")
	}

	// An unrecognised value is a usage error, not a silent "off": someone who
	// typed `update auto yes-please` must not be told the updater is off when
	// nothing was changed.
	before := config.LoadSelfUpdateState().Auto
	if code := RunUpdateCommand([]string{"auto", "yes-please"}); code != 1 {
		t.Errorf("an unknown value exited %d, want 1", code)
	}
	if config.LoadSelfUpdateState().Auto != before {
		t.Error("an unknown value changed the setting")
	}
}

// hookBody builds a payload that passes every check, so each test below can
// break exactly one thing.
func hookBody(marker string, minLen int) string {
	b := strings.Builder{}
	b.WriteString(hookShebang + "\n")
	b.WriteString("// " + marker + "\nconst HOOK_VERSION = 81;\n")
	for b.Len() < minLen {
		b.WriteString("// padding to the minimum length the hook checks\n")
	}
	return b.String()
}

func TestVerifiedHookBodyRefusesWhatItCannotTrust(t *testing.T) {
	spec := hookSpecs[1] // audit: small enough to build in a test
	good := hookBody(spec.marker, spec.minLen)
	sum := sha256.Sum256([]byte(good))
	goodHash := hex.EncodeToString(sum[:])
	enc := base64.StdEncoding.EncodeToString([]byte(good))

	if _, why := verifiedHookBody(enc, goodHash, spec); why != "" {
		t.Fatalf("a valid payload was refused: %s", why)
	}

	// A single flipped bit has to stop the install. This is the check that makes
	// the difference between "the cloud can ship a guard fix" and "anything on
	// the path can ship whatever it likes into a hook that runs before every
	// tool call".
	bad := strings.Replace(good, "HOOK_VERSION = 81", "HOOK_VERSION = 82", 1)
	if _, why := verifiedHookBody(base64.StdEncoding.EncodeToString([]byte(bad)), goodHash, spec); why == "" {
		t.Error("content that does not match its sha256 was accepted")
	}

	// The right bytes for the WRONG hook. The checksum proves integrity, not
	// identity; without the marker an audit bundle could be installed as the
	// shield.
	other := hookBody("Some Other Program", spec.minLen)
	otherSum := sha256.Sum256([]byte(other))
	if _, why := verifiedHookBody(
		base64.StdEncoding.EncodeToString([]byte(other)),
		hex.EncodeToString(otherSum[:]), spec); why == "" {
		t.Error("a payload without the hook's marker was accepted")
	}

	// A truncated download whose checksum was computed over the truncation.
	short := hookShebang + "\n// " + spec.marker + "\n"
	shortSum := sha256.Sum256([]byte(short))
	if _, why := verifiedHookBody(
		base64.StdEncoding.EncodeToString([]byte(short)),
		hex.EncodeToString(shortSum[:]), spec); why == "" {
		t.Error("a truncated payload was accepted")
	}

	// An error page served with a 200, which is what a captive portal or a
	// misconfigured proxy produces.
	page := "<!doctype html><title>Sign in to the network</title>"
	pageSum := sha256.Sum256([]byte(page))
	if _, why := verifiedHookBody(
		base64.StdEncoding.EncodeToString([]byte(page)),
		hex.EncodeToString(pageSum[:]), spec); why == "" {
		t.Error("an HTML page was accepted as a hook")
	}
}

// hookServer answers /api/v1/hooks/<name> the way the cloud does.
func hookServer(t *testing.T, version int, body string) *httptest.Server {
	t.Helper()
	sum := sha256.Sum256([]byte(body))
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/hooks/") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": version,
			"content": base64.StdEncoding.EncodeToString([]byte(body)),
			"sha256":  hex.EncodeToString(sum[:]),
		})
	}))
}

func testClient(t *testing.T, srv *httptest.Server) *api.Client {
	t.Helper()
	t.Setenv("SOLONGATE_API_KEY", "sg_live_"+strings.Repeat("a", 48))
	c := api.New()
	c.APIURLOverride = srv.URL
	return c
}

func TestRefreshHooksNeverCreatesAHookThatIsNotInstalled(t *testing.T) {
	sandbox(t)
	srv := hookServer(t, 81, hookBody("SolonGate Audit Hook", 1500))
	defer srv.Close()

	for _, r := range RefreshHooks(context.Background(), testClient(t, srv)) {
		if r.Updated {
			t.Errorf("%s was installed on a device that had none", r.File)
		}
		if _, err := os.Stat(filepath.Join(config.HooksDir(), r.File)); err == nil {
			t.Errorf("%s was written where nothing was registered", r.File)
		}
	}
	// Files in ~/.solongate/hooks that no client's settings point at look armed
	// and enforce nothing. Registering them is `repair`'s job, and a half
	// install is worse than no install.
}

func TestRefreshHooksReplacesOnlySomethingNewer(t *testing.T) {
	sandbox(t)
	target := filepath.Join(config.HooksDir(), "audit.mjs")
	installed := hookBody("SolonGate Audit Hook", 1500)
	installed = strings.Replace(installed, "HOOK_VERSION = 81", "HOOK_VERSION = 80", 1)
	if err := os.WriteFile(target, []byte(installed), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := hookServer(t, 81, hookBody("SolonGate Audit Hook", 1500))
	defer srv.Close()
	results := RefreshHooks(context.Background(), testClient(t, srv))

	var audit *HookResult
	for i := range results {
		if results[i].File == "audit.mjs" {
			audit = &results[i]
		}
	}
	if audit == nil || !audit.Updated || audit.From != 80 || audit.To != 81 {
		t.Fatalf("audit hook was not updated: %+v", audit)
	}
	if HookVersion("audit.mjs") != 81 {
		t.Fatalf("installed version is %d after the update", HookVersion("audit.mjs"))
	}

	// Same server, second pass: the file is now current and must be left alone.
	// A refresh that rewrote an identical file every time would churn the one
	// file self-protection is watching.
	for _, r := range RefreshHooks(context.Background(), testClient(t, srv)) {
		if r.File == "audit.mjs" && r.Updated {
			t.Error("a hook that was already current was replaced again")
		}
	}
}

func TestRefreshHooksLeavesTheWorkingHookWhenTheDownloadIsBad(t *testing.T) {
	sandbox(t)
	target := filepath.Join(config.HooksDir(), "audit.mjs")
	installed := hookBody("SolonGate Audit Hook", 1500)
	installed = strings.Replace(installed, "HOOK_VERSION = 81", "HOOK_VERSION = 80", 1)
	if err := os.WriteFile(target, []byte(installed), 0o644); err != nil {
		t.Fatal(err)
	}

	// A newer version whose checksum is wrong. The guard runs this file before
	// every tool call: leaving it exactly as it was is the only acceptable
	// outcome.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": 99,
			"content": base64.StdEncoding.EncodeToString([]byte(hookBody("SolonGate Audit Hook", 1500))),
			"sha256":  strings.Repeat("0", 64),
		})
	}))
	defer srv.Close()

	RefreshHooks(context.Background(), testClient(t, srv))

	after, err := os.ReadFile(target)
	if err != nil || string(after) != installed {
		t.Fatal("a refused download changed the installed hook")
	}
	if _, err := os.Stat(filepath.Join(config.HooksDir(), ".audit.mjs.tmp")); err == nil {
		t.Error("a temp file was left in the hooks directory")
	}
}

func TestReplaceFileKeepsSelfProtectionOn(t *testing.T) {
	sandbox(t)
	// Self-protection chmods the guard's files read-only. A plain rename over a
	// 0444 file succeeds on Linux and leaves a 0644 file behind, which silently
	// disarms the protection until the next repair.
	t.Setenv("SOLONGATE_NO_OS_LOCK", "")
	target := filepath.Join(config.HooksDir(), "guard.mjs")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o444); err != nil {
		t.Fatal(err)
	}

	if err := replaceFile(target, []byte("new")); err != nil {
		t.Fatalf("replaceFile: %v", err)
	}
	body, err := os.ReadFile(target)
	if err != nil || string(body) != "new" {
		t.Fatalf("contents = %q, %v", body, err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o222 != 0 {
		t.Errorf("the file came back writable (%v): self-protection was dropped", info.Mode().Perm())
	}
}

func TestReplaceFileIsAtomicWhenNothingIsLocked(t *testing.T) {
	sandbox(t)
	target := filepath.Join(config.HooksDir(), "guard.mjs")
	if err := os.WriteFile(target, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(target, []byte("new")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new" {
		t.Fatalf("contents = %q", b)
	}
	// The temp file the rename came from must not be left behind: a stray
	// .guard.mjs.tmp in the hooks directory is a file that looks like a hook.
	entries, err := os.ReadDir(config.HooksDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left behind %s", e.Name())
		}
	}
}

func TestHookVersionReadsWhatTheHookBakedIn(t *testing.T) {
	sandbox(t)
	if err := os.WriteFile(filepath.Join(config.HooksDir(), "guard.mjs"),
		[]byte("#!/usr/bin/env node\nconst HOOK_VERSION = 80;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := HookVersion("guard.mjs"); got != 80 {
		t.Errorf("HookVersion = %d, want 80", got)
	}
	// Absent and unversioned are the same answer on purpose: a hook with no
	// version predates the self-update mechanism and is behind anything the
	// cloud can serve.
	if got := HookVersion("shield.mjs"); got != 0 {
		t.Errorf("HookVersion of a missing hook = %d, want 0", got)
	}
	if err := os.WriteFile(filepath.Join(config.HooksDir(), "shield.mjs"),
		[]byte("#!/usr/bin/env node\n// no version here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := HookVersion("shield.mjs"); got != 0 {
		t.Errorf("HookVersion of an unversioned hook = %d, want 0", got)
	}
}

func TestNoticeIsThrottledAndSaysWhatToRun(t *testing.T) {
	sandbox(t)
	t.Setenv("SOLONGATE_AUTO_UPDATE", "off")
	defer func(v string) { Version = v }(Version)
	Version = "0.83.20"
	// A check that already happened, so nothing here touches the network.
	if err := config.SaveSelfUpdateState(config.SelfUpdateState{
		LastCheckAt: nowMillis(),
		LatestSeen:  "0.83.21",
	}); err != nil {
		t.Fatal(err)
	}

	var lines []string
	notifyOnce(func(s string) { lines = append(lines, s) })
	if len(lines) == 0 {
		t.Fatal("a newer version was known and nothing was said")
	}
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "0.83.21") || !strings.Contains(joined, "solongate update") {
		t.Errorf("the notice does not say what is out or what to run:\n%s", joined)
	}
	// Never `npm i -g` here: `solongate update` does the install AND the
	// guard-hook refresh that has to follow it.
	if strings.Contains(joined, "npm i -g") {
		t.Errorf("the notice sent the user to npm instead of the command that also refreshes the guard:\n%s", joined)
	}

	// Same version, straight away: the six-hour attempt throttle covers the
	// notice too, or it repeats on every single command.
	lines = nil
	notifyOnce(func(s string) { lines = append(lines, s) })
	if len(lines) != 0 {
		t.Errorf("the notice repeated inside the throttle window: %v", lines)
	}
}

// A failed attempt must not lock the next one out.
//
// notifyOnce used to stamp the attempt BEFORE trying anything, and the comment
// beside the install still promised that a spawn which never started would be
// retried on the next run. It was not — the stamp was already written, so six
// hours had to pass before that version was considered again. npm missing from
// PATH for one invocation, an unwritable log, a fork that failed: any of them
// turned "retry next run" into "give up until tomorrow", which is exactly what
// an auto-update that works most of the time and sometimes does not looks like.
func TestAFailedAttemptDoesNotBurnTheRetryWindow(t *testing.T) {
	sandbox(t)
	defer func(v string) { Version = v }(Version)
	Version = "0.83.20"

	// Auto-update on, and npm unreachable so the spawn cannot start.
	t.Setenv("SOLONGATE_AUTO_UPDATE", "1")
	t.Setenv("PATH", t.TempDir())

	// A newer version already known, so no network call is needed.
	s := readState()
	s.LatestSeen = "0.83.99"
	s.LastCheckAt = nowMillis()
	writeState(s)

	notifyOnce(func(string) {})

	if got := readState().Attempts["0.83.99"]; got != 0 {
		t.Errorf("an attempt that never started was stamped at %d, so the next run will skip it. "+
			"The stamp belongs after the spawn, not before it", got)
	}
}

// And a NOTICE is stamped, because repeating a line somebody has already read on
// every single command is nagging. The two throttles are deliberately different.
func TestANoticeIsThrottledEvenThoughItCannotFail(t *testing.T) {
	sandbox(t)
	defer func(v string) { Version = v }(Version)
	Version = "0.83.20"

	// Auto-update off: the branch that only prints.
	t.Setenv("SOLONGATE_AUTO_UPDATE", "0")

	s := readState()
	s.LatestSeen = "0.83.99"
	s.LastCheckAt = nowMillis()
	writeState(s)

	said := 0
	notifyOnce(func(string) { said++ })
	if said == 0 {
		t.Fatal("no notice for a newer version")
	}
	if readState().Attempts["0.83.99"] == 0 {
		t.Error("the notice was not stamped, so it will repeat on every command")
	}

	said = 0
	notifyOnce(func(string) { said++ })
	if said != 0 {
		t.Error("the notice repeated immediately despite its throttle")
	}
}

// The background install retries far sooner than a notice does. The spawn only
// reports whether npm STARTED — if npm then fails, nothing here learns of it,
// and at six hours a machine could sit a whole day behind with auto-update on
// and apparently working.
func TestTheBackgroundInstallRetriesSoonerThanANotice(t *testing.T) {
	if autoAttemptEvery >= attemptEvery {
		t.Errorf("autoAttemptEvery (%s) is not shorter than attemptEvery (%s); a background "+
			"install that silently failed would wait as long as a line of text nobody needs repeated",
			autoAttemptEvery, attemptEvery)
	}
}

// ── one install at a time ──────────────────────────────────────────────────

// Two installs against the same global prefix leave a machine with NO CLI.
//
// This is not theoretical and it is not npm being fragile: both processes
// extract into the same package directory and both create the same bin
// symlink, so the loser fails with EEXIST and rolls back — taking the
// package.json and the bin link the winner had just written. What the user gets
// is:
//
//	-bash: /home/…/.local/bin/solongate: No such file or directory
//
// and BOTH installs having logged success. So the second one must never start.
func TestOnlyOneInstallRunsAtATime(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	release, ok := acquireInstallLease("0.83.62")
	if !ok {
		t.Fatal("the first installer could not take the lease")
	}
	if _, ok := acquireInstallLease("0.83.62"); ok {
		t.Fatal("a second installer started while the first was running")
	}

	// And once it is done, the next one may go.
	release()
	if _, ok := acquireInstallLease("0.83.63"); !ok {
		t.Fatal("the lease was not released")
	}
}

// Releasing twice is safe, so a caller can defer it without thinking about
// which branch it took.
func TestReleasingTheLeaseTwiceIsSafe(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	release, ok := acquireInstallLease("0.83.62")
	if !ok {
		t.Fatal("could not take the lease")
	}
	release()
	release()
	if _, ok := acquireInstallLease("0.83.62"); !ok {
		t.Fatal("the lease is stuck after a double release")
	}
}

// A lease nobody will ever release expires.
//
// The background installer takes one and exits immediately — its npm outlives
// it, so there is nothing left to release. Without an expiry that machine would
// never update again.
func TestAnAbandonedLeaseExpires(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if _, ok := acquireInstallLease("0.83.62"); !ok {
		t.Fatal("could not take the lease")
	}
	if _, ok := acquireInstallLease("0.83.62"); ok {
		t.Fatal("a live lease did not hold")
	}

	// Wind it back past its deadline, as time would.
	path := installLeasePath()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no lease on disk: %v", err)
	}
	var lease installLease
	if err := json.Unmarshal(body, &lease); err != nil {
		t.Fatalf("the lease is not readable: %v", err)
	}
	lease.Until = time.Now().Add(-time.Minute).Unix()
	next, _ := json.Marshal(lease)
	if err := os.WriteFile(path, next, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, ok := acquireInstallLease("0.83.63"); !ok {
		t.Fatal("an expired lease still blocks every update on the machine")
	}
}

// A lease file that cannot be parsed is taken over rather than obeyed forever.
//
// A corrupt one would otherwise be a permanent block on updates, and what it
// guards against is bounded by a timeout anyway.
func TestAnUnreadableLeaseDoesNotBlockForever(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)

	if err := os.MkdirAll(filepath.Join(home, ".solongate"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installLeasePath(), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, ok := acquireInstallLease("0.83.62"); !ok {
		t.Fatal("a corrupt lease blocks updates permanently")
	}
}

// An exit code of 0 is evidence about npm's own process and nothing else.
//
// Under the race above, the winner exited 0 and the loser then rolled back over
// it — so the install that "succeeded" was already gone. The check is the one a
// shell makes: is there a package here, and does its entry point exist.
func TestVerifyCatchesAnInstallThatWasRolledBackOverIt(t *testing.T) {
	pkgDir := filepath.Join(t.TempDir(), "node_modules", "@solongate", "proxy")
	if err := os.MkdirAll(filepath.Join(pkgDir, "dist"), 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(pkgDir, "package.json")
	entry := filepath.Join(pkgDir, "dist", "cli-launch.js")

	// The state the rollback leaves: a directory full of files and no manifest.
	// This is the one a person cannot diagnose from what their shell prints.
	err := verifyInstalledAt(pkgDir, "0.83.62")
	if err == nil {
		t.Fatal("a package with no package.json passed verification")
	}
	if !strings.Contains(err.Error(), "package.json") {
		t.Errorf("the failure does not name what is missing: %v", err)
	}

	// Manifest back, entry point still gone — the other half of the same
	// rollback, and the half that makes the command not run.
	if err := os.WriteFile(manifest,
		[]byte(`{"version":"0.83.62","bin":{"solongate":"dist/cli-launch.js"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledAt(pkgDir, "0.83.62"); err == nil {
		t.Fatal("a package with no entry point passed verification")
	}

	// Both present: this is what a good install leaves.
	if err := os.WriteFile(entry, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledAt(pkgDir, "0.83.62"); err != nil {
		t.Errorf("a complete install was rejected: %v", err)
	}

	// And a version that is not the one npm said it installed is the other way
	// this goes wrong: the winner installed something else over us.
	if err := os.WriteFile(manifest,
		[]byte(`{"version":"0.83.61","bin":{"solongate":"dist/cli-launch.js"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyInstalledAt(pkgDir, "0.83.62"); err == nil {
		t.Error("the wrong version on disk passed verification")
	}
}

// An unrecognised layout is not a failure. Source builds, unusual prefixes and
// pnpm's store all reach the check, and refusing an update because the tree
// does not look the way one packaging tool lays it out would break more
// machines than it fixes.
func TestVerifyIsSilentWhenItCannotTell(t *testing.T) {
	// No path at all: ownPackageDir found nothing, which is the ordinary answer
	// for a source build.
	if err := verifyInstalledAt("", "0.83.62"); err != nil {
		t.Errorf("verify refused a layout it cannot recognise: %v", err)
	}
	// A path that is not there. This is NOT the rollback state — that leaves
	// the directory behind — and reporting it is what told somebody their
	// working install had failed.
	if err := verifyInstalledAt(filepath.Join(t.TempDir(), "nope"), "0.83.62"); err != nil {
		t.Errorf("a directory that does not exist was called a failed install: %v", err)
	}
}

// The CLI binary is not in the package being installed: it lives in a PLATFORM
// package, nested under the proxy's own node_modules. Walking up to the first
// node_modules therefore lands in the proxy's private dependency folder, where
// @solongate/proxy can never be — which is exactly how a successful install
// came to report "update failed".
func TestThePackageIsFoundFromThePlatformBinary(t *testing.T) {
	root := t.TempDir()
	pkgDir := filepath.Join(root, "node_modules", "@solongate", "proxy")
	binDir := filepath.Join(pkgDir, "node_modules", "@solongate", "guard-linux-x64", "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(dir, name string) {
		if err := os.WriteFile(filepath.Join(dir, "package.json"),
			[]byte(`{"name":"`+name+`","version":"0.83.71"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(pkgDir, pkgName)
	write(filepath.Dir(binDir), "@solongate/guard-linux-x64")

	exe := filepath.Join(binDir, "solongate")
	if got := packageDirAbove(exe, pkgName); got != pkgDir {
		t.Errorf("the package was resolved to %q, want %q", got, pkgDir)
	}
	// The first node_modules above the binary is the WRONG answer, and the one
	// this replaced.
	if got := nodeModulesAbove(exe); got == filepath.Join(root, "node_modules") {
		t.Error("the walk happened to find the global folder; the test proves nothing")
	}
	// A binary with no package above it answers "cannot tell" rather than
	// guessing.
	if got := packageDirAbove(filepath.Join(root, "elsewhere", "solongate"), pkgName); got != "" {
		t.Errorf("a stray binary resolved to %q", got)
	}
}

// npm doing the work and the check not being able to confirm it is not the same
// as the install failing — and the difference decides whether the hooks get
// registered.
//
// This is what happened in the field: a correct 0.83.71 install verified
// against a path the package can never be in, the CLI printed "update failed",
// and the repair that writes and registers the hooks never ran. The machine was
// updated and its conversation hook was a version old, which is the state where
// nothing reports what a turn cost.
func TestAnUnconfirmedInstallStillCountsAsHavingRun(t *testing.T) {
	confirmed := installResult{ok: true, ran: true}
	unconfirmed := installResult{ok: false, ran: true, why: "could not find the package"}
	refused := installResult{}

	if !confirmed.ran || !unconfirmed.ran {
		t.Error("an install npm actually performed does not say so")
	}
	if refused.ran {
		t.Error("an install that never started claims to have run")
	}
	if unconfirmed.why == "" {
		t.Error("an unconfirmed install gives the person nothing to act on")
	}
}
