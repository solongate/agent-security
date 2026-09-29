package commands

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func findCheck(t *testing.T, checks []Check, name string) Check {
	t.Helper()
	for _, c := range checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no %q row in %v", name, checks)
	return Check{}
}

func doctorStub(t *testing.T, c *api.Client, active string) *api.Client {
	t.Helper()
	// The two routes this used to stub — /policies/active and
	// /settings/guard-status — are read from this machine now, so what a test sets
	// up is the FILE. It has to be written AFTER stubClient redirects HOME, which is
	// why this takes the client rather than being passed to it: as an argument it
	// was evaluated first and wrote into the developer's own home directory.
	seedPolicy(t, active)
	return c
}

// A project in DETECT mode carries its limits in rateLimitObserve and nothing at
// all in rateLimit. Reading only the first reported it as off — the guard was
// flagging bursts and the health check said no rate limit was configured.
func TestDoctorReportsDetectModeRateLimit(t *testing.T) {
	c := stubClient(t, http.NewServeMux())
	seedPolicy(t, `{
		"policy":{"id":"pol-1","name":"Default","mode":"whitelist","rules":[]},
		"security":{"rateLimitObserve":{"perMinute":60,"perHour":0,"perDay":0},
		            "dlpRedact":{"patterns":["AWS access key","JWT"],"custom":[]}}
	}`)

	checks := CollectChecks(context.Background(), c)

	rl := findCheck(t, checks, "rate limit")
	if rl.OK != StateOK {
		t.Fatalf("detect mode is configured, not off: %+v", rl)
	}
	if rl.Detail != "detect · 60/min · flags bursts, never blocks" {
		t.Fatalf("wording changed: %q", rl.Detail)
	}

	// The middle DLP state is stored as "redact" and called detect everywhere a
	// user sees it. Printing the storage word made it look like a fourth mode.
	dlp := findCheck(t, checks, "dlp")
	if dlp.Detail != "detect · 2 patterns · masks secrets, never blocks" {
		t.Fatalf("wording changed: %q", dlp.Detail)
	}

	pol := findCheck(t, checks, "active policy")
	if pol.Detail != "Default v1 · whitelist · matched by pinned" {
		t.Fatalf("wording changed: %q", pol.Detail)
	}
}

func TestDoctorReportsBlockingLayers(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{
		"policy":{"id":"pol-1","name":"Locked","rules":[]},
		"version":2,"matched_by":"default","selfProtect":false,
		"security":{"rateLimit":{"perMinute":10,"perHour":200,"perDay":0},
		            "dlpBlock":{"patterns":["JWT"],"custom":[]},"dlpRedact":null}
	}`)
	checks := CollectChecks(context.Background(), c)

	if got := findCheck(t, checks, "rate limit").Detail; got != "block · 10/min · 200/hr" {
		t.Fatalf("an unset window must be left out entirely, got %q", got)
	}
	if got := findCheck(t, checks, "dlp").Detail; got != "block · 1 patterns" {
		t.Fatalf("wording changed: %q", got)
	}
	// A policy with no mode is a denylist; that is the fallback the guard uses.
	if got := findCheck(t, checks, "active policy").Detail; !strings.Contains(got, "· denylist ·") {
		t.Fatalf("missing mode fallback: %q", got)
	}
	sp := findCheck(t, checks, "self-protection")
	if sp.OK != StateWarn || sp.Detail != "off" {
		t.Fatalf("self-protection off is a warning: %+v", sp)
	}
}

// A file that configures LAYERS AND NO RULES is a real configuration: DLP on,
// nothing forbidden. It has to read as "no policy resolves" rather than as an error,
// and the layers still have to be reported.
func TestDoctorSaysWhenNoPolicyResolves(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{"policy":null,"security":null,"selfProtect":false}`)
	checks := CollectChecks(context.Background(), c)

	pol := findCheck(t, checks, "active policy")
	if pol.OK != StateWarn || pol.Detail != "no policy resolves - every call falls back to default" {
		t.Fatalf("wording changed: %+v", pol)
	}
	// `security: null` is an ANSWER — this project has no layers — and both
	// layers have to say off rather than going missing.
	if got := findCheck(t, checks, "rate limit"); got.OK != StateWarn || got.Detail != "off" {
		t.Fatalf("rate limit: %+v", got)
	}
	if got := findCheck(t, checks, "dlp"); got.OK != StateWarn || got.Detail != "off" {
		t.Fatalf("dlp: %+v", got)
	}
}

// AN UNREADABLE POLICY FILE MUST NOT COST THE ROWS ABOUT THIS MACHINE.
//
// This used to stub a 500 on /policies/active and require an "api unreachable" row,
// because the rows worth having when the network is the problem are the local ones.
// There is no network; the equivalent failure is a file the guard cannot parse — and
// the guard answers that the same way, by enforcing nothing.
func TestDoctorStillReportsLocalStateWhenThePolicyIsUnreadable(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{ "rules": [ }`)

	checks := CollectChecks(context.Background(), c)
	if got := findCheck(t, checks, "policy"); got.OK != StateFail {
		t.Fatalf("an unparseable policy is a failed check: %+v", got)
	}
	claude := findCheck(t, checks, "Claude hooks")
	if claude.OK != StateFail || claude.Detail != "guard NOT registered - run `solongate repair`" {
		t.Fatalf("wording changed: %+v", claude)
	}
	findCheck(t, checks, "local logs")
}

func TestDoctorReportsAClientOnlyWhenItIsInstalled(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{"policy":null,"security":null}`)
	home := os.Getenv("HOME")

	checks := CollectChecks(context.Background(), c)
	for _, ch := range checks {
		if strings.HasPrefix(ch.Name, "Codex") || strings.HasPrefix(ch.Name, "OpenCode") {
			t.Fatalf("a row for a client that is not on this machine: %+v", ch)
		}
	}

	// Install Codex's config dir with the guard registered but never trusted.
	// Codex silently SKIPS a hook it has not been trusted for, so "registered"
	// alone does not mean the guard is live there.
	codex := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codex, 0o755); err != nil {
		t.Fatal(err)
	}
	hooks := `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"node ` +
		home + `/.solongate/hooks/guard.mjs codex"}]}]}}`
	if err := os.WriteFile(filepath.Join(codex, "hooks.json"), []byte(hooks), 0o644); err != nil {
		t.Fatal(err)
	}

	got := findCheck(t, CollectChecks(context.Background(), c), "Codex hooks")
	if got.OK != StateWarn || !strings.Contains(got.Detail, "trust them") {
		t.Fatalf("registered-but-untrusted must warn: %+v", got)
	}

	// Hooks switched off wholesale disarms the guard on Codex entirely, and that
	// is a failure rather than a warning.
	cfg := "[features]\nhooks = false\n[hooks.state.\"abc\"]\ntrusted_hash = \"x\"\n"
	if err := os.WriteFile(filepath.Join(codex, "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	got = findCheck(t, CollectChecks(context.Background(), c), "Codex hooks")
	if got.OK != StateFail || !strings.Contains(got.Detail, "hooks disabled") {
		t.Fatalf("hooks=false must fail: %+v", got)
	}
}

// The top-level shape is what some installs have on disk; a reader that only
// looked under "hooks" would send someone to repair an already-guarded machine.
func TestCodexGuardFoundInEitherFileShape(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{"policy":null,"security":null}`)
	_ = c
	home := os.Getenv("HOME")
	codex := filepath.Join(home, ".codex")
	if err := os.MkdirAll(codex, 0o755); err != nil {
		t.Fatal(err)
	}
	top := `{"PreToolUse":[{"hooks":[{"type":"command","command":"node ` + home + `/.solongate/hooks/x.mjs"}]}]}`
	if err := os.WriteFile(filepath.Join(codex, "hooks.json"), []byte(top), 0o644); err != nil {
		t.Fatal(err)
	}
	if !isCodexGuardInstalled() {
		t.Fatal("the guard is registered at the top level and was reported missing")
	}
}

func TestDoctorJSONKeepsTheThreeStateVerdict(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{
		"policy":{"id":"p","name":"N","rules":[]},"version":1,"matched_by":"default",
		"selfProtect":true,
		"security":{"rateLimit":{"perMinute":5,"perHour":0,"perDay":0},"dlpBlock":{"patterns":[],"custom":[]}}
	}`)

	o, e := capture(t, func() {
		code, err := runDoctor(context.Background(), c, parse([]string{"--json"}))
		if err != nil {
			t.Fatalf("doctor --json: %v", err)
		}
		// The Claude hook is not registered on this throwaway HOME, which is a
		// problem and therefore a non-zero exit.
		if code != 1 {
			t.Fatalf("a failing check must exit non-zero, got %d", code)
		}
	})
	if e != "" {
		t.Fatalf("--json must not print the human report too: %q", e)
	}

	var rows []struct {
		Name   string          `json:"name"`
		OK     json.RawMessage `json:"ok"`
		Detail string          `json:"detail"`
	}
	if err := json.Unmarshal([]byte(o), &rows); err != nil {
		t.Fatalf("stdout is not a JSON document: %v\n%s", err, o)
	}
	seen := map[string]string{}
	for _, r := range rows {
		seen[r.Name] = string(r.OK)
	}
	// true / false / "warn" is the shape scripts already read.
	if seen["policy file"] != "true" {
		t.Fatalf("ok for a passing check must be true, got %s", seen["policy file"])
	}
	if seen["Claude hooks"] != "false" {
		t.Fatalf("ok for a failing check must be false, got %s", seen["Claude hooks"])
	}
	if seen["local logs"] != `"warn"` {
		t.Fatalf(`ok for a warning must be "warn", got %s`, seen["local logs"])
	}
}

func TestDoctorSummaryLines(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{"policy":null,"security":null}`)
	_, e := capture(t, func() {
		if _, err := runDoctor(context.Background(), c, parse(nil)); err != nil {
			t.Fatal(err)
		}
	})
	plain := ansi.ReplaceAllString(e, "")
	if !strings.Contains(plain, "SolonGate doctor") {
		t.Fatalf("missing heading: %q", plain)
	}
	if !strings.Contains(plain, "problem(s)") || !strings.Contains(plain, "warning(s)") {
		t.Fatalf("missing summary: %q", plain)
	}
}

func TestGuardHookRowPrefersTheVersionOnDisk(t *testing.T) {
	c := doctorStub(t, stubClient(t, http.NewServeMux()), `{"policy":null,"security":null}`)
	home := os.Getenv("HOME")
	hooks := filepath.Join(home, ".solongate", "hooks")
	if err := os.MkdirAll(hooks, 0o755); err != nil {
		t.Fatal(err)
	}
	// The stub cloud says the newest guard is 30. A device carrying 31 has
	// already updated; reading the cloud's number as the installed one made the
	// health check announce an update that was already applied.
	body := "const HOOK_VERSION = 31;\n"
	if err := os.WriteFile(filepath.Join(hooks, guardHookName), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	got := findCheck(t, CollectChecks(context.Background(), c), "guard hook")
	if got.OK != StateOK {
		t.Fatalf("a newer local guard is not out of date: %+v", got)
	}
	// One machine. The count used to come from a service that knew about others.
	if got.Detail != "v31 (latest) · 1 device(s)" {
		t.Fatalf("wording changed: %q", got.Detail)
	}
}

// The one thing about this install nobody can see from outside.
//
// The Go guard and the Node guard reach the same verdicts, so a machine that
// fell back looks exactly like one that did not — same allows, same denials,
// same audit rows. The binary reached nobody for a while precisely because
// nothing reported it, and these are the four answers doctor has to be able to
// give.
func TestTheNativeGuardCheckSaysWhichEngineIsRunning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}

	// 1. Nothing installed: a warning, never a failure. The machine IS guarded.
	t.Setenv("SOLONGATE_GUARD_BIN", "")
	t.Setenv("SOLONGATE_NO_GO_GUARD", "")
	c := nativeGuardCheck()
	if len(c) != 1 {
		t.Fatalf("expected one check, got %d", len(c))
	}
	if c[0].OK == StateFail {
		t.Error("an absent binary is reported as a FAILURE. It is not one — the Node " +
			"implementation enforces the same policy, and calling this broken sends people " +
			"looking for an outage that is not happening")
	}
	if c[0].OK != StateWarn {
		t.Errorf("an absent binary is reported as %v; it has to be visible, or the whole "+
			"point of the port stays invisible", c[0].OK)
	}

	// 2. Pinned off deliberately: say so rather than reporting it missing.
	t.Setenv("SOLONGATE_NO_GO_GUARD", "1")
	if got := nativeGuardCheck()[0].Detail; !strings.Contains(got, "SOLONGATE_NO_GO_GUARD") {
		t.Errorf("with the escape hatch on, doctor says %q — it should name the variable, "+
			"or the reason looks like a fault", got)
	}
	t.Setenv("SOLONGATE_NO_GO_GUARD", "")

	// 3. A binary that answers with the version the hook wants: in use.
	bin := filepath.Join(t.TempDir(), "fake-guard")
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in is a shell script")
	}
	want := installedGuardVersion()
	v := "80"
	if want != nil {
		v = strconv.Itoa(*want)
	}
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho "+v+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOLONGATE_GUARD_BIN", bin)
	if got := nativeGuardCheck()[0]; got.OK != StateOK {
		t.Errorf("a matching binary is reported as %v (%q), want OK", got.OK, got.Detail)
	}

	// 4. A binary that answers with a DIFFERENT version. The hook refuses it and
	// runs Node — the most confusing state there is, because the file is right
	// there and doing nothing.
	if want != nil {
		if err := os.WriteFile(bin, []byte("#!/bin/sh\necho 1\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		got := nativeGuardCheck()[0]
		if got.OK == StateOK {
			t.Error("a binary whose version does not match the hook is reported as in use. " +
				"The hook refuses it and runs Node, so this is the state that most needs saying")
		}
		if !strings.Contains(got.Detail, "mismatch") && !strings.Contains(got.Detail, "hook is v") {
			t.Errorf("the mismatch is not explained: %q", got.Detail)
		}
	}
}

// …and that it is actually in the list doctor prints.
//
// The test above calls nativeGuardCheck directly, which passes whether or not
// anything ever calls it — deleting the one line that appends it to CollectChecks
// left that test green. A check nobody runs is not a check.
func TestDoctorIncludesTheNativeGuard(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if runtime.GOOS == "windows" {
		t.Setenv("USERPROFILE", home)
	}
	// Unauthenticated on purpose: the native-guard row is about this machine,
	// not about the account, so it has to appear without a login round trip.
	checks := CollectChecks(context.Background(), api.New())
	for _, c := range checks {
		if c.Name == "native guard" {
			return
		}
	}
	var names []string
	for _, c := range checks {
		names = append(names, c.Name)
	}
	t.Errorf("doctor does not report the native guard. It ran: %v\n"+
		"Which engine is enforcing is the one thing about this install that is invisible from "+
		"every other angle — both guards give the same verdicts, so a machine falling back looks "+
		"exactly like one that is not.", names)
}
