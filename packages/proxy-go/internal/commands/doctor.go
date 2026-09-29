package commands

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/install"
)

// CheckState is a check's verdict, and it has three values rather than two.
//
// A warning is not a failure: local logging being off, or no rate limit set, is
// a choice someone may have made deliberately, and only StateFail sets a
// non-zero exit code. The JSON encoding is `true` / `false` / `"warn"` because
// that is what `doctor --json` already emits and scripts read it.
type CheckState int

const (
	StateFail CheckState = iota
	StateOK
	StateWarn
)

func (s CheckState) MarshalJSON() ([]byte, error) {
	switch s {
	case StateOK:
		return []byte("true"), nil
	case StateWarn:
		return []byte(`"warn"`), nil
	}
	return []byte("false"), nil
}

// Check is one row of the health check.
type Check struct {
	Name   string     `json:"name"`
	OK     CheckState `json:"ok"`
	Detail string     `json:"detail"`
}

// CollectChecks runs the health check and returns it without printing anything.
//
// Nothing in here returns an error to the router. An unreachable cloud is a
// FINDING, not a crash: the rows about this machine's own installation are the
// ones that matter most when the network is down, and losing them to a single
// failed request would hide exactly the state someone is running doctor to see.
//
// The no-printing part is load-bearing twice over. The dataroom's Settings panel
// shows the same rows, and Bubble Tea owns the terminal while it is up, so
// anything it calls has to hand back data rather than write to the stream. And
// `--json` needs the same values the human view renders, not a second
// implementation of them that can drift.
func CollectChecks(ctx context.Context, c *api.Client) []Check {
	var checks []Check
	add := func(name string, ok CheckState, detail string) {
		checks = append(checks, Check{Name: name, OK: ok, Detail: detail})
	}

	// The first check used to be `login`, and it failed with "not logged in — add
	// your account in the Accounts panel". Everything below it was skipped on that
	// failure, so a machine with no service reported nothing about itself at all.
	// The first check is the file everything else comes from.
	add("policy file", StateOK, api.PolicyPath())
	checks = append(checks, policyChecks(ctx, c)...)
	checks = append(checks, guardHookCheck(ctx, c)...)

	checks = append(checks, nativeGuardCheck()...)
	checks = append(checks, clientChecks()...)
	checks = append(checks, credentialCheck()...)
	checks = append(checks, localLogCheck()...)
	return checks
}

// activeWithObserve decodes /policies/active twice out of one response.
//
// The typed ActivePolicy does not carry `rateLimitObserve`, and reading only
// `rateLimit` reports a project in DETECT mode as having no rate limit at all —
// the limits ride in one field when they block and the other when they only
// flag. Rather than widen a type another part of the CLI owns, the raw body is
// kept and the extra field read off it.
type activeWithObserve struct {
	api.ActivePolicy
	rateLimitObserve *api.RateLimitSettings
}

// fetchActive reads what the guard would enforce, from the file the guard reads.
//
// It used to go through c.Do for the raw body, because rateLimitObserve is not on
// ActivePolicy and re-asking for it typed would have lost it. Reading the file
// answers both in one pass: a detect-mode limit is `rateLimitObserve` there.
func fetchActive(ctx context.Context, c *api.Client) (activeWithObserve, error) {
	active, err := c.Policies.Active(ctx, "")
	if err != nil {
		return activeWithObserve{}, err
	}
	out := activeWithObserve{ActivePolicy: active}
	raw, err := json.Marshal(active)
	if err != nil {
		return out, nil
	}
	var extra struct {
		Security *struct {
			RateLimitObserve *api.RateLimitSettings `json:"rateLimitObserve"`
		} `json:"security"`
	}
	if json.Unmarshal(raw, &extra) == nil && extra.Security != nil {
		out.rateLimitObserve = extra.Security.RateLimitObserve
	}
	return out, nil
}

func policyChecks(ctx context.Context, c *api.Client) []Check {
	active, err := fetchActive(ctx, c)
	if err != nil {
		// The guard reads this file too, and answers the same way: an unparseable
		// policy is no policy, so nothing is enforced. A failed check, not an
		// "api unreachable".
		return []Check{{Name: "policy", OK: StateFail, Detail: err.Error()}}
	}

	var checks []Check
	if active.Policy != nil {
		mode := string(active.Policy.Mode)
		if mode == "" {
			mode = "denylist"
		}
		checks = append(checks, Check{Name: "active policy", OK: StateOK,
			Detail: active.Policy.Name + " v" + strconv.Itoa(active.Version) + " · " + mode +
				" · matched by " + active.MatchedBy})
	} else {
		checks = append(checks, Check{Name: "active policy", OK: StateWarn,
			Detail: "no policy resolves - every call falls back to default"})
	}

	var rlBlock *api.RateLimitSettings
	if active.Security != nil {
		rlBlock = active.Security.RateLimit
	}
	switch {
	case rlBlock != nil:
		checks = append(checks, Check{Name: "rate limit", OK: StateOK, Detail: "block · " + rlWindows(rlBlock)})
	case active.rateLimitObserve != nil:
		checks = append(checks, Check{Name: "rate limit", OK: StateOK,
			Detail: "detect · " + rlWindows(active.rateLimitObserve) + " · flags bursts, never blocks"})
	default:
		checks = append(checks, Check{Name: "rate limit", OK: StateWarn, Detail: "off"})
	}

	// The middle DLP state is stored as "redact" and called detect everywhere a
	// user sees it, matching the other layers. Reporting the storage word here
	// made it look like a fourth mode that exists nowhere else.
	switch {
	case active.Security != nil && active.Security.DLPBlock != nil:
		checks = append(checks, Check{Name: "dlp", OK: StateOK,
			Detail: "block · " + strconv.Itoa(len(active.Security.DLPBlock.Patterns)) + " patterns"})
	case active.Security != nil && active.Security.DLPRedact != nil:
		checks = append(checks, Check{Name: "dlp", OK: StateOK,
			Detail: "detect · " + strconv.Itoa(len(active.Security.DLPRedact.Patterns)) +
				" patterns · masks secrets, never blocks"})
	default:
		checks = append(checks, Check{Name: "dlp", OK: StateWarn, Detail: "off"})
	}

	selfProt := Check{Name: "self-protection", OK: StateWarn, Detail: "off"}
	if active.SelfProtectionEnabled {
		selfProt = Check{Name: "self-protection", OK: StateOK, Detail: "on"}
	}
	return append(checks, selfProt)
}

func rlWindows(l *api.RateLimitSettings) string {
	var parts []string
	if l.PerMinute != 0 {
		parts = append(parts, strconv.Itoa(l.PerMinute)+"/min")
	}
	if l.PerHour != 0 {
		parts = append(parts, strconv.Itoa(l.PerHour)+"/hr")
	}
	if l.PerDay != 0 {
		parts = append(parts, strconv.Itoa(l.PerDay)+"/day")
	}
	if len(parts) == 0 {
		return "no window set"
	}
	return strings.Join(parts, " · ")
}

// guardHookCheck compares the version ON DISK against the newest release the
// cloud knows about. A failure to reach guard-status produces no row at all,
// exactly as before: the guard's own registration is reported below, and an
// extra red line about an endpoint being down would not tell anyone anything
// they can act on.
func guardHookCheck(ctx context.Context, c *api.Client) []Check {
	g, err := c.Settings.GetGuardStatus(ctx)
	if err != nil {
		return nil
	}
	here := installedGuardVersion()

	// Latest is absent rather than zero when the API does not send it — no guard
	// has ever been version 0 — in which case the local version is the newest
	// thing anyone here knows about.
	latest := g.Latest
	if latest == 0 && here != nil {
		latest = *here
	}
	current := g.UpToDate
	if here != nil && latest != 0 {
		current = *here >= latest
	}

	shown := "?"
	switch {
	case here != nil:
		shown = strconv.Itoa(*here)
	case g.Installed != nil:
		shown = strconv.Itoa(*g.Installed)
	}

	if current {
		return []Check{{Name: "guard hook", OK: StateOK,
			Detail: "v" + shown + " (latest) · " + strconv.Itoa(g.DeviceCount) + " device(s)"}}
	}
	return []Check{{Name: "guard hook", OK: StateWarn,
		Detail: "v" + shown + " → v" + strconv.Itoa(latest) +
			" available · run `solongate update` in your terminal"}}
}

// clientChecks is one row per guarded client, named the way `repair` names them,
// so a machine running several can see at a glance which one is unguarded.
func clientChecks() []Check {
	const registered = "guard registered"
	const missing = "guard NOT registered - run `solongate repair`"

	claude := Check{Name: "Claude hooks", OK: StateFail, Detail: missing}
	if isGuardInstalled() {
		claude = Check{Name: "Claude hooks", OK: StateOK, Detail: registered}
	}
	checks := []Check{claude}

	// "Registered" was the only thing ever asked, and it is not the question.
	//
	// The two rows below are: can the registered command actually START, and has
	// a client ever run it. A machine where the first is no looks exactly like a
	// machine with no guard on it — nothing enforced, nothing logged — and this
	// page used to report that machine as healthy, because the config file said
	// so and the config file was all anything read.
	if isGuardInstalled() {
		rt := install.CheckHookRuntime()
		if rt.OK {
			checks = append(checks, Check{Name: "hook runtime", OK: StateOK, Detail: "node " + rt.Detail})
		} else {
			checks = append(checks, Check{Name: "hook runtime", OK: StateFail,
				Detail: rt.Detail + " - nothing is being enforced or logged"})
		}

		switch beat := install.GuardBeat(); {
		case beat == nil:
			checks = append(checks, Check{Name: "guard fired", OK: StateWarn,
				Detail: "never - open your agent, run one tool call, then check again"})
		case beat.Node == "no-node":
			checks = append(checks, Check{Name: "guard fired", OK: StateFail,
				Detail: install.Ago(beat.At) + ", but found no node to run with - run `solongate repair`"})
		default:
			checks = append(checks, Check{Name: "guard fired", OK: StateOK,
				Detail: install.Ago(beat.At) + " · " + beat.Node})
		}
	}

	p := globalPaths()
	if pathExists(p.antigravityDir) {
		if pathExists(p.antigravityHooksPath) {
			checks = append(checks, Check{Name: "Antigravity hooks", OK: StateOK, Detail: registered})
		} else {
			checks = append(checks, Check{Name: "Antigravity hooks", OK: StateFail, Detail: missing})
		}
	}

	if codexDetected() {
		cx := codexHooksStatus()
		switch {
		case !cx.registered:
			checks = append(checks, Check{Name: "Codex hooks", OK: StateFail, Detail: missing})
		case cx.disabled:
			checks = append(checks, Check{Name: "Codex hooks", OK: StateFail,
				Detail: "hooks disabled in ~/.codex/config.toml ([features] hooks = false)"})
		case !cx.trusted:
			checks = append(checks, Check{Name: "Codex hooks", OK: StateWarn,
				Detail: "registered - run `/hooks` in Codex once and trust them (Codex skips untrusted hooks)"})
		default:
			checks = append(checks, Check{Name: "Codex hooks", OK: StateOK, Detail: "registered + trusted"})
		}
	}

	// `opencode --pure` skips external plugins and with them the guard. That is a
	// per-run flag no check here can see, so the row says so rather than claiming
	// a protection one argument removes.
	if opencodeDetected() {
		if isOpencodeGuardInstalled() {
			checks = append(checks, Check{Name: "OpenCode hooks", OK: StateOK,
				Detail: "guard registered (not active under `opencode --pure`)"})
		} else {
			checks = append(checks, Check{Name: "OpenCode hooks", OK: StateFail, Detail: missing})
		}
	}
	return checks
}

// credentialCheck surfaces the cloud rejecting the credential a HOOK used.
//
// The hooks resolve their key as env → the .env of the folder the agent runs in
// → the login, so a stale key in a project (or home) .env makes every audit
// write 401 while enforcement keeps working — invisible unless it is said out
// loud. The guard drops this marker on a 401/403 and removes it on the next
// success, so its presence is the whole finding.
func credentialCheck() []Check {
	m := config.LoadKeyRejected()
	if m == nil {
		return nil
	}
	apiURL := m.APIURL
	if apiURL == "" {
		apiURL = "the API"
	}
	age := ""
	if m.TS != 0 {
		mins := roundHalfUp(float64(time.Now().UnixMilli()-m.TS) / 60000)
		age = " " + strconv.FormatInt(mins, 10) + "m ago"
	}
	keySource := m.KeySource
	if keySource == "" {
		keySource = "?"
	}
	cwd := ""
	if m.Cwd != "" {
		cwd = " (agent cwd " + m.Cwd + ")"
	}
	return []Check{{Name: "hook credential", OK: StateFail,
		Detail: "rejected by " + apiURL + age + " · key from " + keySource + cwd +
			" - nothing is being logged from there"}}
}

// localLogCheck resolves the folder configured in the dashboard rather than
// assuming the default one. Every viewer used to read the default
// unconditionally, so a custom folder made doctor report an empty log while
// entries were landing correctly somewhere else.
func localLogCheck() []Check {
	file := config.LocalLogFile()
	st, err := os.Stat(file)
	if err != nil {
		return []Check{{Name: "local logs", OK: StateWarn,
			Detail: "nothing recorded yet · " + file}}
	}
	ageMin := float64(time.Since(st.ModTime())) / float64(time.Minute)
	when := strconv.FormatInt(roundHalfUp(ageMin), 10) + "m ago"
	if ageMin < 1 {
		when = "just now"
	}
	return []Check{{Name: "local logs", OK: StateOK,
		Detail: "on · " + fixed0(float64(st.Size())/1024) + "KB · last write " + when}}
}

// roundHalfUp is JavaScript's Math.round: floor(v + 0.5), so a half always goes
// up rather than away from zero. It only differs from math.Round for a negative
// half, which here means a clock that moved backwards — rare, but rounding it
// the same way as the CLI this stands beside is one less difference to explain.
func roundHalfUp(v float64) int64 { return int64(math.Floor(v + 0.5)) }

func runDoctor(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	checks := CollectChecks(ctx, c)

	failed := 0
	warned := 0
	for _, ch := range checks {
		switch ch.OK {
		case StateFail:
			failed++
		case StateWarn:
			warned++
		}
	}

	if p.flagBool("json") {
		printJSON(checks)
		if failed > 0 {
			return 1, nil
		}
		return 0, nil
	}

	errln("")
	errln("  " + bold("SolonGate doctor"))
	errln("")
	for _, ch := range checks {
		mark := red("✗")
		switch ch.OK {
		case StateOK:
			mark = green("✓")
		case StateWarn:
			mark = yellow("!")
		}
		errln("  " + mark + " " + padRight(ch.Name, 16) + " " + dim(ch.Detail))
	}
	errln("")
	switch {
	case failed > 0:
		tail := ""
		if warned > 0 {
			tail = dim(" · " + strconv.Itoa(warned) + " warning(s)")
		}
		errln("  " + red(strconv.Itoa(failed)+" problem(s)") + tail)
	case warned > 0:
		errln("  " + yellow(strconv.Itoa(warned)+" warning(s)") + " " + dim("- guard is working"))
	default:
		errln("  " + green("all good"))
	}
	if failed > 0 {
		return 1, nil
	}
	return 0, nil
}

// padRight pads to n columns and never truncates, matching String.padEnd. A
// check name longer than the column pushes its detail right rather than being
// cut: the name is the thing you look up.
func padRight(s string, n int) string {
	if displayWidth(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-displayWidth(s))
}

// nativeGuardCheck reports whether the fast path is armed.
//
// It is the one thing about this install that is invisible from every angle. The
// Go guard and the Node guard reach the same verdicts on the same policy, so a
// machine falling back looks exactly like one that is not: same allows, same
// denials, same audit rows, tens of milliseconds apart on a number nobody is
// watching. That is not a detail to leave undisplayed — the binary is the entire
// reason the port exists, and it reached nobody for a while precisely because
// nothing here said so.
//
// It resolves the binary the way the HOOK resolves it, not the way this program
// found itself. Those can differ — an override, a stale copy, a version that no
// longer matches the hook — and the answer that matters is the one the hook will
// get on the next tool call.
func nativeGuardCheck() []Check {
	const name = "native guard"

	if os.Getenv("SOLONGATE_NO_GO_GUARD") == "1" {
		return []Check{{Name: name, OK: StateWarn,
			Detail: "off · SOLONGATE_NO_GO_GUARD=1 pins the guard to its Node implementation"}}
	}

	bin := filepath.Join(install.BinDir(), nativeGuardName())
	if override := strings.TrimSpace(os.Getenv("SOLONGATE_GUARD_BIN")); override != "" {
		bin = override
	}
	if _, err := os.Stat(bin); err != nil {
		// Not a failure. The machine is guarded; the Node implementation
		// enforces the same policy. Warn rather than fail, and say which of the
		// two is running, because "slower" and "not working" look identical from
		// outside.
		return []Check{{Name: name, OK: StateWarn,
			Detail: "not installed · the guard runs its Node implementation (same policy, slower). " +
				"`solongate repair` installs it if this platform has one"}}
	}

	out, err := exec.Command(bin, "--sg-version").Output()
	if err != nil {
		return []Check{{Name: name, OK: StateWarn,
			Detail: "present but did not answer · the hook will refuse it and use Node. Run `solongate repair`"}}
	}
	got := strings.TrimSpace(string(out))

	// The hook hands over only on an exact match, so a mismatch is the whole
	// answer: the binary is there, it is being refused, and this says why.
	want := installedGuardVersion()
	if want != nil && got != strconv.Itoa(*want) {
		return []Check{{Name: name, OK: StateWarn,
			Detail: "v" + got + " but the hook is v" + strconv.Itoa(*want) +
				" · refused for the mismatch, running Node. Run `solongate repair`"}}
	}
	return []Check{{Name: name, OK: StateOK, Detail: "v" + got + " · in use"}}
}

func nativeGuardName() string {
	if runtime.GOOS == "windows" {
		return "solongate-guard.exe"
	}
	return "solongate-guard"
}
