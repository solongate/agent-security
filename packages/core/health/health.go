// SPDX-License-Identifier: Apache-2.0

// Package health answers one question: is this machine actually enforcing?
//
// IT IS NOT PART OF THE CLI, even though `solongate doctor` is where most people
// read it. The dataroom shows the same checks, and when this lived in the CLI
// package the TUI imported the CLI to get at them. That edge was the only thing
// standing between the two surfaces being siblings, and five symbols were all it
// carried.
//
// So the collection lives here and the rendering lives with whoever is doing the
// rendering: doctor.go prints a table, the dataroom draws a panel, and neither
// has to know the other exists.

package health

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

	"github.com/solongate/agent-security/packages/core/api"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/install"
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
	//
	// AND WHETHER IT IS THERE. This was StateOK unconditionally: it printed the
	// path and said nothing about whether anything was at it. On a machine that
	// had just been installed, the one check that could have said "you have no
	// policy yet" reported a tick instead, above a row saying no policy resolves.
	// A guard with no policy allows every call, so this is the difference between
	// a machine that is enforcing and one that is only watching.
	if _, err := os.Stat(api.PolicyPath()); err != nil {
		add("policy file", StateWarn, "none yet · "+api.PolicyPath()+" · run `solongate` to write one")
	} else {
		add("policy file", StateOK, api.PolicyPath())
	}
	checks = append(checks, policyChecks(ctx, c)...)
	checks = append(checks, guardHookCheck(ctx, c)...)

	checks = append(checks, nativeGuardCheck()...)
	checks = append(checks, clientChecks()...)
	checks = append(checks, localLogCheck()...)
	checks = append(checks, protectedCheck(ctx, c)...)
	return checks
}

// protectedCheck reports the protected paths and, more importantly, whether
// what is holding them is the operating system or a string match.
//
// THE TWO LOOK IDENTICAL FROM EVERYWHERE ELSE. A protected path with an OS
// lock and a sandboxed agent is a promise the kernel keeps. The same path with
// neither is a promise that holds until the agent writes a two-line script.
// Both print the word "protected" in the config file, so this is the row that
// has to say which.
func protectedCheck(ctx context.Context, c *api.Client) []Check {
	paths, err := c.Settings.ProtectedPaths(ctx)
	if err != nil || len(paths) == 0 {
		return nil
	}

	weakest := ""
	locked := 0
	for _, p := range paths {
		l := config.CheckLock(p)
		if l.Immutable {
			locked++
			continue
		}
		if weakest == "" {
			weakest = p + " · " + l.Summary()
		}
	}

	var out []Check
	switch {
	case locked == len(paths):
		out = append(out, Check{Name: "protected paths", OK: StateOK,
			Detail: plural(len(paths), "path", "paths") + " · all locked against write and delete"})
	default:
		out = append(out, Check{Name: "protected paths", OK: StateWarn,
			Detail: strconv.Itoa(locked) + " of " + strconv.Itoa(len(paths)) +
				" fully locked · " + weakest})
	}

	// And whether the last agent to make a call was actually inside a sandbox.
	required, _ := c.Settings.RequireSandbox(ctx)
	rec := config.NewestEvalRecord()
	switch {
	case required:
		out = append(out, Check{Name: "confinement", OK: StateOK,
			Detail: "required · a call from outside `solongate run` is refused"})
	case rec == nil:
		out = append(out, Check{Name: "confinement", OK: StateWarn,
			Detail: "no tool call recorded yet, so nothing is known about it"})
	case rec.Sandbox != "":
		out = append(out, Check{Name: "confinement", OK: StateOK,
			Detail: "the last call came from inside `solongate run`"})
	default:
		out = append(out, Check{Name: "confinement", OK: StateWarn,
			Detail: "the last call came from an agent started outside `solongate run`, " +
				"so the kernel was not enforcing these paths for it"})
	}
	return out
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
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
		// NOT "falls back to default". There is no default to fall back to: a nil
		// policy evaluates to the empty string and the call is allowed, which is
		// the opposite of what the old wording implied to anyone who read it as a
		// safe default being in force.
		checks = append(checks, Check{Name: "active policy", OK: StateWarn,
			Detail: "none · every call is allowed, and recorded"})
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

	// Redact used to be reported as "detect", on the grounds that the storage
	// word would look like a fourth mode nobody could choose. It was not a
	// storage word: it was what the layer did, and calling it detect is what let
	// a mode that masked every secret it found pass for one that only watched.
	// Three modes exist and each is named here by the thing it does.
	switch {
	case active.Security != nil && active.Security.DLPBlock != nil:
		checks = append(checks, Check{Name: "dlp", OK: StateOK,
			Detail: "block · " + strconv.Itoa(len(active.Security.DLPBlock.Patterns)) +
				" patterns · refuses a call carrying one"})
	case active.Security != nil && active.Security.DLPRedact != nil:
		checks = append(checks, Check{Name: "dlp", OK: StateOK,
			Detail: "redact · " + strconv.Itoa(len(active.Security.DLPRedact.Patterns)) +
				" patterns · masks secrets, never blocks"})
	case active.Security != nil && active.Security.DLPObserve != nil:
		checks = append(checks, Check{Name: "dlp", OK: StateOK,
			Detail: "detect · " + strconv.Itoa(len(active.Security.DLPObserve.Patterns)) +
				" patterns · records hits, changes nothing"})
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

// credentialCheck stood here, and reported `hook credential  rejected by <api> 3m ago
// · key from <source> - nothing is being logged from there`. It read a marker the
// guard dropped on a 401 or a 403, which named which of three places the key had come
// from — the point being that a stale key in the .env of whatever folder an agent
// happened to start in silenced every audit write while enforcement kept working.
//
// Nothing writes to a service, so nothing is ever rejected. What could still silence
// an audit write is a folder that cannot be written, and localLogCheck below says so.

// localLogCheck resolves the folder the POLICY configures rather than assuming the
// default one. Every viewer used to read the default unconditionally, so a custom
// folder made doctor report an empty log while entries landed somewhere else.
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

// fixed0 rounds to a whole number the way JavaScript's toFixed(0) does. It is
// four tokens, and the alternative was for this package to import the CLI's
// formatting helpers, which is the dependency the split exists to remove.
func fixed0(v float64) string { return strconv.FormatInt(int64(math.Round(v)), 10) }

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
