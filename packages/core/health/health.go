// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package health

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
	"github.com/solongate/agent-security/packages/core/config"
	"github.com/solongate/agent-security/packages/core/install"
)

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

type Check struct {
	Name   string     `json:"name"`
	OK     CheckState `json:"ok"`
	Detail string     `json:"detail"`
}

func CollectChecks(ctx context.Context, c *client.Client) []Check {
	var checks []Check
	add := func(name string, ok CheckState, detail string) {
		checks = append(checks, Check{Name: name, OK: ok, Detail: detail})
	}

	if _, err := os.Stat(client.PolicyPath()); err != nil {
		add("policy file", StateWarn, "none yet · "+client.PolicyPath()+" · run `solongate` to write one")
	} else {
		add("policy file", StateOK, client.PolicyPath())
	}
	checks = append(checks, policyChecks(ctx, c)...)
	checks = append(checks, guardHookCheck(ctx, c)...)

	checks = append(checks, clientChecks()...)
	checks = append(checks, localLogCheck()...)
	checks = append(checks, protectedCheck(ctx, c)...)
	return checks
}

func protectedCheck(ctx context.Context, c *client.Client) []Check {
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

	if v, newer := client.NewerThanThisBuild(); newer {
		out = append(out, Check{Name: "policy format", OK: StateWarn,
			Detail: "written by a newer SolonGate (v" + strconv.Itoa(v) + ") · " +
				"keys it added are being ignored by this build"})
	}

	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range []string{"acc" + "ounts.json", "clou" + "d-guard.json"} {
			stale := filepath.Join(home, ".solongate", name)
			if _, err := os.Stat(stale); err != nil {
				continue
			}
			out = append(out, Check{Name: "stale credential", OK: StateWarn,
				Detail: stale + " holds an API key from when this product had accounts · " +
					"`solongate repair` deletes it; revoke the key at whatever issued it"})
		}
	}

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

type activeWithObserve struct {
	client.ActivePolicy
	rateLimitObserve *client.RateLimitSettings
}

func fetchActive(ctx context.Context, c *client.Client) (activeWithObserve, error) {
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
			RateLimitObserve *client.RateLimitSettings `json:"rateLimitObserve"`
		} `json:"security"`
	}
	if json.Unmarshal(raw, &extra) == nil && extra.Security != nil {
		out.rateLimitObserve = extra.Security.RateLimitObserve
	}
	return out, nil
}

func policyChecks(ctx context.Context, c *client.Client) []Check {
	active, err := fetchActive(ctx, c)
	if err != nil {

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
			Detail: "none · every call is allowed, and recorded"})
	}

	var rlBlock *client.RateLimitSettings
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

func rlWindows(l *client.RateLimitSettings) string {
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

func guardHookCheck(ctx context.Context, c *client.Client) []Check {
	g, err := c.Settings.GetGuardStatus(ctx)
	if err != nil {
		return nil
	}
	here := installedGuardVersion()

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

func clientChecks() []Check {
	const registered = "guard registered"
	const missing = "guard NOT registered, run `solongate repair`"

	claude := Check{Name: "Claude hooks", OK: StateFail, Detail: missing}
	if isGuardInstalled() {
		claude = Check{Name: "Claude hooks", OK: StateOK, Detail: registered}
	}
	checks := []Check{claude}

	if isGuardInstalled() {
		rt := install.CheckHookRuntime()
		if rt.OK {
			checks = append(checks, Check{Name: "guard binary", OK: StateOK, Detail: rt.Detail})
		} else {
			checks = append(checks, Check{Name: "guard binary", OK: StateFail,
				Detail: rt.Detail + ", nothing is being enforced or logged"})
		}

		switch beat := install.GuardBeat(); {
		case beat == nil:
			checks = append(checks, Check{Name: "guard fired", OK: StateWarn,
				Detail: "never. Open your agent, run one tool call, then check again"})
		case beat.Status == "no-binary":
			checks = append(checks, Check{Name: "guard fired", OK: StateFail,
				Detail: install.Ago(beat.At) + ", but found no guard binary. Run `solongate repair`"})
		default:
			checks = append(checks, Check{Name: "guard fired", OK: StateOK,
				Detail: install.Ago(beat.At)})
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
				Detail: "registered. Run `/hooks` in Codex once and trust them (Codex skips untrusted hooks)"})
		default:
			checks = append(checks, Check{Name: "Codex hooks", OK: StateOK, Detail: "registered + trusted"})
		}
	}

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

func roundHalfUp(v float64) int64 { return int64(math.Floor(v + 0.5)) }

func fixed0(v float64) string { return strconv.FormatInt(int64(math.Round(v)), 10) }