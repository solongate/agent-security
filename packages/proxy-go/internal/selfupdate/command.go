package selfupdate

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/term"
)

// RunUpdateCommand is `solongate update`, and with `auto` it is
// `solongate update auto [on|off]`.
//
// The two are kept apart on purpose: a bare `update` means "update me now" and
// must never change a setting as a side effect, and `update auto` changes a
// setting and must never install anything.
func RunUpdateCommand(args []string) int {
	if len(args) > 0 && args[0] == "auto" {
		arg := ""
		if len(args) > 1 {
			arg = args[1]
		}
		return runAutoUpdateCommand(arg, len(args) > 1)
	}

	out := term.Log

	// `sudo solongate update` is the obvious thing to try once npm complains,
	// and it half-works, which is worse than failing: npm installs fine as root,
	// then the guard-hook refresh writes into ROOT's home instead of yours, and
	// your agents quietly stop being guarded. Refuse, and hand over the two
	// commands that do the right thing.
	if RunningAsRoot() {
		out("")
		out("  Do not run `solongate update` with sudo.")
		out("  npm would install fine, but the guard hooks would be written into root's")
		out("  home instead of yours, and your agents would stop being guarded.")
		out("")
		out("  Run these two instead:")
		for _, s := range AdminUpdateSteps() {
			out("    " + s)
		}
		out("")
		return 1
	}

	// A build with no version stamp would compare itself as 0.0.0 and install
	// the latest package over a machine it is not even the guard on. Say what is
	// wrong and hand over the implementation that can do this.
	if !VersionKnown() {
		out("")
		out("  This build carries no version stamp, so it cannot tell whether it is")
		out("  out of date - and a binary whose version does not match its package is")
		out("  refused by the guard anyway.")
		out("")
		out("  Update through the npm package: npx " + pkgName + " update")
		out("")
		return 1
	}

	// A previous update on Windows left the old binary beside the new one,
	// because a running executable cannot delete itself. This is the later run
	// that can.
	SweepStagedReplacements()

	ctx := context.Background()
	cur := Version
	out("  current  " + cur)

	fetchCtx, cancel := context.WithTimeout(ctx, registryTimeout)
	latest, ok := LatestVersion(fetchCtx)
	cancel()
	if !ok {
		out("  could not reach the npm registry. Try again, or: npm i -g " + pkgName + "@latest")
		return 1
	}

	if Newer(latest, cur) {
		// Check writability BEFORE installing. On a stock macOS Node the global
		// folder belongs to root, and starting an install we know will fail just
		// buys the user a minute of npm EACCES noise instead of an answer.
		writable, dir := GlobalInstallCheck()
		if writable != nil && !*writable {
			rememberNeedsAdmin(latest)
			out("  v" + latest + " is out, but npm's global folder needs admin rights on this machine:")
			out("    " + dir)
			out("  That is the normal macOS setup - SolonGate cannot install there on its own.")
			out("")
			out("  Run these two:")
			for _, s := range AdminUpdateSteps() {
				out("    " + s)
			}
			out("")
			return 1
		}

		out("  updating " + cur + " -> " + latest + " ...")
		r := runGlobalInstall(ctx, latest)
		if r.busy {
			// Not a failure. Another install is already doing exactly this, and
			// running a second one against the same global folder is what left
			// a machine with no CLI at all — see lease.go.
			out("  an update is already running on this machine.")
			out("  Give it a minute, then run solongate update again.")
			return 0
		}
		if !r.ok {
			// npm refusing for permissions is not a blip to retry: this machine's
			// global folder belongs to root and no amount of retrying changes
			// that.
			if r.needsAdmin {
				rememberNeedsAdmin(latest)
				out("  npm could not write to the global folder (it needs admin rights).")
				out("  Run these two:")
				for _, s := range AdminUpdateSteps() {
					out("    " + s)
				}
			} else if r.ran {
				// npm did the work and the check afterwards could not confirm
				// it. The files are on disk either way, so this says what is
				// actually known rather than "failed", and the hooks below are
				// still refreshed — a machine that is updated but unregistered
				// is the worse of the two states to leave somebody in.
				out("  npm installed " + latest + ", but this could not confirm it:")
				out("    " + r.why)
				out("  Check with: solongate --version")
				refreshGuard(ctx, out)
				return 0
			} else {
				out("  update failed. Try: npm i -g " + pkgName + "@latest")
			}
			return 1
		}
		s := readState()
		s.NeedsAdmin = ""
		writeState(s)
		out("  ✓ updated to " + latest + "  (open a new session to use it)")
		arrangeWithFreshBinary()
	} else {
		out("  ✓ already up to date")
	}

	refreshGuard(ctx, out)
	return 0
}

// refreshGuard brings the installed guard hooks in line with the CLI.
//
// `repair` is the command that owns this: it writes the hooks AND registers them
// in each client's configuration. So it is asked first, through whatever
// `solongate` is on PATH — which after an update is the newly installed one,
// and that matters: if we had just npm-updated, THIS process is still the OLD
// code, and its own idea of the hooks would be the old one too.
// SOLONGATE_INTERNAL=1 gets the subprocess past the human-only gate, which would
// otherwise refuse it for having no terminal.
//
// When that is not available — this Go build does not have `repair` yet — fall
// back to the cloud refresh the guard hooks already use on themselves. It cannot
// register anything, so it can only bring an EXISTING installation up to date;
// where there is nothing installed, the answer is the npm package, and saying so
// is better than a checkmark over a machine that is not guarded.
func refreshGuard(ctx context.Context, out func(string)) {
	if runRepair(out) {
		return
	}

	// One overall budget on top of the per-request one. internal/api retries a
	// GET three times before it gives up, so three hooks against an unreachable
	// API is a minute of a person watching nothing happen; the answer they are
	// waiting for is "the hooks are as they were", and it does not improve after
	// the first thirty seconds.
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	results := RefreshHooks(ctx, api.New())
	updated, present := 0, 0
	for _, r := range results {
		if r.Skipped == "not installed on this device" {
			continue
		}
		present++
		if r.Updated {
			updated++
			out("  ✓ " + r.File + " v" + strconv.Itoa(r.From) + " -> v" + strconv.Itoa(r.To))
			continue
		}
		out("  " + r.File + ": " + r.Skipped)
	}
	if present == 0 {
		out("  no guard hooks are installed on this device.")
		out("  Install them with: npx " + pkgName + " repair")
		return
	}
	if updated == 0 {
		out("  guard hooks left as they are.")
	}
}

// runRepair invokes `solongate repair` and reports whether it actually did the
// job.
//
// Its output is captured rather than inherited, and only printed when it
// succeeded. A `solongate` on PATH that is THIS binary answers `repair` with a
// "not ported yet" notice and a non-zero exit; showing that to someone who ran
// `solongate update` would read as a failed update rather than as the fallback
// below quietly taking over.
func runRepair(out func(string)) bool {
	path, err := exec.LookPath("solongate")
	if err != nil {
		return false
	}
	cmd := exec.Command(path, "repair")
	cmd.Env = append(os.Environ(), "SOLONGATE_INTERNAL=1")
	blob, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	for _, line := range strings.Split(strings.TrimRight(string(blob), "\n"), "\n") {
		out(line)
	}
	return true
}

// runAutoUpdateCommand is `solongate update auto [on|off]`. hasArg is separate
// from the argument itself so that `update auto ""` is a bad value rather than
// silently reading as "show me the setting".
func runAutoUpdateCommand(arg string, hasArg bool) int {
	out := term.Log
	forced := AutoForcedByEnv()

	if !hasArg {
		state := "off"
		if AutoEnabled() {
			state = "on"
		}
		note := ""
		if forced {
			note = "  (forced by SOLONGATE_AUTO_UPDATE)"
		}
		out("  auto-update is " + state + note)
		out("  change it with: solongate update auto on|off")
		return 0
	}

	v := strings.ToLower(strings.TrimSpace(arg))
	on := v == "on" || v == "1" || v == "true" || v == "yes" || v == "enable" || v == "enabled"
	off := v == "off" || v == "0" || v == "false" || v == "no" || v == "disable" || v == "disabled"
	if !on && !off {
		out("  unknown value \"" + arg + "\" - use: solongate update auto on|off")
		return 1
	}

	SetAuto(on)
	if on {
		out("  ✓ auto-update on - new versions install in the background")
	} else {
		out("  ✓ auto-update off - update with: solongate update")
	}

	// Turning it on where npm needs admin rights recreates exactly the failure
	// this setting exists for. Say so now rather than letting it fail silently
	// for weeks.
	if writable, _ := GlobalInstallCheck(); on && writable != nil && !*writable {
		out("")
		out("  Heads up: npm's global folder needs admin rights on this machine, so a")
		out("  background install cannot succeed here. Updates will still be announced,")
		out("  and installing them takes:")
		for _, s := range AdminUpdateSteps() {
			out("    " + s)
		}
	}
	if forced {
		out("  note: SOLONGATE_AUTO_UPDATE is set and overrides this while it stays set")
	}
	return 0
}

// UpdateNow installs the newest version whatever the auto-update setting says.
// The dataroom's UPDATES row runs through here, and so does anything else that
// means "do it now" rather than "tell me when".
func UpdateNow(ctx context.Context) Status {
	cur := Version
	// An unstamped build would read as 0.0.0 and install on every press of the
	// UPDATES row. Failing is the honest answer; see VersionKnown.
	if !VersionKnown() {
		return Status{Kind: KindFailed, Version: cur}
	}
	fetchCtx, cancel := context.WithTimeout(ctx, registryTimeout)
	latest, ok := LatestVersion(fetchCtx)
	cancel()
	if !ok {
		return Status{Kind: KindUnreachable, Version: cur}
	}
	if !Newer(latest, cur) {
		return Status{Kind: KindCurrent, Version: cur}
	}
	// Ask before jumping: a doomed npm run costs a minute and tells the user
	// nothing they can act on.
	if writable, _ := GlobalInstallCheck(); writable != nil && !*writable {
		rememberNeedsAdmin(latest)
		return Status{Kind: KindNeedsAdmin, Version: latest}
	}
	r := runGlobalInstall(ctx, latest)
	switch {
	case r.ok:
		s := readState()
		s.Installed, s.NeedsAdmin = latest, ""
		writeState(s)
		return Status{Kind: KindUpdated, Version: latest}
	case r.busy:
		// Somebody else is installing this exact version. "Updating" is the
		// true answer, and the next poll will find it done.
		return Status{Kind: KindUpdating, Version: latest}
	case r.needsAdmin:
		rememberNeedsAdmin(latest)
		return Status{Kind: KindNeedsAdmin, Version: latest}
	default:
		return Status{Kind: KindFailed, Version: latest}
	}
}

// TUIFlow is the dataroom's updater: check the registry every time the UI opens
// (and periodically while it stays open). With auto-update ON, install in the
// background and ask for a restart; with it OFF, which is the default, only
// report that a version is available.
//
// onStatus drives the in-app status line. Nothing here writes to the terminal:
// a stray line of output on a Bubble Tea screen corrupts the frame the program
// believes it drew.
func TUIFlow(ctx context.Context, onStatus func(Status)) {
	cur := Version
	if !VersionKnown() {
		return // see VersionKnown: nothing said, nothing installed
	}
	fetchCtx, cancel := context.WithTimeout(ctx, registryTimeout)
	latest, ok := LatestVersion(fetchCtx)
	cancel()

	s := readState()
	if ok {
		s.LastCheckAt, s.LatestSeen = nowMillis(), latest
		writeState(s)
	}
	if !ok || !Newer(latest, cur) {
		return
	}

	// Already installed this version during this run: keep saying "restart to
	// apply" rather than reinstalling on every poll.
	if readState().Installed == latest {
		onStatus(Status{Kind: KindUpdated, Version: latest})
		return
	}

	// Auto-update off (the default): say what is out and stop. Updating is the
	// user's call, from the UPDATES row or from `solongate update`.
	if !AutoEnabled() {
		onStatus(Status{Kind: KindAvailable, Version: latest})
		return
	}

	// npm already refused this exact version for permissions. Retrying every
	// thirty minutes cannot succeed and would pin the status line on
	// "updating…", which is how this looked broken on macOS in the first place.
	if readState().NeedsAdmin == latest {
		onStatus(Status{Kind: KindNeedsAdmin, Version: latest})
		return
	}

	onStatus(Status{Kind: KindUpdating, Version: latest})
	r := runGlobalInstall(ctx, latest)
	switch {
	case r.ok:
		st := readState()
		st.Installed, st.NeedsAdmin = latest, ""
		writeState(st)
		onStatus(Status{Kind: KindUpdated, Version: latest})
	case r.needsAdmin:
		rememberNeedsAdmin(latest)
		onStatus(Status{Kind: KindNeedsAdmin, Version: latest})
	}
	// Any other failure is usually registry propagation lag right after a
	// publish: STAY on "updating…" and let the next poll retry. It self-heals in
	// a minute or two.
}

// NotifyAsync is the startup notice, and it returns the wait.
//
// It is deliberately two halves. The check runs in the background so the command
// the user actually typed produces its output first, and the returned function
// blocks — briefly, and only until the registry answers or the budget runs out —
// so the notice is not lost to a process that exits before it prints. That is
// the same observable behaviour as the Node CLI, where the pending fetch keeps
// the event loop alive until it settles.
//
// Call it from the human CLI only. It must never be reachable from the MCP proxy
// runtime or from anything a guarded tool call waits on: this is the exact shape
// of the bug that turned a DENY into an ALLOW when it ran in front of a verdict.
func NotifyAsync(notify func(string)) (wait func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			// A panic in a background nicety must not take the CLI's exit code
			// with it.
			_ = recover()
		}()
		notifyOnce(notify)
	}()
	return func() {
		select {
		case <-done:
		case <-time.After(registryTimeout + 500*time.Millisecond):
		}
	}
}

func notifyOnce(notify func(string)) {
	if !VersionKnown() {
		return // see VersionKnown: no notice, and above all no background install
	}
	s := readState()
	now := nowMillis()
	cur := Version

	// Between polls, still surface a version already known to be newer (an
	// install that failed earlier, or an npx run) without touching the network.
	latest := s.LatestSeen
	if now-s.LastCheckAt >= registryCheckEvery.Milliseconds() {
		ctx, cancel := context.WithTimeout(context.Background(), registryTimeout)
		v, ok := LatestVersion(ctx)
		cancel()
		s.LastCheckAt = now
		if ok {
			s.LatestSeen, latest = v, v
		}
		writeState(s)
	}
	if latest == "" || !Newer(latest, cur) {
		return
	}

	s = readState()
	// The background install gets the shorter window; a notice gets the long
	// one. Checked before the branches because the throttle decides whether
	// anything happens at all.
	window := attemptEvery
	if AutoEnabled() {
		window = autoAttemptEvery
	}
	if now-s.Attempts[latest] < window.Milliseconds() {
		return
	}
	// Recorded at the END of each branch, never here.
	//
	// This used to stamp the attempt before doing anything, and the comment
	// below still promised that a failed spawn would be retried on the next
	// run. It was not: the stamp was already written, so six hours had to pass
	// before this version was considered again. npm missing from PATH for one
	// invocation, a log file that could not be opened, a fork that failed under
	// memory pressure — any of them turned "retry next run" into "give up until
	// tomorrow", which is exactly the shape of an auto-update that works most of
	// the time and sometimes does not.
	//
	// Only the target version is kept: this map is a throttle, not a history,
	// and one entry per version ever published would grow forever.
	markAttempted := func() {
		s := readState()
		s.Attempts = map[string]int64{latest: now}
		writeState(s)
	}

	// Past the throttle with a newer version out, so it is worth finding out
	// whether an install can work at all. That answer decides both what the user
	// is told and whether the background install below would be anything but a
	// guaranteed silent failure.
	writable, _ := GlobalInstallCheck()
	needsAdmin := writable != nil && !*writable
	head := term.Dim + "↑ solongate v" + latest + " available (running v" + cur + ")"

	if needsAdmin {
		// No unattended install can succeed here. Give the exact commands rather
		// than a promise that cannot be kept. The throttle applies: this is a
		// notice, and repeating it every run is nagging.
		markAttempted()
		notify(head + " - needs admin rights on this machine:" + term.Reset)
		for _, step := range AdminUpdateSteps() {
			notify(term.Cyan + "  " + step + term.Reset)
		}
		return
	}

	// Auto-update off (the default): mention it once, and point at our own
	// command. Never `npm i -g` here - `solongate update` does the install AND
	// the guard-hook refresh that has to follow it.
	if !AutoEnabled() {
		markAttempted()
		notify(head + " - run " + term.Reset + term.Cyan + "solongate update" + term.Reset)
		return
	}

	// Auto-update on: install in the background. A spawn that did NOT start is
	// left unstamped, so the very next run tries again — which is what the old
	// comment claimed and the old code prevented.
	if spawnGlobalInstall(latest) {
		markAttempted()
		notify(head + " - updating in the background, next run uses it" + term.Reset)
	}
}

// rememberNeedsAdmin records the version npm refused for permissions, so it is
// not retried every six hours on a machine where it can never succeed.
func rememberNeedsAdmin(version string) {
	s := readState()
	s.NeedsAdmin = version
	writeState(s)
}

// arrangeWithFreshBinary asks the version just installed to arrange the machine.
//
// THE NEW BINARY DOES THE ARRANGING, not this one.
//
// Everything else in an update runs the code of the version being REPLACED,
// which is wrong for anything the new version knows how to do and the old one
// does not. The case that found it: a release that taught this product a new
// install step could not perform it during its own update, because the process
// doing the updating was the version from before. It took a second, unrelated
// command afterwards - which nobody would think to run, and which nothing on
// screen asked for.
//
// A failure is silent because a machine that updated is better off than one that
// refused to, and the next ordinary run arranges it anyway.
func arrangeWithFreshBinary() {
	if fresh := freshCLI(); fresh != "" {
		cmd := exec.Command(fresh, "arrange")
		cmd.Stdout, cmd.Stderr = nil, nil
		_ = cmd.Run()
	}
}

// plural is one word or two, because "1 browsers" reads like a bug in the tool.
func plural(n int, unit string) string {
	if n == 1 {
		return "1 " + unit
	}
	return strconv.Itoa(n) + " " + unit + "s"
}

// freshCLI is the binary the update just put on disk, or empty.
//
// NOT exec.LookPath("solongate"), which finds the launcher on PATH - a node
// script that re-execs this same binary, and on some installs the one from the
// version being replaced. This wants the file the install step wrote, by the
// path it wrote it to, and nothing else.
func freshCLI() string {
	name := "solongate"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	path := filepath.Join(config.Dir(), "bin", name)
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return ""
	}
	return path
}
