// Package selfupdate keeps this CLI current, and the guard hooks with it.
//
// It is the port of packages/proxy/src/self-update.ts, and it keeps that file's
// central decision: THE BACKGROUND UPDATER IS OPT-IN AND SHIPS OFF. On a stock
// macOS Node the global npm prefix belongs to root, so `npm install -g` there
// fails with EACCES unless it runs under sudo — a background updater on such a
// machine can only fail, silently, forever, and the dataroom sat on "updating…"
// while it did. Nothing here installs anything behind the user's back:
// `solongate update` is one command, and both the CLI and the dataroom say when
// a new version is out. `solongate update auto on` turns the background
// installer on for people who want it.
//
// Two rules this package exists inside of:
//
// The npm package is the one that moves. This binary is resolved by
// packages/proxy/hooks/go-binary.mjs, which REFUSES a binary whose --sg-version
// is not exactly the version of the package asking for it, and falls back to the
// Node implementation instead. So a Go binary that updated itself out of step
// with its package would not be a faster guard, it would be a rejected one. Every
// path here updates through npm, which moves the package and the binary together,
// or it does not update at all.
//
// And nothing here may run in front of a verdict. The Node guard carries an 8s
// backstop that force-exits with `process.exitCode || 0` — ALLOW — so anything
// slow that runs BEFORE the decision is emitted turns a DENY into a permitted
// call. That already happened once, through the hook self-update: measured at
// 8043ms, exit 0, on a call DLP had already refused. This package is imported by
// the human CLI and the dataroom only; it must never be pulled onto a decision
// path, and RefreshHooks in particular is a maintenance action, not something a
// guarded call waits for.
package selfupdate

import (
	"os"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Version is the npm version of the package that shipped this binary, stamped
// into main at build time and handed here by main.
var Version = "dev"

// VersionKnown reports whether this build can say what it is.
//
// It gates every path that INSTALLS anything, and the reason is a real incident
// rather than caution: an unstamped build says "dev", "dev" parses as 0.0.0, and
// 0.0.0 is older than everything ever published — so a binary built without the
// ldflags stamp concludes it is out of date on every single run. A test in this
// module invoked `solongate update` on such a build and it ran a real
// `npm install -g` against the machine's global node_modules; with auto-update
// on it would have spawned one from every CLI run past the throttle.
//
// Refusing is also the honest answer. packages/proxy/hooks/go-binary.mjs will
// not trust a binary whose --sg-version does not equal the version of the
// package asking for it, so an unstamped binary is never the guard anyway, and
// npm-installing the package on its behalf changes nothing it can act on.
func VersionKnown() bool {
	v := strings.TrimSpace(Version)
	return v != "" && v != "dev" && triple(v) != [3]int{}
}

const (
	// registryCheckEvery is how often the startup notice is allowed to ask the
	// npm registry anything at all.
	registryCheckEvery = 30 * time.Minute
	// attemptEvery is how long a NOTICE waits before repeating. Six hours,
	// because it is a line of text a person has already read and repeating it on
	// every command is nagging.
	attemptEvery = 6 * time.Hour
	// autoAttemptEvery is the same throttle for the BACKGROUND INSTALL, and it
	// is much shorter for a reason: a notice that does not repeat costs nothing,
	// while an install that did not happen is invisible. The spawn only reports
	// whether npm STARTED — if npm then fails, nothing here learns of it, and at
	// six hours a machine could sit a whole day behind on a transient error with
	// auto-update switched on and apparently working.
	//
	// Thirty minutes matches the registry poll, so at worst one attempt per poll
	// rather than one per command. Somebody who opted into unattended updates is
	// asking for exactly that.
	autoAttemptEvery = 30 * time.Minute
	// registryTimeout is short on purpose: this runs on the way out of an
	// unrelated command, and a registry that is slow today must not make the CLI
	// look slow.
	registryTimeout = 3 * time.Second
	// installTimeout matches the Node side. A global npm install on a cold cache
	// is genuinely slow; anything past five minutes is wedged, not working.
	installTimeout = 5 * time.Minute
)

// Status kinds, spelled the way the dataroom renders them
// (internal/tui.UpdateStatusMsg). They are strings rather than an enum so the
// two packages agree without one importing the other — the TUI must not depend
// on the updater, and the updater must never pull a terminal renderer into a
// path that may run detached.
const (
	KindIdle       = "idle"
	KindAvailable  = "available"
	KindUpdating   = "updating"
	KindUpdated    = "updated"
	KindNeedsAdmin = "needs-admin"
	// KindCurrent and KindUnreachable are answers to an EXPLICIT "update now",
	// which has to say "nothing to do" and "I could not ask" out loud. The
	// passive flow stays silent in both cases.
	KindCurrent     = "current"
	KindUnreachable = "unreachable"
	KindFailed      = "failed"
)

// Status is what the dataroom shows about the updater.
type Status struct {
	Kind    string
	Version string
}

func readState() config.SelfUpdateState { return config.LoadSelfUpdateState() }

// writeState is best-effort by design: a home directory that cannot be written
// costs the throttle, not the CLI.
func writeState(s config.SelfUpdateState) { _ = config.SaveSelfUpdateState(s) }

// AutoEnabled reports whether the background updater is on. Default: NO.
//
// SOLONGATE_AUTO_UPDATE=on|off (1/0, true/false, yes/no) overrides the stored
// setting for one run, so a CI image or a managed fleet can force either way
// without writing into the user's home directory.
func AutoEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SOLONGATE_AUTO_UPDATE"))) {
	case "1", "true", "on", "yes":
		return true
	case "0", "false", "off", "no":
		return false
	}
	return readState().Auto
}

// AutoForcedByEnv is true when the environment is deciding, so the UI can say
// the row is overridden rather than showing a setting the user cannot change.
//
// Only the values AutoEnabled actually acts on count. An unrecognised value is
// not "forced": it is ignored, and a row that claimed otherwise would be lying
// about which answer is in effect.
func AutoForcedByEnv() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("SOLONGATE_AUTO_UPDATE"))) {
	case "1", "true", "on", "yes", "0", "false", "off", "no":
		return true
	}
	return false
}

// SetAuto turns the background updater on or off.
//
// Enabling clears the "npm refused this version for permissions" memo: the user
// may have just fixed the ownership of their global folder, and a stale memo
// would keep the updater from ever trying again.
func SetAuto(on bool) {
	s := readState()
	s.Auto = on
	if on {
		s.NeedsAdmin = ""
	}
	writeState(s)
}

// Newer reports whether b is a strictly newer version than a.
func Newer(b, a string) bool {
	pb, pa := triple(b), triple(a)
	for i := 0; i < 3; i++ {
		if pb[i] != pa[i] {
			return pb[i] > pa[i]
		}
	}
	return false
}

// triple is `v.split('.').map(n => parseInt(n, 10) || 0)`, including the part
// that looks like a bug and is not: parseInt stops at the first non-digit, so
// "0.83.20-rc.1" reads as (0, 83, 20) on both sides. Matching it exactly matters
// because both implementations compare against the same registry answer, and any
// disagreement surfaces as one of them offering an update the other insists is
// already installed.
func triple(v string) [3]int {
	var out [3]int
	for i, part := range strings.SplitN(v, ".", 4) {
		if i > 2 {
			break
		}
		n := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}

func nowMillis() int64 { return time.Now().UnixMilli() }
