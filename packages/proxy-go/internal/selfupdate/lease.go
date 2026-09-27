package selfupdate

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// One install at a time, per machine.
//
// This exists because two of them ran at once and left a device with no CLI at
// all. `npm install -g` is not safe to run concurrently against the same
// prefix: both processes extract into the same package directory and both try
// to create the same bin symlink, so the loser fails with EEXIST and ROLLS BACK
// — removing the package.json and the bin link the winner had just written.
// What is left is a directory full of files that npm no longer considers a
// package and a `solongate` that is not on PATH:
//
//	-bash: /home/…/.local/bin/solongate: No such file or directory
//
// Both installers reported success in the log. Neither was wrong about its own
// npm process; the damage was done by the other one afterwards, which is
// exactly why an exit code is not evidence here and why verifyInstalled exists
// beside this.
//
// The two racers were the background updater and a foreground `solongate
// update` in the same minute, but nothing stops two background ones either: any
// guarded tool call can start the CLI, and a machine running several agents
// starts several.

// A LEASE rather than a lock, because the background installer cannot release
// one. It spawns a detached npm and exits immediately — that is deliberate, so
// the install outlives the CLI — which leaves nobody to unlock afterwards. A
// lease expires on its own, so a crashed or detached holder cannot block
// updates forever.
//
// The duration is the install timeout: past that, the holder is either finished
// or hung, and in both cases another attempt is the better answer.
const installLeaseFor = installTimeout

// installLease is what the file holds. The version and the pid are for a human
// reading it while wondering why an update said it was busy; only Until is
// consulted.
type installLease struct {
	PID     int    `json:"pid"`
	Version string `json:"version"`
	Until   int64  `json:"until"`
}

func installLeasePath() string { return filepath.Join(config.Dir(), "update.lease") }

// acquireInstallLease takes the lease, or reports that somebody else holds it.
//
// release is safe to call whichever way it went and safe to call twice, so a
// caller can defer it without a second thought. A background installer takes
// the lease and never releases it: its npm outlives the process that spawned
// it, and letting it expire is the only honest way to bound something we no
// longer have a handle on.
func acquireInstallLease(version string) (release func(), ok bool) {
	noop := func() {}
	if config.EnsureDir() != nil {
		// Without a directory there is nowhere to keep a lease. Refusing to
		// install because of that would make a missing home directory fatal to
		// updates; the race is rarer than that, so this proceeds unguarded.
		return noop, true
	}
	path := installLeasePath()

	for attempt := 0; attempt < 2; attempt++ {
		if writeLeaseExclusive(path, version) {
			return func() { _ = os.Remove(path) }, true
		}
		// Somebody has it. An expired one is cleared and the create retried
		// once; a live one means step aside.
		if !leaseExpired(path) {
			return noop, false
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return noop, false
		}
	}
	return noop, false
}

// writeLeaseExclusive creates the file only if it does not exist. O_EXCL is the
// whole mechanism: it is one atomic syscall, so two processes arriving together
// cannot both believe they created it.
func writeLeaseExclusive(path, version string) bool {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		return false
	}
	defer f.Close()
	body, err := json.Marshal(installLease{
		PID:     os.Getpid(),
		Version: version,
		Until:   time.Now().Add(installLeaseFor).Unix(),
	})
	if err != nil {
		return true // the lease is held; the contents are only for a reader
	}
	_, _ = f.Write(body)
	return true
}

// leaseExpired reports whether the file on disk may be taken over.
//
// An unreadable or unparseable lease counts as expired. A file nobody can read
// would otherwise block every update on the machine permanently, and the thing
// it is protecting against — two installs in the same minute — is bounded by a
// timeout anyway.
func leaseExpired(path string) bool {
	body, err := os.ReadFile(path)
	if err != nil {
		return true
	}
	var lease installLease
	if json.Unmarshal(body, &lease) != nil || lease.Until <= 0 {
		return true
	}
	return time.Now().Unix() >= lease.Until
}

// verifyInstalled checks that the package npm just reported installing is
// actually there.
//
// npm's exit code is evidence about npm's own process and nothing else. Under
// the race this file prevents, the winning install exited 0 and the losing one
// then rolled back over it — so the CLI that "updated successfully" was gone by
// the time anybody typed its name. The check is the same one a shell makes: is
// there a package here, and does its bin exist.
//
// A nil error on a layout this cannot recognise, deliberately. Source builds,
// unusual prefixes and pnpm's store all reach here, and refusing an update
// because the tree does not look the way one packaging tool lays it out would
// break more machines than it fixes.
// verifyInstalledAt is the check itself, against a directory resolved BEFORE the
// install — see ownPackageDir for why a path worked out afterwards names a
// directory npm is in the middle of replacing.
//
// The distinction it turns on is narrow and it is the whole point: a package
// directory that EXISTS WITHOUT A MANIFEST is the state the rollback leaves,
// and a directory that is not there at all means this check was looking in the
// wrong place. The first is a fault worth reporting; the second is this code
// not recognising a layout, and reporting it told somebody their working
// install had failed.
func verifyInstalledAt(pkgDir, version string) error {
	if strings.TrimSpace(pkgDir) == "" {
		return nil
	}
	if info, err := os.Stat(pkgDir); err != nil || !info.IsDir() {
		// Not the rollback state. Either the layout is one this cannot read, or
		// npm moved the tree somewhere else entirely; neither is evidence that
		// the install failed, and npm exiting 0 is evidence that it did not.
		return nil
	}

	body, err := os.ReadFile(filepath.Join(pkgDir, "package.json"))
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The directory is there and the manifest is not, which is
			// precisely what a concurrent install's rollback leaves behind and
			// the one state a person cannot diagnose from the error their shell
			// prints at them afterwards.
			return errors.New("the install left no package.json in " + pkgDir +
				" — another install was running at the same time")
		}
		return nil
	}

	var manifest struct {
		Version string            `json:"version"`
		Bin     map[string]string `json:"bin"`
	}
	if json.Unmarshal(body, &manifest) != nil {
		return nil
	}
	if version != "" && manifest.Version != "" && manifest.Version != version {
		return errors.New("npm reported installing " + version +
			" but the package on disk is " + manifest.Version)
	}
	for name, rel := range manifest.Bin {
		if strings.TrimSpace(rel) == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(pkgDir, filepath.FromSlash(rel))); err != nil {
			return errors.New("the installed package has no " + name + " entry point")
		}
	}
	return nil
}
