package install

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
)

// What is actually installed on THIS device, read from the files themselves.
//
// Everything here is deliberately local. The cloud's guard-status reports the
// version this device last REPORTED and keeps saying so for about a fortnight,
// so a guard installed, updated or removed a minute ago is invisible to it —
// which is how the health check once announced an update that had already been
// applied, one line above a row saying the guard was current.

var hookVersionRe = regexp.MustCompile(`HOOK_VERSION\s*=\s*(\d+)`)

// InstalledGuardVersion is the HOOK_VERSION of the guard on disk, or nil when no
// guard is installed here.
func InstalledGuardVersion() *int {
	b, err := os.ReadFile(GlobalPaths().GuardPath())
	if err != nil {
		return nil
	}
	m := hookVersionRe.FindSubmatch(b)
	if m == nil {
		return nil
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return nil
	}
	return &n
}

// ShippedGuardVersion is the HOOK_VERSION of the guard THIS BUILD would install,
// read from the packaged hook source beside the binary.
//
// Nil when there is no package to read — a binary carried somewhere on its own —
// and the caller has to treat that as "cannot tell" rather than as zero. A zero
// here is what made every machine report `v? → v0`: an unknown newest version,
// compared against, and losing to, nothing at all.
func ShippedGuardVersion() *int {
	dir, ok := hookSourceDir()
	if !ok {
		return nil
	}
	b, err := readGuardSource(dir)
	if err != nil {
		return nil
	}
	m := hookVersionRe.FindSubmatch(b)
	if m == nil {
		return nil
	}
	n, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return nil
	}
	return &n
}

// GuardHookOutdated reports whether the installed guard DIFFERS from the one
// this build ships, so the dataroom can offer an update even when the API is
// behind or unreachable.
//
// False when there is nothing to compare against — no guard installed, or no
// packaged source next to this binary. "I cannot tell" must not read as "yours
// is out of date", which would send someone to reinstall the same file they
// already have.
func GuardHookOutdated() bool {
	installed, err := os.ReadFile(GlobalPaths().GuardPath())
	if err != nil {
		return false
	}
	dir, ok := hookSourceDir()
	if !ok {
		return false
	}
	shipped, err := readGuardSource(dir)
	if err != nil {
		return false
	}
	return !bytes.Equal(installed, shipped)
}

// GuardHooksPresent reports whether the three hook programs the client
// registrations name are all on disk. A registration pointing at a file that is
// not there is a client logging an error on every tool call, so it is worth
// being able to ask separately from "is it registered".
func GuardHooksPresent() bool {
	p := GlobalPaths()
	for _, name := range []string{GuardHookName, auditHookName, stopHookName} {
		if !Exists(filepath.Join(p.HooksDir, name)) {
			return false
		}
	}
	return true
}
