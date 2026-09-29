package install

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// Result is what the callers that must not print report back. The dataroom owns
// the terminal while it is up, so anything it calls has to hand back a status
// rather than write to the stream.
type Result struct {
	OK      bool
	Message string
	// Notes carry a condition the caller should pass on: an install that
	// succeeded, but did less than it usually does. Silence there would be the
	// worst outcome — a machine that looks freshly installed and is not.
	Notes []string
}

// ErrNoLogin was returned when the machine had no credential to arm the guard
// with. It is kept, unreturned, because the TUI and the repair report still
// recognise it when deciding whether a failure is the user's to fix — and because
// deleting it would silently turn "you need to log in" into an unrecognised error
// string rather than into what it actually is now: nothing at all.
//
// NOTHING RETURNS IT. A machine with no credential is fully installable, which is
// the point: there is no account to have.
var ErrNoLogin = errors.New("no login on this device")

// Install lays the hooks down and registers them in every supported client.
//
// The sequence is the whole design. Everything that can fail is done first and
// in memory — the credential, the node binary, the hook contents, and the merged
// content of every client's config — so a failure at any of those points leaves
// the machine exactly as it was. Only then is anything written, hooks before the
// registrations that name them, so no client is ever pointed at a file that is
// not there yet.
//
// No prompting, no printing, no exit: this is what the dataroom's one-key
// install and `solongate repair` both call.
func Install() Result {
	p := GlobalPaths()

	// THE CREDENTIAL USED TO BE THE FIRST THING RESOLVED, and a machine without one
	// got `no login on this device — add an account first (Accounts → + add)` and no
	// install. On this build every machine is without one: nothing writes a
	// credential, and the Accounts panel that message names is deleted. So the one
	// command that arms the guard refused to run, on a product whose entire
	// configuration is a file. It is not resolved, not required, and not written.
	node, err := resolveNode(p)
	if err != nil {
		return Result{Message: err.Error()}
	}

	st, err := stageHooks(p, node)
	if err != nil {
		return Result{Message: err.Error()}
	}

	// Every client's merged file, computed before a single byte is written. A
	// Claude-side failure here aborts the install; the other three are
	// best-effort, because a machine that has no Antigravity must still end up
	// with a guarded Claude Code.
	claude, err := planClaude(p, node)
	if err != nil {
		return Result{Message: err.Error()}
	}
	antigravity, agErr := planAntigravity(p, node)
	codex, cxErr := planCodex(p, node)

	if err := os.MkdirAll(p.HooksDir, 0o755); err != nil {
		return Result{Message: err.Error()}
	}
	if err := os.MkdirAll(p.ClaudeDir, 0o755); err != nil {
		return Result{Message: err.Error()}
	}

	// Clear any prior OS lock so this (re)install can overwrite the files it
	// pinned last time.
	UnlockProtected()

	// From here a failure has to put the locks back. Returning with them off
	// would mean a failed install had quietly stripped the self-protection the
	// PREVIOUS install put on — the machine would be left less protected than if
	// this had never run, which is the one outcome that is worse than failing.
	fail := func(msg string) Result {
		if !locksDisabled() {
			LockProtected()
		}
		return Result{Message: msg}
	}

	// The hook programs go down first, and each lands atomically: a truncated
	// guard.mjs is not a broken install, it is an UNGUARDED machine, because a
	// hook that fails to parse exits non-zero and every client reads that as
	// "allowed".
	for _, name := range []string{GuardHookName, auditHookName, stopHookName, tokensHookName, shieldHookName} {
		body, ok := st.hooks[name]
		if !ok {
			continue
		}
		if err := writeFileAtomic(filepath.Join(p.HooksDir, name), body); err != nil {
			return fail(err.Error())
		}
	}

	// The launcher, and the directory it beats into. It lands with the hooks and
	// before any config names it, for the same reason they do: a registration
	// pointing at a launcher that is not there is the failure this whole thing
	// exists to end.
	if runtime.GOOS != "windows" {
		if err := writeFileAtomic(filepath.Join(p.HooksDir, LauncherName), []byte(launcherScript(node))); err != nil {
			return fail(err.Error())
		}
		// Invoked as `/bin/sh <path>`, so the bit is a nicety rather than a
		// requirement — which is deliberate: an install that could not chmod
		// still produces a launcher that runs.
		_ = os.Chmod(filepath.Join(p.HooksDir, LauncherName), 0o755)
		_ = os.MkdirAll(filepath.Join(p.SGDir, BeatDirName), config.DirMode)
	}

	// The Go binaries, beside the hook that looks for them. Best effort: see
	// gobinaries.go for why a platform without one is a valid install.
	goBins := InstallGoBinaries()

	if err := claude.commit(); err != nil {
		return fail(err.Error())
	}

	// Best-effort from here on. A failure registering one of the other clients
	// must not fail an install that has already armed Claude Code — and must not
	// be silent either, which is why the repair report re-reads every client
	// afterwards instead of trusting these calls.
	if agErr == nil {
		_ = antigravity.commit()
	}
	if cxErr == nil {
		_ = codex.commit()
	}
	if st.plugin != nil {
		_ = installOpencodePlugin(p, st.plugin)
	}

	if !locksDisabled() {
		LockProtected()
	}

	res := Result{OK: true, Message: "guard installed (open a new session)"}
	if st.sourceMissing {
		// Said out loud rather than folded into success. The registrations were
		// rewritten against the hooks that were already installed, which is the
		// right answer for the common repair (a deleted registration) and is NOT
		// an answer for a tampered guard.mjs — this build has no packaged copy to
		// compare it with, let alone replace it.
		res.Notes = append(res.Notes,
			"The hook programs already on this device were re-registered but NOT rewritten: this build could not find the packaged copies. Run `npx @solongate/proxy repair` to replace the hook files themselves.")
	}
	// Said out loud when the fast path could NOT be armed, because nothing else
	// would say it: a hook running its Node implementation behaves identically
	// to one running the binary, only slower, so an absent binary is invisible
	// from the outside. The install is still a success — the machine is guarded
	// either way — and this is the difference between "slow" and "not working".
	if len(goBins) == 0 {
		res.Notes = append(res.Notes,
			"No native binary for this platform, so the guard runs its Node implementation: same policy, a few tens of milliseconds slower per tool call.")
	}
	return res
}

// Uninstall removes the guard from every client and lifts the OS locks.
//
// It does NOT delete the hook files or the credential. Removing the
// registrations is what stops the guard from running; deleting the account's key
// as well would turn "stop enforcing here" into "log this device out", and those
// are different requests.
func Uninstall() Result {
	p := GlobalPaths()
	UnlockProtected()
	RemoveClaudeShim()

	// Best-effort for the other three: a failure there must not stop the
	// Claude-side removal, which is the one a user watching the row will check.
	_ = removeAntigravityRegistration(p)
	_ = removeCodexRegistration(p)
	_ = removeOpencodePlugin(p)

	if err := removeClaudeRegistration(p); err != nil {
		return Result{Message: err.Error()}
	}
	return Result{OK: true, Message: "guard removed (open a new session)"}
}

// resolveInstallCredential lived here. It looked in the environment, then the
// active-key file, then the account list, and failed with ErrNoLogin when all three
// were empty — which is every machine now. Deleted with the accounts it resolved
// from: see Install for why nothing takes its place.

// writeFileAtomic writes through a temporary file in the same directory and
// renames it into place, so nothing ever reads a half-written hook.
//
// Same directory because a rename across filesystems is a copy, and the point of
// the rename is that it is not one.
func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".solongate-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op once the rename has taken the file away

	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	// Flush to the disk before the rename. Without it a crash between the two can
	// leave the name pointing at a file with no contents, which is the failure
	// this function exists to prevent.
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	// CreateTemp makes the file 0600; the hooks have to be readable by the
	// clients that run them, and the OS lock applied afterwards narrows it again.
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// warmPolicyCache lived here: one detached `guard.mjs <agent> --sg-refresh-policy`
// per registered client, so the first tool call after an install was judged against
// a policy already fetched rather than waved through while the fetch ran. That was a
// measured bug — on a fresh `opencode` id the first denied command was allowed, and
// the identical call blocked once the cache existed.
//
// There is no fetch and no cache. The guard reads a file, and a file needs no
// warming; the first call after an install is judged exactly like the thousandth.
// Four processes per install to accomplish nothing is worse than nothing, so they
// are gone, and so is the flag they passed.

// ClearUpdateCheckStamp deletes the stamp the installed guard reads to skip its
// ~6h check for a newer bundle.
//
// Deleting it forces the guard to re-check, and install a newer bundle, on the
// NEXT executed command — the exact thing the dashboard tells operators to `rm`
// by hand. Idempotent: a missing stamp (already cleared, or an older guard that
// auto-updates anyway) still counts as success. It is not one of the locked
// files, so a plain delete works.
func ClearUpdateCheckStamp() bool {
	err := os.Remove(GlobalPaths().UpdateCheckPath)
	return err == nil || os.IsNotExist(err)
}
