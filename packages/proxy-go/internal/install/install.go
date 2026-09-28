package install

import (
	"errors"
	"os"
	"os/exec"
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

// ErrNoLogin is the one failure that is not a fault: nothing is wrong with the
// machine, it just has no credential to arm the guard with.
var ErrNoLogin = errors.New("no login on this device — add an account first (Accounts → + add)")

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

	cred, err := resolveInstallCredential()
	if err != nil {
		return Result{Message: err.Error()}
	}

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
		_ = os.MkdirAll(filepath.Join(p.SGDir, BeatDirName), 0o755)
	}

	// The Go binaries, beside the hook that looks for them. Best effort: see
	// gobinaries.go for why a platform without one is a valid install.
	goBins := InstallGoBinaries()

	// The credential the hooks enforce with, written through the same writer the
	// rest of the CLI uses so a locked file is handled once and in one place.
	if !config.SetActiveAccount(cred) {
		return fail("could not write " + p.ConfigPath)
	}

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

	// Every client that was just registered gets its policy pulled down now, so
	// its first tool call is judged rather than waved through.
	warmPolicyCache(p, node, []string{"claude-code", "codex", "antigravity", "opencode"})

	// NOTE: the policy CACHE is deliberately not cleared here. The guard
	// re-fetches it on its own schedule, and even a stale cache keeps the
	// security config set — whereas deleting it forces a cold start where the
	// first tool call has no cached config at all (the refresh is a detached
	// background spawn), so DLP-block and rate limits silently do not
	// apply on that one call.

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

// resolveInstallCredential finds the key the installed hooks will enforce with.
//
// The order is the TypeScript's, including the part that looks odd: the stored
// apiUrl wins over the environment. That is deliberate there — the URL belongs
// to the account that was paired, and an exported SOLONGATE_API_URL from an
// unrelated experiment must not silently re-point a device's guard.
//
// The last source is the account list. A fresh device login populates
// accounts.json and the runtime view credential but NOT the active-key file, so
// cloud-guard.json can be empty while the user is fully logged in; without this
// step a logged-in user got "no login on this device" and could never install.
func resolveInstallCredential() (config.Credential, error) {
	apiKey := os.Getenv("SOLONGATE_API_KEY")
	apiURL := os.Getenv("SOLONGATE_API_URL")
	if apiURL == "" {
		apiURL = config.DefaultAPIURL
	}

	stored := config.LoadCredentialFile()
	if apiKey == "" {
		apiKey = stored.APIKey
	}
	if stored.APIURL != "" {
		apiURL = stored.APIURL
	}

	if apiKey == "" {
		for _, acc := range config.ListAccounts() {
			if acc.APIKey == "" {
				continue
			}
			apiKey = acc.APIKey
			if acc.APIURL != "" {
				apiURL = acc.APIURL
			}
			break
		}
	}
	if apiKey == "" {
		return config.Credential{}, ErrNoLogin
	}
	return config.Credential{APIKey: apiKey, APIURL: apiURL}, nil
}

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

// warmPolicyCache fetches each client's policy into its cache, now, at install
// time.
//
// The guard serves policy stale-while-revalidate: a cold cache has nothing to
// serve, so it allows and refreshes in the background for the NEXT call. The
// cache is keyed per agent, so a newly registered client's FIRST tool call runs
// with no policy at all. Measured on a fresh `opencode` id: the first call to a
// command the active policy denies was allowed, and the identical call was
// blocked once the cache existed.
//
// The guard already knows how to do this, so warming is running it once per
// client rather than a second copy of the fetch. Detached and best-effort: an
// offline install still succeeds, it simply leaves the first call in the old
// state.
func warmPolicyCache(p Paths, node string, agents []string) {
	guard := p.GuardPath()
	if !Exists(guard) || node == "" {
		return
	}
	for _, agent := range agents {
		cmd := exec.Command(node, guard, agent, "--sg-refresh-policy")
		cmd.Stdin = nil
		cmd.Stdout = nil
		cmd.Stderr = nil
		detach(cmd)
		if cmd.Start() != nil {
			continue
		}
		// Release rather than Wait: this process must not sit waiting for a
		// refresh, and a child left unwaited-for is exactly the zombie the
		// detached spawn was meant to avoid.
		_ = cmd.Process.Release()
	}
}

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
