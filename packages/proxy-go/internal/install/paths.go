// Package install writes the files that decide whether a machine is guarded at
// all: the hook programs under ~/.solongate/hooks, the registration of those
// hooks in every supported client's configuration, and the OS locks that keep
// something else from editing them away again. It is the port of
// packages/proxy/src/global-install.ts.
//
// Two rules shape everything in here, and both were paid for.
//
// A failed install must leave the machine in the state it was already in.
// Half-registered is worse than not installed: a settings file naming a hook
// that is not there is a client printing an error on every tool call, and a
// truncated guard.mjs is a hook that exits non-zero, which every client reads as
// "allowed". So every byte that will be written is assembled in memory first,
// nothing is touched until all of it exists, the hook programs land before
// anything points at them, and each one is written to a temporary file and
// renamed so a partial file is never visible under the name a client runs.
//
// And the registration this writes has to be the one the clients already have.
// The npm package stays installed and keeps registering the same hooks; if the
// two implementations disagreed about the shape of an entry, a machine with both
// would end up with two registrations, or with one of them re-adding what the
// other had just removed. Ownership is therefore by IDENTITY, not by file: the
// Claude settings' `hooks` key, Antigravity's named group, any Codex entry whose
// command points into ~/.solongate, and the OpenCode plugin's own filename. Each
// implementation replaces the other's entry rather than appending beside it.
package install

import (
	"os"
	"path/filepath"

	"github.com/codeyevsky/solongate/proxy/internal/config"
)

// The programs the installer lays down under ~/.solongate/hooks. Names rather
// than paths: they are also the keys of the staged contents and the basenames
// every client registration points at.
const (
	// GuardHookName is the PreToolUse hook — the one that decides.
	GuardHookName = "guard.mjs"
	auditHookName = "audit.mjs"
	stopHookName  = "stop.mjs"
	// What a turn COST, read off whatever the client reports its usage in.
	//
	// It was `conversation.mjs` and recorded the words as well; the transcript
	// half is gone and the file is named for what is left. A machine holding
	// the old file has a stale registration until `solongate repair` rewrites
	// it, which is what that command is for.
	tokensHookName = "tokens.mjs"
	// The shield is the LLM-path redaction shim, registered in the shell rather
	// than in a client. It is installed with the hooks because it is one of the
	// protected files.
	shieldHookName = "shield.mjs"
	// THE SHARED DLP LIST, imported at runtime by audit.mjs and shield.mjs.
	//
	// Those two ship as LONE FILES — no bundle, no node_modules — so anything they import
	// has to be copied beside them or the hook dies on its import. A hook that fails to
	// start exits non-2, and every client reads a non-2 exit as "allowed": forgetting this
	// file would mean no post-tool masking and no prompt masking, reported as nothing.
	//
	// The guard does not need it installed (its bundle inlines the module), but it is
	// copied for every hook because the two that do need it are here.
	dlpModuleName = "dlp.mjs"

	// The guard ships pre-bundled (opa-wasm inlined) so the single installed file
	// runs with no node_modules beside it. The unbundled source is the dev-tree
	// fallback, exactly as readGuard() prefers them.
	bundledGuardName = "guard.bundled.mjs"

	// OpenCode has no subprocess hook contract, so its registration is a plugin
	// module. This is the source name; it installs as solongate.js.
	opencodePluginName = "opencode-plugin.mjs"
)

// Paths is globalPaths() from the TypeScript: every location the install reads
// or writes, resolved once so nothing downstream builds its own.
type Paths struct {
	Home     string
	SGDir    string
	HooksDir string

	ClaudeDir    string
	SettingsPath string
	// A ONE-TIME copy of the settings file as it was before the first install.
	// Never restored automatically — see removeClaudeRegistration for why.
	BackupPath string

	// The active credential the installed hooks enforce with.
	ConfigPath string

	// Antigravity CLI (`agy`) reads global hooks from ~/.gemini/config/hooks.json.
	// Only the guard is registered there; its ALLOW-path audit comes from the
	// passive session-log collector rather than from a hook.
	AntigravityDir        string
	AntigravityHooksPath  string
	AntigravityBackupPath string

	// Codex reads user-level hooks from hooks.json under CODEX_HOME. The JSON
	// file rather than the [hooks] table in config.toml, so this never has to
	// rewrite the user's TOML — which also holds the hook TRUST state Codex
	// manages itself.
	CodexDir        string
	CodexHooksPath  string
	CodexBackupPath string
	CodexConfigPath string

	// OpenCode scans its plugin folder at startup, so dropping the file IS the
	// installation and deleting it IS the uninstall. Measured on 1.18.10: both
	// `plugin/` and `plugins/` are scanned; this writes the documented one.
	OpencodeDir        string
	OpencodePluginDir  string
	OpencodePluginPath string

	// The stamp the installed guard reads to skip its ~6h update check. Not a
	// protected file: clearing it is how an operator forces the guard to pick up
	// a newer bundle on the next call.
	UpdateCheckPath string
}

// GlobalPaths resolves every location for this user. The environment overrides
// (CODEX_HOME, XDG_CONFIG_HOME) are honoured the way the clients honour them,
// because a machine that moved its config dir would otherwise be registered in a
// folder nothing reads.
func GlobalPaths() Paths {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	claudeDir := filepath.Join(home, ".claude")
	antigravityDir := filepath.Join(home, ".gemini", "config")
	codexDir := absOr(os.Getenv("CODEX_HOME"), filepath.Join(home, ".codex"))
	opencodeDir := filepath.Join(absOr(os.Getenv("XDG_CONFIG_HOME"), filepath.Join(home, ".config")), "opencode")

	return Paths{
		Home:     home,
		SGDir:    config.Dir(),
		HooksDir: config.HooksDir(),

		ClaudeDir:    claudeDir,
		SettingsPath: filepath.Join(claudeDir, "settings.json"),
		BackupPath:   filepath.Join(claudeDir, "settings.solongate.bak"),

		ConfigPath: config.CredentialPath(),

		AntigravityDir:        antigravityDir,
		AntigravityHooksPath:  filepath.Join(antigravityDir, "hooks.json"),
		AntigravityBackupPath: filepath.Join(antigravityDir, "hooks.solongate.bak"),

		CodexDir:        codexDir,
		CodexHooksPath:  filepath.Join(codexDir, "hooks.json"),
		CodexBackupPath: filepath.Join(codexDir, "hooks.solongate.bak"),
		CodexConfigPath: filepath.Join(codexDir, "config.toml"),

		OpencodeDir:        opencodeDir,
		OpencodePluginDir:  filepath.Join(opencodeDir, "plugins"),
		OpencodePluginPath: filepath.Join(opencodeDir, "plugins", "solongate.js"),

		UpdateCheckPath: filepath.Join(config.Dir(), ".hook-update-check"),
	}
}

// absOr is Node's `resolve(env) || fallback`: a relative override is resolved
// against the working directory rather than used as-is, so a registration can
// never end up naming a path that only means anything from one folder.
func absOr(value, fallback string) string {
	if value == "" {
		return fallback
	}
	abs, err := filepath.Abs(value)
	if err != nil {
		return fallback
	}
	return abs
}

// Exists is existsSync: a path that can be stat'ed. Any error is "not there",
// including a permission error, because every caller's next step is the same.
func Exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// GuardPath is the hook every client's PreToolUse registration points at.
func (p Paths) GuardPath() string { return filepath.Join(p.HooksDir, GuardHookName) }

// protectedTargets is what self-protection pins. Everything on this list is a
// file that, if rewritten or removed, turns the guard off somewhere — including
// the OpenCode plugin, which IS its client's whole registration: delete it and
// the guard is gone from that client with nothing left behind to notice.
func (p Paths) protectedTargets() []string {
	return []string{
		filepath.Join(p.HooksDir, GuardHookName),
		filepath.Join(p.HooksDir, auditHookName),
		filepath.Join(p.HooksDir, stopHookName),
		filepath.Join(p.HooksDir, shieldHookName),
		// p.ConfigPath — the credential — was pinned here. Nothing writes that file, so
		// there is nothing to pin: the npm installer's list dropped it for the same
		// reason, and a lock on a file that never exists is a no-op that reads as
		// protection.
		p.SettingsPath,
		filepath.Join(p.HooksDir, tokensHookName),
		// The shared DLP list. Installed hooks import it at RUNTIME, so whoever can
		// rewrite it decides what those hooks scan for — which is the same disarm as
		// rewriting a hook, through a file that used not to exist.
		filepath.Join(p.HooksDir, dlpModuleName),
		// The launcher, which is the enforcement path now: every hook command in
		// every client config runs through it. A program that could rewrite it
		// could point every hook at /bin/true and disarm the guard without
		// touching one file that used to be on this list.
		filepath.Join(p.HooksDir, LauncherName),
		p.AntigravityHooksPath,
		p.CodexHooksPath,
		p.OpencodePluginPath,
		// The guard BINARY, which was the one file in this list's own directory
		// that was not in it.
		//
		// The hook runs whatever sits at this path as soon as it prints the
		// expected number for --sg-version, and then honours its exit code. A
		// two-line stub there allows every call, and `solongate doctor` goes on
		// reporting a native guard in use — so this was a disarm that left the
		// diagnostics saying everything was fine.
		filepath.Join(BinDir(), guardBinaryName()),
	}
}

// guardBinaryName is the file the hook looks for. It is derived from the same
// list the installer copies, so a rename cannot leave this pointing at a file
// that is no longer there.
func guardBinaryName() string { return goBinaryNames()[0] }

// LockProtected pins every protection file at the OS level.
//
// This is the layer that survives the guard's blind spot. The guard inspects
// command STRINGS; it cannot see the filesystem calls a program it allowed then
// makes, so an innocent-looking `node script.mjs` that deletes the hooks from
// the inside gets past it. Nothing gets past a file the OS refuses to write.
//
// Part of self-protection and applied on every install; SOLONGATE_NO_OS_LOCK=1
// is the developer opt-out, checked by the callers so that a machine which asked
// for no locks is never handed one by a repair.
func LockProtected() {
	for _, f := range GlobalPaths().protectedTargets() {
		config.LockFile(f)
	}
}

// UnlockProtected clears those locks so this process can rewrite the files.
// Safe by design: the CLI is human-only, and the lock exists to stop PROGRAMS
// from disarming the guard, not the person at the terminal.
func UnlockProtected() {
	for _, f := range GlobalPaths().protectedTargets() {
		config.UnlockFile(f)
	}
}

// locksDisabled is the developer opt-out. Read at each use rather than once, so
// a test (and a shell that exports it mid-session) sees the value it set.
func locksDisabled() bool { return os.Getenv("SOLONGATE_NO_OS_LOCK") == "1" }
