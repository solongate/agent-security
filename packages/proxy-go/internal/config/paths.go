// Package config is every file the SolonGate CLI reads or writes under
// ~/.solongate.
//
// The shapes are not this port's to choose. The npm package @solongate/proxy
// stays installed and keeps running against the same directory, so a field
// written in a different spelling, or a file written where the other
// implementation does not look, corrupts state both are using. Everything here
// matches what packages/proxy writes today, and where it overlaps
// packages/guard-go/config.go it matches that field for field — see the note in
// state.go about which of the two should own the shared shapes.
package config

import (
	"os"
	"path/filepath"

	"github.com/codeyevsky/solongate/sgshared"
)

// Dir is ~/.solongate. Resolved the same way the guard resolves it, including
// the HOME fallback: on a machine where the user database is unreadable
// os.UserHomeDir fails and the guard still has to find its own files.
// DirMode and FileMode are sgshared's, re-exported so a caller in this tree names
// one constant rather than reaching past config for it. One definition: several
// programs create ~/.solongate and the mode has to be the same in all of them.
const (
	DirMode  = sgshared.DirMode
	FileMode = sgshared.FileMode
)

func Dir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		home = os.Getenv("HOME")
	}
	return filepath.Join(home, ".solongate")
}

// The active credential the guard hooks enforce with. One per device, not one
// per account: accounts.json accumulates every account, this file names the one
// that is armed.
func CredentialPath() string { return filepath.Join(Dir(), "cloud-guard.json") }

// Every account ever logged in on this device, so the dataroom can switch
// between them without another device-login round trip.
func AccountsPath() string { return filepath.Join(Dir(), "accounts.json") }

func TUIConfigPath() string { return filepath.Join(Dir(), "tui-config.json") }

// Desired state of the local audit-log service. `desired` in here outlives the
// process: closing the terminal kills the server, it does not disable it.

// The Shadow AI browser agent: the process a browser asks before it lets
// somebody paste. Its own state file and its own log, beside the audit
// service's, because they are two services with two lifetimes and one file
// holding both would mean stopping one rewrote the other's row.
func BrowserAgentStatePath() string { return filepath.Join(Dir(), ".browser-agent.json") }

func BrowserAgentLogPath() string { return filepath.Join(Dir(), "browser-agent.log") }

func SelfUpdateStatePath() string { return filepath.Join(Dir(), ".self-update.json") }

func SelfUpdateLogPath() string { return filepath.Join(Dir(), "self-update.log") }

// Dropped by the guard when the cloud rejects the key a HOOK used, and removed
// again on the next accepted call. Enforcement keeps working while this exists,
// which is exactly why it has to be surfaced: nothing is being logged and
// nothing says so.
func KeyRejectedPath() string { return filepath.Join(Dir(), ".key-rejected.json") }

// The starter policy the onboarding wizard writes. The guard falls back to it
// when the cloud cache holds no policy.
func LocalPolicyPath() string { return filepath.Join(Dir(), "policy.json") }

func HooksDir() string { return filepath.Join(Dir(), "hooks") }

func LocalLogsDir() string { return filepath.Join(Dir(), "local-logs") }

// Where the hooks append when local logging is on but no folder is configured,
// and the fallback for a folder that is not a location on this device.
func DefaultLocalLogFile() string {
	return filepath.Join(LocalLogsDir(), "solongate-audit.jsonl")
}

// Marker recording which account the local log belongs to. A hash, never the
// key, and never deleted with the log: readers keep only their own entries so a
// change of account separates the history rather than destroying it.
func LocalLogOwnerPath() string { return filepath.Join(LocalLogsDir(), ".owner") }

func PolicyCachePath(agent string) string {
	return filepath.Join(Dir(), ".policy-cache-"+AgentKey(agent)+".json")
}

// AgentKey sanitises an agent id into a filename component. It has to produce
// the same name as the hooks or this CLI opens a cache file nothing writes.
//
// The substitution runs over UTF-16 code units, not runes, because the hooks do
// `(AGENT_ID || 'default').replace(/[^a-zA-Z0-9_-]/g, '_')` and a JavaScript
// character class matches ONE code unit — so an agent id containing an emoji
// becomes two underscores there and would become one here if this iterated
// runes. See the note under ProjectKey.
func AgentKey(a string) string { return sgshared.AgentKey(a) }

// ProjectKey hashes a project path so per-call scratch stays separated per
// project WITHOUT being written into the project.
//
// This hash is duplicated in the Node guard, the audit hook, the dataroom and
// packages/guard-go. All of them must agree or a reader opens an empty
// directory and reports no activity for a project that is busy.
//
// It hashes UTF-16 CODE UNITS. The three Node implementations use
// `s.charCodeAt(i)`, and they are the ones writing the directories today, so
// they are what this has to match. packages/guard-go hashes BYTES instead,
// which agrees for an ASCII path and diverges the moment a path contains a
// non-ASCII character — /home/müşteri/proj hashes to 98d8e9fc here and to
// 1ec69c96 there. Matching the byte version to stay consistent with the other
// Go module would have meant this CLI reading an empty flag directory on every
// machine whose home directory is not ASCII.
func ProjectKey(d string) string { return sgshared.ProjectKey(d) }

// ProjectFlagDir is where the guard leaves the per-call evaluation record the
// audit hook reads back.
func ProjectFlagDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = cwd
	}
	return filepath.Join(Dir(), "projects", ProjectKey(abs))
}

// EnsureDir creates ~/.solongate. Every writer here calls it rather than
// assuming the directory exists: on a machine that has only ever run the CLI
// and never a guarded tool call, nothing has created it yet.
// EnsureDir creates ~/.solongate, owner-only.
//
// Owner-only because the credential files inside it are 0600 and a world-readable
// directory still lets another account on the machine ENUMERATE them — which names
// the projects, the accounts and every agent that has run here.
//
// It delegates to sgshared, which is where the mode lives, because the GUARD
// creates this same directory through that package and the two used to disagree:
// 0700 here and 0755 there, so the mode a machine ended up with depended on which
// program ran first — and the guard runs constantly.
func EnsureDir() error { return sgshared.EnsureSGDir() }

// ensureOwnerOnly narrows an existing path's mode to owner-only, keeping its
// file/directory bits.
//
// Needed because Go's create-with-mode does nothing to a path that is already
// there, and these files predate the mode being right. Best effort: a chmod that
// fails (a read-only mount, a Windows filesystem with no POSIX bits) must not
// stop the CLI from working — it is a hardening step, not a precondition.
func ensureOwnerOnly(path string) {
	info, err := os.Stat(path)
	if err != nil {
		return
	}
	want := os.FileMode(0o600)
	if info.IsDir() {
		want = 0o700
	}
	if info.Mode().Perm() != want {
		_ = os.Chmod(path, want)
	}
}
