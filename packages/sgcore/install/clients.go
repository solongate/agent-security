// SPDX-License-Identifier: Apache-2.0

package install

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"

	"github.com/solongate/agent-security/packages/sgcore/config"
)

// One guard, registered in every client that can run one. Only the response
// contract differs per client, and the guard handles that from the agent type
// baked into its second argument — so what changes below is where the entry
// goes and how that client spells a hook, never what decides.

// hookHandler is one command entry. Claude Code and Antigravity carry only the
// type and the command; Codex also accepts a timeout and a status message, and
// the field order is the order the TypeScript writes them in.
type hookHandler struct {
	Type          string `json:"type"`
	Command       string `json:"command"`
	Timeout       int    `json:"timeout,omitempty"`
	StatusMessage string `json:"statusMessage,omitempty"`
}

// hookGroup is a matcher with the handlers it applies to.
//
// Matcher is a pointer because an EMPTY matcher and an ABSENT matcher are
// different instructions: "" is Claude Code's match-everything, while Codex's
// Stop event ignores matchers entirely and the TypeScript omits the key there.
// A plain string with omitempty could not tell the two apart.
type hookGroup struct {
	Matcher *string       `json:"matcher,omitempty"`
	Hooks   []hookHandler `json:"hooks"`
}

func matcher(s string) *string { return &s }

// callPrefix is PowerShell's call operator.
//
// On Windows, Claude Code and Antigravity run hook commands through PowerShell,
// which reads a line STARTING with a quoted path as a string literal rather than
// as a command: it fails to parse with "Unexpected token", the hook never
// executes, and the guard silently never runs. `&` forces invocation. POSIX
// shells run a quoted path directly, so there is no prefix there — and Codex is
// the exception on Windows too, see codexHookCommand.
func callPrefix() string {
	if runtime.GOOS == "windows" {
		return "& "
	}
	return ""
}

// registration is one client's config file, prepared in full before anything is
// written. original is what was on disk, kept so the one-time backup can be
// taken at commit time from the same bytes the merge was computed from.
type registration struct {
	path       string
	dir        string
	backupPath string
	original   []byte
	content    []byte
}

// commit writes the backup (once, ever) and then the file. Order matters: a
// backup taken after the rewrite would be a copy of our own registration, which
// is the footgun the restore path already avoids by never trusting one.
func (r registration) commit() error {
	if r.dir != "" {
		if err := os.MkdirAll(r.dir, 0o755); err != nil {
			return err
		}
	}
	if r.backupPath != "" && r.original != nil && !Exists(r.backupPath) {
		_ = os.WriteFile(r.backupPath, r.original, 0o644)
	}
	return os.WriteFile(r.path, r.content, 0o644)
}

// readIfPresent returns a file's bytes, or nil when it is not there.
//
// The distinction matters more than it looks. Every merge below starts from what
// is on disk, and treating "I could not read your settings" as "you have no
// settings" would REPLACE them with ours — a permission problem turning into
// data loss. Absent is a fresh start; unreadable is a refusal.
func readIfPresent(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err == nil {
		return b, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, err
}

// ── Claude Code ──────────────────────────────────────────────────────────────
// The global settings file registers all three events. Ownership is the `hooks`
// key itself: this replaces it wholesale, which is also how the npm package
// writes it, so neither implementation can leave a duplicate behind.

func claudeHookCommand(p Paths, node, script string) string {
	return hookCommand(p, node, script, "claude-code", "Claude Code")
}

func claudeHooksValue(p Paths, node string) map[string][]hookGroup {
	group := func(script string) []hookGroup {
		return []hookGroup{{
			Matcher: matcher(""),
			Hooks:   []hookHandler{{Type: "command", Command: claudeHookCommand(p, node, script)}},
		}}
	}
	return map[string][]hookGroup{
		"PreToolUse":  group(GuardHookName),
		"PostToolUse": group(auditHookName),
		// Two groups, in this order, matching the npm package byte for byte.
		// Stop fires both: the turn marker and the reader that records what the
		// turn cost.
		"Stop": {
			{Matcher: matcher(""), Hooks: []hookHandler{{Type: "command", Command: claudeHookCommand(p, node, stopHookName)}}},
			{Matcher: matcher(""), Hooks: []hookHandler{{Type: "command", Command: claudeHookCommand(p, node, tokensHookName)}}},
		},
	}
}

// planClaude merges the registration into whatever the user already has.
//
// A settings file that will not parse is replaced by one holding only the hooks,
// which is what the TypeScript's catch does. It is not a nice outcome and it is
// kept deliberately: the alternative is refusing to guard a machine because of a
// stray comma in an unrelated setting, and the one-time backup taken just below
// still holds the file as it was.
func planClaude(p Paths, node string) (registration, error) {
	raw, err := readIfPresent(p.SettingsPath)
	if err != nil {
		return registration{}, err
	}
	obj, ok := parseJSONObject(raw)
	if !ok {
		obj = newJSONObject()
	}

	// The four events go in one object so they are emitted in the order the
	// TypeScript writes them; a map would come out sorted, which is a different
	// file for no reason.
	//
	// The list is what gets written, so the map naming an event the list does not
	// means the file will not have it — and this object replaces the `hooks` key
	// wholesale, so a missing name here is a registration `solongate repair`
	// quietly strips.
	hooks := newJSONObject()
	values := claudeHooksValue(p, node)
	for _, ev := range []string{"PreToolUse", "PostToolUse", "Stop"} {
		if err := hooks.setValue(ev, values[ev]); err != nil {
			return registration{}, err
		}
	}
	encoded, err := hooks.encode()
	if err != nil {
		return registration{}, err
	}
	obj.set("hooks", encoded)

	content, err := obj.encodeFile()
	if err != nil {
		return registration{}, err
	}
	return registration{
		path:       p.SettingsPath,
		dir:        p.ClaudeDir,
		backupPath: p.BackupPath,
		original:   raw,
		content:    content,
	}, nil
}

// removeClaudeRegistration strips the hooks from the CURRENT settings rather
// than restoring the backup.
//
// Restoring could re-ADD them: a backup taken while the guard was present would
// make the dataroom show "removed" while the guard still ran on every call —
// which is exactly the bug the row was showing.
func removeClaudeRegistration(p Paths) error {
	raw, err := readIfPresent(p.SettingsPath)
	if err != nil {
		return err
	}
	if raw == nil {
		return nil // nothing registered here
	}
	obj, ok := parseJSONObject(raw)
	if !ok {
		return errUnparseableSettings
	}
	obj.delete("hooks")
	content, err := obj.encodeFile()
	if err != nil {
		return err
	}
	return os.WriteFile(p.SettingsPath, content, 0o644)
}

var errUnparseableSettings = errors.New(
	"~/.claude/settings.json is not valid JSON, so the SolonGate hooks could not be removed from it")

// ClaudeGuardInstalled answers for Claude Code: are the hooks registered in the
// global settings on THIS device?
//
// It reads the file rather than the cloud's guard-status on purpose. The cloud
// knows what this device last REPORTED and keeps saying so for about a
// fortnight, so a guard removed a minute ago would still look installed.
func ClaudeGuardInstalled() bool {
	b, err := os.ReadFile(GlobalPaths().SettingsPath)
	if err != nil {
		return false
	}
	obj, ok := parseJSONObject(b)
	if !ok {
		return false
	}
	hooks := obj.get("hooks")
	if len(hooks) == 0 || string(hooks) == "null" {
		return false
	}
	// The registration is identified by the command pointing into ~/.solongate,
	// the same way the installer identifies its own entries.
	return strings.Contains(string(hooks), ".solongate")
}

// claudeRegisteredCommand is the PreToolUse command string already on disk, if
// there is one. Used only to recover the node binary a previous install chose.
func claudeRegisteredCommand(p Paths) string {
	b, err := os.ReadFile(p.SettingsPath)
	if err != nil {
		return ""
	}
	var s struct {
		Hooks map[string][]hookGroup `json:"hooks"`
	}
	if json.Unmarshal(b, &s) != nil {
		return ""
	}
	for _, g := range s.Hooks["PreToolUse"] {
		for _, h := range g.Hooks {
			if strings.Contains(h.Command, ".solongate") {
				return h.Command
			}
		}
	}
	return ""
}

// ── Antigravity CLI (`agy`) ──────────────────────────────────────────────────
// Antigravity's hooks.json is a map of NAMED hook groups, each holding event
// arrays. Its PreToolUse fires a local command before every tool call, which
// blocks by writing {"decision":"deny"} to stdout and exits 0 — a dialect the
// same guard.mjs produces when its agent type is "antigravity". We own ONE named
// group and replace only that, so every other group the user configured survives.

const antigravityGroup = "solongate-guard"

func antigravityHookCommand(p Paths, node string) string {
	return hookCommand(p, node, GuardHookName, "antigravity", "Antigravity")
}

// antigravityTokensCommand is the token reader on this client.
//
// Stop rather than PostInvocation: an invocation is one model call and a turn
// is often several, so PostInvocation would report a figure per step and the
// spend would read as many small turns instead of one.
func antigravityTokensCommand(p Paths, node string) string {
	return hookCommand(p, node, tokensHookName, "antigravity", "Antigravity")
}

func planAntigravity(p Paths, node string) (registration, error) {
	raw, err := readIfPresent(p.AntigravityHooksPath)
	if err != nil {
		return registration{}, err
	}
	obj, ok := parseJSONObject(raw)
	if !ok {
		obj = newJSONObject()
	}
	group := newJSONObject()
	if err := group.setValue("PreToolUse", []hookGroup{{
		Matcher: matcher(""),
		Hooks:   []hookHandler{{Type: "command", Command: antigravityHookCommand(p, node)}},
	}}); err != nil {
		return registration{}, err
	}
	if err := group.setValue("Stop", []hookGroup{{
		Matcher: matcher(""),
		Hooks:   []hookHandler{{Type: "command", Command: antigravityTokensCommand(p, node)}},
	}}); err != nil {
		return registration{}, err
	}
	encoded, err := group.encode()
	if err != nil {
		return registration{}, err
	}
	obj.set(antigravityGroup, encoded)

	content, err := obj.encodeFile()
	if err != nil {
		return registration{}, err
	}
	return registration{
		path:       p.AntigravityHooksPath,
		dir:        p.AntigravityDir,
		backupPath: p.AntigravityBackupPath,
		original:   raw,
		content:    content,
	}, nil
}

// removeAntigravityRegistration deletes only our named group. As with Claude,
// the .bak is never restored — a backup captured while the guard was present
// would silently re-add it.
func removeAntigravityRegistration(p Paths) error {
	raw, err := os.ReadFile(p.AntigravityHooksPath)
	if err != nil {
		return nil
	}
	obj, ok := parseJSONObject(raw)
	if !ok {
		return nil // leave a file we cannot read exactly as it is
	}
	if !obj.has(antigravityGroup) {
		return nil
	}
	obj.delete(antigravityGroup)
	content, err := obj.encodeFile()
	if err != nil {
		return err
	}
	return os.WriteFile(p.AntigravityHooksPath, content, 0o644)
}

func antigravityRegisteredCommand(p Paths) string {
	b, err := os.ReadFile(p.AntigravityHooksPath)
	if err != nil {
		return ""
	}
	var groups map[string]struct {
		PreToolUse []hookGroup `json:"PreToolUse"`
	}
	if json.Unmarshal(b, &groups) != nil {
		return ""
	}
	for _, g := range groups[antigravityGroup].PreToolUse {
		for _, h := range g.Hooks {
			if strings.Contains(h.Command, ".solongate") {
				return h.Command
			}
		}
	}
	return ""
}

// ── OpenCode ─────────────────────────────────────────────────────────────────
// OpenCode has no subprocess hook contract: plugins are JS modules Bun loads
// into the running process, and a call is refused by throwing from
// tool.execute.before. The shipped plugin is a shim that spawns the same guard
// every other client runs — one policy engine, not a second one that drifts.
//
// Installing is just writing the file; OpenCode scans the folder at startup, so
// there is nothing to merge and nothing to register. Two limits, both measured
// on 1.18.10 rather than read: `opencode --pure` runs with external plugins
// disabled and switches the guard off (the client's own escape hatch), and the
// plugin is as removable as any file under the user's config dir — the OS lock
// is what makes removing it require intent.

func installOpencodePlugin(p Paths, plugin []byte) error {
	if err := os.MkdirAll(p.OpencodePluginDir, 0o755); err != nil {
		return err
	}
	// WriteProtectedFile because this file is one of the locked targets: on a
	// machine that already has it pinned, a plain write fails with EPERM and a
	// caller that swallowed that would leave the OLD plugin in place.
	if !config.WriteProtectedFile(p.OpencodePluginPath, plugin) {
		return errors.New("could not write the OpenCode plugin at " + p.OpencodePluginPath)
	}
	return nil
}

func removeOpencodePlugin(p Paths) error {
	config.UnlockFile(p.OpencodePluginPath)
	if err := os.Remove(p.OpencodePluginPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// OpencodeGuardInstalled keys off the hook the plugin implements rather than the
// filename, so a file someone else left under our name is not mistaken for the
// guard.
func OpencodeGuardInstalled() bool {
	b, err := os.ReadFile(GlobalPaths().OpencodePluginPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "tool.execute.before")
}

// OpencodeDetected reports whether OpenCode looks present on this device, so a
// caller can decide whether an OpenCode row is worth showing at all. A line
// saying OpenCode is unguarded, on a machine with no OpenCode, is noise that
// teaches people to ignore the check.
func OpencodeDetected() bool { return Exists(GlobalPaths().OpencodeDir) }
