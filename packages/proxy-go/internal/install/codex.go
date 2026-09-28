package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

// Codex CLI (`codex`) loads user-level lifecycle hooks from hooks.json under
// CODEX_HOME. The file shape is (codex-rs/config/src/hook_config.rs, which
// denies unknown fields):
//
//	{ "description"?: string,
//	  "hooks": { "<Event>": [ { "matcher"?: string,
//	                            "hooks": [ { "type": "command", "command": "…",
//	                                         "timeout"?: <seconds>,
//	                                         "statusMessage"?: "…" } ] } ] } }
//
// Its PreToolUse contract is the one Claude Code uses — deny is exit 2 with the
// reason on stderr, or a permissionDecision on stdout — so the guard's
// claude-code branch already speaks it and the agent type only changes identity
// and audit source. Codex fires the hooks for Bash, apply_patch (whose matcher
// aliases Write/Edit), MCP tools and local function tools.
//
// Unlike Antigravity's named groups, Codex's file is a plain per-event list, so
// "ours" is any entry whose command points into ~/.solongate. Every other entry
// in the file is preserved untouched.
//
// One-time trust: Codex refuses to RUN a non-managed hook until the user
// reviews it with `/hooks`, keyed by a hash of the hook's config. The command
// string is stable across guard updates — the file content changes, the
// registration does not — so the trust survives every later update and is asked
// for exactly once.

// The events registered here, in the order they are written.
//
// Codex takes ONE handler per event, so its Stop is the token reader rather
// than the no-op the Claude registration keeps there for machines that already
// have it.
var codexEvents = []string{"PreToolUse", "PostToolUse", "Stop"}

// The timeout Codex applies to each of our hooks, in seconds.
const codexTimeoutSec = 30

// Every event name Codex knows. Needed because a stray top-level event key makes
// Codex reject the WHOLE file (deny_unknown_fields), silently dropping every
// hook including ours — so the reader folds those keys into `hooks` instead of
// leaving a file that cannot be loaded.
var codexAllEvents = map[string]bool{
	"PreToolUse": true, "PermissionRequest": true, "PostToolUse": true,
	"PreCompact": true, "PostCompact": true, "SessionStart": true, "SessionEnd": true,
	"UserPromptSubmit": true, "SubagentStart": true, "SubagentStop": true, "Stop": true,
}

// codexFile is hooks.json split into the three things a rewrite has to keep
// apart: everything we do not understand (preserved as-is and first), the
// description, and the per-event groups.
type codexFile struct {
	rest        *jsonObject
	description json.RawMessage
	events      []string
	groups      map[string][]json.RawMessage
}

func newCodexFile() codexFile {
	return codexFile{rest: newJSONObject(), groups: map[string][]json.RawMessage{}}
}

func (f *codexFile) setGroups(event string, groups []json.RawMessage) {
	if _, ok := f.groups[event]; !ok {
		f.events = append(f.events, event)
	}
	f.groups[event] = groups
}

func (f *codexFile) appendGroups(event string, groups []json.RawMessage) {
	f.setGroups(event, append(f.groups[event], groups...))
}

func readCodexHooks(path string) codexFile {
	out := newCodexFile()
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	obj, ok := parseJSONObject(b)
	if !ok {
		return out
	}
	for _, k := range obj.keys {
		v := obj.get(k)
		if k == "description" && isJSONString(v) {
			out.description = v
			continue
		}
		if k == "hooks" {
			if nested, ok := parseJSONObject(v); ok {
				for _, ev := range nested.keys {
					if groups, ok := decodeArray(nested.get(ev)); ok {
						out.setGroups(ev, groups)
					}
				}
				continue
			}
		}
		if codexAllEvents[k] {
			if groups, ok := decodeArray(v); ok {
				out.appendGroups(k, groups)
				continue
			}
		}
		out.rest.set(k, v)
	}
	return out
}

// encode renders the file back. An event whose groups all went away is dropped
// rather than written as an empty array, so removing our hook from a file that
// had nothing else in it leaves Codex with a clean `"hooks": {}`.
func (f codexFile) encode() ([]byte, error) {
	hooks := newJSONObject()
	for _, ev := range f.events {
		groups := f.groups[ev]
		if len(groups) == 0 {
			continue
		}
		encoded, err := marshalJS(groups)
		if err != nil {
			return nil, err
		}
		hooks.set(ev, encoded)
	}
	encodedHooks, err := hooks.encode()
	if err != nil {
		return nil, err
	}

	body := newJSONObject()
	for _, k := range f.rest.keys {
		body.set(k, f.rest.get(k))
	}
	// An empty description is dropped, matching the TypeScript's truthiness test:
	// writing `"description": ""` back would be a field Codex has to parse for
	// nothing.
	if len(f.description) > 0 && string(f.description) != `""` {
		body.set("description", f.description)
	}
	body.set("hooks", encodedHooks)
	return body.encodeFile()
}

// codexHookCommand has NO PowerShell call prefix, unlike the Claude and
// Antigravity registrations. Codex runs a hook command through `$SHELL -lc` on
// POSIX and cmd.exe on Windows, and cmd has no call operator — a `&` prefix
// there would break the hook rather than fix it.
func codexHookCommand(p Paths, node, script string) string {
	// Codex runs a hook through `$SHELL -lc` on POSIX, so its environment DOES
	// usually have node on PATH — but "usually" is what the last version of this
	// relied on. It goes through the launcher too, which tries PATH anyway.
	//
	// The one difference from the others: no PowerShell call prefix on Windows.
	// Codex uses cmd.exe there and cmd has no call operator, so the prefix would
	// break the hook rather than fix it. hookCommand adds one on Windows, so
	// Windows is still written out longhand here.
	if runtime.GOOS == "windows" {
		return `"` + filepath.ToSlash(node) + `" "` + filepath.ToSlash(filepath.Join(p.HooksDir, script)) + `" codex "Codex"`
	}
	return hookCommand(p, node, script, "codex", "Codex")
}

func planCodex(p Paths, node string) (registration, error) {
	// An unreadable file skips Codex entirely rather than being rewritten from an
	// empty one: the caller treats this error as "leave that client alone", which
	// is what the TypeScript's try/catch around the Codex install amounts to.
	raw, err := readIfPresent(p.CodexHooksPath)
	if err != nil {
		return registration{}, err
	}
	file := readCodexHooks(p.CodexHooksPath)

	script := map[string]string{
		"PreToolUse":  GuardHookName,
		"PostToolUse": auditHookName,
		"Stop":        tokensHookName,
	}
	status := map[string]string{
		"PreToolUse":  "SolonGate policy check",
		"PostToolUse": "SolonGate audit",
		"Stop":        "SolonGate token report",
	}

	for _, ev := range codexEvents {
		kept := make([]json.RawMessage, 0, len(file.groups[ev]))
		for _, g := range file.groups[ev] {
			if !isOurCodexGroup(g) { // replace only ours
				kept = append(kept, g)
			}
		}
		group := hookGroup{
			// "*" is Codex's match-all. Stop ignores matchers entirely, so the key
			// is omitted there rather than sent as something Codex would ignore.
			Hooks: []hookHandler{{
				Type:          "command",
				Command:       codexHookCommand(p, node, script[ev]),
				Timeout:       codexTimeoutSec,
				StatusMessage: status[ev],
			}},
		}
		if ev != "Stop" {
			group.Matcher = matcher("*")
		}
		encoded, err := marshalJS(group)
		if err != nil {
			return registration{}, err
		}
		file.setGroups(ev, append(kept, encoded))
	}

	content, err := file.encode()
	if err != nil {
		return registration{}, err
	}
	return registration{
		path:       p.CodexHooksPath,
		dir:        p.CodexDir,
		backupPath: p.CodexBackupPath,
		original:   raw,
		content:    content,
	}, nil
}

// removeCodexRegistration drops only our entries; anything the user configured
// stays. Like the other clients the .bak is never restored — a backup taken
// while the guard was registered would silently re-add it.
func removeCodexRegistration(p Paths) error {
	if !Exists(p.CodexHooksPath) {
		return nil
	}
	file := readCodexHooks(p.CodexHooksPath)
	changed := false
	for _, ev := range file.events {
		groups := file.groups[ev]
		kept := make([]json.RawMessage, 0, len(groups))
		for _, g := range groups {
			if !isOurCodexGroup(g) {
				kept = append(kept, g)
			}
		}
		if len(kept) != len(groups) {
			file.groups[ev] = kept
			changed = true
		}
	}
	if !changed {
		return nil
	}
	content, err := file.encode()
	if err != nil {
		return err
	}
	return os.WriteFile(p.CodexHooksPath, content, 0o644)
}

// isOurCodexGroup identifies our entries by the command pointing into
// ~/.solongate, which is how the file itself says who owns a hook — there is no
// name to own, the way Antigravity has one.
func isOurCodexGroup(raw json.RawMessage) bool {
	var g struct {
		Hooks []struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(raw, &g) != nil {
		return false
	}
	for _, h := range g.Hooks {
		if strings.Contains(h.Command, ".solongate") {
			return true
		}
	}
	return false
}

// CodexGuardInstalled looks in BOTH places a PreToolUse group can be written.
//
// The installer folds a stray top-level event key into "hooks" rather than
// leaving a file Codex would reject outright, which means a file on disk may
// still carry either shape. A reader that only looked under "hooks" would report
// a registered guard as missing and send someone to repair a guarded machine.
func CodexGuardInstalled() bool {
	file := readCodexHooks(GlobalPaths().CodexHooksPath)
	for _, g := range file.groups["PreToolUse"] {
		if isOurCodexGroup(g) {
			return true
		}
	}
	return false
}

// CodexDetected reports whether Codex looks present on this device (its config
// directory exists).
func CodexDetected() bool { return Exists(GlobalPaths().CodexDir) }

func codexRegisteredCommand(p Paths) string {
	for _, g := range readCodexHooks(p.CodexHooksPath).groups["PreToolUse"] {
		var group struct {
			Hooks []struct {
				Command string `json:"command"`
			} `json:"hooks"`
		}
		if json.Unmarshal(g, &group) != nil {
			continue
		}
		for _, h := range group.Hooks {
			if strings.Contains(h.Command, ".solongate") {
				return h.Command
			}
		}
	}
	return ""
}

// CodexStatus is three separate questions because Codex has three separate ways
// of not running a hook: it is not registered, hooks are switched off wholesale
// in config.toml, or it is registered but never trusted — and Codex silently
// SKIPS a hook it has not been trusted for. "Registered" alone does not mean the
// guard is live there.
type CodexStatus struct {
	Registered bool
	Trusted    bool
	Disabled   bool
}

var (
	codexTrustedRe  = regexp.MustCompile(`trusted_hash\s*=`)
	codexDisabledRe = regexp.MustCompile(`(?m)^\s*hooks\s*=\s*false\s*$`)
)

// CodexHooksStatus reads the trust state out of config.toml.
//
// Trust cannot be verified precisely: Codex keys it by a private hash this side
// cannot recompute. All that can be answered is whether anything has ever been
// trusted, which is enough to stop nagging someone who already did it.
func CodexHooksStatus() CodexStatus {
	st := CodexStatus{Registered: CodexGuardInstalled()}
	if b, err := os.ReadFile(GlobalPaths().CodexConfigPath); err == nil {
		st.Trusted = codexTrustedRe.Match(b)
		st.Disabled = codexDisabledRe.Match(b)
	}
	return st
}

func isJSONString(v json.RawMessage) bool {
	return len(v) > 0 && v[0] == '"'
}

func decodeArray(v json.RawMessage) ([]json.RawMessage, bool) {
	if len(v) == 0 || v[0] != '[' {
		return nil, false
	}
	var out []json.RawMessage
	if json.Unmarshal(v, &out) != nil {
		return nil, false
	}
	return out, true
}
