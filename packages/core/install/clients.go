// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strings"

	"github.com/solongate/agent-security/packages/core/config"
)

type hookHandler struct {
	Type          string `json:"type"`
	Command       string `json:"command"`
	Timeout       int    `json:"timeout,omitempty"`
	StatusMessage string `json:"statusMessage,omitempty"`
}

type hookGroup struct {
	Matcher *string       `json:"matcher,omitempty"`
	Hooks   []hookHandler `json:"hooks"`
}

func matcher(s string) *string { return &s }

func callPrefix() string {
	if runtime.GOOS == "windows" {
		return "& "
	}
	return ""
}

type registration struct {
	path       string
	dir        string
	backupPath string
	original   []byte
	content    []byte
}

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

		"Stop": {
			{Matcher: matcher(""), Hooks: []hookHandler{{Type: "command", Command: claudeHookCommand(p, node, stopHookName)}}},
			{Matcher: matcher(""), Hooks: []hookHandler{{Type: "command", Command: claudeHookCommand(p, node, tokensHookName)}}},
		},
	}
}

func planClaude(p Paths, node string) (registration, error) {
	raw, err := readIfPresent(p.SettingsPath)
	if err != nil {
		return registration{}, err
	}
	obj, ok := parseJSONObject(raw)
	if !ok {
		obj = newJSONObject()
	}

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

func removeClaudeRegistration(p Paths) error {
	raw, err := readIfPresent(p.SettingsPath)
	if err != nil {
		return err
	}
	if raw == nil {
		return nil
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

	return strings.Contains(string(hooks), ".solongate")
}

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

const antigravityGroup = "solongate-guard"

func antigravityHookCommand(p Paths, node string) string {
	return hookCommand(p, node, GuardHookName, "antigravity", "Antigravity")
}

func antigravityAuditCommand(p Paths, node string) string {
	return hookCommand(p, node, auditHookName, "antigravity", "Antigravity")
}

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
	if err := group.setValue("PostToolUse", []hookGroup{{
		Matcher: matcher(""),
		Hooks:   []hookHandler{{Type: "command", Command: antigravityAuditCommand(p, node)}},
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

func removeAntigravityRegistration(p Paths) error {
	raw, err := os.ReadFile(p.AntigravityHooksPath)
	if err != nil {
		return nil
	}
	obj, ok := parseJSONObject(raw)
	if !ok {
		return nil
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

func installOpencodePlugin(p Paths, plugin []byte) error {
	if err := os.MkdirAll(p.OpencodePluginDir, 0o755); err != nil {
		return err
	}

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

func OpencodeGuardInstalled() bool {
	b, err := os.ReadFile(GlobalPaths().OpencodePluginPath)
	if err != nil {
		return false
	}
	return strings.Contains(string(b), "tool.execute.before")
}

func OpencodeDetected() bool { return Exists(GlobalPaths().OpencodeDir) }