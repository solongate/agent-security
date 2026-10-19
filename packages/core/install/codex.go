// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package install

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

var codexEvents = []string{"PreToolUse", "PostToolUse", "Stop"}

const codexTimeoutSec = 30

var codexAllEvents = map[string]bool{
	"PreToolUse": true, "PermissionRequest": true, "PostToolUse": true,
	"PreCompact": true, "PostCompact": true, "SessionStart": true, "SessionEnd": true,
	"UserPromptSubmit": true, "SubagentStart": true, "SubagentStop": true, "Stop": true,
}

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

	if len(f.description) > 0 && string(f.description) != `""` {
		body.set("description", f.description)
	}
	body.set("hooks", encodedHooks)
	return body.encodeFile()
}

func codexHookCommand(p Paths, kind string) string {
	return hookCommand(p, kind, "codex", "Codex")
}

func planCodex(p Paths) (registration, error) {

	raw, err := readIfPresent(p.CodexHooksPath)
	if err != nil {
		return registration{}, err
	}
	file := readCodexHooks(p.CodexHooksPath)

	kind := map[string]string{
		"PreToolUse":  guardKind,
		"PostToolUse": auditKind,
		"Stop":        tokensKind,
	}
	status := map[string]string{
		"PreToolUse":  "SolonGate policy check",
		"PostToolUse": "SolonGate audit",
		"Stop":        "SolonGate token report",
	}

	for _, ev := range codexEvents {
		kept := make([]json.RawMessage, 0, len(file.groups[ev]))
		for _, g := range file.groups[ev] {
			if !isOurCodexGroup(g) {
				kept = append(kept, g)
			}
		}
		group := hookGroup{

			Hooks: []hookHandler{{
				Type:          "command",
				Command:       codexHookCommand(p, kind[ev]),
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

func CodexGuardInstalled() bool {
	file := readCodexHooks(GlobalPaths().CodexHooksPath)
	for _, g := range file.groups["PreToolUse"] {
		if isOurCodexGroup(g) {
			return true
		}
	}
	return false
}

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

type CodexStatus struct {
	Registered bool
	Trusted    bool
	Disabled   bool
}

var (
	codexTrustedRe  = regexp.MustCompile(`trusted_hash\s*=`)
	codexDisabledRe = regexp.MustCompile(`(?m)^\s*hooks\s*=\s*false\s*$`)
)

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