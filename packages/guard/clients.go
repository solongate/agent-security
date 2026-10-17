// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

type decision struct {
	Type   string
	Reason string
	Patch  map[string]interface{}
}

type parsedPayload struct {
	Tool      string
	Args      map[string]interface{}
	Command   string
	Cwd       string
	SessionID string
	Response  map[string]interface{}
}

type neutralCall struct {
	call

	Client     string
	Permission string
	Response   map[string]interface{}

	Raw []byte
}

type Client struct {
	Parse         func(raw []byte) parsedPayload
	Emit          func(d decision) int
	RedactsOutput bool

	ReportsAfter bool
}

var clients = map[string]*Client{
	"claude-code": {
		Parse:         parseFlatPayload,
		Emit:          emitHookSpecific,
		ReportsAfter:  true,
		RedactsOutput: true,
	},

	"codex": {
		Parse:        parseFlatPayload,
		Emit:         emitHookSpecific,
		ReportsAfter: true,

		RedactsOutput: false,
	},

	"opencode": {
		Parse: parseFlatPayload,
		Emit:  emitHookSpecific,

		ReportsAfter:  true,
		RedactsOutput: true,
	},

	"antigravity": {
		Parse:         parseAntigravity,
		Emit:          emitAntigravity,
		ReportsAfter:  true,
		RedactsOutput: false,
	},

	"generic": {
		Parse:         parseGeneric,
		Emit:          emitHookSpecific,
		ReportsAfter:  false,
		RedactsOutput: false,
	},
}

func clientFor(agentType string) *Client {
	if c, ok := clients[agentType]; ok {
		return c
	}
	return clients["generic"]
}

func rawFields(b json.RawMessage) map[string]json.RawMessage {
	m := map[string]json.RawMessage{}
	if len(b) == 0 {
		return m
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return map[string]json.RawMessage{}
	}
	return m
}

func jsOrRaw(f map[string]json.RawMessage, keys ...string) json.RawMessage {
	for _, k := range keys {
		v, ok := f[k]
		if !ok || len(v) == 0 {
			continue
		}
		var probe interface{}
		if json.Unmarshal(v, &probe) != nil {
			continue
		}
		if policy.JSTruthy(probe) {
			return v
		}
	}
	return nil
}

func jsOrString(f map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		v, ok := f[k]
		if !ok || len(v) == 0 {
			continue
		}
		var probe interface{}
		if json.Unmarshal(v, &probe) != nil {
			continue
		}
		if !policy.JSTruthy(probe) {
			continue
		}
		return policy.JSToString(probe)
	}
	return ""
}

func isJSONish(b json.RawMessage) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

func dropArgKeys(args map[string]interface{}, order []string, drop ...string) (map[string]interface{}, []string) {
	skip := make(map[string]bool, len(drop))
	for _, d := range drop {
		skip[strings.ToLower(d)] = true
	}
	out := make(map[string]interface{}, len(args))
	for k, v := range args {
		if !skip[strings.ToLower(k)] {
			out[k] = v
		}
	}
	var keys []string
	for _, k := range order {
		if !skip[strings.ToLower(k)] {
			keys = append(keys, k)
		}
	}
	return out, keys
}

func parseFlatPayload(raw []byte) parsedPayload {
	f := rawFields(raw)
	args, order := decodeObject(jsOrRaw(f, "tool_input", "toolInput", "params"))
	p := parsedPayload{
		Tool:      jsOrString(f, "tool_name", "toolName"),
		Args:      neutralizeArgs(args, order),
		Cwd:       jsOrString(f, "cwd"),
		SessionID: jsOrString(f, "session_id", "sessionId", "conversation_id"),
	}
	p.Response, _ = decodeObject(jsOrRaw(f, "tool_response", "toolResponse"))
	if s, ok := p.Args["command"].(string); ok {
		p.Command = s
	}
	return p
}

type hookDenyOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

type hookRewriteOutput struct {
	HookEventName      string                 `json:"hookEventName"`
	PermissionDecision string                 `json:"permissionDecision"`
	UpdatedInput       map[string]interface{} `json:"updatedInput"`
}

func emitHookSpecific(d decision) int {
	switch d.Type {
	case "deny":
		msg := d.Reason
		if msg == "" {
			msg = "[SolonGate] Blocked by policy"
		}
		out, err := json.Marshal(map[string]hookDenyOutput{
			"hookSpecificOutput": {
				HookEventName:            "PreToolUse",
				PermissionDecision:       "deny",
				PermissionDecisionReason: msg,
			},
		})
		if err == nil {
			os.Stdout.Write(out)
		}

		os.Stderr.WriteString(msg + "\n")
		return 2
	case "rewrite":
		patch := d.Patch
		if patch == nil {
			patch = map[string]interface{}{}
		}
		out, err := json.Marshal(map[string]hookRewriteOutput{
			"hookSpecificOutput": {
				HookEventName:      "PreToolUse",
				PermissionDecision: "allow",
				UpdatedInput:       patch,
			},
		})
		if err == nil {
			os.Stdout.Write(out)
		}
		return 0
	}
	return 0
}

func parseAntigravity(raw []byte) parsedPayload {
	f := rawFields(raw)
	tc := rawFields(f["toolCall"])
	a, order := decodeObject(tc["args"])

	args := neutralizeArgs(dropArgKeys(a, order, "cwd"))
	cwd := jsOrString(f, "cwd")
	if cwd == "" {
		if s, ok := a["Cwd"].(string); ok && s != "" {
			cwd = s
		} else if paths, ok := decodeArray(f["workspacePaths"]); ok && len(paths) > 0 {
			if first, ok := paths[0].(string); ok {
				cwd = first
			}
		}
	}

	tool := jsOrString(f, "tool_name")
	if tool == "" {
		tool = jsOrString(tc, "name")
	}
	p := parsedPayload{
		Tool:      tool,
		Args:      args,
		Cwd:       cwd,
		SessionID: jsOrString(f, "session_id", "conversationId"),
	}
	p.Response, _ = decodeObject(jsOrRaw(f, "tool_response", "toolResponse"))
	if s, ok := args["command"].(string); ok {
		p.Command = s
	}
	return p
}

func parseGeneric(raw []byte) parsedPayload {
	if isJSONish(rawFields(raw)["toolCall"]) {
		return parseAntigravity(raw)
	}
	return parseFlatPayload(raw)
}

func decodeArray(b json.RawMessage) ([]interface{}, bool) {
	if len(b) == 0 {
		return nil, false
	}
	var out []interface{}
	if json.Unmarshal(b, &out) != nil {
		return nil, false
	}
	return out, true
}

type agyDeny struct {
	Decision   string `json:"decision"`
	Reason     string `json:"reason"`
	AllowTool  bool   `json:"allow_tool"`
	DenyReason string `json:"deny_reason"`
}

type agyRewrite struct {
	Decision  string                 `json:"decision"`
	Overwrite map[string]interface{} `json:"overwrite"`
	AllowTool bool                   `json:"allow_tool"`
}

type agyAllow struct {
	Decision  string `json:"decision"`
	AllowTool bool   `json:"allow_tool"`
}

func emitAntigravity(d decision) int {
	switch d.Type {
	case "deny":
		msg := "[SolonGate] " + d.Reason

		writeJSON(agyDeny{Decision: "deny", Reason: msg, AllowTool: false, DenyReason: msg})
		return 0
	case "rewrite":

		overwrite := map[string]interface{}{}
		if cmd, ok := d.Patch["command"].(string); ok {
			overwrite["CommandLine"] = cmd
		} else {
			for k, v := range d.Patch {
				overwrite[k] = v
			}
		}
		writeJSON(agyRewrite{Decision: "allow", Overwrite: overwrite, AllowTool: true})
		return 0
	}
	writeJSON(agyAllow{Decision: "allow", AllowTool: true})
	return 0
}

func writeJSON(v interface{}) {
	out, err := json.Marshal(v)
	if err != nil {
		os.Stderr.WriteString("[SolonGate] decision could not be encoded\n")
		return
	}
	os.Stdout.Write(out)
}

func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

const jsSpaceClass = `[\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

var (
	reApplyPatchFile = regexp.MustCompile(`^\*\*\*` + jsSpaceClass + `+(?:Add|Update|Delete)` + jsSpaceClass + `+File:(.*)$`)

	reApplyPatchMove = regexp.MustCompile(`^\*\*\*` + jsSpaceClass + `+Move` + jsSpaceClass + `+to:(.*)$`)
)

func splitJSLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029
	})
}

func patchTarget(rest string) string {
	if t := strings.TrimFunc(rest, isJSSpace); t != "" {
		return t
	}
	r := []rune(rest)
	if len(r) == 0 {
		return ""
	}
	return string(r[len(r)-1])
}

func applyPatchTargets(patch string) []string {
	out := []string{}
	if !strings.Contains(patch, "*** ") {
		return out
	}
	lines := splitJSLines(patch)

	for _, re := range []*regexp.Regexp{reApplyPatchFile, reApplyPatchMove} {
		for _, line := range lines {
			m := re.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			if t := patchTarget(m[1]); t != "" {
				out = append(out, t)
			}
		}
	}
	return out
}

func liftFreeformPatchPaths(c *neutralCall) {
	cmd := c.Command
	if c.Tool != "apply_patch" && !strings.HasPrefix(cmd, "*** Begin Patch") {
		return
	}
	targets := applyPatchTargets(cmd)
	if len(targets) == 0 {
		return
	}
	args := make(map[string]interface{}, len(c.Args)+2)
	for k, v := range c.Args {
		args[k] = v
	}
	if !policy.JSTruthy(args["file_path"]) {
		args["file_path"] = targets[0]
	}
	if _, isArray := args["edits"].([]interface{}); !isArray {
		edits := make([]interface{}, 0, len(targets))
		for _, f := range targets {
			edits = append(edits, map[string]interface{}{"file_path": f})
		}
		args["edits"] = edits
	}
	c.Args = args
}

func normalizeToolCall(cl *Client, agentType string, raw []byte) neutralCall {
	parsed := cl.Parse(raw)
	cwd := parsed.Cwd
	if cwd == "" {
		if wd, err := os.Getwd(); err == nil {
			cwd = wd
		}
	}
	args := parsed.Args
	if args == nil {
		args = map[string]interface{}{}
	}
	response := parsed.Response
	if response == nil {
		response = map[string]interface{}{}
	}
	c := neutralCall{
		call: call{
			Tool:      parsed.Tool,
			Args:      args,
			Command:   parsed.Command,
			Cwd:       cwd,
			SessionID: parsed.SessionID,

			CallID: jsOrString(rawFields(raw), "tool_use_id", "toolUseId", "tool_call_id"),
		},
		Client:     agentType,
		Permission: shared.GuessPermission(parsed.Tool),
		Response:   response,
		Raw:        raw,
	}
	liftFreeformPatchPaths(&c)
	return c
}