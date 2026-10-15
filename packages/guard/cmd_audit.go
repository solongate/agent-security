// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/solongate/agent-security/packages/policy"
	"github.com/solongate/agent-security/packages/shared"
)

// runAudit is the PostToolUse twin of main()'s PreToolUse guard: it logs a
// tool call that already ran and, on a client that can accept a rewrite,
// masks secrets out of the result before the model sees them. Ported from
// hooks/audit.mjs, which this must keep matching — a client installs one or
// the other, never both, and the two have to behave identically for whichever
// one lands.
//
// It never signals failure through the exit code. PostToolUse cannot un-run a
// tool, so ALLOW/DENY here are log classifications, not a block — every path,
// including the top-level recover, returns 0.
func runAudit(args []string) (code int) {
	defer func() {
		if recover() != nil {
			code = 0
		}
	}()

	agentID := "claude-code"
	if len(args) > 0 && args[0] != "" {
		agentID = args[0]
	}
	agentName := "Claude Code"
	if len(args) > 1 && args[1] != "" {
		agentName = args[1]
	}

	raw, _ := io.ReadAll(os.Stdin)

	// A payload that fails to parse at all, or parses to JSON null, is the one
	// case audit.mjs can't shrug off field-by-field (`JSON.parse` throws,
	// `null.tool_name` throws) — everything after this point reads through
	// rawFields/jsOrRaw/jsOrString, which treat a missing field as absent
	// rather than a panic.
	var probe interface{}
	if err := json.Unmarshal(raw, &probe); err != nil || probe == nil {
		return 0
	}
	fields := rawFields(json.RawMessage(raw))

	toolName := jsOrString(fields, "tool_name", "toolName")
	if toolName == "" {
		toolName = "unknown"
	}

	toolInputRaw := jsOrRaw(fields, "tool_input", "toolInput", "params")
	if toolInputRaw == nil {
		toolInputRaw = json.RawMessage("{}")
	}
	var toolInputMap map[string]interface{}
	_ = json.Unmarshal(toolInputRaw, &toolInputMap)

	if toolName == "Bash" && strings.Contains(string(toolInputRaw), "audit-logs") {
		return 0
	}

	callID := jsOrString(fields, "tool_use_id", "toolUseId", "tool_call_id")

	// Did the guard already log a DENY for THIS EXACT call? If so this
	// PostToolUse is a duplicate and must not be logged a second time. The
	// match is per-call (tool_use_id, else an argument fingerprint), not per
	// tool name — see guard.mjs's writeDenyFlag and the long comment on the
	// equivalent block in audit.mjs.
	guardDenied := false
	func() {
		defer func() { recover() }()
		b, err := os.ReadFile(filepath.Join(shared.ProjectFlagDir(), ".last-deny"))
		if err != nil {
			return
		}
		var flag struct {
			Tool string  `json:"tool"`
			TS   float64 `json:"ts"`
			ID   string  `json:"id"`
			FP   string  `json:"fp"`
		}
		if json.Unmarshal(b, &flag) != nil {
			return
		}
		now := float64(time.Now().UnixMilli())
		if flag.TS == 0 || now-flag.TS >= 10000 || flag.Tool != toolName {
			return
		}
		switch {
		case flag.ID != "" && callID != "":
			guardDenied = flag.ID == callID
		default:
			fp := callFingerprint(compactJSON(toolInputRaw))
			if flag.FP != "" && fp != "" {
				guardDenied = flag.FP == fp
			} else {
				guardDenied = flag.ID == "" && flag.FP == ""
			}
		}
	}()

	toolResponseRaw := jsOrRaw(fields, "tool_response", "toolResponse")
	if toolResponseRaw == nil {
		toolResponseRaw = json.RawMessage("{}")
	}
	var toolResponseVal interface{}
	_ = json.Unmarshal(toolResponseRaw, &toolResponseVal)

	toolOutput := jsOrString(fields, "tool_output", "toolOutput")

	resultJSONStr := ""
	if r := jsOrRaw(fields, "result_json"); r != nil {
		var v interface{}
		_ = json.Unmarshal(r, &v)
		if s, ok := v.(string); ok {
			resultJSONStr = s
		} else {
			resultJSONStr = string(r)
		}
	}

	local := loadLocalPolicyFile("")
	var sec *shared.Security
	if local != nil && local.HasSecurity {
		sec = local.Security
	}

	// DLP: rewrite the output the model sees so secret values are masked.
	// Fail-open: any error here leaves the original output untouched.
	var emittedPayload []byte
	hitSeen := map[string]bool{}
	var outputHits []string
	addHit := func(name string) {
		if !hitSeen[name] {
			hitSeen[name] = true
			outputHits = append(outputHits, name)
		}
	}
	func() {
		defer func() { recover() }()
		dlpCfg := loadDlpRedactCfg(sec)
		if dlpCfg == nil {
			return
		}

		// Glob (and Grep in files mode) deliver a STRUCTURED result —
		// {filenames: string[], numFiles, totalMatches, ...} — and Claude Code
		// rejects a plain-string updatedToolOutput for it (a "PostToolUse:Glob
		// hook warning", original kept). Return the SAME shape instead: the
		// filenames array with secret-looking names masked.
		if trMap, ok := toolResponseVal.(map[string]interface{}); ok {
			if filenames, ok := trMap["filenames"].([]interface{}); ok {
				orig := make([]string, len(filenames))
				for i, f := range filenames {
					orig[i] = policy.JSToString(f)
				}
				masked := make([]string, len(orig))
				changed := false
				for i, f := range orig {
					for _, name := range dlpScanText(f, dlpCfg) {
						addHit(name)
					}
					masked[i] = dlpRedactText(f, dlpCfg)
					if masked[i] != f {
						changed = true
					}
				}
				if changed {
					updated := cloneMap(trMap)
					maskedIface := make([]interface{}, len(masked))
					for i, m := range masked {
						maskedIface[i] = m
					}
					updated["filenames"] = maskedIface
					updated["numFiles"] = float64(len(masked))
					if _, ok := trMap["totalMatches"].(float64); ok {
						updated["totalMatches"] = float64(len(masked))
					}
					if b, err := json.Marshal(map[string]interface{}{
						"hookSpecificOutput": map[string]interface{}{
							"hookEventName":     "PostToolUse",
							"updatedToolOutput": updated,
						},
					}); err == nil {
						emittedPayload = b
					}
				}
				return
			}
		}

		// String-output tools (Bash, Read, text Grep, MCP listers): redact
		// secrets in the TEXT, return a STRING — but only if the tool's own
		// result shape was already a string; a structured result (stdout,
		// content, file.content) is cloned with its text field swapped,
		// because Claude Code rejects a bare-string replacement for those too.
		base := extractOutputText(toolResponseVal, toolOutput)
		if base == nil {
			return
		}
		for _, name := range dlpScanText(*base, dlpCfg) {
			addHit(name)
		}
		redacted := dlpRedactText(*base, dlpCfg)
		if redacted == *base {
			return
		}
		out := redacted
		if out == "" {
			out = "\n"
		}

		var updated interface{} = out
		if tr, ok := toolResponseVal.(map[string]interface{}); ok {
			switch {
			case isString(tr["stdout"]):
				nt := cloneMap(tr)
				nt["stdout"] = out
				updated = nt
			case isString(tr["content"]):
				nt := cloneMap(tr)
				nt["content"] = out
				updated = nt
			case isArray(tr["content"]):
				nt := cloneMap(tr)
				nt["content"] = []interface{}{map[string]interface{}{"type": "text", "text": out}}
				updated = nt
			default:
				if fm, ok := tr["file"].(map[string]interface{}); ok {
					if isString(fm["content"]) {
						nt := cloneMap(tr)
						nf := cloneMap(fm)
						nf["content"] = out
						nt["file"] = nf
						updated = nt
					}
				}
			}
		}

		if b, err := json.Marshal(map[string]interface{}{
			"hookSpecificOutput": map[string]interface{}{
				"hookEventName":     "PostToolUse",
				"updatedToolOutput": updated,
			},
		}); err == nil {
			emittedPayload = b
		}
	}()

	hasError := guardDenied
	if tr, ok := toolResponseVal.(map[string]interface{}); ok {
		if !hasError && policy.JSTruthy(tr["error"]) {
			hasError = true
		}
		if !hasError && jsToNumber(tr["exitCode"]) > 0 {
			hasError = true
		}
		if !hasError && policy.JSTruthy(tr["isError"]) {
			hasError = true
		}
	}
	if !hasError && toolOutput != "" && strings.Contains(toolOutput, `"error"`) {
		hasError = true
	}
	if !hasError && resultJSONStr != "" && strings.Contains(resultJSONStr, `"error"`) {
		hasError = true
	}

	// Keep the full command/args for audit review. Only cap pathologically
	// large values.
	argsSummary := map[string]interface{}{}
	for k, v := range toolInputMap {
		if s, ok := v.(string); ok {
			r := []rune(s)
			if len(r) > 8000 {
				s = string(r[:8000]) + "…"
			}
			argsSummary[k] = s
		} else {
			argsSummary[k] = v
		}
	}

	// Only a client whose wire protocol actually accepts a rewrite gets the
	// payload — audit.mjs hardcodes this to Codex (its PostToolUse struct is
	// deny_unknown_fields); this generalizes to whichever client the caller
	// names, via clients.go's RedactsOutput capability rather than a second
	// per-client switch.
	if !clientFor(agentID).RedactsOutput {
		emittedPayload = nil
	}
	if emittedPayload != nil {
		_, _ = os.Stdout.Write(emittedPayload)
	}

	sessionID := jsOrString(fields, "session_id", "sessionId", "conversation_id")
	decision := "ALLOW"
	if hasError {
		decision = "DENY"
	}
	reason := ""
	if guardDenied {
		reason = "blocked by policy guard"
	} else if hasError {
		reason = "tool returned error"
	}
	permission := shared.GuessPermission(toolName)
	evaluationTimeMs := readLastEvalMs(toolName, sessionID)

	// DETECT-mode observation: record DLP matches / rate-limit bursts on this
	// ALLOW entry so "detect" means observe-AND-log, not silent. Only
	// meaningful on ALLOW — block-mode hits are denied upstream with their own
	// reason. Fail-safe: any error just omits the field.
	var dlpMatches []string
	rateLimitBurst := false
	if decision == "ALLOW" {
		func() {
			defer func() { recover() }()
			argsJSON, _ := json.Marshal(argsSummary)
			dlpMatches = dlpScanText(string(argsJSON), loadDlpScanCfg(sec))
		}()
		func() {
			defer func() { recover() }()
			if len(outputHits) == 0 {
				scanCfg := loadDlpScanCfg(sec)
				if scanCfg != nil && sec != nil && sec.DLPObserve != nil && sec.DLPRedact == nil && sec.DLPBlock == nil {
					if base := extractOutputText(toolResponseVal, toolOutput); base != nil && *base != "" {
						for _, n := range dlpScanText(*base, scanCfg) {
							addHit(n)
						}
					}
				}
			}
			for _, name := range outputHits {
				found := false
				for _, m := range dlpMatches {
					if m == name {
						found = true
						break
					}
				}
				if !found {
					dlpMatches = append(dlpMatches, name)
				}
			}
		}()
		func() {
			defer func() { recover() }()
			rateLimitBurst = rateLimitObserveBurst(agentID, loadRateLimitObserveCfg(sec))
		}()
	}

	entry := map[string]interface{}{
		"ts":                 time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"tool":               toolName,
		"arguments":          argsSummary,
		"decision":           decision,
		"reason":             reason,
		"permission":         permission,
		"evaluation_time_ms": nil,
		"agent_id":           agentID,
		"agent_name":         agentName,
		"session_id":         sessionID,
	}
	if evaluationTimeMs != nil {
		entry["evaluation_time_ms"] = *evaluationTimeMs
	}
	if len(dlpMatches) > 0 {
		entry["dlp"] = dlpMatches
	}
	if rateLimitBurst {
		entry["rate_limit_burst"] = true
	}
	writeLocalLog(sec, entry)

	return 0
}

func isString(v interface{}) bool {
	s, ok := v.(string)
	return ok && s != ""
}

func isArray(v interface{}) bool {
	_, ok := v.([]interface{})
	return ok
}

func cloneMap(m map[string]interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// extractOutputText is the best-effort extraction of the model-visible text
// from a tool_response, ported from audit.mjs's function of the same name.
// Shapes are undocumented, so it probes the known fields and falls back to a
// raw string output. Returns nil when no text could be found anywhere.
func extractOutputText(toolResponse interface{}, toolOutput string) *string {
	if s, ok := toolResponse.(string); ok {
		return &s
	}
	if m, ok := toolResponse.(map[string]interface{}); ok {
		if s, ok := m["stdout"].(string); ok && s != "" {
			return &s
		}
		if s, ok := m["content"].(string); ok && s != "" {
			return &s
		}
		if fm, ok := m["file"].(map[string]interface{}); ok {
			if s, ok := fm["content"].(string); ok {
				return &s
			}
		}
		if arr, ok := m["content"].([]interface{}); ok {
			var parts []string
			for _, x := range arr {
				if xm, ok := x.(map[string]interface{}); ok {
					if t, _ := xm["type"].(string); t == "text" {
						if txt, ok := xm["text"].(string); ok {
							parts = append(parts, txt)
						}
					}
				}
			}
			if joined := strings.Join(parts, "\n"); joined != "" {
				return &joined
			}
		}
		// Native Glob delivers its hits as a `filenames` string[] with no
		// stdout/content field. Join one-path-per-line so dlpRedactText can
		// act on it.
		if arr, ok := m["filenames"].([]interface{}); ok {
			var parts []string
			for _, x := range arr {
				if s, ok := x.(string); ok {
					parts = append(parts, s)
				}
			}
			if joined := strings.Join(parts, "\n"); joined != "" {
				return &joined
			}
		}
	}
	if toolOutput != "" {
		return &toolOutput
	}
	return nil
}

// compactJSON strips insignificant whitespace while preserving key order and
// value text exactly, standing in for JS's `JSON.stringify(JSON.parse(x))`
// round-trip without Go's map-marshal reordering keys alphabetically — which
// would silently break every fingerprint match against a flag guard.mjs
// wrote, since callFingerprint hashes this exact text.
func compactJSON(raw []byte) string {
	var buf bytes.Buffer
	if json.Compact(&buf, raw) != nil {
		return string(raw)
	}
	return buf.String()
}

// callFingerprint is a small stable string hash (FNV-1a, hex), duplicated
// from guard.mjs/audit.mjs's function of the same name: the two MUST produce
// the same value for the same tool_input text, since that is how a
// PostToolUse call is matched to the guard's deny flag. The loop is over
// UTF-16 code units, matching JS's charCodeAt, the same reason
// shared.ProjectKey does — see its comment.
func callFingerprint(s string) string {
	var h uint32 = 0x811c9dc5
	for _, u := range utf16.Encode([]rune(s)) {
		h ^= uint32(u)
		h = h + (h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)
	}
	const hexDigits = "0123456789abcdef"
	if h == 0 {
		return "0"
	}
	var out []byte
	for h > 0 {
		out = append([]byte{hexDigits[h&0xf]}, out...)
		h >>= 4
	}
	return string(out)
}