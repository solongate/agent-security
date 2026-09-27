package auditscan

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The collectors read what four AI clients have already written to disk and
// normalise it into one shape.
//
// Every one of them is defensive to the point of silence: a transcript line
// that will not parse, a directory that cannot be listed, a schema that drifted
// in the next release of the client — all of these skip the entry and keep
// going. The alternative is a tool that reports nothing at all because one of
// four clients changed a field name, and a security report that fails to appear
// is worse than one that is short.

// resultLimit and messageLimit are how much of a tool result and a user message
// are kept. The result cap is what keeps a session with a few megabyte file
// reads in it from making the whole scan quadratic.
const (
	resultLimit  = 2000
	messageLimit = 500
)

// ── shared plumbing ────────────────────────────────────────────────────────

// readJSONLObjects parses a JSONL file into its object lines. The second return
// distinguishes "the file could not be read" from "the file had nothing in it",
// because the first means the session is skipped entirely.
func readJSONLObjects(path string) ([]*Args, bool) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	lines := strings.Split(string(raw), "\n")
	out := make([]*Args, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		v, err := ParseArgsValue([]byte(line))
		if err != nil {
			continue
		}
		if obj, ok := v.(*Args); ok {
			out = append(out, obj)
		}
	}
	return out, true
}

// truthyStr is `entry.field || ”`: absent, null, false, 0 and "" all read as
// nothing, and anything else is rendered the way String() would render it.
func truthyStr(a *Args, key string) string {
	v, ok := a.Get(key)
	if !ok || !truthy(v) {
		return ""
	}
	return jsString(v)
}

func getObj(a *Args, key string) (*Args, bool) {
	v, ok := a.Get(key)
	if !ok {
		return nil, false
	}
	o, ok := v.(*Args)
	return o, ok
}

func getArr(a *Args, key string) ([]any, bool) {
	v, ok := a.Get(key)
	if !ok {
		return nil, false
	}
	arr, ok := v.([]any)
	return arr, ok
}

func getStr(a *Args, key string) (string, bool) { return a.str(key) }

func asObj(v any) (*Args, bool) {
	o, ok := v.(*Args)
	return o, ok
}

// correlateUserMessages points each user message at the first tool call that
// came after it. An unparseable timestamp leaves the message uncorrelated
// rather than pointing at the first call in the session, which is what
// comparing against a NaN does in the original.
func correlateUserMessages(msgs []UserMessage, calls []*ToolCall) {
	for i := range msgs {
		msgs[i].NextToolCallIndex = -1
		umTime, ok := parseMillis(msgs[i].Timestamp)
		if !ok {
			continue
		}
		for j, tc := range calls {
			t, ok := parseMillis(tc.Timestamp)
			if ok && t > umTime {
				msgs[i].NextToolCallIndex = j
				break
			}
		}
	}
}

func isDir(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func sessionIDFromFile(file, ext string) string {
	return strings.Replace(file, ext, "", 1)
}

// ── Claude Code ────────────────────────────────────────────────────────────
//
// ~/.claude/projects/<project-hash>/<session-id>.jsonl
// A tool call is a `tool_use` block inside a type:"assistant" line; its result
// is a `tool_result` block inside a type:"user" line, matched by tool_use_id.
// Claude puts genuine user messages in the same type:"user" lines — a string
// content is a person typing, an array is tool results.
func collectClaude() []*SessionInfo {
	var sessions []*SessionInfo
	claudeDir := filepath.Join(homeDir(), ".claude", "projects")
	if !exists(claudeDir) {
		return sessions
	}

	projects, err := os.ReadDir(claudeDir)
	if err != nil {
		return sessions
	}
	for _, p := range projects {
		projectPath := filepath.Join(claudeDir, p.Name())
		if !isDir(projectPath) {
			continue
		}
		files, err := os.ReadDir(projectPath)
		if err != nil {
			continue
		}
		for _, f := range files {
			if !strings.HasSuffix(f.Name(), ".jsonl") {
				continue
			}
			filePath := filepath.Join(projectPath, f.Name())
			sessionID := sessionIDFromFile(f.Name(), ".jsonl")

			entries, ok := readJSONLObjects(filePath)
			if !ok {
				continue
			}
			var toolCalls []*ToolCall
			var userMessages []UserMessage
			var startTime, endTime, model string

			for _, entry := range entries {
				ts := truthyStr(entry, "timestamp")
				if ts == "" {
					continue
				}
				if startTime == "" {
					startTime = ts
				}
				endTime = ts

				typ, _ := getStr(entry, "type")

				if typ == "assistant" {
					if msg, ok := getObj(entry, "message"); ok {
						if content, ok := getArr(msg, "content"); ok {
							for _, raw := range content {
								block, ok := asObj(raw)
								if !ok {
									continue
								}
								if bt, _ := getStr(block, "type"); bt != "tool_use" {
									continue
								}
								args, _ := getObj(block, "input")
								if args == nil {
									args = NewArgs()
								}
								toolCalls = append(toolCalls, &ToolCall{
									ID:        truthyStr(block, "id"),
									ToolName:  truthyStr(block, "name"),
									Arguments: args,
									Timestamp: ts,
									Source:    SourceClaude,
									SessionID: sessionID,
								})
							}
						}
						if m := truthyStr(msg, "model"); m != "" {
							model = m
						}
					}
				}

				if typ == "user" {
					msg, ok := getObj(entry, "message")
					if !ok {
						continue
					}
					if text, ok := getStr(msg, "content"); ok && text != "" {
						userMessages = append(userMessages, UserMessage{
							Timestamp: ts, Text: jsSliceHead(text, messageLimit),
						})
					}
					if content, ok := getArr(msg, "content"); ok {
						for _, raw := range content {
							block, ok := asObj(raw)
							if !ok {
								continue
							}
							if bt, _ := getStr(block, "type"); bt != "tool_result" {
								continue
							}
							useID := truthyStr(block, "tool_use_id")
							tc := findCallByID(toolCalls, useID)
							if tc == nil {
								continue
							}
							if s, ok := getStr(block, "content"); ok {
								tc.setResult(jsSliceHead(s, resultLimit))
							} else if arr, ok := getArr(block, "content"); ok {
								tc.setResult(jsSliceHead(joinTextBlocks(arr), resultLimit))
							}
							isErr, _ := block.Get("is_error")
							tc.setIsError(truthy(isErr))
						}
					}
				}
			}

			correlateUserMessages(userMessages, toolCalls)
			if len(toolCalls) > 0 {
				sessions = append(sessions, &SessionInfo{
					ID: sessionID, Source: SourceClaude, StartTime: startTime, EndTime: endTime,
					Model: model, ToolCalls: toolCalls, UserMessages: userMessages, FilePath: filePath,
				})
			}
		}
	}
	return sessions
}

func findCallByID(calls []*ToolCall, id string) *ToolCall {
	for _, tc := range calls {
		if tc.ID == id {
			return tc
		}
	}
	return nil
}

// joinTextBlocks is `content.map(c => c.text || ”).join('\n')`.
func joinTextBlocks(arr []any) string {
	parts := make([]string, 0, len(arr))
	for _, raw := range arr {
		if o, ok := asObj(raw); ok {
			parts = append(parts, truthyStr(o, "text"))
		} else {
			parts = append(parts, "")
		}
	}
	return strings.Join(parts, "\n")
}

// ── Antigravity CLI (`agy`) ────────────────────────────────────────────────
//
// ~/.gemini/antigravity/brain/<conversationId>/.system_generated/logs/transcript.jsonl
// Tool calls arrive nested under `toolCall` — the same shape the PreToolUse
// hook receives — or flat with type "tool_call".
//
// The exact transcript line schema has not been verified against a live agy
// session; the parsing stays defensive so a drift degrades to "no sessions"
// rather than a crash.
func collectAntigravity() []*SessionInfo {
	var sessions []*SessionInfo
	brainDir := filepath.Join(homeDir(), ".gemini", "antigravity", "brain")
	if !exists(brainDir) {
		return sessions
	}
	convs, err := os.ReadDir(brainDir)
	if err != nil {
		return sessions
	}

	for _, c := range convs {
		convPath := filepath.Join(brainDir, c.Name())
		if !isDir(convPath) {
			continue
		}
		transcript := filepath.Join(convPath, ".system_generated", "logs", "transcript.jsonl")
		if !exists(transcript) {
			continue
		}
		entries, ok := readJSONLObjects(transcript)
		if !ok {
			continue
		}

		var toolCalls []*ToolCall
		var userMessages []UserMessage
		var startTime, endTime, model string

		for _, entry := range entries {
			ts := firstNonEmpty(truthyStr(entry, "timestamp"), truthyStr(entry, "time"), truthyStr(entry, "ts"))
			if ts != "" {
				if startTime == "" {
					startTime = ts
				}
				endTime = ts
			}
			if model == "" {
				if m, ok := getStr(entry, "model"); ok {
					model = m
				}
			}

			entryType, _ := getStr(entry, "type")
			tcObj, hasTC := getObj(entry, "toolCall")
			if !hasTC && entryType == "tool_call" {
				tcObj, hasTC = entry, true
			}
			if hasTC && tcObj != nil {
				name := firstNonEmpty(truthyStr(tcObj, "name"), truthyStr(tcObj, "toolName"))
				if name != "" {
					id := truthyStr(tcObj, "id")
					if id == "" {
						if step, ok := entry.Get("stepIdx"); ok && step != nil {
							id = jsString(step)
						}
					}
					args, _ := getObj(tcObj, "args")
					if args == nil {
						args, _ = getObj(tcObj, "arguments")
					}
					if args == nil {
						args = NewArgs()
					}
					call := &ToolCall{
						ID: id, ToolName: name, Arguments: args, Timestamp: ts,
						Source: SourceAntigravity, SessionID: c.Name(),
					}
					if res, ok := entry.Get("result"); ok && truthy(res) {
						call.setResult(jsSliceHead(Stringify(res), resultLimit))
					}
					status, _ := getStr(entry, "status")
					isErrRaw, _ := entry.Get("isError")
					isErrBool, _ := isErrRaw.(bool)
					call.setIsError(status == "error" || isErrBool)
					toolCalls = append(toolCalls, call)
				}
			}

			role := entryType
			if r, ok := getStr(entry, "role"); ok {
				role = r
			}
			if role == "user" || role == "user_message" {
				text := ""
				if v, ok := entry.Get("text"); ok && truthy(v) {
					text = jsString(v)
				} else if v, ok := entry.Get("content"); ok && truthy(v) {
					text = jsString(v)
				}
				if text != "" {
					userMessages = append(userMessages, UserMessage{
						Timestamp: ts, Text: jsSliceHead(text, messageLimit),
					})
				}
			}
		}

		correlateUserMessages(userMessages, toolCalls)
		if len(toolCalls) > 0 {
			sessions = append(sessions, &SessionInfo{
				ID: c.Name(), Source: SourceAntigravity, StartTime: startTime, EndTime: endTime,
				Model: model, ToolCalls: toolCalls, UserMessages: userMessages, FilePath: transcript,
			})
		}
	}
	return sessions
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ── Codex CLI ──────────────────────────────────────────────────────────────
//
// $CODEX_HOME/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl, or ~/.codex.
// Lines are { timestamp, type, payload }; a "response_item" payload carries the
// model's own tagged item:
//
//	function_call        { name, arguments: "<json string>", call_id }
//	custom_tool_call     { name, input: "<raw text>", call_id }   (apply_patch)
//	function_call_output { call_id, output }
//	message              { role, content: [{ text }] }
func collectCodex() []*SessionInfo {
	var sessions []*SessionInfo
	root := filepath.Join(homeDir(), ".codex", "sessions")
	if home := os.Getenv("CODEX_HOME"); home != "" {
		root = filepath.Join(home, "sessions")
	}
	if !exists(root) {
		return sessions
	}

	// The date tree is year/month/day, so the walk is depth-bounded: a symlink
	// loop under ~/.codex must not turn a report into an infinite scan.
	var files []string
	var walk func(dir string, depth int)
	walk = func(dir string, depth int) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			if isDir(p) {
				if depth < 4 {
					walk(p, depth+1)
				}
				continue
			}
			if strings.HasSuffix(e.Name(), ".jsonl") {
				files = append(files, p)
			}
		}
	}
	walk(root, 0)

	for _, filePath := range files {
		entries, ok := readJSONLObjects(filePath)
		if !ok {
			continue
		}
		var toolCalls []*ToolCall
		var userMessages []UserMessage
		var startTime, endTime, model string
		sessionID := sessionIDFromFile(filepath.Base(filePath), ".jsonl")

		for _, entry := range entries {
			ts := truthyStr(entry, "timestamp")
			if ts != "" {
				if startTime == "" {
					startTime = ts
				}
				endTime = ts
			}
			typ, _ := getStr(entry, "type")

			if typ == "session_meta" {
				meta, ok := getObj(entry, "payload")
				if ok {
					if inner, ok := getObj(meta, "meta"); ok {
						meta = inner
					}
				}
				if meta != nil {
					if v, ok := meta.Get("id"); ok && truthy(v) {
						sessionID = jsString(v)
					}
					if v, ok := meta.Get("model"); ok && truthy(v) {
						model = jsString(v)
					}
				}
				continue
			}
			if typ == "turn_context" {
				if payload, ok := getObj(entry, "payload"); ok {
					if v, ok := payload.Get("model"); ok && truthy(v) && model == "" {
						model = jsString(v)
					}
				}
				continue
			}
			if typ != "response_item" {
				continue
			}
			item, ok := getObj(entry, "payload")
			if !ok {
				continue
			}
			itemType, _ := getStr(item, "type")

			if itemType == "function_call" || itemType == "custom_tool_call" || itemType == "local_shell_call" {
				args := codexArgs(item)
				name := truthyStr(item, "name")
				if name == "" && itemType == "local_shell_call" {
					name = "Bash"
				}
				id := truthyStr(item, "call_id")
				if id == "" {
					id = truthyStr(item, "id")
				}
				toolCalls = append(toolCalls, &ToolCall{
					ID: id, ToolName: name, Arguments: args, Timestamp: ts,
					Source: SourceCodex, SessionID: sessionID,
				})
				continue
			}

			if itemType == "function_call_output" || itemType == "custom_tool_call_output" {
				tc := findCallByID(toolCalls, truthyStr(item, "call_id"))
				if tc == nil {
					continue
				}
				out, hasOut := item.Get("output")
				text := ""
				if s, ok := out.(string); ok {
					text = s
				} else if o, ok := asObj(out); ok {
					if c, ok := getStr(o, "content"); ok {
						text = c
					} else {
						text = Stringify(out)
					}
				} else if hasOut && truthy(out) {
					text = Stringify(out)
				}
				clipped := jsSliceHead(text, resultLimit)
				tc.setResult(clipped)
				success := false
				if o, ok := asObj(out); ok {
					if v, ok := o.Get("success"); ok {
						if b, ok := v.(bool); ok && !b {
							success = true
						}
					}
				}
				tc.setIsError(success || strings.Contains(clipped, `"error"`))
				continue
			}

			if itemType == "message" {
				if role, _ := getStr(item, "role"); role == "user" {
					if content, ok := getArr(item, "content"); ok {
						text := strings.TrimSpace(joinTextBlocks(content))
						// Codex replays environment and context blocks as user
						// messages. They open with a tag, and counting them as
						// requests would make every agent action look solicited.
						if text != "" && !strings.HasPrefix(text, "<") {
							userMessages = append(userMessages, UserMessage{
								Timestamp: ts, Text: jsSliceHead(text, messageLimit),
							})
						}
					}
				}
			}
		}

		correlateUserMessages(userMessages, toolCalls)
		if len(toolCalls) > 0 {
			sessions = append(sessions, &SessionInfo{
				ID: sessionID, Source: SourceCodex, StartTime: startTime, EndTime: endTime,
				Model: model, ToolCalls: toolCalls, UserMessages: userMessages, FilePath: filePath,
			})
		}
	}
	return sessions
}

// codexArgs unpacks the four shapes a Codex call can carry its arguments in. A
// JSON-encoded argument string that will not parse is kept verbatim under
// `arguments` rather than dropped, because the raw text is still what the
// checks need to see.
func codexArgs(item *Args) *Args {
	if s, ok := getStr(item, "arguments"); ok {
		if v, err := ParseArgsValue([]byte(s)); err == nil {
			if o, ok := asObj(v); ok {
				return o
			}
		}
		a := NewArgs()
		a.Set("arguments", s)
		return a
	}
	if o, ok := getObj(item, "arguments"); ok {
		return o
	}
	if s, ok := getStr(item, "input"); ok {
		a := NewArgs()
		a.Set("command", s)
		return a
	}
	if o, ok := getObj(item, "action"); ok {
		return o
	}
	return NewArgs()
}

// ── OpenClaw ───────────────────────────────────────────────────────────────
//
// ~/.openclaw/agents/main/sessions/<session-id>.jsonl
func collectOpenClaw() []*SessionInfo {
	var sessions []*SessionInfo
	dir := filepath.Join(homeDir(), ".openclaw", "agents", "main", "sessions")
	if !exists(dir) {
		return sessions
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		return sessions
	}

	for _, f := range files {
		if !strings.HasSuffix(f.Name(), ".jsonl") {
			continue
		}
		filePath := filepath.Join(dir, f.Name())
		sessionID := sessionIDFromFile(f.Name(), ".jsonl")
		entries, ok := readJSONLObjects(filePath)
		if !ok {
			continue
		}

		var toolCalls []*ToolCall
		var userMessages []UserMessage
		var startTime, endTime, model string

		for _, entry := range entries {
			ts := truthyStr(entry, "timestamp")
			if ts == "" {
				continue
			}
			if startTime == "" {
				startTime = ts
			}
			endTime = ts

			typ, _ := getStr(entry, "type")
			if typ == "model_change" {
				model = truthyStr(entry, "modelId")
			}
			if typ != "message" {
				continue
			}
			msg, ok := getObj(entry, "message")
			if !ok {
				continue
			}
			role, _ := getStr(msg, "role")

			if role == "user" {
				if text, ok := getStr(msg, "content"); ok && text != "" {
					userMessages = append(userMessages, UserMessage{
						Timestamp: ts, Text: jsSliceHead(text, messageLimit),
					})
				}
			}

			if role == "assistant" {
				if content, ok := getArr(msg, "content"); ok {
					for _, raw := range content {
						block, ok := asObj(raw)
						if !ok {
							continue
						}
						bt, _ := getStr(block, "type")
						if bt != "toolCall" && bt != "tool_use" {
							continue
						}
						args, _ := getObj(block, "arguments")
						if args == nil {
							args, _ = getObj(block, "input")
						}
						if args == nil {
							args = NewArgs()
						}
						toolCalls = append(toolCalls, &ToolCall{
							ID:        truthyStr(block, "id"),
							ToolName:  truthyStr(block, "name"),
							Arguments: args,
							Timestamp: ts,
							Source:    SourceOpenClaw,
							SessionID: sessionID,
						})
					}
				}
			}

			if role == "toolResult" {
				tc := findCallByID(toolCalls, truthyStr(msg, "toolCallId"))
				if tc == nil {
					continue
				}
				if content, ok := getArr(msg, "content"); ok {
					tc.setResult(jsSliceHead(joinTextBlocks(content), resultLimit))
				}
				isErr, _ := msg.Get("isError")
				tc.setIsError(truthy(isErr))
			}
		}

		correlateUserMessages(userMessages, toolCalls)
		if len(toolCalls) > 0 {
			sessions = append(sessions, &SessionInfo{
				ID: sessionID, Source: SourceOpenClaw, StartTime: startTime, EndTime: endTime,
				Model: model, ToolCalls: toolCalls, UserMessages: userMessages, FilePath: filePath,
			})
		}
	}
	return sessions
}

// ── Custom directories ─────────────────────────────────────────────────────
//
// Whatever the user pointed --add-dir at. The format is sniffed rather than
// declared: a .jsonl file is tried as Claude and as OpenClaw, and a .json file
// as a generic { messages: [{ toolCalls: [...] }] } session.
func collectCustomDirs() []*SessionInfo {
	var sessions []*SessionInfo
	cfg := LoadConfig()

	for _, dir := range cfg.CustomDirs {
		if !exists(dir) {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			filePath := filepath.Join(dir, e.Name())
			info, err := os.Stat(filePath)
			if err != nil || info.IsDir() {
				continue
			}

			if strings.HasSuffix(e.Name(), ".jsonl") {
				if s := collectCustomJSONL(filePath, sessionIDFromFile(e.Name(), ".jsonl")); s != nil {
					sessions = append(sessions, s)
				}
			}
			if strings.HasSuffix(e.Name(), ".json") {
				if s := collectCustomJSON(filePath, sessionIDFromFile(e.Name(), ".json")); s != nil {
					sessions = append(sessions, s)
				}
			}
		}
	}
	return sessions
}

func collectCustomJSONL(filePath, sessionID string) *SessionInfo {
	lines, ok := readJSONLObjects(filePath)
	if !ok {
		return nil
	}
	var toolCalls []*ToolCall
	var startTime, endTime, model string

	for _, entry := range lines {
		ts := truthyStr(entry, "timestamp")
		if ts == "" {
			continue
		}
		if startTime == "" {
			startTime = ts
		}
		endTime = ts

		typ, _ := getStr(entry, "type")
		if typ == "model_change" {
			model = truthyStr(entry, "modelId")
		}

		if typ == "assistant" {
			if msg, ok := getObj(entry, "message"); ok {
				if content, ok := getArr(msg, "content"); ok {
					for _, raw := range content {
						block, ok := asObj(raw)
						if !ok {
							continue
						}
						if bt, _ := getStr(block, "type"); bt != "tool_use" {
							continue
						}
						args, _ := getObj(block, "input")
						if args == nil {
							args = NewArgs()
						}
						toolCalls = append(toolCalls, &ToolCall{
							ID: truthyStr(block, "id"), ToolName: truthyStr(block, "name"),
							Arguments: args, Timestamp: ts, Source: SourceClaude, SessionID: sessionID,
						})
					}
				}
				if m := truthyStr(msg, "model"); m != "" {
					model = m
				}
			}
		}

		if typ == "message" {
			msg, ok := getObj(entry, "message")
			if !ok {
				continue
			}
			role, _ := getStr(msg, "role")
			if role == "assistant" {
				if content, ok := getArr(msg, "content"); ok {
					for _, raw := range content {
						block, ok := asObj(raw)
						if !ok {
							continue
						}
						bt, _ := getStr(block, "type")
						if bt != "toolCall" && bt != "tool_use" {
							continue
						}
						args, _ := getObj(block, "arguments")
						if args == nil {
							args, _ = getObj(block, "input")
						}
						if args == nil {
							args = NewArgs()
						}
						toolCalls = append(toolCalls, &ToolCall{
							ID: truthyStr(block, "id"), ToolName: truthyStr(block, "name"),
							Arguments: args, Timestamp: ts, Source: SourceOpenClaw, SessionID: sessionID,
						})
					}
				}
			}
			if role == "toolResult" {
				if tc := findCallByID(toolCalls, truthyStr(msg, "toolCallId")); tc != nil {
					if content, ok := getArr(msg, "content"); ok {
						tc.setResult(jsSliceHead(joinTextBlocks(content), resultLimit))
					}
					isErr, _ := msg.Get("isError")
					tc.setIsError(truthy(isErr))
				}
			}
		}

		if typ == "user" {
			if msg, ok := getObj(entry, "message"); ok {
				if content, ok := getArr(msg, "content"); ok {
					for _, raw := range content {
						block, ok := asObj(raw)
						if !ok {
							continue
						}
						if bt, _ := getStr(block, "type"); bt != "tool_result" {
							continue
						}
						tc := findCallByID(toolCalls, truthyStr(block, "tool_use_id"))
						if tc == nil {
							continue
						}
						if s, ok := getStr(block, "content"); ok {
							tc.setResult(jsSliceHead(s, resultLimit))
						} else if arr, ok := getArr(block, "content"); ok {
							tc.setResult(jsSliceHead(joinTextBlocks(arr), resultLimit))
						} else {
							tc.Result = nil
						}
						isErr, _ := block.Get("is_error")
						tc.setIsError(truthy(isErr))
					}
				}
			}
		}
	}

	if len(toolCalls) == 0 {
		return nil
	}
	return &SessionInfo{
		ID: sessionID, Source: toolCalls[0].Source, StartTime: startTime, EndTime: endTime,
		Model: model, ToolCalls: toolCalls, FilePath: filePath,
	}
}

func collectCustomJSON(filePath, fallbackID string) *SessionInfo {
	raw, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}
	v, err := ParseArgsValue(raw)
	if err != nil {
		return nil
	}
	data, ok := asObj(v)
	if !ok {
		return nil
	}
	messages, ok := getArr(data, "messages")
	if !ok {
		return nil
	}

	sessionID := fallbackID
	if s := truthyStr(data, "sessionId"); s != "" {
		sessionID = s
	}

	var toolCalls []*ToolCall
	for _, rawMsg := range messages {
		msg, ok := asObj(rawMsg)
		if !ok {
			continue
		}
		calls, ok := getArr(msg, "toolCalls")
		if !ok {
			continue
		}
		for _, rawCall := range calls {
			call, ok := asObj(rawCall)
			if !ok {
				continue
			}
			args, _ := getObj(call, "args")
			if args == nil {
				args, _ = getObj(call, "arguments")
			}
			if args == nil {
				args = NewArgs()
			}
			ts := firstNonEmpty(truthyStr(call, "timestamp"), truthyStr(msg, "timestamp"), truthyStr(data, "startTime"))
			tc := &ToolCall{
				ID: truthyStr(call, "id"), ToolName: truthyStr(call, "name"), Arguments: args,
				Timestamp: ts, Source: SourceAntigravity, SessionID: sessionID,
			}
			if res, ok := call.Get("result"); ok && truthy(res) {
				tc.setResult(jsSliceHead(Stringify(res), resultLimit))
			}
			status, _ := getStr(call, "status")
			tc.setIsError(status == "error")
			toolCalls = append(toolCalls, tc)
		}
	}

	if len(toolCalls) == 0 {
		return nil
	}
	model := ""
	if len(messages) > 0 {
		if first, ok := asObj(messages[0]); ok {
			model = truthyStr(first, "model")
		}
	}
	return &SessionInfo{
		ID: sessionID, Source: SourceAntigravity,
		StartTime: truthyStr(data, "startTime"), EndTime: truthyStr(data, "lastUpdated"),
		Model: model, ToolCalls: toolCalls, FilePath: filePath,
	}
}

// ── Entry point ────────────────────────────────────────────────────────────

// CollectLogs reads every source and merges them into one chronological view.
//
// The merge sorts by start time with a STABLE sort, so two sessions that
// started in the same second stay in collector order rather than shuffling
// between runs — a report whose rows move for no reason reads as activity.
func CollectLogs() *AuditData {
	claude := collectClaude()
	codex := collectCodex()
	antigravity := collectAntigravity()
	openclaw := collectOpenClaw()
	custom := collectCustomDirs()

	sessions := make([]*SessionInfo, 0,
		len(claude)+len(codex)+len(antigravity)+len(openclaw)+len(custom))
	sessions = append(sessions, claude...)
	sessions = append(sessions, codex...)
	sessions = append(sessions, antigravity...)
	sessions = append(sessions, openclaw...)
	sessions = append(sessions, custom...)

	sort.SliceStable(sessions, func(i, j int) bool {
		return sessions[i].StartTime < sessions[j].StartTime
	})

	sources := []string{}
	if len(claude) > 0 {
		sources = append(sources, "Claude Code")
	}
	if len(codex) > 0 {
		sources = append(sources, "Codex")
	}
	if len(antigravity) > 0 {
		sources = append(sources, "Antigravity")
	}
	if len(openclaw) > 0 {
		sources = append(sources, "OpenClaw")
	}

	total := 0
	var stamps []string
	for _, s := range sessions {
		total += len(s.ToolCalls)
		for _, tc := range s.ToolCalls {
			if tc.Timestamp != "" {
				stamps = append(stamps, tc.Timestamp)
			}
		}
	}
	sort.Strings(stamps)

	data := &AuditData{Sessions: sessions, TotalToolCalls: total, Sources: sources}
	if len(stamps) > 0 {
		data.TimeRange = &TimeRange{From: stamps[0], To: stamps[len(stamps)-1]}
	}
	return data
}
