package main

// ── Client adapters ────────────────────────────────────────────────────────
// The ONLY client-aware code in this hook. Everything between the two ends
// reasons over two VENDOR-NEUTRAL shapes that belong to SolonGate, not to any
// one client:
//
//	CALL     { client, tool, args, command, cwd, sessionId, response, raw }
//	DECISION { type: deny | allow | rewrite, reason, patch, stealth }
//
// Each adapter translates one client BOTH ways: Parse maps that client's raw
// payload onto CALL, Emit maps DECISION onto that client's wire format and
// returns the process exit code. No layer outside this block may branch on the
// client. Adding a client = adding one entry here.
//
// `stealth` on a deny means: emit the reason verbatim, with no SolonGate
// branding, so a hidden path looks like it simply does not exist.
//
// Emit RETURNS the exit code rather than calling os.Exit, so main() keeps
// control of process teardown (the Node original had to set process.exitCode
// and unwind for the same reason: exiting inside a settling fetch on Windows
// replaced exit code 2 with an abort, and Claude Code then ran the tool).

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"

	"github.com/codeyevsky/solongate/sgpolicy"
	"github.com/codeyevsky/solongate/sgshared"
)

// DECISION. Type is one of "deny", "allow", "rewrite".
type decision struct {
	Type    string
	Reason  string
	Patch   map[string]interface{}
	Stealth bool
}

// What an adapter's Parse produces: the client-specific half of CALL, before
// the client-agnostic enrichment normalizeToolCall applies on top.
type parsedPayload struct {
	Tool      string
	Args      map[string]interface{}
	Command   string
	Cwd       string
	SessionID string
	Response  map[string]interface{}
}

// neutralCall is the CALL every layer below the translator reasons over. It
// embeds the `call` struct main.go already hands to record() and the policy
// input builder, so the wider contract rides alongside without a second copy of
// the fields the rest of the port reads (pass `nc.call` to those functions).
type neutralCall struct {
	call
	// The client's own tool name is in call.Tool, kept verbatim for logs and
	// audit. Layers must NOT branch on it: clients name the same capability
	// differently (Bash / run_command / shell). Permission is the neutral
	// classification they branch on instead.
	Client     string
	Permission string
	Response   map[string]interface{}
	// The payload exactly as it arrived. Bytes rather than the Node original's
	// parsed object: nothing downstream reads individual fields off it, and
	// keeping the bytes means a re-read can still see key order.
	Raw []byte
}

// `RedactsOutput` is a CAPABILITY, not an identity: true means this client has a
// post-tool stage that can rewrite what the tool returned, so a secret inside a
// file the agent reads gets masked there. False means masking has to happen
// before the tool runs (redact into a temp copy, point the read at it) and any
// masking we cannot apply becomes a block. Layers ask about the capability,
// never about which client is running.
type Client struct {
	Parse         func(raw []byte) parsedPayload
	Emit          func(d decision) int
	RedactsOutput bool

	// ReportsAfter is whether the client runs a POST-tool stage at all, which is
	// what files the audit row for a call that was ALLOWED. False means the only
	// records this client ever produces are the ones the guard writes itself —
	// so anything meant to be OBSERVED rather than blocked has to be recorded
	// here, or it is not recorded anywhere.
	ReportsAfter bool
}

var clients = map[string]*Client{
	"claude-code": {
		Parse:         parseFlatPayload,
		Emit:          emitHookSpecific,
		ReportsAfter:  true,
		RedactsOutput: true, // audit.mjs rewrites the tool result at PostToolUse
	},

	// Codex CLI: same decision dialect as Claude Code, different INPUT problem.
	// Every file edit arrives as one apply_patch call whose target paths live
	// inside the patch text, so parse lifts them onto the neutral fields (see
	// liftFreeformPatchPaths, applied to every client for safety).
	"codex": {
		Parse:         parseFlatPayload,
		Emit:          emitHookSpecific,
		ReportsAfter:  true,
		RedactsOutput: false, // has a post-tool stage, but it rejects output rewrites
	},

	// OpenCode: no subprocess hook contract at all — a plugin runs in-process and
	// refuses a call by throwing. The shim that does the throwing (see
	// hooks/opencode-plugin.mjs) spawns this guard with a flat Claude-shaped
	// payload and reads the Claude dialect back, so both halves are reused as-is
	// and only the identity differs.
	"opencode": {
		Parse: parseFlatPayload,
		Emit:  emitHookSpecific,
		// tool.execute.after does hand the plugin the tool's result, but whether
		// writing to it changes what the model sees is untested. Claiming the
		// capability we have not proven would let a secret through masked-in-name-
		// only; false makes any masking we cannot apply a block instead.
		ReportsAfter:  true, // tool.execute.after does run, and it runs the audit hook
		RedactsOutput: false,
	},

	// Antigravity CLI: nested payload, and a decision dialect of its own.
	"antigravity": {
		Parse:         parseAntigravity,
		Emit:          emitAntigravity,
		ReportsAfter:  false,
		RedactsOutput: false, // no post-tool stage at all (its output is ignored)
	},

	// Unknown client: never silently adopt another client's rules. Parse by
	// payload SHAPE and deny with the most widely enforced signal available
	// (JSON + exit 2). A client that needs anything else gets its own entry.
	"generic": {
		Parse:         parseGeneric,
		Emit:          emitHookSpecific,
		ReportsAfter:  false, // and record from here rather than assume something else will
		RedactsOutput: false, // assume the weaker capability, so masking fails closed
	},
}

func clientFor(agentType string) *Client {
	if c, ok := clients[agentType]; ok {
		return c
	}
	return clients["generic"]
}

// ── Payload field access ───────────────────────────────────────────────────
// The adapters read fields the way the Node original does — `a || b || c` over
// alternative spellings — which needs JS truthiness and the raw bytes, not a
// struct. A struct would also lose the argument object's KEY ORDER, and
// neutralizeArgs resolves alias collisions (`command` vs `cmd`) in that order.

// rawFields decodes one JSON object one level deep. A payload that is not an
// object at all yields an empty map rather than an error: a malformed payload
// must reach a decision, not a panic, and 2 is the deny signal.
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

// jsOrRaw is JavaScript's `raw.a || raw.b || raw.c`, returning the winner
// undecoded so key order survives. An empty object is TRUTHY in JS and has to
// win over the next candidate: a client that sends `tool_input: {}` alongside a
// stale `params` is saying this call has no arguments.
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
		if sgpolicy.JSTruthy(probe) {
			return v
		}
	}
	return nil
}

// Same chain, for the scalar fields. A non-string winner still ENDS the chain,
// as it would in JS, and is stringified the way it would be once it reached the
// audit entry.
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
		if !sgpolicy.JSTruthy(probe) {
			continue
		}
		return sgpolicy.JSToString(probe)
	}
	return ""
}

// isJSONish reports whether a field is `typeof x === 'object'` with x non-null:
// the shape test the generic adapter routes on. Arrays count, because they do in
// JS, and routing a payload the same way the Node hook routes it matters more
// here than the array being useless once it arrives.
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

// dropArgKeys exists because the ported neutralizeArgs has no `drop` parameter
// and main.go owns it. Dropping BEFORE the call is equivalent: the original
// skips a dropped key before any aliasing happens. The key order slice is
// filtered too, or a dropped key would still hold its slot.
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

// ── The Anthropic dialect (Claude Code, Codex, the OpenCode shim) ──────────
// Two clients happen to share Anthropic's PreToolUse wire format. That is a fact
// about those two clients, not a canonical format — the neutral CALL/DECISION
// shapes above are the canonical ones. These helpers exist so the shared dialect
// is written once.

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

// Codex's decision struct is deny_unknown_fields: ONE extra key and the whole
// decision is discarded and the tool runs. Deny and rewrite therefore get
// separate shapes rather than one struct with omitempty — `updatedInput` must
// be absent from a deny, and must still be written on a rewrite even when the
// patch is empty, because Codex rejects a bare allow as unsupported.
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

// Exit 2 is what actually enforces a block: JSON + exit 0 goes through the
// normal permission flow, which AUTO-ACCEPT overrides (observed: a DLP-blocked
// Write still landed on disk in auto mode). Exit 2 hard-blocks before the
// permission system, in every mode. The JSON stays as the Windows/PowerShell
// fallback, where a native exit code may not propagate reliably. Codex reads
// the stderr text at exit 2 and ignores stdout, so both halves serve it too.
func emitHookSpecific(d decision) int {
	switch d.Type {
	case "deny":
		msg := d.Reason
		if !d.Stealth && msg == "" {
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
		// stderr is the half Codex reads, and the half that survives a client
		// that never parses stdout. It is written even if the marshal failed.
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
	return 0 // allow: silence is consent in this dialect
}

// ── The Antigravity dialect ────────────────────────────────────────────────

func parseAntigravity(raw []byte) parsedPayload {
	f := rawFields(raw)
	tc := rawFields(f["toolCall"])
	a, order := decodeObject(tc["args"])
	// Cwd is dropped from args on purpose: it is the environment the call runs
	// in, not something the call acts on, and it is lifted to call.cwd below.
	// Leaving it in made the working directory look like an access target.
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
	// `raw.tool_name || tc.name`: the flat field wins where a client sends both.
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

// Unknown client: parse by payload SHAPE. A nested toolCall is the Antigravity
// dialect; anything else is read flat. The alternative — assuming one client's
// rules for an unknown one — is how a payload gets read with the wrong field
// names and the guard sees an empty call it has nothing to block.
func parseGeneric(raw []byte) parsedPayload {
	if isJSONish(rawFields(raw)["toolCall"]) {
		return parseAntigravity(raw)
	}
	return parseFlatPayload(raw)
}

// decodeArray is decodeObject's counterpart for `Array.isArray(x)`. A non-array
// reports false rather than yielding a zero-length slice, so the caller can tell
// "absent" from "empty" the way the original's chain does.
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

// hooks.md contract is { decision, reason }; the older Go binary reads
// { allow_tool, deny_reason }. Writing both makes the block land on whichever
// build is running. The field names are load-bearing: {"decision":"deny"} alone
// is Antigravity's *Stop* hook schema, not the tool gate, and agy silently runs
// the tool when sent only that (verified in the agy 1.1.5 binary: AllowTool bool
// / DenyReason string).
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
		msg := d.Reason
		if !d.Stealth {
			msg = "[SolonGate] " + d.Reason
		}
		// Exit 0: agy reads the JSON, not the code. Returning 2 here would be a
		// hook FAILURE to agy, and a failed hook does not block.
		writeJSON(agyDeny{Decision: "deny", Reason: msg, AllowTool: false, DenyReason: msg})
		return 0
	case "rewrite":
		// `overwrite` is shallow-merged into the tool args before it runs, so
		// the rewritten call is the one that executes. Shell text rides in
		// CommandLine, which is where this client keeps a command.
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

// A decision that cannot be serialised must not become a silent allow-shaped
// empty stdout, so the write is attempted and the failure left visible on
// stderr rather than swallowed.
func writeJSON(v interface{}) {
	out, err := json.Marshal(v)
	if err != nil {
		os.Stderr.WriteString("[SolonGate] decision could not be encoded\n")
		return
	}
	os.Stdout.Write(out)
}

// ── Translator (input side) ────────────────────────────────────────────────
// Normalize ANY client's raw hook payload into ONE canonical shape the whole
// guard reasons over: Claude's flat {tool_name,tool_input,session_id,cwd} and
// Antigravity's nested {toolCall:{name,args:{CommandLine,Cwd}},conversationId,
// workspacePaths} come out identical here. EVERY tool call passes through this
// before any check runs; the decision is emitted back per-client by Client.Emit
// above (the output side of the translator). New client = extend only these two
// ends — the checks in between never see client-specific shapes.

// Codex sends every file edit as ONE tool call: tool_name "apply_patch" with
// tool_input { command: "*** Begin Patch\n*** Update File: src/a.ts\n…" }. The
// target paths live INSIDE that patch text, so without this every path-scoped
// rule (policy DENY, tamper, ghost, DLP) would see no path at all and a Codex
// edit to a protected file would sail through.

// The set is exactly JavaScript's \s. Go's own \s is [\t\n\f\r ] and
// unicode.IsSpace is the wrong set in the other direction (it includes U+0085,
// which JS does not, and omits U+FEFF, which JS has). Both differences land on
// the TRIM of a patch target: `.env ` left untrimmed matches no rule that
// `.env` matches, which is a bypass, and `.env` trimmed where the original
// keeps it is a divergence in the other direction.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ',
		0x00a0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

// Same set as isJSSpace, as a character class. Keep the two in step.
const jsSpaceClass = `[\t\n\v\f\r \x{00a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]`

var (
	// Anchored per LINE by splitting first rather than by (?m): Go's (?m)$
	// matches only before \n, while the original's /m also breaks on \r, U+2028
	// and U+2029, so a CR-only or U+2028-separated patch would have folded into
	// one unmatchable line here.
	reApplyPatchFile = regexp.MustCompile(`^\*\*\*` + jsSpaceClass + `+(?:Add|Update|Delete)` + jsSpaceClass + `+File:(.*)$`)
	// `*** Move to: <path>` renames the file named by the preceding Update File.
	reApplyPatchMove = regexp.MustCompile(`^\*\*\*` + jsSpaceClass + `+Move` + jsSpaceClass + `+to:(.*)$`)
)

// splitJSLines cuts on every terminator JavaScript's /m treats as a line break.
// A \r\n pair becomes an empty line, which matches nothing and costs nothing.
func splitJSLines(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == '\n' || r == '\r' || r == 0x2028 || r == 0x2029
	})
}

// patchTarget is the original's `\s*(.+?)\s*$` capture, trimming included.
//
// The odd case is deliberate: for a header whose path is ONLY whitespace, that
// pattern still has to capture one character, so it backtracks and yields the
// last whitespace character rather than nothing. Reproduced rather than tidied
// away because the number of targets decides whether liftFreeformPatchPaths
// rewrites args at all.
func patchTarget(rest string) string {
	if t := strings.TrimFunc(rest, isJSSpace); t != "" {
		return t
	}
	r := []rune(rest)
	if len(r) == 0 {
		return "" // `(.+?)` needs a character: the header line does not match
	}
	return string(r[len(r)-1])
}

func applyPatchTargets(patch string) []string {
	out := []string{}
	if !strings.Contains(patch, "*** ") {
		return out
	}
	lines := splitJSLines(patch)
	// Two passes, in the original's order: every Add/Update/Delete target first,
	// then every Move target. Interleaving them per line would be tidier and
	// would change targets[0], which becomes file_path.
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

// Some clients hide their real targets inside free text instead of putting them
// in an argument. Codex does this with apply_patch: one call, every touched path
// living inside the patch body. Keyed on the patch TEXT as well as the tool
// name, so this runs for any client that adopts the same format. Without it, no
// path-scoped layer (policy, tamper, ghost, DLP) sees a path at all and an edit
// to a protected file passes unexamined. The body is left intact so DLP can
// still scan what is about to be written.
//
// Lifted into the canonical fields the rest of the guard already reads:
// file_path (first target) and an edits[] array of {file_path}.
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
	if !sgpolicy.JSTruthy(args["file_path"]) {
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

// Translator, input side. Hands the raw payload to the adapter for whichever
// client is running, then applies the client-agnostic enrichment above. Returns
// the neutral CALL every layer below reasons over. Nothing past this point knows
// which client sent the call.
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
			// The call's identity, read from the RAW payload pre-normalization so
			// it matches what the PostToolUse audit hook will see for the same
			// call. tool_use_id is exact on clients that send it (Codex always
			// does); a client that sends none falls back to the tool+time match in
			// audit.mjs.
			CallID: jsOrString(rawFields(raw), "tool_use_id", "toolUseId", "tool_call_id"),
		},
		Client:     agentType,
		Permission: sgshared.GuessPermission(parsed.Tool),
		Response:   response,
		Raw:        raw,
	}
	liftFreeformPatchPaths(&c)
	return c
}
