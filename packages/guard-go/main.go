// SPDX-License-Identifier: Apache-2.0

// SolonGate guard — the decision path, in Go.
//
// Same contract as the Node hook it is replacing, deliberately: the client
// spawns it, writes one JSON payload on stdin, and reads the verdict from the
// exit code. Exit 2 with the reason on stderr blocks; exit 0 allows. That is
// what lets both implementations be installed side by side and checked against
// the same conformance suite (packages/proxy/test) rather than against each
// other's internals.
//
// What this port is FOR is the per-call cost. The Node hook pays ~26ms starting
// a runtime, ~17ms parsing a 291KB bundle and ~27ms instantiating an OPA WASM
// module it then throws away — measured, per tool call. Embedded OPA here
// prepares a policy in 640µs and decides in 14µs.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/sgpolicy"
	"github.com/codeyevsky/solongate/sgshared"
)

type call struct {
	Tool      string
	Args      map[string]interface{}
	Command   string
	Cwd       string
	SessionID string
	CallID    string
}

// Argument KEYS are part of a client's dialect too. Translating only the
// envelope leaves vendor names sitting inside the arguments, and then every
// layer downstream is back to reasoning about client-specific shapes: a rule
// written against `file_path` would miss a Codex `target_file` or an
// Antigravity `absolutePath`, and `readReferencedFiles` — which looks the
// `command` field up by name — would never see a `commandLine`.
//
// Unrecognised keys pass through untouched: they may still carry a path or a
// secret, and the scanners have to keep seeing them.
var argAliases = map[string]string{
	"commandline":   "command",
	"cmd":           "command",
	"absolutepath":  "file_path",
	"targetfile":    "file_path",
	"filepath":      "file_path",
	"target_file":   "file_path",
	"notebook_path": "file_path",
}

// neutralizeArgs renames aliased keys, keeping the FIRST value for each neutral
// name. First means first in the payload, which is why the key order is read
// off the raw JSON rather than off a Go map: map iteration is randomised, so a
// payload carrying both `command` and `cmd` would otherwise resolve to a
// different one run to run.
// argOriginals maps a NEUTRAL argument name back to the name the client used,
// for the keys neutralizeArgs renamed. Package-level for the same reason
// activeClient is: one process handles one call.
var argOriginals = map[string]string{}

func neutralizeArgs(args map[string]interface{}, order []string) map[string]interface{} {
	if len(order) == 0 {
		order = sgpolicy.SortedKeys(args)
	}
	out := make(map[string]interface{}, len(args))
	for _, k := range order {
		v, ok := args[k]
		if !ok {
			continue
		}
		nk := k
		if alias, has := argAliases[strings.ToLower(k)]; has {
			nk = alias
		}
		if _, exists := out[nk]; !exists {
			out[nk] = v
			if nk != k {
				// First one wins here too: the winning value and the name it is
				// written back under have to be the same argument.
				argOriginals[nk] = k
			}
		}
	}
	return out
}

// decodeObject returns a JSON object both as a map and as its keys in source
// order, which json.Unmarshal alone throws away.
func decodeObject(raw json.RawMessage) (map[string]interface{}, []string) {
	m := map[string]interface{}{}
	if len(raw) == 0 {
		return m, nil
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return map[string]interface{}{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return m, nil
	}
	var order []string
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			break
		}
		k, ok := kt.(string)
		if !ok {
			break
		}
		order = append(order, k)
		var skip interface{}
		if err := dec.Decode(&skip); err != nil {
			break
		}
	}
	return m, order
}

// Which client is running, and therefore how a verdict is spelled. Set once in
// main() from argv; the generic adapter until then, so a decision reached before
// that point is still emitted in the most widely enforced form rather than not
// at all.
//
// No layer below this line may branch on the client. They call deny/allow/
// rewriteCall and the adapter turns that into the client's wire format, which is
// the whole reason the adapter table exists: adding a client is one entry there,
// not a condition threaded through the decision path.
var activeClient = clients["generic"]

func emit(d decision) { os.Exit(activeClient.Emit(d)) }

func deny(reason string) { emit(decision{Type: "deny", Reason: reason}) }

// Allow the call but REPLACE its input, so a read is pointed at a redacted copy
// before the tool runs. The rewritten call is what executes, so no block is
// needed — which is the whole point for DLP: the agent gets an answer, without
// the secret in it.
func rewriteCall(patch map[string]interface{}) {
	emit(decision{Type: "rewrite", Patch: clientArgNames(patch)})
}

// clientArgNames turns the guard's neutral argument names back into the ones the
// client actually sent.
//
// A rewrite is SHALLOW-MERGED into the call's own arguments by the client, so a
// patch keyed `file_path` adds a new argument beside the `AbsolutePath` the
// client is really going to read. The call then runs against the original file
// and the rewrite does nothing at all — silently, because from the guard's side
// it looks like it worked.
//
// For the DLP read-redaction path that is the worst failure this binary has: it
// only runs on clients that CANNOT mask tool output, so the rewrite is the only
// thing standing between the agent and the secret. Antigravity (AbsolutePath)
// and OpenCode (filePath) are both in that group. Only `command` was ever
// translated back, which is why a rewrite of that key worked and a rewrite of
// either of these did not.
func clientArgNames(patch map[string]interface{}) map[string]interface{} {
	if len(patch) == 0 || len(argOriginals) == 0 {
		return patch
	}
	out := make(map[string]interface{}, len(patch))
	for k, v := range patch {
		if orig, ok := argOriginals[k]; ok {
			out[orig] = v
			continue
		}
		out[k] = v
	}
	return out
}

func allow() { emit(decision{Type: "allow"}) }

// observingDLP is the config of a mode that WATCHES rather than refuses, and
// which of the two it is.
//
// Block is handled before this is ever reached, so only detect and redact get
// here. Returning the name alongside the config keeps the recorded reason
// honest: "DLP is in detect mode" and "DLP is in redact mode" are different
// sentences about different outcomes, and one of them used to be printed for
// both.
type observingCfg struct {
	cfg  *sgshared.DLPConfig
	mode string
}

func observingDLP(sec *sgshared.Security) *observingCfg {
	if sec == nil {
		return nil
	}
	if sec.DLPRedact != nil {
		return &observingCfg{cfg: sec.DLPRedact, mode: "redact"}
	}
	if sec.DLPObserve != nil {
		return &observingCfg{cfg: sec.DLPObserve, mode: "detect"}
	}
	return nil
}

// hookVersion is the HOOK_VERSION from packages/proxy/hooks/guard.mjs that this
// binary implements. It is what `--sg-version` prints and what the hook compares
// itself against before handing a call over.
//
// It is NOT the npm version, and the difference is the entire point. The Node
// hook self-updates from the cloud on its own schedule while the binary only
// moves when npm moves it, so the two CAN diverge on a running machine — and
// when they do, the decision logic is what diverged. HOOK_VERSION bumps on every
// guard.mjs change, so comparing it answers the question that actually matters:
// "does this binary decide the way the hook next to it would?" An npm version
// would answer a different question and get this one wrong in both directions —
// falling back for a release that changed nothing here, and staying on the fast
// path after a cloud self-update that changed everything.
//
// TestHookVersionMatchesTheNodeHook reads the number out of guard.mjs, so this
// cannot drift without the build saying so.
const hookVersion = 107

// Stamped at build time: -ldflags "-X main.buildVersion=<npm version>". Printed
// by --sg-build. Diagnostic only: nothing decides anything on it.
var buildVersion = "dev"

func main() {
	// Started before anything else, INCLUDING the read of stdin, because the
	// call was already being charged for this hook long before this process
	// existed. See hookStart.
	started := hookStart()

	// How the hook decides whether this binary is the one it expects. Cheap on
	// purpose: it runs before any client is told the binary can be trusted, and
	// it is on the critical path of every tool call that takes the fast route.
	if len(os.Args) > 1 && os.Args[1] == "--sg-version" {
		fmt.Println(hookVersion)
		return
	}
	// The npm version, for humans reading a bug report. Separate flag because
	// nothing may accidentally compare against it.
	if len(os.Args) > 1 && os.Args[1] == "--sg-build" {
		fmt.Println(buildVersion)
		return
	}

	agentType := "claude-code"
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "--") {
		agentType = os.Args[1]
	}
	agentName := agentType
	if len(os.Args) > 2 && !strings.HasPrefix(os.Args[2], "--") {
		agentName = os.Args[2]
	}
	// THE FLEET MARKER IS GONE, and it was not merely dead.
	//
	// ~/.solongate/.fleet.json said whether this machine was under somebody else's
	// policy: a guest whose key opened their HOST's project, where the host wrote one
	// policy and every machine enforced it. The file was the last answer a policy poll
	// gave, kept separately because the guard needs it before it decides which
	// credential to trust.
	//
	// Nothing polls, so nothing writes it. What it still did was read — and on a machine
	// left with a stale `managed: true` from an older install, THIS GUARD ENFORCED
	// NOTHING: loadLocalPolicyFile returned nil for a managed machine, which is every
	// policy file including this machine's own. The Node hook never read the file at
	// all, so the same machine was guarded or unguarded depending only on whether it had
	// the binary.
	//
	// SOLONGATE_AGENT_ID names the rate-limit counter, and is honoured: it is for
	// running two clients side by side without them sharing a bucket. The managed case
	// withheld it because a guest could otherwise mint a fresh empty counter on demand.
	agentID := agentType
	if v := os.Getenv("SOLONGATE_AGENT_ID"); v != "" {
		agentID = v
	}

	input, _ := io.ReadAll(os.Stdin)

	// THERE IS NO CREDENTIAL HERE AT ALL, and its absence is the point.
	//
	// This used to be `if cred.APIKey == "" { allow() }` — the key was the whole
	// test, on the reasoning that the key selects the project and therefore the
	// policy. That holds for a machine with a service to ask. It makes the guard
	// a NO-OP on every machine that has none, which is how this is ordinarily
	// run: the policy is a file, and it was never read.
	//
	// Nothing needs allowing early for that case. With no policy resolved,
	// EvaluatePolicy answers nothing and the call reaches allow() at the end; the
	// refresh and the audit POST are both skipped where they are written, each on
	// its own empty-key check. What the early exit ALSO skipped was the tamper
	// guard, so a machine with no credential could not protect its own state —
	// and a local policy is kept in exactly that state.
	//
	// The credential itself is gone too, not just the gate. It was read on every
	// call and used for one thing: a hash of it stamped each local log line, for
	// telling two accounts' calls apart. See config.go.

	// Translator, input side: every client's payload becomes ONE shape here.
	// Claude's flat {tool_name, tool_input, …} and Antigravity's nested
	// {toolCall:{name,args}} come out identical, so nothing below this line has
	// to know which client sent the call.
	activeClient = clientFor(agentType)
	nc := normalizeToolCall(activeClient, agentType, input)
	c := nc.call
	// THERE IS NO POLICY CACHE. It held a service's answer with a TTL, a bounded
	// wait for a refresh, and a detached child to warm it for the next call — all
	// of it so a rule added on a dashboard would land within one call. Nothing
	// writes it now, and while it still existed it was worse than dead: a service
	// answering with an empty security block OUTRANKED the file, so a machine whose
	// file configured DLP had it switched off by a reply that said nothing.
	//
	// Read here rather than at the policy step below, because what the file can
	// carry BESIDE the policy is consulted before the policy is: the tamper flag
	// just below, then the rate limit, the egress rules and the DLP scanner.
	local := loadLocalPolicyFile(c.Cwd)

	// hasSecurity is not the same question as "is sec nil": the file can carry a
	// `security` block of null, which is a machine saying it configures no layers,
	// and that is different from a file that says nothing about them.
	var sec *sgshared.Security
	hasSecurity := false
	if local != nil && local.HasSecurity {
		sec, hasSecurity = local.Security, true
	}

	// Hardcoded tamper protection, and it runs FIRST — before the policy is even
	// resolved. Two reasons, both learned the hard way. It cannot be switched off
	// by editing a policy, so it must not be reachable only through the path that
	// reads one. And doing the slow work first is what made the earliest guard
	// processes in a concurrent burst exceed the client's hook timeout and get
	// killed partway through writing their log.
	//
	// The flag defaults ON: a file that is missing, unreadable or silent about it
	// leaves self-protection enabled, because the failure mode of guessing wrong in
	// the other direction is a guard that can be edited out of the way.
	selfProtect := true
	if local != nil && local.SelfProtect != nil {
		selfProtect = *local.SelfProtect
	}
	if selfProtect {
		if reason := tamperCheck(c.Tool, c.Args); reason != "" {
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	}

	// A rewrite is HELD rather than emitted, so no layer decides a call on its
	// own: emitting ends the process, and everything below -- the DLP argument
	// scan, the rate limit and the POLICY -- would never run for a call the
	// rewriting layer happened to touch. See where it is applied.
	var pendingPatch map[string]interface{}

	// A secret leaving the machine in the ARGUMENTS of a call, as opposed to one
	// being read out of a file, which is the redaction plan's job further down.
	if sec != nil {
		if reason := egressSecretCheck(c.Args, sec, c.Cwd); reason != "" {
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	}

	// Layers run before policy, and a block here wins immediately. The cached
	// config is used whether or not it is fresh and whether or not a policy came
	// with it: DLP and the rate limit are configured separately from the policy,
	// so gating them on one being present is how they silently stopped applying.
	argsText := ""
	if b, err := json.Marshal(c.Args); err == nil {
		argsText = string(b)
	}

	if sec != nil && sec.DLPBlock != nil {
		if hit := sgshared.DLPScan(argsText, sec.DLPBlock); hit != "" {
			reason := "Security layer (DLP): blocked - arguments contain a " + hit +
				// A denial names what a person can change; see hooks/guard.mjs.
				". Blocked by SolonGate (DLP). Edit ~/.solongate/policy.json to change what is refused."
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	} else if cfg := observingDLP(sec); cfg != nil {
		// DETECT and REDACT both let the call through and both write the match
		// down; what separates them is what the model ends up seeing, which is
		// decided below and in the post-tool stage, not here.
		//
		// The write only happens on a client with no post-tool stage, where
		// nothing else will do it — see recordObserved. Before this, detect mode
		// on such a client observed nothing at all: reads were still redacted, so
		// it looked like it was working, and an argument carrying a secret went
		// out with no record anywhere that it had.
		if hit := sgshared.DLPScan(argsText, cfg.cfg); hit != "" {
			recordObserved(sec, hasSecurity, c, agentType, agentName,
				"Security layer (DLP): detected - arguments contain a "+hit+". Allowed: DLP is in "+cfg.mode+" mode.",
				started)
		}
	}

	// DETECT mode, and only where nothing else will count. The audit hook does
	// this on clients that run one; on a client with no post-tool stage the burst
	// is invisible unless it is counted here.
	//
	// Before the block check so the two never both append to the counter file for
	// one call — the API sets exactly one of the two, so only one runs anyway,
	// and the ordering makes that impossible to get wrong later.
	if sec != nil && sec.RateLimitObserve != nil && !activeClient.ReportsAfter {
		if reason := rateLimitCheck(agentID, sec.RateLimitObserve); reason != "" {
			recordObserved(sec, hasSecurity, c, agentType, agentName,
				strings.Replace(reason, "Blocked by SolonGate (rate limit). Edit ~/.solongate/policy.json to review or adjust it.",
					"Allowed: the rate limit is in detect mode.", 1),
				started)
		}
	}

	if sec != nil && sec.RateLimit != nil {
		if reason := rateLimitCheck(agentID, sec.RateLimit); reason != "" {
			record(sec, hasSecurity, c, agentType, agentName, reason, started)
			deny(reason)
		}
	}

	// The policy itself. Compiled from JSON in this process rather than fetched,
	// so nothing about this decision depends on the network being there.
	//
	// The cloud cache is preferred, but a MISS falls through to the policy on
	// disk rather than to "nothing to enforce" — a cache that is absent, or that
	// parses and carries a null policy, is the state every machine is in on its
	// first call after install.
	var pol *sgshared.Policy
	if local != nil {
		pol = local.Policy
	}
	policyReason := sgpolicy.EvaluatePolicy(pol, c.Args, c.Tool, c.Cwd)

	// Every call, denial or not: the timing the audit hook reads back, and the
	// clean-up of whatever an older version left in this directory. Written
	// AFTER the decision so the number it carries is the whole evaluation.
	// What the guard EXTRACTED, alongside what it was given. A rule that names a
	// directory and does not fire is almost always a call the guard saw with no
	// path in it, and until this was recorded there was no way to tell that from
	// a rule that matched and lost: the audit log carries denials, and on a
	// client with no post-tool stage an ALLOW leaves no cloud row at all.
	//
	// Argument KEY NAMES, never values. The names are schema and are exactly what
	// is needed to see that a client renamed a field; the values are the file
	// contents, commands and URLs this whole binary exists to keep out of places
	// they do not belong.
	rec, _ := json.Marshal(map[string]interface{}{
		"ms":      elapsedMs(started),
		"ts":      time.Now().UnixMilli(),
		"tool":    c.Tool,
		"session": c.SessionID,
		"client":  agentType,
		// The directory the CALL was made in, which is not always the directory
		// this process was spawned in: a client is free to launch its hooks from
		// anywhere, and Antigravity does. The record is filed under the process
		// cwd (the audit hook pairs with it from there), so without this there is
		// no way to find the calls belonging to a project.
		"cwd":   c.Cwd,
		"perm":  sgshared.GuessPermission(c.Tool),
		"args":  sgpolicy.SortedKeys(c.Args),
		"paths": len(sgpolicy.ExtractPaths(c.Args, sgshared.GuessPermission(c.Tool) == "EXECUTE")),
		"cmds":  len(sgpolicy.ExtractCommands(c.Args)),
		"urls":  len(sgpolicy.ExtractURLs(c.Args)),
	})
	writeEvalRecord(sgshared.ProjectFlagDir(), rec)
	sweepLegacyScratch()

	if policyReason != "" {
		record(sec, hasSecurity, c, agentType, agentName, policyReason, started)
		deny(policyReason)
	}

	// Read redaction, LAST, and only when the call is otherwise allowed.
	//
	// It has to come after policy: a file a DENY rule blocks must never be
	// served, not even redacted. Putting this before the policy once let a
	// redaction rewrite terminate the hook and silently bypass the block.
	//
	// Gated on a CAPABILITY, not on an identity. A client with a post-tool stage
	// that can rewrite what the tool returned masks the secret there instead;
	// one without it has to be handed a redacted copy before the tool runs, and
	// a secret we cannot redact becomes a block rather than a pass.
	// DETECT IS NOT IN THIS LIST, and that is the whole of the mode. Masking a
	// file's contents on the way to the model is redacting; a mode called detect
	// that did it was doing a stronger mode's work under a weaker mode's name,
	// and the person who chose it never saw the real value they had asked only
	// to be told about.
	//
	// THE CAPABILITY GATE IS FOR REDACT, NOT FOR BLOCK. Masking can be deferred
	// to a client that rewrites its own tool output, which is why this whole
	// scan was skipped there. Refusing cannot: by the time a post-tool stage
	// runs, the file has been read. So block mode ran this on nobody who could
	// redact, and `cat secrets.pem` came back masked and ALLOWED on exactly the
	// clients most people use — block quietly degraded to redact, the same shape
	// of bug detect had.
	if sec != nil {
		blocking := sec.DLPBlock != nil
		dlpCfg := sec.DLPBlock
		if dlpCfg == nil {
			dlpCfg = sec.DLPRedact
		}
		if dlpCfg != nil && (blocking || !activeClient.RedactsOutput) {
			if plan := dlpRedactReadPlan(c.Tool, c.Args, dlpCfg, c.Cwd); plan != nil {
				// A Rewrite plan means the file HAS a secret and redaction is
				// possible. In block mode that is not an offer to take.
				if plan.Block || blocking {
					reason := "Security layer (DLP): reading a file that contains a secret is blocked. Blocked by SolonGate."
					record(sec, hasSecurity, c, agentType, agentName, reason, started)
					deny(reason)
				}
				if len(plan.Rewrite) > 0 {
					if pendingPatch == nil {
						pendingPatch = map[string]interface{}{}
					}
					// The redaction wins a collision: both may rewrite `command`,
					// and between "the listing hides a file" and "the read does
					// not hand over a secret", the second is the one that must
					// survive.
					for k, v := range plan.Rewrite {
						pendingPatch[k] = v
					}
				}
			}
		}
	}

	// Anything held along the way is applied now, on a call every layer allowed.
	if len(pendingPatch) > 0 {
		rewriteCall(pendingPatch)
	}

	allow()
}

// hookStart is the instant this call's guard time is measured from.
//
// This binary is NOT the process the client launched. The client launches the
// Node hook; the hook reads stdin, probes this binary's version and only then
// spawns it. By the time main() runs, the call has already paid for Node's boot
// (~26ms), guard.mjs being parsed (~17ms) and two process spawns — and a clock
// started here sees none of it. That is how the audit log came to report a flat
// "1ms" on every row: the number was accurate about the policy arithmetic and
// silent about everything the call actually waited for, which is where the
// latency lives. Nothing on a real machine guards a tool call in a millisecond,
// and a dashboard that says so is not measuring the hook.
//
// SOLONGATE_HOOK_ORIGIN_MS is the hook process's own start in epoch ms, handed
// down by guard.mjs (which takes it from performance.timeOrigin, stamped before
// Node bootstraps). With it, what this binary reports is the whole hook.
//
// Without it — run directly, or spawned by a hook too old to send it — fall back
// to this process's own start. That is less than the truth but never more, and
// an under-report from an old hook is preferable to a guess.
func hookStart() time.Time {
	if v := os.Getenv("SOLONGATE_HOOK_ORIGIN_MS"); v != "" {
		if ms, err := strconv.ParseInt(v, 10, 64); err == nil {
			t := time.UnixMilli(ms)
			// A value from the future, or from a minute ago, is not this call's
			// origin — it is a stale variable inherited through an environment
			// that was built for something else. A duration is only worth
			// reporting when the instant it came from is plausible.
			if d := time.Since(t); d >= 0 && d < time.Minute {
				return t
			}
		}
	}
	return time.Now()
}

// elapsedMs is the duration the audit log carries, in milliseconds to one
// decimal.
//
// time.Duration.Milliseconds() TRUNCATES, which on the old clock (see hookStart)
// mapped everything under 1ms to 0 and everything under 2ms to 1 — so a column
// of genuinely varying durations printed as an unbroken run of identical "1ms"
// rows. Rounding a float keeps the variation that is actually there, and the
// audit column is a real, so nothing downstream needs a whole number.
func elapsedMs(started time.Time) float64 {
	return math.Round(float64(time.Since(started).Microseconds())/100) / 10
}

// record writes the denial where the settings say it goes: to this machine, or
// to the cloud, never both. The cloud write is detached so the agent is not kept
// waiting on a network round trip for a decision already made.
func record(sec *sgshared.Security, hasSecurity bool, c call, agentType, agentName, reason string, started time.Time) {
	recordDecision(sec, hasSecurity, c, agentType, agentName, reason, "DENY", started)
}

// recordObserved files a row for a call that was ALLOWED but carried a signal
// worth keeping — a DLP pattern matched in detect mode, say.
//
// Only for clients with no post-tool stage. Everywhere else the audit hook files
// the allow row and this would be a duplicate; on Antigravity nothing else ever
// runs, so a detect-mode hit that is not written here is not written at all, and
// a mode whose whole job is to observe would observe nothing.
func recordObserved(sec *sgshared.Security, hasSecurity bool, c call, agentType, agentName, reason string, started time.Time) {
	if activeClient.ReportsAfter {
		return
	}
	recordDecision(sec, hasSecurity, c, agentType, agentName, reason, "ALLOW", started)
}

func recordDecision(sec *sgshared.Security, hasSecurity bool, c call, agentType, agentName, reason, decisionVal string, started time.Time) {
	entry := map[string]interface{}{
		"tool":               c.Tool,
		"arguments":          c.Args,
		"decision":           decisionVal,
		"reason":             reason,
		"permission":         sgshared.GuessPermission(c.Tool),
		"source":             agentType + "-guard",
		"agent_id":           agentType,
		"agent_name":         agentName,
		"session_id":         c.SessionID,
		"evaluation_time_ms": elapsedMs(started),
	}
	local := map[string]interface{}{"ts": time.Now().UTC().Format(time.RFC3339Nano)}
	for k, v := range entry {
		local[k] = v
	}
	// The FILE is where a record goes. There used to be a POST here for the case
	// where local logging was switched off, and with the service gone that branch
	// could only ever lose the entry.
	writeLocalLog(sec, local)
}
