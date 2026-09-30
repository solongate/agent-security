package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/codeyevsky/solongate/sgshared"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/core"
	"github.com/codeyevsky/solongate/proxy/internal/mcp"
	"github.com/codeyevsky/solongate/proxy/internal/sdk"
)

// The SolonGate MCP proxy, ported from packages/proxy/src/proxy.ts.
//
// It sits between an MCP client and the tool server that client wanted to talk
// to, and every tool call goes through the security pipeline on the way past:
//
//	agent ──(stdio|http)──> proxy ──(stdio|sse|http)──> upstream MCP server
//	                          │
//	                     [SolonGate]
//	                     rate limit
//	                     policy eval
//	                     audit log
//
// Two things about it are worth stating before the code, because both are easy
// to undo by accident.
//
// FIRST, EVERY LOG LINE GOES TO STDERR. In stdio mode stdout carries the
// protocol, and one line of human text on it lands inside a JSON-RPC frame and
// takes the whole session down with a parse error that names nothing.
//
// SECOND, THE FAILURE DIRECTION IS NOT UNIFORM AND MUST NOT BE MADE SO. The
// licence check fails CLOSED — an unreachable licence server stops the proxy
// from starting. The cloud policy fetch fails OPEN onto the LOCAL policy, which
// is a policy, not an absence of one. Policy evaluation with no evaluator fails
// CLOSED. Each of those is the answer for its own situation and flattening them
// into one rule breaks whichever ones it does not match.

const (
	// maxArgumentSize is the ceiling on one tool call's arguments. Measured in
	// bytes of encoded JSON, not characters — a payload of non-ASCII text is
	// bigger on the wire than it looks.
	maxArgumentSize = 1 << 20
	// mutexTimeout bounds how long a call waits behind another call to the SAME
	// tool. Without it a wedged upstream turns into an agent that never hears
	// back from anything.
	mutexTimeout = 30 * time.Second
	// internalGateKey stops the embedded SDK from picking up SOLONGATE_API_KEY
	// out of the environment. The proxy owns every cloud interaction — audit
	// logs, policy fetch, tool registration — and an SDK doing them too would
	// double every audit entry.
	internalGateKey = "sg_test_proxy_internal_00000000"
)

// ErrNoEvaluator is returned when the runtime has nothing to decide with.
//
// It is a startup refusal rather than a running proxy that denies everything,
// and the difference matters to the person reading the error. A proxy that
// starts and refuses every call looks like a policy problem and sends them to
// the dashboard; one that will not start says what is actually wrong and points
// at the implementation that does work.
var ErrNoEvaluator = errors.New("no policy evaluator is compiled into this build")

// errReported is a failure whose message has already been printed in the shape
// the user expects. The caller turns it into an exit code and says nothing more.
var errReported = errors.New("proxy: startup failed (already reported)")

// Options is everything the runtime needs that is not in the parsed config.
type Options struct {
	Config config.ProxyConfig

	// Evaluator is what decides. It is REQUIRED. There is no default, and a
	// default would have to be either "allow" — which is the failure this whole
	// program exists to prevent — or "deny", which is indistinguishable from a
	// misconfigured policy.
	Evaluator sdk.PolicyEvaluator

	// Log receives one line at a time, unprefixed. Nil sends it to stderr with
	// the [SolonGate] prefix every existing install greps for.
	Log func(string)

	// UpstreamTransport and ServerTransport replace the transports the config
	// would dial. Tests use them; nothing else should.
	UpstreamTransport mcp.Transport
	ServerTransport   mcp.Transport
}

type subAgent struct {
	ID   string
	Name string
}

// Proxy is one running gateway.
type Proxy struct {
	config config.ProxyConfig
	gate   *sdk.SolonGate

	client *mcp.Client
	server *mcp.Server

	upstreamTools   []mcp.Tool
	toolMutexes     *toolMutexes
	syncManager     *SyncManager
	overrideUpsream mcp.Transport
	overrideServer  mcp.Transport

	mu sync.RWMutex
	// policy is replaced by the sync manager on its own goroutine while the
	// proxy is serving, so it is behind the lock rather than read directly.
	policy PolicyDoc
	// agentID and agentName are the trust-map identity: from --agent-name, from
	// MCP clientInfo, or from HTTP headers, in that order of authority.
	agentID   string
	agentName string
	// httpSubAgent is per-request and overwritten by each one, exactly as the
	// Node implementation does it.
	httpSubAgent *subAgent

	logFn func(string)
}

// New builds a proxy. It performs no I/O.
func New(opts Options) (*Proxy, error) {
	if opts.Evaluator == nil {
		return nil, ErrNoEvaluator
	}

	logFn := opts.Log
	if logFn == nil {
		logFn = func(line string) { fmt.Fprintf(os.Stderr, "[SolonGate] %s\n", line) }
	}

	p := &Proxy{
		config:          opts.Config,
		policy:          PolicyDocFromSet(opts.Config.Policy),
		toolMutexes:     newToolMutexes(),
		overrideUpsream: opts.UpstreamTransport,
		overrideServer:  opts.ServerTransport,
		logFn:           logFn,
	}

	// --agent-name is for custom bots that send no useful MCP clientInfo. When
	// it is set it wins, and clientInfo is only logged.
	if opts.Config.AgentName != "" {
		p.agentName = opts.Config.AgentName
		p.agentID = slugify(opts.Config.AgentName)
	}

	// THE RATE LIMIT COMES FROM THE POLICY FILE TOO, and it did not before.
	//
	// These two numbers were taken only from --rate-limit and --global-rate-limit, so a
	// machine whose policy file set `security.rateLimit` got no limit on this path while
	// the guard hooks enforced one. The flag still wins when it is given: it is the more
	// specific instruction, typed for this invocation.
	globalLimit := opts.Config.GlobalRateLimit
	if globalLimit == 0 {
		globalLimit = securityFromDoc(p.policy).perMinute
	}

	gate, err := sdk.New(sdk.Options{
		Name:      orDefault(opts.Config.Name, "solongate-proxy"),
		APIKey:    internalGateKey,
		PolicySet: &p.policy.Set,
		Config: &sdk.Config{
			ValidateSchemas:          sdk.Bool(true),
			VerboseErrors:            opts.Config.Verbose,
			RateLimitPerTool:         opts.Config.RateLimitPerTool,
			GlobalRateLimitPerMinute: globalLimit,
			// THE DLP BLOCK FROM THE POLICY FILE. This path scanned nothing for
			// secrets: the block reached the guard hooks and nothing here, so a
			// `dlpBlock` that refused a secret in an agent's tool calls did not refuse
			// one through the proxy.
			DLPBlock: dlpBlockFromDoc(p.policy),
		},
		PolicyEvaluator: opts.Evaluator,
	})
	if err != nil {
		return nil, err
	}
	p.gate = gate
	for _, w := range gate.Warnings() {
		p.log("WARNING: " + w)
	}

	return p, nil
}

func (p *Proxy) log(line string) { p.logFn(line) }

// currentPolicy reads the policy under the lock. The sync manager replaces it
// from another goroutine at any moment.
func (p *Proxy) currentPolicy() PolicyDoc {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.policy
}

func (p *Proxy) setPolicy(doc PolicyDoc) {
	p.mu.Lock()
	p.policy = doc
	p.mu.Unlock()
}

// Start connects upstream, then serves downstream. It blocks until the
// downstream client goes away.
func (p *Proxy) Start(ctx context.Context) error {
	p.log("Starting SolonGate Proxy...")

	if err := p.loadPolicy(ctx); err != nil {
		return err
	}

	policy := p.currentPolicy()
	p.log("Policy: " + policy.Set.Name + " (" + strconv.Itoa(len(policy.Set.Rules)) + " rules)")
	for _, line := range layerReport(policy, p.config) {
		p.log(line)
	}
	if policy.Unreadable > 0 {
		// Said out loud rather than swallowed: the dashboard still lists these
		// rules, so a silent skip means the enforced policy and the displayed
		// one differ with nothing to say which.
		p.log("WARNING: " + strconv.Itoa(policy.Unreadable) +
			" rule(s) in this policy could not be read by this build and are not being enforced.")
	}

	transport := p.config.Upstream.Transport
	if transport == "" {
		transport = "stdio"
	}
	if transport == "stdio" {
		p.log("Upstream: [stdio] " + p.config.Upstream.Command + " " + strings.Join(p.config.Upstream.Args, " "))
	} else {
		p.log("Upstream: [" + transport + "] " + p.config.Upstream.URL)
	}

	if err := p.connectUpstream(ctx, transport); err != nil {
		return err
	}
	defer p.client.Close()

	if err := p.discoverTools(ctx); err != nil {
		return err
	}

	p.startPolicySync()
	defer func() {
		if p.syncManager != nil {
			p.syncManager.Stop()
		}
	}()

	p.createServer()
	return p.serve(ctx)
}

// ── step 0: licence and policy ─────────────────────────────────────────────

// loadPolicy puts this machine's policy into the gate.
//
// It was validateLicenseAndLoadPolicy, and most of it was the licence: a call to
// /auth/me that refused to start on a 401, a 403, or an unreachable service, and
// then a policy fetched from that service with the local file as the fallback.
// There is no service, so the file is not a fallback — it is the policy.
//
// WHICH LAYERS THIS PATH ENFORCES, said out loud at startup.
//
// The policy file carries a `security` block — a rate limit, DLP, egress rules — and the
// hooks apply all of it. THIS path does not: the interceptor pipeline has rate limiting,
// the exfiltration chain, policy evaluation, capability tokens, request signing and a
// response scan, and no DLP or egress scanner at all.
//
// Which means somebody can configure `dlpBlock`, watch it work on their agent's tool
// calls, put an MCP server behind this proxy, and reasonably assume the same protection
// is there. It is not. A difference a person cannot see is the kind that gets found the
// expensive way, so the proxy names it every time it starts rather than leaving it to
// whoever reads the README.
//
// The rate limit IS read from the file now. It was taken only from --rate-limit and
// --global-rate-limit, so a machine that had set one in its policy got none here.
func layerReport(policy PolicyDoc, cfg config.ProxyConfig) []string {
	sec := securityFromDoc(policy)
	var out []string

	limit := cfg.GlobalRateLimit
	source := "--global-rate-limit"
	if limit == 0 && sec.perMinute > 0 {
		limit, source = sec.perMinute, "the policy file"
	}
	if limit > 0 {
		out = append(out, "Layer: rate limit "+strconv.Itoa(limit)+"/min (from "+source+")")
	} else {
		out = append(out, "Layer: rate limit off")
	}

	// DLP IS ENFORCED HERE NOW, with the same scanner and the same pattern list the guard
	// uses (sgshared.DLPScanViews), so this reports rather than warns.
	if sec.hasDLP {
		out = append(out, "Layer: DLP on — arguments scanned for secrets")
	} else {
		out = append(out, "Layer: DLP off")
	}

	// EGRESS IS NOT, and that is a decision rather than an omission: the check reads the
	// files a transfer command would upload, resolving them against the AGENT's working
	// directory. A proxy in front of a tool server has no such directory — the paths in a
	// call belong to whatever machine the upstream runs on — so a check that read them
	// here would be reading the wrong files. Named only when the policy configures it,
	// which is the only case that can mislead anybody.
	if sec.hasEgress {
		out = append(out, "NOTE: egress protection is configured and applies to the guard "+
			"hooks, not to this path: the files a transfer command would upload live on the "+
			"agent's machine, and a proxy in front of a tool server has no agent working "+
			"directory to resolve them against.")
	}
	return out
}

// securityFromDoc reads the `security` block out of the document's own fields.
//
// Fields is the OUTER document (see DecodePolicyDoc), so this works for the envelope —
// which is the only shape that can carry a security block in the first place.
type docSecurity struct {
	perMinute int
	hasDLP    bool
	hasEgress bool
}

// dlpBlockFromDoc is the policy file's `security.dlpBlock`, in the shape the scanner
// takes. Nil when the policy configures none — and only the envelope can carry one.
func dlpBlockFromDoc(policy PolicyDoc) *sgshared.DLPConfig {
	raw, ok := policy.Fields["security"]
	if !ok {
		return nil
	}
	var sec struct {
		DLPBlock *sgshared.DLPConfig `json:"dlpBlock"`
	}
	if json.Unmarshal(raw, &sec) != nil {
		return nil
	}
	return sec.DLPBlock
}

func securityFromDoc(policy PolicyDoc) docSecurity {
	raw, ok := policy.Fields["security"]
	if !ok {
		return docSecurity{}
	}
	var sec struct {
		RateLimit *struct {
			PerMinute int `json:"perMinute"`
		} `json:"rateLimit"`
		DLPBlock  json.RawMessage `json:"dlpBlock"`
		DLPRedact json.RawMessage `json:"dlpRedact"`
	}
	if json.Unmarshal(raw, &sec) != nil {
		return docSecurity{}
	}
	out := docSecurity{}
	if sec.RateLimit != nil {
		out.perMinute = sec.RateLimit.PerMinute
	}
	has := func(r json.RawMessage) bool { return len(r) > 0 && string(r) != "null" }
	out.hasDLP = has(sec.DLPBlock) || has(sec.DLPRedact)
	// Egress reads the files a transfer command would upload, and it is driven by
	// dlpBlock — the same block, the blocking half.
	out.hasEgress = has(sec.DLPBlock)
	return out
}

// Loaded HERE rather than left to a caller, because a gate with no policy loaded
// denies everything, and an empty machine should not mean a dead agent.
func (p *Proxy) loadPolicy(ctx context.Context) error {
	_ = ctx
	if p.config.PolicyPath != "" {
		p.log("Enforcing " + p.config.PolicyPath + ".")
	} else {
		p.log("No policy file found — nothing is forbidden until one is written.")
	}
	if err := p.gate.LoadPolicy(p.currentPolicy().Set); err != nil {
		return err
	}

	// The Node proxy fetches the policy's compiled OPA WASM bundle here and
	// treats a missing one as "deny everything until it is recompiled". There
	// is no WASM runtime in this build, so the bundle is not fetched: pulling
	// down bytes that could not be executed would only make the startup slower
	// and the log less true. The direction is preserved instead — without an
	// evaluator this runtime refuses to start at all. See the caveat about
	// sharing packages/guard-go's engine.
	return nil
}

// ── step 1: upstream ───────────────────────────────────────────────────────

func (p *Proxy) connectUpstream(ctx context.Context, transport string) error {
	p.client = mcp.NewClient(mcp.Implementation{Name: "solongate-proxy-client", Version: "0.1.0"})

	t := p.overrideUpsream
	if t == nil {
		var err error
		t, err = p.dialUpstream(ctx, transport)
		if err != nil {
			return err
		}
	}

	connectCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	if err := p.client.Connect(connectCtx, t); err != nil {
		return err
	}
	p.log("Connected to upstream server (" + transport + ")")
	return nil
}

func (p *Proxy) dialUpstream(ctx context.Context, transport string) (mcp.Transport, error) {
	switch transport {
	case "sse":
		if p.config.Upstream.URL == "" {
			return nil, errors.New("--upstream-url required for SSE transport")
		}
		return mcp.NewSSEClientTransport(ctx, mcp.HTTPClientOptions{URL: p.config.Upstream.URL})
	case "http":
		if p.config.Upstream.URL == "" {
			return nil, errors.New("--upstream-url required for HTTP transport")
		}
		return mcp.NewStreamableHTTPClientTransport(mcp.HTTPClientOptions{URL: p.config.Upstream.URL})
	default:
		return mcp.NewStdioClientTransport(mcp.StdioClientOptions{
			Command: p.config.Upstream.Command,
			Args:    p.config.Upstream.Args,
			Env:     p.config.Upstream.Env,
			Cwd:     p.config.Upstream.Cwd,
			// The child's own logging is forwarded to this process's stderr
			// rather than into a pipe nobody drains. The Node SDK pipes it and
			// never reads it, which stalls any upstream chatty enough to fill
			// the pipe buffer.
			Stderr: os.Stderr,
		})
	}
}

// ── step 2: discovery ──────────────────────────────────────────────────────

func (p *Proxy) discoverTools(ctx context.Context) error {
	listCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	tools, err := p.client.ListTools(listCtx)
	if err != nil {
		return err
	}
	p.upstreamTools = tools

	p.log("Discovered " + strconv.Itoa(len(tools)) + " tools from upstream:")
	for _, t := range tools {
		description := t.Description
		if description == "" {
			description = "(no description)"
		}
		p.log("  - " + t.Name + ": " + description)
	}
	return nil
}

// ── step 3: registration ───────────────────────────────────────────────────

// ── step 3c: policy sync ───────────────────────────────────────────────────

// startPolicySync watches the policy FILE and reloads the gate when it changes.
//
// It used to poll a service for a newer policy and push a local edit back to one,
// which is where its name comes from. What is left is the half about this machine,
// and it matters more than it did: the file is the only source, so somebody editing
// it expects the proxy to follow without a restart.
func (p *Proxy) startPolicySync() {
	if p.config.PolicyPath == "" {
		return
	}
	p.syncManager = NewSyncManager(SyncOptions{
		LocalPath: p.config.PolicyPath,
		Initial:   p.currentPolicy(),
		OnPolicyUpdate: func(doc PolicyDoc) {
			p.setPolicy(doc)
			if err := p.gate.LoadPolicy(doc.Set); err != nil {
				p.log("Policy reload rejected: " + err.Error())
				return
			}
			p.log("Policy hot-reloaded: " + doc.Set.Name + " v" + strconv.Itoa(doc.Set.Version) +
				" (" + strconv.Itoa(len(doc.Set.Rules)) + " rules)")
		},
		Log: func(line string) { p.logFn("[Sync] " + line) },
	})
	p.syncManager.Start()
	p.log("Watching " + p.config.PolicyPath + " for changes.")
}

// ── step 4: the downstream server ──────────────────────────────────────────

func (p *Proxy) createServer() {
	p.server = mcp.NewServer(mcp.Implementation{
		Name:    orDefault(p.config.Name, "solongate-proxy"),
		Version: "0.1.0",
	})

	p.server.OnInitialized = p.onClientInitialized
	p.server.SetRequestHandler("tools/list", p.handleListTools)
	p.server.SetRequestHandler("tools/call", p.handleCallTool)
	p.server.SetRequestHandler("resources/list", p.passThroughList("resources/list", emptyList("resources")))
	p.server.SetRequestHandler("resources/templates/list",
		p.passThroughList("resources/templates/list", emptyList("resourceTemplates")))
	p.server.SetRequestHandler("prompts/list", p.passThroughList("prompts/list", emptyList("prompts")))
	p.server.SetRequestHandler("resources/read", p.handleReadResource)
	p.server.SetRequestHandler("prompts/get", p.handleGetPrompt)
}

// onClientInitialized resolves the agent identity from MCP clientInfo, unless
// --agent-name already answered it.
func (p *Proxy) onClientInitialized(client mcp.Implementation) {
	raw, _ := json.Marshal(client)
	p.log("MCP clientInfo raw: " + string(raw))

	p.mu.Lock()
	if client.Name != "" && p.config.AgentName == "" {
		id, name := normalizeAgentName(client.Name)
		p.agentID, p.agentName = id, name
	}
	agentID, agentName := p.agentID, p.agentName
	p.mu.Unlock()

	if client.Name != "" && p.config.AgentName == "" {
		p.log("Agent identified from MCP clientInfo: " + agentName + " (raw: " + client.Name + ")")
	} else if p.config.AgentName != "" {
		shown := client.Name
		if shown == "" {
			shown = "none"
		}
		p.log("Agent identity from --agent-name flag: " + agentName + " (clientInfo: " + shown + ")")
	}

	p.writeDebugRecord(client, agentID, agentName)
}

// writeDebugRecord appends the agent-detection facts to .solongate/.debug-proxy
// under the working directory.
//
// It exists because "which agent is this" is answered from three different
// sources and the wrong answer shows up much later, as tool calls attributed to
// the wrong identity in the trust map. Every failure here is ignored: a
// read-only working directory must not stop a proxy from serving.
func (p *Proxy) writeDebugRecord(client mcp.Implementation, agentID, agentName string) {
	record := map[string]any{
		"timestamp":         time.Now().UTC().Format("2006-01-02T15:04:05.000Z"),
		"clientInfo":        client,
		"agentNameFlag":     nullable(p.config.AgentName),
		"resolvedAgentId":   nullable(agentID),
		"resolvedAgentName": nullable(agentName),
		"pid":               os.Getpid(),
	}
	line, err := json.Marshal(record)
	if err != nil {
		return
	}
	dir, err := filepath.Abs(".solongate")
	if err != nil {
		return
	}
	if os.MkdirAll(dir, 0o755) != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(dir, ".debug-proxy"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// handleListTools returns the upstream's tools unmodified.
func (p *Proxy) handleListTools(context.Context, *mcp.Request) (any, error) {
	tools := p.upstreamTools
	if tools == nil {
		tools = []mcp.Tool{}
	}
	return map[string]any{"tools": tools}, nil
}

// handleCallTool is the whole point of the program.
func (p *Proxy) handleCallTool(ctx context.Context, req *mcp.Request) (any, error) {
	var params mcp.CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &mcp.ServerError{Code: mcp.CodeInvalidParams, Message: "Invalid tools/call parameters"}
	}

	agent := p.subAgentFor(params.Meta)

	arguments := params.Arguments
	if arguments == nil {
		arguments = map[string]any{}
	}

	// Size is checked BEFORE the mutex and before any policy work. A caller
	// flooding the proxy with oversized payloads must not be able to turn that
	// into queued work.
	encodedSize, err := encodedByteLen(arguments)
	if err != nil {
		return mcp.TextResult("Arguments could not be encoded.", true), nil
	}
	if encodedSize > maxArgumentSize {
		p.log("DENY: " + params.Name + " — payload size " + strconv.Itoa(encodedSize) +
			" exceeds limit " + strconv.Itoa(maxArgumentSize))
		return mcp.TextResult(fmt.Sprintf("Request payload too large (%dKB > %dKB limit)",
			int(math.Round(float64(encodedSize)/1024)),
			int(math.Round(float64(maxArgumentSize)/1024))), true), nil
	}

	p.log("Tool call: " + params.Name)

	// Calls to the SAME tool are serialised so the rate limiter counts them
	// accurately; calls to DIFFERENT tools run in parallel, because serialising
	// those would make an agent's three independent tools wait on the slowest.
	if !p.toolMutexes.acquire(ctx, params.Name, mutexTimeout) {
		p.log("DENY: " + params.Name + " — mutex timeout (" +
			strconv.Itoa(int(mutexTimeout/time.Millisecond)) + "ms)")
		return mcp.TextResult(fmt.Sprintf("Tool call queued too long (>%ds). Try again.",
			int(mutexTimeout/time.Second)), true), nil
	}
	defer p.toolMutexes.release(params.Name)

	start := time.Now()
	result, err := p.gate.ExecuteToolCall(ctx,
		core.McpCallToolParams{Name: params.Name, Arguments: arguments},
		func(callCtx context.Context, callParams core.McpCallToolParams) (core.McpCallToolResult, error) {
			// Only reached when the pipeline allowed the call.
			raw, err := p.client.CallTool(callCtx, mcp.CallToolParams{
				Name:      callParams.Name,
				Arguments: callParams.Arguments,
			})
			if err != nil {
				return core.McpCallToolResult{}, err
			}
			var out core.McpCallToolResult
			if err := json.Unmarshal(raw, &out); err != nil {
				return core.McpCallToolResult{}, errors.New(
					"the upstream returned a tool result this proxy could not read: " + err.Error())
			}
			return out, nil
		})
	if err != nil {
		// The upstream's own failure, or a gate that refused to run at all.
		// Returned as a transport error rather than as a denial: the call was
		// allowed, and telling the model it was blocked would be untrue.
		return nil, err
	}

	decision := "ALLOW"
	if result.IsError {
		decision = "DENY"
	}
	elapsed := time.Since(start)
	p.log("Result: " + decision + " (" + strconv.FormatInt(elapsed.Milliseconds(), 10) + "ms)")

	p.recordAudit(ctx, params.Name, arguments, result, decision, elapsed, agent)

	return toCallToolResult(result), nil
}

// recordAudit writes one decision to this machine's audit trail.
//
// IT IS NOT GATED ON A CREDENTIAL ANY MORE, and that was a real hole rather than
// tidying. The body was `if !isLiveKey(p.config.APIKey) { log("Skipping audit log");
// return }` — correct while the record was a POST, since there was nothing to POST
// to. But the destination is a file on this machine, and a proxy with no key is the
// ordinary case here, so the gate meant the common configuration kept NO RECORD OF
// ANY TOOL CALL: every denial enforced and none of them written down.
//
// It still does not block the call. The verdict is the product and the audit line is
// bookkeeping; a write that stalls must not sit between "blocked" and the agent
// hearing it.
func (p *Proxy) recordAudit(ctx context.Context, tool string, arguments map[string]any,
	result core.McpCallToolResult, decision string, elapsed time.Duration, agent *subAgent) {

	reason, matchedRule := "allowed", ""
	if result.IsError {
		reason, matchedRule = denialReason(result)
	}

	p.mu.RLock()
	agentID, agentName := p.agentID, p.agentName
	p.mu.RUnlock()

	entry := auditEntry{
		Tool:             tool,
		Arguments:        arguments,
		Decision:         decision,
		Reason:           reason,
		Permission:       string(core.GuessPermission(tool)),
		MatchedRule:      matchedRule,
		EvaluationTimeMs: elapsed.Milliseconds(),
		AgentID:          agentID,
		AgentName:        agentName,
	}
	if agent != nil {
		entry.SubAgentID = agent.ID
		entry.SubAgentName = agent.Name
	}

	// Written to the same file the guard and the hooks write, so one machine has one
	// audit trail. This used to POST the entry and, when every attempt failed, drop
	// it into .solongate-audit-backup.jsonl in whatever directory the proxy started
	// in — a second log, in a place nothing else reads.
	writeAuditEntry(entry, p.log)
}

// matchedRulePattern reads the rule id out of a denial reason of the form
// `Matched rule "deny-shell": …`, which is how the evaluator words them.
var matchedRulePattern = regexp.MustCompile(`^Matched rule "([^"]+)":`)

// denialReason digs the human reason out of a denial result. The pipeline
// encodes it as a JSON object in the first text block; a denial produced
// somewhere else may be plain text, and that is used as-is.
func denialReason(result core.McpCallToolResult) (string, string) {
	rawText := "denied"
	if len(result.Content) > 0 && result.Content[0].Text != "" {
		rawText = result.Content[0].Text
	}
	reason := rawText
	var parsed struct {
		Message string `json:"message"`
	}
	if json.Unmarshal([]byte(rawText), &parsed) == nil && parsed.Message != "" {
		reason = parsed.Message
	}
	if m := matchedRulePattern.FindStringSubmatch(reason); m != nil {
		return reason, m[1]
	}
	return reason, ""
}

// ── pass-through handlers ──────────────────────────────────────────────────

// passThroughList forwards a list method and answers with an empty list when
// the upstream does not implement it.
//
// An error would be the honest answer, but it is the wrong one: a client that
// gets an error for resources/list concludes the server is broken and stops
// asking for prompts too. The Node proxy swallows these for the same reason.
func (p *Proxy) passThroughList(method string, empty any) mcp.Handler {
	return func(ctx context.Context, _ *mcp.Request) (any, error) {
		raw, err := p.client.Raw(ctx, method, map[string]any{})
		if err != nil {
			return empty, nil
		}
		return raw, nil
	}
}

// handleReadResource forwards a resources/read and scans what comes back.
//
// A resource is content the agent was told to go and read, which makes it the
// most reliable place to put text that reads as an instruction. The scan does
// not block it — it prefixes a marker telling the model the content is data.
func (p *Proxy) handleReadResource(ctx context.Context, req *mcp.Request) (any, error) {
	var params mcp.ReadResourceParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &mcp.ServerError{Code: mcp.CodeInvalidParams, Message: "Invalid resources/read parameters"}
	}

	p.log("Resource read: " + params.URI)
	raw, err := p.client.Raw(ctx, "resources/read", params)
	if err != nil {
		return nil, err
	}

	annotated, threats := annotateResourceContents(raw)
	if len(threats) > 0 {
		p.log("WARNING resource response: " + params.URI + " — " + strings.Join(threats, ", "))
	}
	return annotated, nil
}

// handleGetPrompt forwards a prompts/get and scans the messages that come back,
// for the same reason as resources.
func (p *Proxy) handleGetPrompt(ctx context.Context, req *mcp.Request) (any, error) {
	var params mcp.GetPromptParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return nil, &mcp.ServerError{Code: mcp.CodeInvalidParams, Message: "Invalid prompts/get parameters"}
	}

	p.log("Prompt get: " + params.Name)
	raw, err := p.client.Raw(ctx, "prompts/get", params)
	if err != nil {
		return nil, err
	}

	annotated, threats := annotatePromptMessages(raw)
	if len(threats) > 0 {
		p.log("WARNING prompt response: " + params.Name + " — " + strings.Join(threats, ", "))
	}
	return annotated, nil
}

// ── step 5: serving ────────────────────────────────────────────────────────

func (p *Proxy) serve(ctx context.Context) error {
	if p.overrideServer != nil {
		return p.server.Serve(ctx, p.overrideServer)
	}
	if p.config.Port > 0 {
		return p.serveHTTP(ctx)
	}

	transport := mcp.NewStdioServerTransport()
	p.log("Proxy is live. All tool calls are now protected by SolonGate.")
	p.log("Waiting for requests...")
	return p.server.Serve(ctx, transport)
}

func (p *Proxy) serveHTTP(ctx context.Context) error {
	transport := mcp.NewHTTPServerTransport()
	transport.OnRequest = p.readAgentHeaders

	serveCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		_ = p.server.Serve(serveCtx, transport)
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", transport.ServeHTTP)
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "healthy",
			"proxy":  orDefault(p.config.Name, "solongate-proxy"),
		})
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "Not found. Use /mcp for MCP protocol or /health for health check.", http.StatusNotFound)
	})

	addr := ":" + strconv.Itoa(p.config.Port)
	server := &http.Server{
		Addr:    addr,
		Handler: mux,
		// No write timeout: a tool call held open while the upstream works is a
		// normal request here, and a deadline would cut off exactly the slow
		// calls that matter.
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
	}()

	p.log("Proxy is live on http://localhost:" + strconv.Itoa(p.config.Port) + "/mcp")
	p.log("All tool calls are now protected by SolonGate.")

	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// readAgentHeaders takes the agent identity off an HTTP request.
//
// The main identity is only taken once — the first request that carries it
// wins, matching the Node implementation. The SUB-agent is per request and is
// overwritten by every one, including with nothing, so an unattributed call
// after an attributed one is not credited to the previous sub-agent.
func (p *Proxy) readAgentHeaders(r *http.Request) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.agentID == "" {
		if id := r.Header.Get("X-Agent-Id"); id != "" {
			name := r.Header.Get("X-Agent-Name")
			if name == "" {
				name = id
			}
			p.agentID, p.agentName = id, name
			p.logFn("Agent identified from HTTP headers: " + name + " (" + id + ")")
		}
	}

	if id := r.Header.Get("X-Sub-Agent-Id"); id != "" {
		name := r.Header.Get("X-Sub-Agent-Name")
		if name == "" {
			name = id
		}
		p.httpSubAgent = &subAgent{ID: id, Name: name}
		return
	}
	p.httpSubAgent = nil
}

// subAgentFor prefers the identity carried in the request's own _meta over the
// one on the connection: a sub-agent that names itself in the call is more
// specific than a header that was set for the whole session.
func (p *Proxy) subAgentFor(meta json.RawMessage) *subAgent {
	if a := extractSubAgent(meta); a != nil {
		return a
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.httpSubAgent
}

// extractSubAgent reads `_meta["io.solongate/agent"]`, which is where a
// multi-agent client declares which of its agents is calling.
func extractSubAgent(meta json.RawMessage) *subAgent {
	if len(meta) == 0 {
		return nil
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(meta, &envelope) != nil {
		return nil
	}
	raw, ok := envelope["io.solongate/agent"]
	if !ok {
		return nil
	}
	var agent struct {
		ID   any `json:"id"`
		Name any `json:"name"`
	}
	if json.Unmarshal(raw, &agent) != nil || agent.ID == nil {
		return nil
	}
	id := fmt.Sprint(agent.ID)
	if id == "" {
		return nil
	}
	name := id
	if agent.Name != nil {
		if s := fmt.Sprint(agent.Name); s != "" {
			name = s
		}
	}
	return &subAgent{ID: id, Name: name}
}

// ── identity ───────────────────────────────────────────────────────────────

// normalizeAgentName maps a well-known MCP client name onto the identity the
// dashboard's trust map uses. An unrecognised name is kept as it arrived, so a
// custom client shows up as itself rather than as "unknown".
func normalizeAgentName(raw string) (string, string) {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "claude-code") || lower == "claude code":
		return "claude-code", "Claude Code"
	case strings.Contains(lower, "claude"):
		return "claude-desktop", "Claude Desktop"
	case strings.Contains(lower, "antigravity") || lower == "agy":
		return "antigravity", "Antigravity"
	case strings.Contains(lower, "codex"):
		return "codex", "Codex"
	}
	return slugify(raw), raw
}

var whitespaceRun = regexp.MustCompile(`\s+`)

func slugify(s string) string {
	return whitespaceRun.ReplaceAllString(strings.ToLower(s), "-")
}

// ── per-tool mutexes ───────────────────────────────────────────────────────

// toolMutexes hands out one lock per tool name.
type toolMutexes struct {
	mu    sync.Mutex
	locks map[string]chan struct{}
}

func newToolMutexes() *toolMutexes {
	return &toolMutexes{locks: map[string]chan struct{}{}}
}

func (t *toolMutexes) get(name string) chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	lock, ok := t.locks[name]
	if !ok {
		lock = make(chan struct{}, 1)
		t.locks[name] = lock
	}
	return lock
}

// acquire reports whether the lock was taken within the timeout. A timeout is
// answered with a refusal rather than by waiting: a queue that never drains is
// how one wedged upstream call becomes an agent that hangs forever.
func (t *toolMutexes) acquire(ctx context.Context, name string, timeout time.Duration) bool {
	lock := t.get(name)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case lock <- struct{}{}:
		return true
	case <-timer.C:
		return false
	case <-ctx.Done():
		return false
	}
}

func (t *toolMutexes) release(name string) {
	select {
	case <-t.get(name):
	default:
	}
}

// ── small helpers ──────────────────────────────────────────────────────────

func isLiveKey(key string) bool { return strings.HasPrefix(key, "sg_live_") }

// encodedByteLen measures arguments the way the ceiling is defined: bytes of
// JSON, with Go's HTML escaping turned off so the count matches what
// JSON.stringify produces. Left on, an argument holding `<` or `&` measures six
// bytes per character instead of one and a payload well inside the limit is
// refused by the Go build and accepted by the Node one.
func encodedByteLen(v any) (int, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return 0, err
	}
	// Encode appends a newline that JSON.stringify does not produce.
	return buf.Len() - 1, nil
}

func keyPrefix(key string) string {
	if len(key) <= 16 {
		return key
	}
	return key[:16]
}

func emptyList(field string) any {
	return map[string]any{field: []any{}}
}

// nullable keeps an unset string as JSON null rather than as "". The debug
// record is read by a person deciding whether a flag was passed, and an empty
// string does not answer that.
func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// toCallToolResult is what goes back to the client.
//
// Content and isError only, which is what the Node proxy returns and therefore
// what every existing install sees. structuredContent from the upstream does
// not survive the hop — see the caveat.
func toCallToolResult(result core.McpCallToolResult) mcp.CallToolResult {
	blocks := make([]mcp.ContentBlock, 0, len(result.Content))
	for _, c := range result.Content {
		block := mcp.ContentBlock{
			Type: c.Type, Text: c.Text, Data: c.Data, MimeType: c.MimeType,
		}
		if c.Resource != nil {
			if raw, err := json.Marshal(c.Resource); err == nil {
				block.Resource = raw
			}
		}
		blocks = append(blocks, block)
	}
	return mcp.CallToolResult{Content: blocks, IsError: result.IsError}
}
