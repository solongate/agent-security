import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import {
  ListToolsRequestSchema,
  CallToolRequestSchema,
  ListResourcesRequestSchema,
  ListPromptsRequestSchema,
  GetPromptRequestSchema,
  ReadResourceRequestSchema,
  ListResourceTemplatesRequestSchema,
} from '@modelcontextprotocol/sdk/types.js';
import { createServer as createHttpServer } from 'node:http';
import { resolve, join } from 'node:path';
import { mkdirSync, appendFileSync } from 'node:fs';
import { SolonGate } from './sdk/solongate.js';
import { guessPermission } from './core/index.js';
import type { McpCallToolResult } from './core/index.js';
import {
  scanResponse,
  RESPONSE_WARNING_MARKER,
} from './core/index.js';
import type { ProxyConfig } from './config.js';
import { writeAuditEntry } from './config.js';
import { PolicySyncManager } from './sync.js';

const log = (...args: unknown[]) => process.stderr.write(`[SolonGate] ${args.map(String).join(' ')}\n`);
const TEXT_ENCODER = new TextEncoder();

/**
 * Per-tool mutex with timeout to serialize same-tool calls for rate limiter accuracy
 * while allowing different tools to run in parallel.
 */
class Mutex {
  private queue: Array<() => void> = [];
  private locked = false;

  async acquire(timeoutMs = 30_000): Promise<void> {
    if (!this.locked) {
      this.locked = true;
      return;
    }
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        const idx = this.queue.indexOf(onReady);
        if (idx !== -1) this.queue.splice(idx, 1);
        reject(new Error('Mutex acquire timeout'));
      }, timeoutMs);

      const onReady = () => {
        clearTimeout(timer);
        resolve();
      };
      this.queue.push(onReady);
    });
  }

  release(): void {
    const next = this.queue.shift();
    if (next) {
      next();
    } else {
      this.locked = false;
    }
  }
}

/**
 * Manages per-tool mutexes. Each tool gets its own mutex so different tools
 * can execute in parallel while same-tool calls are serialized.
 */
class ToolMutexMap {
  private mutexes = new Map<string, Mutex>();

  get(toolName: string): Mutex {
    let mutex = this.mutexes.get(toolName);
    if (!mutex) {
      mutex = new Mutex();
      this.mutexes.set(toolName, mutex);
    }
    return mutex;
  }
}

/**
 * SolonGate MCP Proxy.
 *
 * Sits between an MCP client (Claude) and an upstream MCP server.
 * Intercepts all tool calls through the SolonGate security pipeline.
 *
 * Architecture:
 *   Claude ──(stdio|http)──> Proxy Server ──(stdio|sse|http)──> Upstream MCP Server
 *                                │
 *                           [SolonGate]
 *                           rate limit
 *                           policy eval
 *                           audit log
 */
export class SolonGateProxy {
  private config: ProxyConfig;
  private readonly gate: SolonGate;
  private client: Client | null = null;
  private server: Server | null = null;
  private readonly toolMutexes = new ToolMutexMap();
  private syncManager: PolicySyncManager | null = null;
  private upstreamTools: Array<{
    name: string;
    description?: string;
    inputSchema: Record<string, unknown>;
  }> = [];
  /** Agent identity for trust map — resolved from CLI flag, HTTP headers, or MCP clientInfo */
  private agentId: string | null = null;
  private agentName: string | null = null;
  /** Per-request sub-agent info from HTTP headers (transient, overwritten per request) */
  private httpSubAgent: { subAgentId: string; subAgentName: string } | null = null;

  constructor(config: ProxyConfig) {
    this.config = config;

    // Set agent identity from --agent-name flag (for custom bots without MCP clientInfo)
    if (config.agentName) {
      this.agentName = config.agentName;
      this.agentId = config.agentName.toLowerCase().replace(/\s+/g, '-');
    }

    // Initialize SolonGate with the configured policy.
    // Use a test key to prevent SDK from reading SOLONGATE_API_KEY from env —
    // the proxy handles all cloud features (audit logs, policy fetch, tool registration)
    // itself, so the SDK must not duplicate them.
    this.gate = new SolonGate({
      name: config.name ?? 'solongate-proxy',
      apiKey: 'sg_test_proxy_internal_00000000',
      policySet: config.policy,
      config: {
        validateSchemas: true,
        verboseErrors: config.verbose ?? false,
        rateLimitPerTool: config.rateLimitPerTool,
        globalRateLimitPerMinute: config.globalRateLimit,
      },
    });

    const warnings = this.gate.getWarnings();
    for (const w of warnings) {
      log('WARNING:', w);
    }
  }

  /** Normalize well-known MCP client names to display-friendly agent identities */
  private normalizeAgentName(raw: string): { id: string; name: string } {
    const lower = raw.toLowerCase();
    // Claude Code / Claude Desktop
    if (lower.includes('claude-code') || lower === 'claude code') return { id: 'claude-code', name: 'Claude Code' };
    if (lower.includes('claude')) return { id: 'claude-desktop', name: 'Claude Desktop' };
    // Antigravity CLI (`agy`)
    if (lower.includes('antigravity') || lower === 'agy') return { id: 'antigravity', name: 'Antigravity' };
    // Codex CLI (`codex`)
    if (lower.includes('codex')) return { id: 'codex', name: 'Codex' };
    // Default: use raw name
    return { id: raw.toLowerCase().replace(/\s+/g, '-'), name: raw };
  }

  /** Extract sub-agent identity from MCP _meta field */
  private extractSubAgent(request: unknown): { subAgentId: string; subAgentName: string } | null {
    const meta = (request as any)?.params?._meta;
    if (meta && typeof meta === 'object') {
      const solonMeta = (meta as Record<string, unknown>)['io.solongate/agent'];
      if (solonMeta && typeof solonMeta === 'object') {
        const agent = solonMeta as Record<string, unknown>;
        const id = agent.id ? String(agent.id) : null;
        if (id) return { subAgentId: id, subAgentName: agent.name ? String(agent.name) : id };
      }
    }
    return null;
  }

  /**
   * Start the proxy: connect to upstream, then serve downstream.
   */
  async start(): Promise<void> {
    log('Starting SolonGate Proxy...');

    // Step 0: THE POLICY IS THIS MACHINE'S FILE.
    //
    // There was a licence check here — /auth/me, refusing to start on a 401, a 403
    // or an unreachable service — and then a policy fetched from that service with
    // the file as a fallback. Both are gone with the service, so the file is not a
    // fallback: it is the policy, and parseArgs has already resolved which one.
    // Reload policy into SolonGate engine after cloud fetch
    this.gate.loadPolicy(this.config.policy);

    // NO OPA WASM. A bundle made this a NIST SP 800-207 PDP, and a service was what
    // compiled one per policy version; with none to fetch, the engine decides with
    // the guard's own evaluator — which is what decided on every cold start anyway.
    log(`Deciding with the ${this.gate.getEvaluatorMode()} evaluator.`);

    log(`Policy: ${this.config.policy.name} (${this.config.policy.rules.length} rules)`);
    const transport = this.config.upstream.transport ?? 'stdio';
    if (transport === 'stdio') {
      log(`Upstream: [stdio] ${this.config.upstream.command} ${(this.config.upstream.args ?? []).join(' ')}`);
    } else {
      log(`Upstream: [${transport}] ${this.config.upstream.url}`);
    }

    // Step 1: Connect to upstream MCP server as a client
    await this.connectUpstream();

    // Step 2: Discover upstream tools
    await this.discoverTools();

    // Step 3: watch the policy file
    this.startPolicySync();

    // Step 4: Create downstream server and wire up handlers
    this.createServer();

    // Step 5: Start serving downstream (stdio or HTTP)
    await this.serve();
  }

  /**
   * Connect to the upstream MCP server.
   * Supports stdio (child process), SSE, and StreamableHTTP transports.
   */
  private async connectUpstream(): Promise<void> {
    this.client = new Client(
      { name: 'solongate-proxy-client', version: '0.1.0' },
      { capabilities: {} },
    );

    const upstreamTransport = this.config.upstream.transport ?? 'stdio';

    switch (upstreamTransport) {
      case 'sse': {
        if (!this.config.upstream.url) throw new Error('--upstream-url required for SSE transport');
        const transport = new SSEClientTransport(new URL(this.config.upstream.url));
        await this.client.connect(transport);
        break;
      }
      case 'http': {
        if (!this.config.upstream.url) throw new Error('--upstream-url required for HTTP transport');
        const transport = new StreamableHTTPClientTransport(new URL(this.config.upstream.url));
        await this.client.connect(transport);
        break;
      }
      case 'stdio':
      default: {
        const transport = new StdioClientTransport({
          command: this.config.upstream.command,
          args: this.config.upstream.args,
          env: this.config.upstream.env,
          cwd: this.config.upstream.cwd,
          stderr: 'pipe',
        });
        await this.client.connect(transport);
        break;
      }
    }

    log(`Connected to upstream server (${upstreamTransport})`);
  }

  /**
   * Discover tools from the upstream server.
   */
  private async discoverTools(): Promise<void> {
    if (!this.client) throw new Error('Client not connected');

    const result = await this.client.listTools();
    this.upstreamTools = result.tools.map((t) => ({
      name: t.name,
      description: t.description,
      inputSchema: t.inputSchema as Record<string, unknown>,
    }));

    log(`Discovered ${this.upstreamTools.length} tools from upstream:`);
    for (const tool of this.upstreamTools) {
      log(`  - ${tool.name}: ${tool.description ?? '(no description)'}`);
    }
  }

  /**
   * Create the downstream MCP server with proxied handlers.
   */
  private createServer(): void {
    this.server = new Server(
      {
        name: this.config.name ?? 'solongate-proxy',
        version: '0.1.0',
      },
      {
        capabilities: {
          tools: {},
          // Pass through resources and prompts if upstream supports them
          resources: {},
          prompts: {},
        },
      },
    );

    // Capture agent identity from MCP clientInfo after initialize handshake
    // --agent-name flag takes priority (set by init per-tool config)
    // clientInfo is only used if --agent-name was NOT provided
    this.server.oninitialized = () => {
      if (this.server) {
        const clientVersion = this.server.getClientVersion();
        log(`MCP clientInfo raw: ${JSON.stringify(clientVersion)}`);

        // Debug: write agent detection info to file for troubleshooting
        try {
          const debugInfo = {
            timestamp: new Date().toISOString(),
            clientInfo: clientVersion,
            agentNameFlag: this.config.agentName ?? null,
            resolvedAgentId: this.agentId,
            resolvedAgentName: this.agentName,
            pid: process.pid,
          };
          const debugDir = resolve('.solongate');
          mkdirSync(debugDir, { recursive: true });
          appendFileSync(join(debugDir, '.debug-proxy'), JSON.stringify(debugInfo) + '\n');
        } catch {}

        if (clientVersion?.name && !this.config.agentName) {
          // Only use clientInfo if --agent-name was not explicitly set
          const normalized = this.normalizeAgentName(clientVersion.name);
          this.agentId = normalized.id;
          this.agentName = normalized.name;
          log(`Agent identified from MCP clientInfo: ${this.agentName} (raw: ${clientVersion.name})`);
        } else if (this.config.agentName) {
          log(`Agent identity from --agent-name flag: ${this.agentName} (clientInfo: ${clientVersion?.name || 'none'})`);
        }
      }
    };

    // --- tools/list: Return upstream tools (unmodified) ---
    this.server.setRequestHandler(ListToolsRequestSchema, async () => {
      return { tools: this.upstreamTools };
    });

    // --- tools/call: Intercept through SolonGate pipeline ---
    // Per-tool mutex: same tool serialized for rate limiter accuracy,
    // different tools run in parallel for maximum throughput
    const MAX_ARGUMENT_SIZE = 1024 * 1024; // 1MB max argument payload
    const MUTEX_TIMEOUT_MS = 30_000; // 30s timeout to prevent deadlocks

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      // Extract sub-agent identity from MCP _meta field or HTTP headers
      const subAgent = this.extractSubAgent(request) || this.httpSubAgent;

      // Request size validation (use TextEncoder for accurate byte count)
      const argsSize = TEXT_ENCODER.encode(JSON.stringify(args ?? {})).length;
      if (argsSize > MAX_ARGUMENT_SIZE) {
        log(`DENY: ${name} — payload size ${argsSize} exceeds limit ${MAX_ARGUMENT_SIZE}`);
        return {
          content: [{ type: 'text' as const, text: `Request payload too large (${Math.round(argsSize / 1024)}KB > ${Math.round(MAX_ARGUMENT_SIZE / 1024)}KB limit)` }],
          isError: true,
        };
      }

      log(`Tool call: ${name}`);

      // Per-tool mutex: serialize calls to the same tool for rate limiter accuracy
      const mutex = this.toolMutexes.get(name);
      try {
        await mutex.acquire(MUTEX_TIMEOUT_MS);
      } catch {
        log(`DENY: ${name} — mutex timeout (${MUTEX_TIMEOUT_MS}ms)`);
        return {
          content: [{ type: 'text' as const, text: `Tool call queued too long (>${MUTEX_TIMEOUT_MS / 1000}s). Try again.` }],
          isError: true,
        };
      }
      const startTime = Date.now();
      try {
        // Run through the SolonGate security pipeline
        const result = await this.gate.executeToolCall(
          { name, arguments: args ?? {} },
          async (params) => {
            // This is the actual upstream call — only reached if SolonGate allows it
            if (!this.client) throw new Error('Upstream client disconnected');

            const upstreamResult = await this.client.callTool({
              name: params.name,
              arguments: params.arguments as Record<string, unknown>,
            });

            // Convert to McpCallToolResult format
            return upstreamResult as unknown as McpCallToolResult;
          },
        );

        const decision = result.isError ? 'DENY' as const : 'ALLOW' as const;
        const evaluationTimeMs = Date.now() - startTime;
        log(`Result: ${decision} (${evaluationTimeMs}ms)`);

        // The record goes to THIS MACHINE's audit trail — the same file the guard and
        // the hooks append to, so a machine has one log rather than two. It used to
        // be POSTed, and only when a live key was configured, which meant a machine
        // without one recorded nothing at all.
        {
          // Extract clean reason and matched rule from result
          let reason = 'allowed';
          let matchedRule: string | undefined;
          if (result.isError) {
            const rawText = (result.content[0] as { text?: string })?.text ?? 'denied';
            try {
              const parsed = JSON.parse(rawText);
              reason = parsed.message ?? rawText;
              // Extract rule ID from message like 'Matched rule "deny-shell": ...'
              const ruleMatch = reason.match(/^Matched rule "([^"]+)":/);
              if (ruleMatch) matchedRule = ruleMatch[1];
            } catch {
              reason = rawText;
            }
          }

          writeAuditEntry({
            tool: name,
            arguments: (args ?? {}) as Record<string, unknown>,
            decision,
            reason,
            permission: guessPermission(name),
            matchedRule,
            evaluationTimeMs,
            agent_id: this.agentId ?? undefined,
            agent_name: this.agentName ?? undefined,
            sub_agent_id: subAgent?.subAgentId,
            sub_agent_name: subAgent?.subAgentName,
          });
        }

        // Return the result (either upstream response or SolonGate denial)
        return {
          content: [...result.content] as Array<{ type: 'text'; text: string }>,
          isError: result.isError,
        };
      } finally {
        mutex.release();
      }
    });

    // --- resources/list: Pass through to upstream ---
    this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
      if (!this.client) return { resources: [] };
      try {
        return await this.client.listResources();
      } catch {
        return { resources: [] };
      }
    });

    // --- resources/read: Validate URI before passing to upstream ---
    this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
      if (!this.client) throw new Error('Upstream client disconnected');

      const uri = request.params.uri;

      // Input guard removed — policy rules handle all blocking

      log(`Resource read: ${uri}`);
      const resourceResult = await this.client.readResource({ uri });

      // Scan resource content for indirect prompt injection
      if (resourceResult.contents) {
        for (const content of resourceResult.contents) {
          if ('text' in content && typeof content.text === 'string') {
            const scan = scanResponse(content.text);
            if (!scan.safe) {
              const threats = scan.threats.map((t) => t.type).join(', ');
              log(`WARNING resource response: ${uri} — ${threats}`);
              (content as { text: string }).text =
                `${RESPONSE_WARNING_MARKER}\n\n${content.text}`;
            }
          }
        }
      }

      return resourceResult;
    });

    // --- resources/templates/list: Pass through to upstream ---
    this.server.setRequestHandler(ListResourceTemplatesRequestSchema, async () => {
      if (!this.client) return { resourceTemplates: [] };
      try {
        return await this.client.listResourceTemplates();
      } catch {
        return { resourceTemplates: [] };
      }
    });

    // --- prompts/list: Pass through to upstream ---
    this.server.setRequestHandler(ListPromptsRequestSchema, async () => {
      if (!this.client) return { prompts: [] };
      try {
        return await this.client.listPrompts();
      } catch {
        return { prompts: [] };
      }
    });

    // --- prompts/get: Validate arguments before passing to upstream ---
    this.server.setRequestHandler(GetPromptRequestSchema, async (request) => {
      if (!this.client) throw new Error('Upstream client disconnected');

      const args = request.params.arguments;

      log(`Prompt get: ${request.params.name}`);
      const promptResult = await this.client.getPrompt({
        name: request.params.name,
        arguments: args,
      });

      // Scan prompt response messages for indirect prompt injection
      if (promptResult.messages) {
        for (const msg of promptResult.messages) {
          if (msg.content && typeof msg.content === 'object' && 'text' in msg.content && typeof msg.content.text === 'string') {
            const scan = scanResponse(msg.content.text);
            if (!scan.safe) {
              const threats = scan.threats.map((t) => t.type).join(', ');
              log(`WARNING prompt response: ${request.params.name} — ${threats}`);
              (msg.content as { text: string }).text =
                `${RESPONSE_WARNING_MARKER}\n\n${msg.content.text}`;
            }
          }
        }
      }

      return promptResult;
    });
  }

  /**
   * Start bidirectional policy sync between local JSON file and cloud dashboard.
   *
   * - Watches local policy.json for changes → pushes to cloud API
   * - Polls cloud API for dashboard changes → writes to local policy.json
   * - Version number determines which is newer (higher wins, cloud wins on tie)
   */

  /**
   * Extract protected filenames from policy DENY rules (filenameConstraints.denied).
   */
  /**
   * Watch the policy file and reload the gate when it changes.
   *
   * It used to poll a service for a newer policy and push a local edit back to one,
   * and re-fetch a recompiled WASM bundle on every reload. What is left is the half
   * about this machine, and it matters more than it did: the file is the only
   * source, so somebody editing it expects the proxy to follow without a restart.
   */
  private startPolicySync(): void {
    if (!this.config.policyPath) return;

    this.syncManager = new PolicySyncManager({
      localPath: this.config.policyPath,
      initialPolicy: this.config.policy,
      onPolicyUpdate: (policy) => {
        this.config.policy = policy;
        this.gate.loadPolicy(policy);
        log(`Policy reloaded: ${policy.name} v${policy.version} (${policy.rules.length} rules)`);
      },
    });

    this.syncManager.start();
    log(`Watching ${this.config.policyPath} for changes.`);
  }

  /**
   * Start serving downstream.
   * If --port is set, serves via StreamableHTTP on that port.
   * Otherwise, serves on stdio (default for Claude Code / etc).
   */
  private async serve(): Promise<void> {
    if (!this.server) throw new Error('Server not created');

    if (this.config.port) {
      // HTTP mode: serve via StreamableHTTP
      const httpTransport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => crypto.randomUUID(),
      });
      await this.server.connect(httpTransport);

      const httpServer = createHttpServer(async (req, res) => {
        // Only handle /mcp path
        if (req.url === '/mcp' || req.url?.startsWith('/mcp?')) {
          // Extract agent identity from HTTP headers
          if (!this.agentId) {
            const headerAgentId = req.headers['x-agent-id'] as string | undefined;
            const headerAgentName = req.headers['x-agent-name'] as string | undefined;
            if (headerAgentId) {
              this.agentId = headerAgentId;
              this.agentName = headerAgentName || headerAgentId;
              log(`Agent identified from HTTP headers: ${this.agentName} (${this.agentId})`);
            }
          }
          // Extract sub-agent identity from HTTP headers (per-request, overwritten)
          const subAgentId = req.headers['x-sub-agent-id'] as string | undefined;
          const subAgentName = req.headers['x-sub-agent-name'] as string | undefined;
          this.httpSubAgent = subAgentId
            ? { subAgentId, subAgentName: subAgentName || subAgentId }
            : null;
          await httpTransport.handleRequest(req, res);
        } else if (req.url === '/health') {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'healthy', proxy: this.config.name ?? 'solongate-proxy' }));
        } else {
          res.writeHead(404);
          res.end('Not found. Use /mcp for MCP protocol or /health for health check.');
        }
      });

      httpServer.listen(this.config.port, () => {
        log(`Proxy is live on http://localhost:${this.config.port}/mcp`);
        log('All tool calls are now protected by SolonGate.');
      });
    } else {
      // stdio mode (default)
      const transport = new StdioServerTransport();
      await this.server.connect(transport);

      log('Proxy is live. All tool calls are now protected by SolonGate.');
      log('Waiting for requests...');

    }
  }
}
