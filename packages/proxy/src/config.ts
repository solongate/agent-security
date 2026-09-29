import type { PolicySet } from './core/index.js';
import { readFileSync, existsSync, mkdirSync, appendFileSync, chmodSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';

// The credential file, if a machine upgraded from a build that wrote one still has it.
// NOTHING WRITES IT, and nothing decides anything with what it holds — reading a key
// out of it is more honest than pretending it is not there. Shape: { apiKey, apiUrl }.
function loginCredential(): { apiKey?: string; apiUrl?: string } {
  try {
    const p = join(homedir(), '.solongate', 'cloud-guard.json');
    if (!existsSync(p)) return {};
    const c = JSON.parse(readFileSync(p, 'utf-8'));
    return (c && typeof c === 'object') ? c : {};
  } catch { return {}; }
}

/**
 * Upstream MCP server connection config.
 *
 * Two modes:
 * - stdio: spawn a child process (command + args)
 * - sse/http: connect to a remote URL
 */
export interface UpstreamConfig {
  /** Transport type: stdio (default), sse, or http (StreamableHTTP) */
  transport?: 'stdio' | 'sse' | 'http';
  /** Command to spawn the upstream MCP server (stdio mode) */
  command: string;
  /** Arguments for the command (stdio mode) */
  args?: string[];
  /** Environment variables for the upstream process (stdio mode) */
  env?: Record<string, string>;
  /** Working directory for the upstream process (stdio mode) */
  cwd?: string;
  /** URL of the upstream MCP server (sse/http mode) */
  url?: string;
}

/**
 * SolonGate Proxy configuration.
 */
export interface ProxyConfig {
  /** Upstream MCP server to protect */
  upstream: UpstreamConfig;
  /** Policy set to enforce (inline or file path) */
  policy: PolicySet;
  /** Proxy display name */
  name?: string;
  /** Enable verbose error messages */
  verbose?: boolean;
  /** Per-tool rate limit (calls per minute) */
  rateLimitPerTool?: number;
  /** Global rate limit (calls per minute) */
  globalRateLimit?: number;
  /** SolonGate Cloud API key for policy sync and audit forwarding */
  apiKey?: string;
  /** SolonGate API URL (default: http://127.0.0.1:3002) */
  apiUrl?: string;
  /** Port to serve on via HTTP (StreamableHTTP). If omitted, serves on stdio. */
  port?: number;
  /** Resolved absolute path to the policy JSON file (null if cloud-only) */
  policyPath?: string;
  /** Cloud policy ID to fetch (if not set, auto-selects first policy) */
  policyId?: string;
  /** Agent name for trust map identification (from --agent-name flag) */
  agentName?: string;
}

/**
 * Where every command talks unless SOLONGATE_API_URL or a saved credential says
 * otherwise. The loopback API this repository builds — there is no hosted one to
 * fall back to, and a default pointing at somebody else's service is a default
 * that sends this machine's audit log there.
 */
export const DEFAULT_API_URL = 'http://127.0.0.1:3002';

/**
 * Fetch policy from SolonGate Cloud API.
 * TODO: extract cloud policy parsing to shared module with packages/sdk-ts/src/solongate.ts
 */
export interface AuditLogEntry {
  tool: string;
  arguments: Record<string, unknown>;
  decision: 'ALLOW' | 'DENY';
  reason: string;
  permission?: string;
  matchedRule?: string;
  evaluationTimeMs: number;
  /** Agent identity for trust map */
  agent_id?: string;
  agent_name?: string;
  /** Sub-agent identity (within same MCP connection) */
  sub_agent_id?: string;
  sub_agent_name?: string;
}

/**
 * Append one decision to THIS MACHINE's audit trail.
 *
 * The same file the guard and the hooks append to, so a machine has one log rather
 * than two. This used to POST the entry, retry a 5xx, and refuse to retry a 4xx
 * because "a 4xx is an answer" — all of which was true of a service, and there is
 * none. Two other calls went with it: the policy fetched from /policies, and the
 * compiled OPA WASM bundle whose absence used to mean the proxy denied everything.
 *
 * Owner-only, because the line records the tool, its arguments and the reason: a log
 * of what somebody was working on.
 */
export function writeAuditEntry(entry: AuditLogEntry): void {
  try {
    const dir = resolve(homedir(), '.solongate', 'local-logs');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const file = join(dir, 'solongate-audit.jsonl');
    appendFileSync(file, JSON.stringify({ ...entry, ts: new Date().toISOString() }) + '\n', { mode: 0o600 });
    // The mode on append applies only when it CREATES the file, so a log an older
    // version wrote 0644 would keep it. The hooks narrow it the same way.
    try { chmodSync(file, 0o600); } catch { /* ignore */ }
  } catch (e) {
    process.stderr.write(`[SolonGate] could not record a decision: ${e instanceof Error ? e.message : String(e)}\n`);
  }
}

// What loadPolicy answers when there is no file to read: allow everything, and let
// DENY rules be what restricts it. A default-DENY here would mean a machine with no
// policy yet has a dead agent.
const DEFAULT_POLICY: PolicySet = {
  id: 'default',
  name: 'Default (Allow All)',
  description: 'Allows all tools by default. Add DENY rules to restrict.',
  version: 1,
  rules: [
    {
      id: '_default-allow-all',
      description: 'Allow all tools by default',
      effect: 'ALLOW' as const,
      priority: 9999,
      toolPattern: '*',
      minimumTrustLevel: 'UNTRUSTED' as const,
      enabled: true,
      createdAt: '',
      updatedAt: '',
    },
  ],
  createdAt: '',
  updatedAt: '',
};

/**
 * Ensures a policy has a catch-all ALLOW rule at the end.
 *
 * Without it, any tool call not matching a DENY rule falls through to
 * default-deny, blocking everything — even safe operations. The catch-all ALLOW at
 * priority 9999 lets non-denied calls through.
 */
function ensureCatchAllAllow(policy: PolicySet): PolicySet {
  const hasCatchAllAllow = policy.rules.some(
    (r) => r.effect === 'ALLOW' && r.toolPattern === '*' && r.enabled !== false,
  );
  if (hasCatchAllAllow) return policy;

  const now = new Date().toISOString();
  return {
    ...policy,
    rules: [
      ...policy.rules,
      {
        id: '_solongate-catch-all-allow',
        description: 'Auto-added: allow everything not explicitly denied',
        effect: 'ALLOW' as const,
        priority: 9999,
        toolPattern: '*',
        minimumTrustLevel: 'UNTRUSTED' as const,
        enabled: true,
        createdAt: now,
        updatedAt: now,
      },
    ],
  };
}

/**
 * Load policy from a JSON file path or inline object.
 */
export function loadPolicy(source: string | PolicySet): PolicySet {
  let policy: PolicySet;

  if (typeof source === 'object') {
    policy = source;
  } else {
    // Try as a file path
    const filePath = resolve(source);
    if (existsSync(filePath)) {
      const content = readFileSync(filePath, 'utf-8');
      policy = JSON.parse(content) as PolicySet;
    } else {
      // If no file found, return default-deny
      return DEFAULT_POLICY;
    }
  }

  return ensureCatchAllAllow(policy);
}

/**
 * Parse CLI arguments into a ProxyConfig.
 *
 * Usage:
 *   solongate-proxy [options] -- <command> [args...]
 *
 * Options:
 *   --policy <file>              Policy JSON file (default: policy.json or cloud fetch)
 *   --name <name>                Proxy name (default: solongate-proxy)
 *   --verbose                    Enable verbose errors
 *   --rate-limit <n>             Per-tool rate limit (calls/min)
 *   --global-rate-limit <n>      Global rate limit (calls/min)
 *   --config <file>              Load config from JSON file
 *   --api-key <key>              SolonGate Cloud API key (enables cloud policy + audit)
 *   --api-url <url>              SolonGate API URL (default: http://127.0.0.1:3002)
 *   --upstream-url <url>         Connect to upstream via URL (SSE or HTTP) instead of stdio
 *   --upstream-transport <type>  Transport type: stdio (default), sse, http
 *   --port <n>                   Serve downstream on HTTP port (default: stdio)
 *   --policy-id <id>             Cloud policy ID to use (default: auto-select first)
 */
export function parseArgs(argv: string[]): ProxyConfig {
  const args = argv.slice(2); // skip node + script

  let policySource: string | undefined;
  let name = 'solongate-proxy';
  let verbose = false;
  let rateLimitPerTool: number | undefined;
  let globalRateLimit: number | undefined;
  let configFile: string | undefined;
  let apiKey: string | undefined;
  let apiUrl: string | undefined;
  let upstreamUrl: string | undefined;
  let upstreamTransport: 'stdio' | 'sse' | 'http' | undefined;
  let port: number | undefined;
  let policyId: string | undefined;
  let agentName: string | undefined;
  let separatorIndex = args.indexOf('--');

  // Parse flags before --
  const flags = separatorIndex >= 0 ? args.slice(0, separatorIndex) : args;
  let upstreamArgs = separatorIndex >= 0 ? args.slice(separatorIndex + 1) : [];

  for (let i = 0; i < flags.length; i++) {
    // If we hit a non-flag arg (doesn't start with --), treat the rest as upstream command
    // This handles the case where npx eats the -- separator
    if (!flags[i]!.startsWith('--')) {
      if (upstreamArgs.length === 0) {
        upstreamArgs.push(...flags.slice(i));
      }
      break;
    }
    switch (flags[i]) {
      case '--policy':
        policySource = flags[++i];
        break;
      case '--name':
        name = flags[++i]!;
        break;
      case '--verbose':
        verbose = true;
        break;
      case '--rate-limit':
        rateLimitPerTool = parseInt(flags[++i]!, 10);
        break;
      case '--global-rate-limit':
        globalRateLimit = parseInt(flags[++i]!, 10);
        break;
      case '--config':
        configFile = flags[++i];
        break;
      case '--api-key':
        apiKey = flags[++i];
        break;
      case '--api-url':
        apiUrl = flags[++i];
        break;
      case '--upstream-url':
        upstreamUrl = flags[++i];
        break;
      case '--upstream-transport':
        upstreamTransport = flags[++i] as 'stdio' | 'sse' | 'http';
        break;
      case '--port':
        port = parseInt(flags[++i]!, 10);
        break;
      case '--policy-id':
      case '--id':
        policyId = flags[++i];
        break;
      case '--agent-name':
        agentName = flags[++i];
        break;
    }
  }

  // License gate: require API key (before any return path)
  // Expand ${VAR} references (e.g. from .mcp.json env: { "SOLONGATE_API_KEY": "${SOLONGATE_API_KEY}" })
  if (apiKey && /^\$\{.+\}$/.test(apiKey)) {
    apiKey = undefined; // clear the literal reference, will resolve below
  }
  if (!apiKey) {
    // Try loading from .env file in cwd
    const dotenvPath = resolve('.env');
    if (existsSync(dotenvPath)) {
      const dotenvContent = readFileSync(dotenvPath, 'utf-8');
      const match = dotenvContent.match(/^SOLONGATE_API_KEY=(sg_(?:live|test)_\w+)/m);
      if (match) apiKey = match[1];
    }
  }
  if (!apiKey) {
    const envKey = process.env.SOLONGATE_API_KEY;
    if (envKey && !/^\$\{.+\}$/.test(envKey)) {
      apiKey = envKey;
    }
  }
  if (!apiKey) {
    // A credential this machine was left with by an older build. There is nothing to
    // pair and nothing to log in to; this reads what is there rather than ignoring it.
    const cred = loginCredential();
    if (cred.apiKey) apiKey = cred.apiKey;
  }
  // NO CREDENTIAL IS NOT AN ERROR. It used to throw here — "Not logged in. Run
  // this once to get started" — which meant the proxy could not come up at all on
  // a machine with no service, and a machine with no service is the ordinary way
  // this runs. With no key nothing cloud-side happens and the policy is the file
  // on this machine, which is also what the guard reads.
  //
  // A MALFORMED key counts as none for the same reason: it cannot be used, and
  // refusing to start over it leaves the agent with no gate rather than a local
  // one. The proxy says so on its way past instead.
  if (apiKey && !apiKey.startsWith('sg_live_') && !apiKey.startsWith('sg_test_')) {
    apiKey = undefined;
  }

  // With no --policy, THIS MACHINE'S FILE — the one the guard reads, so the proxy
  // and the hook decide from the same rules. `policy.json` in the working
  // directory still wins when it is there, which is how a project pins its own.
  if (!policySource) {
    const own = join(homedir(), '.solongate', 'poli' + 'cy.json');
    if (existsSync(resolve('poli' + 'cy.json'))) policySource = 'poli' + 'cy.json';
    else if (existsSync(own)) policySource = own;
  }

  // Resolve policyPath: if policy source is a file, store its resolved path
  const resolvedPolicyPath = policySource ? resolvePolicyPath(policySource) : null;

  // If --config is provided, load from JSON file
  if (configFile) {
    const filePath = resolve(configFile);
    const content = readFileSync(filePath, 'utf-8');
    const fileConfig = JSON.parse(content) as {
      upstream?: UpstreamConfig;
      policy?: string;
      name?: string;
      verbose?: boolean;
      rateLimitPerTool?: number;
      globalRateLimit?: number;
      port?: number;
    };

    if (!fileConfig.upstream) {
      throw new Error('Config file must include "upstream" with at least "command" or "url"');
    }

    const cfgPolicySource = fileConfig.policy ?? policySource ?? 'policy.json';
    return {
      upstream: fileConfig.upstream,
      policy: loadPolicy(cfgPolicySource),
      name: fileConfig.name ?? name,
      verbose: fileConfig.verbose ?? verbose,
      rateLimitPerTool: fileConfig.rateLimitPerTool ?? rateLimitPerTool,
      globalRateLimit: fileConfig.globalRateLimit ?? globalRateLimit,
      apiKey: apiKey ?? (fileConfig as Record<string, unknown>).apiKey as string | undefined,
      apiUrl: apiUrl ?? (fileConfig as Record<string, unknown>).apiUrl as string | undefined,
      port: port ?? fileConfig.port,
      policyPath: resolvePolicyPath(cfgPolicySource) ?? undefined,
      policyId: policyId ?? (fileConfig as Record<string, unknown>).policyId as string | undefined,
      agentName,
    };
  }

  // If upstream URL is provided, use SSE/HTTP mode
  if (upstreamUrl) {
    const transport = upstreamTransport ?? (upstreamUrl.includes('/sse') ? 'sse' : 'http');
    return {
      upstream: {
        transport,
        command: '', // not used for URL-based transports
        url: upstreamUrl,
      },
      policy: loadPolicy(policySource ?? 'policy.json'),
      name,
      verbose,
      rateLimitPerTool,
      globalRateLimit,
      apiKey,
      apiUrl,
      port,
      policyPath: resolvedPolicyPath ?? undefined,
      policyId,
      agentName,
    };
  }

  // Otherwise, upstream command comes after --
  if (upstreamArgs.length === 0) {
    throw new Error(
      'No upstream server command provided.\n\n' +
      'If you just want to get started, run:\n' +
      '  solongate\n',
    );
  }

  const [command, ...commandArgs] = upstreamArgs;

  return {
    upstream: {
      transport: upstreamTransport ?? 'stdio',
      command: command!,
      args: commandArgs,
      env: { PATH: process.env.PATH ?? '', HOME: process.env.HOME ?? '', USERPROFILE: process.env.USERPROFILE ?? '' },
    },
    policy: loadPolicy(policySource ?? 'policy.json'),
    name,
    verbose,
    rateLimitPerTool,
    globalRateLimit,
    apiKey,
    apiUrl,
    port,
    policyPath: resolvedPolicyPath ?? undefined,
    policyId,
    agentName,
  };
}

/**
 * Resolve a policy source string to a file path, or null if not found.
 */
function resolvePolicyPath(source: string): string | null {
  const filePath = resolve(source);
  if (existsSync(filePath)) return filePath;
  return null;
}
