import type { PolicySet } from './core/index.js';
import { readFileSync, existsSync } from 'node:fs';
import { appendFile } from 'node:fs/promises';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';

// Credential written when this machine is paired (~/.solongate/cloud-guard.json).
// Lets every solongate command authenticate after pairing once — no API key
// flag/env needed anywhere. Shape: { apiKey, apiUrl }.
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
export async function fetchCloudPolicy(apiKey: string, apiUrl: string, policyId?: string): Promise<PolicySet> {
  // If no policyId given, list all policies and pick the first one
  let resolvedId = policyId;
  if (!resolvedId) {
    const listRes = await fetch(`${apiUrl}/api/v1/policies`, {
      headers: { 'Authorization': `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!listRes.ok) {
      const body = await listRes.text().catch(() => '');
      throw new Error(`Failed to list policies from cloud (${listRes.status}): ${body}`);
    }
    const listData = await listRes.json() as { policies?: { id: string }[] };
    const policies = listData.policies ?? [];
    if (policies.length === 0) {
      throw new Error('No policies found in cloud. Create one in the dashboard first.');
    }
    resolvedId = policies[0]!.id;
  }

  const url = `${apiUrl}/api/v1/policies/${resolvedId}`;
  const res = await fetch(url, {
    headers: { 'Authorization': `Bearer ${apiKey}` },
    signal: AbortSignal.timeout(10_000),
  });
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Failed to fetch policy from cloud (${res.status}): ${body}`);
  }
  const data = await res.json() as Record<string, unknown>;
  return {
    id: String(data.id ?? 'cloud'),
    name: String(data.name ?? 'Cloud Policy'),
    description: String(data.description ?? ''),
    version: Number(data._version ?? 1),
    rules: (data.rules as PolicySet['rules']) ?? [],
    createdAt: String(data._created_at ?? ''),
    updatedAt: '',
  };
}

/**
 * Fetch a policy's compiled OPA WASM bundle from the cloud. The cloud API
 * compiles every policy version to WASM on save; the proxy evaluates with it
 * (OPA is the sole evaluator — same engine as the airgap product).
 * Returns the WASM bundle bytes, or null if none is available yet.
 */
export async function fetchCloudPolicyWasm(apiKey: string, apiUrl: string, policyId: string): Promise<Uint8Array | null> {
  try {
    const res = await fetch(`${apiUrl}/api/v1/policies/${policyId}/wasm`, {
      headers: { 'Authorization': `Bearer ${apiKey}` },
      signal: AbortSignal.timeout(10_000),
    });
    if (!res.ok) return null;
    return new Uint8Array(await res.arrayBuffer());
  } catch {
    return null;
  }
}

/**
 * Send audit log entry to SolonGate Cloud API.
 * Retries up to 3 times with exponential backoff.
 * Falls back to local file backup if all retries fail.
 */
const AUDIT_MAX_RETRIES = 3;
const AUDIT_LOG_BACKUP_PATH = resolve('.solongate-audit-backup.jsonl');

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

export async function sendAuditLog(
  apiKey: string,
  apiUrl: string,
  entry: AuditLogEntry,
): Promise<void> {
  const url = `${apiUrl}/api/v1/audit-logs`;
  const body = JSON.stringify({
    ...entry,
    agent_id: entry.agent_id,
    agent_name: entry.agent_name,
  });

  for (let attempt = 0; attempt < AUDIT_MAX_RETRIES; attempt++) {
    try {
      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json',
        },
        body,
        signal: AbortSignal.timeout(5_000),
      });
      if (res.ok) return; // success
      if (res.status >= 400 && res.status < 500) {
        // Client error — don't retry, just log
        const resBody = await res.text().catch(() => '');
        process.stderr.write(`[SolonGate] Audit log rejected (${res.status}): ${resBody}\n`);
        return;
      }
      // Server error — retry
    } catch {
      // Network error — retry
    }

    // Exponential backoff: 500ms, 1500ms, 3500ms
    if (attempt < AUDIT_MAX_RETRIES - 1) {
      await new Promise(r => setTimeout(r, 500 * Math.pow(2, attempt)));
    }
  }

  // All retries failed — save to local backup file
  process.stderr.write(`[SolonGate] Audit log failed after ${AUDIT_MAX_RETRIES} retries, saving to local backup.\n`);
  try {
    const line = JSON.stringify({ ...entry, timestamp: new Date().toISOString() }) + '\n';
    appendFile(AUDIT_LOG_BACKUP_PATH, line, 'utf-8').catch((err) => {
      process.stderr.write(`[SolonGate] Audit backup write error: ${err instanceof Error ? err.message : String(err)}\n`);
    });
  } catch (err) {
    process.stderr.write(`[SolonGate] Audit backup write error: ${err instanceof Error ? err.message : String(err)}\n`);
  }
}

/**
 * Default policy — allows everything until cloud policy is fetched.
 * Users add DENY rules from the dashboard to restrict specific tools.
 */
const DEFAULT_POLICY: PolicySet = {
  id: 'default',
  name: 'Default (Allow All)',
  description: 'Allows all tools by default. Add DENY rules from the dashboard to restrict.',
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
 * Without this, any tool call not matching a DENY rule falls through
 * to default-deny, blocking everything — even safe operations.
 * The catch-all ALLOW at priority 9999 lets non-denied calls through.
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
    // Fall back to the dataroom login credential — the zero-config path:
    // log in once (run `solongate`, Accounts panel), then every command works
    // with no API key anywhere.
    const cred = loginCredential();
    if (cred.apiKey) apiKey = cred.apiKey;
  }
  if (!apiKey) {
    throw new Error(
      'Not logged in. Run this once to get started:\n\n' +
      '  solongate\n\n' +
      '  then add your account from the Accounts panel.\n',
    );
  }
  if (!apiKey.startsWith('sg_live_') && !apiKey.startsWith('sg_test_')) {
    // The stored credential is unusable. Nobody types one of these, so the fix
    // is not "correct your key" — it is to pair the machine again, which writes
    // a good one.
    throw new Error(
      'This machine\'s stored credential is not valid. Pair it again:\n\n' +
      '  solongate\n\n' +
      '  then add your account from the Accounts panel.\n',
    );
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
