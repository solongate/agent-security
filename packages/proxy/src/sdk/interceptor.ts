import type {
  ExecutionRequest,
  ExecutionResult,
  McpCallToolParams,
  McpCallToolResult,
  ResponseScanConfig,
} from '../core/index.js';
import {
  Permission,
  guessPermission,
  PolicyDeniedError,
  RateLimitError,
  createDeniedToolResult,
  createSecurityContext,
  scanResponse,
  RESPONSE_WARNING_MARKER,
  DEFAULT_RESPONSE_SCAN_CONFIG,
} from '../core/index.js';
import type { PolicyEngine } from '../policy-engine/index.js';
import type { TokenIssuer } from './token-issuer.js';
import type { ServerVerifier } from './server-verifier.js';
import type { RateLimiter } from './rate-limiter.js';
import { randomUUID } from 'node:crypto';

// --- Exfiltration Chain Tracker ---

/** Tools that read/access data. */
const DATA_SOURCE_TOOLS = new Set([
  'file_read', 'db_query', 'read_file', 'readFile',
  'database_query', 'sql_query', 'get_secret', 'read_resource',
]);

/** Tools that can send data externally. */
const DATA_SINK_TOOLS = new Set([
  'web_fetch', 'shell_exec', 'http_request', 'send_email',
  'fetch', 'curl', 'wget', 'write_file', 'writeFile',
]);

interface ToolCallRecord {
  readonly name: string;
  readonly timestamp: number;
}

const CHAIN_WINDOW_SIZE = 10;
const CHAIN_TIME_WINDOW_MS = 60_000; // 1 minute

export class ExfiltrationChainTracker {
  private readonly recentCalls: (ToolCallRecord | undefined)[] = new Array(CHAIN_WINDOW_SIZE);
  private writeIndex = 0;
  private count = 0;

  record(toolName: string): void {
    this.recentCalls[this.writeIndex] = { name: toolName, timestamp: Date.now() };
    this.writeIndex = (this.writeIndex + 1) % CHAIN_WINDOW_SIZE;
    if (this.count < CHAIN_WINDOW_SIZE) this.count++;
  }

  /**
   * Check if a data sink tool call follows a recent data source tool call,
   * which may indicate a read-then-exfiltrate chain.
   */
  detectChain(currentTool: string): boolean {
    if (!DATA_SINK_TOOLS.has(currentTool)) return false;

    const now = Date.now();
    const cutoff = now - CHAIN_TIME_WINDOW_MS;

    for (let i = 0; i < this.count; i++) {
      const call = this.recentCalls[i];
      if (call && DATA_SOURCE_TOOLS.has(call.name) && call.timestamp >= cutoff) {
        return true;
      }
    }
    return false;
  }
}

export interface InterceptorOptions {
  readonly policyEngine: PolicyEngine;
  readonly validateSchemas: boolean;
  readonly verboseErrors: boolean;
  readonly onDecision?: (result: ExecutionResult) => void;

  // Phase 1 additions
  readonly tokenIssuer?: TokenIssuer;
  readonly serverVerifier?: ServerVerifier;
  readonly rateLimiter?: RateLimiter;
  readonly rateLimitPerTool?: number;
  readonly globalRateLimitPerMinute?: number;

  // Prompt injection protection
  readonly exfiltrationTracker?: ExfiltrationChainTracker;
  readonly responseScanConfig?: ResponseScanConfig;
  readonly blockUnsafeResponses?: boolean;
}

/**
 * Intercepts an MCP tool call and runs the full security pipeline:
 *
 * 1. Rate limit check → RateLimitError if exceeded
 * 2. Exfiltration chain check → deny if data-source → data-sink pattern
 * 3. Policy evaluation (path + command constraints) → PolicyDeniedError if denied
 * 4. Issue capability token (if TokenIssuer configured)
 * 5. Sign request (if ServerVerifier configured)
 * 6. Call upstream
 * 7. Scan response for indirect prompt injection
 * 8. Record rate limit usage
 * 9. Log to audit trail
 * 10. Return result
 */
export async function interceptToolCall(
  params: McpCallToolParams,
  upstreamCall: (params: McpCallToolParams) => Promise<McpCallToolResult>,
  options: InterceptorOptions,
): Promise<McpCallToolResult> {
  const requestId = randomUUID();
  const timestamp = new Date().toISOString();

  const context = createSecurityContext({ requestId });

  const request: ExecutionRequest = {
    context,
    toolName: params.name,
    serverName: 'default',
    arguments: params.arguments ?? {},
    requiredPermission: guessPermission(params.name),
    timestamp,
  };

  // --- Step 1: Rate limit check ---
  if (options.rateLimiter) {
    // Per-tool rate limit
    if (options.rateLimitPerTool) {
      const toolLimit = options.rateLimiter.checkLimit(
        params.name,
        options.rateLimitPerTool,
      );
      if (!toolLimit.allowed) {
        const result: ExecutionResult = {
          status: 'ERROR',
          request,
          error: new RateLimitError(params.name, options.rateLimitPerTool),
          timestamp,
        };
        options.onDecision?.(result);
        return createDeniedToolResult(
          `Rate limit exceeded for tool "${params.name}"`,
        );
      }
    }

    // Global rate limit
    if (options.globalRateLimitPerMinute) {
      const globalLimit = options.rateLimiter.checkGlobalLimit(
        options.globalRateLimitPerMinute,
      );
      if (!globalLimit.allowed) {
        const result: ExecutionResult = {
          status: 'ERROR',
          request,
          error: new RateLimitError('*', options.globalRateLimitPerMinute),
          timestamp,
        };
        options.onDecision?.(result);
        return createDeniedToolResult('Global rate limit exceeded');
      }
    }
  }

  // --- Step 2: Exfiltration chain check ---
  if (options.exfiltrationTracker) {
    if (options.exfiltrationTracker.detectChain(params.name)) {
      const result: ExecutionResult = {
        status: 'DENIED',
        request,
        decision: {
          effect: 'DENY' as const,
          matchedRule: null,
          reason: `Exfiltration chain detected: data-sink tool "${params.name}" called after recent data-source tool`,
          timestamp,
          evaluationTimeMs: 0,
        },
        timestamp,
      };
      options.onDecision?.(result);
      return createDeniedToolResult(
        `Potential data exfiltration chain blocked: "${params.name}" called after a data-access tool`,
      );
    }
    // Record this call in the chain tracker
    options.exfiltrationTracker.record(params.name);
  }

  // --- Step 3: Policy evaluation ---
  const decision = options.policyEngine.evaluate(request);

  if (decision.effect === 'DENY') {
    const result: ExecutionResult = {
      status: 'DENIED',
      request,
      decision,
      timestamp,
    };
    options.onDecision?.(result);

    const reason = options.verboseErrors
      ? decision.reason
      : 'Tool execution denied by security policy.';
    return createDeniedToolResult(reason);
  }

  // --- Step 4: Issue capability token ---
  let capabilityToken: string | undefined;
  if (options.tokenIssuer) {
    capabilityToken = options.tokenIssuer.issue(
      requestId,
      [Permission.EXECUTE],
      [params.name],
    );
  }

  // --- Step 5: Sign request ---
  let callParams = params;
  if (options.serverVerifier && capabilityToken) {
    const signed = options.serverVerifier.createSignedRequest(params, capabilityToken);
    callParams = signed as unknown as McpCallToolParams;
  }

  // --- Step 6: Call upstream ---
  try {
    const startTime = performance.now();
    const toolResult = await upstreamCall(callParams);
    const durationMs = performance.now() - startTime;

    // --- Step 7: Scan response for indirect prompt injection ---
    const scanConfig = options.responseScanConfig ?? DEFAULT_RESPONSE_SCAN_CONFIG;
    let finalResult = toolResult;

    if (toolResult.content && Array.isArray(toolResult.content)) {
      for (const item of toolResult.content) {
        if (item.type === 'text' && typeof item.text === 'string') {
          const scan = scanResponse(item.text, scanConfig);
          if (!scan.safe) {
            if (options.blockUnsafeResponses) {
              const threats = scan.threats.map((t) => t.description).join('; ');
              return createDeniedToolResult(
                `Response blocked by security scanner: ${threats}`,
              );
            }
            // Default: prepend warning marker
            (item as { text: string }).text =
              `${RESPONSE_WARNING_MARKER}\n\n${item.text}`;
          }
        }
      }
    }

    // --- Step 8: Record rate limit usage ---
    if (options.rateLimiter) {
      options.rateLimiter.recordCall(params.name);
    }

    // --- Step 9: Log to audit trail ---
    const result: ExecutionResult = {
      status: 'ALLOWED',
      request,
      decision,
      toolResult: finalResult,
      durationMs,
      timestamp,
    };
    options.onDecision?.(result);

    return finalResult;
  } catch (error) {
    const result: ExecutionResult = {
      status: 'ERROR',
      request,
      error: error instanceof Error
        ? new PolicyDeniedError(params.name, error.message)
        : new PolicyDeniedError(params.name, 'Unknown upstream error'),
      timestamp,
    };
    options.onDecision?.(result);
    throw error;
  }
}
