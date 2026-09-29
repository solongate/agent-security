import type { PolicySet, McpCallToolParams, McpCallToolResult } from '../core/index.js';
import { TOKEN_ALGORITHM } from '../core/index.js';
import { PolicyEngine, PolicyStore } from '../policy-engine/index.js';
import { resolveConfig, type SolonGateConfig } from './config.js';
import { interceptToolCall, ExfiltrationChainTracker } from './interceptor.js';
import { SecurityLogger } from './logger.js';
import { TokenIssuer } from './token-issuer.js';
import { ServerVerifier } from './server-verifier.js';
// The record goes where every other record goes: this machine's audit trail. A gate
// embedded in somebody's tool server has no more business shipping their tool calls
// off the machine than the guard did.
import { writeAuditEntry } from '../config.js';
import { RateLimiter } from './rate-limiter.js';

/**
 * Thrown when a key is present and malformed.
 *
 * It is a distinct type because it is the one startup failure with an action
 * attached, and the message carries that action. It no longer means "missing": a key
 * is optional, and the advice to go and pair the machine went with the pairing.
 */
export class LicenseError extends Error {
  constructor(message: string) {
    super(
      `${message}\n` +
      "  Usage: new SolonGate({ name: '...' }) — a key is optional and unused.",
    );
    this.name = 'LicenseError';
  }
}

/**
 * SolonGate - Security Gateway for MCP Tool Servers.
 *
 * Everything it enforces comes from this machine: a policy file and the layers
 * configured in it. There is no account, no key and nothing to point it at.
 *
 * Usage:
 * ```typescript
 * const gate = new SolonGate({ name: 'my-gateway' });
 *
 * // Intercept a tool call
 * const result = await gate.executeToolCall(
 *   { name: 'file.read', arguments: { path: '/etc/passwd' } },
 *   async (params) => upstreamMcpServer.callTool(params),
 * );
 * ```
 *
 * Architecture:
 *   [LLM] -> [SolonGate.executeToolCall] -> [Security Pipeline] -> [Upstream MCP Server]
 *
 * Pipeline:
 *   Rate Limit → Policy Eval (path + command constraints) → Token Issue → Sign → Call → Audit
 */
export class SolonGate {
  private readonly policyEngine: PolicyEngine;
  private readonly config: SolonGateConfig;
  private readonly logger: SecurityLogger;
  private readonly configWarnings: string[];
  private readonly tokenIssuer: TokenIssuer | null;
  private readonly serverVerifier: ServerVerifier | null;
  private readonly rateLimiter: RateLimiter;
  private readonly exfiltrationTracker: ExfiltrationChainTracker;

  constructor(options: {
    name: string;
    version?: string;
    apiKey?: string;
    config?: Partial<SolonGateConfig>;
    policySet?: PolicySet;
  }) {
    // NO KEY IS REQUIRED, and that is the point. This threw
    // `A valid SolonGate API key is required.` without one — a licence gate, and what
    // it licensed is deleted. The MCP proxy builds its gate through here, so that
    // throw was the last thing standing between a machine with no service and a
    // working proxy. internal/sdk/solongate.go dropped the same check; a gate that
    // refuses to start in one implementation and starts in the other is the worst of
    // both.
    //
    // A key that is PRESENT and malformed is still refused: it is a configuration
    // mistake worth naming, and nothing about naming it needs a network.
    const apiKey = options.apiKey || process.env.SOLONGATE_API_KEY || '';
    if (apiKey && !apiKey.startsWith('sg_live_') && !apiKey.startsWith('sg_test_')) {
      throw new LicenseError(
        "Invalid API key format. Keys must start with 'sg_live_' or 'sg_test_'.",
      );
    }

    const { config, warnings } = resolveConfig(options.config);
    this.config = config;
    this.configWarnings = warnings;

    this.logger = new SecurityLogger({
      level: config.logLevel,
      enabled: config.enableLogging,
    });

    for (const warning of warnings) {
      console.warn(`[SolonGate] WARNING: ${warning}`);
    }

    // Initialize PolicyEngine with optional versioned store
    const store = config.enableVersionedPolicies ? new PolicyStore() : undefined;
    this.policyEngine = new PolicyEngine({
      policySet: options.policySet ?? config.policySet,
      timeoutMs: config.evaluationTimeoutMs,
      store,
    });

    // Initialize TokenIssuer if secret is provided
    this.tokenIssuer = config.tokenSecret
      ? new TokenIssuer({
          secret: config.tokenSecret,
          ttlSeconds: config.tokenTtlSeconds,
          algorithm: TOKEN_ALGORITHM,
          issuer: config.tokenIssuer ?? options.name,
        })
      : null;

    // Initialize ServerVerifier if gateway secret is provided
    this.serverVerifier = config.gatewaySecret
      ? new ServerVerifier({ gatewaySecret: config.gatewaySecret })
      : null;

    // Always initialize rate limiter
    this.rateLimiter = new RateLimiter();
    this.exfiltrationTracker = new ExfiltrationChainTracker();
  }

  /**
   * Intercept and evaluate a tool call against the full security pipeline.
   * If denied at any stage, returns an error result without calling upstream.
   * If allowed, calls upstream and returns the result.
   */
  async executeToolCall(
    params: McpCallToolParams,
    upstreamCall: (params: McpCallToolParams) => Promise<McpCallToolResult>,
  ): Promise<McpCallToolResult> {
    const startTime = performance.now();
    return interceptToolCall(params, upstreamCall, {
      policyEngine: this.policyEngine,
      validateSchemas: this.config.validateSchemas,
      verboseErrors: this.config.verboseErrors,
      onDecision: (result) => {
        this.logger.logDecision(result);
        if (result.status === 'ALLOWED' || result.status === 'DENIED') {
          writeAuditEntry({
            tool: params.name,
            arguments: (params.arguments ?? {}) as Record<string, unknown>,
            decision: result.decision.effect === 'ALLOW' ? 'ALLOW' : 'DENY',
            reason: result.decision.reason,
            matchedRule: result.decision.matchedRule?.id,
            evaluationTimeMs: performance.now() - startTime,
          });
        } else if (result.status === 'ERROR') {
          writeAuditEntry({
            tool: params.name,
            arguments: (params.arguments ?? {}) as Record<string, unknown>,
            decision: 'DENY',
            reason: result.error.message,
            evaluationTimeMs: performance.now() - startTime,
          });
        }
      },
      tokenIssuer: this.tokenIssuer ?? undefined,
      serverVerifier: this.serverVerifier ?? undefined,
      rateLimiter: this.rateLimiter,
      rateLimitPerTool: this.config.rateLimitPerTool,
      globalRateLimitPerMinute: this.config.globalRateLimitPerMinute,
      exfiltrationTracker: this.exfiltrationTracker,
    });
  }

  /** Load a new policy set at runtime. */
  loadPolicy(
    policySet: PolicySet,
    options?: { reason?: string; createdBy?: string },
  ) {
    return this.policyEngine.loadPolicySet(policySet, options);
  }

  /**
   * Load a pre-compiled OPA WASM bundle for evaluation. OPA WASM is the sole
   * evaluation backend — until a bundle is loaded, evaluate() fails closed
   * (default DENY). The bundle is fetched from the cloud /policies/:id/wasm.
   */
  async loadWasmBundle(wasmBundle: BufferSource): Promise<void> {
    return this.policyEngine.loadWasmBundle(wasmBundle);
  }

  /** Which backend decides: 'opa' with a WASM bundle loaded, 'local' without. */
  getEvaluatorMode(): 'opa' | 'local' {
    return this.policyEngine.getEvaluatorMode();
  }

  /** Get current security warnings. */
  getWarnings(): readonly string[] {
    return [
      ...this.configWarnings,
      ...this.policyEngine.getSecurityWarnings().map((w) => `[${w.level}] ${w.message}`),
    ];
  }

  /** Get the policy engine for direct access. */
  getPolicyEngine(): PolicyEngine {
    return this.policyEngine;
  }

  /** Get the rate limiter for direct access. */
  getRateLimiter(): RateLimiter {
    return this.rateLimiter;
  }

  /** Get the token issuer (null if not configured). */
  getTokenIssuer(): TokenIssuer | null {
    return this.tokenIssuer;
  }

  /**
   * Release resources.
   *
   * It used to stop a policy poller. There is nothing to poll: the policy comes in
   * through loadPolicy, and whoever embeds this owns when that happens.
   */
  destroy(): void {}
}
