import type { PolicySet, McpCallToolParams, McpCallToolResult } from '../core/index.js';
import { TOKEN_ALGORITHM } from '../core/index.js';
import { PolicyEngine, PolicyStore } from '../policy-engine/index.js';
import { resolveConfig, type SolonGateConfig } from './config.js';
import { interceptToolCall, ExfiltrationChainTracker } from './interceptor.js';
import { SecurityLogger } from './logger.js';
import { TokenIssuer } from './token-issuer.js';
import { ServerVerifier } from './server-verifier.js';
import { RateLimiter } from './rate-limiter.js';

/**
 * Error thrown when a valid SolonGate license (API key) is missing or invalid.
 */
export class LicenseError extends Error {
  constructor(message: string) {
    super(
      `${message}\n` +
      '  Pair this machine with `solongate`, or set SOLONGATE_API_KEY.\n' +
      "  Usage: new SolonGate({ name: '...', apiKey: 'sg_live_xxx' })",
    );
    this.name = 'LicenseError';
  }
}

/**
 * SolonGate - Security Gateway for MCP Tool Servers.
 *
 * Requires an API key for the service this is pointed at (SOLONGATE_API_URL).
 *
 * Usage:
 * ```typescript
 * const gate = new SolonGate({ name: 'my-gateway', apiKey: 'sg_live_xxx' });
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
  private readonly apiKey: string;
  private licenseValidated = false;
  private pollingTimer: ReturnType<typeof setInterval> | null = null;

  constructor(options: {
    name: string;
    version?: string;
    apiKey?: string;
    config?: Partial<SolonGateConfig>;
    policySet?: PolicySet;
  }) {
    // License gate: require a valid API key
    const apiKey = options.apiKey || process.env.SOLONGATE_API_KEY || '';
    if (!apiKey) {
      throw new LicenseError('A valid SolonGate API key is required.');
    }
    if (!apiKey.startsWith('sg_live_') && !apiKey.startsWith('sg_test_')) {
      throw new LicenseError(
        "Invalid API key format. Keys must start with 'sg_live_' or 'sg_test_'.",
      );
    }
    this.apiKey = apiKey;

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

    // If no local policySet provided and using a live key, fetch from cloud + start polling
    if (!options.policySet && !config.policySet && apiKey.startsWith('sg_live_')) {
      this.fetchCloudPolicyOnce();
      this.startPolicyPolling();
    }

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
   * Validate the API key against the SolonGate cloud API.
   * Called once on first executeToolCall. Throws LicenseError if invalid.
   * Test keys (sg_test_) skip online validation.
   */
  private async validateLicense(): Promise<void> {
    if (this.licenseValidated) return;

    // Test keys only accepted in test/development environments
    if (this.apiKey.startsWith('sg_test_')) {
      const nodeEnv = typeof process !== 'undefined' ? process.env.NODE_ENV : '';
      if (nodeEnv === 'production') {
        throw new LicenseError(
          'Test API keys (sg_test_) cannot be used in production. Use a sg_live_ key instead.',
        );
      }
      this.licenseValidated = true;
      return;
    }

    const apiUrl = this.config.apiUrl ?? 'http://127.0.0.1:3002';
    try {
      const res = await fetch(`${apiUrl}/api/v1/auth/me`, {
        headers: {
          'X-API-Key': this.apiKey,
          'Authorization': `Bearer ${this.apiKey}`,
        },
        signal: AbortSignal.timeout(5_000),
      });

      if (res.status === 401) {
        throw new LicenseError('Invalid or expired API key.');
      }
      if (res.status === 403) {
        // 403 is the service refusing this key for its own reasons — a
        // revoked key, a project that is gone. It is the operator's answer
        // to give, so it is passed on rather than interpreted.
        throw new LicenseError('The service refused this API key (403). Check it with whoever runs it.');
      }

      this.licenseValidated = true;
    } catch (err) {
      if (err instanceof LicenseError) throw err;
      // Network errors should not block usage — log and allow through
      console.warn('[SolonGate] License validation failed (network error), allowing through:', err instanceof Error ? err.message : String(err));
      this.licenseValidated = true;
    }
  }

  /**
   * Fetch policy from SolonGate Cloud API (fire once, non-blocking).
   * TODO: extract cloud policy parsing to shared module with packages/proxy/src/config.ts
   */
  private fetchCloudPolicyOnce(): void {
    const apiUrl = this.config.apiUrl ?? 'http://127.0.0.1:3002';
    fetch(`${apiUrl}/api/v1/policies/default`, {
      headers: { 'Authorization': `Bearer ${this.apiKey}` },
      signal: AbortSignal.timeout(10_000),
    })
      .then(async (res) => {
        if (!res.ok) return;
        const data = (await res.json()) as Record<string, unknown>;
        const policySet: PolicySet = {
          id: String(data.id ?? 'cloud'),
          name: String(data.name ?? 'Cloud Policy'),
          description: String(data.description ?? ''),
          version: Number(data._version ?? 1),
          rules: (data.rules as PolicySet['rules']) ?? [],
          createdAt: String(data._created_at ?? ''),
          updatedAt: '',
        };
        this.policyEngine.loadPolicySet(policySet);
        // Fetch + load the compiled OPA WASM bundle (OPA is the sole evaluator).
        await this.loadCloudWasm(apiUrl, policySet.id);
      })
      .catch(() => {
        // Silently fall back to default-allow if cloud is unreachable
      });
  }

  /**
   * Fetch the compiled OPA WASM bundle for a policy and load it into the engine.
   * The proxy does not compile policies itself — the cloud API compiles every
   * policy version to WASM on save and serves it from /policies/:id/wasm.
   */
  private async loadCloudWasm(apiUrl: string, policyId: string): Promise<void> {
    try {
      const res = await fetch(`${apiUrl}/api/v1/policies/${policyId}/wasm`, {
        headers: { 'Authorization': `Bearer ${this.apiKey}` },
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) {
        console.warn(
          `[SolonGate] No compiled OPA WASM for policy "${policyId}" (HTTP ${res.status}). ` +
          'Policy evaluation fails closed (DENY) until the policy is recompiled.',
        );
        return;
      }
      const wasmBytes = new Uint8Array(await res.arrayBuffer());
      await this.policyEngine.loadWasmBundle(wasmBytes);
    } catch (err) {
      console.warn(
        '[SolonGate] Failed to load policy WASM bundle:',
        err instanceof Error ? err.message : String(err),
      );
    }
  }

  /**
   * Poll for policy updates from dashboard every 60 seconds.
   */
  private startPolicyPolling(): void {
    const apiUrl = this.config.apiUrl ?? 'http://127.0.0.1:3002';
    let currentVersion = 0;

    const timer = setInterval(async () => {
      try {
        const res = await fetch(`${apiUrl}/api/v1/policies/default`, {
          headers: { 'Authorization': `Bearer ${this.apiKey}` },
          signal: AbortSignal.timeout(10_000),
        });
        if (!res.ok) return;
        const data = (await res.json()) as Record<string, unknown>;
        const version = Number(data._version ?? 0);
        if (version !== currentVersion && version > 0) {
          const policySet: PolicySet = {
            id: String(data.id ?? 'cloud'),
            name: String(data.name ?? 'Cloud Policy'),
            description: String(data.description ?? ''),
            version,
            rules: (data.rules as PolicySet['rules']) ?? [],
            createdAt: String(data._created_at ?? ''),
            updatedAt: '',
          };
          this.policyEngine.loadPolicySet(policySet);
          await this.loadCloudWasm(apiUrl, policySet.id);
          currentVersion = version;
          // Policy updated from dashboard (debug-level, not a warning)
        }
      } catch {
        // Silent
      }
    }, 60_000);
    // Allow process to exit without waiting for the polling timer
    if (typeof timer.unref === 'function') timer.unref();
    this.pollingTimer = timer;
  }

  /**
   * Send audit log to SolonGate Cloud API (fire-and-forget).
   */
  private sendAuditLog(entry: {
    tool: string;
    arguments: Record<string, unknown>;
    decision: 'ALLOW' | 'DENY';
    reason: string;
    matchedRule?: string;
    evaluationTimeMs: number;
  }): void {
    if (!this.apiKey.startsWith('sg_live_')) return;
    const apiUrl = this.config.apiUrl ?? 'http://127.0.0.1:3002';
    fetch(`${apiUrl}/api/v1/audit-logs`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(entry),
      signal: AbortSignal.timeout(5_000),
    }).catch(() => {
      // Audit log send failed (debug-level, not a warning)
    });
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
    // Validate license on first call
    await this.validateLicense();

    const startTime = performance.now();
    return interceptToolCall(params, upstreamCall, {
      policyEngine: this.policyEngine,
      validateSchemas: this.config.validateSchemas,
      verboseErrors: this.config.verboseErrors,
      onDecision: (result) => {
        this.logger.logDecision(result);
        if (result.status === 'ALLOWED' || result.status === 'DENIED') {
          this.sendAuditLog({
            tool: params.name,
            arguments: (params.arguments ?? {}) as Record<string, unknown>,
            decision: result.decision.effect === 'ALLOW' ? 'ALLOW' : 'DENY',
            reason: result.decision.reason,
            matchedRule: result.decision.matchedRule?.id,
            evaluationTimeMs: performance.now() - startTime,
          });
        } else if (result.status === 'ERROR') {
          this.sendAuditLog({
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

  /** Stop policy polling and release resources. */
  destroy(): void {
    if (this.pollingTimer) {
      clearInterval(this.pollingTimer);
      this.pollingTimer = null;
    }
  }
}
