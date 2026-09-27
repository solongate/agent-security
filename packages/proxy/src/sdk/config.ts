import type { PolicySet } from '../core/index.js';
import { UNSAFE_CONFIGURATION_WARNINGS } from '../core/index.js';

/**
 * Configuration for the SolonGate SDK.
 * All fields have secure defaults. Weakening requires explicit opt-in.
 */
export interface SolonGateConfig {
  readonly policySet?: PolicySet;
  readonly validateSchemas: boolean;
  readonly enableLogging: boolean;
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error';
  readonly evaluationTimeoutMs: number;
  readonly verboseErrors: boolean;
  readonly globalRateLimitPerMinute: number;

  // Phase 1 additions
  readonly rateLimitPerTool: number;
  readonly tokenSecret?: string;
  readonly tokenTtlSeconds: number;
  readonly tokenIssuer?: string;
  readonly gatewaySecret?: string;
  readonly enableVersionedPolicies: boolean;
  readonly apiUrl?: string;
}

export const DEFAULT_CONFIG: Readonly<SolonGateConfig> = Object.freeze({
  validateSchemas: true,
  enableLogging: true,
  logLevel: 'info',
  evaluationTimeoutMs: 100,
  verboseErrors: false,
  globalRateLimitPerMinute: 600,
  rateLimitPerTool: 60,
  tokenTtlSeconds: 30,
  enableVersionedPolicies: true,
});

export function resolveConfig(
  userConfig?: Partial<SolonGateConfig>,
): { config: SolonGateConfig; warnings: string[] } {
  const warnings: string[] = [];
  const config = { ...DEFAULT_CONFIG, ...userConfig };

  if (!config.validateSchemas) {
    warnings.push(UNSAFE_CONFIGURATION_WARNINGS.DISABLED_VALIDATION);
  }
  if (config.globalRateLimitPerMinute === 0) {
    warnings.push(UNSAFE_CONFIGURATION_WARNINGS.RATE_LIMIT_ZERO);
  }
  if (config.verboseErrors) {
    warnings.push(
      'Verbose errors enabled: internal error details will be sent to the LLM.',
    );
  }
  if (config.tokenSecret && config.tokenSecret.length < 32) {
    warnings.push(
      'Token secret is shorter than 32 characters. Use a longer secret for production.',
    );
  }
  if (config.apiUrl && config.apiUrl.startsWith('http://') && !config.apiUrl.startsWith('http://localhost') && !config.apiUrl.startsWith('http://127.0.0.1')) {
    warnings.push(
      'API URL uses plaintext HTTP. API keys will be sent unencrypted. Use HTTPS in production.',
    );
  }

  return { config, warnings };
}
