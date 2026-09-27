import type { Permission } from './permissions.js';

/**
 * Capability Token: a signed, short-lived, single-use token
 * that authorizes execution of specific tools within specific scopes.
 *
 * Security properties:
 * - Short-lived: TTL defaults to 30 seconds
 * - Single-use: nonce prevents replay attacks
 * - Scoped: limited to specific tools and servers
 * - Signed: HMAC-SHA256 prevents forgery
 */
export interface CapabilityToken {
  readonly jti: string;           // Unique token ID (nonce)
  readonly iss: string;           // Issuer (gateway ID)
  readonly sub: string;           // Subject (request ID)
  readonly iat: number;           // Issued at (unix timestamp)
  readonly exp: number;           // Expires at (unix timestamp)
  readonly permissions: readonly Permission[];
  readonly toolScope: readonly string[];    // Which tools this token covers
  readonly serverScope: readonly string[];  // Which servers
  readonly pathScope?: readonly string[];   // Optional path restrictions
}

/**
 * Configuration for token issuance.
 */
export interface TokenConfig {
  readonly secret: string;        // HMAC signing key
  readonly ttlSeconds: number;    // Default 30 seconds
  readonly algorithm: 'HS256';    // Start with HMAC
  readonly issuer: string;
}

/**
 * Default token configuration.
 * Secret must be provided - no default.
 */
export const DEFAULT_TOKEN_TTL_SECONDS = 30;
export const TOKEN_ALGORITHM = 'HS256' as const;
export const MIN_SECRET_LENGTH = 32;

/**
 * Result of token verification.
 */
export interface TokenVerificationResult {
  readonly valid: boolean;
  readonly payload?: CapabilityToken;
  readonly reason?: string;
}
