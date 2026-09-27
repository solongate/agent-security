import { createHmac, randomUUID } from 'node:crypto';
import type {
  CapabilityToken,
  TokenConfig,
  TokenVerificationResult,
  Permission,
} from '../core/index.js';
import {
  DEFAULT_TOKEN_TTL_SECONDS,
  TOKEN_ALGORITHM,
  TOKEN_MAX_AGE_SECONDS,
  MIN_SECRET_LENGTH,
} from '../core/index.js';
import { ExpiringSet } from './expiring-set.js';

/**
 * Issues and verifies capability tokens using HMAC-SHA256.
 *
 * Security properties:
 * - Short-lived TTL (default 30 seconds)
 * - Single-use nonces (replay prevention)
 * - Revocation support
 * - No external JWT library dependency
 */
export class TokenIssuer {
  private readonly secret: string;
  private readonly ttlSeconds: number;
  private readonly issuer: string;
  private readonly usedNonces: ExpiringSet;
  private readonly revokedTokens: ExpiringSet;

  constructor(config: TokenConfig) {
    if (config.secret.length < MIN_SECRET_LENGTH) {
      throw new Error(
        `Token secret must be at least ${MIN_SECRET_LENGTH} characters`,
      );
    }
    this.secret = config.secret;
    this.ttlSeconds = config.ttlSeconds || DEFAULT_TOKEN_TTL_SECONDS;
    this.issuer = config.issuer;

    // Nonces/revocations only need to live as long as tokens are valid
    const maxAgMs = TOKEN_MAX_AGE_SECONDS * 1000;
    this.usedNonces = new ExpiringSet(maxAgMs);
    this.revokedTokens = new ExpiringSet(maxAgMs);
  }

  /**
   * Issues a signed capability token.
   */
  issue(
    requestId: string,
    permissions: readonly Permission[],
    toolScope: readonly string[],
    serverScope: readonly string[] = ['*'],
    pathScope?: readonly string[],
  ): string {
    const now = Math.floor(Date.now() / 1000);
    const jti = randomUUID();

    const payload: CapabilityToken = {
      jti,
      iss: this.issuer,
      sub: requestId,
      iat: now,
      exp: now + this.ttlSeconds,
      permissions: [...permissions],
      toolScope: [...toolScope],
      serverScope: [...serverScope],
      ...(pathScope && { pathScope: [...pathScope] }),
    };

    return this.sign(payload);
  }

  /**
   * Verifies a capability token and consumes the nonce (single-use).
   */
  verify(token: string): TokenVerificationResult {
    // 1. Parse and verify signature
    const parsed = this.parseAndVerify(token);
    if (!parsed.valid || !parsed.payload) {
      return parsed;
    }

    const payload = parsed.payload;

    // 2. Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp <= now) {
      return { valid: false, reason: 'Token expired' };
    }

    // 3. Check if revoked
    if (this.revokedTokens.has(payload.jti)) {
      return { valid: false, reason: 'Token has been revoked' };
    }

    // 4. Check if already used (single-use)
    if (this.usedNonces.has(payload.jti)) {
      return { valid: false, reason: 'Token already used (replay detected)' };
    }

    // 5. Consume nonce
    this.usedNonces.add(payload.jti);

    return { valid: true, payload };
  }

  /**
   * Revokes a token by its ID.
   */
  revoke(jti: string): void {
    this.revokedTokens.add(jti);
  }

  /**
   * Checks if a token ID has been revoked.
   */
  isRevoked(jti: string): boolean {
    return this.revokedTokens.has(jti);
  }

  // --- Internal helpers ---

  private sign(payload: CapabilityToken): string {
    const header = base64UrlEncode(JSON.stringify({ alg: TOKEN_ALGORITHM, typ: 'JWT' }));
    const body = base64UrlEncode(JSON.stringify(payload));
    const signature = this.computeSignature(`${header}.${body}`);
    return `${header}.${body}.${signature}`;
  }

  private parseAndVerify(token: string): TokenVerificationResult {
    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, reason: 'Invalid token format' };
    }

    const [header, body, signature] = parts as [string, string, string];
    const expectedSignature = this.computeSignature(`${header}.${body}`);

    if (signature !== expectedSignature) {
      return { valid: false, reason: 'Invalid token signature' };
    }

    try {
      const payload = JSON.parse(base64UrlDecode(body)) as CapabilityToken;
      return { valid: true, payload };
    } catch {
      return { valid: false, reason: 'Invalid token payload' };
    }
  }

  private computeSignature(data: string): string {
    return base64UrlEncode(
      createHmac('sha256', this.secret).update(data).digest('base64'),
    );
  }
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64UrlDecode(str: string): string {
  const padded = str + '='.repeat((4 - (str.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
}
