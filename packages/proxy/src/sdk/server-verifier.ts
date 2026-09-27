import { createHmac, randomUUID } from 'node:crypto';
import type { McpCallToolParams } from '../core/index.js';
import { ExpiringSet } from './expiring-set.js';

/**
 * A signed MCP request that includes capability token and integrity signature.
 * Requests without valid gateway signature should be rejected by MCP servers.
 */
export interface SignedMcpRequest {
  readonly params: McpCallToolParams;
  readonly capabilityToken: string;
  readonly signature: string;
  readonly timestamp: string;
  readonly nonce: string;
}

/**
 * Result of validating a signed request.
 */
export interface SignatureValidationResult {
  readonly valid: boolean;
  readonly reason?: string;
}

/**
 * Signs and verifies MCP requests to ensure they originate from the gateway.
 *
 * Security properties:
 * - HMAC-SHA256 signature of request params + token
 * - Timestamp to prevent old request replays
 * - Nonce for uniqueness
 * - Configurable max age for timestamp validation
 */
export class ServerVerifier {
  private readonly gatewaySecret: string;
  private readonly maxAgeMs: number;
  private readonly usedNonces: ExpiringSet;

  constructor(config: {
    gatewaySecret: string;
    maxAgeMs?: number;
  }) {
    if (config.gatewaySecret.length < 32) {
      throw new Error('Gateway secret must be at least 32 characters');
    }
    this.gatewaySecret = config.gatewaySecret;
    this.maxAgeMs = config.maxAgeMs ?? 60_000; // 1 minute default
    this.usedNonces = new ExpiringSet(this.maxAgeMs * 2);
  }

  /**
   * Computes HMAC signature for request data.
   */
  signRequest(params: McpCallToolParams, capabilityToken: string): string {
    const data = JSON.stringify({ params, capabilityToken });
    return createHmac('sha256', this.gatewaySecret)
      .update(data)
      .digest('hex');
  }

  /**
   * Verifies the HMAC signature of request data.
   */
  verifySignature(
    params: McpCallToolParams,
    capabilityToken: string,
    signature: string,
  ): boolean {
    const expected = this.signRequest(params, capabilityToken);
    // Constant-time comparison to prevent timing attacks
    if (expected.length !== signature.length) return false;
    let result = 0;
    for (let i = 0; i < expected.length; i++) {
      result |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
    }
    return result === 0;
  }

  /**
   * Creates a complete signed request including timestamp and nonce.
   */
  createSignedRequest(
    params: McpCallToolParams,
    capabilityToken: string,
  ): SignedMcpRequest {
    const timestamp = new Date().toISOString();
    const nonce = randomUUID();
    const signature = this.signRequest(params, capabilityToken);

    return {
      params,
      capabilityToken,
      signature,
      timestamp,
      nonce,
    };
  }

  /**
   * Validates a complete signed request including timestamp, nonce, and signature.
   */
  validateSignedRequest(request: SignedMcpRequest): SignatureValidationResult {
    // 1. Check timestamp freshness
    const requestTime = new Date(request.timestamp).getTime();
    const now = Date.now();
    if (isNaN(requestTime)) {
      return { valid: false, reason: 'Invalid timestamp' };
    }
    if (now - requestTime > this.maxAgeMs) {
      return { valid: false, reason: 'Request too old' };
    }
    if (requestTime > now + 30_000) {
      return { valid: false, reason: 'Request timestamp in the future' };
    }

    // 2. Check nonce uniqueness
    if (this.usedNonces.has(request.nonce)) {
      return { valid: false, reason: 'Duplicate nonce (replay detected)' };
    }

    // 3. Verify signature
    if (!this.verifySignature(request.params, request.capabilityToken, request.signature)) {
      return { valid: false, reason: 'Invalid signature' };
    }

    // 4. Mark nonce as used
    this.usedNonces.add(request.nonce);

    return { valid: true };
  }
}
