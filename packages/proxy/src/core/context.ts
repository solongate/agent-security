import type { TrustLevel } from './trust.js';
import type { PermissionSet } from './permissions.js';

/**
 * SecurityContext represents the security state of a single request.
 * Created fresh for each MCP request and NEVER reused.
 * All fields are readonly - state transitions create new contexts.
 */
export interface SecurityContext {
  readonly requestId: string;
  readonly trustLevel: TrustLevel;
  readonly grantedPermissions: PermissionSet;
  readonly sessionId: string | null;
  readonly createdAt: string;
  readonly metadata: Readonly<Record<string, unknown>>;
  readonly capabilityToken?: string;
}

/** Extends SecurityContext with tool-specific execution information. */
export interface ExecutionContext extends SecurityContext {
  readonly toolName: string;
  readonly serverName: string;
  readonly arguments: Readonly<Record<string, unknown>>;
}

/** Creates a new SecurityContext with default-deny settings. */
export function createSecurityContext(
  params: Pick<SecurityContext, 'requestId'> &
    Partial<Omit<SecurityContext, 'requestId' | 'createdAt' | 'trustLevel' | 'grantedPermissions'>>,
): SecurityContext {
  return {
    trustLevel: 'UNTRUSTED',
    grantedPermissions: new Set(),
    sessionId: null,
    metadata: {},
    createdAt: new Date().toISOString(),
    ...params,
  };
}
