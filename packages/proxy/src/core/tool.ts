import type { Permission } from './permissions.js';

/**
 * Declares a tool's capabilities and security requirements.
 * Wraps MCP tool definitions with SolonGate-specific metadata.
 */
export interface ToolCapability {
  readonly name: string;
  readonly description: string;
  readonly serverName: string;

  /** Maximum permissions this tool CAN request (capability ceiling). */
  readonly maxPermissions: readonly Permission[];

  /** Default permissions when no explicit policy exists. Must be empty in Phase 0 (default-deny). */
  readonly defaultPermissions: readonly Permission[];

  readonly inputSchema: Record<string, unknown>;

  /** Tools with side effects cannot be READ-only. */
  readonly hasSideEffects: boolean;

  /** Sensitive data access affects audit log redaction behavior. */
  readonly accessesSensitiveData: boolean;

  /** Max calls per minute. 0 = unlimited. */
  readonly rateLimitPerMinute: number;
}

/** Creates a ToolCapability with the most restrictive secure defaults. */
export function createToolCapability(
  params: Pick<ToolCapability, 'name' | 'description' | 'serverName' | 'inputSchema'> &
    Partial<Omit<ToolCapability, 'name' | 'description' | 'serverName' | 'inputSchema'>>,
): ToolCapability {
  return {
    maxPermissions: [],
    defaultPermissions: [],
    hasSideEffects: true,
    accessesSensitiveData: true,
    rateLimitPerMinute: 60,
    ...params,
  };
}
