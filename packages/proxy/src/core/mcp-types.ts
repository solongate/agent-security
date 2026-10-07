// SPDX-License-Identifier: Apache-2.0

/**
 * Types that bridge between the MCP protocol and SolonGate's type system.
 * Adapts MCP SDK types without creating a hard dependency.
 */

export interface McpToolDefinition {
  readonly name: string;
  readonly description?: string;
  readonly inputSchema: {
    readonly type: 'object';
    readonly properties?: Record<string, unknown>;
    readonly required?: readonly string[];
  };
}

export interface McpCallToolParams {
  readonly name: string;
  readonly arguments?: Record<string, unknown>;
}

export interface McpCallToolResult {
  readonly content: readonly McpToolResultContent[];
  readonly isError?: boolean;
  readonly structuredContent?: unknown;
}

export type McpToolResultContent =
  | { readonly type: 'text'; readonly text: string }
  | { readonly type: 'image'; readonly data: string; readonly mimeType: string }
  | { readonly type: 'resource'; readonly resource: unknown };

/** Wraps denied tool calls in MCP error responses. */
export function createDeniedToolResult(
  reason: string,
): McpCallToolResult {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({
          error: 'POLICY_DENIED',
          message: reason,
          hint: 'This tool call was blocked by SolonGate security policy. Check your policy configuration.',
        }),
      },
    ],
    isError: true,
  };
}
