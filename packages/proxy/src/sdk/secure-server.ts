/**
 * SecureMcpServer — Drop-in replacement for McpServer with SolonGate protection.
 *
 * Extends the standard McpServer and automatically wraps every tool handler
 * with SolonGate's security pipeline (rate limiting, input guard, policy eval,
 * audit logging). No manual wrapping of individual tool handlers needed.
 *
 * Usage:
 * ```typescript
 * import { SecureMcpServer } from '@solongate/proxy';
 *
 * // Just replace `new McpServer(...)` with `new SecureMcpServer(...)`
 * const server = new SecureMcpServer({
 *   name: 'my-server',
 *   version: '1.0.0',
 * });
 *
 * // Register tools as normal — they're automatically protected
 * server.tool('file_read', { path: z.string() }, async ({ path }) => {
 *   return { content: [{ type: 'text', text: readFileSync(path, 'utf-8') }] };
 * });
 *
 * // API key comes from env: SOLONGATE_API_KEY=sg_live_xxx
 * ```
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import type { Implementation } from '@modelcontextprotocol/sdk/types.js';
import type { PolicySet, McpCallToolResult } from '../core/index.js';
import { SolonGate } from './solongate.js';
import type { SolonGateConfig } from './config.js';

/**
 * Options for SecureMcpServer that control SolonGate behavior.
 */
export interface SecureMcpServerOptions {
  /** SolonGate Cloud API key. Defaults to process.env.SOLONGATE_API_KEY */
  apiKey?: string;
  /** Policy set to enforce. If omitted, uses cloud policy or default. */
  policySet?: PolicySet;
  /** SolonGate configuration overrides. */
  config?: Partial<SolonGateConfig>;
}

export class SecureMcpServer extends McpServer {
  private readonly gate: SolonGate;

  /**
   * Create a secure MCP server.
   *
   * @param serverInfo - MCP server info (name, version)
   * @param solongateOptions - SolonGate security options
   * @param mcpOptions - Standard McpServer options (capabilities, etc.)
   */
  constructor(
    serverInfo: Implementation,
    solongateOptions?: SecureMcpServerOptions,
    mcpOptions?: ConstructorParameters<typeof McpServer>[1],
  ) {
    super(serverInfo, mcpOptions);

    this.gate = new SolonGate({
      name: serverInfo.name,
      version: serverInfo.version,
      apiKey: solongateOptions?.apiKey,
      policySet: solongateOptions?.policySet,
      config: solongateOptions?.config,
    });

    const warnings = this.gate.getWarnings();
    for (const w of warnings) {
      console.warn(`[SolonGate] ${w}`);
    }
  }

  /**
   * Override tool() to auto-wrap handlers with SolonGate security pipeline.
   *
   * Supports all McpServer.tool() overloads — the handler (always the last
   * argument) is transparently wrapped. Tool name, description, schema, and
   * annotations pass through unchanged.
   */
  override tool(name: string, ...rest: unknown[]): ReturnType<McpServer['tool']> {
    const handler = rest[rest.length - 1];
    if (typeof handler !== 'function') {
      // Not a handler — pass through unchanged
      return (super.tool as Function).call(this, name, ...rest);
    }

    const toolName = name;
    const gate = this.gate;

    rest[rest.length - 1] = async (...callArgs: unknown[]) => {
      // Extract tool arguments for policy evaluation.
      // Schema-based tools: callArgs = [parsedArgs, extra]
      // Zero-arg tools: callArgs = [extra]
      const toolArgs =
        callArgs.length > 1 &&
        typeof callArgs[0] === 'object' &&
        callArgs[0] !== null
          ? (callArgs[0] as Record<string, unknown>)
          : {};

      const result = await gate.executeToolCall(
        { name: toolName, arguments: toolArgs },
        async () => (handler as Function)(...callArgs) as Promise<McpCallToolResult>,
      );

      // Bridge McpCallToolResult (readonly content) to CallToolResult (mutable content)
      return { ...result, content: [...result.content] };
    };

    return (super.tool as Function).call(this, name, ...rest);
  }

  /**
   * Override registerTool() to auto-wrap handlers with SolonGate security pipeline.
   *
   * This is the modern (non-deprecated) API for registering tools.
   */
  override registerTool(
    name: string,
    config: Parameters<McpServer['registerTool']>[1],
    cb: unknown,
  ): ReturnType<McpServer['registerTool']> {
    if (typeof cb !== 'function') {
      return (super.registerTool as Function).call(this, name, config, cb);
    }

    const toolName = name;
    const gate = this.gate;

    const wrappedCb = async (...callArgs: unknown[]) => {
      const toolArgs =
        callArgs.length > 1 &&
        typeof callArgs[0] === 'object' &&
        callArgs[0] !== null
          ? (callArgs[0] as Record<string, unknown>)
          : {};

      const result = await gate.executeToolCall(
        { name: toolName, arguments: toolArgs },
        async () => (cb as Function)(...callArgs) as Promise<McpCallToolResult>,
      );

      return { ...result, content: [...result.content] };
    };

    return (super.registerTool as Function).call(this, name, config, wrappedCb);
  }

  /** Get the underlying SolonGate instance for direct access. */
  getSolonGate(): SolonGate {
    return this.gate;
  }
}
