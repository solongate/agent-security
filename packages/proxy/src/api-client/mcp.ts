/** Protected MCP server endpoints (/api/v1/mcp-servers). */
import { request } from './client.js';

export interface McpServer {
  id: string;
  name: string;
  url?: string;
  command?: string;
  status: string;
}

export function list(): Promise<{ servers: McpServer[] }> {
  return request('GET', '/mcp-servers');
}
