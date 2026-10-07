// SPDX-License-Identifier: Apache-2.0

/**
 * The store the CLI and the TUI are written against.
 *
 * It was an HTTP client — `import { api } from './api-client/index.js'` then
 * `api.policies.list()` — and the names and the types are unchanged, because
 * every command and every panel is written against them. What is underneath is
 * two files on this machine; see local-store.ts.
 *
 * What is NOT here any more: auth, keys, mcp and the device-login flow. Each was
 * a conversation with a service — who am I, mint me a key, which MCP servers are
 * registered, sign this machine in — and there is no service. Nothing outside
 * this directory referred to the first three at all.
 */
export * from './types.js';
export { LocalStoreError, policyPath } from './local-store.js';

import * as policies from './policies.js';
import * as settings from './settings.js';
import * as stats from './stats.js';
import * as audit from './audit.js';

export const api = { policies, settings, stats, audit };
