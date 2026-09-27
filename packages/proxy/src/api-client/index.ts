/**
 * SolonGate Cloud API client — shared by the CLI commands and the Ink TUI.
 * Import as `import { api } from './api-client/index.js'` then `api.policies.list()`.
 */
export * from './client.js';
export * from './types.js';
export * from './device-login.js';

import * as auth from './auth.js';
import * as policies from './policies.js';
import * as settings from './settings.js';
import * as stats from './stats.js';
import * as audit from './audit.js';
import * as agents from './agents.js';
import * as keys from './keys.js';
import * as mcp from './mcp.js';

export const api = { auth, policies, settings, stats, audit, agents, keys, mcp };
