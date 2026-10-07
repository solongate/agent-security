// SPDX-License-Identifier: Apache-2.0

/**
 * Scriptable CLI command router. Invoked from src/index.ts for the human
 * management subcommands (policy / ratelimit / dlp / stats / audit).
 *
 * Submodules are STATICALLY imported so tsup bundles this whole layer into one
 * dist chunk (dist/commands/index.js) - the only dynamic boundary is between
 * the proxy runtime (src/index.ts) and this file, keeping the proxy hot path
 * free of the API-client / command code.
 *
 * Every command returns a process exit code. Errors from the API layer
 * (ApiError / NotAuthenticatedError) are caught here and printed as one clean
 * line - no stack traces - so the CLI reads like a tool, not a crash.
 */
import { err, red } from './format.js';
import * as policy from './policy.js';
import * as ratelimit from './ratelimit.js';
import * as dlp from './dlp.js';
import * as stats from './stats.js';
import * as audit from './audit.js';
import * as doctor from './doctor.js';
import * as trace from './trace.js';
import * as watch from './watch.js';

async function dispatch(command: string, argv: string[]): Promise<number> {
  switch (command) {
    case 'policy':
      return policy.run(argv);
    case 'ratelimit':
      return ratelimit.run(argv);
    case 'dlp':
      return dlp.run(argv);
    case 'stats':
      return stats.run(argv);
    case 'audit':
      return audit.run(argv);
    case 'doctor':
      return doctor.run(argv);
    case 'trace':
      return trace.run(argv);
    case 'watch':
      return watch.run(argv);
    default:
      err(`  Unknown command: ${command}`);
      return 1;
  }
}

/**
 * Run a management command. `command` is the subcommand name (e.g. 'policy'),
 * `argv` are the tokens after it. Never throws - resolves to an exit code.
 */
export async function runCommand(command: string, argv: string[]): Promise<number> {
  try {
    return await dispatch(command, argv);
  } catch (e) {
    // One branch, because there is one kind of failure left. The two that were
    // here — not authenticated, and an HTTP status — described a service, and a
    // LocalStoreError already carries a sentence worth printing on its own.
    const msg = e instanceof Error ? e.message : String(e);
    err(red('  ✗ ') + msg);
    return 1;
  }
}

/** The subcommand names this router owns (used by src/index.ts to route). */
export const COMMAND_NAMES = ['policy', 'ratelimit', 'dlp', 'stats', 'audit', 'doctor', 'watch'] as const;
