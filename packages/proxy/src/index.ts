#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0

/**
 * The SolonGate CLI.
 *
 * Every command here reads or changes a security posture, so the whole surface
 * is gated to a real terminal. What it does NOT do any more is stand in front of
 * a tool server: this file used to end in an MCP proxy runtime, and SolonGate is
 * not an MCP gateway. The guard runs on a client's tool call hook, and the
 * commands below are how a person configures it.
 */

const CLI_SUBCOMMANDS = new Set(['repair', 'policy', 'ratelimit', 'dlp', 'stats', 'audit', 'doctor', 'trace', 'watch', 'dataroom']);
// Human-facing flags/aliases that print a banner and must keep normal console
// output (no [SolonGate] prefix): help, version, and the removed `login` alias.
const CLI_INFO_ARGS = new Set(['login', 'help', '--help', '-h', '--version', '-v', 'version']);
const IS_HUMAN_CLI = process.argv.length <= 2 || CLI_SUBCOMMANDS.has(process.argv[2] ?? '') || CLI_INFO_ARGS.has(process.argv[2] ?? '');
if (!IS_HUMAN_CLI) {
  console.log = (...args: unknown[]) => {
    process.stderr.write(`[SolonGate] ${args.map(String).join(' ')}\n`);
  };
  console.warn = (...args: unknown[]) => {
    process.stderr.write(`[SolonGate WARN] ${args.map(String).join(' ')}\n`);
  };
  console.error = (...args: unknown[]) => {
    process.stderr.write(`[SolonGate ERROR] ${args.map(String).join(' ')}\n`);
  };
}

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { c } from './cli-utils.js';

// Package version for `solongate --version`, read from the shipped package.json
// (dist/index.js sits one level below it). Falls back gracefully if unreadable.
const PKG_VERSION: string = (() => {
  try {
    const p = join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
    return (JSON.parse(readFileSync(p, 'utf-8')).version as string) || 'unknown';
  } catch { return 'unknown'; }
})();

/**
 * Bare-run welcome — printed when a human runs `npx @solongate/proxy` with no
 * arguments. The proxy normally runs under an MCP client (`-- <command>`); a
 * plain invocation means someone is trying it out, so the only thing we ask of
 * them is the single onboarding command. No upstream wiring, no API keys.
 */
function printWelcome() {
  console.log('');
  console.log(`  ${c.bold}${c.blue4}SolonGate${c.reset} ${c.dim}secure gateway for your AI agents${c.reset}`);
  console.log('');
  console.log('  Get started with one command:');
  console.log('');
  console.log(`    ${c.cyan}solongate${c.reset}             ${c.dim}open the dataroom (policies, audit, settings)${c.reset}`);
  console.log(`    ${c.cyan}solongate --help${c.reset}      ${c.dim}list every command${c.reset}`);
  console.log('');
  // IT TOLD PEOPLE TO LOG IN. "Open the dataroom, log in from the Accounts panel to
  // pair this device" was the first sentence a new user read, and there is no account
  // to add and no panel to add it from — so the one instruction on the welcome screen
  // could not be followed. The Go twin (printWelcome in main.go) already said this;
  // the two disagreeing about the first thing a user sees is the worst place for it.
  console.log(`  ${c.dim}Open the dataroom to install the guard and write a policy. The${c.reset}`);
  console.log(`  ${c.dim}policy is a file on this machine: ${c.reset}${c.cyan}~/.solongate/policy.json${c.reset}`);
  console.log('');
}

/**
 * `solongate --help` / `-h` / `help` — the FULL command tree, every sub-command
 * and its exact syntax, so config commands (how to edit a rate limit, a policy,
 * a DLP rule) are discoverable from the CLI without opening the dataroom. Kept in
 * sync with the individual commands' own `help` usage blocks.
 */
function printHelp() {
  const W = 46; // syntax column width
  const head = (t: string) => console.log(`\n  ${c.bold}${t}${c.reset}`);
  // Print a command line: cyan syntax + dim description. Long syntaxes drop to
  // their own line with the description indented under them.
  const cmd = (syntax: string, desc = '') => {
    if (!desc) { console.log(`    ${c.cyan}${syntax}${c.reset}`); return; }
    if (syntax.length <= W) {
      console.log(`    ${c.cyan}${syntax}${c.reset}${' '.repeat(W - syntax.length)}${c.dim}${desc}${c.reset}`);
    } else {
      console.log(`    ${c.cyan}${syntax}${c.reset}`);
      console.log(`    ${' '.repeat(W)}${c.dim}${desc}${c.reset}`);
    }
  };
  console.log('');
  console.log(`  ${c.bold}${c.blue4}SolonGate${c.reset} ${c.dim}secure gateway for your AI agents${c.reset}  ${c.dim}v${PKG_VERSION}${c.reset}`);
  console.log('');
  console.log(`  ${c.dim}Usage:${c.reset} ${c.cyan}solongate${c.reset} ${c.dim}[command]${c.reset}   ${c.dim}(no command opens the dataroom: all of this in a terminal UI)${c.reset}`);

  head('Setup & status');
  cmd('solongate', 'open the dataroom UI (login, policies, audit, settings)');
  cmd('repair', 'restore the guard + hook + settings files if they were deleted or disarmed');
  cmd('doctor', 'health check: login, policy, guard, local logs');
  cmd('trace [--limit N]', 'what the guard saw in this directory, allows included');
  cmd('doctor --json', 'the same health check as machine-readable JSON');

  head('Policies');
  cmd('policy list', 'list all policies');
  cmd('policy create <name>', 'create a new empty policy');
  cmd('policy delete <id>', 'delete a policy');
  cmd('policy show <id>', 'show one policy (rules, mode)');
  cmd('policy allow <id> [--command|--path|--filename|--url <val>]', 'add an ALLOW rule');
  cmd('policy deny <id> [--command|--path|--filename|--url <val>]', 'add a DENY rule');
  cmd('  --permission READ,WRITE,EXECUTE,NETWORK', 'scope an allow/deny to a class of call');
  cmd('policy mode <id> <denylist|whitelist>', 'switch deny-by-default / allow-by-default');
  cmd('policy rule <id> <ruleId> <enable|disable>', 'turn one rule on or off without deleting it');
  cmd('policy revoke <id> <ruleId>', 'remove a rule');
  cmd('policy activate <id> | --off', 'pin the active policy, or enforce nothing');
  cmd('policy active', 'show the resolved active policy');

  head('Rate limits');
  cmd('ratelimit show', 'current limits + change history');
  cmd('ratelimit set --minute N [--hour N] [--day N] [--mode off|detect|block]', 'edit limits (unset fields kept)');
  cmd('ratelimit history', 'recent limit changes');

  head('DLP (secrets)');
  cmd('dlp show', 'current mode + enabled patterns');
  cmd('dlp mode <off|detect|redact|block>', 'detect records, redact masks, block refuses');
  cmd('dlp enable <pattern>', 'enable a built-in pattern');
  cmd('dlp disable <pattern>', 'disable a built-in pattern');
  cmd('dlp add-custom --name X --re <regex>', 'add a custom pattern');
  cmd('dlp remove-custom <name>', 'remove a custom pattern');


  head('Monitoring');
  cmd('audit [--filter ALLOW|DENY] [--tool <s>] [--signal dlp|ratelimit] [--limit N]', 'browse the audit log');
  cmd('audit whitelist <logId> [--scope exact|tool]', 'turn a denial into an ALLOW rule');
  cmd('audit block <logId> [--scope exact|tool]', 'turn a call into a DENY rule');
  cmd('stats [timeseries|drift]', 'traffic & security statistics');
  cmd('watch [--filter DENY] [--tool <s>]', 'live-tail tool calls (Ctrl+C to stop)');

  console.log('');
  console.log(`  ${c.dim}Add ${c.reset}${c.cyan}--json${c.reset}${c.dim} to most read commands for machine output.${c.reset}`);
  console.log(`  ${c.dim}Details for a command: ${c.reset}${c.cyan}solongate <command> help${c.reset}`);
  console.log('');
}

/**
 * HUMAN-ONLY GATE.
 *
 * Every command in this CLI reads or changes your security posture (policies,
 * rate limits, DLP, the guard itself). An AI agent must never be able to run
 * them as a tool call — otherwise a compromised or prompt-injected agent could
 * simply disable the thing that is supposed to be watching it.
 *
 * Two independent signals, either one refuses:
 *   1. No interactive terminal. An agent tool call pipes stdin/stdout, so there
 *      is no TTY on both ends. A person at a terminal always has one.
 *   2. A known agent marker in the environment, even if a TTY somehow exists.
 *
 * THERE IS NO EXEMPTION. SOLONGATE_INTERNAL=1 used to be one, for the detached
 * logs-server daemon that spawned itself — and that daemon is gone, so the
 * variable had no legitimate setter left and was only a way past this gate. An
 * agent that exported it would have been let straight through to edit policy.
 */
// Env-name PREFIXES that only ever exist inside an AI agent's process tree, not
// a plain human shell. Prefix-matched (not exact) so we catch whichever specific
// variable a given agent leaks into a tool subprocess — e.g. Antigravity/agy
// leaks many ANTIGRAVITY_* / CORTEX_* / GEMINI_* vars; we don't need to know
// which one, only the family. A human who runs these commands from inside an
// agent's integrated terminal is refused too, on purpose ("no exceptions").
const AGENT_ENV_PREFIXES = [
  'CLAUDECODE', 'CLAUDE_CODE', 'CLAUDE_AGENT',
  'ANTIGRAVITY', 'CORTEX_', 'CASCADE_', 'WINDSURF', 'JETSKI', 'EXA_',
  'GEMINI_CLI', 'GEMINI_SESSION', 'GEMINI_PROJECT', 'GEMINI_CWD',
  'CURSOR', 'AIDER', 'OPENAI_CODEX', 'CODEX_', 'OPENCLAW', 'REPLIT', 'DEVIN',
];
function agentMarker(): string | null {
  for (const k of Object.keys(process.env)) {
    if (AGENT_ENV_PREFIXES.some((p) => k === p || k.startsWith(p))) return k;
  }
  return null;
}
function assertHumanTerminal(): void {
  const marker = agentMarker();
  const isTty = Boolean(process.stdin.isTTY && process.stdout.isTTY);
  if (isTty && !marker) return;
  const w = (s: string): void => void process.stderr.write(s + '\n');
  w('');
  w('  SolonGate is human-only.');
  w('  These commands control your security policy, so they cannot be run by an AI');
  w('  agent or any non-interactive process. Run them yourself, in a terminal.');
  w(marker ? `  (refused: agent environment detected via ${marker})` : '  (refused: no interactive terminal)');
  w('');
  process.exit(1);
}

async function main() {
  // Check for subcommands: `npx @solongate/proxy <subcommand>`
  const subcommand = process.argv[2];

  // Gate the human-facing CLI. The MCP proxy runtime (`-- <cmd>`) is not gated:
  // it is meant to be launched by a client and never edits security config.
  if (IS_HUMAN_CLI) assertHumanTerminal();

  // Help / version — print and exit before any runtime setup.
  if (subcommand === '--help' || subcommand === '-h' || subcommand === 'help') {
    printHelp();
    return;
  }
  if (subcommand === '--version' || subcommand === '-v' || subcommand === 'version') {
    console.log(PKG_VERSION);
    return;
  }

  // Bare invocation (no subcommand, no upstream): the management TUI on an
  // interactive terminal, the welcome otherwise. It used to turn on whether the
  // device was PAIRED, opening the dataroom even when it was not so the user could log
  // in from inside it — there is nothing to pair, so the only question left is whether
  // a person is watching.
  if (process.argv.length <= 2) {
    if (process.stdout.isTTY && process.stdin.isTTY) {
      const { launchTui } = await import('./tui/index.js');
      await launchTui();
      return;
    }
    printWelcome();
    return;
  }

  // Interactive management TUI.
  if (subcommand === 'dataroom') {
    const { launchTui } = await import('./tui/index.js');
    await launchTui();
    return;
  }

  // Scriptable management commands (policy / ratelimit / dlp / stats / audit /
  // agents). Kept behind a dynamic import so the proxy runtime never loads the
  // API-client / command layer.
  const MGMT_COMMANDS = new Set(['policy', 'ratelimit', 'dlp', 'stats', 'audit', 'doctor', 'trace', 'watch']);
  if (MGMT_COMMANDS.has(subcommand ?? '')) {
    const { runCommand } = await import('./commands/index.js');
    const code = await runCommand(subcommand!, process.argv.slice(3));
    process.exit(code);
  }

  if (subcommand === 'repair') {
    const { runRepair } = await import('./global-install.js');
    process.exit(await runRepair());
  }

  // ANYTHING LEFT IS NOT A COMMAND. It used to fall through to an MCP proxy
  // runtime, which spawned the token as an upstream program: `solongate h`
  // failed with "spawn h ENOENT" under a wall of startup logs. That runtime is
  // gone, so there is nothing to fall through to and nothing to guess at.
  //
  // Written to stdout directly so it is not wrapped in a [SolonGate] prefix.
  process.stdout.write(`\n  Unknown command: ${subcommand}\n`);
  process.stdout.write(`  Run \`solongate --help\` to see every command, or \`solongate\` for the dataroom.\n\n`);
  process.exit(1);
}

main();
