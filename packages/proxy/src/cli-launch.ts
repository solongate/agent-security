#!/usr/bin/env node
/**
 * The `solongate` entry point: the Go CLI when there is one, this package's
 * TypeScript when there is not.
 *
 * Kept as its own tiny module rather than folded into index.ts because ESM
 * hoists imports — code at the top of index.ts still runs after its whole module
 * graph (the MCP SDK, React, Ink) has been evaluated, which is most of what the
 * delegation is trying to avoid paying. Nothing is imported here but node
 * builtins, and index.js is reached through a dynamic import that only happens
 * on the fallback path.
 *
 * WHAT IS AND IS NOT DELEGATED, and why the line is where it is:
 *
 * Human subcommands go to Go. That is where the port is complete — all seven
 * dataroom panels, every command in the table — and where a failure is a person
 * looking at a terminal who can read an error and try again.
 *
 * The MCP PROXY RUNTIME stays on TypeScript. A Go implementation exists and is
 * wired to the same policy engine, but it has no conformance suite the way the
 * guard hook does, and it sits in front of every tool call an agent makes. "It
 * compiles and the tests pass" is not evidence about a protocol surface nobody
 * has driven end to end. Moving this line is a decision to make on purpose, with
 * a suite to back it, not a side effect of shipping the CLI.
 *
 * Failure here is not a security event — a CLI that will not start is visible,
 * unlike a guard that quietly stops guarding — but it still falls through to the
 * TypeScript rather than exiting, because a working slow path beats a broken
 * fast one for the same reason it does in the hook.
 */
import { accessSync, constants, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';

// The commands the Go binary owns. Matches cliSubcommands in
// packages/proxy-go/main.go; a name in one and not the other means a command
// that either never reaches Go or reaches it and is not understood.
const GO_SUBCOMMANDS = new Set([
  'repair', 'logs-server', 'local-logs', 'policy', 'ratelimit', 'dlp',
  'stats', 'audit', 'sessions', 'session', 'doctor', 'watch', 'alerts',
  'webhooks', 'dataroom',
  // The `browser` command is gone on purpose: the agent installs, arranges and
  // restarts itself, and everything a person manages is on the dashboard. There
  // is no subcommand to delegate, and the proxy-go test that reads this list
  // enforces that the two halves agree.
]);
const GO_INFO_ARGS = new Set(['login', 'help', '--help', '-h', '--version', '-v', 'version']);

const argv = process.argv.slice(2);
const first = argv[0] ?? '';
// No arguments at all is the dataroom, which is the Go TUI.
const delegable = argv.length === 0 || GO_SUBCOMMANDS.has(first) || GO_INFO_ARGS.has(first);

function candidates(): string[] {
  const out: string[] = [];
  if (process.env.SOLONGATE_CLI_BIN) out.push(process.env.SOLONGATE_CLI_BIN);
  const exe = process.platform === 'win32' ? 'solongate.exe' : 'solongate';
  const os_ = process.platform === 'win32' ? 'win32' : process.platform;
  const cpu = process.arch === 'x64' ? 'x64' : process.arch;
  try {
    const req = createRequire(import.meta.url);
    out.push(join(dirname(req.resolve(`@solongate/guard-${os_}-${cpu}/package.json`)), exe));
  } catch {
    // No platform package for this host: optionalDependencies declined it, which
    // is the supported outcome rather than an error.
  }
  out.push(resolve(homedir(), '.solongate', 'bin', exe));
  return out;
}

function runGo(): number | null {
  for (const bin of candidates()) {
    try {
      if (!existsSync(bin)) continue;
      if (process.platform !== 'win32') accessSync(bin, constants.X_OK);
    } catch { continue; }
    // stdio inherited: this is an interactive terminal program — a TUI, a
    // prompt, a pager. Capturing its output would break all three, and unlike
    // the guard there is no payload to preserve for a fallback.
    const r = spawnSync(bin, argv, { stdio: 'inherit' });
    if (r.error || r.signal) return null;
    // 69 is the binary's own "I do not implement this": fall through rather than
    // reporting a failure the TypeScript can still handle.
    if (r.status === 69) return null;
    return r.status ?? 0;
  }
  return null;
}

if (delegable && process.env.SOLONGATE_NO_GO_CLI !== '1') {
  let code: number | null = null;
  try { code = runGo(); } catch { code = null; }
  if (code !== null) process.exit(code);
}

// Computed rather than written as a literal on purpose. A bundler resolves
// `import('./index.js')` at build time and inlines the whole module graph into
// this file, which puts back exactly the startup cost this entry exists to
// skip — measured at 690 KB in one bundle before this line looked like this.
// A URL it cannot analyse stays a real runtime import of a real sibling file.
await import(new URL('./index.js', import.meta.url).href);
