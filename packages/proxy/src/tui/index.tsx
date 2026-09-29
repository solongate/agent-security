/**
 * TUI entry point. Reached only via dynamic import() from src/index.ts, so React
 * and Ink never load in the proxy runtime hot path.
 */
import { appendFileSync, mkdirSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { render } from 'ink';
import { App } from './App.js';

export async function launchTui(): Promise<void> {
  if (!process.stdout.isTTY || !process.stdin.isTTY) {
    process.stderr.write(
      'The SolonGate TUI needs an interactive terminal.\n' +
        'Use the scriptable commands instead, e.g. `solongate stats`, `solongate policy list`.\n',
    );
    return;
  }
  // No auth gate, and nothing to gate on: there is no account and nothing to pair.
  // Alternate screen buffer — the TUI takes over the whole terminal (like
  // htop/vim) and restores the user's scrollback on exit.
  process.stdout.write('\x1b[?1049h\x1b[H');
  // Console output MUST NOT reach the screen while the TUI owns it. ink's
  // default patchConsole renders every console.log/warn/error (React warnings
  // included) as Static text ABOVE the frame — the frame gets pushed down and
  // the top of the screen freezes at a stale copy. Route console to a debug
  // file instead and render with patchConsole off.
  const debugLog = join(homedir(), '.solongate', 'dataroom-debug.log');
  const saved = { log: console.log, warn: console.warn, error: console.error, info: console.info, debug: console.debug };
  const toFile = (level: string) => (...args: unknown[]) => {
    try {
      mkdirSync(join(homedir(), '.solongate'), { recursive: true });
      appendFileSync(debugLog, `${new Date().toISOString()} [${level}] ${args.map((a) => (typeof a === 'string' ? a : JSON.stringify(a))).join(' ')}\n`);
    } catch {
      /* never disturb the TUI */
    }
  };
  console.log = toFile('log');
  console.warn = toFile('warn');
  console.error = toFile('error');
  console.info = toFile('info');
  console.debug = toFile('debug');
  try {
    const { waitUntilExit } = render(<App />, { patchConsole: false });
    await waitUntilExit();
  } finally {
    Object.assign(console, saved);
    process.stdout.write('\x1b[?1049l');
  }
}
