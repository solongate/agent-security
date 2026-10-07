// SPDX-License-Identifier: Apache-2.0

/**
 * Does the guard actually RUN? Not "is it registered" — that question was
 * already answered, and it answered yes the whole time nothing was enforced.
 *
 * The gap this closes: a hook is a command string in somebody else's config
 * file, and every check this CLI had read the string. A string can name a node
 * binary that a `brew upgrade` deleted, or a hook file somebody removed, and it
 * still reads as "guard registered". The client spawns it, the spawn fails, and
 * the client says nothing — Claude Code does not report a hook that could not
 * start. From the outside that is indistinguishable from a machine with no
 * guard on it at all, which is exactly what it is.
 *
 * So there are two facts here that no amount of reading a config can produce:
 *
 *   canStart  the command in the config, run for real, reaches a node that
 *             executes. Checked by running it.
 *   lastFired when the client last invoked the hook. Recorded by the launcher
 *             itself, before it does anything else, so it is true even when
 *             everything after it fails.
 *
 * Together they separate the three states that used to look the same: never
 * invoked (the client is not calling us), invoked but cannot start (the node
 * path is dead), and starting fine but enforcing nothing (a credential
 * problem, which the existing checks already cover).
 */
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { BEAT_DIR, LAUNCHER_NAME } from './hook-launcher.js';

/**
 * The two paths this file needs, derived here rather than imported from
 * global-install.
 *
 * That module imports this one — repair reports the runtime — and a cycle
 * between them is the kind that works until an import order changes and then
 * fails at module init with an undefined function. Two joins are cheaper than
 * that risk, and these are the same two constants global-install builds.
 */
const sgDir = (): string => join(homedir(), '.solongate');
const hooksDir = (): string => join(sgDir(), 'hooks');

export interface HookStart {
  ok: boolean;
  /** The node the launcher resolved, when it resolved one. */
  node?: string;
  detail: string;
}

/**
 * Run the launcher's own resolution and report what it found.
 *
 * It runs the INSTALLED launcher rather than reimplementing its search here.
 * A second copy of the candidate list would drift from the first, and the drift
 * would be invisible: the check would pass while the thing it stands for
 * failed.
 */
export function hookCanStart(): HookStart {
  const launcher = join(hooksDir(), LAUNCHER_NAME);

  if (process.platform === 'win32') {
    // Windows names node directly in the command, so the question there is
    // whether that path still exists.
    const ok = existsSync(process.execPath);
    return { ok, node: process.execPath, detail: ok ? process.execPath : `${process.execPath} is gone` };
  }

  if (!existsSync(launcher)) {
    return { ok: false, detail: 'hook launcher missing - run `solongate repair`' };
  }
  try {
    const out = execFileSync('/bin/sh', [launcher, '--sg-doctor'], {
      encoding: 'utf-8',
      timeout: 5000,
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    if (!out) return { ok: false, detail: 'launcher found no node runtime - set SOLONGATE_NODE or install node' };
    return { ok: true, node: out, detail: out };
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return { ok: false, detail: `launcher will not run: ${msg.split('\n')[0]}` };
  }
}

export interface HookBeat {
  hook: string;
  at: Date;
  /** What the launcher resolved that time, or `no-node` when it resolved nothing. */
  node: string;
}

/** Every hook that has ever been invoked on this machine, newest first. */
export function hookBeats(): HookBeat[] {
  const dir = join(sgDir(), BEAT_DIR);
  const out: HookBeat[] = [];
  for (const hook of ['guard.mjs', 'audit.mjs', 'tokens.mjs', 'stop.mjs']) {
    const f = join(dir, hook);
    try {
      const st = statSync(f);
      out.push({ hook, at: st.mtime, node: readFileSync(f, 'utf-8').trim() });
    } catch {
      /* never fired, or the beat was removed */
    }
  }
  return out.sort((a, b) => b.at.getTime() - a.at.getTime());
}

/** The guard's own beat, which is the one that means enforcement happened. */
export function guardBeat(): HookBeat | null {
  return hookBeats().find((b) => b.hook === 'guard.mjs') ?? null;
}

export function agoLabel(d: Date): string {
  const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
  if (s < 60) return s <= 3 ? 'just now' : `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86_400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86_400)}d ago`;
}
