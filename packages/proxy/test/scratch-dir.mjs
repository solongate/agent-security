// SPDX-License-Identifier: Apache-2.0

/**
 * Per-call flags stay out of the directories people work in.
 *
 * They used to be written to `./.solongate/`, relative to wherever the agent
 * happened to be, which left a dot-folder in every directory an agent had ever
 * touched — seventeen on one machine, including ~/.config/ags, ~/.local/bin and
 * repos with no ignore rule for it. Anyone who found one read it as "local
 * logging is on", which is a different setting entirely.
 *
 * The sweep that clears them is deliberately narrow, and that narrowness is the
 * part worth pinning: someone else's file in a folder of that name must survive.
 */
import { suite, check, note, done, sandbox, call } from './harness.mjs';
import { existsSync, mkdirSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const OURS = ['.eval-ring.jsonl', '.last-eval', '.last-deny', '.last-tool-call'];

suite('scratch — the working directory is left alone');

const work = join(tmpdir(), 'sg-conformance', 'work-dir');
try { rmSync(work, { recursive: true, force: true }); } catch { /* fresh anyway */ }
mkdirSync(join(work, '.solongate'), { recursive: true });
// A legacy folder AND a file that is not ours, so the sweep has something it
// must keep.
for (const f of OURS.slice(0, 2)) writeFileSync(join(work, '.solongate', f), '{}');
writeFileSync(join(work, '.solongate', 'keep-me.txt'), 'not ours');

const home = sandbox('scratch', { security: {} });
call(home, 'bash', { command: 'echo scratch' }, work);

const left = existsSync(join(work, '.solongate')) ? readdirSync(join(work, '.solongate')).sort() : [];
check('only the file that is not ours remains', left, ['keep-me.txt']);
note('our own leftovers were removed; the folder stayed because something else was in it');

suite('scratch — a folder holding only our files is removed entirely');

const work2 = join(tmpdir(), 'sg-conformance', 'work-dir-2');
try { rmSync(work2, { recursive: true, force: true }); } catch { /* fresh anyway */ }
mkdirSync(join(work2, '.solongate'), { recursive: true });
writeFileSync(join(work2, '.solongate', '.last-tool-call'), '1');
call(home, 'bash', { command: 'echo scratch2' }, work2);
check('the folder is gone', existsSync(join(work2, '.solongate')), false);

suite('scratch — the flags went somewhere, they were not just dropped');

// Keyed by a hash of the project path so per-project separation survives. The
// hash lives in three places (guard, audit hook, dataroom) and they must agree
// or the dataroom silently reads an empty ring.
const projectKey = (dir) => {
  let h = 0x811c9dc5;
  for (let i = 0; i < dir.length; i++) {
    h ^= dir.charCodeAt(i);
    h = (h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24))) >>> 0;
  }
  return h.toString(16);
};
// Under the sandbox's HOME, not this process's — that is the home the guard ran
// with, and looking in the real one reports a miss that never happened.
const expected = join(home, '.solongate', 'projects', projectKey(work));
check('written under ~/.solongate/projects/<key>', existsSync(expected), true);
if (existsSync(expected)) note('contents: ' + readdirSync(expected).sort().join(', '));

process.exit(done() === 0 ? 0 : 1);
