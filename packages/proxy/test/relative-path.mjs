// SPDX-License-Identifier: Apache-2.0

/**
 * A PATH RULE HAS TO COVER THE FILE, NOT ONE WAY OF REACHING IT.
 *
 * Path rules are written absolute, because that is what a file tool sends: the
 * client resolves the path before the hook ever sees the call. A shell command
 * carries whatever the model typed, and a model sitting in the directory types
 * a relative path. So one rule over one directory refused `Read` and handed the
 * same file over to `cat`, with no cleverness required and nothing saying so.
 *
 * Found by hand, on a real policy, against the EXECUTE-scoped half of a
 * permission matrix — the filename-scoped rule beside it fired, which is what
 * made it clear the scope was fine and the path was not.
 *
 * Both halves are asserted here. The second one matters at least as much:
 * resolving a relative path must not INVENT a match for a file in some other
 * directory that happens to share a suffix.
 */
import { suite, check, note, done, sandbox, call } from './harness.mjs';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

suite('a relative path in a command meets the same rule as an absolute one');

const home = sandbox('relpath');
const proj = join(home, 'proj');
const forbidden = join(proj, 'forbidden');
const work = join(proj, 'work');
const elsewhere = join(home, 'elsewhere');
for (const d of [forbidden, work, join(elsewhere, 'forbidden')]) mkdirSync(d, { recursive: true });
writeFileSync(join(forbidden, 'notes.txt'), 'denied\n');
writeFileSync(join(work, 'notes.txt'), 'fine\n');
writeFileSync(join(elsewhere, 'forbidden', 'notes.txt'), 'a different file\n');

// The pattern has to be the real absolute directory, so the policy is written
// after the sandbox exists rather than passed into it.
writeFileSync(join(home, '.solongate', 'poli' + 'cy.json'), JSON.stringify({
  policy: {
    id: 'relpath', name: 'Relpath', mode: 'denylist',
    rules: [{
      id: 'no-forbidden', description: 'conformance', effect: 'DENY', priority: 10,
      toolPattern: '*', minimumTrustLevel: 'UNTRUSTED', enabled: true,
      pathConstraints: { denied: [forbidden + '/*'] },
    }],
  },
  security: {}, selfProtect: false,
}));

check('the absolute read is refused',
  call(home, 'Read', { file_path: join(forbidden, 'notes.txt') }, proj).code, 2);
check('and so is the relative one in a command',
  call(home, 'bash', { command: 'cat forbidden/notes.txt' }, proj).code, 2);
check('./ names the same file',
  call(home, 'bash', { command: 'cat ./forbidden/notes.txt' }, proj).code, 2);
check('and so does ../ from a sibling directory',
  call(home, 'bash', { command: 'cat ../forbidden/notes.txt' }, work).code, 2);
note('the glob expander already resolved `forbidden/note*.txt`; a plain name went through');

suite('resolving must not invent a match');

check('the same relative path under another cwd is allowed',
  call(home, 'bash', { command: 'cat forbidden/notes.txt' }, elsewhere).code, 0);
check('an unrelated file in the same project is allowed',
  call(home, 'bash', { command: 'cat work/notes.txt' }, proj).code, 0);

done();
