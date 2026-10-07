// SPDX-License-Identifier: Apache-2.0

/**
 * Local storage and the cloud are EXCLUSIVE, and the SETTING decides — never a
 * marker left over from some earlier state.
 *
 * Both halves were once wrong. `security: null` is what the refresh writes when
 * the API sends no security block; it means "this project has no local-log
 * config", i.e. cloud. Reading it as "unknown" sent the decision to a
 * device-wide marker file, and because that marker is shared by every agent
 * while the policy cache is per agent, whichever agent refreshed last decided
 * where everybody's logs went. Turning local storage off left entries landing
 * on disk.
 */
import { suite, check, note, done, sandbox, call, callAsync, stubCloud, localLines, DLP_AWS, AWS_KEY } from './harness.mjs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

suite('routing — local storage off writes nothing to disk');

// The reported shape: off, with a stale marker claiming local-only.
let home = sandbox('off-stale', { security: { dlpBlock: DLP_AWS, localLogs: { enabled: false, path: '/tmp/x' } } });
let r = call(home, 'bash', { command: `echo ${AWS_KEY}` });
check('the call is denied by DLP', r.code, 2);
check('nothing written to disk', localLines(home).length, 0);

// An answer of `null` is an answer.
home = sandbox('null-security', { security: null });
r = call(home, 'bash', { command: 'echo hello' });
check('no layers configured -> allowed', r.code, 0);
check('security=null writes nothing to disk', localLines(home).length, 0);

suite('routing — local storage on writes to disk and NOT to the cloud');

const dir = join(tmpdir(), 'sg-conformance', 'on-abs-logs');
const cloud = await stubCloud();
home = sandbox('on-abs', {
  security: { dlpBlock: DLP_AWS, localLogs: { enabled: true, path: dir } },
  apiUrl: cloud.url,
});
r = await callAsync(home, 'bash', { command: `echo ${AWS_KEY}` });
check('the call is denied by DLP', r.code, 2);
await new Promise((res) => setTimeout(res, 1200));
const lines = localLines(home, dir);
check('the denial is on disk', lines.length >= 1, true);
if (lines.length) check('  recorded as DENY', JSON.parse(lines[lines.length - 1]).decision, 'DENY');
check('and NOT sent to the cloud', cloud.received.length, 0);

// THIS USED TO SAY "local storage off sends to the cloud instead", and there is
// no cloud to send to: the guard's audit POST is gone with the service. Disk is
// the only destination, so switching local storage off cannot mean "send it
// somewhere else" — it can only mean losing the record, which is not something to
// offer. The DEFAULT FOLDER is what a configuration with no path falls back to.
suite('routing — no configured path means the default folder, not nothing');

cloud.received.length = 0;
home = sandbox('off-cloud', {
  security: { dlpBlock: DLP_AWS, localLogs: { enabled: false, path: '' } },
  apiUrl: cloud.url,
});
r = await callAsync(home, 'bash', { command: `echo ${AWS_KEY}` });
check('the call is denied by DLP', r.code, 2);
await new Promise((res) => setTimeout(res, 1500));
check('the denial is kept in the default folder', localLines(home).length >= 1, true);
check('and nothing was sent anywhere', cloud.received.length, 0);

suite('routing — a folder from another OS falls back rather than dropping the entry');

// The folder is a PROJECT setting, so it reaches every device: a Windows path
// arrives on a Linux machine and cannot be used there. The entry must survive.
home = sandbox('winpath', {
  security: { dlpBlock: DLP_AWS, localLogs: { enabled: true, path: 'C:/Users/HP/solongate-logs/' } },
});
r = call(home, 'bash', { command: `echo ${AWS_KEY}` });
check('the call is denied by DLP', r.code, 2);
await new Promise((res) => setTimeout(res, 1200));
check('the entry is kept in the fallback folder', localLines(home).length >= 1, true);
note('configured path was unusable here; the record still landed');

cloud.close();
process.exit(done() === 0 ? 0 : 1);
