// SPDX-License-Identifier: Apache-2.0

/**
 * The limit holds when calls arrive together — which is the only case that
 * matters, because a burst is exactly what a rate limit exists to stop.
 *
 * The counter was a JSON array of timestamps: read it, count, push, write the
 * whole thing back. Parallel hooks each read the same array and each wrote back
 * their own copy, so increments were lost. Measured before the fix, with a limit
 * of 5 and 30 calls fired at once: 7, 8, 5, 14, 11 got through across five
 * rounds. Nearly three times the limit.
 */
import { suite, check, note, done, sandbox, call, burst } from './harness.mjs';

const LIMIT = 5;
const RL = { security: { rateLimit: { mode: 'block', perMinute: LIMIT, perHour: 0, perDay: 0 } } };
const tally = (rs) => ({ allowed: rs.filter((x) => x.code === 0).length, denied: rs.filter((x) => x.code === 2).length });

suite(`rate limit — sequential, limit ${LIMIT}/min`);

let home = sandbox('rl-seq', RL);
const seq = [];
for (let i = 0; i < 20; i++) seq.push(call(home, 'bash', { command: `echo ${i}` }));
let t = tally(seq);
note(`allowed ${t.allowed} · denied ${t.denied}`);
check('exactly the limit gets through', t.allowed, LIMIT);
check('the rest are refused', t.denied, 20 - LIMIT);

suite(`rate limit — 30 calls fired at once, limit ${LIMIT}/min`);

// EXACTLY the limit, not "at most". Counting everything in the window after
// appending held the ceiling and lost the floor: the process that counted last
// saw all thirty records and refused itself, though it was among the first five
// to reserve, so how many got through depended on the interleaving. A limit of 5
// let 3 through on a loaded machine and this case failed on a run where nothing
// had changed. Each record carries a token now and a call is allowed when fewer
// than `limit` records sit ahead of its own, which is the same answer whenever a
// process happens to look.
home = sandbox('rl-burst', RL);
t = tally(await burst(home, 30));
note(`allowed ${t.allowed} · denied ${t.denied}`);
check('never over the limit', t.allowed <= LIMIT, true);
check('and never under it either', t.allowed, LIMIT);

suite('rate limit — a spent window stays spent');

t = tally(await burst(home, 10));
check('nothing gets through once the window is gone', t.allowed, 0);

process.exit(done() === 0 ? 0 : 1);
