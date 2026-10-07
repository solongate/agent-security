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

// The ceiling is the property. Reserve-then-check can come in one UNDER when two
// processes append in the same instant and each counts the other — conservative,
// and the right direction for a limiter to err in.
home = sandbox('rl-burst', RL);
t = tally(await burst(home, 30));
note(`allowed ${t.allowed} · denied ${t.denied}`);
check('never over the limit', t.allowed <= LIMIT, true);
check('still lets a useful number through', t.allowed >= LIMIT - 1, true);

suite('rate limit — a spent window stays spent');

t = tally(await burst(home, 10));
check('nothing gets through once the window is gone', t.allowed, 0);

process.exit(done() === 0 ? 0 : 1);
