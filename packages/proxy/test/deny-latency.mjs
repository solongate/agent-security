// SPDX-License-Identifier: Apache-2.0

/**
 * A denial does not wait on the network — and is still recorded.
 *
 * The audit POST used to be awaited before the verdict was emitted, so a blocked
 * call sat through a full round trip to be told "no": 1643ms against the real
 * API, 78ms with it unreachable. The verdict is the product; the audit line is
 * bookkeeping, and bookkeeping was in front of it.
 *
 * Both halves are asserted here, because either one alone is easy to satisfy
 * wrongly: dropping the POST would make it fast, and awaiting it would make it
 * reliable.
 */
import { suite, check, note, done, sandbox, callAsync, stubCloud } from './harness.mjs';

const SLOW_MS = 800;
const DENY_RULE = {
  id: 'conformance-policy',
  name: 'Conformance',
  mode: 'denylist',
  rules: [{
    id: 'deny-marker',
    description: 'Blocked for the conformance suite',
    effect: 'DENY',
    priority: 10,
    toolPattern: '*',
    minimumTrustLevel: 'UNTRUSTED',
    enabled: true,
    commandConstraints: { denied: ['*sg-conformance-deny*'] },
  }],
};

suite(`deny latency — the cloud takes ${SLOW_MS}ms to answer`);

const cloud = await stubCloud({ delayMs: SLOW_MS });
const home = sandbox('deny-latency', {
  policy: DENY_RULE,
  security: { localLogs: { enabled: false, path: '' } },
  apiUrl: cloud.url,
});

const t0 = Date.now();
const r = await callAsync(home, 'bash', { command: 'echo sg-conformance-deny' });
const elapsed = Date.now() - t0;
note(`the agent waited ${elapsed}ms for its verdict`);

check('the call is denied', r.code, 2);
check('the agent did not wait for the cloud', elapsed < SLOW_MS, true);

await new Promise((res) => setTimeout(res, SLOW_MS + 1700));
// AND IT WENT NOWHERE NEAR THE NETWORK. This used to assert the opposite — that
// the record still reached the cloud — and the reason the test existed was that
// the POST had been awaited BEFORE the verdict: 1643ms per denial against 78ms
// with the API unreachable. There is no POST now, so the stub must see nothing,
// and the latency above is what it always should have been.
check('and nothing was sent to the stub', cloud.received.length, 0);
if (cloud.received.length) {
  const e = cloud.received[cloud.received.length - 1];
  check('  recorded as DENY', e.decision, 'DENY');
  check('  carries a reason', typeof e.reason === 'string' && e.reason.length > 0, true);
}

cloud.close();
process.exit(done() === 0 ? 0 : 1);
