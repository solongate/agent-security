/**
 * The policy MODE decides the default, and getting it backwards is silent.
 *
 * The compiled policy always carries `default decision := DENY` — that is
 * whitelist semantics, baked into the generated Rego. Mode has to be re-applied
 * on top of the engine's answer, and the two failure modes are equally quiet:
 * read a denylist as its default and every ordinary call is blocked; read a
 * whitelist as its default and the strict policy a user switched on enforces
 * nothing at all.
 *
 * Nothing pinned this before, because the rest of the suite only ever drives a
 * denylist policy. Both modes are asserted here, from both directions, plus the
 * precedence between them: a DENY outranks a matching ALLOW.
 */
import { suite, check, note, done, sandbox, call } from './harness.mjs';

const rule = (over) => ({
  id: 'r', description: 'conformance', effect: 'DENY', priority: 10,
  toolPattern: '*', minimumTrustLevel: 'UNTRUSTED', enabled: true, ...over,
});

const policy = (mode, rules) => ({ id: 'conformance-mode', name: 'Mode', mode, rules });

suite('policy mode — denylist allows unless a DENY matched');

let home = sandbox('mode-denylist', {
  policy: policy('denylist', [
    rule({ id: 'no-marker', commandConstraints: { denied: ['*sg-conformance-deny*'] } }),
  ]),
});
check('an unmatched call is allowed', call(home, 'bash', { command: 'echo hello' }).code, 0);
check('a matched DENY blocks', call(home, 'bash', { command: 'echo sg-conformance-deny' }).code, 2);
note('default-allow: the engine answers DENY when nothing matched, and that is not a denial');

suite('policy mode — whitelist denies unless an ALLOW matched');

home = sandbox('mode-whitelist', {
  policy: policy('whitelist', [
    rule({ id: 'only-echo', effect: 'ALLOW', commandConstraints: { allowed: ['echo*'] } }),
  ]),
});
check('a matched ALLOW passes', call(home, 'bash', { command: 'echo hello' }).code, 0);
const blocked = call(home, 'bash', { command: 'curl localhost/x' });
check('an unmatched call is blocked', blocked.code, 2);
check('  the block carries a reason', blocked.stderr.trim().length > 0, true);

suite('policy mode — a whitelist with no ALLOW rule at all blocks everything');

home = sandbox('mode-whitelist-empty', { policy: policy('whitelist', []) });
check('nothing gets through', call(home, 'bash', { command: 'echo hello' }).code, 2);
note('a strict policy with nothing allowed is strict, not disabled');

suite('policy mode — DENY outranks a matching ALLOW');

home = sandbox('mode-precedence', {
  policy: policy('whitelist', [
    rule({ id: 'only-echo', effect: 'ALLOW', priority: 10, commandConstraints: { allowed: ['echo*'] } }),
    rule({ id: 'never-secret', effect: 'DENY', priority: 1, commandConstraints: { denied: ['*secret*'] } }),
  ]),
});
check('the DENY wins', call(home, 'bash', { command: 'echo secret' }).code, 2);
check('the ALLOW still works otherwise', call(home, 'bash', { command: 'echo hello' }).code, 0);

suite('policy mode — no policy at all enforces nothing');

home = sandbox('mode-none', { policy: null });
check('an unselected policy is not an empty whitelist', call(home, 'bash', { command: 'echo hello' }).code, 0);
note('a plain launch is intentionally unrestricted; that must not read as strict mode');

process.exit(done() === 0 ? 0 : 1);
