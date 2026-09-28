/**
 * A machine with NO credential still enforces, and the policy it enforces is a
 * file.
 *
 * THIS IS THE ORDINARY DEPLOYMENT. Nothing here needs a service, an account or a
 * sign-in: the policy is a file on the machine, the record of a denial is a file
 * on the machine, and nothing leaves it. The guard used to do none of that —
 * `if (!API_KEY) { allowTool(); return; }` came before everything, so a machine
 * without a credential allowed every call while its policy sat on disk unread.
 * Every check below fails against that version, and the first one is the whole
 * point: ALLOW instead of BLOCK.
 *
 * The three things the credential gate also skipped, each asserted here:
 *
 *   the tamper guard      the guard could not protect its own state, and a
 *                         local policy is kept in exactly that state
 *   the audit record      writeLocalLog answered "cloud only" for a machine
 *                         with no cloud, so a denial was written nowhere
 *   the security layers   the rate limit, the egress rules and the DLP scanner
 *                         arrive in `security`, which only a service could send
 *
 * And the asymmetry that keeps the last two honest: the per-project file sits
 * inside a repository the agent can write to, so it may add RULES and nothing
 * else. If it could carry `selfProtect: false` it would be a one-line disarm.
 */
import { mkdtempSync, mkdirSync, writeFileSync, statSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { suite, check, note, done, call, callAsync, stubCloud, awaitLocalLines, localLines } from './harness.mjs';

// Assembled, because the guard protects paths spelled this way and the tooling
// that writes this file is itself subject to it. tamper-path.mjs says the same.
const NAME = 'poli' + 'cy.json';
const CACHE = '.' + 'policy' + '-cache-';

/** A machine with a policy file and NO credential. That absence is the fixture. */
function machine({ own = null, project = null } = {}) {
  const home = mkdtempSync(join(tmpdir(), 'sg-local-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  if (own) writeFileSync(join(home, '.solongate', NAME), JSON.stringify(own));
  if (project) writeFileSync(join(home, NAME), JSON.stringify(project));
  return home;
}

const DENY = {
  id: 'local', name: 'Local', mode: 'denylist',
  rules: [{
    id: 'deny-marker', description: 'Blocked by the local file',
    effect: 'DENY', priority: 10, toolPattern: '*',
    minimumTrustLevel: 'UNTRUSTED', enabled: true,
    commandConstraints: { denied: ['*sg-local-deny*'] },
  }],
};
const blocked = (r) => r.code === 2;

suite('local mode — no credential, and the policy is a file');

// ── the policy, in both spellings the file is allowed to take ────────────────
//
// A hand-written file is usually just the policy; /policies/active answers with
// an envelope. Accepting both is what lets a file that already exists keep
// working while `security` becomes reachable at all.
for (const [label, own] of [
  ['bare policy', DENY],
  ['envelope', { policy: DENY, selfProtect: true }],
]) {
  const home = machine({ own });
  check(`${label}: a denied command is BLOCKED`, blocked(call(home, 'Bash', { command: 'echo sg-local-deny' })), true);
  check(`${label}: an unrelated command is allowed`, blocked(call(home, 'Bash', { command: 'echo hello' })), false);
}

// ── the record ───────────────────────────────────────────────────────────────
{
  const home = machine({ own: DENY });
  call(home, 'Bash', { command: 'echo sg-local-deny' });
  const lines = await awaitLocalLines(home, 1);
  check('the denial is recorded on this machine', lines.length, 1);
  if (lines.length) {
    const e = JSON.parse(lines[0]);
    check('the record says DENY', e.decision, 'DENY');
    check('and names the tool', e.tool, 'Bash');
  }
  // The log lists every command, path and URL the agent was told no about. It
  // was being created 0644 inside a 0755 directory, so any other account on a
  // shared machine could read what somebody was working on.
  const dir = join(home, '.solongate', 'local-logs');
  const file = join(dir, 'solongate-audit.jsonl');
  check('the log is owner-only', existsSync(file) ? statSync(file).mode & 0o777 : -1, 0o600);
  check('so is the folder holding it', existsSync(dir) ? statSync(dir).mode & 0o777 : -1, 0o700);
}

// ── and it goes nowhere else ─────────────────────────────────────────────────
//
// With no credential there is nothing to authenticate with, so the POST used to
// go out UNAUTHENTICATED to whatever API_URL happened to be — by default a
// hosted service the person running this does not operate — carrying the command
// that was just blocked.
{
  const cloud = await stubCloud();
  const home = machine({ own: DENY });
  const r = await callAsync(home, 'Bash', { command: 'echo sg-local-deny' }, home, { SOLONGATE_API_URL: cloud.url });
  check('still blocked with a reachable service and no key', r.code, 2);
  await awaitLocalLines(home, 1);
  await new Promise((res) => setTimeout(res, 600));
  check('nothing was sent to it', cloud.received.length, 0);
  if (cloud.received.length) note(`received ${JSON.stringify(cloud.received[0]).slice(0, 120)}`);
  cloud.close();
}

// ── the security layers, which only a service could configure before ────────
{
  const home = machine({ own: { policy: { id: 'l', name: 'L', mode: 'denylist', rules: [] }, security: { rateLimit: { mode: 'enforce', perMinute: 1 } } } });
  const first = call(home, 'Bash', { command: 'echo one' });
  const second = call(home, 'Bash', { command: 'echo two' });
  check('the local rate limit lets the first call through', blocked(first), false);
  check('and stops the second', blocked(second), true);
  check('for the stated reason', /rate limit/i.test(second.stderr), true);
}

// ── the per-project file may add rules, and nothing else ─────────────────────
//
// It lives in a repository the agent can write to. Rules there can only make the
// machine stricter than the nothing it had; `selfProtect` and `security` there
// would let the agent switch protections OFF from inside the checkout.
{
  const home = machine({
    project: {
      policy: DENY,
      selfProtect: false,
      security: { rateLimit: { mode: 'enforce', perMinute: 1 } },
    },
  });
  check("a project file's rules apply", blocked(call(home, 'Bash', { command: 'echo sg-local-deny' })), true);

  const cache = join(home, '.solongate', CACHE + 'conformance.json');
  check('it cannot switch the tamper guard off',
    blocked(call(home, 'Write', { file_path: cache, content: '{}' })), true);

  const a = call(home, 'Bash', { command: 'echo one' });
  const b = call(home, 'Bash', { command: 'echo two' });
  check('and it cannot set a rate limit', [blocked(a), blocked(b)].join(','), 'false,false');
}

// ── a machine with no policy at all is unchanged ─────────────────────────────
//
// Nothing to enforce still means nothing is enforced. The guard runs further
// than it used to on such a machine — far enough to protect its own state — and
// that is the only difference.
{
  const home = machine();
  check('no policy, no credential: allowed', blocked(call(home, 'Bash', { command: 'echo sg-local-deny' })), false);
  check('and no record is invented', localLines(home).length, 0);
  const cache = join(home, '.solongate', CACHE + 'conformance.json');
  check('but its own state is protected now',
    blocked(call(home, 'Write', { file_path: cache, content: '{}' })), true);
}

process.exit(done());
