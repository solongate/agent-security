/**
 * The MCP proxy and the guard reach the SAME verdict on the same policy.
 *
 * They did not, and the way they failed to is worth stating. The proxy's engine
 * had OPA WASM as its sole backend, and a SERVICE compiled the bundle — so with no
 * service it loaded none and answered every call with
 *
 *   "OPA WASM evaluator not loaded — failing closed (default DENY)"
 *
 * which on a machine that has no service is not fail-safe, it is not working. The
 * guard never had that problem: OPA is an optional upgrade there and a local
 * evaluator is the primary path, "so air-gapped installs without OPA see ZERO
 * behavior change".
 *
 * The fix was not to give the proxy an evaluator of its own. A policy has to mean
 * the same thing wherever it is read, and a second implementation is a second set
 * of answers waiting to diverge — this repository has had that bug twice, once in
 * the tamper globs and once in the DLP list. So the guard's evaluator moved to
 * hooks/policy-eval.mjs and BOTH import it.
 *
 * Which makes this test the thing that keeps it honest: every case runs through
 * the ENGINE and through the GUARD ITSELF, and the two have to agree. The suite
 * drives it against the Node hook and against the Go binary, so the Go guard is
 * pinned to the same answers.
 */
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { suite, check, note, done, HOOK } from './harness.mjs';

const { PolicyEngine } = await import('../dist/policy-engine/engine.js');

const POLICY_FILE = 'poli' + 'cy.json';

const rule = (over) => ({
  id: 'r', description: 'd', effect: 'DENY', priority: 10,
  toolPattern: '*', minimumTrustLevel: 'UNTRUSTED', enabled: true, ...over,
});

const CASES = [
  {
    name: 'a denied command',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [rule({ commandConstraints: { denied: ['*rm -rf /*'] } })] },
    tool: 'Bash', args: { command: 'rm -rf /etc' }, deny: true,
  },
  {
    name: 'a command the rule does not name',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [rule({ commandConstraints: { denied: ['*rm -rf /*'] } })] },
    tool: 'Bash', args: { command: 'ls -la' }, deny: false,
  },
  {
    name: 'a denied path',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [rule({ pathConstraints: { denied: ['**/.ssh/**'] } })] },
    tool: 'Read', args: { file_path: '/home/me/.ssh/id_rsa' }, deny: true,
  },
  {
    name: 'a denied filename',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [rule({ filenameConstraints: { denied: ['*.env'] } })] },
    tool: 'Read', args: { file_path: '/srv/app/secret.env' }, deny: true,
  },
  {
    name: 'a denied URL',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [rule({ urlConstraints: { denied: ['*evil.example*'] } })] },
    tool: 'WebFetch', args: { url: 'https://evil.example/x' }, deny: true,
  },
  {
    name: 'a disabled rule decides nothing',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [rule({ enabled: false, commandConstraints: { denied: ['*rm -rf /*'] } })] },
    tool: 'Bash', args: { command: 'rm -rf /etc' }, deny: false,
  },
  {
    name: 'a rule scoped to another permission',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [rule({ permission: ['READ'], commandConstraints: { denied: ['*rm -rf /*'] } })] },
    tool: 'Bash', args: { command: 'rm -rf /etc' }, deny: false,
  },
  // WHITELIST IS THE INTERESTING HALF, because the two engines used opposite
  // defaults: the guard allows what no rule forbids in denylist mode, and the
  // proxy's old fallback denied everything in every mode.
  {
    name: 'whitelist: nothing matches',
    policy: { id: 'p', name: 'P', mode: 'whitelist', rules: [rule({ effect: 'ALLOW', commandConstraints: { allowed: ['git *'] } })] },
    tool: 'Bash', args: { command: 'curl http://x' }, deny: true,
  },
  {
    name: 'whitelist: an ALLOW rule matches',
    policy: { id: 'p', name: 'P', mode: 'whitelist', rules: [rule({ effect: 'ALLOW', commandConstraints: { allowed: ['*git status*'] } })] },
    tool: 'Bash', args: { command: 'git status' }, deny: false,
  },
  {
    name: 'whitelist: no ALLOW rule applies to this tool at all',
    policy: { id: 'p', name: 'P', mode: 'whitelist', rules: [rule({ effect: 'ALLOW', permission: ['READ'], commandConstraints: { allowed: ['*'] } })] },
    tool: 'Bash', args: { command: 'git status' }, deny: true,
  },
  {
    name: 'DENY outranks ALLOW at the same priority',
    policy: {
      id: 'p', name: 'P', mode: 'whitelist',
      rules: [
        rule({ id: 'a', effect: 'ALLOW', commandConstraints: { allowed: ['*'] } }),
        rule({ id: 'd', effect: 'DENY', commandConstraints: { denied: ['*secret*'] } }),
      ],
    },
    tool: 'Bash', args: { command: 'cat secret' }, deny: true,
  },
  // THE CASE THAT FOUND A REAL DIVERGENCE. The Go guard compiled its Rego chain
  // sorted by priority alone, so an ALLOW written above a DENY won at equal
  // priority — and at ANY priority, because the hook's DENY pass ignores the
  // number entirely. Measured: the hook blocked `cat secret`, the binary allowed
  // it, in both modes.
  {
    name: 'DENY wins over an ALLOW with a better priority',
    policy: {
      id: 'p', name: 'P', mode: 'denylist',
      rules: [
        rule({ id: 'a', effect: 'ALLOW', priority: 1, commandConstraints: { allowed: ['*'] } }),
        rule({ id: 'd', effect: 'DENY', priority: 50, commandConstraints: { denied: ['*secret*'] } }),
      ],
    },
    tool: 'Bash', args: { command: 'cat secret' }, deny: true,
  },
  {
    name: 'an empty rule list in denylist mode forbids nothing',
    policy: { id: 'p', name: 'P', mode: 'denylist', rules: [] },
    tool: 'Bash', args: { command: 'anything at all' }, deny: false,
  },
];

/** What the proxy's engine decides. */
function engineDenies(policy, tool, args) {
  const engine = new PolicyEngine({ policySet: policy });
  const d = engine.evaluate({
    context: { trustLevel: 'UNTRUSTED' },
    toolName: tool,
    serverName: 'test',
    arguments: args,
    requiredPermission: 'EXECUTE',
    timestamp: new Date().toISOString(),
  });
  return { denied: d.effect === 'DENY', reason: d.reason };
}

/** What the GUARD decides, run as the program it is. */
function guardDenies(policy, tool, args) {
  const home = mkdtempSync(join(tmpdir(), 'sg-agree-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  writeFileSync(join(home, '.solongate', POLICY_FILE), JSON.stringify(policy));
  const launch = HOOK.endsWith('.mjs')
    ? [process.execPath, [HOOK, 'claude-code', 'claude-code']]
    : [HOOK, ['claude-code', 'claude-code']];
  const r = spawnSync(launch[0], launch[1], {
    input: JSON.stringify({ tool_name: tool, tool_input: args, session_id: 's', tool_use_id: 't', cwd: home }),
    env: { ...process.env, HOME: home, USERPROFILE: home },
    encoding: 'utf-8',
    timeout: 30_000,
  });
  return { denied: r.status === 2, reason: String(r.stderr || '').trim() };
}

suite('the proxy and the guard agree');

// The engine reports which backend decided. With no bundle loaded it has to be
// the local one — if this said 'opa' the rest would be measuring something else.
check('the engine decides locally without a bundle',
  new PolicyEngine({ policySet: CASES[0].policy }).getEvaluatorMode(), 'local');

for (const c of CASES) {
  const engine = engineDenies(c.policy, c.tool, c.args);
  const guard = guardDenies(c.policy, c.tool, c.args);
  check(`${c.name}: the engine says ${c.deny ? 'DENY' : 'ALLOW'}`, engine.denied, c.deny);
  check(`${c.name}: and the guard agrees`, guard.denied, engine.denied);
  if (guard.denied !== engine.denied) {
    note(`engine: ${engine.reason}\n    guard : ${guard.reason.slice(0, 120)}`);
  }
}

// ── THE PROXY'S OWN LOADER, on both spellings of the file ────────────────────
//
// Everything above feeds a policy OBJECT to the engine and to the guard, which skips the
// step where the MCP proxy READS the file — and that step was where it failed.
//
//   {"mode": "denylist", "rules": [ … ]}                   a bare policy
//   {"policy": {…}, "security": {…}, "selfProtect": true}  the envelope
//
// The envelope is what the README documents for configuring any security layer and what
// the CLI writes the moment one is set (local-cli.mjs: "written as an envelope"). Only
// the bare shape was read, and the two implementations failed differently:
//
//   this one   `JSON.parse(content) as PolicySet` is a cast, which does nothing at
//              runtime, so the next line — `policy.rules.some(...)` — threw
//              `Cannot read properties of undefined`. The proxy did not start.
//   the Go one read zero rules and enforced NOTHING, silently, which is worse.
//
// So on a machine that had configured DLP or a rate limit, `solongate -- <upstream>`
// either refused to start or ran as an open pipe. This is the fourth reader of that file
// and the last to learn the rule the other three follow: the PRESENCE of a `policy` key
// tells the shapes apart, and its VALUE may be null.
{
  const { loadPolicy } = await import('../dist/config.js');
  const denied = [rule({ commandConstraints: { denied: ['*rm -rf /*'] } })];
  const inner = { id: 'p', name: 'P', mode: 'denylist', rules: denied };

  const dir = mkdtempSync(join(tmpdir(), 'sg-envelope-'));
  const write = (name, body) => {
    const p = join(dir, name);
    writeFileSync(p, typeof body === 'string' ? body : JSON.stringify(body, null, 2));
    return p;
  };

  const ruleCount = (file) => {
    try {
      const p = loadPolicy(file);
      return Array.isArray(p.rules) ? p.rules.length : `rules is ${typeof p.rules}`;
    } catch (e) {
      return `THREW ${e.constructor.name}`;
    }
  };

  // ensureCatchAllAllow appends a trailing `ALLOW *` when the file has none, which is
  // what makes denylist mode allow whatever no rule forbids. So a one-rule file loads
  // TWO rules, and that is the contract rather than an accident — the count is written
  // out here so a change to it has to be deliberate.
  const bare = ruleCount(write('bare.json', inner));
  check('a bare policy file loads its rule plus the catch-all', bare, 2);
  check('an envelope loads THE SAME rules',
    ruleCount(write('envelope.json', {
      policy: inner,
      security: { dlpBlock: { patterns: ['AWS access key'], custom: [] } },
      selfProtect: true,
    })), bare);

  // A file carrying LAYERS AND NO RULES is a real configuration — DLP on, nothing
  // forbidden — and reads as no rules rather than as a failure.
  check('a null policy loads nothing but the catch-all, rather than throwing',
    ruleCount(write('null.json', { policy: null, security: { dlpBlock: { patterns: [] } } })), 1);

  // Half a file is not a policy. Throwing here would take the agent down with the
  // proxy; enforcing nothing silently is the other wrong answer, so the DEFAULT applies
  // — which allows, and is the documented default for a machine with no policy.
  check('half a file falls back to a default rather than throwing',
    typeof ruleCount(write('broken.json', '{ "policy": { "rules": [')) === 'number', true);

  // A `rules` that is not an array must read as no rules, not as a crash downstream.
  check('a rules field of the wrong type reads as none of its own',
    ruleCount(write('wrongtype.json', { policy: { rules: 'nope' } })), 1);
}

process.exit(done());
