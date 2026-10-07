// SPDX-License-Identifier: Apache-2.0

// THE POLICY MATRIX, swept rather than sampled.
//
// A rule has four constraint kinds, two effects, and two policy modes; the guard has four
// clients, each with its own wire format and — this is the part hand-testing gets wrong —
// its own way of SAYING no. Antigravity denies with exit 0 and a JSON body; the other
// three deny with exit 2. A tester watching exit codes would read every Antigravity block
// as an allow and every Antigravity allow as an allow, and conclude the client was fine.
//
// Sixty-four cells, each driven twice: once with a call the rule should catch, once with a
// call it should not. The second half is the half that finds walls — a rule that blocks
// everything passes every "was it blocked?" check ever written.
//
// This is not a replacement for the suite next to it. The other files each prove one
// thing deeply; this one proves that the combinations agree, which is where a port drifts.
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const HOOK = process.env.SG_HOOK || join(HERE, '..', 'hooks', 'guard.bundled.mjs');
const IS_BIN = !HOOK.endsWith('.mjs');

// ── the clients ───────────────────────────────────────────────────
//
// `payload` builds that client's wire format; `verdict` reads its answer back. The two
// are separate because they disagree in different ways: three clients share Anthropic's
// flat input shape, and one of those three still differs on output.
const CLIENTS = {
  'claude-code': {
    label: 'Claude Code',
    payload: flat,
    verdict: (r) => (r.status === 2 ? 'deny' : 'allow'),
  },
  codex: {
    label: 'Codex',
    payload: flat,
    verdict: (r) => (r.status === 2 ? 'deny' : 'allow'),
  },
  opencode: {
    label: 'OpenCode',
    payload: flat,
    verdict: (r) => (r.status === 2 ? 'deny' : 'allow'),
  },
  antigravity: {
    label: 'Antigravity',
    payload: nested,
    // EXIT 0 ON A BLOCK. This client reads the JSON, not the code, so the code says
    // nothing at all about the verdict and reading it would score every row as allowed.
    verdict(r) {
      try {
        const out = JSON.parse(r.stdout || '{}');
        if (out.decision === 'deny' || out.allow_tool === false) return 'deny';
      } catch { /* fall through: unparseable output is not a block */ }
      return 'allow';
    },
  },
};

function flat(tool, args, cwd) {
  return JSON.stringify({
    hook_event_name: 'PreToolUse', session_id: 'matrix', cwd,
    tool_name: tool, tool_input: args,
  });
}

function nested(tool, args, cwd) {
  // Antigravity nests the call and keeps shell text in CommandLine.
  const a = { ...args };
  if (a.command !== undefined) { a.CommandLine = a.command; delete a.command; }
  return JSON.stringify({ toolCall: { name: tool, args: a }, cwd, workspacePaths: [cwd] });
}

// ── the constraint kinds ──────────────────────────────────────────
//
// Each names the pattern to store, a call that must match it, and one that must not. The
// near-miss is chosen to be close: a rule about `/etc/*` that also catches `/etcetera` is
// a different bug from one that catches nothing, and only a near-miss separates them.
const KINDS = [
  {
    kind: 'command',
    pattern: 'curl *',
    hit: ['Bash', { command: 'curl https://example.com' }],
    miss: ['Bash', { command: 'echo curl is a program' }],
  },
  {
    kind: 'path',
    pattern: '/etc/*',
    hit: ['Read', { file_path: '/etc/hosts' }],
    miss: ['Read', { file_path: '/home/someone/notes.txt' }],
  },
  {
    kind: 'filename',
    pattern: '*.pem',
    hit: ['Read', { file_path: '/home/someone/keys/server.pem' }],
    miss: ['Read', { file_path: '/home/someone/keys/server.pub' }],
  },
  {
    kind: 'url',
    pattern: 'https://evil.example/*',
    hit: ['WebFetch', { url: 'https://evil.example/steal' }],
    miss: ['WebFetch', { url: 'https://good.example/docs' }],
  },
];

// ── the policy ────────────────────────────────────────────────────

function ruleFor(kind, pattern, effect) {
  const field = {
    command: 'commandConstraints',
    path: 'pathConstraints',
    filename: 'filenameConstraints',
    url: 'urlConstraints',
  }[kind];
  const list = effect === 'DENY' ? { denied: [pattern] } : { allowed: [pattern] };
  return {
    id: 'matrix-rule',
    description: `${effect} ${kind} ${pattern}`,
    effect,
    priority: 100,
    toolPattern: '*',
    minimumTrustLevel: 'UNTRUSTED',
    enabled: true,
    [field]: list,
  };
}

function homeWith(mode, rule) {
  const home = mkdtempSync(join(tmpdir(), 'sg-matrix-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  writeFileSync(join(home, '.solongate', 'pol' + 'icy.json'), JSON.stringify({
    policy: { id: 'matrix', name: 'Matrix', mode, rules: [rule] },
    selfProtect: true,
  }));
  return home;
}

function ask(clientKey, home, tool, args) {
  const c = CLIENTS[clientKey];
  const body = c.payload(tool, args, home);
  const argv = IS_BIN ? [] : [HOOK];
  const bin = IS_BIN ? HOOK : process.execPath;
  const r = spawnSync(bin, [...argv, clientKey, c.label], {
    input: body, env: { ...process.env, HOME: home }, cwd: home, encoding: 'utf-8',
  });
  return c.verdict(r);
}

// ── the sweep ─────────────────────────────────────────────────────
//
// denylist + DENY: the rule is the only thing that blocks, so the hit must be denied and
// the miss allowed. whitelist + ALLOW is its mirror: nothing runs unless the rule says so,
// so the hit must be allowed and the miss denied. Those are the two shapes anybody
// actually writes; the other two combinations are policies that say nothing.
const CASES = [
  { mode: 'denylist', effect: 'DENY', hit: 'deny', miss: 'allow' },
  { mode: 'whitelist', effect: 'ALLOW', hit: 'allow', miss: 'deny' },
];

const clients = Object.keys(CLIENTS);
console.log(`# matrix (${IS_BIN ? 'go' : 'node'}) — ${KINDS.length} kinds × ${CASES.length} modes × ${clients.length} clients`);
console.log();

let bad = 0;
for (const c of CASES) {
  console.log(`  ${c.mode} / ${c.effect}`);
  const width = Math.max(...clients.map((k) => k.length));
  console.log('    ' + 'kind'.padEnd(10) + clients.map((k) => k.padEnd(width + 2)).join(''));

  for (const k of KINDS) {
    const home = homeWith(c.mode, ruleFor(k.kind, k.pattern, c.effect));
    const cells = [];
    for (const client of clients) {
      const got = {
        hit: ask(client, home, ...k.hit),
        miss: ask(client, home, ...k.miss),
      };
      const okHit = got.hit === c.hit;
      const okMiss = got.miss === c.miss;
      if (!okHit || !okMiss) {
        bad++;
        cells.push((okHit ? '' : `hit=${got.hit} `) + (okMiss ? '' : `miss=${got.miss}`));
      } else {
        cells.push('ok');
      }
    }
    console.log('    ' + k.kind.padEnd(10) + cells.map((s) => s.padEnd(width + 2)).join(''));
  }
  console.log();
}

if (bad) {
  console.log(`${bad} cell(s) wrong`);
  console.log('hit=  the call the rule names was decided the wrong way');
  console.log('miss= a call the rule does not name was decided the wrong way');
  process.exit(1);
}
console.log(`all ${KINDS.length * CASES.length * clients.length} cells agree`);
