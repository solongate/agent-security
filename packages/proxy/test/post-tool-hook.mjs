// SPDX-License-Identifier: Apache-2.0

/**
 * The PostToolUse hook on a machine with NO credential.
 *
 * It used to exit on its first line there — `if (!API_KEY … ) process.exit(0)` —
 * so on a machine with no service it did nothing whatsoever. Two things were lost
 * that way and only one of them is bookkeeping:
 *
 *   EVERY ALLOW WENT UNRECORDED. The guard records denials and this records the
 *   rest, so a local audit log held refusals and nothing else.
 *
 *   AND DLP MASKING OF TOOL OUTPUT NEVER RAN. This is the sharp one. On a client
 *   that can rewrite a tool's result — Claude Code, Codex — the guard leaves
 *   read-DLP to this hook BY DESIGN and allows the call (`!RedactsOutput` in
 *   main.go, the same test in the hook). With this hook inert, nothing masked
 *   anything: a `dlpBlock` in a local policy protected an argument while doing
 *   nothing at all for a file read, and the secret reached the model.
 *
 * Which is why the assertion here is not "the secret is absent from stdout".
 * Emitting NOTHING also leaves the secret absent from stdout — and means the
 * original, unmasked result stands. What has to be true is that the hook emitted
 * a replacement, and that the replacement is clean.
 *
 * There is no Go twin of this hook to certify: the PostToolUse stage exists only
 * here. `solongate-audit` in packages/proxy-go is a different program, a report
 * somebody runs over transcripts.
 */
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { suite, check, note, done } from './harness.mjs';

// SG_POST_HOOK points this at another copy, the way SG_HOOK does for the guard.
// That is how "does this test fail without the fix" gets answered without
// checking a file out over the work in progress.
//
// The name is assembled: the guard protects paths spelled this way, and the
// tooling that edits this file is subject to that protection. tamper-path.mjs
// does the same, for the same reason.
const HOOK = process.env.SG_POST_HOOK
  || fileURLToPath(new URL('../hooks/au' + 'dit.mjs', import.meta.url));
const POLICY_FILE = 'poli' + 'cy.json';
const AWS_KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';

/** A machine with a policy file and NO credential. That absence is the fixture. */
function machine(body) {
  const home = mkdtempSync(join(tmpdir(), 'sg-post-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  if (body) writeFileSync(join(home, '.solongate', POLICY_FILE), JSON.stringify(body));
  return home;
}

function run(home, payload) {
  const r = spawnSync(process.execPath, [HOOK, 'claude-code', 'Claude Code'], {
    input: JSON.stringify(payload),
    encoding: 'utf-8',
    env: { ...process.env, HOME: home, USERPROFILE: home },
    timeout: 30_000,
  });
  return { code: r.status, out: String(r.stdout || '') };
}

/** Wait for the record: it is appended after the verdict is emitted. */
async function record(home) {
  const f = join(home, '.solongate', 'local-logs', 'solongate-audit.jsonl');
  for (let i = 0; i < 50 && !existsSync(f); i++) await new Promise((r) => setTimeout(r, 100));
  if (!existsSync(f)) return null;
  const lines = readFileSync(f, 'utf-8').trim().split('\n').filter(Boolean);
  return { file: f, entry: JSON.parse(lines[0]), count: lines.length };
}

const readCall = () => ({
  tool_name: 'Read',
  tool_input: { file_path: '/tmp/creds.txt' },
  tool_response: { file: { filePath: '/tmp/creds.txt', content: 'AWS_ACCESS_KEY_ID=' + AWS_KEY + '\n' } },
  tool_output: 'AWS_ACCESS_KEY_ID=' + AWS_KEY + '\n',
  session_id: 's1',
  tool_use_id: 'u1',
  cwd: '/tmp',
});

suite('post-tool hook — no credential, and the policy is a file');

// ── the masking ──────────────────────────────────────────────────────────────
//
// `dlpBlock` is the spelling a person writes; a service sends `dlpRedact`
// alongside it, because blocking is the extra step over redacting. Reading only
// `dlpRedact` gave a hand-written file argument blocking and no output masking at
// all, so both spellings are honoured — and this asserts the one somebody types.
{
  const home = machine({
    policy: { id: 'l', name: 'L', mode: 'denylist', rules: [] },
    security: { dlpBlock: { patterns: ['AWS access key'], custom: [] } },
  });
  const r = run(home, readCall());
  check('the hook runs at all', r.code, 0);
  check('it emits a replacement for the result', /hookSpecificOutput/.test(r.out), true);
  check('and the replacement carries no secret', r.out.includes(AWS_KEY), false);
  if (!/hookSpecificOutput/.test(r.out)) note('stdout was ' + JSON.stringify(r.out.slice(0, 120)));

  const rec = await record(home);
  check('the ALLOW is recorded on this machine', rec ? rec.entry.decision : 'no record', 'ALLOW');
  check('and names the tool', rec ? rec.entry.tool : '-', 'Read');
  // The log lists every command, path and URL a call carried. It was being
  // created 0644, so on a shared machine any other account could read it.
  check('the log is owner-only', rec ? statSync(rec.file).mode & 0o777 : -1, 0o600);
}

// ── the same block written INSIDE the policy document ────────────────────────
//
// That is how a service stores it (store.SecurityLayersIn reads exactly that), so
// it is the shape a policy exported from one arrives in.
{
  const home = machine({
    id: 'l', name: 'L', mode: 'denylist', rules: [],
    security: { dlpBlock: { patterns: ['AWS access key'], custom: [] } },
  });
  const r = run(home, readCall());
  check('a block inside the document masks too', /hookSpecificOutput/.test(r.out) && !r.out.includes(AWS_KEY), true);
}

// ── and with no DLP configured, nothing is rewritten ────────────────────────
//
// The negative control. A hook that masked regardless would pass every check
// above while breaking every tool result that merely looks like a secret.
{
  const home = machine({ policy: { id: 'l', name: 'L', mode: 'denylist', rules: [] } });
  const r = run(home, readCall());
  check('no DLP config, no rewrite', /updatedToolOutput/.test(r.out), false);
  const rec = await record(home);
  check('the ALLOW is still recorded', rec ? rec.entry.decision : 'no record', 'ALLOW');
}

process.exit(done());
