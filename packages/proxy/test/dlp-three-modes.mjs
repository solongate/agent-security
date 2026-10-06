/**
 * THREE MODES, THREE OUTCOMES.
 *
 * There used to be two behaviours wearing three names. "detect" wrote
 * `dlpRedact`, so it masked every secret it found, which is redacting, and
 * "block" wrote both keys, so the only thing separating them was whether an
 * ARGUMENT hit also refused the call. A read whose secret lived in the FILE was
 * identical under both: allowed, masked, and recorded as clean.
 *
 * So somebody who asked to be TOLD about secrets had them hidden from him, and
 * somebody who asked for secrets to be REFUSED got them quietly masked instead.
 * Both would find out the same way: by reading a file through the gate and
 * seeing [REDACTED:...] where the mode they picked promised either the value or
 * a refusal.
 *
 * Each mode now does the thing its name is:
 *
 *   detect   scan, record, change nothing
 *   redact   mask the secret, let the call through
 *   block    refuse the call
 */
import { suite, check, note, done, sandbox } from './harness.mjs';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const AUDIT = join(HERE, '..', 'hooks', 'aud' + 'it.mjs');

// A real-shaped AWS key, assembled so this file is not itself a secret.
const KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';
const RULES = { patterns: ['AWS access key'], custom: [] };

function setup(name, security) {
  const home = sandbox(name);
  const proj = join(home, 'proj');
  mkdirSync(proj, { recursive: true });
  const leak = join(proj, 'leak.txt');
  writeFileSync(leak, KEY + '\n');
  writeFileSync(join(home, '.solongate', 'poli' + 'cy.json'), JSON.stringify({
    policy: null, security, selfProtect: false,
  }));
  return { home, proj, leak };
}

function runPostTool(s) {
  return spawnSync(process.execPath, [AUDIT], {
    input: JSON.stringify({
      hook_event_name: 'PostToolUse',
      session_id: 'conformance', tool_use_id: 'c1', cwd: s.proj,
      tool_name: 'Read',
      tool_input: { file_path: s.leak },
      tool_response: { file: { filePath: s.leak, content: KEY } },
    }),
    env: { ...process.env, HOME: s.home, SOLONGATE_AGENT_ID: 'conformance' },
    encoding: 'utf-8', timeout: 25000, cwd: s.proj,
  });
}

function lastRow(home) {
  const file = join(home, '.solongate', 'local-logs', 'solongate-audit.jsonl');
  if (!existsSync(file)) return null;
  const rows = readFileSync(file, 'utf-8').split('\n').filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  return rows[rows.length - 1] || null;
}

suite('detect — record the hit, change nothing');

let s = setup('dlp-mode-detect', { dlpObserve: RULES });
let r = runPostTool(s);
check('the hook exits cleanly', r.status, 0);
check('the output is NOT rewritten', (r.stdout || '').includes('[REDACTED:'), false);
check('the row names the pattern that fired',
  Array.isArray(lastRow(s.home)?.dlp) && lastRow(s.home).dlp.includes('AWS access key'), true);
note('a detect that hides the value is redaction under another name: the mode exists to tell you, not to change the call');

suite('redact — mask the secret, let the call through');

s = setup('dlp-mode-redact', { dlpRedact: RULES });
r = runPostTool(s);
check('the hook exits cleanly', r.status, 0);
check('the model sees the mask', (r.stdout || '').includes('[REDACTED:AWS access key]'), true);
check('and never the key', (r.stdout || '').includes(KEY), false);
check('the row still names the pattern',
  Array.isArray(lastRow(s.home)?.dlp) && lastRow(s.home).dlp.includes('AWS access key'), true);

suite('block — refuse the call');

s = setup('dlp-mode-block', { dlpBlock: RULES, dlpRedact: RULES });

function guardCall(input, agent) {
  return spawnSync(process.execPath, [join(HERE, '..', 'hooks', 'guard.bundled.mjs')], {
    input: JSON.stringify({
      hook_event_name: 'PreToolUse', session_id: 'conformance', tool_use_id: 'c1',
      cwd: s.proj, tool_name: 'bash', tool_input: input,
    }),
    env: { ...process.env, HOME: s.home, SOLONGATE_AGENT_ID: agent || 'conformance' },
    encoding: 'utf-8', timeout: 25000, cwd: s.proj,
  });
}

let g = guardCall({ command: 'echo ' + KEY });
check('a secret in the arguments is refused', g.status, 2);
check('and the refusal names the layer', (g.stderr || '').includes('DLP'), true);

// THE HALF THAT DEGRADED TO REDACT.
//
// The pre-tool file scan was gated on the client NOT being able to rewrite its
// own tool output — true for the clients most people use. Masking can be
// deferred to a post-tool stage; refusing cannot, because by the time that stage
// runs the file has been read. So on Claude Code `cat secrets.txt` came back
// masked and ALLOWED under a mode called block.
g = guardCall({ command: 'cat ' + s.leak });
check('reading a file that holds a secret is refused too', g.status, 2);
check('and says it was the file, not the arguments',
  (g.stderr || '').includes('file that contains a secret'), true);

// And the direction that keeps it usable: a file with nothing in it still reads.
const plain = join(s.proj, 'plain.txt');
writeFileSync(plain, 'nothing secret here\n');
check('an ordinary file is untouched', guardCall({ command: 'cat ' + plain }).status, 0);

suite('off — nothing is scanned');

s = setup('dlp-mode-off', {});
r = runPostTool(s);
check('the hook exits cleanly', r.status, 0);
check('the output is untouched', (r.stdout || '').includes('[REDACTED:'), false);
check('and no pattern is recorded', lastRow(s.home)?.dlp, undefined);

done();
