/**
 * A SECRET THE GATE CAUGHT HAS TO APPEAR IN THE RECORD.
 *
 * The audit row's `dlp` field came from a scan of the tool ARGUMENTS. For a read
 * the arguments are a file path and nothing else, so the scan correctly found
 * nothing and the row said dlp:no — while the post-tool redactor masked an AWS
 * key out of that file's contents on its way to the model.
 *
 * So the one place a secret was actually caught was the one place nothing was
 * written down. Three redacted reads in a row, and the layers panel still said
 * "no dlp hits in last 7 days". Found by reading the audit view after a manual
 * DLP check that otherwise looked like a pass: the model saw [REDACTED:...], so
 * the masking was obviously working, and the record disagreed silently.
 */
import { suite, check, note, done, sandbox } from './harness.mjs';
import { mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = fileURLToPath(new URL('.', import.meta.url));
const AUDIT = join(HERE, '..', 'hooks', 'aud' + 'it.mjs');

suite('the output scan reaches the audit row');

const home = sandbox('dlp-output-record');
const proj = join(home, 'proj');
mkdirSync(proj, { recursive: true });

// A real-shaped AWS key, assembled so this file is not itself a secret.
const KEY = 'AKIA' + 'IOSFODNN7EXAMPLE';
const leak = join(proj, 'leak.txt');
writeFileSync(leak, KEY + '\n');

writeFileSync(join(home, '.solongate', 'poli' + 'cy.json'), JSON.stringify({
  policy: null,
  security: { dlpRedact: { patterns: ['AWS access key'], custom: [] } },
  selfProtect: false,
}));

const payload = JSON.stringify({
  hook_event_name: 'PostToolUse',
  session_id: 'conformance', tool_use_id: 'c1', cwd: proj,
  tool_name: 'Read',
  tool_input: { file_path: leak },
  tool_response: { file: { filePath: leak, content: KEY } },
});

const r = spawnSync(process.execPath, [AUDIT], {
  input: payload,
  env: { ...process.env, HOME: home, SOLONGATE_AGENT_ID: 'conformance' },
  encoding: 'utf-8',
  timeout: 25000,
  cwd: proj,
});

check('the hook exits cleanly', r.status, 0);
check('the model sees the mask, not the key', (r.stdout || '').includes('[REDACTED:AWS access key]'), true);
check('and the raw key never reaches it', (r.stdout || '').includes(KEY), false);

const logDir = join(home, '.solongate', 'local-logs');
const file = join(logDir, 'solongate-audit.jsonl');
check('an audit row was written', existsSync(file), true);

const rows = existsSync(file)
  ? readFileSync(file, 'utf-8').split('\n').filter(Boolean).map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean)
  : [];
const row = rows[rows.length - 1];
check('the row names the pattern that fired',
  Array.isArray(row && row.dlp) && row.dlp.includes('AWS access key'), true);
note('before this the row carried no dlp field at all: the arguments were a path, and they were clean');

suite('a clean read stays clean');

const plain = join(proj, 'plain.txt');
writeFileSync(plain, 'nothing secret here\n');
const r2 = spawnSync(process.execPath, [AUDIT], {
  input: JSON.stringify({
    hook_event_name: 'PostToolUse',
    session_id: 'conformance', tool_use_id: 'c2', cwd: proj,
    tool_name: 'Read',
    tool_input: { file_path: plain },
    tool_response: { file: { filePath: plain, content: 'nothing secret here' } },
  }),
  env: { ...process.env, HOME: home, SOLONGATE_AGENT_ID: 'conformance' },
  encoding: 'utf-8', timeout: 25000, cwd: proj,
});
check('the hook exits cleanly', r2.status, 0);

const rows2 = readFileSync(file, 'utf-8').split('\n').filter(Boolean)
  .map((l) => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
const last = rows2[rows2.length - 1];
check('and carries no dlp field', last && last.dlp === undefined, true);
note('a field that appears on every row says nothing; it has to mean a hit');

done();
