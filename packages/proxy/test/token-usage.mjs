/**
 * What a turn cost, read out of each client's own record.
 *
 * These run against SYNTHETIC files shaped like the real ones, because the real
 * ones live in a developer's home directory and a test that needs somebody's
 * Claude Code history to pass is a test that fails on every other machine. The
 * shapes here were copied from real data — the fan-out, the disjoint cache
 * buckets, the cumulative-versus-delta split in Codex — and every assertion is
 * here because getting it wrong produces a PLAUSIBLE number rather than an
 * error, which is the worst failure this feature has.
 */
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL, fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { suite, check, note, done } from './harness.mjs';

const HOOK = new URL('../hooks/tokens.mjs', import.meta.url);

/**
 * Load the hook's readers.
 *
 * The hook is a PROGRAM, not a module: it ends in an IIFE that reads stdin and
 * sends things. So the definitions above that IIFE are written to a temporary
 * module with an export line appended — the same text node would run, without
 * the part that would try to talk to a server.
 */
function loadReaders() {
  const src = readFileSync(HOOK, 'utf-8');
  const cut = src.indexOf('(async () => {');
  if (cut < 0) throw new Error('the hook no longer ends with its main body');
  const dir = mkdtempSync(join(tmpdir(), 'sg-tok-'));
  const file = join(dir, 'readers.mjs');
  writeFileSync(file, src.slice(0, cut) +
    '\nexport { collectTokens, readClaudeCode, readCodex, readAntigravity };\n');
  return import(pathToFileURL(file).href);
}

const tmp = () => mkdtempSync(join(tmpdir(), 'sg-tok-'));

const readers = await loadReaders();
const { collectTokens, readClaudeCode, readCodex } = readers;

suite('token usage — Claude Code');

// One API response is written as SEVERAL transcript records carrying the SAME
// usage object. In a real 51MB transcript, 4164 records held 2724 distinct
// requests — so summing records rather than requests overcounts by about half.
{
  const usage = {
    input_tokens: 2,
    cache_creation_input_tokens: 9401,
    cache_read_input_tokens: 21998,
    output_tokens: 590,
  };
  const rec = (requestId) => JSON.stringify({
    type: 'assistant', requestId, timestamp: '2026-08-14T10:00:00.000Z',
    message: { id: 'msg_' + requestId, usage },
  });
  const file = join(tmp(), 't.jsonl');
  writeFileSync(file, [rec('req_a'), rec('req_a'), rec('req_a'), rec('req_a')].join('\n'));

  const rows = readClaudeCode(file);
  check('four records carrying one request are one row', rows.length, 1);
  // The three prompt buckets are DISJOINT — proven on real data, where
  // cache_read[n+1] == cache_read[n] + cache_creation[n] holds to the token — so
  // the total is all four fields rather than input plus output.
  check('the total is the whole prompt plus the completion',
    rows[0] && rows[0].total, 2 + 9401 + 21998 + 590);
  note('summing records rather than requests would have given four times this');
}

{
  const rec = (id, out) => JSON.stringify({
    type: 'assistant', requestId: id, timestamp: '2026-08-14T10:00:00.000Z',
    message: { id: 'msg_' + id, usage: { input_tokens: 1, output_tokens: out } },
  });
  const file = join(tmp(), 't.jsonl');
  writeFileSync(file, [rec('a', 10), rec('b', 20)].join('\n'));
  check('two requests are two rows', readClaudeCode(file).length, 2);
}

// A malformed line, a user message, an assistant record with no usage: none of
// them is an error, and none may stop the rest of the file being read.
{
  const file = join(tmp(), 't.jsonl');
  writeFileSync(file, [
    'not json at all',
    JSON.stringify({ type: 'user', message: { content: 'hello' } }),
    JSON.stringify({ type: 'assistant', requestId: 'x', message: { id: 'm' } }),
    JSON.stringify({
      type: 'assistant', requestId: 'good', timestamp: '2026-08-14T10:00:00.000Z',
      message: { id: 'm2', usage: { input_tokens: 5, output_tokens: 7 } },
    }),
    '',
  ].join('\n'));

  const rows = readClaudeCode(file);
  check('junk is stepped over, the good record is kept', rows.length, 1);
  check('and its total is right', rows[0] && rows[0].total, 12);
}

suite('token usage — Codex');

// total_token_usage is CUMULATIVE for the session and last_token_usage is the
// delta. Sending the cumulative one to a store that ADDS rows would count the
// whole session again on every turn.
{
  const evt = (n, total, last) => JSON.stringify({
    type: 'event_msg', timestamp: `2026-08-14T10:0${n}:00.000Z`,
    payload: {
      type: 'token_count',
      info: {
        total_token_usage: { input_tokens: total, output_tokens: 0, total_tokens: total },
        last_token_usage: {
          input_tokens: last, output_tokens: 3, cached_input_tokens: 1,
          reasoning_output_tokens: 1, total_tokens: last + 3,
        },
      },
    },
  });
  const file = join(tmp(), 'rollout.jsonl');
  writeFileSync(file, [evt(1, 100, 100), evt(2, 250, 150)].join('\n'));

  const rows = readCodex(file);
  check('one row per token_count event', rows.length, 2);
  check('the first is the delta, not the running total', rows[0] && rows[0].total, 103);
  check('and so is the second', rows[1] && rows[1].total, 153);
  // Two turns sharing a key would have the second ignored as a retry.
  check('the two turns have different keys',
    rows[0] && rows[1] ? rows[0].turn_key !== rows[1].turn_key : false, true);
  note('the cumulative field beside it would have reported 350 for these two');
}

// The ordinal must be the RECORD's own, never a count of what this read saw.
// Counting within the tail renumbers every event the moment the file grows past
// the window — the same turn gets a new key, and a new key is a second row.
{
  const evt = (ordinal, total) => JSON.stringify({
    type: 'event_msg', ordinal, timestamp: '2026-08-14T10:00:00.000Z',
    payload: {
      type: 'token_count',
      info: {
        total_token_usage: { total_tokens: total },
        last_token_usage: { input_tokens: 10, output_tokens: 1, total_tokens: 11 },
      },
    },
  });
  const whole = join(tmp(), 'a.jsonl');
  writeFileSync(whole, [evt(7, 100), evt(8, 200), evt(9, 300)].join('\n'));
  // The same file with the earlier events gone, which is what a slid window
  // looks like to the reader.
  const slid = join(tmp(), 'b.jsonl');
  writeFileSync(slid, [evt(9, 300)].join('\n'));

  const before = readCodex(whole, 'sess-1');
  const after = readCodex(slid, 'sess-1');
  check('the last turn keeps its key when the window slides',
    before[before.length - 1].turn_key, after[0].turn_key);
  note('a key that counted within the tail would have renumbered it, doubling the row');
}

// A positional id is only unique inside one rollout, and the server's key does
// not include the session — so the reader has to carry that scope itself.
{
  const evt = JSON.stringify({
    type: 'event_msg', ordinal: 1, timestamp: '2026-08-14T10:00:00.000Z',
    payload: { type: 'token_count', info: { last_token_usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } },
  });
  const file = join(tmp(), 'r.jsonl');
  writeFileSync(file, evt);
  const a = readCodex(file, 'sess-a');
  const b = readCodex(file, 'sess-b');
  check('two sessions do not collide on the same ordinal',
    a[0].turn_key !== b[0].turn_key, true);
}

{
  const file = join(tmp(), 'rollout.jsonl');
  writeFileSync(file, [
    JSON.stringify({ type: 'event_msg', payload: { type: 'agent_message' } }),
    JSON.stringify({ type: 'response_item', payload: { type: 'token_count' } }),
    JSON.stringify({
      type: 'event_msg', timestamp: '2026-08-14T10:00:00.000Z',
      payload: { type: 'token_count', info: { last_token_usage: { input_tokens: 9, output_tokens: 1, total_tokens: 10 } } },
    }),
  ].join('\n'));
  check('only token_count events on event_msg lines count', readCodex(file).length, 1);
}

suite('token usage — reporting nothing');

// A client that cannot report must send NOTHING. A zero would be a measurement
// — "they spent nothing" — and every surface reads it as one.
{
  check('an empty payload reports nothing', collectTokens({}, 'claude-code').length, 0);
  check('a missing transcript reports nothing',
    collectTokens({ transcript_path: '/nonexistent/nope.jsonl' }, 'codex').length, 0);
  check('no conversation id reports nothing',
    collectTokens({ common: {} }, 'antigravity').length, 0);
  note('zero is a measurement; absent is not, and the surfaces tell them apart');
}

suite('token usage — the figure lands on this machine');

// COLLECTING A NUMBER AND DROPPING IT is the failure this block exists for.
//
// The hook POSTed each turn to a service. When the send was removed, the readers above
// kept running on every Stop and the result went nowhere: the expensive half of the
// hook ran and produced nothing. Every check here fails against that version, and the
// first one is the whole point — a file that does not exist.
//
// This runs the hook as a PROGRAM, with a payload on stdin, so what is tested is what
// a client actually invokes.
{
  const home = tmp();
  const transcript = join(tmp(), 'conv.jsonl');
  writeFileSync(transcript, [
    JSON.stringify({
      type: 'assistant', uuid: 'u1', sessionId: 's1',
      message: {
        id: 'msg_1', model: 'claude-opus-4',
        usage: { input_tokens: 120, output_tokens: 34, cache_read_input_tokens: 8, cache_creation_input_tokens: 2 },
      },
    }),
  ].join('\n') + '\n');

  const r = spawnSync(process.execPath, [fileURLToPath(HOOK), 'claude-code', 'Claude Code'], {
    input: JSON.stringify({ hook_event_name: 'Stop', session_id: 's1', transcript_path: transcript }),
    env: { ...process.env, HOME: home },
    encoding: 'utf-8',
    timeout: 20000,
  });
  check('the hook exits cleanly', r.status, 0);

  const dir = join(home, '.solongate', 'local-logs');
  const files = existsSync(dir) ? readdirSync(dir).filter((f) => f.startsWith('token-usage-')) : [];
  check('a usage file was written', files.length, 1);

  const lines = files.length
    ? readFileSync(join(dir, files[0]), 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
    : [];
  check('one line for one turn', lines.length, 1);
  if (lines.length) {
    check('the input count is the transcript\'s', lines[0].input, 120);
    check('and the output count', lines[0].output, 34);
    check('the model is named', lines[0].model, 'claude-opus-4');
    check('the session is named', lines[0].session_id, 's1');
    // The turn id is what lets a reader drop a repeat. A Stop that fires twice for one
    // exchange must not double somebody's count, and without this there is no way to
    // tell a duplicate from a second turn that happened to cost the same.
    check('and the turn carries an id', typeof lines[0].turn_key === 'string' && lines[0].turn_key.length > 0, true);
  }

  // OWNER-ONLY. What a session cost is not as sensitive as what it said, but it is
  // nobody else's business either, and the audit trail beside it holds the same mode.
  if (files.length) {
    const mode = statSync(join(dir, files[0])).mode & 0o777;
    check('the file is owner-only', mode.toString(8), '600');
  }

  // A SECOND TURN APPENDS rather than replacing. One file per day, one line per turn.
  const second = join(tmp(), 'conv2.jsonl');
  writeFileSync(second, JSON.stringify({
    type: 'assistant', uuid: 'u2', sessionId: 's1',
    message: { id: 'msg_2', model: 'claude-opus-4', usage: { input_tokens: 7, output_tokens: 3 } },
  }) + '\n');
  spawnSync(process.execPath, [fileURLToPath(HOOK), 'claude-code', 'Claude Code'], {
    input: JSON.stringify({ hook_event_name: 'Stop', session_id: 's1', transcript_path: second }),
    env: { ...process.env, HOME: home },
    encoding: 'utf-8',
    timeout: 20000,
  });
  const after = readFileSync(join(dir, files[0]), 'utf-8').trim().split('\n').filter(Boolean);
  check('a second turn appends', after.length, 2);
}

// A turn with nothing to report writes NOTHING — not a line of zeros. A zero is a
// measurement, and a file full of them would make an average meaningless.
{
  const home = tmp();
  spawnSync(process.execPath, [fileURLToPath(HOOK), 'claude-code', 'Claude Code'], {
    input: JSON.stringify({ hook_event_name: 'Stop', session_id: 's1', transcript_path: '/nonexistent/nope.jsonl' }),
    env: { ...process.env, HOME: home },
    encoding: 'utf-8',
    timeout: 20000,
  });
  const dir = join(home, '.solongate', 'local-logs');
  const files = existsSync(dir) ? readdirSync(dir).filter((f) => f.startsWith('token-usage-')) : [];
  check('nothing to report writes no file', files.length, 0);
}

process.exit(done());
