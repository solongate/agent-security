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
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { suite, check, note, done } from './harness.mjs';

const HOOK = new URL('../hooks/conversation.mjs', import.meta.url);

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

process.exit(done());
