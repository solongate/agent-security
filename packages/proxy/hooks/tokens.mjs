#!/usr/bin/env node
/**
 * SolonGate Token Hook (Stop)
 *
 * What a turn COST: the tokens a client reports for one exchange with the model.
 * Nothing else in this package records it.
 *
 * This is the surviving half of what used to be the conversation hook, which
 * recorded both what was said and what it cost. The transcript half is gone —
 * this product does not store what a person wrote to their agent — and the cost
 * half stayed, because spend is a fact about the work rather than a copy of it.
 *
 * WHERE THE FIGURE COMES FROM. Not from this hook counting anything: each client
 * already reports its own usage, and the reader per client below pulls it out of
 * whatever that client writes. Claude Code and Codex keep it in the transcript
 * file the hook is handed a path to, Antigravity in a local database, OpenCode
 * hands it over in process. That file is read ONLY for its usage numbers; no
 * prose is read out of it and none is sent.
 *
 * WHAT IS SENT, AND WHEN NOTHING IS. No credential -> nothing, the same rule
 * every hook here follows. The server keys on the turn id and ignores a repeat,
 * so a re-send costs bytes and nothing else.
 *
 * Fire-and-forget, and every failure is silent. This hook must never delay a
 * turn and must never be the reason one fails: it records something ABOUT the
 * work, and the work matters more.
 */
import { readFileSync, existsSync, openSync, readSync, closeSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Bump on every change to this file, alongside the other hooks.
//
// 5 drops the transcript half. The number carries on from the file this was
// carved out of rather than restarting at 1, so a machine holding the old hook
// sees a newer version and replaces it.
const HOOK_VERSION = 5;

const AGENT_ID = (process.env.SOLONGATE_AGENT_ID || process.argv[2] || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');

function loadGlobalCloudConfig() {
  try {
    const p = resolve(homedir(), '.solongate', 'cloud-guard.json');
    if (!existsSync(p)) return {};
    const cfg = JSON.parse(readFileSync(p, 'utf-8'));
    return (cfg && typeof cfg === 'object') ? cfg : {};
  } catch { return {}; }
}

function readStdin() {
  try { return readFileSync(0, 'utf-8'); } catch { return ''; }
}

// How much of a transcript to read. A turn is a few kilobytes; two megabytes is
// a long turn with large tool results in it, and reading a 50MB transcript on
// every Stop is the cost this bound exists to refuse.
const TAIL_BYTES = 2 * 1024 * 1024;

// One request per Stop carries at most this many turns.
//
// Forty rather than everything in the tail. The server keys on the turn id and
// ignores a repeat, so re-sending is free of consequence but not of bytes —
// forty covers a missed Stop or two while keeping the request small, and the
// ones before that were sent when they happened.
const MAX_TURNS = 40;

/** Read the last bytes of a file, dropping the first partial line. */
function tailLines(path, bytes = TAIL_BYTES) {
  let fd;
  try {
    const size = statSync(path).size;
    const from = Math.max(0, size - bytes);
    const len = size - from;
    if (len <= 0) return [];
    const buf = Buffer.allocUnsafe(len);
    fd = openSync(path, 'r');
    readSync(fd, buf, 0, len, from);
    const text = buf.toString('utf-8');
    const lines = text.split('\n');
    // A read that started mid-file starts mid-line. That first fragment is not
    // JSON and would be the one line that throws on every single turn.
    if (from > 0) lines.shift();
    return lines;
  } catch {
    return [];
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* already gone */ } }
  }
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.round(v) : 0);
const stamp = (v) => {
  const t = Date.parse(v || '');
  return Number.isFinite(t) ? t : Date.now();
};

// ── Claude Code ────────────────────────────────────────────────────────────

/**
 * One row per API REQUEST, deduped.
 *
 * The dedupe is the whole correctness of this reader. Usage is reported per API
 * request but the transcript writes one record per content block, so the same
 * usage object appears up to four times with the same requestId. Summing
 * records rather than requests overcounts by roughly half.
 */
function readClaudeCode(transcriptPath) {
  const seen = new Set();
  const out = [];
  for (const line of tailLines(transcriptPath)) {
    if (!line || line[0] !== '{') continue;
    let r;
    try { r = JSON.parse(line); } catch { continue; }
    if (r.type !== 'assistant') continue;
    const u = r.message && r.message.usage;
    if (!u) continue;

    // requestId is the API request's identity. A few synthetic records carry
    // none — API-error placeholders with all-zero usage — so the message id is
    // the fallback rather than letting them collide on null.
    const key = r.requestId || (r.message && r.message.id) || '';
    if (!key || seen.has(key)) continue;
    seen.add(key);

    const input = num(u.input_tokens);
    const cacheWrite = num(u.cache_creation_input_tokens);
    const cacheRead = num(u.cache_read_input_tokens);
    const output = num(u.output_tokens);
    const total = input + cacheWrite + cacheRead + output;
    if (total <= 0) continue;

    out.push({
      turn_key: key,
      input, output, cache_read: cacheRead, cache_write: cacheWrite,
      reasoning: num(u.output_tokens_details && u.output_tokens_details.thinking_tokens),
      // The three prompt buckets are DISJOINT — proven on real data, where
      // cache_read[n+1] == cache_read[n] + cache_creation[n] holds to the
      // token — so the sum is the whole prompt plus the completion.
      total,
      at: stamp(r.timestamp),
    });
  }
  return out;
}

// ── Codex ──────────────────────────────────────────────────────────────────

/**
 * One row per model request, from the token_count events.
 *
 * `last_token_usage` rather than `total_token_usage`: the second is cumulative
 * for the session, and sending cumulative values to a store that adds rows
 * would count the whole session again on every turn.
 */
function readCodex(transcriptPath, sessionId) {
  const out = [];
  for (const line of tailLines(transcriptPath)) {
    if (!line || line[0] !== '{') continue;
    let r;
    try { r = JSON.parse(line); } catch { continue; }
    if (r.type !== 'event_msg') continue;
    const p = r.payload;
    if (!p || p.type !== 'token_count') continue;

    const last = p.info && p.info.last_token_usage;
    if (!last) continue;

    const total = num(last.total_tokens) || (num(last.input_tokens) + num(last.output_tokens));
    if (total <= 0) continue;

    // The record's OWN ordinal, never a count of what this read happened to
    // see. Counting within the tail renumbers every event the moment the file
    // grows past the window — the same turn gets a new key, and a new key is a
    // second row. Older rollouts carry no ordinal, so those fall back to the
    // timestamp paired with the running total, which together do not repeat.
    const id = typeof r.ordinal === 'number'
      ? 'o:' + r.ordinal
      : 't:' + (r.timestamp || '') + ':' + num((p.info.total_token_usage || {}).total_tokens);

    out.push({
      // Prefixed with the session, because an ordinal is only unique WITHIN a
      // rollout. The server's key does not include the session — resuming a
      // conversation would otherwise double every turn it copies forward — so
      // a positional id has to carry its own scope.
      turn_key: (sessionId || 'codex') + ':' + id,
      // input_tokens INCLUDES cached here, and output INCLUDES reasoning —
      // the opposite of Claude Code's disjoint buckets. The total is the
      // provider's own, so the difference never has to be reconciled.
      input: num(last.input_tokens),
      output: num(last.output_tokens),
      cache_read: num(last.cached_input_tokens),
      cache_write: num(last.cache_write_input_tokens),
      reasoning: num(last.reasoning_output_tokens),
      total,
      at: stamp(r.timestamp),
    });
  }
  return out;
}

// ── Antigravity ────────────────────────────────────────────────────────────

/** Read a protobuf varint. Returns [value, nextIndex]. */
function varint(buf, i) {
  let result = 0n;
  let shift = 0n;
  while (i < buf.length) {
    const b = buf[i++];
    result |= BigInt(b & 0x7f) << shift;
    if (!(b & 0x80)) return [result, i];
    shift += 7n;
    if (shift > 70n) break;
  }
  return [result, i];
}

/**
 * Pull the varints at one dotted protobuf path out of a blob.
 *
 * A tiny hand-rolled walker rather than a schema, because there is no schema on
 * disk: Antigravity stores an opaque message and the field numbers below were
 * established by decoding real generations and testing an identity that held
 * every time.
 */
function pbFields(buf, want) {
  const found = {};
  const walk = (b, path, depth) => {
    let i = 0;
    while (i < b.length) {
      let key;
      [key, i] = varint(b, i);
      const field = Number(key >> 3n);
      const wire = Number(key & 7n);
      const here = path ? path + '.' + field : String(field);
      if (wire === 0) {
        let v;
        [v, i] = varint(b, i);
        if (want.has(here) && found[here] === undefined) found[here] = Number(v);
      } else if (wire === 2) {
        let len;
        [len, i] = varint(b, i);
        const end = i + Number(len);
        if (end > b.length) return;
        if (depth < 6) walk(b.subarray(i, end), here, depth + 1);
        i = end;
      } else if (wire === 5) { i += 4; }
      else if (wire === 1) { i += 8; }
      else { return; }
    }
  };
  try { walk(buf, '', 0); } catch { /* a blob we cannot read is a blob we skip */ }
  return found;
}

// The field numbers, and what each one is. See the file header for how they
// were established — this is the one client whose mapping is not published, so
// it is the one where the evidence matters most.
const AGY = {
  IN_UNCACHED: '1.4.2',
  IN_CACHED: '1.4.5',
  OUT: '1.4.3',
  THINKING: '1.4.9',
  // The generation's own clock: a google.protobuf.Timestamp, whose field 1 is
  // seconds. Without it every generation in the tail would be stamped with the
  // moment it was READ, which puts a week of work on today's bar.
  AT_SECONDS: '1.9.4.1',
};
const AGY_WANT = new Set(Object.values(AGY));

function readAntigravity(conversationId) {
  if (!conversationId) return [];
  const db = resolve(homedir(), '.gemini', 'antigravity-cli', 'conversations', conversationId + '.db');
  if (!existsSync(db)) return [];

  let DatabaseSync;
  try {
    // Node 22+. On an older runtime there is no way to read this without a
    // native dependency, and adding one to a security tool to report a number
    // is the wrong trade — the client simply reports nothing.
    ({ DatabaseSync } = require('node:sqlite'));
  } catch {
    return [];
  }

  let handle;
  try {
    // Read-only: this is the client's own live database and nothing here has
    // any business writing to it.
    handle = new DatabaseSync(db, { readOnly: true });
    const rows = handle.prepare('SELECT idx, data FROM gen_metadata ORDER BY idx').all();
    const out = [];
    for (const row of rows) {
      const blob = row.data;
      if (!blob || !blob.length) continue;
      const f = pbFields(Buffer.from(blob), AGY_WANT);

      const input = (f[AGY.IN_UNCACHED] || 0) + (f[AGY.IN_CACHED] || 0);
      const output = f[AGY.OUT] || 0;
      if (input + output <= 0) continue;

      out.push({
        // The generation index, prefixed with the conversation it counts
        // within: an index is only unique inside one database, and the
        // server's key does not include the session.
        turn_key: conversationId + ':gen:' + row.idx,
        input,
        output,
        // The cached half of the prompt, which Antigravity reports separately
        // and is a SUBSET of the input above.
        cache_read: f[AGY.IN_CACHED] || 0,
        cache_write: 0,
        reasoning: f[AGY.THINKING] || 0,
        total: input + output,
        at: (f[AGY.AT_SECONDS] || 0) * 1000,
      });
    }
    return out;
  } catch {
    return [];
  } finally {
    if (handle) { try { handle.close(); } catch { /* already closed */ } }
  }
}


// ── sending ────────────────────────────────────────────────────────────────

/**
 * collectTokens works out which client this payload is from and reads its
 * numbers. Returns [] when the client cannot report, which is a normal answer
 * and never a zero.
 */
function collectTokens(data, source) {
  const transcript = data.transcript_path || data.transcriptPath ||
    (data.common && (data.common.transcriptPath || data.common.transcript_path)) || '';

  if (source === 'antigravity') {
    const id = (data.common && (data.common.conversationId || data.common.conversation_id)) || '';
    return readAntigravity(id);
  }
  if (!transcript || !existsSync(transcript)) return [];
  const sessionId = data.session_id || data.sessionId || '';
  if (source === 'codex') return readCodex(transcript, sessionId);
  // Claude Code needs no prefix: requestId is provider-issued and unique
  // across every transcript, which is exactly what makes a resumed session
  // report the same turn once rather than twice.
  return readClaudeCode(transcript);
}

/**
 * sendTokens posts a batch. One request per Stop whatever the count.
 *
 * Silent on every failure, including a missing credential: a machine that is
 * not logged in has nowhere to report and nothing to say about it.
 */
async function sendTokens({ apiUrl, apiKey, sessionId, agentId, agentName, source, turns }) {
  if (!apiKey || !turns || !turns.length) return;
  const body = turns.slice(-MAX_TURNS).map((t) => ({
    ...t,
    session_id: sessionId || '',
    agent_id: agentId || '',
    agent_name: agentName || '',
    source: source || '',
  }));
  try {
    await fetch(`${apiUrl.replace(/\/$/, '')}/api/v1/token-usage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${apiKey}` },
      body: JSON.stringify({ turns: body }),
    });
  } catch { /* silent: a figure that could not be sent must not fail a turn */ }
}

// reportTokens sends what the turn cost, beside the record of what was said.
//
// It rides on THIS hook rather than on one of its own because the events are
// the same events: a turn ends once, and registering a second hook for the same
// moment is a second thing to install, a second thing to keep current, and a
// second thing that can be missing on a machine where the first is fine.
//
// Everything it needs is already on the payload. It is awaited so a short-lived
// hook process does not exit before the request goes out, and it can only
// fail silently — see tokens.mjs.
async function reportTokens(data, source, sessionId, agentName) {
  try {
    const turns = collectTokens(data, source);
    if (!turns.length) return;
    const cfg = loadGlobalCloudConfig();
    await sendTokens({
      apiUrl: cfg.apiUrl || 'https://api.solongate.com',
      apiKey: cfg.apiKey || '',
      sessionId,
      agentId: AGENT_ID,
      agentName: agentName || '',
      source,
      turns,
    });
  } catch { /* silent: spend is a note about the work, not the work */ }
}

// tokenSourceOf names the client from the payload's SHAPE rather than from the
// argv the hook was installed with, for the reason the Antigravity branch below
// gives: a payload is a fact and an argument is a claim.
function tokenSourceOf(data) {
  if (data.common || (data.hookArgs && data.hookArgs.common)) return 'antigravity';
  const path = String(data.transcript_path || data.transcriptPath || '');
  if (path.includes('/.codex/') || path.includes('\\.codex\\')) return 'codex';
  return 'claude-code';
}

(async () => {
  // Whatever happens below, this hook allows the turn. It has no opinion about
  // whether the work should proceed; it is a record of what it cost.
  process.exitCode = 0;

  let data = {};
  try { data = JSON.parse(readStdin() || '{}'); } catch { return; }

  const event = data.hook_event_name || data.hookEventName || '';

  // OPENCODE calls this hook directly from its plugin, and its spend arrives
  // already counted, in process, rather than being read back off a transcript
  // the way the other three are.
  if (data.opencode === true) {
    if (data.tokens !== true) return;
    const cfg = loadGlobalCloudConfig();
    await sendTokens({
      apiUrl: cfg.apiUrl || 'https://api.solongate.com',
      apiKey: cfg.apiKey || '',
      sessionId: data.session_id || '',
      agentId: AGENT_ID,
      agentName: 'OpenCode',
      source: 'opencode',
      turns: [{
        turn_key: data.turn_key || '',
        input: data.input || 0,
        output: data.output || 0,
        cache_read: data.cache_read || 0,
        cache_write: data.cache_write || 0,
        reasoning: data.reasoning || 0,
        total: data.total || 0,
        at: data.at || 0,
      }],
    });
    return;
  }

  // ANTIGRAVITY sends a different shape: `{common: {...}, args: {...}}`, with
  // the generations already on disk. It is detected by shape rather than by a
  // flag, because the client name is an argv argument this hook is also given
  // for the other three, and a payload is a fact while an argument is a claim.
  const agCommon = data.common || (data.hookArgs && data.hookArgs.common) || null;
  const agStop = data.stopHookArgs || (data.args && data.args.stopHookArgs) ||
    (data.hookArgs && data.hookArgs.stopHookArgs) || null;
  if (agCommon) {
    // Only at the END of an exchange: this hook fires on several events and the
    // generations are already on disk, so reading them on every one would be
    // the same rows read many times for nothing.
    if (agStop) {
      await reportTokens(data, 'antigravity',
        agCommon.conversationId || agCommon.conversation_id || '',
        agCommon.agentName || agCommon.agent_name || 'Antigravity');
    }
    return;
  }

  // Stop is the one event that matters: a turn ends once, and that is when its
  // cost is final. A turn that ended with a tool call and no prose still cost
  // something, so nothing here is gated on there having been words.
  if (event !== 'Stop' && event !== 'SubagentStop') return;
  const sessionId = data.session_id || data.sessionId || data.conversation_id || '';
  if (!sessionId) return;
  await reportTokens(data, tokenSourceOf(data), sessionId, data.agent_name || '');
})();
