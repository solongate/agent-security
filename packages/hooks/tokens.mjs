#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

import { readFileSync, existsSync, openSync, readSync, closeSync, statSync, mkdirSync, appendFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const HOOK_VERSION = 6;

const AGENT_ID = (process.env.SOLONGATE_AGENT_ID || process.argv[2] || 'default').replace(/[^a-zA-Z0-9_-]/g, '_');


function readStdin() {
  try { return readFileSync(0, 'utf-8'); } catch { return ''; }
}

const TAIL_BYTES = 2 * 1024 * 1024;

const MAX_TURNS = 40;

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
    if (from > 0) lines.shift();
    return lines;
  } catch {
    return [];
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch {  } }
  }
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.round(v) : 0);
const stamp = (v) => {
  const t = Date.parse(v || '');
  return Number.isFinite(t) ? t : Date.now();
};


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
      model: (r.message && typeof r.message.model === 'string') ? r.message.model : '',
      input, output, cache_read: cacheRead, cache_write: cacheWrite,
      reasoning: num(u.output_tokens_details && u.output_tokens_details.thinking_tokens),
      total,
      at: stamp(r.timestamp),
    });
  }
  return out;
}


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

    const id = typeof r.ordinal === 'number'
      ? 'o:' + r.ordinal
      : 't:' + (r.timestamp || '') + ':' + num((p.info.total_token_usage || {}).total_tokens);

    out.push({
      turn_key: (sessionId || 'codex') + ':' + id,
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
  try { walk(buf, '', 0); } catch {  }
  return found;
}

const AGY = {
  IN_UNCACHED: '1.4.2',
  IN_CACHED: '1.4.5',
  OUT: '1.4.3',
  THINKING: '1.4.9',
  AT_SECONDS: '1.9.4.1',
};
const AGY_WANT = new Set(Object.values(AGY));

function readAntigravity(conversationId) {
  if (!conversationId) return [];
  const db = resolve(homedir(), '.gemini', 'antigravity-cli', 'conversations', conversationId + '.db');
  if (!existsSync(db)) return [];

  let DatabaseSync;
  try {
    ({ DatabaseSync } = require('node:sqlite'));
  } catch {
    return [];
  }

  let handle;
  try {
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
        turn_key: conversationId + ':gen:' + row.idx,
        input,
        output,
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
    if (handle) { try { handle.close(); } catch {  } }
  }
}



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
  return readClaudeCode(transcript);
}

function writeTokenUsage({ sessionId, agentId, agentName, source, turns }) {
  try {
    if (!Array.isArray(turns) || !turns.length) return;
    const dir = resolve(homedir(), '.solongate', 'local-logs');
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const now = new Date();
    const day = now.toISOString().slice(0, 10);
    const lines = turns.map((t) => JSON.stringify({
      ts: now.toISOString(),
      turn_key: t.turn_key || '',
      session_id: sessionId || '',
      agent_id: agentId || '',
      agent_name: agentName || '',
      source: source || '',
      input: t.input || 0,
      output: t.output || 0,
      cache_read: t.cache_read || 0,
      cache_write: t.cache_write || 0,
      reasoning: t.reasoning || 0,
      total: t.total || 0,
      model: t.model || '',
      at: t.at || 0,
    })).join('\n') + '\n';
    appendFileSync(resolve(dir, 'token-usage-' + day + '.jsonl'), lines, { mode: 0o600 });
  } catch {  }
}

function reportTokens(data, source, sessionId, agentName) {
  try {
    writeTokenUsage({
      sessionId,
      agentId: AGENT_ID,
      agentName: agentName || '',
      source,
      turns: collectTokens(data, source),
    });
  } catch {  }
}

function tokenSourceOf(data) {
  if (data.common || (data.hookArgs && data.hookArgs.common)) return 'antigravity';
  const path = String(data.transcript_path || data.transcriptPath || '');
  if (path.includes('/.codex/') || path.includes('\\.codex\\')) return 'codex';
  return 'claude-code';
}

(async () => {
  process.exitCode = 0;

  let data = {};
  try { data = JSON.parse(readStdin() || '{}'); } catch { return; }

  const event = data.hook_event_name || data.hookEventName || '';

  if (data.opencode === true) {
    if (data.tokens !== true) return;
    writeTokenUsage({
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

  const agCommon = data.common || (data.hookArgs && data.hookArgs.common) || null;
  const agStop = data.stopHookArgs || (data.args && data.args.stopHookArgs) ||
    (data.hookArgs && data.hookArgs.stopHookArgs) || null;
  if (agCommon) {
    if (agStop) {
      reportTokens(data, 'antigravity',
        agCommon.conversationId || agCommon.conversation_id || '',
        agCommon.agentName || agCommon.agent_name || 'Antigravity');
    }
    return;
  }

  if (event !== 'Stop' && event !== 'SubagentStop') return;
  const sessionId = data.session_id || data.sessionId || data.conversation_id || '';
  if (!sessionId) return;
  reportTokens(data, tokenSourceOf(data), sessionId, data.agent_name || '');
})();