// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const GUARD_TIMEOUT_MS = 8000;

const GUARD_BAKED = '__SOLONGATE_GUARD_BIN__';
const GUARD_BIN = GUARD_BAKED.startsWith('__SOLONGATE') || !existsSync(GUARD_BAKED)
  ? join(homedir(), '.solongate', 'bin', 'solongate-guard')
  : GUARD_BAKED;

// Talks to the guard binary directly: spawn it with the same argv shape the
// shell launcher would have used (an optional subcommand, then client and
// label), write the JSON payload to stdin, and parse whatever it printed to
// stdout. Any failure here (binary missing, crash, timeout) resolves to null
// so callers fail open, same as every other agent's hook wiring.
function runGuard(args, payload, timeoutMs) {
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(GUARD_BIN, args, { stdio: ['pipe', 'pipe', 'pipe'] });
    } catch {
      resolve(null);
      return;
    }

    let out = '';
    let settled = false;
    const finish = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      let body = null;
      try { body = out ? JSON.parse(out) : null; } catch {  }
      resolve({ code, body });
    };

    const timer = setTimeout(() => {
      if (settled) return;
      try { child.kill('SIGKILL'); } catch {  }
      finish(0);
    }, timeoutMs);

    child.stdout?.on('data', (d) => { out += d; });
    child.on('error', () => finish(0));
    child.on('close', (code) => finish(code ?? 0));

    try {
      child.stdin.end(JSON.stringify(payload));
    } catch {
      finish(0);
    }
  });
}

function denyReason(res) {
  return res?.body?.hookSpecificOutput?.permissionDecisionReason || '[SolonGate] Blocked by policy';
}

function rewritePatch(res) {
  const out = res?.body?.hookSpecificOutput;
  if (out?.permissionDecision === 'allow' && out.updatedInput && typeof out.updatedInput === 'object') {
    return out.updatedInput;
  }
  return null;
}

function redactedOutput(res) {
  const out = res?.body?.hookSpecificOutput;
  if (!out || out.updatedToolOutput === undefined) return null;
  return out.updatedToolOutput;
}

export const SolonGate = async ({ directory, worktree } = {}) => {
  const cwd = directory || worktree || process.cwd();

  return {
    'tool.execute.before': async (input, output) => {
      const res = await runGuard(['opencode', 'OpenCode'], {
        tool_name: input?.tool ?? '',
        tool_input: output?.args ?? {},
        session_id: input?.sessionID ?? '',
        tool_use_id: input?.callID ?? '',
        cwd,
      }, GUARD_TIMEOUT_MS);

      if (!res) return;

      if (res.code === 2) {
        throw new Error(denyReason(res));
      }

      const patch = rewritePatch(res);
      if (patch && output && typeof output === 'object') {
        try { Object.assign(output.args, patch); } catch {  }
      }
    },

    event: async ({ event } = {}) => {
      if (!event || typeof event !== 'object') return;

      const numberOr = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.round(v) : 0);

      if (event.type === 'message.part.updated') return;

      if (event.type === 'message.updated') {
        const info = event.properties?.info;
        if (!info || info.role !== 'assistant' || !info.time?.completed) return;

        const t = info.tokens;
        if (t) {
          const input = numberOr(t.input);
          const output = numberOr(t.output);
          const reasoning = numberOr(t.reasoning);
          const cacheRead = numberOr(t.cache?.read);
          const cacheWrite = numberOr(t.cache?.write);
          const total = numberOr(t.total) || input + output + reasoning + cacheRead + cacheWrite;
          if (total > 0) {
            void runGuard(['tokens', 'opencode', 'OpenCode'], {
              opencode: true,
              tokens: true,
              session_id: info.sessionID || '',
              turn_key: info.id || '',
              agent_name: 'OpenCode',
              input, output, reasoning,
              cache_read: cacheRead,
              cache_write: cacheWrite,
              total,
              at: info.time?.completed ? Number(info.time.completed) : 0,
            }, GUARD_TIMEOUT_MS);
          }
        }

      }
    },

    'tool.execute.after': async (input, output) => {
      const res = await runGuard(['audit', 'opencode', 'OpenCode'], {
        tool_name: input?.tool ?? '',
        tool_input: input?.args ?? {},
        tool_response: output?.output ?? output?.metadata ?? {},
        session_id: input?.sessionID ?? '',
        tool_use_id: input?.callID ?? '',
        cwd,
      }, GUARD_TIMEOUT_MS);
      if (!res) return;
      const masked = redactedOutput(res);
      if (masked === null) return;
      try {
        if (typeof masked === 'string') {
          if (typeof output?.output === 'string') output.output = masked;
        } else if (masked && typeof masked === 'object' && output) {
          if (typeof masked.stdout === 'string' && typeof output.output === 'string') output.output = masked.stdout;
          else if (typeof masked.content === 'string' && typeof output.output === 'string') output.output = masked.content;
          else if (output.metadata && typeof output.metadata === 'object') Object.assign(output.metadata, masked);
        }
      } catch {  }
    },
  };
}