// SPDX-License-Identifier: Apache-2.0

/**
 * SolonGate plugin for OpenCode.
 *
 * OpenCode is the odd one out among the guarded clients: it has no subprocess
 * hook contract. Plugins are JavaScript modules Bun loads INTO the running
 * process, and a tool call is refused by throwing from `tool.execute.before`.
 *
 * So this file is a shim, not an engine. It spawns the same guard every other
 * client runs and turns its answer into the shape OpenCode wants — which keeps
 * one implementation of policy, DLP, rate limiting and auditing
 * instead of a second one that drifts.
 *
 * Measured against opencode 1.18.10, because none of this is documented:
 *   tool.execute.before(input, output)
 *     input  = { tool, sessionID, callID }
 *     output = { args }                      ← mutable, so a rewrite lands here
 *     throwing blocks the call, and the Error message is handed to the model as
 *     the tool result (it reads it and reports it, so the reason is visible)
 *   tool.execute.after(input, output)
 *     input  = { tool, sessionID, callID, args }
 *     output = { title, metadata, output, attachments }
 *
 * Verified on the same version: subagent calls spawned through the `task` tool
 * DO reach this hook (in their own sessionID), and so do MCP tool calls (named
 * `<server>_<tool>`). Both were once bypasses; both are closed.
 *
 * Not covered, and it cannot be: `opencode --pure` runs with external plugins
 * disabled, which switches the guard off. That is the client's design and there
 * is no hook that survives it.
 */
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';

const HOOKS_DIR = join(homedir(), '.solongate', 'hooks');
const GUARD = join(HOOKS_DIR, 'guard.mjs');
const AUDIT = join(HOOKS_DIR, 'audit.mjs');
const CONVERSATION = join(HOOKS_DIR, 'conversation.mjs');

// The node binary, written in by the installer.
//
// NOT process.execPath: OpenCode runs plugins inside its own Bun-based binary,
// so in here process.execPath is `.../opencode-ai/bin/opencode.exe`. Spawning
// THAT with the guard as an argument does not run the guard — it re-runs
// opencode with nonsense arguments, which exits non-2, which this shim reads as
// "allowed". The result was a guard that never guarded and never said so.
// Measured: execPath=/…/opencode-ai/bin/opencode.exe, versions.bun=1.3.14.
const NODE_BAKED = '__SOLONGATE_NODE__';
const NODE = NODE_BAKED.startsWith('__SOLONGATE') || !existsSync(NODE_BAKED) ? 'node' : NODE_BAKED;

// On POSIX the spawn goes through the shared launcher instead, which resolves
// node at RUN time and leaves the beat every other client leaves.
//
// The baked path above is `process.execPath` from the install, and on a Mac
// that is a Homebrew Cellar path or an nvm version directory — both deleted by
// a routine upgrade. The `'node'` fallback then needs PATH to have one, which
// is exactly the assumption that does not hold inside a hook environment. The
// launcher tries the baked path first, then PATH, then everywhere a Mac keeps a
// node.
const LAUNCHER = join(HOOKS_DIR, 'sg-run.sh');
const USE_LAUNCHER = process.platform !== 'win32' && existsSync(LAUNCHER);

/** The argv for one hook run: through the launcher when there is one. */
function spawnArgs(script) {
  return USE_LAUNCHER
    ? ['/bin/sh', [LAUNCHER, script, 'opencode', 'OpenCode']]
    : [NODE, [script, 'opencode', 'OpenCode']];
}

// The guard carries its own 8s backstop; this is the outer bound for the whole
// round trip so a wedged process can never hang the editor.
const GUARD_TIMEOUT_MS = 15000;

/**
 * Run a hook with a JSON payload on stdin. Resolves to {code, stdout, stderr},
 * or null when the hook could not be run at all.
 */
function runHook(script, payload, timeoutMs) {
  return new Promise((resolve) => {
    if (!existsSync(script)) return resolve(null);
    let done = false;
    const finish = (v) => { if (!done) { done = true; resolve(v); } };
    let child;
    try {
      const [bin, argv] = spawnArgs(script);
      child = spawn(bin, argv, {
        stdio: ['pipe', 'pipe', 'pipe'],
        windowsHide: true,
      });
    } catch {
      return finish(null);
    }
    let stdout = '', stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('error', () => finish(null));
    child.on('close', (code) => finish({ code, stdout, stderr }));
    const timer = setTimeout(() => { try { child.kill('SIGKILL'); } catch {} finish(null); }, timeoutMs);
    if (typeof timer.unref === 'function') timer.unref();
    try { child.stdin.end(JSON.stringify(payload)); } catch { finish(null); }
  });
}

/** The deny reason, preferring the structured field over the stderr line. */
function denyReason(res) {
  try {
    const j = JSON.parse(res.stdout);
    const r = j?.hookSpecificOutput?.permissionDecisionReason;
    if (typeof r === 'string' && r.trim()) return r.trim();
  } catch { /* not JSON — fall back to stderr */ }
  const line = String(res.stderr || '').split('\n').map((s) => s.trim()).filter(Boolean).pop();
  return line || 'Blocked by SolonGate.';
}

/** A rewrite instruction, when the guard asked for one (DLP read redaction). */
function rewritePatch(res) {
  try {
    const j = JSON.parse(res.stdout);
    const h = j?.hookSpecificOutput;
    if (h?.permissionDecision === 'allow' && h.updatedInput && typeof h.updatedInput === 'object') {
      return h.updatedInput;
    }
  } catch { /* no patch */ }
  return null;
}

// The assistant text held between the part events and the message completing.
//
// Keyed by message id, cleared on flush, and dropped whole past a bound: a
// plugin that grows a buffer for the life of an editor session is a leak in
// somebody's editor, which is a worse bug than a missing transcript.
const pending = new Map();
const MAX_PENDING = 64;

// textOf joins the text parts of a message and ignores the rest — a file
// attachment or a tool call is not something a person said. A synthetic part
// is one OpenCode wrote itself, which is not either.
function textOf(parts) {
  if (!Array.isArray(parts)) return '';
  return parts
    .filter((x) => x && x.type === 'text' && typeof x.text === 'string' && !x.synthetic)
    .map((x) => x.text)
    .join('\n')
    .trim();
}

export const SolonGate = async ({ directory, worktree } = {}) => {
  const cwd = directory || worktree || process.cwd();

  return {
    'tool.execute.before': async (input, output) => {
      const res = await runHook(GUARD, {
        tool_name: input?.tool ?? '',
        tool_input: output?.args ?? {},
        session_id: input?.sessionID ?? '',
        tool_use_id: input?.callID ?? '',
        cwd,
      }, GUARD_TIMEOUT_MS);

      // The guard could not run (not installed, spawn refused, wedged). Fail
      // OPEN, the same way every enforcement layer inside it does: a guard that
      // cannot answer must not become an editor that cannot work.
      if (!res) return;

      if (res.code === 2) {
        throw new Error(denyReason(res));
      }

      // Allow-with-rewrite: `output.args` is what actually runs, so replacing it
      // here is how a hidden path gets filtered out of a listing before the
      // model ever sees the result.
      const patch = rewritePatch(res);
      if (patch && output && typeof output === 'object') {
        try { Object.assign(output.args, patch); } catch { /* leave the call as it was */ }
      }
    },

    // ── the conversation record ──────────────────────────────────────────
    //
    // OpenCode is the third client to record this and the only one that needs
    // two different hooks to do it, because its halves arrive by different
    // routes: `chat.message` carries what the person wrote, and the answer is
    // streamed as text PARTS which are only final when the assistant message
    // is.
    //
    // So the parts are held per message id and flushed when that message
    // completes.
    'chat.message': async (input, output) => {
      const text = textOf(output?.parts);
      if (!text) return;
      void runHook(CONVERSATION, {
        opencode: true,
        role: 'prompt',
        body: text,
        session_id: input?.sessionID ?? output?.message?.sessionID ?? '',
      }, GUARD_TIMEOUT_MS);
    },

    event: async ({ event } = {}) => {
      if (!event || typeof event !== 'object') return;

      // A text part of a message. `text` is the WHOLE text so far rather than a
      // delta, so the last one wins and nothing is concatenated.
      // numberOr keeps a missing or nonsense count out of a spend figure. A
      // field this SDK version does not declare — info.tokens.total is one —
      // arrives undefined rather than zero, and Number(undefined) is NaN.
      const numberOr = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.round(v) : 0);

      if (event.type === 'message.part.updated') {
        const part = event.properties?.part;
        if (part?.type === 'text' && part.messageID && typeof part.text === 'string') {
          if (pending.size > MAX_PENDING) pending.clear();
          pending.set(part.messageID, { text: part.text, sessionID: part.sessionID ?? '' });
        }
        return;
      }

      // The message finished. Anything else — a user message, one still being
      // written — is not a completed answer and is left alone.
      if (event.type === 'message.updated') {
        const info = event.properties?.info;
        if (!info || info.role !== 'assistant' || !info.time?.completed) return;

        // WHAT THE MESSAGE COST, which OpenCode is alone among the four clients
        // in handing over directly: the other three have to be read back off a
        // transcript or a database, and this arrives in process, already
        // counted by the provider. It was in `info` all along and thrown away.
        //
        // Sent whether or not there was text to record. A message that produced
        // only tool calls still cost something, and gating the figure on the
        // words would lose exactly the turns that ran longest.
        const t = info.tokens;
        if (t) {
          const input = numberOr(t.input);
          const output = numberOr(t.output);
          const reasoning = numberOr(t.reasoning);
          const cacheRead = numberOr(t.cache?.read);
          const cacheWrite = numberOr(t.cache?.write);
          // OpenCode's own total when it sends one — it counts reasoning
          // ALONGSIDE output rather than inside it, which is its convention and
          // not ours to reconcile.
          const total = numberOr(t.total) || input + output + reasoning + cacheRead + cacheWrite;
          if (total > 0) {
            void runHook(CONVERSATION, {
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

        const held = pending.get(info.id);
        pending.delete(info.id);
        if (!held || !held.text.trim()) return;
        void runHook(CONVERSATION, {
          opencode: true,
          role: 'reply',
          body: held.text,
          session_id: info.sessionID || held.sessionID || '',
        }, GUARD_TIMEOUT_MS);
      }
    },

    'tool.execute.after': async (input, output) => {
      // The ALLOW-path audit record. Fire and forget: it must never delay the
      // editor, and losing one line is better than a stalled tool.
      void runHook(AUDIT, {
        tool_name: input?.tool ?? '',
        tool_input: input?.args ?? {},
        tool_response: output?.output ?? output?.metadata ?? {},
        session_id: input?.sessionID ?? '',
        tool_use_id: input?.callID ?? '',
        cwd,
      }, GUARD_TIMEOUT_MS);
    },
  };
};
