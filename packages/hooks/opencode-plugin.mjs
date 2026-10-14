// SPDX-License-Identifier: Apache-2.0

/**
 * SolonGate plugin for OpenCode.
 *
 * OpenCode is the odd one out among the guarded clients: it has no subprocess
 * hook contract. Plugins are JavaScript modules Bun loads INTO the running
 * process, and a tool call is refused by throwing from `tool.execute.before`.
 *
 * So this file is a shim, not an engine. It spawns the same guard every other
 * client runs and turns its answer into the shape OpenCode wants, which keeps
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
// THE SPEND HOOK, AND IT WAS POINTED AT A FILE THAT DOES NOT EXIST.
//
// This was `conversation.mjs`, which recorded a turn's words as well as its
// cost. The transcript half was dropped and the file was renamed for what is
// left, which this plugin never followed: nothing produces `conversation.mjs`,
// no build emits it, the installer does not stage it, so all three calls below
// were spawning a path that is not there. runHook does not report that, so the
// failure was silent and OpenCode was the one client reporting no spend at all.
//
// The payload the token call sends is exactly the shape the hook's `opencode`
// branch reads: `{opencode: true, tokens: true, session_id, turn_key, ...}`.
// Only the filename was wrong.
const TOKENS = join(HOOKS_DIR, 'tokens.mjs');

// The node binary, written in by the installer.
//
// NOT process.execPath: OpenCode runs plugins inside its own Bun-based binary,
// so in here process.execPath is `.../opencode-ai/bin/opencode.exe`. Spawning
// THAT with the guard as an argument does not run the guard, it re-runs
// opencode with nonsense arguments, which exits non-2, which this shim reads as
// "allowed". The result was a guard that never guarded and never said so.
// Measured: execPath=/…/opencode-ai/bin/opencode.exe, versions.bun=1.3.14.
const NODE_BAKED = '__SOLONGATE_NODE__';
const NODE = NODE_BAKED.startsWith('__SOLONGATE') || !existsSync(NODE_BAKED) ? 'node' : NODE_BAKED;

// On POSIX the spawn goes through the shared launcher instead, which resolves
// node at RUN time and leaves the beat every other client leaves.
//
// The baked path above is `process.execPath` from the install, and on a Mac
// that is a Homebrew Cellar path or an nvm version directory, both deleted by
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
// THE REPLY BUFFER AND THE TEXT JOINER WERE HERE, and both are gone with the
// transcript recorder they fed.
//
// `pending` held each message's text by id so a completed message could be
// flushed to a hook that recorded what was said. `textOf` joined a message's
// text parts and skipped attachments, tool calls and the synthetic parts
// OpenCode writes itself.
//
// Nothing records a transcript now, so the buffer was accumulating every reply
// in the editor's own process for nothing to read. A bound kept it from growing
// without end, which made it a small leak rather than a large one; neither is
// worth having for a feature that does not exist.
//
// Spend is still reported, from `event` below, and that path never needed the
// text.

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
    // THE PROMPT AND REPLY CALLS ARE GONE, not repointed.
    //
    // They sent `{role: 'prompt', body: text}` and `{role: 'reply', body}` to
    // the transcript recorder, and that feature was removed from this product:
    // the hook they went to reads `tokens: true` and returns on anything else,
    // so repointing them at it would send a turn's full text to a hook that
    // drops it. Sending the words of every prompt and reply somewhere, for
    // nothing to read, is the opposite of what this tool is for.
    //
    // `chat.message` has nothing else to do, so the handler goes with them.
    // Spend is reported from `event` below, where OpenCode sends it.

    event: async ({ event } = {}) => {
      if (!event || typeof event !== 'object') return;

      // numberOr keeps a missing or nonsense count out of a spend figure. A
      // field this SDK version does not declare, info.tokens.total is one,
      // arrives undefined rather than zero, and Number(undefined) is NaN.
      const numberOr = (v) => (typeof v === 'number' && Number.isFinite(v) && v > 0 ? Math.round(v) : 0);

      // `message.part.updated` was handled here, to hold each text part for the
      // transcript recorder. With nothing holding text there is nothing to do
      // with the event, and falling through to the completion check below would
      // read a part as a finished message. Returning early on it is the one
      // thing still needed.
      if (event.type === 'message.part.updated') return;

      // The message finished. Anything else, a user message, one still being
      // written, is not a completed answer and is left alone.
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
          // OpenCode's own total when it sends one, it counts reasoning
          // ALONGSIDE output rather than inside it, which is its convention and
          // not ours to reconcile.
          const total = numberOr(t.total) || input + output + reasoning + cacheRead + cacheWrite;
          if (total > 0) {
            void runHook(TOKENS, {
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

    // MASKING THE RESULT, WHICH MEANS MUTATING `output` IN PLACE.
    //
    // This is why `opencode` declares redactsOutput. OpenCode calls
    //
    //     let V = {...result};
    //     yield* trigger('tool.execute.after', {…}, V);
    //     return V;
    //
    // and Plugin.trigger is `for (const h of hooks) await h(input, output);
    // return output`, no clone, the hook is awaited, and the object handed to
    // it is the one returned to the model. So assigning to a field of `output`
    // here changes what the model reads. Verified against the installed binary
    // (opencode 1.18.16): both the per-tool path and the MCP/subtask paths pass
    // the same reference they return.
    //
    // TWO CONSEQUENCES, both deliberate:
    //
    // The audit call is AWAITED now, where it used to be fire-and-forget with a
    // comment saying it must never delay the editor. A mask that arrives after
    // the result has gone to the model is not a mask, so the wait is the
    // feature; GUARD_TIMEOUT_MS still bounds it and a timeout leaves the output
    // untouched.
    //
    // And it FAILS OPEN, unlike the pre-tool path. A pre-tool failure can
    // refuse the call, which is the safe direction. Here the tool has already
    // run and its result exists: there is nothing left to refuse, and throwing
    // would lose the output entirely rather than protect it. Block mode is what
    // covers the case where masking is not good enough, the guard refuses the
    // read before it happens (see dlpRedactReadPlan), which is the half of this
    // that cannot fail open.
    'tool.execute.after': async (input, output) => {
      const res = await runHook(AUDIT, {
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
      // The hook returns the shape it was given. It was given
      // `output.output`, a string for every text-producing tool, so a string
      // back is assigned straight to it. An object back means the hook
      // preserved a structured result's shape, and the field it belongs in is
      // the one it came from.
      try {
        if (typeof masked === 'string') {
          if (typeof output?.output === 'string') output.output = masked;
        } else if (masked && typeof masked === 'object' && output) {
          if (typeof masked.stdout === 'string' && typeof output.output === 'string') output.output = masked.stdout;
          else if (typeof masked.content === 'string' && typeof output.output === 'string') output.output = masked.content;
          else if (output.metadata && typeof output.metadata === 'object') Object.assign(output.metadata, masked);
        }
      } catch { /* a result we cannot write to is one we leave alone */ }
    },
  };
};