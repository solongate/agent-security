// SPDX-License-Identifier: Apache-2.0

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
import type { ToolCall, SessionInfo, AuditData, UserMessage } from './types.js';
import { loadConfig } from './config.js';

// ── Claude Code logs ──
// Location: ~/.claude/projects/<project-hash>/<session-id>.jsonl
// Format: JSONL with {"type":"message","message":{"role":"toolResult","toolName":"...","toolCallId":"..."}}
function collectClaude(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const claudeDir = resolve(homedir(), '.claude', 'projects');
  if (!existsSync(claudeDir)) return sessions;

  for (const projectDir of readdirSync(claudeDir)) {
    const projectPath = join(claudeDir, projectDir);
    if (!statSync(projectPath).isDirectory()) continue;

    for (const file of readdirSync(projectPath)) {
      if (!file.endsWith('.jsonl')) continue;
      const filePath = join(projectPath, file);
      const sessionId = file.replace('.jsonl', '');

      try {
        const lines = readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
        const toolCalls: ToolCall[] = [];
        const userMessages: UserMessage[] = [];
        let startTime = '';
        let endTime = '';
        let model = '';

        for (const line of lines) {
          try {
            const entry = JSON.parse(line);
            if (!entry.timestamp) continue;

            if (!startTime) startTime = entry.timestamp;
            endTime = entry.timestamp;

            // Tool use (assistant calling a tool) — Claude uses type: "assistant"
            if (entry.type === 'assistant') {
              const content = entry.message?.content;
              if (Array.isArray(content)) {
                for (const block of content) {
                  if (block.type === 'tool_use') {
                    toolCalls.push({
                      id: block.id || '',
                      toolName: block.name || '',
                      arguments: block.input || {},
                      timestamp: entry.timestamp,
                      source: 'claude',
                      sessionId,
                    });
                  }
                }
              }
              if (entry.message?.model) model = entry.message.model;
            }

            // User messages + tool results — Claude puts both inside type: "user"
            if (entry.type === 'user') {
              const content = entry.message?.content;
              // Plain string = actual user message
              if (typeof content === 'string' && content.length > 0) {
                userMessages.push({ timestamp: entry.timestamp, text: content.slice(0, 500) });
              }
              // Array = tool results
              if (Array.isArray(content)) {
                for (const block of content) {
                  if (block.type === 'tool_result') {
                    const tc = toolCalls.find((t) => t.id === block.tool_use_id);
                    if (tc) {
                      const resultContent = block.content;
                      if (typeof resultContent === 'string') {
                        tc.result = resultContent.slice(0, 2000);
                      } else if (Array.isArray(resultContent)) {
                        tc.result = resultContent.map((c: any) => c.text || '').join('\n').slice(0, 2000);
                      }
                      tc.isError = !!block.is_error;
                    }
                  }
                }
              }
            }
          } catch {}
        }

        // Correlate user messages with next tool call
        for (const um of userMessages) {
          const umTime = new Date(um.timestamp).getTime();
          const nextIdx = toolCalls.findIndex((tc) => new Date(tc.timestamp).getTime() > umTime);
          if (nextIdx >= 0) um.nextToolCallIndex = nextIdx;
        }

        if (toolCalls.length > 0) {
          sessions.push({ id: sessionId, source: 'claude', startTime, endTime, model, toolCalls, userMessages, filePath });
        }
      } catch {}
    }
  }

  return sessions;
}

// ── Antigravity CLI (`agy`) logs ──
// Location: ~/.gemini/antigravity/brain/<conversationId>/.system_generated/logs/transcript.jsonl
// Format: JSONL. Tool calls appear as objects carrying a `toolCall` ({ name, args })
// — the same shape the PreToolUse hook receives. Parsed defensively: unknown line
// shapes are skipped, so a schema drift degrades to "no sessions", never a crash.
// NOTE: the exact transcript line schema is not yet verified against a live agy
// session — revisit if audit collection comes up empty on a real run.
function collectAntigravity(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const brainDir = resolve(homedir(), '.gemini', 'antigravity', 'brain');
  if (!existsSync(brainDir)) return sessions;

  for (const convId of readdirSync(brainDir)) {
    const convPath = join(brainDir, convId);
    try { if (!statSync(convPath).isDirectory()) continue; } catch { continue; }
    const transcript = join(convPath, '.system_generated', 'logs', 'transcript.jsonl');
    if (!existsSync(transcript)) continue;

    try {
      const lines = readFileSync(transcript, 'utf-8').split('\n').filter(Boolean);
      const toolCalls: ToolCall[] = [];
      const userMessages: UserMessage[] = [];
      let startTime = '';
      let endTime = '';
      let model = '';

      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          const ts = entry.timestamp || entry.time || entry.ts || '';
          if (ts) { if (!startTime) startTime = ts; endTime = ts; }
          if (!model && typeof entry.model === 'string') model = entry.model;

          // Tool call — the hook-shaped { toolCall: { name, args } }, or a flat
          // tool entry ({ type: 'tool_call', name, args }).
          const tc = entry.toolCall || (entry.type === 'tool_call' ? entry : null);
          if (tc && typeof tc === 'object' && (tc.name || tc.toolName)) {
            toolCalls.push({
              id: tc.id || (entry.stepIdx != null ? String(entry.stepIdx) : ''),
              toolName: tc.name || tc.toolName || '',
              arguments: tc.args || tc.arguments || {},
              result: entry.result ? JSON.stringify(entry.result).slice(0, 2000) : undefined,
              isError: entry.status === 'error' || entry.isError === true,
              timestamp: ts,
              source: 'antigravity',
              sessionId: convId,
            });
          }

          // User prompt
          const role = entry.role || entry.type;
          if ((role === 'user' || role === 'user_message') && (entry.text || entry.content)) {
            const text = String(entry.text || entry.content).slice(0, 500);
            if (text.length > 0) userMessages.push({ timestamp: ts, text });
          }
        } catch {}
      }

      // Correlate user messages with next tool call
      for (const um of userMessages) {
        const umTime = new Date(um.timestamp).getTime();
        const nextIdx = toolCalls.findIndex((tc) => new Date(tc.timestamp).getTime() > umTime);
        if (nextIdx >= 0) um.nextToolCallIndex = nextIdx;
      }

      if (toolCalls.length > 0) {
        sessions.push({
          id: convId,
          source: 'antigravity',
          startTime,
          endTime,
          model,
          toolCalls,
          userMessages,
          filePath: transcript,
        });
      }
    } catch {}
  }

  return sessions;
}

// ── Codex CLI logs ──
// Location: ~/.codex/sessions/YYYY/MM/DD/rollout-<ts>-<uuid>.jsonl
// Format: JSONL "rollout lines" — { timestamp, type, payload }, where type
// "response_item" carries the model's items (codex-rs/protocol: RolloutItem is
// tagged type/payload, ResponseItem is tagged by its own `type`):
//   function_call         { name, arguments: "<json string>", call_id }  (shell, MCP, …)
//   custom_tool_call      { name, input: "<raw text>", call_id }         (apply_patch)
//   function_call_output  { call_id, output }
//   message               { role, content: [{ text }] }
// Parsed defensively — an unknown line shape is skipped, so a schema change
// degrades to "fewer sessions", never a crash.
function collectCodex(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const root = process.env['CODEX_HOME']
    ? resolve(process.env['CODEX_HOME'], 'sessions')
    : resolve(homedir(), '.codex', 'sessions');
  if (!existsSync(root)) return sessions;

  // sessions/<year>/<month>/<day>/*.jsonl — walk the date tree (bounded depth).
  const files: string[] = [];
  const walk = (dir: string, depth: number): void => {
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const e of entries) {
      const p = join(dir, e);
      let isDir = false;
      try { isDir = statSync(p).isDirectory(); } catch { continue; }
      if (isDir) { if (depth < 4) walk(p, depth + 1); }
      else if (e.endsWith('.jsonl')) files.push(p);
    }
  };
  walk(root, 0);

  for (const filePath of files) {
    try {
      const lines = readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
      const toolCalls: ToolCall[] = [];
      const userMessages: UserMessage[] = [];
      let startTime = '';
      let endTime = '';
      let model = '';
      let sessionId = filePath.split(/[\\/]/).pop()!.replace('.jsonl', '');

      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          const ts: string = entry.timestamp || '';
          if (ts) {
            if (!startTime) startTime = ts;
            endTime = ts;
          }

          if (entry.type === 'session_meta') {
            const meta = entry.payload?.meta ?? entry.payload;
            if (meta?.id) sessionId = String(meta.id);
            if (meta?.model) model = String(meta.model);
            continue;
          }
          if (entry.type === 'turn_context' && entry.payload?.model && !model) {
            model = String(entry.payload.model);
            continue;
          }
          if (entry.type !== 'response_item') continue;

          const item = entry.payload;
          if (!item || typeof item !== 'object') continue;

          // Tool call — function_call carries JSON-encoded arguments, while a
          // freeform custom tool (apply_patch) carries raw text in `input`.
          if (item.type === 'function_call' || item.type === 'custom_tool_call' || item.type === 'local_shell_call') {
            let args: Record<string, unknown> = {};
            if (typeof item.arguments === 'string') {
              try { args = JSON.parse(item.arguments); } catch { args = { arguments: item.arguments }; }
            } else if (item.arguments && typeof item.arguments === 'object') {
              args = item.arguments as Record<string, unknown>;
            } else if (typeof item.input === 'string') {
              args = { command: item.input };
            } else if (item.action && typeof item.action === 'object') {
              args = item.action as Record<string, unknown>;
            }
            toolCalls.push({
              id: String(item.call_id || item.id || ''),
              toolName: String(item.name || (item.type === 'local_shell_call' ? 'Bash' : '')),
              arguments: args,
              timestamp: ts,
              source: 'codex',
              sessionId,
            });
            continue;
          }

          if (item.type === 'function_call_output' || item.type === 'custom_tool_call_output') {
            const tc = toolCalls.find((t) => t.id === String(item.call_id || ''));
            if (tc) {
              const out = item.output;
              const text = typeof out === 'string' ? out
                : typeof out?.content === 'string' ? out.content
                : out ? JSON.stringify(out) : '';
              tc.result = text.slice(0, 2000);
              tc.isError = out?.success === false || /"error"/.test(text.slice(0, 2000));
            }
            continue;
          }

          if (item.type === 'message' && item.role === 'user' && Array.isArray(item.content)) {
            const text = item.content.map((c: any) => c?.text || '').join('\n').trim();
            // Codex replays environment/context blocks as user messages — keep
            // only what a person actually typed.
            if (text && !text.startsWith('<')) {
              userMessages.push({ timestamp: ts, text: text.slice(0, 500) });
            }
          }
        } catch {}
      }

      // Correlate user messages with next tool call
      for (const um of userMessages) {
        const umTime = new Date(um.timestamp).getTime();
        const nextIdx = toolCalls.findIndex((tc) => new Date(tc.timestamp).getTime() > umTime);
        if (nextIdx >= 0) um.nextToolCallIndex = nextIdx;
      }

      if (toolCalls.length > 0) {
        sessions.push({ id: sessionId, source: 'codex', startTime, endTime, model, toolCalls, userMessages, filePath });
      }
    } catch {}
  }

  return sessions;
}

// ── OpenClaw logs ──
// Location: ~/.openclaw/agents/main/sessions/<session-id>.jsonl
// Format: JSONL with {"type":"message","message":{"role":"toolResult","toolName":"..."}}
function collectOpenClaw(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const oclawDir = resolve(homedir(), '.openclaw', 'agents', 'main', 'sessions');
  if (!existsSync(oclawDir)) return sessions;

  for (const file of readdirSync(oclawDir)) {
    if (!file.endsWith('.jsonl')) continue;
    const filePath = join(oclawDir, file);
    const sessionId = file.replace('.jsonl', '');

    try {
      const lines = readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
      const toolCalls: ToolCall[] = [];
      const userMessages: UserMessage[] = [];
      let startTime = '';
      let endTime = '';
      let model = '';

      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          if (!entry.timestamp) continue;

          if (!startTime) startTime = entry.timestamp;
          endTime = entry.timestamp;

          if (entry.type === 'model_change') {
            model = entry.modelId || '';
          }

          // User messages
          if (entry.type === 'message' && entry.message?.role === 'user') {
            const content = entry.message.content;
            if (typeof content === 'string' && content.length > 0) {
              userMessages.push({ timestamp: entry.timestamp, text: content.slice(0, 500) });
            }
          }

          // Tool use from assistant
          if (entry.type === 'message' && entry.message?.role === 'assistant') {
            const content = entry.message.content;
            if (Array.isArray(content)) {
              for (const block of content) {
                if (block.type === 'toolCall' || block.type === 'tool_use') {
                  toolCalls.push({
                    id: block.id || '',
                    toolName: block.name || '',
                    arguments: block.arguments || block.input || {},
                    timestamp: entry.timestamp,
                    source: 'openclaw',
                    sessionId,
                  });
                }
              }
            }
          }

          // Tool result
          if (entry.type === 'message' && entry.message?.role === 'toolResult') {
            const tc = toolCalls.find((t) => t.id === entry.message.toolCallId);
            if (tc) {
              const content = entry.message.content;
              if (Array.isArray(content)) {
                tc.result = content.map((c: any) => c.text || '').join('\n').slice(0, 2000);
              }
              tc.isError = !!entry.message.isError;
            }
          }
        } catch {}
      }

      // Correlate user messages with next tool call
      for (const um of userMessages) {
        const umTime = new Date(um.timestamp).getTime();
        const nextIdx = toolCalls.findIndex((tc) => new Date(tc.timestamp).getTime() > umTime);
        if (nextIdx >= 0) um.nextToolCallIndex = nextIdx;
      }

      if (toolCalls.length > 0) {
        sessions.push({ id: sessionId, source: 'openclaw', startTime, endTime, model, toolCalls, userMessages, filePath });
      }
    } catch {}
  }

  return sessions;
}

// ── Custom directory logs ──
// Tries to parse JSONL/JSON files from user-specified directories
// Auto-detects format (Claude, Antigravity, or OpenClaw style)
function collectCustomDirs(): SessionInfo[] {
  const sessions: SessionInfo[] = [];
  const config = loadConfig();

  for (const dir of config.customDirs) {
    if (!existsSync(dir)) continue;

    try {
      for (const file of readdirSync(dir)) {
        const filePath = join(dir, file);
        try {
          if (!statSync(filePath).isFile()) continue;
        } catch { continue; }

        // JSONL files — try Claude/OpenClaw format
        if (file.endsWith('.jsonl')) {
          try {
            const lines = readFileSync(filePath, 'utf-8').split('\n').filter(Boolean);
            const toolCalls: ToolCall[] = [];
            let startTime = '';
            let endTime = '';
            let model = '';
            const sessionId = file.replace('.jsonl', '');

            for (const line of lines) {
              try {
                const entry = JSON.parse(line);
                if (!entry.timestamp) continue;
                if (!startTime) startTime = entry.timestamp;
                endTime = entry.timestamp;

                if (entry.type === 'model_change') model = entry.modelId || '';

                // Claude format: type === 'assistant'
                if (entry.type === 'assistant') {
                  const content = entry.message?.content;
                  if (Array.isArray(content)) {
                    for (const block of content) {
                      if (block.type === 'tool_use') {
                        toolCalls.push({ id: block.id || '', toolName: block.name || '', arguments: block.input || {}, timestamp: entry.timestamp, source: 'claude', sessionId });
                      }
                    }
                  }
                  if (entry.message?.model) model = entry.message.model;
                }

                // OpenClaw format: type === 'message', role === 'assistant'
                if (entry.type === 'message' && entry.message?.role === 'assistant') {
                  const content = entry.message.content;
                  if (Array.isArray(content)) {
                    for (const block of content) {
                      if (block.type === 'toolCall' || block.type === 'tool_use') {
                        toolCalls.push({ id: block.id || '', toolName: block.name || '', arguments: block.arguments || block.input || {}, timestamp: entry.timestamp, source: 'openclaw', sessionId });
                      }
                    }
                  }
                }

                // Claude tool result
                if (entry.type === 'user') {
                  const content = entry.message?.content;
                  if (Array.isArray(content)) {
                    for (const block of content) {
                      if (block.type === 'tool_result') {
                        const tc = toolCalls.find((t) => t.id === block.tool_use_id);
                        if (tc) {
                          const rc = block.content;
                          tc.result = typeof rc === 'string' ? rc.slice(0, 2000) : Array.isArray(rc) ? rc.map((c: any) => c.text || '').join('\n').slice(0, 2000) : undefined;
                          tc.isError = !!block.is_error;
                        }
                      }
                    }
                  }
                }

                // OpenClaw tool result
                if (entry.type === 'message' && entry.message?.role === 'toolResult') {
                  const tc = toolCalls.find((t) => t.id === entry.message.toolCallId);
                  if (tc) {
                    const content = entry.message.content;
                    if (Array.isArray(content)) {
                      tc.result = content.map((c: any) => c.text || '').join('\n').slice(0, 2000);
                    }
                    tc.isError = !!entry.message.isError;
                  }
                }
              } catch {}
            }

            if (toolCalls.length > 0) {
              sessions.push({ id: sessionId, source: toolCalls[0]!.source, startTime, endTime, model, toolCalls, filePath });
            }
          } catch {}
        }

        // JSON files — generic session format ({ messages: [{ toolCalls: [...] }] })
        if (file.endsWith('.json')) {
          try {
            const data = JSON.parse(readFileSync(filePath, 'utf-8'));
            if (!data.messages || !Array.isArray(data.messages)) continue;
            const toolCalls: ToolCall[] = [];
            const sessionId = data.sessionId || file.replace('.json', '');

            for (const msg of data.messages) {
              if (!msg.toolCalls || !Array.isArray(msg.toolCalls)) continue;
              for (const tc of msg.toolCalls) {
                toolCalls.push({ id: tc.id || '', toolName: tc.name || '', arguments: tc.args || tc.arguments || {}, result: tc.result ? JSON.stringify(tc.result).slice(0, 2000) : undefined, isError: tc.status === 'error', timestamp: tc.timestamp || msg.timestamp || data.startTime || '', source: 'antigravity', sessionId });
              }
            }

            if (toolCalls.length > 0) {
              sessions.push({ id: sessionId, source: 'antigravity', startTime: data.startTime || '', endTime: data.lastUpdated || '', model: data.messages?.[0]?.model || '', toolCalls, filePath });
            }
          } catch {}
        }
      }
    } catch {}
  }

  return sessions;
}

export function collectLogs(): AuditData {
  const claudeSessions = collectClaude();
  const codexSessions = collectCodex();
  const antigravitySessions = collectAntigravity();
  const openclawSessions = collectOpenClaw();
  const customSessions = collectCustomDirs();

  const sessions = [...claudeSessions, ...codexSessions, ...antigravitySessions, ...openclawSessions, ...customSessions]
    .sort((a, b) => (a.startTime || '').localeCompare(b.startTime || ''));

  const sources: string[] = [];
  if (claudeSessions.length > 0) sources.push('Claude Code');
  if (codexSessions.length > 0) sources.push('Codex');
  if (antigravitySessions.length > 0) sources.push('Antigravity');
  if (openclawSessions.length > 0) sources.push('OpenClaw');

  const allCalls = sessions.flatMap((s) => s.toolCalls);
  const timestamps = allCalls.map((t) => t.timestamp).filter(Boolean).sort();

  return {
    sessions,
    totalToolCalls: allCalls.length,
    sources,
    timeRange: timestamps.length > 0
      ? { from: timestamps[0]!, to: timestamps[timestamps.length - 1]! }
      : null,
  };
}
