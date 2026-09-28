// Shared system-wide (global) install logic for the cloud guard hook.
// Used by BOTH `init --global` and `login` so the two stay in lockstep.
//
// A global install registers a single hook in the user's GLOBAL Claude Code
// settings (~/.claude/settings.json) that intercepts EVERY tool call from EVERY
// session on the machine — the air-gapped product's behavior, sourced from the
// cloud. The SAME guard is registered for every supported client:
// Antigravity CLI (`agy`) in ~/.gemini/config/hooks.json under a named hook
// group's PreToolUse event, Codex CLI (`codex`) in ~/.codex/hooks.json, and
// OpenCode as a plugin module in ~/.config/opencode/plugins/.
// Only the hook's response contract differs per agent (Claude Code AND Codex:
// exit-2/stderr + permissionDecision JSON; Antigravity: {"decision":"deny"} JSON
// on stdout; OpenCode: a plugin that spawns the guard and throws on exit 2),
// which the guard hook itself handles from the AGENT_TYPE baked into
// argv[2]. Layout:
//   ~/.solongate/hooks/{guard,audit,stop}.mjs   (guard = opa-wasm bundle)
//   ~/.solongate/cloud-guard.json               ({ apiKey, apiUrl })
//   ~/.claude/settings.json                      (PreToolUse/PostToolUse/Stop)
//   ~/.claude/settings.solongate.bak             (one-time backup of the above)
//   ~/.gemini/config/hooks.json                  ({ "solongate-guard": { PreToolUse } })
//   ~/.gemini/config/hooks.solongate.bak         (one-time backup of the above)
//   ~/.codex/hooks.json                          ({ hooks: { PreToolUse, PostToolUse, Stop } })
//   ~/.codex/hooks.solongate.bak                 (one-time backup of the above)
//   ~/.config/opencode/plugins/solongate.js      (plugin module; the file IS the registration)
import { readFileSync, writeFileSync, existsSync, mkdirSync, rmSync, rmdirSync, readdirSync, statSync, chmodSync, copyFileSync, renameSync } from 'node:fs';
import { resolve, join, dirname, basename } from 'node:path';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawn } from 'node:child_process';
import { BEAT_DIR, LAUNCHER_NAME, launcherScript } from './hook-launcher.js';
// Re-exported so the conformance suite can reach them: tsup bundles
// hook-launcher.ts into this entry rather than emitting it separately, so
// ../dist/hook-launcher.js does not exist to import.
export { BEAT_DIR, LAUNCHER_NAME, launcherScript } from './hook-launcher.js';
export { agoLabel, guardBeat, hookBeats, hookCanStart } from './hook-health.js';
import { hookCanStart } from './hook-health.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const HOOKS_DIR = resolve(__dirname, '..', 'hooks');

// ── OS-level immutability for the active protection files ────────────────────
// Defense-in-depth beyond the guard hook: lock the installed hooks + settings at
// the OS level so NO process (any AI, any editor, plain `rm`/`>`, or an innocent-
// looking `node script.mjs` that deletes the files from inside) can modify them.
// This is the ONLY layer that survives the guard's blind spot: the guard inspects
// command STRINGS, not the filesystem calls a spawned program makes. It is part of
// self-protection and applied on every install (self-protection defaults ON); a
// dev can opt out with SOLONGATE_NO_OS_LOCK=1. All best-effort; never throws.
//
// Each mechanism works for the CURRENT USER without sudo/admin:
//   macOS:   chflags uchg  — user-immutable; blocks delete AND overwrite even by
//            the owner. No sudo.
//   Windows: icacls deny(delete,write,write-DAC) to Everyone + an OWNER_RIGHTS
//            (S-1-3-4) ACE pinned to read/execute, so the owner can't rewrite the
//            ACL back and then delete. + read-only attribute. No admin.
//   Linux:   chattr +i is the only true immutability but needs privilege (a no-op
//            otherwise, harmless). chmod a-w ALWAYS works with no sudo and blocks
//            the overwrite-disarm (rewriting the hook/config in place). A pure
//            unlink still needs privileged chattr on Linux — see runRepair.
function lockFile(file: string): void {
  if (!existsSync(file)) return;
  try {
    if (process.platform === 'win32') {
      // No admin needed for a file the current user owns. Deny delete + write +
      // ACL/owner rewrite to Everyone, then neuter the owner's IMPLICIT rights via
      // the OWNER_RIGHTS SID (S-1-3-4) so the owner can't simply grant themselves
      // delete back. Inherited allow-read/execute stays, so node still loads it.
      try { execFileSync('icacls', [file, '/deny', '*S-1-1-0:(WD,AD,DC,DE,WDAC,WO)'], { stdio: 'ignore' }); } catch {}
      try { execFileSync('icacls', [file, '/grant', '*S-1-3-4:(RX)'], { stdio: 'ignore' }); } catch {}
      try { execFileSync('attrib', ['+R', file], { stdio: 'ignore' }); } catch {}
    } else if (process.platform === 'darwin') {
      try { execFileSync('chflags', ['uchg', file], { stdio: 'ignore' }); } catch {}
    } else {
      try { execFileSync('chattr', ['+i', file], { stdio: 'ignore' }); } catch {}
      try { chmodSync(file, 0o444); } catch {}
    }
  } catch { /* best-effort */ }
}

function unlockFile(file: string): void {
  if (!existsSync(file)) return;
  try {
    if (process.platform === 'win32') {
      try { execFileSync('icacls', [file, '/remove:g', '*S-1-3-4'], { stdio: 'ignore' }); } catch {}
      try { execFileSync('icacls', [file, '/remove:d', '*S-1-1-0'], { stdio: 'ignore' }); } catch {}
      try { execFileSync('icacls', [file, '/reset'], { stdio: 'ignore' }); } catch {}
      try { execFileSync('attrib', ['-R', file], { stdio: 'ignore' }); } catch {}
    } else if (process.platform === 'darwin') {
      try { execFileSync('chflags', ['nouchg', file], { stdio: 'ignore' }); } catch {}
    } else {
      try { execFileSync('chattr', ['-i', file], { stdio: 'ignore' }); } catch {}
      try { chmodSync(file, 0o644); } catch {}
    }
  } catch { /* best-effort */ }
}

function protectedTargets(): string[] {
  const p = globalPaths();
  return [
    join(p.hooksDir, 'guard.mjs'),
    join(p.hooksDir, 'audit.mjs'),
    join(p.hooksDir, 'stop.mjs'),
    join(p.hooksDir, 'shield.mjs'),
    // The conversation record is locked with the rest. A guest who could edit
    // it could decide what their host sees them say, which is the same class of
    // problem as editing the guard.
    join(p.hooksDir, 'conversation.mjs'),
    // The launcher is the enforcement path now: every hook command in every
    // client config runs THROUGH it. A program that could rewrite it could
    // point every hook at /bin/true and disarm the guard without touching a
    // single file that used to be locked.
    join(p.hooksDir, LAUNCHER_NAME),
    p.configPath,
    p.settingsPath,
    p.antigravityHooksPath,
    p.codexHooksPath,
    // The OpenCode plugin IS the registration — delete it and the guard is gone
    // from that client with nothing left to notice the absence, so it belongs
    // under the same OS lock as every other protection file.
    p.opencodePluginPath,
  ];
}

export function lockProtected(): void { for (const f of protectedTargets()) lockFile(f); }
export function unlockProtected(): void { for (const f of protectedTargets()) unlockFile(f); }

/**
 * Rewrite ONE protected file, clearing and restoring its OS lock around the
 * write. Needed by the credential writers: cloud-guard.json is locked
 * (chflags uchg on macOS, read-only ACL on Windows, 0444 on Linux), so a plain
 * writeFileSync throws EPERM and the caller — which swallows the error — leaves
 * the OLD key in place. That is how a device revoked in the dashboard got stuck
 * on "Invalid API key": removing or switching the account reported success while
 * the dead key was still on disk.
 *
 * Only unlocks when the direct write actually fails, so a device with the lock
 * disabled is untouched, and re-locks only what it unlocked. Safe by design: the
 * CLI is human-only, and the lock exists to stop PROGRAMS (agents, editors,
 * stray scripts) from disarming the guard, not the person at the terminal.
 */
export function writeProtectedFile(file: string, contents: string): boolean {
  try {
    writeFileSync(file, contents);
    return true;
  } catch {
    unlockFile(file);
    try {
      writeFileSync(file, contents);
      return true;
    } catch {
      return false;
    } finally {
      if (process.env['SOLONGATE_NO_OS_LOCK'] !== '1') lockFile(file);
    }
  }
}

export function globalPaths() {
  const home = homedir();
  const sgDir = join(home, '.solongate');
  const hooksDir = join(sgDir, 'hooks');
  const claudeDir = join(home, '.claude');
  // Antigravity CLI (`agy`) keeps its global config under ~/.gemini/config.
  const antigravityDir = join(home, '.gemini', 'config');
  // Codex CLI keeps its config under CODEX_HOME (defaults to ~/.codex).
  const codexDir = process.env['CODEX_HOME'] ? resolve(process.env['CODEX_HOME']) : join(home, '.codex');
  // OpenCode keeps global config under XDG_CONFIG_HOME/opencode (~/.config/opencode).
  const opencodeDir = join(process.env['XDG_CONFIG_HOME'] ? resolve(process.env['XDG_CONFIG_HOME']) : join(home, '.config'), 'opencode');
  // Where the Go binaries are copied so a GLOBAL install can find them. The
  // hook installed under hooksDir is a lone file launched from arbitrary working
  // directories, so resolving the platform package through node_modules from
  // there finds nothing. See installGoBinaries.
  const binDir = join(sgDir, 'bin');
  return {
    home, sgDir, hooksDir, binDir, claudeDir, antigravityDir, codexDir, opencodeDir,
    settingsPath: join(claudeDir, 'settings.json'),
    backupPath: join(claudeDir, 'settings.solongate.bak'),
    configPath: join(sgDir, 'cloud-guard.json'),
    // Antigravity reads global hooks from ~/.gemini/config/hooks.json. Only the
    // guard is registered there (PreToolUse); Antigravity's ALLOW-path audit is
    // covered by the passive session-log collector, not a hook.
    antigravityHooksPath: join(antigravityDir, 'hooks.json'),
    antigravityBackupPath: join(antigravityDir, 'hooks.solongate.bak'),
    // Codex reads user-level hooks from ~/.codex/hooks.json (or a [hooks] table
    // in ~/.codex/config.toml — we use the JSON file so we never have to rewrite
    // the user's TOML, which also holds the hook TRUST state Codex manages).
    codexHooksPath: join(codexDir, 'hooks.json'),
    codexBackupPath: join(codexDir, 'hooks.solongate.bak'),
    codexConfigPath: join(codexDir, 'config.toml'),
    // OpenCode scans its plugin folder at startup and loads every module in it.
    // Measured on 1.18.10: BOTH `plugin/` and `plugins/` are scanned, so the
    // docs and the field reports are each half right. We write the documented
    // one. There is nothing to register anywhere — dropping the file IS the
    // installation, which also means deleting the file IS the uninstall.
    opencodePluginDir: join(opencodeDir, 'plugins'),
    opencodePluginPath: join(opencodeDir, 'plugins', 'solongate.js'),
  };
}

// The installed guard hook only re-checks the registry for a newer bundle every
// ~6h; between checks it skips the network by reading ~/.solongate/.hook-update-check.
// Deleting that stamp forces the guard to re-check (and install a newer bundle)
// on the NEXT executed command — the exact thing the dashboard tells operators to
// `rm` by hand. Idempotent: a missing stamp (already cleared, or guard <v26 which
// auto-updates anyway) still counts as success. Not one of the locked/immutable
// protected files, so a plain delete works. Returns false only on a real fs error.
export function clearGuardUpdateCheck(): boolean {
  try {
    rmSync(join(globalPaths().sgDir, '.hook-update-check'), { force: true });
    return true;
  } catch {
    return false;
  }
}

function readHook(filename: string): string {
  return readFileSync(join(HOOKS_DIR, filename), 'utf-8');
}

// The device's logged-in accounts live in ~/.solongate/accounts.json (written by
// the dataroom's device login). cloud-guard.json holds only the ACTIVE key the
// guard hooks read — and a fresh device login populates accounts.json but sets
// only the runtime VIEW credential, NOT the active-key file. So cloud-guard.json
// can be empty while the user is fully logged in. When that happens we fall back
// to the first saved account here; the install then persists this key to
// cloud-guard.json, activating it. Without this a logged-in user got a spurious
// "no login on this device" and could never install the guard.
function firstAccountCredential(): { apiKey?: string; apiUrl?: string } {
  try {
    const raw = JSON.parse(readFileSync(join(homedir(), '.solongate', 'accounts.json'), 'utf-8'));
    if (Array.isArray(raw)) {
      const acc = raw.find((a) => a && typeof a.apiKey === 'string' && a.apiKey);
      if (acc) return { apiKey: acc.apiKey as string, apiUrl: typeof acc.apiUrl === 'string' ? acc.apiUrl : undefined };
    }
  } catch { /* no accounts file */ }
  return {};
}

// Prefer the pre-bundled guard (opa-wasm inlined) so the lone installed file
// works with no node_modules next to it. Fall back to source in a dev tree.
function readGuard(): string {
  const bundled = join(HOOKS_DIR, 'guard.bundled.mjs');
  return existsSync(bundled) ? readFileSync(bundled, 'utf-8') : readHook('guard.mjs');
}

/**
 * Copy the Go binaries next to the installed hook.
 *
 * The hook this installer writes is a LONE FILE under ~/.solongate/hooks,
 * launched by a client from whatever directory the agent happens to be in.
 * Resolving @solongate/guard-<platform> through node_modules from there finds
 * nothing, so the binary is copied to a fixed path the hook already looks in.
 *
 * BEST EFFORT, AND THAT IS THE POINT. No binary for this platform, a registry
 * that declined the optionalDependency, a read-only home — none of it is an
 * install failure. The hook falls back to its Node implementation and enforces
 * the same policy more slowly. A missing binary costs speed, never protection,
 * and an installer that refused to proceed without one would turn a performance
 * feature into an outage.
 *
 * Returns what it managed to place, for the caller to report.
 */
function installGoBinaries(binDir: string): string[] {
  const os_ = process.platform === 'win32' ? 'win32' : process.platform;
  const cpu = process.arch === 'x64' ? 'x64' : process.arch;
  const suffix = process.platform === 'win32' ? '.exe' : '';
  const placed: string[] = [];
  let pkgDir: string;
  try {
    const require_ = createRequire(import.meta.url);
    pkgDir = dirname(require_.resolve(`@solongate/guard-${os_}-${cpu}/package.json`));
  } catch {
    return placed; // unsupported platform, or installed with --no-optional
  }
  try { mkdirSync(binDir, { recursive: true }); } catch { return placed; }
  for (const name of ['solongate-guard', 'solongate']) {
    const from = join(pkgDir, name + suffix);
    const to = join(binDir, name + suffix);
    try {
      if (!existsSync(from)) continue;
      // Written to a temp name and renamed so a hook that fires mid-install
      // never sees a half-copied binary. It would be refused (the version probe
      // fails) and fall back to Node, which is safe but slower for no reason.
      const tmp = to + '.new';
      copyFileSync(from, tmp);
      chmodSync(tmp, 0o755);
      renameSync(tmp, to);
      placed.push(name + suffix);
    } catch { /* leave the previous copy, or none */ }
  }
  return placed;
}

// ── Antigravity CLI guard registration ───────────────────────────────────────
// Antigravity CLI (`agy`) runs hooks configured in ~/.gemini/config/hooks.json.
// The file is a map of NAMED hook groups; each group holds event arrays. Its
// PreToolUse event fires a local command before every tool call, which blocks
// the tool by writing {"decision":"deny","reason":"..."} to stdout (exit 0) and
// allows it with {"decision":"allow"}. The SAME guard.mjs produces that contract
// when its agent type (argv[2]) is "antigravity" instead of "claude-code" — so
// we register the one guard here under our OWN group key, leaving any other hook
// groups the user configured untouched. matcher "" matches every tool. Best
// effort: an Antigravity failure must never break the Claude install, so callers
// wrap these in try/catch.
const ANTIGRAVITY_GROUP = 'solongate-guard';

function antigravityHookCommand(guardAbs: string): string {
  // Through the launcher, for the same reason Claude's goes through it: the
  // node path recorded here at install time is a Homebrew Cellar or nvm version
  // directory on most Macs, and both are deleted by a routine upgrade.
  return hookCommandFor(dirname(guardAbs), basename(guardAbs), 'antigravity', 'Antigravity');
}

// antigravityConversationCommand is the same launcher with the conversation
// hook behind it. It takes the guard's path only to derive the hooks directory,
// which is the one thing every hook here shares.
function antigravityConversationCommand(guardAbs: string): string {
  return hookCommandFor(dirname(guardAbs), 'conversation.mjs', 'antigravity', 'Antigravity');
}

function installAntigravityGuard(p: ReturnType<typeof globalPaths>, guardAbs: string): void {
  mkdirSync(p.antigravityDir, { recursive: true });
  let existing: Record<string, unknown> = {};
  if (existsSync(p.antigravityHooksPath)) {
    const raw = readFileSync(p.antigravityHooksPath, 'utf-8');
    if (!existsSync(p.antigravityBackupPath)) writeFileSync(p.antigravityBackupPath, raw); // one-time backup
    try { existing = JSON.parse(raw) as Record<string, unknown>; } catch { existing = {}; }
  }
  // Own a single named group — replace only ours, preserve every other group.
  //
  // Two events. PreToolUse is the guard, and Stop is the conversation record —
  // which on this client is ONE hook for both halves of an exchange, because
  // its payload carries the person's last message on `common.lastUserInput`
  // (present on every hook) and the answer on `stopHookArgs.finalModelOutput`.
  // Claude Code and Codex need two events to record the same thing.
  //
  // Stop, not PostInvocation: an invocation is one model call and a turn is
  // often several, so PostInvocation would write a row per step and the
  // transcript would read as the agent interrupting itself. Stop is the end of
  // the turn, which is what a person means by a message.
  const merged = {
    ...existing,
    [ANTIGRAVITY_GROUP]: {
      PreToolUse: [{ matcher: '', hooks: [{ type: 'command', command: antigravityHookCommand(guardAbs) }] }],
      Stop: [{ matcher: '', hooks: [{ type: 'command', command: antigravityConversationCommand(guardAbs) }] }],
    },
  };
  writeFileSync(p.antigravityHooksPath, JSON.stringify(merged, null, 2) + '\n');
}

// Remove ONLY our named group from Antigravity's hooks.json (leaving any user
// hook groups intact). We never restore the .bak — a backup captured while the
// guard was present would silently re-add it (the same footgun uninstallGlobal
// Quiet avoids for Claude), so stripping our own key is the safe path.
function removeAntigravityGuard(p: ReturnType<typeof globalPaths>): void {
  if (!existsSync(p.antigravityHooksPath)) return;
  try {
    const s = JSON.parse(readFileSync(p.antigravityHooksPath, 'utf-8')) as Record<string, unknown>;
    if (!(ANTIGRAVITY_GROUP in s)) return;
    delete s[ANTIGRAVITY_GROUP];
    writeFileSync(p.antigravityHooksPath, JSON.stringify(s, null, 2) + '\n');
  } catch { /* leave as-is */ }
}

// ── Codex CLI guard registration ─────────────────────────────────────────────
// Codex CLI (`codex`) loads user-level lifecycle hooks from ~/.codex/hooks.json.
// The file shape is (codex-rs/config/src/hook_config.rs, deny_unknown_fields):
//   { "description"?: string,
//     "hooks": { "<Event>": [ { "matcher"?: string,
//                               "hooks": [ { "type": "command", "command": "…",
//                                            "timeout"?: <seconds>,
//                                            "statusMessage"?: "…" } ] } ] } }
// Its PreToolUse contract is the SAME one Claude Code uses — a deny is
// {"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":
// "deny","permissionDecisionReason":"…"}} on stdout, OR exit 2 with the reason on
// stderr; an allow is exit 0 with empty stdout; a rewrite is permissionDecision
// "allow" + updatedInput. So the guard's claude-code branch already speaks it and
// AGENT_TYPE only changes identity/audit source. Codex fires the hooks for Bash,
// apply_patch (matcher aliases Write/Edit), MCP tools and local function tools.
//
// Unlike Antigravity's named hook groups, Codex's file is a plain per-event list,
// so "ours" is identified by the command referencing the ~/.solongate hooks dir —
// every other entry in the file is preserved untouched.
//
// One-time trust: Codex requires a user to review a non-managed hook (`/hooks`)
// before it runs, keyed by a hash of the hook's config. Our command string is
// stable across guard updates (the file content changes, the registration does
// not), so the trust survives every later update — it is asked for exactly once.
// Codex declares UserPromptSubmit and Stop in the same shape Claude Code does,
// so a fleet on that client records the conversation too. Antigravity runs
// neither — it has PreToolUse and nothing else — which is why a fleet on agy has
// tool calls and no conversation, and why the fleet page says so rather than
// leaving a reader to wonder where the words went.
const CODEX_EVENTS = ['PreToolUse', 'PostToolUse', 'UserPromptSubmit', 'Stop'] as const;
const CODEX_TIMEOUT_SEC = 30;

type CodexHandler = { type: string; command?: string; [k: string]: unknown };
type CodexGroup = { matcher?: string; hooks?: CodexHandler[] };

function codexHookCommand(scriptAbs: string): string {
  // Codex runs a hook through `$SHELL -lc` on POSIX, so its environment DOES
  // usually have node on PATH — but "usually" is what the last version of this
  // relied on. It goes through the launcher too, which tries PATH anyway.
  //
  // The one difference from the others: no PowerShell `&` prefix on Windows.
  // Codex uses `cmd.exe /C` there, and cmd has no call operator, so the prefix
  // would break the hook rather than fix it.
  if (process.platform === 'win32') {
    return `"${process.execPath.replace(/\\/g, '/')}" "${scriptAbs.replace(/\\/g, '/')}" codex "Codex"`;
  }
  return hookCommandFor(dirname(scriptAbs), basename(scriptAbs), 'codex', 'Codex');
}

function isOurCodexGroup(group: CodexGroup): boolean {
  const hooks = Array.isArray(group?.hooks) ? group.hooks : [];
  return hooks.some((h) => typeof h?.command === 'string' && h.command.includes('.solongate'));
}

/** Read ~/.codex/hooks.json into the { description?, hooks } shape, folding any
 *  stray top-level event keys into `hooks`. Codex parses the file with
 *  deny_unknown_fields, so a top-level "PreToolUse" would make it reject the
 *  WHOLE file (silently dropping every hook, ours included) — folding keeps both
 *  the user's config and our guard alive. */
function readCodexHooksFile(path: string): { description?: string; hooks: Record<string, CodexGroup[]>; rest: Record<string, unknown> } {
  const out: { description?: string; hooks: Record<string, CodexGroup[]>; rest: Record<string, unknown> } = { hooks: {}, rest: {} };
  if (!existsSync(path)) return out;
  let raw: Record<string, unknown>;
  try { raw = JSON.parse(readFileSync(path, 'utf-8')) as Record<string, unknown>; } catch { return out; }
  if (!raw || typeof raw !== 'object') return out;
  const EVENTS = new Set([
    'PreToolUse', 'PermissionRequest', 'PostToolUse', 'PreCompact', 'PostCompact',
    'SessionStart', 'SessionEnd', 'UserPromptSubmit', 'SubagentStart', 'SubagentStop', 'Stop',
  ]);
  for (const [k, v] of Object.entries(raw)) {
    if (k === 'description' && typeof v === 'string') { out.description = v; continue; }
    if (k === 'hooks' && v && typeof v === 'object') {
      for (const [ev, groups] of Object.entries(v as Record<string, unknown>)) {
        if (Array.isArray(groups)) out.hooks[ev] = groups as CodexGroup[];
      }
      continue;
    }
    if (EVENTS.has(k) && Array.isArray(v)) { out.hooks[k] = (out.hooks[k] ?? []).concat(v as CodexGroup[]); continue; }
    out.rest[k] = v;
  }
  return out;
}

function writeCodexHooksFile(path: string, file: { description?: string; hooks: Record<string, CodexGroup[]>; rest: Record<string, unknown> }): void {
  const hooks: Record<string, CodexGroup[]> = {};
  for (const [ev, groups] of Object.entries(file.hooks)) if (groups.length) hooks[ev] = groups;
  const body: Record<string, unknown> = { ...file.rest };
  if (file.description) body['description'] = file.description;
  body['hooks'] = hooks;
  writeFileSync(path, JSON.stringify(body, null, 2) + '\n');
}

function installCodexGuard(p: ReturnType<typeof globalPaths>, hooksDir: string): void {
  mkdirSync(p.codexDir, { recursive: true });
  if (existsSync(p.codexHooksPath) && !existsSync(p.codexBackupPath)) {
    writeFileSync(p.codexBackupPath, readFileSync(p.codexHooksPath, 'utf-8')); // one-time backup
  }
  const file = readCodexHooksFile(p.codexHooksPath);
  const script: Record<(typeof CODEX_EVENTS)[number], string> = {
    PreToolUse: 'guard.mjs',
    PostToolUse: 'audit.mjs',
    UserPromptSubmit: 'conversation.mjs',
    // Codex takes one handler per event here, so the conversation record is
    // what Stop runs. The Claude registration keeps both because its Stop
    // already had a no-op registered that other machines are holding.
    Stop: 'conversation.mjs',
  };
  const status: Record<(typeof CODEX_EVENTS)[number], string> = {
    PreToolUse: 'SolonGate policy check',
    PostToolUse: 'SolonGate audit',
    UserPromptSubmit: 'SolonGate conversation record',
    Stop: 'SolonGate conversation record',
  };
  for (const ev of CODEX_EVENTS) {
    const kept = (file.hooks[ev] ?? []).filter((g) => !isOurCodexGroup(g)); // replace only ours
    // "*" is Codex's match-all; Stop ignores matchers entirely, so omit it there.
    const group: CodexGroup = {
      ...(ev === 'Stop' ? {} : { matcher: '*' }),
      hooks: [{
        type: 'command',
        command: codexHookCommand(join(hooksDir, script[ev]).replace(/\\/g, '/')),
        timeout: CODEX_TIMEOUT_SEC,
        statusMessage: status[ev],
      }],
    };
    file.hooks[ev] = [...kept, group];
  }
  writeCodexHooksFile(p.codexHooksPath, file);
}

// Remove ONLY our entries from Codex's hooks.json (any hook the user configured
// stays). Like the Antigravity path we never restore the .bak — a backup taken
// while the guard was registered would silently re-add it.
function removeCodexGuard(p: ReturnType<typeof globalPaths>): void {
  if (!existsSync(p.codexHooksPath)) return;
  try {
    const file = readCodexHooksFile(p.codexHooksPath);
    let changed = false;
    for (const [ev, groups] of Object.entries(file.hooks)) {
      const kept = groups.filter((g) => !isOurCodexGroup(g));
      if (kept.length !== groups.length) { file.hooks[ev] = kept; changed = true; }
    }
    if (changed) writeCodexHooksFile(p.codexHooksPath, file);
  } catch { /* leave as-is */ }
}

/** Is our guard currently registered in Codex's hooks.json on THIS device? */
export function isCodexGuardInstalled(): boolean {
  try {
    const p = globalPaths();
    const file = readCodexHooksFile(p.codexHooksPath);
    return (file.hooks['PreToolUse'] ?? []).some(isOurCodexGroup);
  } catch {
    return false;
  }
}

/** True when Codex CLI looks present on this device (its config dir exists), so
 *  callers can decide whether the Codex line is worth showing at all. */
export function codexDetected(): boolean {
  try { return existsSync(globalPaths().codexDir); } catch { return false; }
}

/** Codex refuses to RUN a non-managed hook until the user trusts it once via
 *  `/hooks`; the trust lives in ~/.codex/config.toml as `[hooks.state."…"]`
 *  entries with a `trusted_hash`. We can't recompute Codex's private hash, so
 *  this only answers "has anything been trusted yet" — enough to stop nagging a
 *  user who already did it. Also reports hooks being switched OFF wholesale
 *  (`[features] hooks = false`), which would disarm the guard on Codex. */
export function codexHooksStatus(): { registered: boolean; trusted: boolean; disabled: boolean } {
  const p = globalPaths();
  const registered = isCodexGuardInstalled();
  let trusted = false, disabled = false;
  try {
    const toml = readFileSync(p.codexConfigPath, 'utf-8');
    trusted = /trusted_hash\s*=/.test(toml);
    disabled = /^\s*hooks\s*=\s*false\s*$/m.test(toml);
  } catch { /* no config.toml yet */ }
  return { registered, trusted, disabled };
}

// ── OpenCode plugin registration ─────────────────────────────────────────────
// OpenCode has no subprocess hook contract: plugins are JS modules Bun loads
// into the running process, and a call is refused by throwing from
// `tool.execute.before`. So the shipped plugin is a shim that spawns the same
// guard every other client runs (see hooks/opencode-plugin.mjs) — one policy
// engine, not a second one that drifts.
//
// Installing is just writing the file: OpenCode scans its plugin folder at
// startup, so there is no config to edit and nothing to merge. That also makes
// the file the whole registration, which is why it is a locked protected target.
//
// Two limits worth knowing, both measured on 1.18.10 rather than read:
//   - `opencode --pure` runs with external plugins disabled and switches the
//     guard off. No hook survives it; it is the client's own escape hatch.
//   - the plugin lives under the user's config dir, so it is as removable as
//     any file there. The OS lock is what makes that require intent.
function installOpencodeGuard(p: ReturnType<typeof globalPaths>): void {
  mkdirSync(p.opencodePluginDir, { recursive: true });
  // Bake in the node binary. OpenCode loads plugins inside its own Bun-based
  // executable, so the plugin's own process.execPath is the opencode binary and
  // spawning it would re-run opencode instead of the guard — silently, since the
  // nonsense run exits non-2 and the shim reads that as an allow. This CLI runs
  // under node, so its execPath is the one to hand over.
  const src = readHook('opencode-plugin.mjs').replace('__SOLONGATE_NODE__', process.execPath.replace(/\\/g, '\\\\'));
  writeProtectedFile(p.opencodePluginPath, src);
}

function removeOpencodeGuard(p: ReturnType<typeof globalPaths>): void {
  try {
    unlockFile(p.opencodePluginPath);
    rmSync(p.opencodePluginPath, { force: true });
  } catch { /* already gone */ }
}

/**
 * Fetch each client's policy into its cache, now, at install time.
 *
 * The guard serves policy stale-while-revalidate: a cold cache has nothing to
 * serve, so it allows and refreshes in the background for the NEXT call. The
 * cache is keyed per agent, which means a newly registered client's FIRST tool
 * call runs with no policy at all. Measured on a fresh `opencode` id: the first
 * call to a command the active policy denies was allowed, and the identical
 * call was blocked once the cache existed.
 *
 * The guard already knows how to do this (`--sg-refresh-policy`), so warming is
 * just running it once per client rather than a second copy of the fetch here.
 * Detached and best-effort: an offline install still succeeds, it simply leaves
 * the first call in the old state.
 */
function warmPolicyCache(hooksDir: string, agents: string[]): void {
  for (const agent of agents) {
    try {
      const child = spawn(process.execPath, [join(hooksDir, 'guard.mjs'), agent, '--sg-refresh-policy'], {
        detached: true,
        stdio: 'ignore',
        windowsHide: true,
      });
      child.on('error', () => {});
      child.unref();
    } catch { /* best-effort */ }
  }
}

export function isOpencodeGuardInstalled(): boolean {
  try {
    return readFileSync(globalPaths().opencodePluginPath, 'utf-8').includes('tool.execute.before');
  } catch {
    return false;
  }
}

/** True when OpenCode looks present on this device, so callers can decide
 *  whether the OpenCode line is worth showing at all. */
export function opencodeDetected(): boolean {
  try { return existsSync(globalPaths().opencodeDir); } catch { return false; }
}

/**
 * Clear the `./.solongate/` scratch folders older versions scattered around.
 *
 * The guard used to keep its per-call flags next to the user's code, so one of
 * these was left in every directory an agent had ever run in — config folders
 * and dotfile repos included. The guard now sweeps the folder it finds in its
 * own working directory, which heals anywhere an agent goes again; somewhere
 * like ~/.config/ags may never be visited twice, so `repair` goes looking.
 *
 * Deliberately narrow: only our own filenames are removed, only a directory
 * that empties as a result is taken, and the walk is bounded in depth and in
 * how many directories it will visit. Anything unexpected inside is left alone
 * and the folder stays.
 */
const SCRATCH_FILES = new Set(['.eval-ring.jsonl', '.last-eval', '.last-deny', '.last-tool-call', '.debug-guard-log']);

// Depth 6 because a monorepo puts real working directories four or five levels
// down (…/repo/apps/web/src), and the budget is high enough that one big repo
// early in the walk cannot use it all up before the rest of home is reached —
// which is exactly what a smaller one did. Only ever runs on an explicit repair.
export function sweepStrayScratchDirs(root = homedir(), maxDepth = 6, budget = 40000): number {
  let removed = 0;
  let visited = 0;
  const skip = new Set(['node_modules', '.git', 'dist', '.next', 'build']);
  // The real store, which must never be a candidate. Excluded by PATH, not by
  // name — excluding the name would skip every folder we came here to remove.
  const store = join(homedir(), '.solongate');
  const walk = (dir: string, depth: number): void => {
    if (depth > maxDepth || visited++ > budget) return;
    let entries: string[];
    try { entries = readdirSync(dir); } catch { return; }
    for (const name of entries) {
      if (skip.has(name)) continue;
      const full = join(dir, name);
      if (full === store) continue;
      let isDir = false;
      try { isDir = statSync(full).isDirectory(); } catch { continue; }
      if (!isDir) continue;
      if (name === '.solongate') {
        try {
          const left: string[] = [];
          for (const f of readdirSync(full)) {
            if (SCRATCH_FILES.has(f)) { try { rmSync(join(full, f), { force: true }); } catch { left.push(f); } }
            else left.push(f);
          }
          if (left.length === 0) { rmdirSync(full); removed++; }
        } catch { /* leave it */ }
        continue;
      }
      walk(full, depth + 1);
    }
  };
  walk(root, 0);
  return removed;
}

export function runGlobalRestore(): void {
  const p = globalPaths();
  // Clear OS locks first so we can rewrite/restore the settings file.
  unlockProtected();
  // Remove the auto-shield `claude` shim from the shell config.
  removeClaudeShim();
  // Strip our guard from Antigravity CLI's and Codex CLI's hooks too.
  removeAntigravityGuard(p);
  try { removeCodexGuard(p); } catch { /* best-effort */ }
  try { removeOpencodeGuard(p); } catch { /* best-effort */ }
  if (existsSync(p.backupPath)) {
    writeFileSync(p.settingsPath, readFileSync(p.backupPath, 'utf-8'));
    console.log(`  Restored ${p.settingsPath} from backup.`);
  } else if (existsSync(p.settingsPath)) {
    try {
      const s = JSON.parse(readFileSync(p.settingsPath, 'utf-8'));
      delete s.hooks;
      writeFileSync(p.settingsPath, JSON.stringify(s, null, 2) + '\n');
      console.log(`  Removed SolonGate hooks from ${p.settingsPath}.`);
    } catch { /* leave as-is */ }
  } else {
    console.log('  Nothing to restore — no global Claude Code settings found.');
  }
  console.log('  Global SolonGate enforcement uninstalled. Restart Claude Code.');
}

/**
 * TUI-safe (re)install — the dataroom's one-key "install / update guard" action.
 * Writes the hook files THIS CLI ships (readGuard = the current package's bundle,
 * so a self-updated dataroom installs the newest hooks DIRECTLY — no waiting for a
 * tool call) and registers them in the global Claude settings, reusing the key
 * already stored in cloud-guard.json. No prompt, no stdout, no process.exit — safe
 * to call from Ink. Returns a status; asks the user to log in when no key exists.
 * The auto-shield shell shim is left to `solongate` login (it can print), so this
 * touches only the guard/audit/stop hooks — the primary protection.
 */
/**
 * `solongate repair` — restore the guard after tampering/deletion. Reports what
 * was missing, then rewrites every protection file (guard/audit/stop/shield hooks
 * + cloud config) and re-registers the hooks in Claude Code and Antigravity, then
 * re-locks. Reuses the logged-in account, so no re-login. Human-only (gated).
 */
export interface RepairLine {
  label: string;
  ok: boolean;
  detail: string;
}
export interface RepairReport {
  ok: boolean;
  message: string;
  before: RepairLine[];
  after: RepairLine[];
  notes: string[];
}

/**
 * The repair itself, with no printing — so the same restore backs both
 * `solongate repair` and the Settings panel in the dataroom. Ink owns the
 * terminal while the TUI is up, so anything it calls must return data instead
 * of writing to the stream (see installGlobalQuiet).
 */
export function repairQuiet(): RepairReport {
  const p = globalPaths();
  const has = (f: string): boolean => existsSync(f);
  const guardFile = join(p.hooksDir, 'guard.mjs');
  const line = (label: string, ok: boolean, yes: string, no: string): RepairLine => ({ label, ok, detail: ok ? yes : no });

  // The runtime row is the one that matters on a Mac. Every other line here
  // reads a config file, and a config file said the guard was registered for
  // the whole time it could not start.
  const runtime = (): RepairLine => {
    const r = hookCanStart();
    return { label: 'hook runtime', ok: r.ok, detail: r.ok ? `node ${r.detail}` : r.detail };
  };

  const before: RepairLine[] = [
    line('guard hook file', has(guardFile), 'present', 'MISSING'),
    line('cloud credential', has(p.configPath), 'present', 'MISSING'),
    runtime(),
    line('Claude hooks', isGuardInstalled(), 'guard registered', 'guard NOT registered'),
    line('Antigravity hooks', has(p.antigravityHooksPath), 'guard registered', 'guard NOT registered'),
    line('Codex hooks', isCodexGuardInstalled(), 'guard registered', 'guard NOT registered'),
    line('OpenCode hooks', isOpencodeGuardInstalled(), 'guard registered', 'guard NOT registered'),
  ];

  const r = installGlobalQuiet();
  if (!r.ok) return { ok: false, message: r.message, before, after: [], notes: [] };

  const after: RepairLine[] = [
    { label: 'guard hook file', ok: true, detail: `present (v${installedGuardVersion() ?? '?'})` },
    runtime(),
    line('Claude hooks', isGuardInstalled(), 'guard registered', 'NOT registered'),
    line('Antigravity hooks', has(p.antigravityHooksPath), 'guard registered', 'NOT registered'),
    line('Codex hooks', isCodexGuardInstalled(), 'guard registered', 'NOT registered'),
    line('OpenCode hooks', isOpencodeGuardInstalled(), 'guard registered', 'NOT registered'),
  ];

  const notes: string[] = [];
  // Older versions kept per-call scratch next to the user's code. The guard
  // clears the one in its own working directory, but a folder no agent visits
  // again would keep it forever — so repair goes and looks.
  try {
    const swept = sweepStrayScratchDirs();
    if (swept > 0) notes.push(`Removed ${swept} leftover .solongate scratch folder(s) from earlier versions; per-call flags now live under ~/.solongate/projects.`);
  } catch { /* best-effort */ }
  const cx = codexHooksStatus();
  if (cx.registered && !cx.trusted) {
    notes.push('Codex only: run `/hooks` inside Codex once and trust the SolonGate hooks (Codex skips any hook it has not been told to trust).');
  }
  if (cx.disabled) {
    notes.push('Codex only: hooks are turned OFF in ~/.codex/config.toml ([features] hooks = false) - the guard cannot run there until that line is removed.');
  }

  return { ok: true, message: 'guard repaired. Open a new AI session for it to take effect.', before, after, notes };
}

export async function runRepair(): Promise<number> {
  const out = (s: string): void => void process.stderr.write(s + '\n');

  // Repair writes the guard hooks into the INVOKING user's home. Under sudo
  // that is root's home, so it would report success while the user's agents
  // stayed exactly as broken as before. This is easy to hit by momentum, since
  // the fix for a root-owned npm folder is `sudo npm i -g ...` followed by this
  // command — which must NOT be sudo.
  if (process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() === 0 && process.env['SOLONGATE_INTERNAL'] !== '1') {
    out('');
    out('  Do not run `solongate repair` with sudo.');
    out('  It installs the guard into your home directory, and as root it would');
    out(`  arm root’s home instead${process.env['SUDO_USER'] ? ` of ${process.env['SUDO_USER']}’s` : ''} — reporting success while nothing changed for you.`);
    out('');
    out('  Run it as yourself:  solongate repair');
    out('');
    return 1;
  }

  const rep = repairQuiet();

  out('');
  out('  SolonGate repair');
  out('');
  out('  before:');
  for (const l of rep.before) out(`    ${l.label.padEnd(20)} ${l.detail}`);
  out('');

  if (!rep.ok) {
    out(`  ✗ ${rep.message}`);
    return 1;
  }
  out('  restored:');
  for (const l of rep.after) out(`    ${l.label.padEnd(20)} ${l.detail}`);
  out('');
  for (const n of rep.notes) {
    out(`  ${n}`);
    out('');
  }
  out(`  ✓ ${rep.message}`);
  out('');
  return 0;
}

export function installGlobalQuiet(): { ok: boolean; message: string } {
  try {
    const p = globalPaths();
    let apiKey = process.env['SOLONGATE_API_KEY'] || '';
    let apiUrl = process.env['SOLONGATE_API_URL'] || 'http://127.0.0.1:3002';
    try {
      const cfg = JSON.parse(readFileSync(p.configPath, 'utf-8')) as { apiKey?: string; apiUrl?: string };
      if (cfg && typeof cfg.apiKey === 'string') apiKey = apiKey || cfg.apiKey;
      if (cfg && typeof cfg.apiUrl === 'string') apiUrl = cfg.apiUrl;
    } catch { /* no stored credential */ }
    // cloud-guard.json empty but an account is logged in? Activate that account.
    if (!apiKey) {
      const acc = firstAccountCredential();
      if (acc.apiKey) { apiKey = acc.apiKey; if (acc.apiUrl) apiUrl = acc.apiUrl; }
    }
    if (!apiKey) return { ok: false, message: 'no login on this device — add an account first (Accounts → + add)' };

    mkdirSync(p.hooksDir, { recursive: true });
    mkdirSync(p.claudeDir, { recursive: true });
    unlockProtected(); // clear any prior OS lock so this (re)install can overwrite

    writeFileSync(join(p.hooksDir, 'guard.mjs'), readGuard());
    // The fast path, if this platform has one. The hook works without it.
    installGoBinaries(p.binDir);
    writeFileSync(join(p.hooksDir, 'audit.mjs'), readHook('audit.mjs'));
    writeFileSync(join(p.hooksDir, 'stop.mjs'), readHook('stop.mjs'));
    writeFileSync(join(p.hooksDir, 'shield.mjs'), readHook('shield.mjs'));
    writeFileSync(join(p.hooksDir, 'conversation.mjs'), readHook('conversation.mjs'));
  writeLauncher(p.hooksDir);
    writeLauncher(p.hooksDir);
    writeFileSync(p.configPath, JSON.stringify({ apiKey, apiUrl }, null, 2) + '\n');

    let existing: Record<string, unknown> = {};
    if (existsSync(p.settingsPath)) {
      const raw = readFileSync(p.settingsPath, 'utf-8');
      if (!existsSync(p.backupPath)) writeFileSync(p.backupPath, raw); // one-time backup
      try { existing = JSON.parse(raw) as Record<string, unknown>; } catch { existing = {}; }
    }
    const hookCmd = (script: string) => hookCommandFor(p.hooksDir, script);
    const merged = {
      ...existing,
      hooks: {
        PreToolUse: [{ matcher: '', hooks: [{ type: 'command', command: hookCmd('guard.mjs') }] }],
        PostToolUse: [{ matcher: '', hooks: [{ type: 'command', command: hookCmd('audit.mjs') }] }],
        // The two halves of a turn, for a machine in a fleet.
        //
        // UserPromptSubmit carries what the person typed. Stop carries
        // last_assistant_message, which is the answer to THIS turn — the
        // transcript on disk is flushed asynchronously and lags the live
        // conversation, so reading that file instead would sometimes record the
        // previous answer.
        //
        // Registering them does not start collecting anything: the server drops
        // a turn from an account with no accepted fleet grant. That check is on
        // the server on purpose, because a check on this side would live on the
        // machine of the person it is about.
        UserPromptSubmit: [{ matcher: '', hooks: [{ type: 'command', command: hookCmd('conversation.mjs') }] }],
        Stop: [
          { matcher: '', hooks: [{ type: 'command', command: hookCmd('stop.mjs') }] },
          { matcher: '', hooks: [{ type: 'command', command: hookCmd('conversation.mjs') }] },
        ],
      },
    };
    writeFileSync(p.settingsPath, JSON.stringify(merged, null, 2) + '\n');
    // Register the same guard for Antigravity CLI (PreToolUse) and Codex CLI
    // (PreToolUse + PostToolUse + Stop). Best-effort — a failure on either side
    // must not fail the Claude install.
    try { installAntigravityGuard(p, join(p.hooksDir, 'guard.mjs').replace(/\\/g, '/')); } catch { /* best-effort */ }
    try { installCodexGuard(p, p.hooksDir); } catch { /* best-effort */ }
    try { installOpencodeGuard(p); } catch { /* best-effort */ }
    // Every client that was just registered gets its policy pulled down now, so
    // its first tool call is judged rather than waved through.
    warmPolicyCache(p.hooksDir, ['claude-code', 'codex', 'antigravity', 'opencode']);
    // NOTE: do NOT clear the policy cache here. The guard already re-fetches it
    // every 10s (POLICY_TTL_MS), and even a stale cache keeps `securityCfg` set —
    // whereas DELETING it forces a cold start where the first tool call has NO
    // cached security config yet (the refresh is a detached background spawn), so
    // DLP-block / rate-limit silently don't apply on that one call.
    // Part of self-protection: OS-level lock so a program can't silently rewrite
    // or delete the guard/settings/hook files to disarm the guard. Applied on
    // every install across all three OSes without sudo/admin (dev opt-out:
    // SOLONGATE_NO_OS_LOCK=1). See lockFile for the per-OS mechanism.
    if (process.env['SOLONGATE_NO_OS_LOCK'] !== '1') lockProtected();
    return { ok: true, message: 'guard installed (open a new session)' };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

/** HOOK_VERSION of the guard hook currently installed on THIS device (read from
 *  the file), or null when not installed. The LOCAL truth — independent of the
 *  cloud guard-status (which only knows what the device last REPORTED). */
export function installedGuardVersion(): number | null {
  try {
    const p = globalPaths();
    const s = readFileSync(join(p.hooksDir, 'guard.mjs'), 'utf-8');
    const m = s.match(/HOOK_VERSION\s*=\s*(\d+)/);
    return m ? parseInt(m[1]!, 10) : null;
  } catch {
    return null;
  }
}

/** True when the installed guard hook DIFFERS from the one this CLI ships — i.e.
 *  a newer hook is available locally (the CLI self-updated). Cloud-independent,
 *  so the dataroom can offer/apply an update even when the API is behind. */
export function guardHookOutdated(): boolean {
  try {
    const p = globalPaths();
    return readFileSync(join(p.hooksDir, 'guard.mjs'), 'utf-8') !== readGuard();
  } catch {
    return false;
  }
}

/**
 * Are the SolonGate guard hooks currently installed in the global Claude settings
 * on THIS device? Reflects a local install/remove IMMEDIATELY — unlike the cloud
 * guard-status (which shows the version this device last reported and lingers for
 * ~14 days), so the dataroom can show "removed" the instant you remove it.
 */
/**
 * The command string a client config gets for one hook.
 *
 * POSIX goes through the launcher, which resolves node at run time. See
 * hook-launcher.ts for why an absolute node path recorded at install time is
 * not survivable on a Mac.
 *
 * Windows keeps naming node directly. Its node lives at a fixed location under
 * Program Files rather than in a versioned directory a package manager deletes,
 * there is no /bin/sh to launch from, and the `&` prefix is already required
 * because Claude Code runs hook commands through PowerShell — which reads a
 * line starting with a quoted path as a string literal rather than a command,
 * fails to parse it, and runs nothing.
 *
 * `/bin/sh <script>` rather than executing the launcher directly, so the file
 * never needs its executable bit. npm does not preserve the mode of files
 * outside `bin`, and a launcher that unpacks as 0644 would fail to start on
 * every install.
 */
export function hookCommandFor(hooksDir: string, script: string, client = 'claude-code', label = 'Claude Code'): string {
  const target = join(hooksDir, script).replace(/\\/g, '/');
  if (process.platform === 'win32') {
    return `& "${process.execPath.replace(/\\/g, '/')}" "${target}" ${client} "${label}"`;
  }
  const launcher = join(hooksDir, LAUNCHER_NAME).replace(/\\/g, '/');
  return `/bin/sh "${launcher}" "${target}" ${client} "${label}"`;
}

/**
 * Write the launcher. Called by every install path before the configs that
 * point at it, because a config naming a launcher that is not there is the
 * failure this whole file exists to end.
 */
export function writeLauncher(hooksDir: string): void {
  writeFileSync(join(hooksDir, LAUNCHER_NAME), launcherScript(process.execPath));
  try { chmodSync(join(hooksDir, LAUNCHER_NAME), 0o755); } catch { /* invoked via /bin/sh, so the bit is a nicety */ }
  // The beat directory, so the launcher's first run does not have to create it.
  try { mkdirSync(join(hooksDir, '..', BEAT_DIR), { recursive: true }); } catch { /* the launcher makes it if this fails */ }
}

export function isGuardInstalled(): boolean {
  try {
    const p = globalPaths();
    if (!existsSync(p.settingsPath)) return false;
    const s = JSON.parse(readFileSync(p.settingsPath, 'utf-8')) as { hooks?: unknown };
    return !!s.hooks && JSON.stringify(s.hooks).includes('.solongate');
  } catch {
    return false;
  }
}

/**
 * TUI-safe uninstall (dataroom Settings → guard → remove). Same effect as
 * runGlobalRestore but returns a status string instead of writing to stdout —
 * any console output would corrupt the Ink render. Unlocks the protected files,
 * removes the auto-shield shell shim, then strips the SolonGate hooks from the
 * global Claude settings (restoring the pre-install backup when present).
 */
export function uninstallGlobalQuiet(): { ok: boolean; message: string } {
  try {
    const p = globalPaths();
    unlockProtected();
    removeClaudeShim();
    // Strip our guard from Antigravity CLI's and Codex CLI's hooks too
    // (best-effort — a failure there must not stop the Claude-side removal).
    try { removeAntigravityGuard(p); } catch { /* best-effort */ }
    try { removeCodexGuard(p); } catch { /* best-effort */ }
    try { removeOpencodeGuard(p); } catch { /* best-effort */ }
    if (!existsSync(p.settingsPath)) return { ok: true, message: 'guard removed (open a new session)' };
    const s = JSON.parse(readFileSync(p.settingsPath, 'utf-8')) as Record<string, unknown>;
    // ALWAYS strip the hooks from the CURRENT settings. (Restoring the backup
    // could re-add them: a backup taken while the guard was present would make it
    // look "removed" while it still ran — the exact bug the row was showing.)
    delete s.hooks;
    writeFileSync(p.settingsPath, JSON.stringify(s, null, 2) + '\n');
    return { ok: true, message: 'guard removed (open a new session)' };
  } catch (e) {
    return { ok: false, message: e instanceof Error ? e.message : String(e) };
  }
}

// ── Auto-shield `claude` shim ────────────────────────────────────────────────
// Makes secret redaction on the LLM path automatic for every TERMINAL Claude
// session: a marked block in the shell config redefines `claude` to run through
// the shield (which masks secrets before they reach the model). No daemon; the
// proxy lives only for each wrapped session. Restore strips the block cleanly.
const SHIM_BEGIN = '# >>> SolonGate shield (auto secret redaction) >>>';
const SHIM_END = '# <<< SolonGate shield <<<';
function escapeRe(s: string): string { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function resolveRealClaude(): string | null {
  try {
    const finder = process.platform === 'win32' ? 'where' : 'which';
    const out = execFileSync(finder, ['claude'], { encoding: 'utf-8' })
      .split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    if (process.platform === 'win32') {
      // The shield spawns the real claude via cmd.exe, which can only run a
      // .cmd/.exe — NOT the npm-generated `claude.ps1` or extension-less bash
      // shim. `where` lists all of them, so pick the .cmd (then .exe/.bat).
      const low = (s: string) => s.toLowerCase();
      return out.find((l) => low(l).endsWith('.cmd'))
        || out.find((l) => low(l).endsWith('.exe'))
        || out.find((l) => low(l).endsWith('.bat'))
        || out[0] || null;
    }
    return out[0] || null;
  } catch { return null; }
}

// Shell config files to inject the `claude` shim into, per platform.
function shimTargets(): string[] {
  if (process.platform === 'win32') {
    try {
      const prof = execFileSync('powershell', ['-NoProfile', '-Command', '$PROFILE.CurrentUserAllHosts'], { encoding: 'utf-8' }).trim();
      return prof ? [prof] : [];
    } catch { return []; }
  }
  return ['.bashrc', '.zshrc', '.profile'].map((f) => join(homedir(), f)).filter((f) => existsSync(f));
}

function writeShimBlock(file: string, block: string | null): void {
  const re = new RegExp(escapeRe(SHIM_BEGIN) + '[\\s\\S]*?' + escapeRe(SHIM_END) + '\\r?\\n?', 'g');
  let content = existsSync(file) ? readFileSync(file, 'utf-8') : '';
  content = content.replace(re, ''); // remove any prior block (idempotent)
  if (block) {
    if (content.length && !content.endsWith('\n')) content += '\n';
    content += block + '\n';
  }
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, content);
}

export function installClaudeShim(shieldPath: string): void {
  const real = resolveRealClaude();
  if (!real) {
    console.log('  (Claude Code not found on PATH — skipped auto-shield. Install it, then re-open `solongate` → Settings → guard.)');
    return;
  }
  const node = process.execPath.replace(/\\/g, '/');
  const shield = shieldPath.replace(/\\/g, '/');
  const win = process.platform === 'win32';
  const block = win
    ? `${SHIM_BEGIN}\nfunction claude { & "${node}" "${shield}" -- "${real}" @args }\n${SHIM_END}`
    : `${SHIM_BEGIN}\nclaude() { "${node}" "${shield}" -- "${real}" "$@"; }\n${SHIM_END}`;
  // Install silently: the shield is a SECONDARY layer (LLM-path redaction). The
  // main protection is the hook-based guard/policy, so login output shouldn't
  // headline this — just wire the shim and move on.
  const targets = shimTargets();
  if (targets.length === 0) return;
  for (const file of targets) {
    try { writeShimBlock(file, block); } catch { /* best-effort */ }
  }
}

export function removeClaudeShim(): void {
  for (const file of shimTargets()) { try { writeShimBlock(file, null); } catch { /* best-effort */ } }
}

// Installs the global hook. `apiKey` may be omitted, in which case the stored
// credential is used. `apiUrl` defaults to the loopback API (or SOLONGATE_API_URL).
export async function runGlobalInstall(opts: { apiKey?: string; apiUrl?: string } = {}): Promise<void> {
  const p = globalPaths();

  let apiKey = opts.apiKey || process.env['SOLONGATE_API_KEY'] || '';
  // Already logged in? Reuse the stored credential so re-running `init --global`
  // (e.g. to pick up updated hooks) needs no re-login.
  if (!apiKey || apiKey === 'sg_live_your_key_here') {
    try {
      const cfg = JSON.parse(readFileSync(p.configPath, 'utf-8'));
      if (cfg && typeof cfg.apiKey === 'string') apiKey = cfg.apiKey;
    } catch { /* no stored credential */ }
  }
  // Still nothing but an account is logged in (dataroom device login populates
  // accounts.json, not cloud-guard.json)? Reuse it instead of prompting.
  if (!apiKey || apiKey === 'sg_live_your_key_here') {
    const acc = firstAccountCredential();
    if (acc.apiKey) apiKey = acc.apiKey;
  }
  // NOBODY TYPES A CREDENTIAL. It used to prompt for one here, which asked the
  // person to find and paste a string they have no reason to have ever seen: the
  // credential is written by pairing, and every source above is a place pairing
  // already put it. With none of them holding one, the machine is simply not
  // paired, and saying so is the only useful thing to say.
  if (!apiKey || apiKey === 'sg_live_your_key_here') {
    console.log('');
    console.log('  This machine is not paired yet. Run `solongate` and add your');
    console.log('  account from the Accounts panel, then run this again.');
    console.log('');
    process.exit(1);
  }
  if (!apiKey.startsWith('sg_live_') && !apiKey.startsWith('sg_test_')) {
    console.log('  The stored credential is not valid. Pair this machine again with `solongate`.');
    process.exit(1);
  }
  const apiUrl = opts.apiUrl || process.env['SOLONGATE_API_URL'] || 'http://127.0.0.1:3002';

  mkdirSync(p.hooksDir, { recursive: true });
  mkdirSync(p.claudeDir, { recursive: true });

  // Clear any prior OS lock so this (re)install can overwrite the files.
  unlockProtected();

  writeFileSync(join(p.hooksDir, 'guard.mjs'), readGuard());
  writeFileSync(join(p.hooksDir, 'audit.mjs'), readHook('audit.mjs'));
  writeFileSync(join(p.hooksDir, 'stop.mjs'), readHook('stop.mjs'));
  writeFileSync(join(p.hooksDir, 'shield.mjs'), readHook('shield.mjs'));
  writeFileSync(join(p.hooksDir, 'conversation.mjs'), readHook('conversation.mjs'));
  console.log(`  Installed hooks → ${p.hooksDir}`);

  // Auto-shield: wrap every terminal `claude` via a shell-profile shim so the
  // LLM-path redaction runs with NO extra command. The shield masks secrets in the
  // request body — INCLUDING your typed prompt and any file/tool text in context —
  // before it reaches the model, which the PreToolUse/PostToolUse hooks alone can't
  // do (hooks only see tool calls, never the prompt). Hooks still cover tool I/O;
  // the shim adds the prompt/request surface on top.
  installClaudeShim(join(p.hooksDir, 'shield.mjs'));

  writeFileSync(p.configPath, JSON.stringify({ apiKey, apiUrl }, null, 2) + '\n');
  console.log(`  Wrote ${p.configPath}`);

  let existing: Record<string, unknown> = {};
  if (existsSync(p.settingsPath)) {
    const raw = readFileSync(p.settingsPath, 'utf-8');
    if (!existsSync(p.backupPath)) {
      writeFileSync(p.backupPath, raw);
      console.log(`  Backed up existing settings → ${p.backupPath}`);
    }
    try { existing = JSON.parse(raw); } catch { existing = {}; }
  }

  const guardAbs = join(p.hooksDir, 'guard.mjs').replace(/\\/g, '/');
  const hookCmd = (script: string) => hookCommandFor(p.hooksDir, script);
  const merged = {
    ...existing,
    hooks: {
      PreToolUse: [{ matcher: '', hooks: [{ type: 'command', command: hookCmd('guard.mjs') }] }],
      PostToolUse: [{ matcher: '', hooks: [{ type: 'command', command: hookCmd('audit.mjs') }] }],
      UserPromptSubmit: [{ matcher: '', hooks: [{ type: 'command', command: hookCmd('conversation.mjs') }] }],
      Stop: [
        { matcher: '', hooks: [{ type: 'command', command: hookCmd('stop.mjs') }] },
        { matcher: '', hooks: [{ type: 'command', command: hookCmd('conversation.mjs') }] },
      ],
    },
  };
  writeFileSync(p.settingsPath, JSON.stringify(merged, null, 2) + '\n');
  console.log(`  Registered global hooks → ${p.settingsPath}`);

  // Register the same guard for Antigravity CLI (PreToolUse event). Best-effort:
  // an Antigravity-side failure must never abort the Claude install.
  try {
    installAntigravityGuard(p, guardAbs);
    console.log(`  Registered Antigravity CLI guard → ${p.antigravityHooksPath}`);
  } catch { /* best-effort */ }

  // Codex CLI: same guard on PreToolUse, plus the audit/stop hooks (Codex runs
  // PostToolUse and Stop, which Antigravity does not). Best-effort as above.
  try {
    installCodexGuard(p, p.hooksDir);
    console.log(`  Registered Codex CLI hooks → ${p.codexHooksPath}`);
    const cx = codexHooksStatus();
    if (!cx.trusted) {
      console.log('  Codex: run `/hooks` inside Codex once and trust the SolonGate hooks');
      console.log('         (Codex skips any hook it has not been told to trust). Asked once —');
      console.log('         later guard updates keep the same registration, so trust sticks.');
    }
    if (cx.disabled) {
      console.log('  Codex: hooks are disabled in ~/.codex/config.toml ([features] hooks = false)');
      console.log('         — remove that line or the guard cannot run in Codex.');
    }
  } catch { /* best-effort */ }

  // OpenCode: a plugin module rather than a hook registration. Dropping the file
  // in the scanned folder IS the install; nothing else to configure.
  try {
    installOpencodeGuard(p);
    console.log(`  Installed OpenCode plugin → ${p.opencodePluginPath}`);
    console.log('  OpenCode: `opencode --pure` runs without external plugins and');
    console.log('            therefore without the guard. That is its own escape hatch.');
  } catch { /* best-effort */ }

  // Part of self-protection: OS-level lock (all three OSes, no sudo/admin) so a
  // program can't silently rewrite or delete these files to disarm the guard.
  // Dev opt-out: SOLONGATE_NO_OS_LOCK=1.
  if (process.env['SOLONGATE_NO_OS_LOCK'] !== '1') {
    lockProtected();
    console.log('  Locked protection files (OS-level read-only/immutable).');
  }
}

// Convenience for the pairing flow: write config + install in one go, given a
// credential already obtained by device pairing.
export async function installGlobalWithKey(apiKey: string, apiUrl?: string): Promise<void> {
  await runGlobalInstall({ apiKey, apiUrl });
}
