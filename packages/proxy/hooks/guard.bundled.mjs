#!/usr/bin/env node
// AUTO-GENERATED from guard.mjs by scripts/bundle-hooks.mjs — DO NOT EDIT.
// Edit guard.mjs and run `pnpm --filter @solongate/proxy build:hooks` to regenerate.

// hooks/guard.mjs
import { readFileSync, existsSync, statSync, readdirSync, writeFileSync, mkdirSync, chmodSync, renameSync, appendFileSync, rmSync, rmdirSync, openSync, readSync, closeSync, accessSync, constants } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import { resolve, join, dirname, isAbsolute } from "node:path";
import { homedir } from "node:os";
import { createRequire } from "node:module";

// hooks/policy-eval.mjs
function matchGlob(str, pattern) {
  if (pattern === "*")
    return true;
  const s = str.toLowerCase();
  const p = pattern.toLowerCase();
  if (s === p)
    return true;
  const startsW = p.startsWith("*");
  const endsW = p.endsWith("*");
  if (startsW && endsW) {
    const infix = p.slice(1, -1);
    return infix.length > 0 && s.includes(infix);
  }
  if (startsW)
    return s.endsWith(p.slice(1));
  if (endsW)
    return s.startsWith(p.slice(0, -1));
  const idx = p.indexOf("*");
  if (idx !== -1) {
    const pre = p.slice(0, idx);
    const suf = p.slice(idx + 1);
    return s.startsWith(pre) && s.endsWith(suf) && s.length >= pre.length + suf.length;
  }
  return false;
}
function matchPathGlob(path, pattern) {
  const p = path.replace(/\\/g, "/").toLowerCase();
  const g = pattern.replace(/\\/g, "/").toLowerCase();
  if (p === g)
    return true;
  if (g.includes("**")) {
    const parts = g.split("**").filter((s) => s.length > 0);
    if (parts.length === 0)
      return true;
    return parts.every((segment) => p.includes(segment));
  }
  return matchGlob(p, g);
}
function scanStrings(obj) {
  const strings = [];
  function walk(v) {
    if (typeof v === "string" && v.trim())
      strings.push(v.trim());
    else if (Array.isArray(v))
      v.forEach(walk);
    else if (v && typeof v === "object")
      Object.values(v).forEach(walk);
  }
  walk(obj);
  return strings;
}
function looksLikeFilename(s) {
  if (s.startsWith("."))
    return true;
  if (/\.\w+$/.test(s))
    return true;
  const known = ["id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "authorized_keys", "known_hosts", "makefile", "dockerfile"];
  return known.includes(s.toLowerCase());
}
function normalizeShellCommand(cmd) {
  if (typeof cmd !== "string" || !cmd)
    return cmd;
  const vars = {};
  const out = [];
  for (const rawPart of cmd.split(/\s*(?:;|&&|\|\|)\s*/)) {
    let part = rawPart;
    const m = part.match(/^(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))\s*$/);
    if (m) {
      vars[m[1]] = m[2] ?? m[3] ?? m[4] ?? "";
      continue;
    }
    part = part.replace(/\$\{(\w+)\}/g, (_, n) => vars[n] !== void 0 ? vars[n] : "${" + n + "}");
    part = part.replace(/\$(\w+)/g, (_, n) => vars[n] !== void 0 ? vars[n] : "$" + n);
    part = part.replace(/"([^"]*)"/g, "$1").replace(/'([^']*)'/g, "$1");
    out.push(part);
  }
  return out.join("; ");
}
function normalizeArgs(args) {
  if (!args || typeof args !== "object")
    return args;
  const fields = ["command", "cmd", "function", "script", "shell"];
  const copy = { ...args };
  for (const [k, v] of Object.entries(copy)) {
    if (fields.includes(k.toLowerCase()) && typeof v === "string") {
      copy[k] = normalizeShellCommand(v);
    }
  }
  return copy;
}
function extractFilenames(args) {
  args = normalizeArgs(args);
  const names = /* @__PURE__ */ new Set();
  const dequote = (t) => t.replace(/^["'`]+/, "").replace(/["'`]+$/, "");
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s))
      continue;
    const tokens = s.includes(" ") ? s.split(/\s+/) : [s];
    const single = tokens.length === 1;
    for (let tok of tokens) {
      tok = dequote(tok);
      if (!tok || /^https?:\/\//i.test(tok))
        continue;
      if (tok.includes("/") || tok.includes("\\")) {
        const b = dequote(tok.replace(/\\/g, "/").split("/").pop() || "");
        if (b && (single || looksLikeFilename(b)))
          names.add(b);
      } else if (looksLikeFilename(tok)) {
        names.add(tok);
      }
    }
  }
  return [...names];
}
function extractUrls(args) {
  const urls = /* @__PURE__ */ new Set();
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) {
      urls.add(s);
      continue;
    }
    if (s.includes(" ")) {
      for (const tok of s.split(/\s+/)) {
        if (/^https?:\/\//i.test(tok))
          urls.add(tok);
      }
    }
  }
  return [...urls];
}
function extractPipelines(args) {
  args = normalizeArgs(args);
  const out = [];
  const fields = ["command", "cmd", "function", "script", "shell"];
  if (typeof args === "object" && args) {
    for (const [k, v] of Object.entries(args)) {
      if (fields.includes(k.toLowerCase()) && typeof v === "string") {
        for (const part of v.split(/\s*(?:&&|\|\||;)\s*/)) {
          const trimmed = part.trim();
          if (trimmed)
            out.push(trimmed);
        }
      }
    }
  }
  return out;
}
function extractCommands(args) {
  args = normalizeArgs(args);
  const cmds = [];
  const fields = ["command", "cmd", "function", "script", "shell"];
  if (typeof args === "object" && args) {
    for (const [k, v] of Object.entries(args)) {
      if (fields.includes(k.toLowerCase()) && typeof v === "string") {
        for (const part of v.split(/\s*(?:&&|\|\||;|\|)\s*/)) {
          const trimmed = part.trim();
          if (trimmed)
            cmds.push(trimmed);
        }
      }
    }
  }
  return cmds;
}
function extractPaths(args, isExec) {
  const paths = [];
  const add = (t) => {
    if (!t || /^https?:\/\//i.test(t))
      return;
    if (t.includes("/") || t.includes("\\") || t.startsWith("."))
      paths.push(t.replace(/\\/g, "/"));
  };
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s))
      continue;
    if (isExec && /\s/.test(s)) {
      for (const tok of s.split(/[\s;|&><()`'"]+/))
        add(tok);
    } else {
      add(s);
    }
  }
  return paths;
}
function guessPermission(toolName) {
  const name = (toolName || "").toLowerCase();
  if (name === "apply_patch" || name === "applypatch")
    return "WRITE";
  if (name.includes("exec") || name.includes("shell") || name.includes("run") || name.includes("eval") || name === "bash")
    return "EXECUTE";
  if (name.includes("fetch") || name.includes("http") || name.includes("request") || name.includes("curl") || name.includes("network") || name.includes("download") || name.includes("upload") || name === "websearch")
    return "NETWORK";
  if (name.includes("write") || name.includes("create") || name.includes("delete") || name.includes("update") || name.includes("set") || name.includes("edit") || name.includes("remove") || name.includes("insert") || name.includes("replace") || name.includes("patch") || name.includes("modify") || name.includes("append") || name.includes("overwrite") || name.includes("rename") || name.includes("move") || name.includes("mkdir") || name.includes("touch"))
    return "WRITE";
  return "READ";
}
function patternsOf(constraint) {
  if (!constraint)
    return null;
  const list = constraint.denied || constraint.allowed;
  return Array.isArray(list) && list.length > 0 ? list : null;
}
function permissionApplies(rule, toolName) {
  if (!rule.permission)
    return true;
  const perms = Array.isArray(rule.permission) ? rule.permission : [rule.permission];
  if (perms.length === 0)
    return true;
  const guessed = guessPermission(toolName);
  return perms.includes(guessed);
}
function ruleMatches(rule, args, isExec) {
  const fnPats = patternsOf(rule.filenameConstraints);
  if (fnPats) {
    const filenames = extractFilenames(args);
    for (const fn of filenames) {
      for (const pat of fnPats) {
        if (matchGlob(fn, pat))
          return { kind: "filename", value: fn, pattern: pat };
      }
    }
  }
  const urlPats = patternsOf(rule.urlConstraints);
  if (urlPats) {
    const urls = extractUrls(args);
    for (const url of urls) {
      for (const pat of urlPats) {
        if (matchGlob(url, pat))
          return { kind: "URL", value: url, pattern: pat };
      }
    }
  }
  const cmdPats = patternsOf(rule.commandConstraints);
  if (cmdPats) {
    const cmds = extractCommands(args);
    for (const cmd of cmds) {
      for (const pat of cmdPats) {
        if (matchGlob(cmd, pat))
          return { kind: "command", value: cmd.slice(0, 60), pattern: pat };
      }
    }
  }
  const pathPats = patternsOf(rule.pathConstraints);
  if (pathPats) {
    const paths = extractPaths(args, isExec);
    for (const p of paths) {
      for (const pat of pathPats) {
        if (matchPathGlob(p, pat))
          return { kind: "path", value: p, pattern: pat };
      }
    }
  }
  return null;
}
function evaluate(policy, args, toolName) {
  if (!policy || !policy.rules)
    return null;
  const enabledRules = policy.rules.filter((r) => r.enabled !== false);
  const mode = policy.mode === "whitelist" ? "whitelist" : "denylist";
  const isExec = /bash|shell|exec|powershell|cmd|run|eval/.test((toolName || "").toLowerCase());
  const denyRules = enabledRules.filter((r) => r.effect === "DENY" && permissionApplies(r, toolName)).sort((a, b) => (a.priority || 100) - (b.priority || 100));
  for (const rule of denyRules) {
    const m = ruleMatches(rule, args, isExec);
    if (m)
      return "Blocked by policy: " + m.kind + ' "' + m.value + '" matches "' + m.pattern + '"';
  }
  if (mode === "whitelist") {
    const allowRules = enabledRules.filter((r) => r.effect === "ALLOW" && permissionApplies(r, toolName));
    if (allowRules.length === 0) {
      return "Blocked by policy: strict whitelist mode is on and no ALLOW rule applies to " + (toolName || "this tool");
    }
    let matched = false;
    for (const rule of allowRules) {
      if (ruleMatches(rule, args, isExec)) {
        matched = true;
        break;
      }
    }
    if (!matched) {
      return "Blocked by policy: strict whitelist mode \u2014 request does not match any ALLOW rule";
    }
  }
  return null;
}

// hooks/guard.mjs
import { createHash } from "node:crypto";
function projectKey(dir) {
  let h = 2166136261;
  const s = String(dir || "");
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return h.toString(16);
}
function projectFlagDir() {
  return join(resolve(homedir(), ".solongate"), "projects", projectKey(resolve(process.cwd())));
}
var _legacySwept = false;
function sweepLegacyFlagDir() {
  if (_legacySwept)
    return;
  _legacySwept = true;
  try {
    const dir = resolve(process.cwd(), ".solongate");
    if (!existsSync(dir))
      return;
    const ours = /* @__PURE__ */ new Set([".eval-ring.jsonl", ".last-eval", ".last-deny", ".last-tool-call", ".debug-guard-log"]);
    const left = [];
    for (const f of readdirSync(dir)) {
      if (ours.has(f)) {
        try {
          rmSync(join(dir, f), { force: true });
        } catch {
          left.push(f);
        }
      } else
        left.push(f);
    }
    if (left.length === 0) {
      try {
        rmdirSync(dir);
      } catch {
      }
    }
  } catch {
  }
}
var HOOK_VERSION = 99;
var SG_DIR_MODE = 448;
var SG_FILE_MODE = 384;
var SG_STDIN = (() => {
  try {
    return readFileSync(0, "utf-8");
  } catch {
    return "";
  }
})();
var SG_ORIGIN_MS = (() => {
  try {
    return Math.round(performance.timeOrigin);
  } catch {
    return Date.now();
  }
})();
function sgGuardCandidates() {
  const out = [];
  if (process.env.SOLONGATE_GUARD_BIN)
    out.push(process.env.SOLONGATE_GUARD_BIN);
  const exe = process.platform === "win32" ? "solongate-guard.exe" : "solongate-guard";
  const os_ = process.platform === "win32" ? "win32" : process.platform;
  const cpu = process.arch === "x64" ? "x64" : process.arch;
  try {
    const req = createRequire(import.meta.url);
    out.push(join(dirname(req.resolve(`@solongate/guard-${os_}-${cpu}/package.json`)), exe));
  } catch {
  }
  out.push(resolve(homedir(), ".solongate", "bin", exe));
  return out;
}
function sgTryGoGuard() {
  for (const bin of sgGuardCandidates()) {
    try {
      if (!existsSync(bin))
        continue;
      if (process.platform !== "win32")
        accessSync(bin, constants.X_OK);
    } catch {
      continue;
    }
    let version;
    try {
      const v = spawnSync(bin, ["--sg-version"], { encoding: "utf-8", timeout: 2e3 });
      if (v.error || v.status !== 0)
        continue;
      version = String(v.stdout || "").trim();
    } catch {
      continue;
    }
    if (version !== String(HOOK_VERSION))
      continue;
    let r;
    try {
      r = spawnSync(bin, process.argv.slice(2), {
        input: SG_STDIN,
        encoding: "utf-8",
        // The binary writes the eval record the audit hook reads back, so it is
        // the one reporting this call's guard time — and from inside a process
        // that was spawned partway through the work, it can only see its own
        // share of it. Node's boot, this file's parse, the fd 0 read and the
        // version probe above are all already spent by the time it starts.
        // Handing it the origin is what lets the number it reports be the whole
        // hook instead of the last two milliseconds of it.
        env: { ...process.env, SOLONGATE_HOOK_ORIGIN_MS: String(SG_ORIGIN_MS) },
        // Well past every network call the guard makes. A binary still running
        // at this point is not going to produce an answer worth waiting for.
        timeout: 1e4
      });
    } catch {
      return;
    }
    if (!r || r.error || r.signal)
      return;
    const status = r.status;
    const stdout = r.stdout || "";
    if (status !== 0 && status !== 2)
      return;
    if (status === 2 && stdout.trim() === "")
      return;
    try {
      if (stdout)
        process.stdout.write(stdout);
      if (r.stderr)
        process.stderr.write(r.stderr);
    } catch {
      return;
    }
    process.exit(status);
  }
}
if (process.env.SOLONGATE_NO_GO_GUARD !== "1") {
  try {
    sgTryGoGuard();
  } catch {
  }
}
function loadLocalPolicyFile(cwd) {
  for (const p of [
    join(resolve(homedir(), ".solongate"), "policy.json"),
    cwd ? resolve(cwd, "policy.json") : ""
  ]) {
    if (!p || !existsSync(p))
      continue;
    try {
      const obj = JSON.parse(readFileSync(p, "utf-8"));
      if (!obj || typeof obj !== "object")
        continue;
      const own = !cwd || p !== resolve(cwd, "policy.json");
      const inner = own && obj.policy && typeof obj.policy === "object" ? obj.policy.security : void 0;
      if (obj.policy && typeof obj.policy === "object") {
        return {
          policy: obj.policy,
          security: own && obj.security !== void 0 ? obj.security : inner,
          selfProtect: own && typeof obj.selfProtect === "boolean" ? obj.selfProtect : void 0,
          path: p
        };
      }
      return {
        policy: obj,
        security: own && obj.security !== void 0 ? obj.security : void 0,
        selfProtect: void 0,
        path: p
      };
    } catch {
    }
  }
  return null;
}
function writeLocalLog(security, entry) {
  try {
    const l = security && security.localLogs;
    if (!l || typeof l.path !== "string" || !l.path.trim()) {
      const fallbackDir = resolve(homedir(), ".solongate", "local-logs");
      const fallbackLine = JSON.stringify(entry) + "\n";
      const fallbackPayload = Buffer.from(JSON.stringify({ dir: fallbackDir, line: fallbackLine }), "utf-8").toString("base64");
      spawn(process.execPath, [process.argv[1], "--sg-log-write", fallbackPayload], { detached: true, stdio: "ignore" }).unref();
      return;
    }
    let dir = String(l.path).trim().replace(/[\\/]+$/, "");
    if (!dir)
      return;
    if (!isAbsolute(dir))
      dir = resolve(homedir(), ".solongate", "local-logs");
    const line = JSON.stringify(entry) + "\n";
    const payload = Buffer.from(JSON.stringify({ dir, line }), "utf-8").toString("base64");
    spawn(process.execPath, [process.argv[1], "--sg-log-write", payload], { detached: true, stdio: "ignore" }).unref();
  } catch {
  }
}
var MAX_FILE_READ = 1024 * 1024;
var AGENT_TYPE = process.argv[2] || "claude-code";
var POLICY_SELECTOR = process.env.SOLONGATE_AGENT_ID || "";
var AGENT_ID = POLICY_SELECTOR || AGENT_TYPE;
var AGENT_NAME = process.env.SOLONGATE_AGENT_NAME || process.argv[3] || AGENT_TYPE;
{
  const _wi = process.argv.indexOf("--sg-log-write");
  if (_wi !== -1) {
    try {
      const _pl = JSON.parse(Buffer.from(process.argv[_wi + 1] || "", "base64").toString("utf-8"));
      if (_pl && _pl.dir && _pl.line) {
        let _dir = _pl.dir;
        const _narrow = (f) => {
          try {
            chmodSync(f, SG_FILE_MODE);
          } catch {
          }
        };
        try {
          mkdirSync(_dir, { recursive: true, mode: SG_DIR_MODE });
          const _f = join(_dir, "solongate-audit.jsonl");
          appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
          _narrow(_f);
        } catch {
          const _fb = join(resolve(homedir(), ".solongate"), "local-logs");
          try {
            mkdirSync(_fb, { recursive: true, mode: SG_DIR_MODE });
          } catch {
          }
          try {
            const _f = join(_fb, "solongate-audit.jsonl");
            appendFileSync(_f, _pl.line, { mode: SG_FILE_MODE });
            _narrow(_f);
          } catch {
          }
          try {
            writeFileSync(
              join(resolve(homedir(), ".solongate"), ".local-logs-invalid-path"),
              JSON.stringify({ configured: _dir, fallback: _fb, ts: Date.now() })
            );
          } catch {
          }
        }
      }
    } catch {
    }
    process.exit(0);
  }
}
var SG_DONE = Symbol("sg-done");
var _sgDone = false;
var _decisionEmitted = false;
function sgFinish(code) {
  if (!_sgDone) {
    _sgDone = true;
    process.exitCode = code;
  }
  throw SG_DONE;
}
var ARG_ALIASES = {
  commandline: "command",
  cmd: "command",
  absolutepath: "file_path",
  targetfile: "file_path",
  filepath: "file_path",
  target_file: "file_path",
  notebook_path: "file_path"
};
function neutralizeArgs(a, drop = []) {
  const out = {};
  for (const [k, v] of Object.entries(a && typeof a === "object" ? a : {})) {
    const lk = k.toLowerCase();
    if (drop.includes(lk))
      continue;
    const nk = ARG_ALIASES[lk] || k;
    if (out[nk] === void 0)
      out[nk] = v;
  }
  return out;
}
function parseFlatPayload(raw) {
  const args = neutralizeArgs(raw.tool_input || raw.toolInput || raw.params || {});
  return {
    tool: raw.tool_name || raw.toolName || "",
    args,
    command: typeof args?.command === "string" ? args.command : null,
    cwd: raw.cwd || "",
    sessionId: raw.session_id || raw.sessionId || raw.conversation_id || "",
    response: raw.tool_response || raw.toolResponse || {}
  };
}
function emitHookSpecific(d) {
  if (d.type === "deny") {
    const msg = d.reason || "[SolonGate] Blocked by policy";
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: msg
      }
    }));
    process.stderr.write(msg + "\n");
    return 2;
  }
  if (d.type === "rewrite") {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "allow", updatedInput: d.patch }
    }));
    return 0;
  }
  return 0;
}
var CLIENTS = {
  "claude-code": {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    redactsOutput: true
    // audit.mjs rewrites the tool result at PostToolUse
  },
  // Codex CLI: same decision dialect as Claude Code, different INPUT problem.
  // Every file edit arrives as one apply_patch call whose target paths live
  // inside the patch text, so parse lifts them onto the neutral `paths` field
  // (see liftFreeformPatchPaths, applied to every client for safety).
  codex: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    redactsOutput: false
    // has a post-tool stage, but it rejects output rewrites
  },
  // OpenCode: no subprocess hook contract at all — a plugin runs in-process and
  // refuses a call by throwing. The shim that does the throwing (see
  // hooks/opencode-plugin.mjs) spawns this guard with a flat Claude-shaped
  // payload and reads the Claude dialect back, so both halves are reused as-is
  // and only the identity differs.
  opencode: {
    parse: parseFlatPayload,
    emit: emitHookSpecific,
    // tool.execute.after does hand the plugin the tool's result, but whether
    // writing to it changes what the model sees is untested. Claiming the
    // capability we have not proven would let a secret through masked-in-name-
    // only; false makes any masking we cannot apply a block instead.
    redactsOutput: false
  },
  // Antigravity CLI: nested payload, and a decision dialect of its own.
  antigravity: {
    redactsOutput: false,
    // no post-tool stage at all (its output is ignored)
    parse(raw) {
      const tc = raw.toolCall && typeof raw.toolCall === "object" ? raw.toolCall : {};
      const a = tc.args && typeof tc.args === "object" ? tc.args : {};
      const args = neutralizeArgs(a, ["cwd"]);
      let cwd = raw.cwd || "";
      if (!cwd) {
        if (typeof a.Cwd === "string" && a.Cwd)
          cwd = a.Cwd;
        else if (Array.isArray(raw.workspacePaths) && typeof raw.workspacePaths[0] === "string")
          cwd = raw.workspacePaths[0];
      }
      return {
        tool: raw.tool_name || tc.name || "",
        args,
        command: typeof args.command === "string" ? args.command : null,
        cwd,
        sessionId: raw.session_id || raw.conversationId || "",
        response: raw.tool_response || raw.toolResponse || {}
      };
    },
    emit(d) {
      if (d.type === "deny") {
        const msg = `[SolonGate] ${d.reason}`;
        process.stdout.write(JSON.stringify({ decision: "deny", reason: msg, allow_tool: false, deny_reason: msg }));
        return 0;
      }
      if (d.type === "rewrite") {
        const overwrite = {};
        if (d.patch && typeof d.patch.command === "string")
          overwrite.CommandLine = d.patch.command;
        else
          Object.assign(overwrite, d.patch || {});
        process.stdout.write(JSON.stringify({ decision: "allow", overwrite, allow_tool: true }));
        return 0;
      }
      process.stdout.write(JSON.stringify({ decision: "allow", allow_tool: true }));
      return 0;
    }
  },
  // Unknown client: never silently adopt another client's rules. Parse by
  // payload SHAPE and deny with the most widely enforced signal available
  // (JSON + exit 2). A client that needs anything else gets its own entry.
  generic: {
    redactsOutput: false,
    // assume the weaker capability, so masking fails closed
    parse(raw) {
      return raw.toolCall && typeof raw.toolCall === "object" ? CLIENTS.antigravity.parse(raw) : parseFlatPayload(raw);
    },
    emit: emitHookSpecific
  }
};
var CLIENT = CLIENTS[AGENT_TYPE] || CLIENTS.generic;
function emitDecision(d) {
  if (!_decisionEmitted) {
    _decisionEmitted = true;
    const code = CLIENT.emit(d);
    sgFinish(code);
  }
  sgFinish(0);
}
function blockTool(reason) {
  emitDecision({ type: "deny", reason });
}
function allowTool() {
  emitDecision({ type: "allow" });
}
function rewriteTool(patch) {
  emitDecision({ type: "rewrite", patch });
}
var CALL_ID = "";
var CALL_FP = "";
function callFingerprint(s) {
  let h = 2166136261;
  const str = String(s || "");
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = h + ((h << 1) + (h << 4) + (h << 7) + (h << 8) + (h << 24)) >>> 0;
  }
  return h.toString(16);
}
function writeDenyFlag(toolName) {
  try {
    const flagDir = projectFlagDir();
    mkdirSync(flagDir, { recursive: true });
    writeFileSync(join(flagDir, ".last-deny"), JSON.stringify({
      tool: toolName,
      ts: Date.now(),
      id: CALL_ID,
      fp: CALL_FP
    }));
  } catch {
  }
}
var TAMPER_GUARD_TOOLS_EXEC = /* @__PURE__ */ new Set([
  "bash",
  "powershell",
  "shell",
  "exec",
  "run",
  "eval",
  "cmd"
]);
var TAMPER_HOME = resolve(homedir()).replace(/\\/g, "/").toLowerCase();
var TAMPER_SG = "/.solongate";
var TAMPER_CC = "/.claude";
var TAMPER_CX = "/.codex";
var TAMPER_AGY = "/.gemini/config";
var TAMPER_PROTECTED_ABS = [
  TAMPER_HOME + TAMPER_CC + "/settings.json",
  TAMPER_HOME + TAMPER_CC + "/settings.local.json",
  TAMPER_HOME + TAMPER_CX + "/hooks.json",
  TAMPER_HOME + TAMPER_CX + "/config.toml",
  TAMPER_HOME + TAMPER_AGY + "/hooks.json",
  TAMPER_HOME + TAMPER_SG + "/hooks",
  TAMPER_HOME + TAMPER_SG + "/policy.json",
  TAMPER_HOME + TAMPER_SG + "/.policy-cache.json",
  // The cloud credential (contains the API key) — never readable via a tool.
  TAMPER_HOME + TAMPER_SG + "/cloud-guard.json"
];
var TAMPER_INSTALL = "/solongate";
var TAMPER_PROTECTED_GLOBS = [
  "**" + TAMPER_CC + "/settings.json",
  "**" + TAMPER_CC + "/settings.local.json",
  "**" + TAMPER_CX + "/hooks.json",
  "**" + TAMPER_CX + "/config.toml",
  "**" + TAMPER_AGY + "/hooks.json",
  "**" + TAMPER_SG + "/hooks/**",
  "**" + TAMPER_SG + "/policy.json",
  "**" + TAMPER_SG + "/.policy-cache.json",
  "**" + TAMPER_SG + "/.policy-cache-*.json",
  "**" + TAMPER_SG + "/.pi-config-cache.json",
  "**" + TAMPER_SG + "/cloud-guard.json",
  "**" + TAMPER_SG + "/.opa-wasm-*.json",
  "**" + TAMPER_SG + "/.ratelimit-*.json",
  // Persistent host data (DB + audit JSONL) at ~/.solongate/data
  "**" + TAMPER_SG + "/data/**",
  // Customer install layout (zip extracted as solongate/)
  "**" + TAMPER_INSTALL + "/compose/**",
  "**" + TAMPER_INSTALL + "/data/**",
  "**" + TAMPER_INSTALL + "/images/**",
  "**" + TAMPER_INSTALL + "/helm/**",
  "**" + TAMPER_INSTALL + "/solongate.exe",
  "**" + TAMPER_INSTALL + "/setup.sh"
];
var TAMPER_BASENAMES = [
  "guard.mjs",
  "audit.mjs",
  "stop.mjs",
  "shield.mjs",
  "policy.json",
  // Prefixes (substring match) so per-agent runtime state can't be deleted or
  // rewritten via a shell command either — `.policy-cache-<agent>.json`,
  // `.ratelimit-<agent>.json`, `.opa-wasm-<agent>.json`. Editing these could
  // otherwise flip enforcement off until the next cloud refresh; deleting just
  // forces a refetch, but neither should be reachable from an agent tool call.
  ".policy-cache",
  ".ratelimit-",
  ".opa-wasm-",
  ".pi-config-cache",
  "cloud-guard.json",
  // Customer install: DB and wizard exe
  "solongate.db",
  "solongate.exe"
];
var TAMPER_PATH_FIELDS = /* @__PURE__ */ new Set([
  "file_path",
  "path",
  "target_file",
  "notebook_path",
  "dest",
  "destination",
  "source",
  "src",
  "from",
  "to",
  "directory",
  "dir",
  "folder",
  // Antigravity CLI file-tool arg names (camelCase, lowercased here): its
  // write/read/list tools carry the path in these, so tamper protection sees it.
  "targetfile",
  "absolutepath",
  "filepath"
]);
function normTamperPath(p) {
  return String(p || "").replace(/\\/g, "/").toLowerCase();
}
function isProtectedPath(p) {
  if (!p)
    return false;
  const np = normTamperPath(p);
  for (const abs of TAMPER_PROTECTED_ABS) {
    if (np === abs || np.startsWith(abs + "/"))
      return abs;
  }
  for (const g of TAMPER_PROTECTED_GLOBS) {
    if (matchPathGlob(np, g))
      return g;
  }
  if (/\/\.claude\/settings(\.local)?\.json$/.test(np))
    return "settings.json";
  if (/\/\.solongate\/hooks(\/|$)/.test(np))
    return "solongate-hooks";
  if (/\/\.codex\/(hooks\.json|config\.toml)$/.test(np))
    return "codex-hooks";
  if (/\/\.gemini\/config\/hooks\.json$/.test(np))
    return "antigravity-hooks";
  if (/(^|\/)\.solongate\//.test(np)) {
    const base = np.slice(np.lastIndexOf("/") + 1);
    for (const b of TAMPER_BASENAMES) {
      if (base.startsWith(b.toLowerCase()))
        return b;
    }
  }
  return false;
}
function commandTargetsProtected(cmd) {
  const c = String(cmd || "").toLowerCase();
  if (!c)
    return false;
  for (const b of TAMPER_BASENAMES) {
    if (c.includes(b.toLowerCase()))
      return b;
  }
  if (/\.claude[\\/]+settings(\.local)?\.json/.test(c))
    return "settings.json";
  if (/\.solongate[\\/]+hooks/.test(c))
    return "solongate-hooks";
  if (/\.codex[\\/]+(hooks\.json|config\.toml)/.test(c))
    return "codex-hooks";
  if (/\.gemini[\\/]+config[\\/]+hooks\.json/.test(c))
    return "antigravity-hooks";
  if (/[\\/]solongate[\\/]+(compose|data|images|helm)[\\/]/.test(c))
    return "solongate-install";
  const mutating = /\b(post|put|delete|patch)\b/.test(c) || /(-x|--request|-method)\s+(post|put|delete|patch)\b/.test(c);
  if (mutating && /api\/v1\/(policies|audit-logs)/.test(c))
    return "api-policies-mutation";
  return false;
}
function extractTargetPaths(args) {
  const out = [];
  if (typeof args !== "object" || !args)
    return out;
  for (const [k, v] of Object.entries(args)) {
    const lk = k.toLowerCase();
    if (TAMPER_PATH_FIELDS.has(lk) && typeof v === "string")
      out.push(v);
    if (Array.isArray(v)) {
      for (const item of v) {
        if (item && typeof item === "object") {
          for (const [k2, v2] of Object.entries(item)) {
            if (TAMPER_PATH_FIELDS.has(k2.toLowerCase()) && typeof v2 === "string")
              out.push(v2);
          }
        }
      }
    }
  }
  return out;
}
function tamperCheck(toolName, args) {
  const tn = String(toolName || "").toLowerCase();
  const isExec = TAMPER_GUARD_TOOLS_EXEC.has(tn) || /bash|shell|exec|powershell|cmd|run|eval/.test(tn);
  for (const p of extractTargetPaths(args)) {
    const hit = isProtectedPath(p);
    if (hit)
      return 'Tamper protection: access to "' + p + '" is blocked (protected: ' + hit + ")";
  }
  if (isExec) {
    for (const cmd of extractCommands(args)) {
      const hit = commandTargetsProtected(cmd);
      if (hit)
        return 'Tamper protection: command references protected resource "' + hit + '" \u2014 blocked';
    }
  }
  return null;
}
var DLP_PATTERNS = [
  { name: "AWS access key", re: /AKIA[0-9A-Z]{16}/ },
  { name: "Private key block", re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----|-----BEGIN [A-Z ]*PRIVATE KEY-----/ },
  { name: "Anthropic key", re: /sk-ant-[A-Za-z0-9_-]{20,}/ },
  { name: "OpenAI key", re: /sk-(proj-)?[A-Za-z0-9_-]{20,}/ },
  { name: "GitHub token", re: /gh[pousr]_[A-Za-z0-9]{20,}/ },
  { name: "GitHub fine-grained PAT", re: /github_pat_[A-Za-z0-9_]{20,}/ },
  { name: "GitLab token", re: /glpat-[A-Za-z0-9_-]{20,}/ },
  { name: "Slack token", re: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { name: "Stripe key", re: /[sr]k_(live|test)_[A-Za-z0-9]{20,}/ },
  { name: "SendGrid key", re: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}/ },
  { name: "Twilio key", re: /SK[0-9a-fA-F]{32}/ },
  { name: "npm token", re: /npm_[A-Za-z0-9]{36}/ },
  { name: "JWT", re: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { name: "Bearer token", re: /bearer\s+[A-Za-z0-9._-]{20,}/i },
  // Kept in step with packages/guard-go/dlp.go, name for name and
  // expression for expression. The two lists had drifted to 14 here
  // against 74 there, and a name this list does not carry silently stops
  // being enforced on every machine that runs the hook rather than the
  // binary — which is every machine by default. dlp-parity.mjs holds them
  // together now.
  { name: "Google API key", re: /AIza[0-9A-Za-z_-]{35}/ },
  { name: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/_+-]{40,}/ },
  { name: "Twilio account SID", re: /AC[0-9a-fA-F]{32}/ },
  { name: "Mailgun key", re: /key-[0-9a-f]{32}/ },
  { name: "Mailchimp key", re: /[0-9a-f]{32}-us[0-9]{1,2}/ },
  { name: "DigitalOcean token", re: /dop_v1_[0-9a-f]{64}/ },
  { name: "Databricks token", re: /dapi[0-9a-f]{32}/ },
  { name: "Shopify token", re: /shp(at|ca|pa|ss)_[0-9a-fA-F]{32}/ },
  { name: "Square token", re: /sq0(atp|csp)-[0-9A-Za-z_-]{22,43}/ },
  { name: "Telegram bot token", re: /[0-9]{8,10}:AA[0-9A-Za-z_-]{33}/ },
  { name: "Postman key", re: /PMAK-[0-9a-f]{24}-[0-9a-f]{34}/ },
  { name: "Doppler token", re: /dp\.(pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,}/ },
  { name: "HashiCorp Vault token", re: /hvs\.[A-Za-z0-9_-]{24,}/ },
  { name: "New Relic key", re: /NRAK-[A-Z0-9]{27}/ },
  { name: "Grafana token", re: /glc_[A-Za-z0-9+\/=_-]{32,}/ },
  { name: "Razorpay key", re: /rzp_(live|test)_[0-9A-Za-z]{14}/ },
  { name: "Linear key", re: /lin_api_[0-9A-Za-z]{40,}/ },
  { name: "Figma token", re: /figd_[0-9A-Za-z_-]{40,}/ },
  { name: "Atlassian token", re: /ATATT3[0-9A-Za-z_=.-]{20,}/ },
  { name: "Google OAuth token", re: /ya29\.[0-9A-Za-z_-]{50,}/ },
  { name: "Google OAuth refresh", re: /1\/\/0[0-9A-Za-z_-]{30,}/ },
  { name: "Alibaba access key", re: /LTAI[0-9A-Za-z]{20}/ },
  { name: "Tencent secret id", re: /AKID[0-9A-Za-z]{13,40}/ },
  { name: "Hugging Face token", re: /hf_[0-9A-Za-z]{34,}/ },
  { name: "Replicate token", re: /r8_[0-9A-Za-z]{37,}/ },
  { name: "Groq key", re: /gsk_[0-9A-Za-z]{48,}/ },
  { name: "OpenRouter key", re: /sk-or-v1-[0-9a-f]{64}/ },
  { name: "Perplexity key", re: /pplx-[0-9A-Za-z]{40,}/ },
  { name: "xAI key", re: /xai-[0-9A-Za-z]{40,}/ },
  { name: "LangSmith key", re: /lsv2_(pt|sk)_[0-9a-f]{32}_[0-9a-f]{10}/ },
  { name: "Stripe webhook secret", re: /whsec_[0-9A-Za-z]{32,}/ },
  { name: "Plaid token", re: /access-(sandbox|development|production)-[0-9a-f-]{36}/ },
  { name: "Braintree token", re: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/ },
  { name: "Discord bot token", re: /[MNO][0-9A-Za-z_-]{23}\.[0-9A-Za-z_-]{6}\.[0-9A-Za-z_-]{27}/ },
  { name: "Discord webhook", re: /https:\/\/discord(app)?\.com\/api\/webhooks\/[0-9]{17,20}\/[0-9A-Za-z_-]{60,}/ },
  { name: "Slack app token", re: /xapp-[0-9]-[0-9A-Za-z]+-[0-9]+-[0-9a-f]+/ },
  { name: "Sentry DSN", re: /https:\/\/[0-9a-f]{32}@[0-9a-z.-]+sentry\.io\/[0-9]+/ },
  { name: "Supabase token", re: /sbp_[0-9a-f]{40}/ },
  { name: "PlanetScale token", re: /pscale_tkn_[0-9A-Za-z._-]{32,}/ },
  { name: "PlanetScale password", re: /pscale_pw_[0-9A-Za-z._-]{32,}/ },
  { name: "Airtable token", re: /pat[0-9A-Za-z]{14}\.[0-9a-f]{64}/ },
  { name: "Cloudinary URL", re: /cloudinary:\/\/[0-9]{12,}:[0-9A-Za-z_-]{20,}@[0-9a-z-]+/ },
  { name: "MongoDB SRV URI", re: /mongodb\+srv:\/\/[^\s:@]+:[^\s:@]+@[0-9a-z.-]+/ },
  { name: "Terraform Cloud token", re: /[0-9A-Za-z]{14}\.atlasv1\.[0-9A-Za-z_-]{60,}/ },
  { name: "PyPI token", re: /pypi-AgEIcHlwaS[0-9A-Za-z_-]{50,}/ },
  { name: "RubyGems key", re: /rubygems_[0-9a-f]{48}/ },
  { name: "NuGet key", re: /oy2[a-z0-9]{43}/ },
  { name: "Docker Hub token", re: /dckr_pat_[0-9A-Za-z_-]{27,}/ },
  { name: "Notion token", re: /ntn_[0-9A-Za-z]{40,}/ },
  { name: "Dropbox token", re: /sl\.[0-9A-Za-z_-]{130,}/ },
  { name: "Sentry auth token", re: /sntrys_[0-9A-Za-z_=+\/-]{40,}/ },
  { name: "Contentful token", re: /CFPAT-[0-9A-Za-z_-]{40,}/ },
  { name: "Typeform token", re: /tfp_[0-9A-Za-z_-]{40,}/ },
  { name: "Pinecone key", re: /pcsk_[0-9A-Za-z_-]{40,}/ },
  { name: "WooCommerce key", re: /c[ks]_[0-9a-f]{40}/ },
  { name: "PostHog key", re: /ph[cs]_[0-9A-Za-z]{40,}/ }
];
var dlpGlobCollapse = /\*{2,}/g;
var DLP_MAX_FILE_BYTES = 1048576;
function dlpGlobToRe(glob) {
  let re = "";
  for (const ch of String(glob || "").replace(dlpGlobCollapse, "*")) {
    if (ch === "*")
      re += "[^\\s]*";
    else if (".+?^${}()|[]\\".indexOf(ch) !== -1)
      re += "\\" + ch;
    else
      re += ch;
  }
  return new RegExp(re, "i");
}
function dlpViews(text) {
  const views = [text];
  try {
    const dequoted = text.replace(/[`'"\\]/g, "");
    if (dequoted !== text)
      views.push(dequoted);
    const src = dequoted !== text ? text + "\n" + dequoted : text;
    const toks = src.match(/[A-Za-z0-9+/]{16,}={0,2}/g) || [];
    let decoded = "";
    for (const t of toks.slice(0, 60)) {
      try {
        const d = Buffer.from(t, "base64").toString("latin1");
        if (/[ -~]{8,}/.test(d))
          decoded += d + "\n";
      } catch {
      }
    }
    if (decoded)
      views.push(decoded);
  } catch {
  }
  return views;
}
function dlpScan(args, cfg) {
  if (!cfg)
    return null;
  let text = "";
  try {
    text = JSON.stringify(args || {});
  } catch {
    return null;
  }
  text = text.replace(/\[REDACTED:[^\]]*\]/g, "");
  const views = dlpViews(text);
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  for (const p of DLP_PATTERNS) {
    if (allow.has(p.name) && views.some((v) => p.re.test(v)))
      return p.name;
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try {
      const re = dlpGlobToRe(c.re);
      if (views.some((v) => re.test(v)))
        return c.name || "custom pattern";
    } catch {
    }
  }
  return null;
}
function egressSecretCheck(args, sec, cwd) {
  try {
    const dlp = sec && sec.dlpBlock;
    if (!dlp)
      return null;
    const base = cwd || process.cwd();
    for (const cmd of extractPipelines(args)) {
      const c = String(cmd || "");
      const lc = c.toLowerCase();
      if (!/\b(curl|wget|scp|rsync|sftp|ftp|nc|netcat)\b/.test(lc))
        continue;
      if (!/https?:\/\//.test(lc) && !/@[\w.-]+:/.test(c) && !/\b\S+:\S/.test(c))
        continue;
      const files = /* @__PURE__ */ new Set();
      let m;
      for (const re of [
        /@([^\s'"|>&]+)/g,
        /(?:-T|--upload-file|--data-binary|--data-raw|--data|-d|-F|--form)[=\s]+@?([^\s'"|>&]+)/g,
        /\bcat\s+([^\s'"|>&]+)/g,
        /<\s*([^\s'"|>&]+)/g
      ]) {
        while (m = re.exec(c)) {
          const f = m[1];
          if (f && f !== "-" && !/^https?:\/\//.test(f) && !/^[@{[]/.test(f))
            files.add(f);
        }
      }
      if (/\b(scp|rsync|sftp)\b/.test(lc)) {
        for (const tok of c.split(/\s+/).slice(1)) {
          if (!tok || tok.startsWith("-"))
            continue;
          if (/^[\w.-]*@?[\w.-]+:/.test(tok))
            continue;
          if (/^https?:\/\//.test(tok))
            continue;
          files.add(tok.replace(/^@/, ""));
        }
      }
      for (let f of files) {
        if (f.startsWith("~"))
          f = homedir() + f.slice(1);
        let abs;
        try {
          abs = isAbsolute(f) ? f : resolve(base, f);
        } catch {
          continue;
        }
        let content = null;
        try {
          const st = statSync(abs);
          if (!st.isFile() || st.size > DLP_MAX_FILE_BYTES)
            continue;
        } catch {
          continue;
        }
        try {
          content = readFileSync(abs, "utf-8");
        } catch {
          continue;
        }
        if (!content)
          continue;
        const hit = dlpScan(content, dlp);
        if (hit)
          return 'DLP: outbound transfer of "' + f + '" is blocked - it contains a ' + hit + " (egress protection)";
      }
    }
  } catch {
  }
  return null;
}
function dlpRedactText(text, cfg) {
  if (!cfg || typeof text !== "string")
    return text;
  let out = text;
  const allow = new Set(Array.isArray(cfg.patterns) ? cfg.patterns : []);
  for (const p of DLP_PATTERNS) {
    if (!allow.has(p.name))
      continue;
    const g = p.re.flags.includes("g") ? p.re.flags : p.re.flags + "g";
    try {
      out = out.replace(new RegExp(p.re.source, g), `[REDACTED:${p.name}]`);
    } catch {
    }
  }
  for (const c of Array.isArray(cfg.custom) ? cfg.custom : []) {
    try {
      const re = dlpGlobToRe(c.re);
      out = out.replace(new RegExp(re.source, re.flags.includes("g") ? re.flags : re.flags + "g"), `[REDACTED:${c.name || "custom"}]`);
    } catch {
    }
  }
  return out;
}
function dlpRedactReadPlan(toolName, args, dlp, cwd) {
  try {
    if (!dlp || !args)
      return null;
    const base = cwd || process.cwd();
    const abends = (f) => {
      let x = f;
      if (x.startsWith("~"))
        x = homedir() + x.slice(1);
      return isAbsolute(x) ? x : resolve(base, x);
    };
    const redactCopy = (abs) => {
      let content;
      try {
        const st = statSync(abs);
        if (!st.isFile() || st.size > DLP_MAX_FILE_BYTES)
          return "SKIP";
        content = readFileSync(abs, "utf-8");
      } catch {
        return "SKIP";
      }
      if (dlpScan(content, dlp) == null)
        return "CLEAN";
      try {
        const dir = join(resolve(homedir(), ".solongate"), ".redacted");
        mkdirSync(dir, { recursive: true });
        const tmp = join(dir, createHash("sha256").update(abs).digest("hex").slice(0, 24) + "-" + (abs.split("/").pop() || "f"));
        writeFileSync(tmp, dlpRedactText(content, dlp));
        return tmp;
      } catch {
        return "FAILED";
      }
    };
    for (const [k, v] of Object.entries(args)) {
      if (k === "command" || typeof v !== "string" || !v || !/[./]/.test(v))
        continue;
      const r = redactCopy(abends(v));
      if (r === "SKIP" || r === "CLEAN")
        continue;
      if (r === "FAILED")
        return { block: true };
      return { rewrite: { [k]: r } };
    }
    const GLOB_META = /[*?\[]/;
    const expandGlob = (absGlob) => {
      try {
        const dir = dirname(absGlob);
        const base2 = absGlob.slice(dir.length + 1);
        if (!GLOB_META.test(base2))
          return [absGlob];
        const re = new RegExp("^" + base2.replace(/\*{2,}/g, "*").replace(/[.+^${}()|\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]") + "$");
        return readdirSync(dir).filter((f) => re.test(f)).map((f) => join(dir, f));
      } catch {
        return [];
      }
    };
    const cmd = typeof args.command === "string" ? args.command : "";
    if (cmd && /\b(cat|less|more|head|tail|bat|nl|od|xxd|hexdump|strings|grep|egrep|fgrep|rg|ag|cut|awk|gawk|sed|tr|sort|uniq|paste|join|comm|column|fold|tac|rev|pr|expand|unexpand|base64|base32|dd|mapfile|readarray)\b/.test(cmd.toLowerCase())) {
      let newCmd = cmd, changed = false;
      for (const tok of cmd.split(/[\s'"|<>;&()]+/)) {
        if (!tok || tok.startsWith("-") || !/[./]/.test(tok))
          continue;
        if (GLOB_META.test(tok)) {
          for (const f of expandGlob(abends(tok))) {
            const rg = redactCopy(f);
            if (rg !== "SKIP" && rg !== "CLEAN")
              return { block: true };
          }
          continue;
        }
        const r = redactCopy(abends(tok));
        if (r === "SKIP" || r === "CLEAN")
          continue;
        if (r === "FAILED")
          return { block: true };
        newCmd = newCmd.split(tok).join(r);
        changed = true;
      }
      if (changed)
        return { rewrite: { command: newCmd } };
    }
  } catch {
    return { block: true };
  }
  return null;
}
var RL_WINDOWS = [
  { key: "perDay", ms: 864e5, label: "day" },
  { key: "perHour", ms: 36e5, label: "hour" },
  { key: "perMinute", ms: 6e4, label: "minute" }
];
var RL_REC = 14;
var RL_MAX_READ = 1048576;
var RL_MAX_FILE = 4194304;
function rateLimitCheck(agentKey, limits) {
  try {
    const dir = resolve(homedir(), ".solongate");
    const file = join(dir, ".ratelimit-" + agentKey + ".log");
    const now = Date.now();
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
    }
    try {
      appendFileSync(file, String(now).padStart(13, "0") + "\n");
    } catch {
      return null;
    }
    let size = 0;
    try {
      size = statSync(file).size;
    } catch {
      return null;
    }
    const start = Math.max(0, size - RL_MAX_READ);
    const from = start - start % RL_REC;
    let buf = "";
    try {
      const fd = openSync(file, "r");
      const b = Buffer.alloc(size - from);
      readSync(fd, b, 0, b.length, from);
      closeSync(fd);
      buf = b.toString("latin1");
    } catch {
      return null;
    }
    const stamps = [];
    for (let i = 0; i + RL_REC <= buf.length; i += RL_REC) {
      const t = parseInt(buf.slice(i, i + 13), 10);
      if (Number.isFinite(t) && now - t < 864e5)
        stamps.push(t);
    }
    for (const w of RL_WINDOWS) {
      const limit = limits[w.key];
      if (limit > 0) {
        const count = stamps.reduce((n, t) => now - t < w.ms ? n + 1 : n, 0);
        if (count > limit)
          return { window: w.label, limit };
      }
    }
    if (size > RL_MAX_FILE) {
      try {
        const tmp = file + "." + process.pid + ".tmp";
        writeFileSync(tmp, stamps.map((t) => String(t).padStart(13, "0") + "\n").join(""));
        renameSync(tmp, file);
      } catch {
      }
    }
    return null;
  } catch {
    return null;
  }
}
function securityLayerCheck(toolName, args, cfg, agentKey) {
  if (!cfg)
    return null;
  try {
    if (cfg.dlpBlock) {
      const hit = dlpScan(args, cfg.dlpBlock);
      if (hit)
        return "Security layer (DLP): blocked - arguments contain a " + hit + ". Blocked by SolonGate - check your dashboard for details.";
    }
    if (cfg.rateLimit) {
      const hit = rateLimitCheck(agentKey, cfg.rateLimit);
      if (hit) {
        return "Security layer (rate limit): exceeded " + hit.limit + " calls/" + hit.window + " for this agent. Blocked by SolonGate - check your dashboard to review or adjust the limit.";
      }
    }
  } catch {
  }
  return null;
}
var OPA_WASM_TTL_MS = 24 * 60 * 60 * 1e3;
function applyPatchTargets(patch) {
  const out = [];
  if (typeof patch !== "string" || !patch.includes("*** "))
    return out;
  const re = /^\*\*\*\s+(?:Add|Update|Delete)\s+File:\s*(.+?)\s*$/gm;
  let m;
  while (m = re.exec(patch))
    if (m[1])
      out.push(m[1]);
  const mv = /^\*\*\*\s+Move\s+to:\s*(.+?)\s*$/gm;
  while (m = mv.exec(patch))
    if (m[1])
      out.push(m[1]);
  return out;
}
function liftFreeformPatchPaths(call) {
  const cmd = call.command;
  if (call.tool !== "apply_patch" && !(typeof cmd === "string" && cmd.startsWith("*** Begin Patch")))
    return;
  const targets = applyPatchTargets(cmd);
  if (!targets.length)
    return;
  call.args = { ...call.args };
  if (!call.args.file_path)
    call.args.file_path = targets[0];
  if (!Array.isArray(call.args.edits))
    call.args.edits = targets.map((f) => ({ file_path: f }));
}
function normalizeToolCall(raw) {
  const parsed = CLIENT.parse(raw) || {};
  const tool = parsed.tool || "";
  const call = {
    client: AGENT_TYPE,
    // The client's own tool name, kept verbatim for logs and audit. Layers must
    // NOT branch on it: clients name the same capability differently (Bash /
    // run_command / shell). `permission` below is the neutral classification.
    tool,
    permission: guessPermission(tool),
    args: parsed.args || {},
    command: parsed.command ?? null,
    cwd: parsed.cwd || process.cwd(),
    sessionId: parsed.sessionId || "",
    response: parsed.response || {},
    raw
  };
  liftFreeformPatchPaths(call);
  return call;
}
var input = "";
input += SG_STDIN;
(async () => {
  try {
    setTimeout(() => {
      try {
        process.exit(process.exitCode || 0);
      } catch {
      }
    }, 8e3).unref();
  } catch {
  }
  try {
    if (process.env.SOLONGATE_DEBUG) {
    }
    const _evalStart = SG_ORIGIN_MS;
    try {
      const raw = JSON.parse(input);
      if (process.env.SOLONGATE_DEBUG) {
        try {
          const { appendFileSync: afs, mkdirSync: mds } = await import("node:fs");
          mds(resolve(".solongate"), { recursive: true });
          const debugLine = JSON.stringify({ ts: (/* @__PURE__ */ new Date()).toISOString(), hook: "guard", argv: process.argv.slice(2), tool_name: raw.tool_name || raw.toolName || raw.command, agent_id: AGENT_ID }) + "\n";
          afs(resolve(".solongate", ".debug-guard-log"), debugLine);
        } catch {
        }
      }
      CALL_ID = String(raw.tool_use_id || raw.toolUseId || raw.tool_call_id || "");
      try {
        CALL_FP = callFingerprint(JSON.stringify(raw.tool_input || raw.toolInput || raw.params || {}));
      } catch {
        CALL_FP = "";
      }
      const call = normalizeToolCall(raw);
      const args = call.args;
      const toolName = call.tool;
      if (process.env.SOLONGATE_DEBUG) {
        try {
          process.stderr.write("[SolonGate CALL] " + JSON.stringify({
            permission: call.permission,
            args: call.args,
            command: call.command,
            cwd: call.cwd,
            sessionId: call.sessionId
          }) + "\n");
        } catch {
        }
      }
      const hookCwd = call.cwd || process.cwd();
      let policy;
      let selfProtectEnabled = true;
      let securityCfg = null;
      const agentKey = (AGENT_ID || "default").replace(/[^a-zA-Z0-9_-]/g, "_");
      try {
        {
          const local = loadLocalPolicyFile(hookCwd);
          if (local) {
            policy = local.policy;
            if (local.security !== void 0)
              securityCfg = local.security;
            if (local.selfProtect !== void 0)
              selfProtectEnabled = local.selfProtect;
          }
        }
      } catch {
      }
      if (process.env.SOLONGATE_DEBUG) {
      }
      {
        const scope = policy && Array.isArray(policy.agents) && policy.agents.length > 0 ? policy.agents : ["*"];
        if (!scope.includes("*") && !scope.includes(AGENT_TYPE)) {
          allowTool();
          return;
        }
      }
      if (process.env.SOLONGATE_DEBUG) {
      }
      let reason = selfProtectEnabled ? tamperCheck(toolName, args) : null;
      if (!reason)
        reason = egressSecretCheck(args, securityCfg, call.cwd);
      if (!reason)
        reason = securityLayerCheck(toolName, args, securityCfg, agentKey);
      if (process.env.SOLONGATE_DEBUG) {
      }
      let opaRoute = "white";
      if (reason) {
        opaRoute = "black";
      } else if (policy && policy.rules) {
        const verdict = evaluate(policy, args, toolName);
        if (typeof verdict === "string") {
          reason = verdict;
          opaRoute = "black";
        } else {
          opaRoute = "white";
        }
      }
      if (!reason && !CLIENT.redactsOutput && securityCfg && (securityCfg.dlpBlock || securityCfg.dlpRedact)) {
        const dlpCfg = securityCfg.dlpBlock || securityCfg.dlpRedact;
        const plan = dlpRedactReadPlan(toolName, args, dlpCfg, hookCwd);
        if (plan && plan.block) {
          reason = "Security layer (DLP): reading a file that contains a secret is blocked. Blocked by SolonGate.";
          opaRoute = "black";
        } else if (plan && plan.rewrite) {
          rewriteTool(plan.rewrite);
        }
      }
      if (AGENT_TYPE !== "codex")
        process.stderr.write(`[SolonGate ROUTE] ${opaRoute.toUpperCase()} (${reason ? "block" : "allow"})
`);
      try {
        const _fd = projectFlagDir();
        mkdirSync(_fd, { recursive: true });
        sweepLegacyFlagDir();
        const _rec = { ms: Date.now() - _evalStart, ts: Date.now(), tool: toolName, session: call.sessionId };
        writeFileSync(join(_fd, ".last-eval"), JSON.stringify(_rec));
        try {
          const ring = join(_fd, ".eval-ring.jsonl");
          appendFileSync(ring, JSON.stringify(_rec) + "\n");
          try {
            if (statSync(ring).size > 16384)
              writeFileSync(ring, readFileSync(ring, "utf-8").split("\n").filter(Boolean).slice(-50).join("\n") + "\n");
          } catch {
          }
        } catch {
        }
      } catch {
      }
      if (reason) {
        if (true) {
          try {
            const logEntry = {
              tool: toolName,
              arguments: args,
              decision: "DENY",
              reason,
              permission: guessPermission(toolName),
              source: `${AGENT_TYPE}-guard`,
              agent_id: AGENT_TYPE,
              agent_name: AGENT_NAME,
              session_id: call.sessionId,
              evaluation_time_ms: Date.now() - _evalStart
            };
            writeLocalLog(securityCfg, { ts: (/* @__PURE__ */ new Date()).toISOString(), ...logEntry });
          } catch {
          }
        }
        writeDenyFlag(toolName);
        blockTool(reason);
      }
    } catch {
    }
    allowTool();
  } catch (e) {
    if (e !== SG_DONE) {
      process.exitCode = process.exitCode || 0;
    }
  }
})();
