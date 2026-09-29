/**
 * The decision itself: one policy, one set of extractors, one set of matchers.
 *
 * THIS IS SHARED ON PURPOSE. It was inside the guard hook, and the MCP proxy had
 * its own engine with OPA WASM as the sole backend — a bundle a service compiled,
 * so with no service the proxy loaded none and FAILED CLOSED on every call. The
 * guard never had that problem: OPA is an optional upgrade there and this is the
 * primary path, which is why an air-gapped install sees no behaviour change.
 *
 * Giving the proxy an evaluator of its own would have been a second set of
 * answers waiting to diverge from the guard's. This repository has had that bug
 * twice already — the two tamper globs disagreed about `*`, and the DLP list ran
 * 14 patterns against 70 — so the proxy imports THIS instead, and a policy means
 * the same thing wherever it is read.
 *
 * Plain JavaScript, in hooks/, because the hook is the demanding consumer: it has
 * to run as a lone file with no node_modules beside it. esbuild inlines this into
 * guard.bundled.mjs, which is what the installer writes. The TypeScript side
 * imports it through policy-eval.d.mts.
 *
 * evaluate() answers a REASON STRING or null. Null is "nothing here forbids it",
 * not "this is allowed by a rule" — the caller decides what to do with silence,
 * and in whitelist mode this returns a reason precisely because silence would be
 * the wrong answer.
 *
 * The Go twin of all of this is packages/sgpolicy, which the Go guard and the Go
 * proxy both import for the same reason.
 */

// ── Glob Matching ──
function matchGlob(str, pattern) {
  if (pattern === '*') return true;
  const s = str.toLowerCase();
  const p = pattern.toLowerCase();
  if (s === p) return true;
  const startsW = p.startsWith('*');
  const endsW = p.endsWith('*');
  if (startsW && endsW) { const infix = p.slice(1, -1); return infix.length > 0 && s.includes(infix); }
  if (startsW) return s.endsWith(p.slice(1));
  if (endsW) return s.startsWith(p.slice(0, -1));
  const idx = p.indexOf('*');
  if (idx !== -1) {
    const pre = p.slice(0, idx);
    const suf = p.slice(idx + 1);
    return s.startsWith(pre) && s.endsWith(suf) && s.length >= pre.length + suf.length;
  }
  return false;
}

// ── Path Glob (supports **) ──
function matchPathGlob(path, pattern) {
  const p = path.replace(/\\/g, '/').toLowerCase();
  const g = pattern.replace(/\\/g, '/').toLowerCase();
  if (p === g) return true;
  if (g.includes('**')) {
    const parts = g.split('**').filter(s => s.length > 0);
    if (parts.length === 0) return true;
    return parts.every(segment => p.includes(segment));
  }
  return matchGlob(p, g);
}

// ── Extract Functions (deep scan all string values) ──
function scanStrings(obj) {
  const strings = [];
  function walk(v) {
    if (typeof v === 'string' && v.trim()) strings.push(v.trim());
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  }
  walk(obj);
  return strings;
}

function looksLikeFilename(s) {
  if (s.startsWith('.')) return true;
  if (/\.\w+$/.test(s)) return true;
  const known = ['id_rsa','id_dsa','id_ecdsa','id_ed25519','authorized_keys','known_hosts','makefile','dockerfile'];
  return known.includes(s.toLowerCase());
}

// Deterministic shell normalizer — handles the common bypass tricks BEFORE
// any semantic check, so OPA's literal matcher sees the canonical command.
// Specifically: variable assignment + interpolation, quote concatenation
// (.e""nv, ."env"). Doesn't try to be a full shell — just enough to defeat
// the obfuscation patterns AI judges keep getting wrong non-deterministically.
function normalizeShellCommand(cmd) {
  if (typeof cmd !== 'string' || !cmd) return cmd;
  const vars = {};
  const out = [];
  // Split on statement separators (; && ||) but NOT pipes (|).
  for (const rawPart of cmd.split(/\s*(?:;|&&|\|\|)\s*/)) {
    let part = rawPart;
    // Detect var assignment: NAME=value | NAME="value" | NAME='value'
    const m = part.match(/^(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))\s*$/);
    if (m) {
      vars[m[1]] = m[2] ?? m[3] ?? m[4] ?? '';
      continue;
    }
    // Substitute ${var} then $var.
    part = part.replace(/\$\{(\w+)\}/g, (_, n) => vars[n] !== undefined ? vars[n] : '${' + n + '}');
    part = part.replace(/\$(\w+)/g, (_, n) => vars[n] !== undefined ? vars[n] : '$' + n);
    // Collapse quote-concat: a"b"c → abc, .e""nv → .env, ."env" → .env
    part = part.replace(/"([^"]*)"/g, '$1').replace(/'([^']*)'/g, '$1');
    out.push(part);
  }
  return out.join('; ');
}

// Normalize all shell-command-valued fields of an args object before tokenizing.
function normalizeArgs(args) {
  if (!args || typeof args !== 'object') return args;
  const fields = ['command', 'cmd', 'function', 'script', 'shell'];
  const copy = { ...args };
  for (const [k, v] of Object.entries(copy)) {
    if (fields.includes(k.toLowerCase()) && typeof v === 'string') {
      copy[k] = normalizeShellCommand(v);
    }
  }
  return copy;
}

function extractFilenames(args) {
  args = normalizeArgs(args);
  const names = new Set();
  // Strip surrounding/trailing quotes — `"…/secret.env"` must reduce to
  // `secret.env`, not `secret.env"` (a trailing quote breaks the *.env glob).
  const dequote = (t) => t.replace(/^["'`]+/, '').replace(/["'`]+$/, '');
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) continue;
    // Process EVERY whitespace-separated token, not just the last `/` segment of
    // the whole string. Multi-file commands (`rm a b c`) must check all of them.
    const tokens = s.includes(' ') ? s.split(/\s+/) : [s];
    const single = tokens.length === 1;
    for (let tok of tokens) {
      tok = dequote(tok);
      if (!tok || /^https?:\/\//i.test(tok)) continue;
      if (tok.includes('/') || tok.includes('\\')) {
        const b = dequote(tok.replace(/\\/g, '/').split('/').pop() || '');
        if (b && (single || looksLikeFilename(b))) names.add(b);
      } else if (looksLikeFilename(tok)) {
        names.add(tok);
      }
    }
  }
  return [...names];
}

function extractUrls(args) {
  const urls = new Set();
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) { urls.add(s); continue; }
    if (s.includes(' ')) {
      for (const tok of s.split(/\s+/)) {
        if (/^https?:\/\//i.test(tok)) urls.add(tok);
      }
    }
  }
  return [...urls];
}

function extractCommands(args) {
  args = normalizeArgs(args);
  const cmds = [];
  const fields = ['command', 'cmd', 'function', 'script', 'shell'];
  if (typeof args === 'object' && args) {
    for (const [k, v] of Object.entries(args)) {
      if (fields.includes(k.toLowerCase()) && typeof v === 'string') {
        for (const part of v.split(/\s*(?:&&|\|\||;|\|)\s*/)) {
          const trimmed = part.trim();
          if (trimmed) cmds.push(trimmed);
        }
      }
    }
  }
  return cmds;
}

function extractPaths(args, isExec) {
  const paths = [];
  const add = (t) => {
    if (!t || /^https?:\/\//i.test(t)) return;
    // Normalize Windows backslashes to forward slashes so paths match the
    // compiled Rego patterns (which are also normalized to "/"). OPA glob.match
    // does no separator translation, so raw "C:\..." never matched "/" patterns.
    if (t.includes('/') || t.includes('\\') || t.startsWith('.')) paths.push(t.replace(/\\/g, '/'));
  };
  for (const s of scanStrings(args)) {
    if (/^https?:\/\//i.test(s)) continue;
    if (isExec && /\s/.test(s)) {
      // A command line (exec tool): pull out individual path-like tokens instead
      // of treating the whole command as one path. Otherwise `node src/app.js`
      // becomes the path "node src/app.js", which no path glob can match — so a
      // path-scoped EXECUTE rule would never fire. Tokenizing yields "src/app.js".
      for (const tok of s.split(/[\s;|&><()`'"]+/)) add(tok);
    } else {
      add(s);
    }
  }
  return paths;
}

function guessPermission(toolName) {
  const name = (toolName || '').toLowerCase();
  // Codex writes every file edit through one tool named `apply_patch` — no
  // substring below matches it, so without this it would be classified READ and
  // a WRITE-scoped rule would never fire on a Codex edit.
  if (name === 'apply_patch' || name === 'applypatch') return 'WRITE';
  if (name.includes('exec') || name.includes('shell') || name.includes('run') || name.includes('eval') || name === 'bash') return 'EXECUTE';
  if (name.includes('fetch') || name.includes('http') || name.includes('request') || name.includes('curl') || name.includes('network') || name.includes('download') || name.includes('upload') || name === 'websearch') return 'NETWORK';
  // `replace`, `patch` and `modify` are here because Antigravity's edit tool is
  // `replace_file_content`, which matched none of the words above and fell
  // through to READ. A WRITE-scoped rule therefore missed the tool the agent
  // actually edits with: "deny writes under config/" left it free to rewrite
  // config/ all day. The list is words a tool NAME uses for changing something,
  // not an enumeration of known tools, and it errs wide because the name that
  // classifies wrong is silently unguarded rather than loudly broken.
  if (name.includes('write') || name.includes('create') || name.includes('delete') || name.includes('update') || name.includes('set') || name.includes('edit') || name.includes('remove') || name.includes('insert') ||
      name.includes('replace') || name.includes('patch') || name.includes('modify') || name.includes('append') || name.includes('overwrite') || name.includes('rename') || name.includes('move') || name.includes('mkdir') || name.includes('touch')) return 'WRITE';
  return 'READ';
}

// Returns the first pattern that any of the rule's constraints matches against
// the args, or null if nothing matches. Used for both DENY (engine blocks on
// match) and ALLOW (whitelist mode requires at least one match).
// Each constraint may store its pattern list in either `denied` or `allowed`
// depending on which effect the rule was created with in the dashboard. The
// hook treats both as the same "pattern list" — the rule's effect determines
// whether a match means block (DENY) or pass (ALLOW in whitelist mode).
function patternsOf(constraint) {
  if (!constraint) return null;
  const list = constraint.denied || constraint.allowed;
  return Array.isArray(list) && list.length > 0 ? list : null;
}

// Permission filter: a rule with rule.permission set only applies to tool
// calls whose guessed permission category is in that list. Empty/missing =
// applies to all categories.
function permissionApplies(rule, toolName) {
  if (!rule.permission) return true;
  const perms = Array.isArray(rule.permission) ? rule.permission : [rule.permission];
  if (perms.length === 0) return true;
  const guessed = guessPermission(toolName);
  return perms.includes(guessed);
}

function ruleMatches(rule, args, isExec) {
  const fnPats = patternsOf(rule.filenameConstraints);
  if (fnPats) {
    const filenames = extractFilenames(args);
    for (const fn of filenames) {
      for (const pat of fnPats) {
        if (matchGlob(fn, pat)) return { kind: 'filename', value: fn, pattern: pat };
      }
    }
  }
  const urlPats = patternsOf(rule.urlConstraints);
  if (urlPats) {
    const urls = extractUrls(args);
    for (const url of urls) {
      for (const pat of urlPats) {
        if (matchGlob(url, pat)) return { kind: 'URL', value: url, pattern: pat };
      }
    }
  }
  const cmdPats = patternsOf(rule.commandConstraints);
  if (cmdPats) {
    const cmds = extractCommands(args);
    for (const cmd of cmds) {
      for (const pat of cmdPats) {
        if (matchGlob(cmd, pat)) return { kind: 'command', value: cmd.slice(0, 60), pattern: pat };
      }
    }
  }
  const pathPats = patternsOf(rule.pathConstraints);
  if (pathPats) {
    const paths = extractPaths(args, isExec);
    for (const p of paths) {
      for (const pat of pathPats) {
        if (matchPathGlob(p, pat)) return { kind: 'path', value: p, pattern: pat };
      }
    }
  }
  return null;
}

// Evaluate policy. Two modes:
//   denylist (default): default ALLOW. Any DENY rule that matches → block.
//   whitelist (strict): default DENY. Must match at least one ALLOW rule to
//                       pass. DENY rules still override on top.
function evaluate(policy, args, toolName) {
  if (!policy || !policy.rules) return null;
  const enabledRules = policy.rules.filter(r => r.enabled !== false);
  const mode = policy.mode === 'whitelist' ? 'whitelist' : 'denylist';
  const isExec = /bash|shell|exec|powershell|cmd|run|eval/.test((toolName || '').toLowerCase());

  // DENY pass — runs in both modes. DENY wins over ALLOW.
  const denyRules = enabledRules
    .filter(r => r.effect === 'DENY' && permissionApplies(r, toolName))
    .sort((a, b) => (a.priority || 100) - (b.priority || 100));
  for (const rule of denyRules) {
    const m = ruleMatches(rule, args, isExec);
    if (m) return 'Blocked by policy: ' + m.kind + ' "' + m.value + '" matches "' + m.pattern + '"';
  }

  // Whitelist pass — only in strict mode. Must match at least one ALLOW rule.
  if (mode === 'whitelist') {
    const allowRules = enabledRules.filter(r => r.effect === 'ALLOW' && permissionApplies(r, toolName));
    if (allowRules.length === 0) {
      return 'Blocked by policy: strict whitelist mode is on and no ALLOW rule applies to ' + (toolName || 'this tool');
    }
    let matched = false;
    for (const rule of allowRules) {
      if (ruleMatches(rule, args, isExec)) { matched = true; break; }
    }
    if (!matched) {
      return 'Blocked by policy: strict whitelist mode — request does not match any ALLOW rule';
    }
  }

  return null;
}

export {
  evaluate,
  ruleMatches,
  permissionApplies,
  patternsOf,
  guessPermission,
  matchGlob,
  matchPathGlob,
  scanStrings,
  normalizeArgs,
  extractFilenames,
  extractUrls,
  extractCommands,
  extractPaths,
};
