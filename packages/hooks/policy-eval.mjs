// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors


function matchGlob(str, pattern) {
  if (pattern === '*') return true;
  const s0 = str.toLowerCase();
  const p = pattern.toLowerCase();
  if (s0 === p) return true;
  if (!p.includes('*')) return false;

  const parts = p.split('*');
  let s = s0;

  if (parts[0] !== '') {
    if (!s.startsWith(parts[0])) return false;
    s = s.slice(parts[0].length);
  }

  for (const part of parts.slice(1, -1)) {
    if (part === '') continue;
    const i = s.indexOf(part);
    if (i < 0) return false;
    s = s.slice(i + part.length);
  }

  const last = parts[parts.length - 1];
  if (last !== '') return s.endsWith(last);
  return true;
}

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

function normalizeShellCommand(cmd) {
  if (typeof cmd !== 'string' || !cmd) return cmd;
  const vars = {};
  const out = [];
  for (const rawPart of cmd.split(/\s*(?:;|&&|\|\|)\s*/)) {
    let part = rawPart;
    const m = part.match(/^(\w+)=(?:"([^"]*)"|'([^']*)'|([^\s;&|]*))\s*$/);
    if (m) {
      vars[m[1]] = m[2] ?? m[3] ?? m[4] ?? '';
      continue;
    }
    part = part.replace(/\$\{(\w+)\}/g, (_, n) => vars[n] !== undefined ? vars[n] : '${' + n + '}');
    part = part.replace(/\$(\w+)/g, (_, n) => vars[n] !== undefined ? vars[n] : '$' + n);
    part = part.replace(/"([^"]*)"/g, '$1').replace(/'([^']*)'/g, '$1');
    out.push(part);
  }
  return out.join('; ');
}

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
  const dequote = (t) => t.replace(/^["'`]+/, '').replace(/["'`]+$/, '');
  for (const s of scanTargetStrings(args)) {
    if (/^https?:\/\//i.test(s)) continue;
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

function extractPipelines(args) {
  args = normalizeArgs(args);
  const out = [];
  const fields = ['command', 'cmd', 'function', 'script', 'shell'];
  if (typeof args === 'object' && args) {
    for (const [k, v] of Object.entries(args)) {
      if (fields.includes(k.toLowerCase()) && typeof v === 'string') {
        for (const part of v.split(/\s*(?:&&|\|\||;)\s*/)) {
          const trimmed = part.trim();
          if (trimmed) out.push(trimmed);
        }
      }
    }
  }
  return out;
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

const CONTENT_FIELDS = new Set([
  'content', 'body', 'text',
  'new_string', 'old_string', 'newstring', 'oldstring',
  'replacement', 'prompt', 'instructions',
  'description', 'message',
]);

function scanTargetStrings(v) {
  const out = [];
  const walk = (x) => {
    if (typeof x === 'string') {
      const s = x.trim();
      if (s) out.push(s);
      return;
    }
    if (Array.isArray(x)) { for (const item of x) walk(item); return; }
    if (x && typeof x === 'object') {
      for (const k of Object.keys(x).sort((a, b) => a.localeCompare(b))) {
        if (CONTENT_FIELDS.has(k.toLowerCase())) continue;
        walk(x[k]);
      }
    }
  };
  walk(v);
  return out;
}

function extractPaths(args, isExec) {
  const paths = [];
  const add = (t) => {
    if (!t || /^https?:\/\//i.test(t)) return;
    if (t.includes('/') || t.includes('\\') || t.startsWith('.')) paths.push(t.replace(/\\/g, '/'));
  };
  for (const s of scanTargetStrings(args)) {
    if (/^https?:\/\//i.test(s)) continue;
    if (isExec && /\s/.test(s)) {
      for (const tok of s.split(/[\s;|&><()`'"]+/)) add(tok);
    } else {
      add(s);
    }
  }
  return paths;
}

function absolutizePaths(paths, cwd) {
  const base = (cwd || '').replace(/\\/g, '/').replace(/\/+$/, '');
  if (!base) return [];
  const out = [];
  const seen = new Set();
  for (const p of paths) {
    if (!p || p.startsWith('/') || p.startsWith('~') || /^[A-Za-z]:[\\/]/.test(p)) continue;
    const abs = normalizeSlashPath(base + '/' + p);
    if (!abs || abs === p || seen.has(abs)) continue;
    seen.add(abs);
    out.push(abs);
  }
  return out;
}

function normalizeSlashPath(p) {
  const absolute = p.startsWith('/');
  const parts = [];
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (parts.length && parts[parts.length - 1] !== '..') parts.pop();
      else if (!absolute) parts.push('..');
      continue;
    }
    parts.push(seg);
  }
  const joined = parts.join('/');
  if (absolute) return '/' + joined;
  return joined || '.';
}

function guessPermission(toolName) {
  const name = (toolName || '').toLowerCase();
  if (name === 'apply_patch' || name === 'applypatch') return 'WRITE';
  if (name.includes('exec') || name.includes('shell') || name.includes('run') || name.includes('eval') || name === 'bash') return 'EXECUTE';
  if (name.includes('fetch') || name.includes('http') || name.includes('request') || name.includes('curl') || name.includes('network') || name.includes('download') || name.includes('upload') || name === 'websearch') return 'NETWORK';
  if (name.includes('write') || name.includes('create') || name.includes('delete') || name.includes('update') || name.includes('set') || name.includes('edit') || name.includes('remove') || name.includes('insert') ||
      name.includes('replace') || name.includes('patch') || name.includes('modify') || name.includes('append') || name.includes('overwrite') || name.includes('rename') || name.includes('move') || name.includes('mkdir') || name.includes('touch')) return 'WRITE';
  return 'READ';
}

function patternsOf(constraint) {
  if (!constraint) return null;
  const list = constraint.denied || constraint.allowed;
  return Array.isArray(list) && list.length > 0 ? list : null;
}

function permissionApplies(rule, toolName) {
  if (!rule.permission) return true;
  const perms = Array.isArray(rule.permission) ? rule.permission : [rule.permission];
  if (perms.length === 0) return true;
  const guessed = guessPermission(toolName);
  return perms.includes(guessed);
}

function ruleMatches(rule, args, isExec, cwd) {
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
    for (const abs of absolutizePaths(paths, cwd)) paths.push(abs);
    for (const p of paths) {
      for (const pat of pathPats) {
        if (matchPathGlob(p, pat)) return { kind: 'path', value: p, pattern: pat };
      }
    }
  }
  return null;
}

function evaluate(policy, args, toolName, cwd) {
  if (!policy || !policy.rules) return null;
  const enabledRules = policy.rules.filter(r => r.enabled !== false);
  const mode = policy.mode === 'whitelist' ? 'whitelist' : 'denylist';
  const isExec = /bash|shell|exec|powershell|cmd|run|eval/.test((toolName || '').toLowerCase());

  const denyRules = enabledRules
    .filter(r => r.effect === 'DENY' && permissionApplies(r, toolName))
    .sort((a, b) => (a.priority || 100) - (b.priority || 100));
  for (const rule of denyRules) {
    const m = ruleMatches(rule, args, isExec, cwd);
    if (m) return 'Blocked by policy: ' + m.kind + ' "' + m.value + '" matches "' + m.pattern + '"';
  }

  if (mode === 'whitelist') {
    const allowRules = enabledRules.filter(r => r.effect === 'ALLOW' && permissionApplies(r, toolName));
    if (allowRules.length === 0) {
      return 'Blocked by policy: strict whitelist mode is on and no ALLOW rule applies to ' + (toolName || 'this tool');
    }
    let matched = false;
    for (const rule of allowRules) {
      if (ruleMatches(rule, args, isExec, cwd)) { matched = true; break; }
    }
    if (!matched) {
      return 'Blocked by policy: strict whitelist mode, request does not match any ALLOW rule';
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
  extractPipelines,
  extractPaths,
};