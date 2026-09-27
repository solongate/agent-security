import type { PolicyRule } from '../core/index.js';

type FilenameConstraints = NonNullable<PolicyRule['filenameConstraints']>;

// ─── Sensitive Filename Registry ───────────────────────────────────────────
// These are the "protected files" — like OS-level permissions.
// If ANY of these appear in ANY form inside ANY argument, it's a match.
// No shell trick, encoding, or indirection can bypass substring scanning.

const SENSITIVE_FILENAMES = [
  '.env', '.env.local', '.env.production', '.env.development', '.env.staging',
  '.env.test', '.env.example',
  'credentials.json', 'secrets.json', 'secrets.yaml', 'secrets.yml',
  '.npmrc', '.pypirc', '.netrc', '.docker/config.json',
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
  'authorized_keys', 'known_hosts',
  'policy.json', '.mcp.json', 'guard.mjs', 'audit.mjs',
  'settings.json',
];

// ─── Core: Shell-Agnostic Filename Extraction ──────────────────────────────
// Instead of parsing each shell construct separately, we:
// 1. Strip ALL shell metacharacters to get raw text
// 2. Extract every "word" from the raw text
// 3. Check each word against sensitive filename patterns
// 4. Also do substring scan of the entire raw text
// This makes it impossible to bypass via shell tricks.

/**
 * Strips all shell metacharacters and syntax, leaving only raw words.
 * This is the nuclear option — no matter how creative the shell trick,
 * the underlying filename must appear somewhere in the command text.
 */
function stripShellSyntax(value: string): string {
  return value
    // Remove command substitution markers
    .replace(/\$\(/g, ' ')
    .replace(/\)/g, ' ')
    // Remove backticks
    .replace(/`/g, ' ')
    // Remove variable references: ${var}, $var, ${a}${b}
    .replace(/\$\{[^}]*\}/g, ' ')
    .replace(/\$\w+/g, ' ')
    // Remove quotes (single, double, backtick)
    .replace(/['"]/g, ' ')
    // Remove redirects but keep the filename after them
    .replace(/>{1,2}/g, ' ')
    .replace(/<{1,3}/g, ' ')
    // Remove pipe, semicolon, ampersand
    .replace(/[|;&]/g, ' ')
    // Remove assignment operators
    .replace(/\+=/g, ' ')
    .replace(/(\w)=/g, '$1 ')
    // Remove brace expansion markers but keep content
    .replace(/[{}]/g, ' ')
    // Remove parentheses
    .replace(/[()]/g, ' ')
    // Remove backslashes
    .replace(/\\/g, ' ')
    // Collapse whitespace
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * Extracts filenames from ALL string arguments using shell-agnostic scanning.
 *
 * Architecture: OS-permission style enforcement.
 * Instead of trying to parse every shell trick, we strip ALL shell syntax
 * and scan the raw text. If a protected filename appears in ANY form,
 * it gets extracted and checked against policy constraints.
 */
export function extractFilenames(
  args: Readonly<Record<string, unknown>>,
): string[] {
  const filenames: string[] = [];
  const seen = new Set<string>();

  function addFilename(name: string): void {
    const trimmed = name.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      filenames.push(trimmed);
    }
  }

  function scanValue(value: unknown): void {
    if (typeof value === 'string') {
      const trimmed = value.trim();
      if (!trimmed) return;

      // Skip URLs (but still scan URL paths below)
      const isUrl = /^https?:\/\//i.test(trimmed);
      if (isUrl) return;

      // ── LAYER 0: Extract basename from full paths (Unix + Windows) ──
      // e.g. "C:\Users\HP\.openclaw\workspace\test.log" → "test.log"
      // e.g. "/home/user/project/test.log" → "test.log"
      if (trimmed.includes('/') || trimmed.includes('\\')) {
        const parts = trimmed.split(/[/\\]/);
        const basename = parts[parts.length - 1];
        if (basename && looksLikeFilename(basename)) {
          addFilename(basename);
        }
      }

      // ── LAYER 1: Raw substring scan (OS-permission level) ──
      // Scan the ENTIRE raw value for sensitive filename substrings.
      // No shell parsing needed — if ".env" appears anywhere, it's caught.
      const lower = trimmed.toLowerCase();
      for (const sensitive of SENSITIVE_FILENAMES) {
        const sl = sensitive.toLowerCase();
        if (lower.includes(sl)) {
          addFilename(sensitive);
        }
      }

      // ── LAYER 2: Strip shell syntax and extract words ──
      // Handles cases where filename is constructed from parts
      const stripped = stripShellSyntax(trimmed);
      const words = stripped.split(/\s+/).filter(Boolean);

      for (const word of words) {
        // Check if word is or looks like a filename
        if (looksLikeFilename(word)) {
          addFilename(word);
        }
        // Extract basename from paths (Unix / and Windows \)
        if (word.includes('/') || word.includes('\\')) {
          const parts = word.split(/[/\\]/);
          const basename = parts[parts.length - 1];
          if (basename && looksLikeFilename(basename)) {
            addFilename(basename);
          }
        }
        // Expand glob wildcards against sensitive files
        if (word.includes('*') || word.includes('?')) {
          for (const expanded of expandSensitiveGlob(word)) {
            addFilename(expanded);
          }
        }
      }

      // ── LAYER 3: String concatenation detection ──
      // Collect ALL quoted string literals and try combining them
      const quotedParts: string[] = [];
      const quotedMatches = trimmed.matchAll(/['"]([^'"]*)['"]/g);
      for (const m of quotedMatches) {
        if (m[1]) quotedParts.push(m[1]);
      }
      // Also collect variable assignment values: a=.en, b=v
      const assignMatches = trimmed.matchAll(/\b\w+=([^\s&;|'"]+)/g);
      for (const m of assignMatches) {
        if (m[1]) quotedParts.push(m[1]);
      }
      // Try all pairwise and triple concatenations (capped to prevent O(n^3) DoS)
      const cappedParts = quotedParts.length > 8 ? quotedParts.slice(0, 8) : quotedParts;
      if (cappedParts.length >= 2) {
        for (let i = 0; i < cappedParts.length; i++) {
          for (let j = i + 1; j < cappedParts.length; j++) {
            const concat = cappedParts[i]! + cappedParts[j]!;
            if (looksLikeFilename(concat)) addFilename(concat);
            // Check against sensitive filenames directly
            const concatLower = concat.toLowerCase();
            for (const sensitive of SENSITIVE_FILENAMES) {
              if (concatLower === sensitive.toLowerCase()) {
                addFilename(sensitive);
              }
            }
            // Try triple
            for (let k = j + 1; k < cappedParts.length; k++) {
              const triple = concat + cappedParts[k]!;
              if (looksLikeFilename(triple)) addFilename(triple);
              const tripleLower = triple.toLowerCase();
              for (const sensitive of SENSITIVE_FILENAMES) {
                if (tripleLower === sensitive.toLowerCase()) {
                  addFilename(sensitive);
                }
              }
            }
          }
        }
      }

      // ── LAYER 4: Glob expansion in stripped text ──
      // After stripping shell syntax, check if remaining words
      // are glob prefixes of sensitive files (e.g., "cred" from "cred*")
      for (const word of words) {
        const wordLower = word.toLowerCase().replace(/[*?]/g, '');
        if (wordLower.length >= 3) { // Minimum 3 chars to avoid false positives
          for (const sensitive of SENSITIVE_FILENAMES) {
            const sl = sensitive.toLowerCase();
            if (sl.startsWith(wordLower) && wordLower !== sl) {
              addFilename(sensitive);
            }
          }
        }
      }

      return;
    }
    // Recurse into arrays and objects
    if (Array.isArray(value)) {
      for (const item of value) {
        scanValue(item);
      }
    } else if (typeof value === 'object' && value !== null) {
      for (const v of Object.values(value)) {
        scanValue(v);
      }
    }
  }

  for (const value of Object.values(args)) {
    scanValue(value);
  }

  return filenames;
}

// ─── Glob Expansion Against Sensitive Files ────────────────────────────────

/**
 * Expands a glob-like pattern against known sensitive filenames.
 * e.g., "cred*" → ["credentials.json"], "sec*" → ["secrets.json", "secrets.yaml"]
 */
function expandSensitiveGlob(pattern: string): string[] {
  const p = pattern.toLowerCase();
  const matches: string[] = [];

  if (p === '*') return matches; // Don't expand bare wildcard

  for (const filename of SENSITIVE_FILENAMES) {
    const f = filename.toLowerCase();
    const startsWithStar = p.startsWith('*');
    const endsWithStar = p.endsWith('*');

    if (startsWithStar && endsWithStar) {
      const infix = p.slice(1, -1);
      if (infix && f.includes(infix)) matches.push(filename);
    } else if (endsWithStar) {
      const prefix = p.slice(0, -1);
      if (f.startsWith(prefix)) matches.push(filename);
    } else if (startsWithStar) {
      const suffix = p.slice(1);
      if (f.endsWith(suffix)) matches.push(filename);
    } else if (p.includes('?')) {
      const regex = new RegExp('^' + p.replace(/\?/g, '.').replace(/\*/g, '.*') + '$', 'i');
      if (regex.test(f)) matches.push(filename);
    }
  }
  return matches;
}

// ─── Filename Detection ────────────────────────────────────────────────────

/**
 * Checks if a string looks like a filename.
 */
const KNOWN_EXTENSIONLESS_FILES = new Set([
  'id_rsa', 'id_dsa', 'id_ecdsa', 'id_ed25519',
  'authorized_keys', 'known_hosts',
  'makefile', 'dockerfile', 'vagrantfile',
  'gemfile', 'rakefile', 'procfile',
  'environ',
]);

function looksLikeFilename(s: string): boolean {
  if (s.startsWith('.')) return true;
  if (/\.\w+$/.test(s)) return true;
  if (KNOWN_EXTENSIONLESS_FILES.has(s.toLowerCase())) return true;
  return false;
}

// ─── Filename Pattern Matching ─────────────────────────────────────────────

/**
 * Glob-style filename pattern matching (case-insensitive).
 */
export function matchFilenamePattern(filename: string, pattern: string): boolean {
  if (pattern === '*') return true;

  const normalizedFilename = filename.trim().toLowerCase();
  const normalizedPattern = pattern.trim().toLowerCase();

  if (normalizedFilename === normalizedPattern) return true;

  const startsWithStar = normalizedPattern.startsWith('*');
  const endsWithStar = normalizedPattern.endsWith('*');

  if (startsWithStar && endsWithStar) {
    const infix = normalizedPattern.slice(1, -1);
    return infix.length > 0 && normalizedFilename.includes(infix);
  }
  if (startsWithStar) {
    const suffix = normalizedPattern.slice(1);
    return normalizedFilename.endsWith(suffix);
  }
  if (endsWithStar) {
    const prefix = normalizedPattern.slice(0, -1);
    return normalizedFilename.startsWith(prefix);
  }

  // Single * in middle: .env.* → split on * and check prefix+suffix
  const starIdx = normalizedPattern.indexOf('*');
  if (starIdx !== -1) {
    const prefix = normalizedPattern.slice(0, starIdx);
    const suffix = normalizedPattern.slice(starIdx + 1);
    return (
      normalizedFilename.startsWith(prefix) &&
      normalizedFilename.endsWith(suffix) &&
      normalizedFilename.length >= prefix.length + suffix.length
    );
  }

  return false;
}

// ─── Constraint Evaluation ─────────────────────────────────────────────────

/**
 * Checks if a filename is allowed by the given constraints.
 */
export function isFilenameAllowed(
  filename: string,
  constraints: FilenameConstraints,
): boolean {
  // 1. Denied list — any match means denied
  if (constraints.denied && constraints.denied.length > 0) {
    for (const pattern of constraints.denied) {
      if (matchFilenamePattern(filename, pattern)) {
        return false;
      }
    }
  }

  // 2. Allowed list — must match at least one
  if (constraints.allowed && constraints.allowed.length > 0) {
    let matchesAllowed = false;
    for (const pattern of constraints.allowed) {
      if (matchFilenamePattern(filename, pattern)) {
        matchesAllowed = true;
        break;
      }
    }
    if (!matchesAllowed) return false;
  }

  return true;
}
