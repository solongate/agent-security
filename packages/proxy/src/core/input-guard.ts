/**
 * Input Guard: detects and blocks dangerous patterns in tool arguments.
 *
 * Prevents physical execution of injected instructions by checking for:
 * - Path traversal attacks (../, ..\, encoded variants)
 * - Shell injection (;, |, &, `, $(), etc.)
 * - Wildcard abuse (**, recursive globs)
 * - Excessive length
 * - High-entropy payloads (potential encoded exploits)
 */

import {
  INPUT_GUARD_MAX_WILDCARDS,
  INPUT_GUARD_ENTROPY_THRESHOLD,
  INPUT_GUARD_MIN_ENTROPY_LENGTH,
} from './constants.js';

/** Threat type detected by input guard. */
export type ThreatType =
  | 'PATH_TRAVERSAL'
  | 'SHELL_INJECTION'
  | 'WILDCARD_ABUSE'
  | 'LENGTH_EXCEEDED'
  | 'HIGH_ENTROPY'
  | 'SSRF'
  | 'SQL_INJECTION'
  | 'PROMPT_INJECTION'
  | 'EXFILTRATION'
  | 'BOUNDARY_ESCAPE';

/** A detected threat with details. */
export interface DetectedThreat {
  readonly type: ThreatType;
  readonly field: string;
  readonly value: string;
  readonly description: string;
}

/** Result of sanitization check. */
export interface SanitizationResult {
  readonly safe: boolean;
  readonly threats: readonly DetectedThreat[];
}

/** Configuration for input guard checks. */
export interface InputGuardConfig {
  readonly pathTraversal: boolean;
  readonly shellInjection: boolean;
  readonly wildcardAbuse: boolean;
  readonly lengthLimit: number;
  readonly entropyLimit: boolean;
  readonly ssrf: boolean;
  readonly sqlInjection: boolean;
  readonly exfiltration: boolean;
  readonly boundaryEscape: boolean;
}

export const DEFAULT_INPUT_GUARD_CONFIG: Readonly<InputGuardConfig> =
  Object.freeze({
    pathTraversal: true,
    shellInjection: true,
    wildcardAbuse: true,
    lengthLimit: 4096,
    entropyLimit: true,
    ssrf: true,
    sqlInjection: true,
    exfiltration: true,
    boundaryEscape: true,
  });

// --- Path Traversal Detection ---

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//,          // ../
  /\.\.\\/,          // ..\
  /%2e%2e/i,         // URL-encoded ..
  /%2e\./i,          // partial URL-encoded
  /\.%2e/i,          // partial URL-encoded
  /%252e%252e/i,     // double URL-encoded
  /\.\.\0/,          // null byte variant
];

const SENSITIVE_PATHS = [
  /\/etc\/passwd/i,
  /\/etc\/shadow/i,
  /\/proc\/self\/environ/i,         // Process environment variables
  /\/proc\/\d+\/environ/i,          // Any process environment
  /\/proc\//i,
  /\/dev\//i,
  /c:\\windows\\system32/i,
  /c:\\windows\\syswow64/i,
  /\/root\//i,
  /~\//,
  /\.env(\.|$)/i,                    // .env, .env.local, .env.production
  /\.aws\/credentials/i,            // AWS credentials
  /\.ssh\/id_/i,                     // SSH keys
  /\.kube\/config/i,                 // Kubernetes config
  /wp-config\.php/i,                 // WordPress config
  /\.git\/config/i,                  // Git config
  /\.npmrc/i,                        // npm credentials
  /\.pypirc/i,                       // PyPI credentials
];

export function detectPathTraversal(value: string): boolean {
  for (const pattern of PATH_TRAVERSAL_PATTERNS) {
    if (pattern.test(value)) return true;
  }
  for (const pattern of SENSITIVE_PATHS) {
    if (pattern.test(value)) return true;
  }
  return false;
}

// --- Shell Injection Detection ---

const SHELL_INJECTION_PATTERNS = [
  /[;|&`]/,          // Command separators and backtick execution
  /\$\(/,            // Command substitution $(...)
  /\$\{/,            // Variable expansion ${...}
  />\s*/,            // Output redirect
  /<\s*/,            // Input redirect
  /&&/,              // AND chaining
  /\|\|/,            // OR chaining
  /\beval\b/i,       // eval command
  /\bexec\b/i,       // exec command
  /\bsystem\b/i,     // system call
  /%0a/i,            // URL-encoded newline
  /%0d/i,            // URL-encoded carriage return
  /%09/i,            // URL-encoded tab
  /\r\n/,            // CRLF injection
  /\n/,              // Newline (command separator on Unix)
  /\bbash\s+-c\b/i,  // Subshell wrapper: bash -c
  /\bsh\s+-c\b/i,    // Subshell wrapper: sh -c
  /\bzsh\s+-c\b/i,   // Subshell wrapper: zsh -c
  /\bsource\s+/i,    // Source command
  /\bprintenv\b/i,   // Environment variable leak
  /\$'\\x[0-9a-f]/i, // Hex escape in bash: $'\x72\x6d'
  /\bxargs\b/i,      // xargs chaining
  /\bbase64\s+-d\b/i, // Base64 decode pipe
  /\bxxd\s+-r\b/i,   // Hex decode pipe
];

export function detectShellInjection(value: string): boolean {
  for (const pattern of SHELL_INJECTION_PATTERNS) {
    if (pattern.test(value)) return true;
  }
  return false;
}

// --- Wildcard Abuse Detection ---

export function detectWildcardAbuse(value: string): boolean {
  // Block recursive globs
  if (value.includes('**')) return true;

  // Count wildcards with early exit (no array allocation)
  let count = 0;
  for (let i = 0; i < value.length; i++) {
    if (value.charCodeAt(i) === 42 /* '*' */ && ++count > INPUT_GUARD_MAX_WILDCARDS) return true;
  }

  return false;
}

// --- SSRF Detection ---

const SSRF_PATTERNS = [
  /^https?:\/\/localhost\b/i,
  /^https?:\/\/127\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /^https?:\/\/0\.0\.0\.0/,
  /^https?:\/\/\[::1\]/,                         // IPv6 loopback
  /^https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}/,  // 10.x.x.x
  /^https?:\/\/172\.(1[6-9]|2\d|3[01])\./,       // 172.16-31.x.x
  /^https?:\/\/192\.168\./,                       // 192.168.x.x
  /^https?:\/\/169\.254\./,                       // Link-local / AWS metadata
  /metadata\.google\.internal/i,                  // GCP metadata
  /^https?:\/\/metadata\b/i,                      // Generic metadata endpoint
  // IPv6 bypass patterns
  /^https?:\/\/\[fe80:/i,                         // IPv6 link-local
  /^https?:\/\/\[fc00:/i,                         // IPv6 unique local
  /^https?:\/\/\[fd[0-9a-f]{2}:/i,               // IPv6 unique local (fd00::/8)
  /^https?:\/\/\[::ffff:127\./i,                  // IPv4-mapped IPv6 loopback
  /^https?:\/\/\[::ffff:10\./i,                   // IPv4-mapped IPv6 private
  /^https?:\/\/\[::ffff:172\.(1[6-9]|2\d|3[01])\./i, // IPv4-mapped IPv6 private
  /^https?:\/\/\[::ffff:192\.168\./i,             // IPv4-mapped IPv6 private
  /^https?:\/\/\[::ffff:169\.254\./i,             // IPv4-mapped IPv6 link-local
  // Hex IP bypass (e.g., 0x7f000001 = 127.0.0.1)
  /^https?:\/\/0x[0-9a-f]+\b/i,
  // Octal IP bypass (e.g., 0177.0.0.1 = 127.0.0.1)
  /^https?:\/\/0[0-7]{1,3}\./,
];

/**
 * Detects decimal IP representation (e.g., http://2130706433 = 127.0.0.1).
 * Converts decimal to IPv4 and checks if it's in a private/loopback range.
 */
function detectDecimalIP(value: string): boolean {
  const match = value.match(/^https?:\/\/(\d{8,10})(?:[:/]|$)/);
  if (!match || !match[1]) return false;

  const decimal = parseInt(match[1], 10);
  if (isNaN(decimal) || decimal > 0xffffffff) return false;

  // Check private/loopback ranges
  return (
    (decimal >= 0x7f000000 && decimal <= 0x7fffffff) || // 127.0.0.0/8
    (decimal >= 0x0a000000 && decimal <= 0x0affffff) || // 10.0.0.0/8
    (decimal >= 0xac100000 && decimal <= 0xac1fffff) || // 172.16.0.0/12
    (decimal >= 0xc0a80000 && decimal <= 0xc0a8ffff) || // 192.168.0.0/16
    (decimal >= 0xa9fe0000 && decimal <= 0xa9feffff) || // 169.254.0.0/16
    decimal === 0                                        // 0.0.0.0
  );
}

export function detectSSRF(value: string): boolean {
  for (const pattern of SSRF_PATTERNS) {
    if (pattern.test(value)) return true;
  }
  // Check for decimal IP bypass
  if (detectDecimalIP(value)) return true;
  return false;
}

// --- SQL Injection Detection ---

const SQL_INJECTION_PATTERNS = [
  /'\s{0,20}(OR|AND)\s{0,20}'.{0,200}'/i,  // ' OR '1'='1 — bounded to prevent ReDoS
  /'\s{0,10};\s{0,10}(DROP|DELETE|UPDATE|INSERT|ALTER|CREATE|EXEC)/i, // '; DROP TABLE
  /UNION\s+(ALL\s+)?SELECT/i,       // UNION SELECT
  /--\s*$/m,                         // SQL comment at end of line
  /\/\*.{0,500}?\*\//,              // SQL block comment — bounded + non-greedy
  /\bSLEEP\s*\(/i,                  // Time-based injection
  /\bBENCHMARK\s*\(/i,              // MySQL benchmark
  /\bWAITFOR\s+DELAY/i,             // MSSQL delay
  /\b(LOAD_FILE|INTO\s+OUTFILE|INTO\s+DUMPFILE)\b/i, // File operations
];

export function detectSQLInjection(value: string): boolean {
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(value)) return true;
  }
  return false;
}

// --- Data Exfiltration Detection ---

const EXFILTRATION_PATTERNS = [
  // Base64 data in URL query parameters (min 20 chars of base64)
  /[?&](data|d|q|payload|content|body|msg|token|key|secret)=[A-Za-z0-9+/]{20,}={0,2}/,
  // Hex-encoded data in URL paths (min 32 hex chars = 16 bytes)
  /\/[0-9a-f]{32,}\b/i,
  // DNS exfiltration: long subdomain labels (labels > 30 chars are suspicious)
  /https?:\/\/[a-z0-9]{30,}\./i,
  // Data URL scheme for exfil
  /data:[a-z]+\/[a-z]+;base64,[A-Za-z0-9+/]{20,}/i,
  // Webhook/exfil services
  /\b(requestbin|hookbin|webhook\.site|burpcollaborator|interact\.sh|pipedream|ngrok)\b/i,
  // curl/wget with data piping patterns in arguments
  /\bcurl\b.*\s(-d|--data|--data-binary|--data-urlencode)[\s=]/i,
  /\bwget\b.*--post-(data|file)\b/i,
];

export function detectExfiltration(value: string): boolean {
  for (const pattern of EXFILTRATION_PATTERNS) {
    if (pattern.test(value)) return true;
  }
  return false;
}

// --- Boundary Escape Detection ---

/** Context boundary markers used by SolonGate. */
export const BOUNDARY_PREFIX = '[USER_INPUT_START]';
export const BOUNDARY_SUFFIX = '[USER_INPUT_END]';

export function detectBoundaryEscape(value: string): boolean {
  return (
    value.includes(BOUNDARY_PREFIX) ||
    value.includes(BOUNDARY_SUFFIX)
  );
}

// --- Length Check ---

export function checkLengthLimits(
  value: string,
  maxLength: number = 4096,
): boolean {
  return value.length <= maxLength;
}

// --- Entropy Detection ---

/**
 * Detects high-entropy strings that may indicate encoded payloads.
 * Uses Shannon entropy calculation.
 * Threshold: 4.5 bits per character (base64 encoded data is ~6.0).
 */
export function checkEntropyLimits(value: string): boolean {
  if (value.length < INPUT_GUARD_MIN_ENTROPY_LENGTH) return true; // Too short to be meaningful

  const entropy = calculateShannonEntropy(value);
  return entropy <= INPUT_GUARD_ENTROPY_THRESHOLD;
}

function calculateShannonEntropy(str: string): number {
  // Use fixed-size array for ASCII, Map for non-ASCII (accurate per-codepoint counting)
  const freq = new Uint32Array(128);
  const nonAsciiFreq = new Map<number, number>();
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i);
    if (code < 128) {
      freq[code] = freq[code]! + 1;
    } else {
      nonAsciiFreq.set(code, (nonAsciiFreq.get(code) || 0) + 1);
    }
  }

  let entropy = 0;
  const len = str.length;
  for (let i = 0; i < 128; i++) {
    if (freq[i]! > 0) {
      const p = freq[i]! / len;
      entropy -= p * Math.log2(p);
    }
  }
  for (const count of nonAsciiFreq.values()) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// --- Main Sanitization Function ---

/**
 * Runs all input guard checks on a value.
 * Returns structured result with all detected threats.
 */
export function sanitizeInput(
  field: string,
  value: unknown,
  config: InputGuardConfig = DEFAULT_INPUT_GUARD_CONFIG,
): SanitizationResult {
  const threats: DetectedThreat[] = [];

  if (typeof value !== 'string') {
    // For non-string values, recursively check string values in objects/arrays
    if (typeof value === 'object' && value !== null) {
      return sanitizeObject(field, value, config);
    }
    return { safe: true, threats: [] };
  }

  if (config.pathTraversal && detectPathTraversal(value)) {
    threats.push({
      type: 'PATH_TRAVERSAL',
      field,
      value: truncate(value, 100),
      description: 'Path traversal pattern detected',
    });
  }

  if (config.shellInjection && detectShellInjection(value)) {
    threats.push({
      type: 'SHELL_INJECTION',
      field,
      value: truncate(value, 100),
      description: 'Shell injection pattern detected',
    });
  }

  if (config.wildcardAbuse && detectWildcardAbuse(value)) {
    threats.push({
      type: 'WILDCARD_ABUSE',
      field,
      value: truncate(value, 100),
      description: 'Wildcard abuse pattern detected',
    });
  }

  if (!checkLengthLimits(value, config.lengthLimit)) {
    threats.push({
      type: 'LENGTH_EXCEEDED',
      field,
      value: `[${value.length} chars]`,
      description: `Value exceeds maximum length of ${config.lengthLimit}`,
    });
  }

  if (config.entropyLimit && !checkEntropyLimits(value)) {
    threats.push({
      type: 'HIGH_ENTROPY',
      field,
      value: truncate(value, 100),
      description: 'High entropy string detected - possible encoded payload',
    });
  }

  if (config.ssrf && detectSSRF(value)) {
    threats.push({
      type: 'SSRF',
      field,
      value: truncate(value, 100),
      description: 'Server-side request forgery pattern detected — internal/metadata URL blocked',
    });
  }

  if (config.sqlInjection && detectSQLInjection(value)) {
    threats.push({
      type: 'SQL_INJECTION',
      field,
      value: truncate(value, 100),
      description: 'SQL injection pattern detected',
    });
  }

  if (config.exfiltration && detectExfiltration(value)) {
    threats.push({
      type: 'EXFILTRATION',
      field,
      value: truncate(value, 100),
      description: 'Data exfiltration pattern detected — encoded data or exfil service in argument',
    });
  }

  if (config.boundaryEscape && detectBoundaryEscape(value)) {
    threats.push({
      type: 'BOUNDARY_ESCAPE',
      field,
      value: truncate(value, 100),
      description: 'Context boundary escape attempt — user input contains boundary markers',
    });
  }

  return { safe: threats.length === 0, threats };
}

/**
 * Recursively sanitizes all string values in an object or array.
 */
function sanitizeObject(
  basePath: string,
  obj: object,
  config: InputGuardConfig,
): SanitizationResult {
  const threats: DetectedThreat[] = [];

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      const result = sanitizeInput(`${basePath}[${i}]`, obj[i], config);
      threats.push(...result.threats);
    }
  } else {
    for (const [key, val] of Object.entries(obj)) {
      const result = sanitizeInput(`${basePath}.${key}`, val, config);
      threats.push(...result.threats);
    }
  }

  return { safe: threats.length === 0, threats };
}

function truncate(str: string, maxLen: number): string {
  return str.length > maxLen ? str.slice(0, maxLen) + '...' : str;
}

// --- Async Sanitization ---

/** Async result shape (kept for API compatibility; same as the sync result). */
export type AsyncSanitizationResult = SanitizationResult;

/**
 * Async wrapper around sanitizeInput(). Kept async so callers (the proxy) can
 * await it uniformly; the deterministic checks run synchronously.
 */
export async function sanitizeInputAsync(
  field: string,
  value: unknown,
  config: InputGuardConfig = DEFAULT_INPUT_GUARD_CONFIG,
): Promise<AsyncSanitizationResult> {
  return sanitizeInput(field, value, config);
}
