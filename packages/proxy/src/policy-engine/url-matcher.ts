import type { PolicyRule } from '../core/index.js';

type UrlConstraints = NonNullable<PolicyRule['urlConstraints']>;

/**
 * Known argument field names that typically contain URLs.
 */
const URL_FIELDS = new Set([
  'url',
  'href',
  'uri',
  'endpoint',
  'link',
  'src',
  'source',
  'target',
  'redirect',
  'callback',
  'webhook',
]);

/**
 * Extracts URL arguments from tool call arguments.
 * Scans ALL string values — not just known field names.
 * Any string containing http:// or https:// is treated as a URL.
 */
export function extractUrlArguments(
  args: Readonly<Record<string, unknown>>,
): string[] {
  const urls: string[] = [];
  const seen = new Set<string>();

  function addUrl(value: string): void {
    const trimmed = value.trim();
    if (trimmed && !seen.has(trimmed)) {
      seen.add(trimmed);
      urls.push(trimmed);
    }
  }

  function scanValue(key: string, value: unknown): void {
    if (typeof value === 'string') {
      const lower = key.toLowerCase();
      // Known URL fields — always extract
      if (URL_FIELDS.has(lower)) {
        addUrl(value);
        return;
      }
      // Deep scan: any string containing a URL protocol
      if (/https?:\/\//i.test(value)) {
        addUrl(value);
        return;
      }
      // Bare domain patterns (e.g. "instagram.com", "foo.onion")
      // Require known TLD suffix to avoid false positives on version strings like "1.0.abc"
      if (/^[a-zA-Z0-9]([a-zA-Z0-9-]*\.)+(?:com|net|org|io|dev|app|co|me|info|biz|gov|edu|mil|onion|xyz|ai|cloud|sh|run|so|to|cc|tv|fm|am|gg|id)(\/.*)?$/.test(value)) {
        addUrl(value);
        return;
      }
    }
    // Recurse into arrays and objects
    if (Array.isArray(value)) {
      for (const item of value) {
        scanValue(key, item);
      }
    } else if (typeof value === 'object' && value !== null) {
      for (const [k, v] of Object.entries(value)) {
        scanValue(k, v);
      }
    }
  }

  for (const [key, value] of Object.entries(args)) {
    scanValue(key, value);
  }

  return urls;
}

/**
 * Glob-style URL pattern matching.
 * Normalizes both URL and pattern to lowercase for comparison.
 *
 * Patterns:
 *   '*instagram.com*' → URL contains instagram.com
 *   'https://api.example.com/*' → URL starts with prefix
 *   '*.onion' → URL ends with .onion
 *   '*' → matches everything
 */
export function matchUrlPattern(url: string, pattern: string): boolean {
  if (pattern === '*') return true;

  const normalizedUrl = url.trim().toLowerCase();
  const normalizedPattern = pattern.trim().toLowerCase();

  if (normalizedPattern === normalizedUrl) return true;

  const startsWithStar = normalizedPattern.startsWith('*');
  const endsWithStar = normalizedPattern.endsWith('*');

  if (startsWithStar && endsWithStar) {
    const infix = normalizedPattern.slice(1, -1);
    return infix.length > 0 && normalizedUrl.includes(infix);
  }
  if (endsWithStar) {
    const prefix = normalizedPattern.slice(0, -1);
    return normalizedUrl.startsWith(prefix);
  }
  if (startsWithStar) {
    const suffix = normalizedPattern.slice(1);
    return normalizedUrl.endsWith(suffix);
  }

  return false;
}

/**
 * Checks if a URL is allowed by the given constraints.
 *
 * Evaluation order:
 * 1. If denied list exists, URL must NOT match any denied pattern
 * 2. If allowed list exists, URL must match at least one allowed pattern
 * 3. If neither list exists, URL is allowed
 */
export function isUrlAllowed(
  url: string,
  constraints: UrlConstraints,
): boolean {
  // 1. Denied list — any match means denied
  if (constraints.denied && constraints.denied.length > 0) {
    for (const pattern of constraints.denied) {
      if (matchUrlPattern(url, pattern)) {
        return false;
      }
    }
  }

  // 2. Allowed list — must match at least one
  if (constraints.allowed && constraints.allowed.length > 0) {
    let matchesAllowed = false;
    for (const pattern of constraints.allowed) {
      if (matchUrlPattern(url, pattern)) {
        matchesAllowed = true;
        break;
      }
    }
    if (!matchesAllowed) return false;
  }

  return true;
}
