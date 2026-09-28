/**
 * SolonGate Cloud API client — the single HTTP layer shared by the human CLI
 * commands (src/commands/*) and the interactive TUI (src/tui/*).
 *
 * Auth mirrors the rest of the proxy: pairing the machine once writes
 * ~/.solongate/cloud-guard.json ({ apiKey, apiUrl }); every request here sends
 * `Authorization: Bearer <key>`. Credentials are resolved once and cached.
 *
 * Nothing in this module (or anything it imports) may be pulled into the proxy
 * runtime hot path — it is only loaded by the `commands`/`tui` entry points.
 */
import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { homedir } from 'node:os';
// Credential file writes must survive the OS lock self-protection puts on the
// active-key file — see writeProtectedFile. (global-install imports only node
// builtins, so this cannot cycle back into the client.)
import { OWNER_ONLY, OWNER_ONLY_DIR, narrowToOwner, writeProtectedFile } from '../global-install.js';

export const DEFAULT_API_URL = 'http://127.0.0.1:3002';

export interface Credentials {
  apiKey: string;
  apiUrl: string;
}

// ── Multiple accounts on one device ────────────────────────────────────────
// A device can have several accounts logged in over time. `cloud-guard.json`
// only holds the ACTIVE key (used by the guard hooks); `accounts.json`
// accumulates every account so the dataroom can show which one it's viewing
// and switch between them WITHOUT re-running login. Two separate accounts stay
// isolated — switching only changes which account's cloud data we READ.

export interface SavedAccount {
  apiKey: string;
  apiUrl: string;
  project?: string;
  user?: string;
  /** Owner e-mail — the PRIMARY human-facing label for an account. */
  email?: string;
  addedAt?: number;
}

const accountsFile = (): string => join(homedir(), '.solongate', 'accounts.json');

export function listAccounts(): SavedAccount[] {
  let list: SavedAccount[] = [];
  try {
    const raw = JSON.parse(readFileSync(accountsFile(), 'utf-8'));
    if (Array.isArray(raw)) list = raw.filter((a) => a && typeof a.apiKey === 'string');
  } catch {
    /* no file yet */
  }
  // Seed from the active login file so the current account always appears.
  const active = loginCredentialFile();
  if (active.apiKey && !list.some((a) => a.apiKey === active.apiKey)) {
    list.unshift({ apiKey: active.apiKey, apiUrl: active.apiUrl || DEFAULT_API_URL });
  }
  return list;
}

/** Upsert an account (dedupe by apiKey). Called from `login`. */
export function saveAccount(acc: SavedAccount): void {
  try {
    const list = (() => {
      try {
        const raw = JSON.parse(readFileSync(accountsFile(), 'utf-8'));
        return Array.isArray(raw) ? (raw as SavedAccount[]).filter((a) => a && a.apiKey) : [];
      } catch {
        return [] as SavedAccount[];
      }
    })();
    const next = list.filter((a) => a.apiKey !== acc.apiKey);
    next.unshift({ ...acc, addedAt: acc.addedAt ?? Date.now() });
    mkdirSync(join(homedir(), '.solongate'), { recursive: true, mode: OWNER_ONLY_DIR });
    narrowToOwner(join(homedir(), '.solongate'));
    // 0600: this file holds live API keys in cleartext. See OWNER_ONLY.
    writeFileSync(accountsFile(), JSON.stringify(next, null, 2), { mode: OWNER_ONLY });
    narrowToOwner(accountsFile());
  } catch {
    /* best-effort */
  }
}

/** Remove a saved account from this device (does NOT revoke the cloud key). */
export function removeAccount(apiKey: string): void {
  try {
    const list = (() => {
      try {
        const raw = JSON.parse(readFileSync(accountsFile(), 'utf-8'));
        return Array.isArray(raw) ? (raw as SavedAccount[]).filter((a) => a && a.apiKey) : [];
      } catch {
        return [] as SavedAccount[];
      }
    })();
    writeFileSync(accountsFile(), JSON.stringify(list.filter((a) => a.apiKey !== apiKey), null, 2), { mode: OWNER_ONLY });
    narrowToOwner(accountsFile());
  } catch {
    /* best-effort */
  }
}

// Runtime VIEW override — set by the dataroom's account switcher. Wins over
// every persisted source but never touches disk, so the guard hooks keep using
// the real active key regardless of what the dataroom is currently viewing.
let viewOverride: Credentials | null = null;
export function setViewCredentials(creds: Credentials | null): void {
  viewOverride = creds;
  cached = null; // force re-resolve on the next request
}

/** The key this device enforces with, or null when it is not paired. */
export function enforcingKey(): string | null {
  return loginCredentialFile().apiKey ?? null;
}

/** True when the given key is the ACTIVE one the guard hooks use. */
export function isActiveAccount(apiKey: string): boolean {
  return loginCredentialFile().apiKey === apiKey;
}

/**
 * Make an account the ACTIVE one the guard hooks read (writes the active-key
 * file). Used when a dataroom login should also become this device's enforcing
 * account. Best-effort; returns false on failure.
 */
export function setActiveAccount(creds: Credentials): boolean {
  try {
    const dir = join(homedir(), '.solongate');
    mkdirSync(dir, { recursive: true, mode: OWNER_ONLY_DIR });
    narrowToOwner(dir);
    const p = join(dir, ['cloud', 'guard.json'].join('-'));
    let existing: Record<string, unknown> = {};
    try {
      existing = JSON.parse(readFileSync(p, 'utf-8')) as Record<string, unknown>;
    } catch {
      /* new file */
    }
    if (!writeProtectedFile(p, JSON.stringify({ ...existing, apiKey: creds.apiKey, apiUrl: creds.apiUrl }, null, 2))) return false;
    cached = null;
    return true;
  } catch {
    return false;
  }
}

/**
 * Clear the ACTIVE login credential — a local sign-out. Removes the key/url from
 * the active-key file so `listAccounts` no longer re-seeds it (the source of the
 * "phantom account …xxxx" that lingers after removing the account you're logged in
 * as). The guard hooks then have NO credential until the machine is paired again, so this
 * only runs when the user removes their LAST account. Best-effort; false on error.
 */
export function clearActiveCredential(): boolean {
  try {
    const p = join(homedir(), '.solongate', ['cloud', 'guard.json'].join('-'));
    if (!existsSync(p)) {
      cached = null;
      return true;
    }
    let existing: Record<string, unknown> = {};
    try {
      existing = JSON.parse(readFileSync(p, 'utf-8')) as Record<string, unknown>;
    } catch {
      /* unreadable — overwrite with an empty object below */
    }
    delete existing.apiKey;
    delete existing.apiUrl;
    if (!writeProtectedFile(p, JSON.stringify(existing, null, 2))) return false;
    cached = null;
    viewOverride = null;
    return true;
  } catch {
    return false;
  }
}

/**
 * Thrown for any non-2xx response. `code`/`message` come from the API's
 * `{ error: { code, message } }` envelope when present; `status` is the HTTP
 * status. Callers render `.message` to the user.
 */
export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
  }
}

/** Raised when no API key can be found — tells the user to run `solongate` and pair. */
export class NotAuthenticatedError extends Error {
  constructor() {
    super('Not logged in. Run `solongate` and log in from the Accounts panel.');
    this.name = 'NotAuthenticatedError';
  }
}

// ── Credential resolution ──────────────────────────────────────────────────
// Precedence: explicit env → login credential file → .env in cwd.

function loginCredentialFile(): { apiKey?: string; apiUrl?: string } {
  try {
    const p = join(homedir(), '.solongate', 'cloud-guard.json');
    if (!existsSync(p)) return {};
    const c = JSON.parse(readFileSync(p, 'utf-8'));
    return c && typeof c === 'object' ? c : {};
  } catch {
    return {};
  }
}

/** Read SOLONGATE_API_KEY from a local .env (mirrors pull-push.ts loadEnv). */
function dotenvApiKey(): string | undefined {
  try {
    const envPath = resolve('.env');
    if (!existsSync(envPath)) return undefined;
    for (const line of readFileSync(envPath, 'utf-8').split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eq = trimmed.indexOf('=');
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      if (key !== 'SOLONGATE_API_KEY') continue;
      return trimmed
        .slice(eq + 1)
        .trim()
        .replace(/^["']|["']$/g, '');
    }
  } catch {
    /* ignore */
  }
  return undefined;
}

let cached: Credentials | null = null;

/** True when a key is available without prompting. */
export function isAuthenticated(): boolean {
  try {
    resolveCredentials();
    return true;
  } catch {
    return false;
  }
}

/**
 * Resolve API key + URL. `apiUrl` override (from a `--api-url` flag) wins over
 * every source. Throws NotAuthenticatedError when no key is found.
 */
export function resolveCredentials(apiUrlOverride?: string): Credentials {
  if (viewOverride && !apiUrlOverride) return viewOverride;
  if (cached && !apiUrlOverride) return cached;
  const file = loginCredentialFile();
  const apiKey = process.env['SOLONGATE_API_KEY'] || file.apiKey || dotenvApiKey();
  if (!apiKey) throw new NotAuthenticatedError();
  const apiUrl =
    apiUrlOverride ||
    process.env['SOLONGATE_API_URL'] ||
    file.apiUrl ||
    DEFAULT_API_URL;
  const creds = { apiKey, apiUrl: apiUrl.replace(/\/$/, '') };
  if (!apiUrlOverride) cached = creds;
  return creds;
}

// ── Request layer ──────────────────────────────────────────────────────────

export interface RequestOptions {
  /**
   * Query parameters. An ARRAY is sent as the same key repeated, not as a
   * comma-joined value — the fleet filters (`group`, `who`) are repeated
   * parameters on the API side, and a joined one reads as a single group whose
   * name contains a comma.
   */
  query?: Record<string, string | number | boolean | string[] | undefined>;
  body?: unknown;
  timeoutMs?: number;
  /** Override api URL for this request (rarely needed). */
  apiUrl?: string;
  /**
   * Return the response body as TEXT rather than parsing it as JSON.
   *
   * For the routes that answer with a document — the report download is
   * markdown or CSV. Without this the body parses to undefined and the caller
   * gets an empty file with no error to explain it.
   */
  raw?: boolean;
}

function buildUrl(base: string, path: string, query?: RequestOptions['query']): string {
  const url = new URL(`${base}/api/v1${path}`);
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v === undefined) continue;
      if (Array.isArray(v)) {
        for (const one of v) url.searchParams.append(k, one);
        continue;
      }
      url.searchParams.set(k, String(v));
    }
  }
  return url.toString();
}

/**
 * Typed request against the v1 API. Returns the parsed JSON body (as T) for 2xx
 * responses; throws ApiError otherwise. `ArrayBuffer` bodies (e.g. wasm) are not
 * handled here — none of the CLI surfaces need them.
 */
export async function request<T = unknown>(
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE',
  path: string,
  opts: RequestOptions = {},
): Promise<T> {
  const creds = resolveCredentials(opts.apiUrl);
  const url = buildUrl(creds.apiUrl, path, opts.query);
  const headers: Record<string, string> = {
    Authorization: `Bearer ${creds.apiKey}`,
  };
  let bodyInit: string | undefined;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    bodyInit = JSON.stringify(opts.body);
  }

  // Transient network failures (dead keep-alive socket after a long idle, DNS
  // hiccup, laptop resume) are retried with backoff before surfacing. A stale
  // connection often needs a couple of attempts to re-establish, so GETs get 3
  // tries total; mutations are never retried (must not be double-sent).
  //
  // `Connection: close` avoids reusing a pooled socket that may have been
  // silently dropped by the OS/NAT after hours of inactivity — the #1 cause of
  // the "Cannot reach API" flash on an idle session.
  const attempt = (): Promise<Response> =>
    fetch(url, {
      method,
      headers: { ...headers, Connection: 'close' },
      body: bodyInit,
      signal: AbortSignal.timeout(opts.timeoutMs ?? 15_000),
    });
  const maxTries = method === 'GET' ? 3 : 1;
  let res: Response | undefined;
  let lastErr: unknown;
  for (let i = 0; i < maxTries; i++) {
    try {
      res = await attempt();
      break;
    } catch (err) {
      lastErr = err;
      if (i < maxTries - 1) await new Promise((r) => setTimeout(r, 600 * (i + 1)));
    }
  }
  if (!res) {
    const msg = lastErr instanceof Error ? lastErr.message : String(lastErr);
    throw new ApiError(0, 'NETWORK_ERROR', `Cannot reach SolonGate API: ${msg}`);
  }

  const text = await res.text().catch(() => '');
  let json: unknown = undefined;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      /* non-JSON body — leave undefined, handled below */
    }
  }

  if (!res.ok) {
    // Standard envelope: { error: { code, message } }. Some routes return a
    // bare { error: "string" }. Fall back to status text.
    const envelope = (json as { error?: { code?: string; message?: string } | string } | undefined)?.error;
    if (envelope && typeof envelope === 'object') {
      throw new ApiError(res.status, envelope.code || 'ERROR', envelope.message || res.statusText);
    }
    if (typeof envelope === 'string') {
      throw new ApiError(res.status, 'ERROR', envelope);
    }
    if (res.status === 401) throw new ApiError(401, 'AUTHENTICATION_ERROR', 'Invalid API key. Run `solongate` and log in from the Accounts panel.');
    if (res.status === 429) throw new ApiError(429, 'RATE_LIMITED', 'Rate limited by the API. Slow down and retry.');
    // 5xx with no useful body → a readable message instead of a bare "HTTP 500".
    if (res.status >= 500) throw new ApiError(res.status, 'SERVER_ERROR', text || 'SolonGate API had a problem (server error). Please try again in a moment.');
    throw new ApiError(res.status, 'ERROR', text || res.statusText || `HTTP ${res.status}`);
  }

  if (opts.raw) return text as unknown as T;
  return json as T;
}
