// `solongate logs-server` — a tiny loopback HTTP server that lets the SolonGate
// dashboard show your LOCAL audit logs live WITHOUT a browser file picker.
//
// When local-log storage is on, the hooks write solongate-audit.jsonl to a folder
// on this machine and nothing goes to the cloud. A hosted web page cannot read an
// OS path on its own, so this agent reads that one file and serves it over
// 127.0.0.1; the dashboard fetches it (with the user's consent) and polls for
// updates. It binds to loopback only, serves ONLY solongate-audit.jsonl, and
// never lists or exposes anything else on disk.
import { createServer, IncomingMessage, ServerResponse } from 'node:http';
import { closeSync, openSync, readFileSync, readSync, statSync } from 'node:fs';
import { resolve, join, isAbsolute } from 'node:path';
import { homedir } from 'node:os';
import { readdirSync } from 'node:fs';

const LOG_FILENAME = 'solongate-audit.jsonl';
const DEFAULT_PORT = 8788;

// MAX_SERVED_BYTES bounds one response, and with it the memory this service can be
// made to allocate.
//
// The log is append-only with no rotation anywhere: it grows for as long as the
// machine works. Reading the whole file per request was fine on the first day and
// is not on the hundredth — and this endpoint is POLLED every few seconds, so the
// allocation is not once but continuous. Sixteen megabytes is the same bound the
// dataroom's own reader uses for the same file, and the Go twin uses here.
const MAX_SERVED_BYTES = 16 * 1024 * 1024;

/**
 * At most `max` bytes from the END of a file, starting at a line boundary.
 *
 * The END, because this is a log and the recent entries are the ones a reader
 * wants. The first line of a bounded read is dropped: it is almost certainly a
 * fragment, and a fragment that happens to parse as JSON is worse than one that
 * does not — it would show up as a call that never occurred.
 */
function tailText(file: string, max: number): string {
  const size = statSync(file).size;
  if (size <= max) return readFileSync(file, 'utf-8');
  const fd = openSync(file, 'r');
  try {
    const buf = Buffer.allocUnsafe(max);
    const n = readSync(fd, buf, 0, max, size - max);
    const text = buf.subarray(0, n).toString('utf-8');
    const nl = text.indexOf('\n');
    return nl >= 0 ? text.slice(nl + 1) : text;
  } finally {
    closeSync(fd);
  }
}

// Origins allowed to read from the agent: loopback only, because that is the
// whole audience — this server listens on the loopback interface and serves this
// machine's own log. An installation that reads it from somewhere else names that
// origin in SOLONGATE_DASHBOARD_ORIGIN (comma list) rather than finding a
// hostname it does not control already trusted here.
function allowedOrigins(): Set<string> {
  const base = [
    'http://localhost:3000',
    'http://localhost:3005',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:3005',
  ];
  const extra = (process.env.SOLONGATE_DASHBOARD_ORIGIN || '')
    .split(',').map((s) => s.trim()).filter(Boolean);
  return new Set([...base, ...extra]);
}

// Same rule the hooks use: the configured path must be ABSOLUTE on this machine,
// otherwise it would have been written to the safe home fallback rather than the
// (invalid-here) path — so read from wherever the logs actually landed.
function resolveLocalLogDir(rawPath: string): string | null {
  const dir = String(rawPath || '').trim().replace(/[\\/]+$/, '');
  if (!dir) return null;
  if (isAbsolute(dir)) return dir;
  return resolve(homedir(), '.solongate', 'local-logs');
}

// Discover the configured local-logs path. Prefer the policy cache the hooks
// already maintain; fall back to the live policy from the API using the stored
// key. Returns the RESOLVED directory (where logs actually get written here).
async function findLogDir(): Promise<{ dir: string | null; configured: string | null }> {
  const base = resolve(homedir(), '.solongate');
  // 1) Policy cache files written by the hooks: .policy-cache-*.json
  try {
    const files = readdirSync(base).filter((f) => f.startsWith('.policy-cache-') && f.endsWith('.json'));
    for (const f of files) {
      try {
        const c = JSON.parse(readFileSync(join(base, f), 'utf-8'));
        const p = c?.security?.localLogs?.path;
        if (typeof p === 'string' && p.trim()) return { dir: resolveLocalLogDir(p), configured: p };
      } catch { /* try next */ }
    }
  } catch { /* no ~/.solongate yet */ }
  // 2) Fall back to the live policy from the API.
  try {
    const cfgRaw = readFileSync(join(base, 'cloud-guard.json'), 'utf-8');
    const { apiKey, apiUrl } = JSON.parse(cfgRaw) as { apiKey?: string; apiUrl?: string };
    if (apiKey) {
      const url = `${apiUrl || 'http://127.0.0.1:3002'}/api/v1/policies/active`;
      const res = await fetch(url, { headers: { Authorization: `Bearer ${apiKey}` } });
      if (res.ok) {
        const body = await res.json() as { security?: { localLogs?: { path?: string } } };
        const p = body?.security?.localLogs?.path;
        if (typeof p === 'string' && p.trim()) return { dir: resolveLocalLogDir(p), configured: p };
      }
    }
  } catch { /* offline / no key */ }
  return { dir: null, configured: null };
}

function setCors(req: IncomingMessage, res: ServerResponse) {
  const origin = req.headers.origin;
  if (origin && allowedOrigins().has(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  // Chrome Private Network Access: a public site calling loopback preflights with
  // this header and requires the matching allow header to proceed.
  if (req.headers['access-control-request-private-network'] === 'true') {
    res.setHeader('Access-Control-Allow-Private-Network', 'true');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'If-Modified-Since, Content-Type');
}

function fileInfo(dir: string | null): { file: string | null; exists: boolean; size: number; mtimeMs: number } {
  if (!dir) return { file: null, exists: false, size: 0, mtimeMs: 0 };
  const file = join(dir, LOG_FILENAME);
  try {
    const st = statSync(file);
    return { file, exists: true, size: st.size, mtimeMs: st.mtimeMs };
  } catch {
    return { file, exists: false, size: 0, mtimeMs: 0 };
  }
}

export async function runLogsServer(): Promise<void> {
  const argv = process.argv.slice(3);

  // Service verbs: `logs-server start` launches the DETACHED daemon and exits
  // (what the dashboard banner tells users to run), `stop` disables it for
  // good, `status` reports. A bare `logs-server` keeps the foreground run.
  const verb = argv[0];
  if (verb === 'start' || verb === 'stop' || verb === 'status') {
    const d = await import('./logs-server-daemon.js');
    if (verb === 'start') {
      d.startLogsServerDaemon();
      await new Promise((r) => setTimeout(r, 800)); // let it bind before reporting
      const st = d.logsServerStatus();
      process.stdout.write(
        st.running
          ? `[SolonGate] Local logs service running on http://127.0.0.1:${st.port} — background service, survives closing this terminal. Disable: solongate logs-server stop\n`
          : `[SolonGate] Could not start the local logs service — see ~/.solongate/logs-server.log\n`,
      );
    } else if (verb === 'stop') {
      d.stopLogsServerDaemon();
      process.stdout.write('[SolonGate] Local logs service stopped and disabled (re-enable from the dataroom Settings or with `solongate logs-server start`).\n');
    } else {
      const st = d.logsServerStatus();
      process.stdout.write(`[SolonGate] Local logs service: ${st.running ? `running on http://127.0.0.1:${st.port} (pid ${st.pid})` : 'stopped'} · desired ${st.desired}\n`);
    }
    return;
  }

  const portArg = argv[argv.indexOf('--port') + 1];
  const port = Number(process.env.SOLONGATE_LOGS_PORT || (argv.includes('--port') ? portArg : '') || DEFAULT_PORT) || DEFAULT_PORT;

  const server = createServer(async (req, res) => {
    setCors(req, res);
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }
    if (req.method !== 'GET') { res.writeHead(405); res.end(); return; }

    const url = (req.url || '/').split('?')[0];
    const { dir, configured } = await findLogDir();

    if (url === '/health') {
      const info = fileInfo(dir);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true, agent: 'solongate-logs-server',
        configuredPath: configured, resolvedDir: dir, file: info.file,
        exists: info.exists, size: info.size,
        mtime: info.mtimeMs ? new Date(info.mtimeMs).toISOString() : null,
      }));
      return;
    }

    if (url === '/local-logs') {
      const info = fileInfo(dir);
      if (!dir) {
        res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Solongate-Configured': '0' });
        res.end('');
        return;
      }
      if (!info.exists) {
        res.writeHead(200, { 'Content-Type': 'text/plain', 'X-Solongate-Exists': '0' });
        res.end('');
        return;
      }
      // Conditional GET: skip re-transfer when the file hasn't changed.
      const lastMod = new Date(info.mtimeMs).toUTCString();
      const since = req.headers['if-modified-since'];
      if (since && new Date(since).getTime() >= Math.floor(info.mtimeMs / 1000) * 1000) {
        res.writeHead(304, { 'Last-Modified': lastMod });
        res.end();
        return;
      }
      try {
        const text = tailText(info.file as string, MAX_SERVED_BYTES);
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Last-Modified': lastMod, 'X-Solongate-Exists': '1' });
        res.end(text);
      } catch {
        res.writeHead(500); res.end('read error');
      }
      return;
    }

    res.writeHead(404); res.end('not found');
  });

  server.listen(port, '127.0.0.1', async () => {
    // Record desired=on + our pid: the service model treats ANY start as an
    // enable, and every human CLI run resurrects a dead-but-desired server —
    // only the Settings row (stopLogsServerDaemon) turns it off for good.
    const { recordLogsServerStarted } = await import('./logs-server-daemon.js');
    recordLogsServerStarted(port);
    const { dir, configured } = await findLogDir();
    process.stdout.write(`[SolonGate] Local logs agent listening on http://127.0.0.1:${port}\n`);
    if (configured) {
      process.stdout.write(`[SolonGate] Configured path: ${configured}\n`);
      if (dir && dir !== configured.trim().replace(/[\\/]+$/, '')) {
        process.stdout.write(`[SolonGate] That path isn't absolute on this machine — reading from: ${dir}\n`);
      }
    } else {
      process.stdout.write(`[SolonGate] Local log storage not configured yet (set it in dashboard Settings).\n`);
    }
    process.stdout.write(`[SolonGate] Keep this running; the dashboard reads your logs live from here. Ctrl+C to stop.\n`);
  });

  server.on('error', (err: NodeJS.ErrnoException) => {
    if (err.code === 'EADDRINUSE') {
      process.stderr.write(`[SolonGate] Port ${port} is already in use. Pass --port <n> or set SOLONGATE_LOGS_PORT.\n`);
    } else {
      process.stderr.write(`[SolonGate] Local logs agent error: ${err.message}\n`);
    }
    process.exit(1);
  });
}
