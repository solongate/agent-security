/**
 * Best-effort self-update for the HUMAN CLI (never the MCP proxy runtime).
 *
 * Auto-update is OPT-IN and ships OFF. On macOS the global npm prefix is often
 * root-owned (/usr/local/lib/node_modules), so `npm install -g` there fails
 * with EACCES unless it runs under sudo — a background updater can only fail,
 * silently and forever, and the dataroom sat on "updating…" while it did.
 * Rather than guess whether this machine is one of those, we do nothing behind
 * the user's back: `solongate update` is one command, and both CLI and dataroom
 * say when a new version is out. Turn the background updater on with
 * `solongate update auto on` (dataroom: Settings → UPDATES).
 *
 * With auto-update ON and a global npm install, a newer version spawns a
 * detached `npm install -g` so the NEXT run is the new version; output goes to
 * ~/.solongate/self-update.log.
 *
 * Everything is fail-safe: no network, no npm, no permissions — the CLI works
 * exactly as before, at most a dim notice is shown.
 */
import { execFile, execFileSync, spawn } from 'node:child_process';
import { access, mkdirSync, openSync, readFileSync, writeFileSync, constants as FS } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { c } from './cli-utils.js';

const PKG = '@solongate/proxy';
const CHECK_EVERY_MS = 30 * 60 * 1000; // registry poll at most every 30 min
const ATTEMPT_EVERY_MS = 6 * 60 * 60 * 1000; // retry a failed install at most every 6h
const STATE_FILE = join(homedir(), '.solongate', '.self-update.json');
const LOG_FILE = join(homedir(), '.solongate', 'self-update.log');

// ── One global install at a time ───────────────────────────────────────────
//
// Two `npm install -g` runs over the same tree do not merge, they collide: npm
// unlinks the package's bin entries and relinks them, so the second run fails
// with EEXIST on a symlink the first one is halfway through replacing — and it
// fails AFTER the removal, which leaves the machine with no `solongate` at all.
// Observed exactly that way, from one command: `solongate update` kicked the
// background updater and then ran its own install.
//
// The lock is a timestamp file rather than a held descriptor because the
// background install is DETACHED: this process exits before npm does, so there
// is nobody left to release anything. Staleness is what ends it, and the window
// is sized for an install (seconds) rather than for the npm timeout.
const LOCK_FILE = join(homedir(), '.solongate', '.update-install.lock');
const LOCK_STALE_MS = 3 * 60_000;
// How long `solongate update` waits for a background install to finish before
// going ahead anyway. The user asked for this one; it does not get abandoned
// because something else started first.
const LOCK_WAIT_MS = 90_000;

function lockHeldAt(): number | null {
  try {
    const ts = Number(readFileSync(LOCK_FILE, 'utf-8').trim().split(/\s+/)[1] ?? 0);
    if (!Number.isFinite(ts) || Date.now() - ts >= LOCK_STALE_MS) return null;
    return ts;
  } catch {
    return null; // no lock, or unreadable — either way nothing is holding it
  }
}

function takeInstallLock(): void {
  try {
    mkdirSync(join(homedir(), '.solongate'), { recursive: true });
    writeFileSync(LOCK_FILE, `${process.pid} ${Date.now()}\n`);
  } catch {
    /* a lock we cannot write is a lock we do without */
  }
}

function releaseInstallLock(): void {
  try {
    writeFileSync(LOCK_FILE, `${process.pid} 0\n`); // an epoch-0 stamp is always stale
  } catch {
    /* ignore */
  }
}

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

// npm's own words when the global prefix is not writable by this user. Matching
// these is what separates "retry later, it was a blip" from "no amount of
// retrying will help — this needs sudo".
const NEEDS_ADMIN_RE = /\bEACCES\b|\bEPERM\b|permission denied|operation not permitted/i;

interface UpdateState {
  lastCheckAt?: number;
  latestSeen?: string;
  attempts?: Record<string, number>; // version -> last attempt ts
  installed?: string; // version we already installed this run (→ "restart to apply")
  auto?: boolean; // background updater — opt-in, absent/false means off
  needsAdmin?: string; // version whose install npm refused for permissions (→ don't retry it)
}

function readState(): UpdateState {
  try {
    const s = JSON.parse(readFileSync(STATE_FILE, 'utf-8')) as UpdateState;
    return s && typeof s === 'object' ? s : {};
  } catch {
    return {};
  }
}

function writeState(s: UpdateState): void {
  try {
    mkdirSync(join(homedir(), '.solongate'), { recursive: true });
    writeFileSync(STATE_FILE, JSON.stringify(s));
  } catch {
    /* best-effort */
  }
}

/**
 * Is the background updater turned on? Default: NO — see the file header.
 * SOLONGATE_AUTO_UPDATE=on|off (1/0, true/false) overrides the stored setting
 * for one run, so a CI image or a managed fleet can force either way without
 * writing to the user's home directory.
 */
export function autoUpdateEnabled(): boolean {
  const env = (process.env.SOLONGATE_AUTO_UPDATE ?? '').trim().toLowerCase();
  if (env === '1' || env === 'true' || env === 'on' || env === 'yes') return true;
  if (env === '0' || env === 'false' || env === 'off' || env === 'no') return false;
  return readState().auto === true;
}

/** True when the env var is deciding, so the UI can say the row is overridden. */
export function autoUpdateForcedByEnv(): boolean {
  const env = (process.env.SOLONGATE_AUTO_UPDATE ?? '').trim().toLowerCase();
  return ['1', 'true', 'on', 'yes', '0', 'false', 'off', 'no'].includes(env);
}

/** Turn the background updater on/off. Clears the "npm refused" memo on enable. */
export function setAutoUpdate(on: boolean): void {
  const s = readState();
  writeState(on ? { ...s, auto: true, needsAdmin: undefined } : { ...s, auto: false });
}

export function currentVersion(): string {
  try {
    const pkg = JSON.parse(readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'package.json'), 'utf-8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

/** true when `b` is a strictly newer semver than `a` (numeric triples only). */
export function newerThan(b: string, a: string): boolean {
  const pa = a.split('.').map((n) => parseInt(n, 10) || 0);
  const pb = b.split('.').map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((pb[i] ?? 0) > (pa[i] ?? 0)) return true;
    if ((pb[i] ?? 0) < (pa[i] ?? 0)) return false;
  }
  return false;
}

/** The latest version published to npm, or null if it can't be reached. */
export async function latestVersion(): Promise<string | null> {
  return fetchLatest();
}

async function fetchLatest(): Promise<string | null> {
  try {
    // Abbreviated packument — exactly what `npm install` resolves against, so
    // dist-tags and versions are consistent. We deliberately do NOT hit the
    // small `/latest` doc: right after a publish its `latest` pointer can
    // propagate to a CDN edge BEFORE that version's metadata does, so we'd flag
    // an "available" version that `npm install` still rejects with ETARGET —
    // burning the 6h retry slot for nothing. Requiring `versions[latest]` in
    // the same document ties "seen" to "installable".
    const res = await fetch(`https://registry.npmjs.org/${PKG}`, {
      headers: { accept: 'application/vnd.npm.install-v1+json' },
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) return null;
    const j = (await res.json()) as { 'dist-tags'?: { latest?: string }; versions?: Record<string, unknown> };
    const latest = j['dist-tags']?.latest;
    if (typeof latest !== 'string') return null;
    if (!j.versions || !(latest in j.versions)) return null; // not installable yet — stay quiet
    return latest;
  } catch {
    return null;
  }
}

/**
 * Detached background `npm install -g` — output appended to the update log.
 *
 * Skipped outright while another install holds the lock. The background path
 * fails CLOSED on purpose: nobody asked for this one, so losing it costs a
 * delay until the next run, while running it anyway costs the CLI itself.
 */
function spawnGlobalInstall(version: string): boolean {
  if (lockHeldAt() !== null) return false;
  try {
    mkdirSync(join(homedir(), '.solongate'), { recursive: true });
    takeInstallLock();
    const log = openSync(LOG_FILE, 'a');
    const p = spawn('npm', ['install', '-g', `${PKG}@${version}`], {
      stdio: ['ignore', log, log],
      detached: true,
      windowsHide: true,
      shell: process.platform === 'win32',
    });
    p.on('error', () => {});
    p.unref();
    return true;
  } catch {
    return false;
  }
}

/**
 * `solongate update` — the normal way to update, and the ONLY way when the
 * background updater is off (which is the default): installs the newest CLI
 * globally, then refreshes the installed guard hooks. Returns a process exit
 * code.
 */
export async function runUpdateCommand(): Promise<number> {
  const out = (s: string): void => void process.stderr.write(s + '\n');

  // `sudo solongate update` is the obvious thing to try once npm complains, and
  // it half-works, which is worse than failing: npm installs fine as root, then
  // the guard-hook refresh below writes into ROOT's home instead of yours, and
  // your agents quietly stop being guarded. Refuse, and hand over the two
  // commands that do the right thing.
  if (runningAsRoot()) {
    out('');
    out('  Do not run `solongate update` with sudo.');
    out('  npm would install fine, but the guard hooks would be written into root’s');
    out('  home instead of yours, and your agents would stop being guarded.');
    out('');
    out('  Run these two instead:');
    for (const s of adminUpdateSteps()) out('  ' + s);
    out('');
    return 1;
  }

  const cur = currentVersion();
  out(`  current  ${cur}`);
  const latest = await latestVersion();
  if (!latest) {
    out('  could not reach the npm registry. Try again, or: npm i -g @solongate/proxy@latest');
    return 1;
  }
  if (newerThan(latest, cur)) {
    // Check writability BEFORE installing. On a stock macOS Node the global
    // folder belongs to root, and starting an install we know will fail just
    // buys the user a minute of npm EACCES noise instead of an answer.
    const pre = await globalInstallCheck();
    if (pre.writable === false) {
      writeState({ ...readState(), needsAdmin: latest });
      out(`  v${latest} is out, but npm’s global folder needs admin rights on this machine:`);
      out(`    ${pre.dir}`);
      out('  That is the normal macOS setup — SolonGate cannot install there on its own.');
      out('');
      out('  Run these two:');
      for (const s of adminUpdateSteps()) out('  ' + s);
      out('');
      return 1;
    }
    out(`  updating ${cur} -> ${latest} ...`);
    const r = await installGlobally(latest, out);
    if (!r.ok) {
      // npm refusing for permissions is not a blip to retry — this machine's
      // global folder belongs to root and no amount of retrying changes that.
      if (r.needsAdmin) {
        writeState({ ...readState(), needsAdmin: latest });
        out('  npm could not write to the global folder (it needs admin rights).');
        out('  Run these two:');
        for (const s of adminUpdateSteps()) out('  ' + s);
      } else {
        // npm removes the old package before it installs the new one, so a
        // failure here can leave no `solongate` on PATH at all. Say the version
        // out loud: `@latest` is what just failed, and pinning is what gets a
        // working CLI back on a machine that currently has none.
        out('  update failed — the CLI may not be installed right now. Run:');
        out(`    npm i -g ${PKG}@${latest}`);
      }
      return 1;
    }
    writeState({ ...readState(), needsAdmin: undefined });
    out(`  ✓ updated to ${latest}  (open a new session to use it)`);
  } else {
    out(`  ✓ already up to date`);
  }
  // Refresh the installed guard hooks so the guard matches the CLI. If we just
  // npm-updated, THIS process is still the OLD code — so its in-process install
  // would write the OLD hooks. Invoke the freshly-installed binary instead so the
  // NEW hooks land (SOLONGATE_INTERNAL bypasses the human gate for this internal
  // call). When already up to date, the running code IS latest, so refresh inline.
  try {
    if (newerThan(latest, cur)) {
      execFileSync('solongate', ['repair'], {
        env: { ...process.env, SOLONGATE_INTERNAL: '1' },
        stdio: 'inherit',
        shell: process.platform === 'win32',
      });
    } else {
      const { installGlobalQuiet, installedGuardVersion } = await import('./global-install.js');
      const r = installGlobalQuiet();
      out(r.ok ? `  ✓ guard hooks refreshed (v${installedGuardVersion() ?? '?'})` : `  guard: ${r.message}`);
    }
  } catch {
    /* best-effort — the guard also self-updates from the cloud on its next run */
  }
  return 0;
}

/** Outcome of a foreground install. `needsAdmin` = npm refused for permissions. */
interface InstallResult {
  ok: boolean;
  needsAdmin: boolean;
}

/**
 * The foreground install, run once. `installGlobally` below is what callers
 * want: it waits out a background install first and retries a collision.
 */
function runGlobalInstall(version: string): Promise<InstallResult> {
  return new Promise((resolve) => {
    try {
      mkdirSync(join(homedir(), '.solongate'), { recursive: true });
      execFile(
        'npm',
        ['install', '-g', `${PKG}@${version}`],
        { timeout: 300_000, windowsHide: true, shell: process.platform === 'win32' },
        (err, stdout, stderr) => {
          const output = `${stdout}\n${stderr}`;
          try {
            writeFileSync(LOG_FILE, `${new Date().toISOString()} install ${version}: ${err ? 'FAILED' : 'ok'}\n${output}\n`, { flag: 'a' });
          } catch {
            /* ignore */
          }
          resolve({ ok: !err, needsAdmin: !!err && NEEDS_ADMIN_RE.test(output) });
        },
      );
    } catch {
      resolve({ ok: false, needsAdmin: false });
    }
  });
}

/**
 * `solongate update`'s install: wait out whatever else is installing, take the
 * lock, and retry ONCE on a non-permission failure.
 *
 * The retry is not optimism. The failure this exists for is npm tripping over
 * bin symlinks another npm is replacing (EEXIST), and by the time we see it the
 * other run has finished and the same command succeeds. A permissions refusal
 * is not retried: the global folder belongs to root and a second attempt
 * changes nothing.
 */
async function installGlobally(version: string, out: (s: string) => void): Promise<InstallResult> {
  const heldSince = lockHeldAt();
  if (heldSince !== null) {
    out('  another install is already running — waiting for it to finish ...');
    const until = Date.now() + LOCK_WAIT_MS;
    while (Date.now() < until && lockHeldAt() !== null) await sleep(1000);
  }

  takeInstallLock();
  try {
    let r = await runGlobalInstall(version);
    if (!r.ok && !r.needsAdmin) {
      await sleep(2000);
      out('  install did not take — retrying once ...');
      r = await runGlobalInstall(version);
    }
    return r;
  } finally {
    releaseInstallLock();
  }
}

/** The exact command that fixes a root-owned global prefix. */
export function adminInstallCommand(): string {
  return process.platform === 'win32' ? `npm i -g ${PKG}@latest  (in an Administrator terminal)` : `sudo npm i -g ${PKG}@latest`;
}

/** Are we root — i.e. did someone run this under sudo? */
export function runningAsRoot(): boolean {
  return process.platform !== 'win32' && typeof process.getuid === 'function' && process.getuid() === 0;
}

/**
 * The node_modules directory this CLI is installed into, or null when we are
 * not running from one (a source/tsx run).
 *
 * Deliberately NOT `npm prefix -g`: that spawns npm, and npm pipes its output
 * through a secret-redactor that will happily rewrite parts of a path it finds
 * suspicious (a UUID in the path is enough), handing back a directory that does
 * not exist. Our own location needs no subprocess and cannot be misreported.
 */
function ownNodeModules(): string | null {
  let dir = dirname(fileURLToPath(import.meta.url));
  for (let i = 0; i < 12; i++) {
    const parent = dirname(dir);
    if (parent === dir) break;
    if (dir.endsWith(`${sep}node_modules`)) return dir;
    dir = parent;
  }
  return null;
}

/**
 * Can THIS user replace the installed copy — i.e. can `npm install -g` work
 * without sudo? Answering before we install is the whole point: on a stock
 * macOS Node the answer is no, and running the install anyway just buys a wall
 * of npm EACCES noise a minute later.
 *
 * `writable: null` means we could not tell (running from source, unusual
 * layout) — never block on a guess; try the install and report what npm says.
 * Cached because it is read from TUI render paths.
 */
let prefixCheck: Promise<{ writable: boolean | null; dir: string | null }> | null = null;
export function globalInstallCheck(): Promise<{ writable: boolean | null; dir: string | null }> {
  prefixCheck ??= new Promise((resolve) => {
    try {
      const dir = ownNodeModules();
      if (!dir) return resolve({ writable: null, dir: null });
      // npm replaces the package directory in place, so write permission on the
      // node_modules that holds it is exactly what the install needs.
      access(dir, FS.W_OK, (e) => resolve({ writable: !e, dir }));
    } catch {
      resolve({ writable: null, dir: null });
    }
  });
  return prefixCheck;
}

/**
 * The two commands that update SolonGate on a machine whose global npm folder
 * belongs to root. `repair` is deliberately NOT under sudo: it writes the guard
 * hooks into the invoking user's home, so as root it would arm root's home and
 * leave the actual user unguarded.
 */
export function adminUpdateSteps(): string[] {
  return [`  ${adminInstallCommand()}`, `  solongate repair${process.platform === 'win32' ? '' : '   (this one WITHOUT sudo)'}`];
}

/**
 * Install the newest version NOW, whatever the auto-update setting says — the
 * dataroom's UPDATES row and `solongate update` both run through here.
 */
export async function updateNow(): Promise<{ status: 'updated' | 'current' | 'needs-admin' | 'unreachable' | 'failed'; version: string }> {
  const cur = currentVersion();
  const latest = await fetchLatest();
  if (!latest) return { status: 'unreachable', version: cur };
  if (!newerThan(latest, cur)) return { status: 'current', version: cur };
  // Ask before jumping: a doomed npm run costs a minute and tells the user
  // nothing they can act on.
  if ((await globalInstallCheck()).writable === false) {
    writeState({ ...readState(), needsAdmin: latest });
    return { status: 'needs-admin', version: latest };
  }
  const r = await runGlobalInstall(latest);
  if (r.ok) {
    writeState({ ...readState(), installed: latest, needsAdmin: undefined });
    return { status: 'updated', version: latest };
  }
  if (r.needsAdmin) {
    writeState({ ...readState(), needsAdmin: latest });
    return { status: 'needs-admin', version: latest };
  }
  return { status: 'failed', version: latest };
}

/**
 * `solongate update auto [on|off]` — show or change the background updater.
 * Kept separate from `runUpdateCommand` so `solongate update` stays "update me
 * now" and never changes a setting as a side effect.
 */
export async function runAutoUpdateCommand(arg?: string): Promise<number> {
  const out = (s: string): void => void process.stderr.write(s + '\n');
  const envForced = autoUpdateForcedByEnv();
  if (arg === undefined) {
    out(`  auto-update is ${autoUpdateEnabled() ? 'on' : 'off'}${envForced ? '  (forced by SOLONGATE_AUTO_UPDATE)' : ''}`);
    out('  change it with: solongate update auto on|off');
    return 0;
  }
  const v = arg.trim().toLowerCase();
  const on = ['on', '1', 'true', 'yes', 'enable', 'enabled'].includes(v);
  const off = ['off', '0', 'false', 'no', 'disable', 'disabled'].includes(v);
  if (!on && !off) {
    out(`  unknown value "${arg}" — use: solongate update auto on|off`);
    return 1;
  }
  setAutoUpdate(on);
  out(on ? '  ✓ auto-update on — new versions install in the background' : '  ✓ auto-update off — update with: solongate update');
  // Turning it on where npm needs admin rights recreates exactly the failure
  // this setting exists for. Say so now rather than letting it fail silently
  // for weeks.
  if (on && (await globalInstallCheck()).writable === false) {
    out('');
    out('  Heads up: npm’s global folder needs admin rights on this machine, so a');
    out('  background install cannot succeed here. Updates will still be announced,');
    out('  and installing them takes:');
    for (const s of adminUpdateSteps()) out('  ' + s);
  }
  if (envForced) out(`  note: SOLONGATE_AUTO_UPDATE is set and overrides this while it stays set`);
  return 0;
}

/** What the dataroom shows about the updater. */
export type UpdateStatus =
  | { kind: 'idle' }
  | { kind: 'available'; version: string } // newer version out, auto-update off → the user decides
  | { kind: 'updating'; version: string }
  | { kind: 'updated'; version: string } // installed — restart to apply
  | { kind: 'needs-admin'; version: string }; // npm refused: root-owned global folder
// The dataroom still never NAGS with `npm i -g` while it can do the job itself.
// It does say a version is out (auto-update is opt-in, so nobody would ever find
// out otherwise), and when npm refuses for permissions it prints the sudo line —
// at that point that command is the only thing that works, and staying quiet
// just leaves the user stuck on a stale version wondering why.

/**
 * The dataroom's updater: check the registry EVERY time the TUI opens (and
 * periodically while it stays open). With auto-update ON, install in the
 * background and ask for a restart; with it OFF (the default), only report that
 * a version is available. `onStatus` drives the in-app status line; nothing is
 * ever written to the terminal directly.
 */
export async function tuiUpdateFlow(onStatus: (s: UpdateStatus) => void): Promise<void> {
  try {
    const current = currentVersion();
    const latest = await fetchLatest();
    const state = readState();
    if (latest) writeState({ ...state, lastCheckAt: Date.now(), latestSeen: latest });
    if (!latest || !newerThan(latest, current)) return;

    // Already installed this newer version this run → just keep showing "restart
    // to apply"; don't reinstall on every poll.
    if (readState().installed === latest) {
      onStatus({ kind: 'updated', version: latest });
      return;
    }

    // Auto-update off (default): say what's out and stop. Updating is the
    // user's call — from the UPDATES row here, or `solongate update`.
    if (!autoUpdateEnabled()) {
      onStatus({ kind: 'available', version: latest });
      return;
    }

    // npm already refused this exact version for permissions. Retrying every 30
    // minutes cannot succeed and would pin the status line on "updating…", which
    // is how this looked broken on macOS in the first place.
    if (readState().needsAdmin === latest) {
      onStatus({ kind: 'needs-admin', version: latest });
      return;
    }

    onStatus({ kind: 'updating', version: latest });
    const r = await runGlobalInstall(latest);
    if (r.ok) {
      writeState({ ...readState(), installed: latest, needsAdmin: undefined });
      onStatus({ kind: 'updated', version: latest });
    } else if (r.needsAdmin) {
      writeState({ ...readState(), needsAdmin: latest });
      onStatus({ kind: 'needs-admin', version: latest });
    }
    // On any other failure (usually just npm-registry propagation lag right after
    // a publish) we STAY on "updating…" and let the next 30-min poll retry — it
    // self-heals in a minute or two.
  } catch {
    /* never disturb the TUI */
  }
}

/**
 * Fire-and-forget startup hook. `notify` writes the human-facing one-liner —
 * callers pass a stderr writer so the notice never lands in piped stdout.
 */
export function maybeSelfUpdate(notify: (line: string) => void = (l) => process.stderr.write(l + '\n')): void {
  void (async () => {
    try {
      const state = readState();
      const now = Date.now();
      const current = currentVersion();

      // Between polls, still surface a known-newer version (e.g. the install
      // failed earlier or the user runs npx) without hitting the registry.
      let latest = state.latestSeen ?? null;
      if (now - (state.lastCheckAt ?? 0) >= CHECK_EVERY_MS) {
        latest = await fetchLatest();
        if (latest) writeState({ ...state, lastCheckAt: now, latestSeen: latest });
        else writeState({ ...state, lastCheckAt: now });
      }
      if (!latest || !newerThan(latest, current)) return;

      const attempts = readState().attempts ?? {};
      // The 6h throttle covers BOTH branches below, so neither the install nor
      // the notice repeats on every single command.
      if (now - (attempts[latest] ?? 0) < ATTEMPT_EVERY_MS) return;
      writeState({ ...readState(), attempts: { [latest]: now } }); // keep only the target version

      // We are past the 6h throttle and a newer version exists, so it is worth
      // one `npm prefix -g` to find out whether an install can work at all —
      // that answer decides what we tell the user AND whether the background
      // install below is anything but a guaranteed silent failure.
      const needsAdmin = (await globalInstallCheck()).writable === false;
      const head = `${c.dim}↑ solongate v${latest} available (running v${current})`;

      if (needsAdmin) {
        // No install can succeed unattended here. Give the exact commands
        // instead of a promise we cannot keep.
        notify(`${head} — needs admin rights on this machine:${c.reset}`);
        for (const s of adminUpdateSteps()) notify(`${c.cyan}  ${s.trim()}${c.reset}`);
        return;
      }

      // Auto-update off (default): mention it once, point at our own command.
      // Never `npm i -g` here — `solongate update` does the install AND the
      // guard-hook refresh that has to follow it.
      if (!autoUpdateEnabled()) {
        notify(`${head} — run ${c.reset}${c.cyan}solongate update${c.reset}`);
        return;
      }

      // Auto-update on → install in the background. On a spawn failure we simply
      // stay silent; the next run retries (a publish's registry propagation lag
      // self-heals in a minute).
      if (spawnGlobalInstall(latest)) {
        notify(`${head} — updating in the background, next run uses it${c.reset}`);
      }
    } catch {
      /* never disturb the CLI */
    }
  })();
}
