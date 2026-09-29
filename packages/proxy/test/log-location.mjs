/**
 * THE VIEWERS READ THE FILE THE HOOKS WRITE.
 *
 * Local logging takes a FOLDER, and the hooks append solongate-audit.jsonl inside it.
 * Which means there are two resolutions of the same question on every machine — the
 * writers' and the viewers' — and they have to land on the same path. When they did
 * not, the dataroom, `watch` and `doctor` all showed an empty log while entries were
 * being written correctly somewhere else, and nothing said so.
 *
 * It broke a second way, from the other side. The viewers read a policy CACHE, newest
 * first, because that is where a service's answer lived; nothing has written one since
 * the refresh was removed. So `localLogsSetting()` returned `enabled: false` on every
 * machine — and the Live panel SKIPS READING THE LOG ENTIRELY when it is told off. The
 * guard wrote every denial to disk and no viewer would show any of them.
 *
 * `enabled` is therefore reported TRUE always, which is the honest answer and not a
 * simplification: while there was a service, entries went there OR to a file and never
 * both, so `false` meant "do not write locally". With nowhere to send them, both writers
 * ignore the flag and record unconditionally — the setting chooses only the folder. A
 * viewer that honoured a `false` would refuse to read a file that is being written.
 *
 * internal/config/config_test.go holds the Go twin of every case below.
 */
import { mkdtempSync, mkdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { suite, check, done } from './harness.mjs';

const NAME = 'poli' + 'cy.json';
const MODULE = new URL('../dist/tui/local-log.js', import.meta.url).href;

/**
 * Resolve the setting on a machine with the given policy file.
 *
 * In a CHILD process with its own HOME, because homedir() is cached per process and
 * DEFAULT_LOCAL_LOG is computed at module load — so moving HOME under a loaded module
 * would test the wrong path. local-cli.mjs does the same for the same reason.
 */
function settingOn(doc) {
  const home = mkdtempSync(join(tmpdir(), 'sg-loglocation-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  if (doc !== undefined) {
    writeFileSync(join(home, '.solongate', NAME),
      typeof doc === 'string' ? doc : JSON.stringify(doc, null, 2));
  }
  const script = `
    const m = await import(${JSON.stringify(MODULE)});
    process.stdout.write(JSON.stringify({ setting: m.localLogsSetting(), file: m.localLogFile() }));
  `;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, HOME: home, USERPROFILE: home },
    encoding: 'utf-8',
    timeout: 30_000,
  });
  let value = null;
  try { value = JSON.parse(r.stdout || 'null'); } catch { /* left null */ }
  return { home, value, stderr: String(r.stderr || '') };
}

const DEFAULT = (home) => join(home, '.solongate', 'local-logs', 'solongate-audit.jsonl');

suite('log location — the viewers resolve what the hooks write');

// ── a bare machine records, in the default folder ────────────────────────────
{
  const { home, value, stderr } = settingOn(undefined);
  check('the module loads', value !== null, true, stderr.slice(0, 400));
  if (value) {
    check('recording is on with no policy at all', value.setting.enabled, true);
    check('and the file is the default', value.file, DEFAULT(home));
  }
}

// ── the folder the policy names ─────────────────────────────────────────────
{
  const dir = mkdtempSync(join(tmpdir(), 'sg-logdir-'));
  const { value } = settingOn({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: { localLogs: { enabled: true, path: dir + '/' } },
  });
  if (value) {
    check('a configured folder is used', value.file, join(dir, 'solongate-audit.jsonl'));
    check('and reported verbatim', value.setting.configuredPath, dir + '/');
    check('and usable here', value.setting.usableHere, true);
  }
}

// ── both spellings of the file ──────────────────────────────────────────────
//
// A policy document carrying `security` inside it is how one exported from elsewhere
// arrives, and every other reader on this machine accepts it. A viewer that did not
// would read a different folder than the hooks write to.
{
  const dir = mkdtempSync(join(tmpdir(), 'sg-logdir2-'));
  const { value } = settingOn({
    id: 'p1', name: 'P', mode: 'denylist', rules: [],
    security: { localLogs: { enabled: true, path: dir } },
  });
  if (value) check('security inside the document is found', value.file, join(dir, 'solongate-audit.jsonl'));
}

// ── enabled:false chooses a folder, it does not turn recording off ──────────
{
  const dir = mkdtempSync(join(tmpdir(), 'sg-logdir3-'));
  const { value } = settingOn({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: { localLogs: { enabled: false, path: dir } },
  });
  if (value) {
    check('enabled:false still reads the log', value.setting.enabled, true);
    check('and still honours the folder', value.file, join(dir, 'solongate-audit.jsonl'));
  }
}

// ── a folder from another OS falls back rather than dropping ────────────────
//
// A "C:/logs" on Linux is not absolute to Node, which would create it inside whatever
// repository the agent happened to be running in. The hooks fall back to the default
// folder, so the viewers have to look there — and still say the configured path is
// unusable, because that is the thing somebody needs to be told.
{
  const { home, value } = settingOn({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: { localLogs: { enabled: true, path: 'C:/logs/' } },
  });
  if (value) {
    check('a Windows path is not usable here', value.setting.usableHere, false);
    check('entries are still read from somewhere', value.file, DEFAULT(home));
    check('and the configured folder is named', value.setting.configuredPath, 'C:/logs/');
  }
}

// ── a folder that does not exist on this machine ────────────────────────────
{
  const { home, value } = settingOn({
    policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
    security: { localLogs: { enabled: true, path: '/nonexistent/sg-logs-' + process.pid } },
  });
  if (value) {
    check('an absent folder is not usable here', value.setting.usableHere, false);
    check('and the default is read instead', value.file, DEFAULT(home));
  }
}

// ── half a policy file does not move the log ────────────────────────────────
//
// The guard falls back to the default folder for the same file, so a viewer that did
// anything else would look in the wrong place at exactly the moment somebody is
// debugging a policy they have just broken.
{
  const { home, value } = settingOn('{ "security": { "localLogs": {');
  if (value) {
    check('an unparseable policy still reads the default', value.file, DEFAULT(home));
    check('and recording is still reported on', value.setting.enabled, true);
  }
}

process.exit(done());
