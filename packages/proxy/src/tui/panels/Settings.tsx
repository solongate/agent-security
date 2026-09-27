/**
 * Settings panel — the dashboard Settings page, dataroom edition. Everything an
 * operator configures, in one single-cursor list (↑↓ move, enter/m act):
 *   ACCOUNTS        : accounts logged in on this device (dataroom twin of the
 *                     dashboard's Connected devices) — view / make active /
 *                     add (device login) / remove
 *   GUARD           : installed vs latest hook version + device count (read-only)
 *   SELF-PROTECTION : block agents from touching SolonGate's own files (toggle)
 *   UPDATES         : this CLI's version + update now, and the background
 *                     auto-updater (off unless turned on — `npm i -g` needs
 *                     sudo on most macOS setups, so it must not run unasked)
 *   LOCAL LOGS      : mirror path + enable, plus the background dashboard link
 *   WEBHOOKS        : POST every matching event to a URL (add/toggle/events/test/delete)
 *   ALERTS          : spike alerts to ONE email + ONE telegram — signal,
 *                     threshold, window and on/off status are editable in a
 *                     small editor (or m to toggle from the row)
 *
 * Keys: ↑↓ move · enter act/edit · m make-active/toggle · t test · e edit ·
 *   a add · x remove account · d delete (twice) · n add account · r refresh
 */
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { useEffect, useRef, useState } from 'react';
import { api } from '../../api-client/index.js';
import type { AlertRule, DenialWebhook } from '../../api-client/settings.js';
import {
  DEFAULT_API_URL,
  clearActiveCredential,
  isActiveAccount,
  listAccounts,
  removeAccount,
  saveAccount,
  setActiveAccount,
  setViewCredentials,
  type SavedAccount,
} from '../../api-client/client.js';
import { openBrowser, pollDeviceLogin, startDeviceLogin } from '../../api-client/device-login.js';
import { codexDetected, codexHooksStatus, guardHookOutdated, installedGuardVersion, installGlobalQuiet, isGuardInstalled, repairQuiet, uninstallGlobalQuiet } from '../../global-install.js';
import { collectChecks } from '../../commands/doctor.js';
import { logsServerStatus, startLogsServerDaemon, stopLogsServerDaemon } from '../../logs-server-daemon.js';
import { adminUpdateSteps, autoUpdateEnabled, autoUpdateForcedByEnv, currentVersion, globalInstallCheck, latestVersion, newerThan, setAutoUpdate, updateNow } from '../../self-update.js';
import type { LogsServerStatus } from '../../logs-server-daemon.js';
import { DataView } from '../components.js';
import { useLoader, usePanelSize } from '../hooks.js';
import { theme, truncate } from '../theme.js';
import { clearLocalLog, localLogsSetting, type LocalLogSetting } from '../local-log.js';

const EVENTS: Array<DenialWebhook['events']> = ['denials', 'allowed', 'all'];
const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

type Signal = AlertRule['signal'];
const SIGNALS: Signal[] = ['any', 'deny', 'dlp', 'ratelimit'];
const SIGNAL_LABEL: Record<Signal, string> = { any: 'any signal', deny: 'denials', dlp: 'dlp secrets', ratelimit: 'rate-limit' };
const WINDOWS = [30, 60, 300, 3600, 86400];
const winLabel = (s: number): string => (s < 60 ? `${s}s` : s < 3600 ? `${s / 60}m` : s < 86400 ? `${s / 3600}h` : `${s / 86400}d`);
const THRESH_MIN = 5;
const THRESH_MAX = 100;
const nearestWindowIdx = (s: number): number => {
  let best = 0;
  for (let i = 1; i < WINDOWS.length; i++) if (Math.abs(WINDOWS[i]! - s) < Math.abs(WINDOWS[best]! - s)) best = i;
  return best;
};

type Row =
  | { kind: 'acct'; acc: SavedAccount }
  | { kind: 'acct-add' }
  | { kind: 'guard' }
  | { kind: 'self' }
  | { kind: 'doctor' }
  | { kind: 'repair' }
  | { kind: 'cli-update' }
  | { kind: 'auto-update' }
  | { kind: 'll-enabled' }
  | { kind: 'll-path' }
  | { kind: 'll-server' }
  | { kind: 'wh'; wh: DenialWebhook }
  | { kind: 'wh-add' }
  | { kind: 'alert'; rule: AlertRule }
  | { kind: 'alert-add-email' }
  | { kind: 'alert-add-tg' };

interface LoginState {
  phase: 'starting' | 'waiting' | 'done' | 'error';
  url?: string;
  msg?: string;
}

// Alert editor — a small focused form for one rule (new or existing).
interface AlertEditor {
  id?: string; // set = editing an existing rule
  channel: 'email' | 'telegram';
  target: string;
  signal: Signal;
  threshold: number;
  windowSeconds: number;
  enabled: boolean;
  field: number; // 0 target · 1 signal · 2 threshold · 3 window · 4 status (existing only)
}
// New rules have 4 fields; an existing rule adds a 5th "status" row so it can be
// turned off right here (enter on an alert lands in this editor).
const editorFieldCount = (e: AlertEditor): number => (e.id ? 5 : 4);

const acctLabel = (a: SavedAccount): string => a.email || a.user || 'account …' + a.apiKey.slice(-4);
const alertChannel = (r: AlertRule): 'email' | 'telegram' | null =>
  r.emails && r.emails.length ? 'email' : r.telegram && r.telegram.length ? 'telegram' : null;

export function SettingsPanel({
  active,
  focused,
  viewApiKey,
  onView,
  onAccountsChanged,
}: {
  active: boolean;
  focused: boolean;
  viewApiKey?: string;
  onView?: (acc: SavedAccount) => void;
  /** Fired after this panel mutates the on-disk account set so the App shell can
   *  re-derive its header / view / locked state from disk. */
  onAccountsChanged?: () => void;
}): JSX.Element {
  void active;
  const { cols, rows } = usePanelSize();
  const [sel, setSel] = useState(0);
  const [editing, setEditing] = useState<null | 'path' | 'wh-url' | 'alert-target'>(null);
  const [input, setInput] = useState('');
  const [confirmDel, setConfirmDel] = useState<string | null>(null); // row key awaiting 2nd d/x
  const [msg, setMsg] = useState<{ text: string; level: 'ok' | 'bad' } | null>(null);
  const [busy, setBusy] = useState(false);
  const [editor, setEditor] = useState<AlertEditor | null>(null);
  const [latest, setLatest] = useState<string | null>(null);
  // Result of the last doctor / repair run, rendered as read-only lines under
  // the row that produced it. Kept here rather than printed, because Ink owns
  // the terminal — writing to the stream would tear the frame.
  const [diagBusy, setDiagBusy] = useState<null | 'doctor' | 'repair'>(null);
  // Background updater: opt-in, read from disk so it survives restarts. Held in
  // state so the row flips the instant it is toggled.
  const [autoUp, setAutoUp] = useState(() => autoUpdateEnabled());
  const [updBusy, setUpdBusy] = useState(false);
  // Whether npm can install globally as this user. Resolved in the background
  // (it shells out to `npm prefix -g`) so opening the panel stays instant, and
  // shown on the row BEFORE the user presses enter — on macOS the answer is
  // usually no, and that is the thing they need to know up front.
  // Where local logging actually lands on THIS device, read from the same cache
  // the hooks enforce from — so the path row can say when the configured folder
  // is not one this machine has.
  const [llSetting, setLlSetting] = useState<LocalLogSetting | null>(null);
  useEffect(() => {
    const read = () => { try { setLlSetting(localLogsSetting()); } catch { /* no cache yet */ } };
    read();
    const t = setInterval(read, 5000);
    return () => clearInterval(t);
  }, []);
  const [canInstall, setCanInstall] = useState<boolean | null>(null);
  useEffect(() => {
    let live = true;
    globalInstallCheck().then((r) => { if (live) setCanInstall(r.writable); }).catch(() => {});
    return () => { live = false; };
  }, []);
  const [diag, setDiag] = useState<null | { of: 'doctor' | 'repair' | 'cli-update'; lines: { text: string; level: 'ok' | 'warn' | 'bad' | 'dim' }[] }>(null);
  // Progress animation for those two. Repair is synchronous and usually
  // finishes in a few ms, so without a paced screen the panel would flash and
  // look like nothing ran. The steps are honest about what each pass does; the
  // pacing is what's cosmetic.
  const [diagStep, setDiagStep] = useState(0);
  const DIAG_STEPS: Record<'doctor' | 'repair', string[]> = {
    doctor: ['login', 'active policy', 'guard hook', 'agent hooks', 'local logs'],
    repair: ['inspecting protection files', 'rewriting hook files', 'registering with agents', 're-locking'],
  };
  // Hold the progress screen until every step has had its turn on screen. A
  // repair that finishes in 8ms would otherwise flash past unread; a doctor run
  // that takes two seconds is already past this and waits for nothing.
  const settle = async (started: number, of: 'doctor' | 'repair'): Promise<void> => {
    const min = DIAG_STEPS[of].length * 220 + 160;
    const left = min - (Date.now() - started);
    if (left > 0) await new Promise((res) => setTimeout(res, left));
  };
  useEffect(() => {
    if (!diagBusy) return;
    const total = DIAG_STEPS[diagBusy].length;
    const step = setInterval(() => setDiagStep((s) => Math.min(s + 1, total - 1)), 220);
    return () => clearInterval(step);
  }, [diagBusy]);
  const ver = currentVersion();
  useEffect(() => {
    let live = true;
    latestVersion().then((v) => { if (live) setLatest(v); }).catch(() => {});
    return () => { live = false; };
  }, []);

  // ── accounts on this device ───────────────────────────────────────────────
  const [accounts, setAccounts] = useState<SavedAccount[]>(() => listAccounts());
  const [login, setLogin] = useState<LoginState | null>(null);
  const [tick, setTick] = useState(0);
  const abort = useRef(false);
  const refreshAccounts = () => setAccounts(listAccounts());
  // LOCAL guard state (read from THIS device's files) — the truth, independent of
  // the cloud guard-status which lingers ~14 days and needs the API deployed.
  // Reflects install/remove instantly.
  const [guardHere, setGuardHere] = useState(() => isGuardInstalled());
  const [guardVer, setGuardVer] = useState<number | null>(() => installedGuardVersion());
  const [guardOld, setGuardOld] = useState(() => guardHookOutdated());
  // Codex skips any hook it has not been trusted for (`/hooks` inside Codex,
  // once). The guard can be installed and still not run there, so surface it —
  // otherwise the row reads "protected" while Codex silently ignores us.
  const codexNeedsTrust = () => {
    if (!codexDetected()) return false;
    const cx = codexHooksStatus();
    return cx.registered && !cx.trusted;
  };
  const [codexTrust, setCodexTrust] = useState(codexNeedsTrust);
  const refreshGuard = () => {
    setGuardHere(isGuardInstalled());
    setGuardVer(installedGuardVersion());
    setGuardOld(guardHookOutdated());
    setCodexTrust(codexNeedsTrust());
  };
  const locked = accounts.length === 0; // unpaired device — cloud sections are inert

  // logs-server daemon status — a filesystem/pid check, polled while visible.
  const [srv, setSrv] = useState<LogsServerStatus>(() => logsServerStatus());
  useEffect(() => {
    const t = setInterval(() => setSrv(logsServerStatus()), 3000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    const loggingIn = login && login.phase !== 'done' && login.phase !== 'error';
    // Same frame clock drives the login overlay, the doctor/repair progress and
    // the update spinner — an npm install is slow enough that a frozen glyph
    // would read as a hang.
    if (!loggingIn && !diagBusy && !updBusy) return;
    const t = setInterval(() => setTick((n) => n + 1), 120);
    return () => clearInterval(t);
  }, [login, diagBusy, updBusy]);

  // Cloud config — skipped while unpaired (there is no key to call with).
  const localQ = useLoader(() => (listAccounts().length ? api.settings.getLocalLogs() : Promise.resolve(null)));
  const whQ = useLoader(() => (listAccounts().length ? api.settings.getWebhooks() : Promise.resolve(null)));
  const alertQ = useLoader(() => (listAccounts().length ? api.settings.getAlerts() : Promise.resolve(null)));
  const guardQ = useLoader(() => (listAccounts().length ? api.settings.getGuardStatus() : Promise.resolve(null)));
  const selfQ = useLoader(() => (listAccounts().length ? api.settings.getSelfProtection() : Promise.resolve(null)));

  const local = localQ.data;
  const selfProt = selfQ.data;

  // AUTO update: when the dataroom (running the freshest CLI) finds the guard
  // installed but BEHIND the latest, write the newest hooks DIRECTLY — no waiting
  // for a tool call. Once per session; manual `enter` still forces it anytime.
  const autoInstalledRef = useRef(false);
  useEffect(() => {
    if (autoInstalledRef.current) return;
    if (guardHere && guardOld) {
      autoInstalledRef.current = true;
      const res = installGlobalQuiet();
      if (res.ok) {
        refreshGuard();
        setMsg({ text: `✓ guard updated → v${installedGuardVersion() ?? '?'} (open a new session)`, level: 'ok' });
        guardQ.reload();
      }
    }
  }, [guardHere, guardOld]);
  // Deleted rows vanish the INSTANT the API confirms — the background reload
  // (1-2s) only reconciles; without this the row lingered until it finished.
  const [hidden, setHidden] = useState<Set<string>>(new Set());
  const webhooks = (whQ.data?.webhooks ?? []).filter((w) => !hidden.has('wh:' + w.id));
  const alerts = (alertQ.data?.rules ?? []).filter((r) => !hidden.has('alert:' + r.id));
  const hasEmailAlert = alerts.some((r) => alertChannel(r) === 'email');
  const hasTgAlert = alerts.some((r) => alertChannel(r) === 'telegram');

  const rowsAll: Row[] = [
    ...accounts.map((acc) => ({ kind: 'acct' as const, acc })),
    { kind: 'acct-add' },
    ...(locked
      ? []
      : [
          { kind: 'guard' as const },
          { kind: 'self' as const },
          { kind: 'doctor' as const },
          { kind: 'repair' as const },
          { kind: 'cli-update' as const },
          { kind: 'auto-update' as const },
          { kind: 'll-enabled' as const },
          { kind: 'll-path' as const },
          { kind: 'll-server' as const },
          ...webhooks.map((wh) => ({ kind: 'wh' as const, wh })),
          { kind: 'wh-add' as const },
          ...alerts.map((rule) => ({ kind: 'alert' as const, rule })),
          ...(hasEmailAlert ? [] : [{ kind: 'alert-add-email' as const }]),
          ...(hasTgAlert ? [] : [{ kind: 'alert-add-tg' as const }]),
        ]),
  ];
  const selClamped = Math.min(sel, rowsAll.length - 1);
  const cur = rowsAll[selClamped]!;
  const keyOf = (r: Row): string =>
    r.kind === 'acct' ? 'acct:' + r.acc.apiKey : r.kind === 'wh' ? 'wh:' + r.wh.id : r.kind === 'alert' ? 'alert:' + r.rule.id : r.kind;

  const reloadAll = () => {
    refreshAccounts();
    localQ.reload();
    whQ.reload();
    alertQ.reload();
    guardQ.reload();
    selfQ.reload();
  };

  const run = (label: string, fn: () => Promise<unknown>, reload: () => void) => {
    if (busy) return;
    setBusy(true);
    setMsg({ text: label + '…', level: 'ok' });
    fn()
      .then(() => {
        setMsg({ text: '✓ ' + label, level: 'ok' });
        reload();
      })
      .catch((e: unknown) => setMsg({ text: '✗ ' + (e instanceof Error ? e.message : String(e)), level: 'bad' }))
      .finally(() => setBusy(false));
  };

  // ── device login, driven entirely in-panel ────────────────────────────────
  const beginLogin = () => {
    if (login && (login.phase === 'starting' || login.phase === 'waiting')) return;
    abort.current = false;
    setLogin({ phase: 'starting' });
    void (async () => {
      let start;
      try {
        start = await startDeviceLogin(DEFAULT_API_URL);
      } catch (e) {
        setLogin({ phase: 'error', msg: 'could not reach SolonGate: ' + (e instanceof Error ? e.message : String(e)) });
        return;
      }
      setLogin({ phase: 'waiting', url: start.verifyUrl });
      openBrowser(start.verifyUrl);
      while (Date.now() < start.expiresAt && !abort.current) {
        await new Promise((r) => setTimeout(r, start.intervalMs));
        if (abort.current) return;
        const res = await pollDeviceLogin(DEFAULT_API_URL, start.deviceCode);
        if (res.status === 'approved' && res.apiKey) {
          saveAccount({ apiKey: res.apiKey, apiUrl: DEFAULT_API_URL, project: res.project, user: res.user, email: res.email });
          setLogin({ phase: 'done', msg: `✓ added ${res.email || res.user || res.project || 'account'}` });
          setViewCredentials({ apiKey: res.apiKey, apiUrl: DEFAULT_API_URL });
          onView?.({ apiKey: res.apiKey, apiUrl: DEFAULT_API_URL, project: res.project, user: res.user, email: res.email });
          reloadAll();
          return;
        }
        if (res.status === 'expired' || res.status === 'not_found') {
          setLogin({ phase: 'error', msg: 'code expired — press n to retry' });
          return;
        }
      }
      if (!abort.current) setLogin({ phase: 'error', msg: 'timed out — press n to retry' });
    })();
  };

  // ── alert editor ──────────────────────────────────────────────────────────
  const openAlertEditor = (channel: 'email' | 'telegram', rule?: AlertRule) => {
    setEditor({
      id: rule?.id,
      channel,
      target: (channel === 'email' ? rule?.emails?.[0] : rule?.telegram?.[0]) ?? '',
      signal: rule?.signal ?? 'any',
      threshold: rule?.threshold ?? THRESH_MIN,
      windowSeconds: rule?.windowSeconds ?? 300,
      enabled: rule?.enabled ?? true,
      field: rule ? 1 : 0, // new rule starts on the target; existing on signal
    });
    if (!rule) {
      setInput('');
      setEditing('alert-target');
    }
  };

  const normTarget = (channel: 'email' | 'telegram', raw: string): { value: string; error?: string } => {
    const v = raw.trim();
    if (channel === 'email') {
      const email = v.replace(/^mailto:/i, '').replace(/^["'<]+|["'>]+$/g, '').replace(/[.,;:]+$/, '').replace(/\s+/g, '');
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return { value: email, error: 'that does not look like an e-mail address' };
      return { value: email };
    }
    const tg = v.replace(/^@/, '').replace(/^(chat[\s_-]*)?id[:=\s]*/i, '').replace(/\s+/g, '');
    if (!/^-?\d{5,}$/.test(tg)) return { value: tg, error: 'a telegram chat id is a number — get yours from @userinfobot' };
    return { value: tg };
  };

  const saveEditor = () => {
    if (!editor) return;
    const t = normTarget(editor.channel, editor.target);
    if (t.error) {
      setMsg({ text: '✗ ' + t.error, level: 'bad' });
      return;
    }
    const channels = editor.channel === 'email' ? { emails: [t.value], telegram: [] } : { telegram: [t.value], emails: [] };
    const body = { signal: editor.signal, threshold: editor.threshold, windowSeconds: editor.windowSeconds, enabled: editor.enabled, ...channels };
    const id = editor.id;
    setEditor(null);
    if (id) run('alert updated', () => api.settings.updateAlert(id, body), alertQ.reload);
    else run(`${editor.channel} alert added`, () => api.settings.createAlert({ name: 'SolonGate alert', ...body }), alertQ.reload);
  };

  // NOTE: alerts have NO send-test. A test that delivers a real message to any
  // email/telegram is an abuse vector (spam an arbitrary target, burn provider
  // rate limits). Only webhooks — which POST to the user's OWN url — are testable.

  // ── row activation (enter) ────────────────────────────────────────────────
  const activate = (r: Row) => {
    if (r.kind === 'acct') {
      setViewCredentials({ apiKey: r.acc.apiKey, apiUrl: r.acc.apiUrl });
      onView?.(r.acc);
      setMsg({ text: `viewing ${acctLabel(r.acc)}`, level: 'ok' });
    } else if (r.kind === 'acct-add') {
      beginLogin();
    } else if (r.kind === 'guard') {
      // enter = install / reinstall the guard DIRECTLY — write the hook files this
      // CLI ships and register them, right now. Works whether the guard is removed,
      // outdated, or already current (a plain re-write). To pull a NEWER release,
      // run `solongate update` (updates the CLI, then installs the newest hooks).
      const res = installGlobalQuiet();
      setMsg({ text: (res.ok ? '✓ ' : '✗ ') + res.message, level: res.ok ? 'ok' : 'bad' });
      refreshGuard();
      guardQ.reload();
    } else if (r.kind === 'doctor') {
      if (diagBusy) return;
      setDiagBusy('doctor');
      setDiagStep(0);
      setDiag(null);
      void (async () => {
        const started = Date.now();
        try {
          const checks = await collectChecks();
          await settle(started, 'doctor');
          const bad = checks.filter((c) => c.ok === false).length;
          const warn = checks.filter((c) => c.ok === 'warn').length;
          setDiag({
            of: 'doctor',
            lines: checks.map((c) => ({
              text: `${c.ok === true ? '✓' : c.ok === 'warn' ? '!' : '✗'} ${c.name.padEnd(16)} ${c.detail}`,
              level: c.ok === true ? ('ok' as const) : c.ok === 'warn' ? ('warn' as const) : ('bad' as const),
            })),
          });
          setMsg(
            bad
              ? { text: `✗ ${bad} problem(s)${warn ? ` · ${warn} warning(s)` : ''}`, level: 'bad' }
              : { text: warn ? `✓ guard is working · ${warn} warning(s)` : '✓ all good', level: 'ok' },
          );
        } catch (e) {
          setMsg({ text: '✗ doctor failed: ' + (e instanceof Error ? e.message : String(e)), level: 'bad' });
        } finally {
          setDiagBusy(null);
        }
      })();
    } else if (r.kind === 'repair') {
      if (diagBusy) return;
      setDiagBusy('repair');
      setDiagStep(0);
      setDiag(null);
      void (async () => {
      try {
        // Yield first: repairQuiet() is synchronous, so without handing the
        // loop back to Ink the progress screen would never get painted and the
        // whole thing would look like it did nothing.
        const started = Date.now();
        await new Promise((res) => setTimeout(res, 60));
        const rep = repairQuiet();
        await settle(started, 'repair');
        setDiag({
          of: 'repair',
          lines: [
            ...(rep.ok ? rep.after : rep.before).map((l) => ({
              text: `${l.ok ? '✓' : '✗'} ${l.label.padEnd(20)} ${l.detail}`,
              level: l.ok ? ('ok' as const) : ('bad' as const),
            })),
            ...rep.notes.map((n) => ({ text: n, level: 'warn' as const })),
          ],
        });
        setMsg({ text: (rep.ok ? '✓ ' : '✗ ') + rep.message, level: rep.ok ? 'ok' : 'bad' });
        refreshGuard();
        guardQ.reload();
      } catch (e) {
        setMsg({ text: '✗ repair failed: ' + (e instanceof Error ? e.message : String(e)), level: 'bad' });
      } finally {
        setDiagBusy(null);
      }
      })();
    } else if (r.kind === 'self') {
      if (!selfProt) return;
      run(selfProt.enabled ? 'self-protection disabled' : 'self-protection enabled', () => api.settings.setSelfProtection(!selfProt.enabled), selfQ.reload);
    } else if (r.kind === 'cli-update') {
      if (updBusy) return;
      setUpdBusy(true);
      setMsg({ text: 'updating…', level: 'ok' });
      setDiag(null);
      void (async () => {
        try {
          const res = await updateNow();
          if (res.status === 'updated') setMsg({ text: `✓ v${res.version} installed · restart (q, then solongate) to apply`, level: 'ok' });
          else if (res.status === 'current') setMsg({ text: `✓ already on the latest version (v${res.version})`, level: 'ok' });
          else if (res.status === 'needs-admin') {
            // Two commands and a reason do not fit the one-line status, so they
            // go under the row the way doctor/repair results do.
            setMsg({ text: `✗ v${res.version} needs admin rights — run the two commands below`, level: 'bad' });
            setDiag({
              of: 'cli-update',
              lines: [
                { text: 'npm’s global folder belongs to root on this machine (the usual macOS', level: 'warn' },
                { text: 'setup), so SolonGate cannot install there by itself. In a terminal:', level: 'warn' },
                ...adminUpdateSteps().map((s) => ({ text: s.trim(), level: 'ok' as const })),
                { text: 'run repair WITHOUT sudo, or the guard hooks land in root’s home', level: 'dim' },
              ],
            });
          } else if (res.status === 'unreachable') setMsg({ text: '✗ could not reach the npm registry', level: 'bad' });
          else setMsg({ text: `✗ update to v${res.version} failed — see ~/.solongate/self-update.log`, level: 'bad' });
          setLatest(await latestVersion());
          setCanInstall((await globalInstallCheck()).writable);
        } finally {
          setUpdBusy(false);
        }
      })();
    } else if (r.kind === 'auto-update') {
      if (autoUpdateForcedByEnv()) {
        setMsg({ text: 'SOLONGATE_AUTO_UPDATE is set — unset it to change this here', level: 'bad' });
        return;
      }
      const next = !autoUp;
      setAutoUpdate(next);
      setAutoUp(next);
      setMsg(
        next
          ? canInstall === false
            ? { text: '✓ auto-update on — but npm needs sudo here, so it still cannot install on its own', level: 'bad' }
            : { text: '✓ auto-update on — new versions install in the background', level: 'ok' }
          : { text: '✓ auto-update off — update from this row or with: solongate update', level: 'ok' },
      );
    } else if (r.kind === 'll-enabled') {
      if (!local) return;
      if (!local.enabled && !local.path.trim()) {
        setMsg({ text: 'set a path first (↓ then enter)', level: 'bad' });
        return;
      }
      run(local.enabled ? 'local logs disabled' : 'local logs enabled', () => api.settings.setLocalLogs({ enabled: !local.enabled, path: local.path }), localQ.reload);
    } else if (r.kind === 'll-path') {
      setInput(local?.path ?? '');
      setEditing('path');
    } else if (r.kind === 'll-server') {
      const next = srv.running ? stopLogsServerDaemon() : startLogsServerDaemon();
      setSrv(next);
      setMsg(
        next.running
          ? { text: `✓ dashboard link running on 127.0.0.1:${next.port} — keeps running after you close the dataroom`, level: 'ok' }
          : { text: '✓ dashboard link stopped (disabled until you start it again)', level: 'ok' },
      );
    } else if (r.kind === 'wh') {
      run(r.wh.enabled ? 'webhook disabled' : 'webhook enabled', () => api.settings.updateWebhook(r.wh.id, { enabled: !r.wh.enabled }), whQ.reload);
    } else if (r.kind === 'wh-add') {
      setInput('');
      setEditing('wh-url');
    } else if (r.kind === 'alert') {
      const ch = alertChannel(r.rule);
      if (ch) openAlertEditor(ch, r.rule);
    } else if (r.kind === 'alert-add-email') {
      openAlertEditor('email');
    } else if (r.kind === 'alert-add-tg') {
      openAlertEditor('telegram');
    }
  };

  const submitInput = () => {
    const v = input.trim();
    const which = editing;
    setEditing(null);
    if (which === 'path') {
      const enabled = (local?.enabled ?? false) && v.length > 0;
      run(v ? `path saved${enabled ? '' : ' (press enter on enabled to turn on)'}` : 'path cleared (local logs off)', () => api.settings.setLocalLogs({ enabled, path: v }), localQ.reload);
    } else if (which === 'wh-url') {
      const url = v.replace(/^["'<]+|["'>]+$/g, '').trim();
      if (!url) return;
      if (!/^https?:\/\/\S+$/i.test(url)) {
        setMsg({ text: '✗ webhook url must start with http:// or https://', level: 'bad' });
        return;
      }
      run('webhook added', () => api.settings.createWebhook({ url, events: 'denials' }), whQ.reload);
    } else if (which === 'alert-target' && editor) {
      setEditor({ ...editor, target: v, field: 1 }); // move focus to signal after entering target
    }
  };

  // ── keys ──────────────────────────────────────────────────────────────────
  useInput(
    (inp, key) => {
      // While pairing, only esc (cancel) is live.
      if (login && (login.phase === 'starting' || login.phase === 'waiting')) {
        if (key.escape) {
          abort.current = true;
          setLogin(null);
        }
        return;
      }
      // Alert editor navigation.
      if (editor) {
        if (key.escape) {
          setEditor(null);
          return;
        }
        if (inp === 'e' || (key.return && editor.field === 0)) {
          setInput(editor.target);
          setEditing('alert-target');
          return;
        }
        if (key.return) {
          saveEditor();
          return;
        }
        const nFields = editorFieldCount(editor);
        if (key.upArrow) setEditor({ ...editor, field: (editor.field + nFields - 1) % nFields });
        else if (key.downArrow) setEditor({ ...editor, field: (editor.field + 1) % nFields });
        else if (key.leftArrow || key.rightArrow) {
          const d = key.rightArrow ? 1 : -1;
          if (editor.field === 1) setEditor({ ...editor, signal: SIGNALS[(SIGNALS.indexOf(editor.signal) + d + SIGNALS.length) % SIGNALS.length]! });
          else if (editor.field === 2) setEditor({ ...editor, threshold: Math.max(THRESH_MIN, Math.min(THRESH_MAX, editor.threshold + d * 5)) });
          else if (editor.field === 3) setEditor({ ...editor, windowSeconds: WINDOWS[Math.max(0, Math.min(WINDOWS.length - 1, nearestWindowIdx(editor.windowSeconds) + d))]! });
          else if (editor.field === 4) setEditor({ ...editor, enabled: !editor.enabled });
        }
        return;
      }
      setMsg(null);
      if (key.upArrow) {
        setSel((n) => Math.max(0, n - 1));
        setConfirmDel(null);
      } else if (key.downArrow) {
        setSel((n) => Math.min(rowsAll.length - 1, n + 1));
        setConfirmDel(null);
      } else if (key.return || inp === ' ') activate(cur);
      else if (inp === 'm') {
        if (cur.kind === 'acct') {
          // The machine-local log is not per account, so the calls already in
          // it belong to whoever was active before. Start it over rather than
          // showing another account's history in Live.
          const ok = setActiveAccount({ apiKey: cur.acc.apiKey, apiUrl: cur.acc.apiUrl });
          if (ok) clearLocalLog();
          setMsg(ok ? { text: `✓ ${acctLabel(cur.acc)} is now the ACTIVE key (guard + logging)`, level: 'ok' } : { text: '✗ could not set active', level: 'bad' });
          refreshAccounts();
        } else if (cur.kind === 'wh' || cur.kind === 'alert' || cur.kind === 'self' || cur.kind === 'auto-update' || cur.kind === 'll-enabled' || cur.kind === 'll-server') {
          if (cur.kind === 'alert') run(cur.rule.enabled ? 'alert disabled' : 'alert enabled', () => api.settings.setAlertEnabled(cur.rule.id, !cur.rule.enabled), alertQ.reload);
          else activate(cur);
        }
      } else if (inp === 'x' && cur.kind === 'acct') {
        const target = cur.acc;
        const k = 'acct:' + target.apiKey;
        const wasActive = isActiveAccount(target.apiKey);
        // Every OTHER account this device knows — the one that takes over the
        // active guard key, or (when empty) the signal that removing this is a
        // full local sign-out.
        const others = accounts.filter((a) => a.apiKey !== target.apiKey);
        if (confirmDel !== k) {
          setConfirmDel(k);
          const note = wasActive
            ? others.length
              ? ` — the ACTIVE guard key; ${acctLabel(others[0]!)} takes over`
              : ' — your ONLY account & the active guard key; this signs the device out (guard has no key until you log in again)'
            : ' (the cloud account is untouched)';
          setMsg({ text: `press x again to remove ${acctLabel(target)} from this device${note}`, level: 'bad' });
          return;
        }
        setConfirmDel(null);
        // Remove from accounts.json, then repair the ACTIVE key so it doesn't get
        // re-seeded as a ghost by listAccounts(): promote another account, or —
        // when this was the last one — clear the active credential entirely.
        removeAccount(target.apiKey);
        clearLocalLog();
        let extra = ' from this device';
        if (wasActive) {
          if (others.length) {
            setActiveAccount({ apiKey: others[0]!.apiKey, apiUrl: others[0]!.apiUrl });
            extra = ` · ${acctLabel(others[0]!)} is now the active key`;
          } else {
            clearActiveCredential();
            extra = ' · signed out of this device';
          }
        }
        setMsg({ text: `✓ removed ${acctLabel(target)}${extra}`, level: 'ok' });
        refreshAccounts();
        onAccountsChanged?.(); // let the App shell re-derive header / view / lock from disk
      } else if (inp === 't' && cur.kind === 'wh') {
        run('webhook test sent — check your endpoint', () => api.settings.sendTestWebhook(cur.wh.id).then((r) => { if (!r.delivered) throw new Error('endpoint rejected the test (non-2xx)'); }), whQ.reload);
      } else if (inp === 'e' && cur.kind === 'll-path') activate(cur);
      else if (inp === 'e' && cur.kind === 'wh') {
        const next = EVENTS[(EVENTS.indexOf(cur.wh.events) + 1) % EVENTS.length]!;
        run(`webhook events → ${next}`, () => api.settings.updateWebhook(cur.wh.id, { events: next }), whQ.reload);
      } else if (inp === 'e' && cur.kind === 'alert') {
        const ch = alertChannel(cur.rule);
        if (ch) openAlertEditor(ch, cur.rule);
      } else if (inp === 'n') beginLogin();
      else if (inp === 'a') {
        if (cur.kind === 'wh' || cur.kind === 'wh-add') {
          setInput('');
          setEditing('wh-url');
        } else if (cur.kind === 'alert-add-email') openAlertEditor('email');
        else if (cur.kind === 'alert-add-tg') openAlertEditor('telegram');
      } else if (inp === 'd' && cur.kind === 'guard') {
        // Remove (uninstall) the guard hooks from this device — the dataroom twin
        // of `solongate` restore. Double-press to confirm; the TUI writes the
        // files directly (its own fs is not guard-intercepted).
        if (!guardHere) {
          setMsg({ text: 'guard already removed on this device', level: 'ok' });
          return;
        }
        const k = keyOf(cur);
        if (confirmDel !== k) {
          setConfirmDel(k);
          setMsg({ text: '⚠ d again REMOVES the guard from this device — Claude Code sessions stop being protected until you reinstall', level: 'bad' });
          return;
        }
        setConfirmDel(null);
        const res = uninstallGlobalQuiet();
        setMsg({ text: (res.ok ? '✓ ' : '✗ ') + res.message, level: res.ok ? 'ok' : 'bad' });
        refreshGuard(); // reflect the removal in the row immediately
        guardQ.reload();
      } else if (inp === 'd' && (cur.kind === 'wh' || cur.kind === 'alert')) {
        const k = keyOf(cur);
        if (confirmDel !== k) {
          setConfirmDel(k);
          setMsg({ text: 'press d again to delete', level: 'bad' });
          return;
        }
        setConfirmDel(null);
        if (cur.kind === 'wh') {
          const id = cur.wh.id;
          run('webhook deleted', () => api.settings.deleteWebhook(id).then(() => setHidden((h) => new Set(h).add('wh:' + id))), whQ.reload);
        } else {
          const id = cur.rule.id;
          run('alert deleted', () => api.settings.deleteAlert(id).then(() => setHidden((h) => new Set(h).add('alert:' + id))), alertQ.reload);
        }
      } else if (inp === 'r') reloadAll();
    },
    { isActive: focused && !editing },
  );

  const spin = SPIN[tick % SPIN.length];

  // ── login overlay ─────────────────────────────────────────────────────────
  if (login && (login.phase === 'starting' || login.phase === 'waiting')) {
    return (
      <Box flexDirection="column">
        <Text bold color={theme.accentBright}>
          Add an account
        </Text>
        {login.phase === 'starting' ? (
          <Text color={theme.dim}>{spin} starting device pairing…</Text>
        ) : (
          <Box flexDirection="column" marginTop={1}>
            <Text color={theme.dim}>Opening your browser to authorize. If it didn't open, visit:</Text>
            <Text color={theme.accentBright} bold wrap="truncate">
              {login.url}
            </Text>
            <Box marginTop={1}>
              <Text color={theme.warn}>{spin} waiting for authorization… </Text>
              <Text color={theme.dim}>esc to cancel</Text>
            </Box>
          </Box>
        )}
      </Box>
    );
  }

  // ── alert editor overlay ──────────────────────────────────────────────────
  if (editor) {
    const fieldRow = (idx: number, label: string, value: JSX.Element, hint?: string) => (
      <Text wrap="truncate">
        <Text color={editor.field === idx ? theme.accentBright : theme.dim}>{editor.field === idx ? '▸ ' : '  '}</Text>
        <Text color={theme.dim}>{label.padEnd(11)}</Text>
        {value}
        {editor.field === idx && hint ? <Text color={theme.dim}>{'   ' + hint}</Text> : null}
      </Text>
    );
    return (
      <Box flexDirection="column">
        <Text bold color={theme.accentBright}>
          {editor.id ? 'Edit' : 'New'} {editor.channel} alert
        </Text>
        <Text color={theme.dim}>↑↓ field · ←→ change · e edit target · enter save · esc cancel</Text>
        {editing === 'alert-target' ? (
          <Box marginTop={1}>
            <Text color={theme.warn}>{editor.channel === 'email' ? 'e-mail address: ' : 'telegram chat id (from @userinfobot): '}</Text>
            <TextInput value={input} onChange={setInput} onSubmit={submitInput} />
          </Box>
        ) : msg ? (
          <Text color={msg.level === 'bad' ? theme.bad : theme.ok}>{truncate(msg.text, cols)}</Text>
        ) : (
          <Text> </Text>
        )}
        <Box marginTop={1} flexDirection="column">
          {fieldRow(0, 'target', editor.target ? <Text color={theme.accent}>{truncate(editor.target, cols - 16)}</Text> : <Text color={theme.dim}>empty — press e</Text>, 'press e to edit')}
          {fieldRow(1, 'signal', <Text color={theme.accent}>{SIGNAL_LABEL[editor.signal]}</Text>, '←→ change')}
          {fieldRow(2, 'threshold', <Text color={theme.accent}>{`≥ ${editor.threshold}`}</Text>, '←→ ±5')}
          {fieldRow(3, 'window', <Text color={theme.accent}>{winLabel(editor.windowSeconds)}</Text>, '←→ change')}
          {editor.id
            ? fieldRow(4, 'status', editor.enabled ? <Text color={theme.ok}>on</Text> : <Text color={theme.dim}>off</Text>, '←→ turn on/off')
            : null}
        </Box>
        <Box marginTop={1}>
          {editor.id && !editor.enabled ? (
            <Text color={theme.warn}>disabled — this alert will NOT fire until you set status back to on</Text>
          ) : (
            <Text color={theme.dim}>
              fires when <Text color={theme.accent}>{SIGNAL_LABEL[editor.signal]}</Text> reach <Text color={theme.accent}>{editor.threshold}</Text> within{' '}
              <Text color={theme.accent}>{winLabel(editor.windowSeconds)}</Text>
            </Text>
          )}
        </Box>
      </Box>
    );
  }

  const loading =
    !locked &&
    ((localQ.loading && !localQ.data) || (whQ.loading && !whQ.data) || (alertQ.loading && !alertQ.data) || (guardQ.loading && !guardQ.data) || (selfQ.loading && !selfQ.data));
  const rawError = locked ? null : localQ.error ?? whQ.error ?? alertQ.error ?? guardQ.error ?? selfQ.error;
  // An AUTH failure must never take the panel over. Every cloud loader here 401s
  // when the stored key is revoked or rotated, and DataView renders the error
  // INSTEAD of the rows — which hides the Accounts section, i.e. the only way to
  // remove the dead account and pair again. A device revoked from the dashboard
  // was then stuck: the CLI said "Invalid API key. Run `solongate` and log in
  // from the Accounts panel" while that panel showed nothing but that sentence.
  // So: keep rendering (accounts + the local guard rows still work offline) and
  // carry the auth problem as a banner with the actual way out.
  const authError = rawError && /invalid api key|authentication|401|unauthor|not logged in/i.test(rawError) ? rawError : null;
  // Two different problems, two different ways out: a key that exists and is
  // rejected, versus no key at all. Telling someone already inside the dataroom
  // to "run solongate" is the message that made this look broken.
  const noKey = !!authError && /not logged in/i.test(authError);
  const error = authError ? null : rawError;

  const onOff = (on: boolean) => (on ? <Text color={theme.ok}>on </Text> : <Text color={theme.dim}>off</Text>);
  const chanOf = (rule: AlertRule): string =>
    [...(rule.emails ?? []), ...(rule.telegram ?? []).map((t) => 'tg ' + t)].join(', ') || '—';

  // ── one line per row (the panel is a single scrollable list) ──────────────
  const isCur = (r: Row) => keyOf(r) === keyOf(cur) && focused;
  const cursor = (r: Row) => <Text color={isCur(r) ? theme.accentBright : theme.dim}>{isCur(r) ? '▸ ' : '  '}</Text>;
  const rowLine = (r: Row): JSX.Element => {
    switch (r.kind) {
      case 'acct': {
        const a = r.acc;
        const isView = viewApiKey ? a.apiKey === viewApiKey : accounts[0]?.apiKey === a.apiKey;
        const isActive = isActiveAccount(a.apiKey);
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.accent}>{truncate(acctLabel(a), 30).padEnd(31)}</Text>
            {isView ? <Text color={theme.ok}>● viewing </Text> : <Text color={theme.dim}>{'          '}</Text>}
            {isActive ? <Text color={theme.warn}>ACTIVE </Text> : <Text color={theme.dim}>{'       '}</Text>}
            <Text color={theme.dim}>{a.project ? truncate(a.project, 20) : ''}</Text>
          </Text>
        );
      }
      case 'acct-add':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>+ add account (enter — device login in the browser)</Text>
          </Text>
        );
      case 'guard':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'guard'.padEnd(11)}</Text>
            {!guardHere ? (
              <>
                <Text color={theme.bad} bold>removed</Text>
                <Text color={theme.dim}>{' · '}</Text>
                <Text color={theme.accentBright}>enter to install</Text>
              </>
            ) : (
              <>
                <Text color={guardOld ? theme.warn : theme.ok}>{`v${guardVer ?? '?'}`}</Text>
                <Text color={theme.dim}>{guardOld ? ' · update available · enter update' : ' (latest) · enter reinstall'}</Text>
                <Text color={theme.dim}>{' · d remove'}</Text>
                {codexTrust ? <Text color={theme.warn}>{' · codex: run /hooks once to trust'}</Text> : null}
              </>
            )}
          </Text>
        );
      case 'self':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'self-prot'.padEnd(11)}</Text>
            {selfProt ? onOff(selfProt.enabled) : <Text color={theme.dim}>…</Text>}
            <Text color={theme.dim}>{'   blocks agents editing SolonGate’s own hooks/config · enter toggles'}</Text>
          </Text>
        );
      case 'doctor':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'doctor'.padEnd(11)}</Text>
            {diagBusy === 'doctor' ? (
              <Text color={theme.accentBright}>{`${spin} running health check…`}</Text>
            ) : (
              <Text color={theme.dim}>health check: login, policy, guard, hooks, local logs · enter runs it</Text>
            )}
          </Text>
        );
      case 'repair':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'repair'.padEnd(11)}</Text>
            {diagBusy === 'repair' ? (
              <Text color={theme.accentBright}>{`${spin} restoring protection…`}</Text>
            ) : (
              <Text color={theme.dim}>restore every protection file after tampering or deletion · enter runs it</Text>
            )}
          </Text>
        );
      case 'cli-update': {
        const behind = latest ? newerThan(latest, ver) : false;
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'version'.padEnd(11)}</Text>
            <Text color={behind ? theme.warn : theme.ok}>{`v${ver}`}</Text>
            {updBusy ? (
              <Text color={theme.accentBright}>{`   ${spin} updating…`}</Text>
            ) : behind && canInstall === false ? (
              // Said before they press enter, not after a minute of npm noise.
              <Text color={theme.warn}>{`   v${latest} on npm · needs sudo here · enter shows how`}</Text>
            ) : behind ? (
              <Text color={theme.dim}>{`   v${latest} on npm · enter updates now`}</Text>
            ) : (
              <Text color={theme.dim}>{latest ? '   latest · enter checks again' : '   enter checks npm and updates'}</Text>
            )}
          </Text>
        );
      }
      case 'auto-update':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'auto'.padEnd(11)}</Text>
            {onOff(autoUp)}
            <Text color={theme.dim}>
              {autoUpdateForcedByEnv()
                ? '   set by SOLONGATE_AUTO_UPDATE'
                : canInstall === false
                  ? '   cannot work here: npm needs sudo, so updates stay manual · enter toggles'
                  : autoUp
                    ? '   installs new versions in the background · enter toggles'
                    : '   off: nothing installs on its own (npm -g may need sudo) · enter toggles'}
            </Text>
          </Text>
        );
      case 'll-enabled':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'enabled '.padEnd(11)}</Text>
            {onOff(!!local?.enabled)}
            <Text color={theme.dim}>{'   enter toggles'}</Text>
          </Text>
        );
      case 'll-path':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'path '.padEnd(11)}</Text>
            {local?.path ? (
              // The folder is a PROJECT setting shared by every device on it, so
              // it can name a path that only exists on another OS. The hooks then
              // quietly fall back and this row was the last place still claiming
              // the configured path was in use.
              llSetting && local.enabled && !llSetting.usableHere ? (
                <>
                  <Text color={theme.warn}>{truncate(local.path, Math.max(12, Math.floor((cols - 20) / 2)))}</Text>
                  <Text color={theme.dim}>{`  not valid here → ${truncate(llSetting.file, Math.max(12, Math.floor((cols - 20) / 2)))}`}</Text>
                </>
              ) : (
                <Text color={theme.accent}>{truncate(local.path, cols - 14)}</Text>
              )
            ) : (
              <Text color={theme.dim}>not set — enter to edit</Text>
            )}
          </Text>
        );
      case 'll-server':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>{'dashboard'.padEnd(11)}</Text>
            {srv.running ? <Text color={theme.ok}>{`running 127.0.0.1:${srv.port}`}</Text> : <Text color={theme.dim}>stopped</Text>}
            <Text color={theme.dim}>{srv.running ? '   survives closing the dataroom · enter stops' : '   enter starts the dashboard local-logs link'}</Text>
          </Text>
        );
      case 'wh':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            {onOff(r.wh.enabled)}
            <Text color={theme.warn}>{(' ' + r.wh.events).padEnd(9)}</Text>
            <Text color={theme.accent}>{truncate(r.wh.url, cols - 16)}</Text>
          </Text>
        );
      case 'wh-add':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>+ add webhook (enter)</Text>
          </Text>
        );
      case 'alert':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            {onOff(r.rule.enabled)}
            <Text color={theme.warn}>{(' ' + SIGNAL_LABEL[r.rule.signal]).padEnd(13)}</Text>
            <Text>{`≥${r.rule.threshold}/${winLabel(r.rule.windowSeconds)} `.padEnd(11)}</Text>
            <Text color={theme.accent}>{truncate(chanOf(r.rule), cols - 34)}</Text>
          </Text>
        );
      case 'alert-add-email':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>+ add email alert (enter)</Text>
          </Text>
        );
      case 'alert-add-tg':
        return (
          <Text wrap="truncate">
            {cursor(r)}
            <Text color={theme.dim}>+ add telegram alert (enter — numeric chat id from @userinfobot)</Text>
          </Text>
        );
    }
  };

  const sectionOf = (r: Row): string =>
    r.kind === 'acct' || r.kind === 'acct-add'
      ? 'ACCOUNTS'
      : r.kind === 'guard' || r.kind === 'self' || r.kind === 'doctor' || r.kind === 'repair'
        ? 'PROTECTION'
        : r.kind === 'cli-update' || r.kind === 'auto-update'
          ? 'UPDATES'
          : r.kind === 'll-enabled' || r.kind === 'll-path' || r.kind === 'll-server'
            ? 'LOCAL LOGS'
            : r.kind === 'wh' || r.kind === 'wh-add'
              ? 'WEBHOOKS'
              : 'ALERTS';
  const SECTION_DESC: Record<string, string> = {
    ACCOUNTS: `on this device (${accounts.length}) · ● viewing · ACTIVE = guard key · x removes`,
    PROTECTION: 'guard hook: enter install/update · d remove · self-protection · doctor + repair',
    UPDATES: 'the solongate CLI itself · background auto-update is off unless you turn it on',
    'LOCAL LOGS': 'mirror every decision to a file + dashboard link',
    WEBHOOKS: `POST events to a URL (${webhooks.length}) · t tests`,
    ALERTS: `one email + one telegram (${alerts.length}) · enter edits · m on/off`,
  };

  // Flatten rows + section headers into ONE line list, then window it around the
  // selected row so the panel never exceeds its box (that overflow is what slid
  // the banner). Section headers travel with their rows.
  const lineEls: JSX.Element[] = [];
  const lineKey: string[] = []; // '' for a header line, else the row key
  let lastSec = '';
  rowsAll.forEach((r) => {
    const sec = sectionOf(r);
    if (sec !== lastSec) {
      // Blank spacer before every section header (except the first) so the
      // sections breathe instead of running together.
      if (lastSec) {
        lineEls.push(<Text key={'sp:' + sec}> </Text>);
        lineKey.push('');
      }
      lastSec = sec;
      lineEls.push(
        <Text key={'h:' + sec} wrap="truncate">
          <Text bold color={theme.accentBright}>
            {sec}
          </Text>
          <Text color={theme.dim}>{'  — ' + SECTION_DESC[sec]}</Text>
        </Text>,
      );
      lineKey.push('');
      // Cloud notifications (webhooks + alerts) fire server-side off the cloud
      // audit POST — which the guard SKIPS in local-log mode. Warn so it's not a
      // silent no-op; the t test still delivers (it posts directly).
      if ((sec === 'WEBHOOKS' || sec === 'ALERTS') && local?.enabled) {
        lineEls.push(
          <Text key={'warn:' + sec} wrap="truncate" color={theme.warn}>
            {`  ⚠ local logs on — real denials stay on this machine, so ${sec.toLowerCase()} do NOT fire${sec === 'WEBHOOKS' ? ' (t test still works)' : ''}`}
          </Text>,
        );
        lineKey.push('');
      }
    }
    lineEls.push(<Box key={keyOf(r)}>{rowLine(r)}</Box>);
    lineKey.push(keyOf(r));
    // While a run is in flight, the step list replaces the results underneath
    // the row: done steps tick, the current one spins, the rest sit dim.
    if ((r.kind === 'doctor' || r.kind === 'repair') && diagBusy === r.kind) {
      DIAG_STEPS[r.kind].forEach((label, i) => {
        const done = i < diagStep;
        lineEls.push(
          <Text key={`step:${r.kind}:${i}`} wrap="truncate" color={done ? theme.ok : i === diagStep ? theme.accentBright : theme.dim}>
            {`      ${done ? '✓' : i === diagStep ? spin : ' '} ${label}`}
          </Text>,
        );
        lineKey.push('');
      });
    }
    // Read-only result lines from the last doctor / repair run, directly under
    // the row that produced them. '' in lineKey keeps them unselectable.
    if (diag && ((r.kind === 'doctor' && diag.of === 'doctor') || (r.kind === 'repair' && diag.of === 'repair') || (r.kind === 'cli-update' && diag.of === 'cli-update'))) {
      diag.lines.forEach((l, i) => {
        lineEls.push(
          <Text
            key={`diag:${diag.of}:${i}`}
            wrap="truncate"
            color={l.level === 'ok' ? theme.ok : l.level === 'warn' ? theme.warn : l.level === 'bad' ? theme.bad : theme.dim}
          >
            {'    ' + l.text}
          </Text>,
        );
        lineKey.push('');
      });
    }
  });
  if (hasEmailAlert && hasTgAlert) {
    lineEls.push(
      <Text key="both-note" color={theme.dim}>
        {'  both channels in use — remove one (d) to change it'}
      </Text>,
    );
    lineKey.push('');
  }

  // Version, at the very bottom of the scrollable list (scroll down to see it).
  lineEls.push(<Text key="ver-sp"> </Text>);
  lineKey.push('');
  lineEls.push(
    <Text key="ver" wrap="truncate" color={theme.dim}>
      {`solongate v${ver}`}
      {latest
        ? newerThan(latest, ver)
          ? <Text color={theme.warn}>{`  · v${latest} on npm — ${autoUp ? 'auto-updating' : 'UPDATES above'}`}</Text>
          : <Text color={theme.ok}>{'  · latest'}</Text>
        : null}
    </Text>,
  );
  lineKey.push('');

  // hint + status line consume 2; the auth banner (when shown) takes one more —
  // the panel must not grow, or the frame exceeds its height and ink repaints
  // the whole terminal on every render.
  const budget = Math.max(4, rows - 2 - (authError ? 1 : 0));
  const selLine = Math.max(0, lineKey.indexOf(keyOf(cur)));
  const maxStart = Math.max(0, lineEls.length - budget);
  const startL = Math.min(Math.max(0, selLine - Math.floor(budget / 2)), maxStart);
  const win = lineEls.slice(startL, startL + budget);
  const moreAbove = startL;
  const moreBelow = Math.max(0, lineEls.length - (startL + budget));

  return (
    <DataView loading={loading} error={error}>
      <Box flexDirection="column">
        <Text wrap="truncate" color={theme.dim}>
          {focused
            ? `↑↓ move · enter act · m toggle · t test · e edit · x remove · d delete · n add${moreAbove ? ` · ▲${moreAbove}` : ''}${moreBelow ? ` · ▼${moreBelow}` : ''}`
            : 'press → to configure'}
        </Text>

        {authError ? (
          <Text wrap="truncate" color={theme.bad}>
            {truncate(
              noKey
                ? '✗ this device is not paired yet — press + add account below to sign in and pair it'
                : '✗ this device\'s key is invalid or was revoked — press x on the account below to remove it, then + add account to pair again',
              cols,
            )}
          </Text>
        ) : null}

        {editing ? (
          <Box>
            <Text color={theme.warn}>{editing === 'path' ? 'local log path: ' : 'webhook url: '}</Text>
            <TextInput value={input} onChange={setInput} onSubmit={submitInput} />
          </Box>
        ) : msg ? (
          <Text wrap="truncate" color={msg.level === 'bad' ? theme.bad : theme.ok}>{truncate(msg.text, cols)}</Text>
        ) : login?.msg ? (
          <Text wrap="truncate" color={login.phase === 'error' ? theme.bad : theme.ok}>{login.msg}</Text>
        ) : (
          <Text> </Text>
        )}

        <Box flexDirection="column" height={budget} overflow="hidden">
          {win}
        </Box>
      </Box>
    </DataView>
  );
}
