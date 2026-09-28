/**
 * Settings panel — the dashboard Settings page, dataroom edition. Everything an
 * operator configures, in one single-cursor list (↑↓ move, enter/m act):
 *   GUARD           : the hook installed here, against the one this CLI ships
 *   SELF-PROTECTION : block agents from touching SolonGate's own files (toggle)
 *   LOCAL LOGS      : where the hooks write this machine's audit trail
 *
 * Keys: ↑↓ move · enter act/edit · m toggle · e edit · d remove the guard ·
 *   r refresh
 */
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { useEffect, useRef, useState } from 'react';
import { api } from '../../api-client/index.js';
import { codexDetected, codexHooksStatus, guardHookOutdated, installedGuardVersion, installGlobalQuiet, isGuardInstalled, repairQuiet, uninstallGlobalQuiet } from '../../global-install.js';
import { collectChecks } from '../../commands/doctor.js';
import { DataView } from '../components.js';
import { useLoader, usePanelSize } from '../hooks.js';
import { theme, truncate } from '../theme.js';
import { localLogsSetting, type LocalLogSetting } from '../local-log.js';

const SPIN = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

type Row =
  | { kind: 'guard' }
  | { kind: 'self' }
  | { kind: 'doctor' }
  | { kind: 'repair' }
  | { kind: 'll-enabled' }
  | { kind: 'll-path' }


export function SettingsPanel({
  active,
  focused,
  onChanged,
}: {
  active: boolean;
  focused: boolean;
  /** Fired after this panel changes something the other panels read, so the App
   *  shell can remount them. Deleting the policy from here is the case. */
  onChanged?: () => void;
}): JSX.Element {
  void active;
  const { cols, rows } = usePanelSize();
  const [sel, setSel] = useState(0);
  const [editing, setEditing] = useState<null | 'path'>(null);
  const [input, setInput] = useState('');
  const [confirmDel, setConfirmDel] = useState<string | null>(null); // row key awaiting 2nd d/x
  const [msg, setMsg] = useState<{ text: string; level: 'ok' | 'bad' } | null>(null);
  const [busy, setBusy] = useState(false);
  // Result of the last doctor / repair run, rendered as read-only lines under
  // the row that produced it. Kept here rather than printed, because Ink owns
  // the terminal — writing to the stream would tear the frame.
  const [diagBusy, setDiagBusy] = useState<null | 'doctor' | 'repair'>(null);
  // Background updater: opt-in, read from disk so it survives restarts. Held in
  // state so the row flips the instant it is toggled.
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
  const [diag, setDiag] = useState<null | { of: 'doctor' | 'repair'; lines: { text: string; level: 'ok' | 'warn' | 'bad' | 'dim' }[] }>(null);
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

  const [tick, setTick] = useState(0);
  // The guard as it is ON THIS MACHINE, read from its files. Reflects an install
  // or a removal instantly, and needs nothing but the disk.
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
  useEffect(() => {
    // The frame clock for the doctor/repair progress screen. An install is slow
    // enough that a frozen glyph would read as a hang.
    if (!diagBusy) return;
    const t = setInterval(() => setTick((n) => n + 1), 120);
    return () => clearInterval(t);
  }, [diagBusy]);

  // All three read this machine's own files. They were skipped while unpaired,
  // because each was an HTTP call that needed a key; there is nothing to skip.
  const localQ = useLoader(() => api.settings.getLocalLogs());
  const guardQ = useLoader(() => api.settings.getGuardStatus());
  const selfQ = useLoader(() => api.settings.getSelfProtection());

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
  const rowsAll: Row[] = [
    { kind: 'guard' },
    { kind: 'self' },
    { kind: 'doctor' },
    { kind: 'repair' },
    { kind: 'll-enabled' },
    { kind: 'll-path' },
  ];
  const selClamped = Math.min(sel, rowsAll.length - 1);
  const cur = rowsAll[selClamped]!;
  const keyOf = (r: Row): string => r.kind;

  const reloadAll = () => {
    localQ.reload();
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
        // Every change here lands in the file the other panels read — the layers
        // and the tamper flag live beside the policy — so they are remounted
        // rather than left showing what was true before.
        onChanged?.();
      })
      .catch((e: unknown) => setMsg({ text: '✗ ' + (e instanceof Error ? e.message : String(e)), level: 'bad' }))
      .finally(() => setBusy(false));
  };

  // ── row activation (enter) ────────────────────────────────────────────────
  const activate = (r: Row) => {
    if (r.kind === 'guard') {
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
    }
  };

  const submitInput = () => {
    const v = input.trim();
    const which = editing;
    setEditing(null);
    if (which === 'path') {
      const enabled = (local?.enabled ?? false) && v.length > 0;
      run(v ? `path saved${enabled ? '' : ' (press enter on enabled to turn on)'}` : 'path cleared (local logs off)', () => api.settings.setLocalLogs({ enabled, path: v }), localQ.reload);
    }
  };

  // ── keys ──────────────────────────────────────────────────────────────────
  useInput(
    (inp, key) => {
      setMsg(null);
      if (key.upArrow) {
        setSel((n) => Math.max(0, n - 1));
        setConfirmDel(null);
      } else if (key.downArrow) {
        setSel((n) => Math.min(rowsAll.length - 1, n + 1));
        setConfirmDel(null);
      } else if (key.return || inp === ' ') activate(cur);
      else if (inp === 'm') {
        if (cur.kind === 'self' || cur.kind === 'll-enabled') activate(cur);
      } else if (inp === 'e' && cur.kind === 'll-path') activate(cur);
      else if (inp === 'd' && cur.kind === 'guard') {
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
      } else if (inp === 'r') reloadAll();
    },
    { isActive: focused && !editing },
  );

  const spin = SPIN[tick % SPIN.length];


  const loading = (localQ.loading && !localQ.data) || (guardQ.loading && !guardQ.data) || (selfQ.loading && !selfQ.data);
  // An error must never take the panel over: DataView renders it INSTEAD of the
  // rows, and the rows are how somebody fixes whatever produced it. The one that
  // reaches here now is an unreadable policy file — and the guard reads that same
  // file, so hiding the rows would hide the only place to see that and repair it.
  const rawError = localQ.error ?? guardQ.error ?? selfQ.error;
  const authError = rawError && /invalid api key|authentication|401|unauthor|not logged in/i.test(rawError) ? rawError : null;
  // Two different problems, two different ways out: a key that exists and is
  // rejected, versus no key at all. Telling someone already inside the dataroom
  // to "run solongate" is the message that made this look broken.
  const noKey = !!authError && /not logged in/i.test(authError);
  const error = authError ? null : rawError;

  const onOff = (on: boolean) => (on ? <Text color={theme.ok}>on </Text> : <Text color={theme.dim}>off</Text>);

  // ── one line per row (the panel is a single scrollable list) ──────────────
  const isCur = (r: Row) => keyOf(r) === keyOf(cur) && focused;
  const cursor = (r: Row) => <Text color={isCur(r) ? theme.accentBright : theme.dim}>{isCur(r) ? '▸ ' : '  '}</Text>;
  const rowLine = (r: Row): JSX.Element => {
    switch (r.kind) {
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
    }
  };

  const sectionOf = (r: Row): string =>
    r.kind === 'guard' || r.kind === 'self' || r.kind === 'doctor' || r.kind === 'repair'
      ? 'PROTECTION'
      : 'LOCAL LOGS';
  const SECTION_DESC: Record<string, string> = {
    PROTECTION: 'guard hook: enter install/update · d remove · self-protection · doctor + repair',
    'LOCAL LOGS': 'where the hooks write this machine\'s audit trail',
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
    if (diag && ((r.kind === 'doctor' && diag.of === 'doctor') || (r.kind === 'repair' && diag.of === 'repair'))) {
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

  // Version, at the very bottom of the scrollable list (scroll down to see it).
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
