/** `solongate doctor` - health check: login, active policy, guard, local logs. */
import { existsSync, readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { api } from '../api-client/index.js';
import { policyPath } from '../api-client/local-store.js';
import { codexDetected, codexHooksStatus, globalPaths, installedGuardVersion, isGuardInstalled, isOpencodeGuardInstalled, opencodeDetected } from '../global-install.js';
import { agoLabel, guardBeat, hookCanStart } from '../hook-health.js';
import { localLogFile } from '../tui/local-log.js';
import { bold, dim, err, green, printJson, red, yellow } from './format.js';
import { flagBool, parse } from './args.js';

export interface Check {
  name: string;
  ok: boolean | 'warn';
  detail: string;
}

/**
 * The health check itself, with no printing — so the same checks back both
 * `solongate doctor` and the Settings panel in the dataroom. Ink owns the
 * terminal while the TUI is up, so anything it calls must return data rather
 * than write to the stream.
 */
export async function collectChecks(): Promise<Check[]> {
  const checks: Check[] = [];

  // 1. the policy file, which is where everything below comes from
  {
    checks.push({ name: 'policy file', ok: true, detail: policyPath() });

    // 2. what the guard would enforce, read from that same file
    try {
      const active = await api.policies.active();
      if (active.policy) {
        checks.push({ name: 'active policy', ok: true, detail: `${active.policy.name} v${active.version} · ${active.policy.mode ?? 'denylist'} · matched by ${active.matched_by}` });
      } else {
        checks.push({ name: 'active policy', ok: 'warn', detail: 'no policy resolves - every call falls back to default' });
      }
      const sec = active.security;
      // Three states, and only one of them is "off". The limits ride in
      // `rateLimit` when they block and in `rateLimitObserve` when they only
      // flag, so reading the first alone reported a project in detect as off.
      const rlBlock = sec?.rateLimit;
      const rlObserve = (sec as { rateLimitObserve?: { perMinute?: number; perHour?: number; perDay?: number } } | null | undefined)?.rateLimitObserve;
      const rlWindows = (l: { perMinute?: number; perHour?: number; perDay?: number }): string =>
        [l.perMinute ? `${l.perMinute}/min` : '', l.perHour ? `${l.perHour}/hr` : '', l.perDay ? `${l.perDay}/day` : '']
          .filter(Boolean)
          .join(' · ') || 'no window set';
      checks.push(
        rlBlock
          ? { name: 'rate limit', ok: true, detail: `block · ${rlWindows(rlBlock)}` }
          : rlObserve
            ? { name: 'rate limit', ok: true, detail: `detect · ${rlWindows(rlObserve)} · flags bursts, never blocks` }
            : { name: 'rate limit', ok: 'warn', detail: 'off' },
      );
      // The middle state is stored as "redact" but is called detect everywhere a
      // user sees it, matching the other layers. Reporting the storage word here
      // made it look like a fourth mode that exists nowhere else.
      checks.push(
        sec?.dlpBlock
          ? { name: 'dlp', ok: true, detail: `block · ${sec.dlpBlock.patterns.length} patterns · refuses a call carrying one` }
          : sec?.dlpRedact
            ? { name: 'dlp', ok: true, detail: `redact · ${sec.dlpRedact.patterns.length} patterns · masks secrets, never blocks` }
            : sec?.dlpObserve
              ? { name: 'dlp', ok: true, detail: `detect · ${sec.dlpObserve.patterns.length} patterns · records hits, changes nothing` }
              : { name: 'dlp', ok: 'warn', detail: 'off' },
      );
      checks.push({ name: 'self-protection', ok: active.self_protection_enabled ? true : 'warn', detail: active.self_protection_enabled ? 'on' : 'off' });
    } catch (e) {
      // The guard reads this file too, and answers the same way: an unparseable
      // policy is no policy, so nothing is enforced. Worth a failed check.
      checks.push({ name: 'policy', ok: false, detail: e instanceof Error ? e.message : String(e) });
    }

    // 3. guard hook version
    try {
      const g = await api.settings.getGuardStatus();
      // What the cloud has on file is what this device last REPORTED, which
      // lags an update until the guard next runs and says so. Reading it as the
      // installed version made the health check announce an update that was
      // already applied, one line under the guard row saying it was current.
      // The file on disk is the fact; the cloud is only asked what the newest
      // release is.
      const here = installedGuardVersion();
      const latest = g.latest ?? here;
      const current = here != null && latest != null ? here >= latest : g.up_to_date;
      checks.push({
        name: 'guard hook',
        ok: current ? true : 'warn',
        detail: current
          ? `v${here ?? g.installed} (latest) · ${g.device_count} device(s)`
          : `v${here ?? g.installed} → v${latest} available · run \`solongate update\` in your terminal`,
      });
    } catch {
      /* non-fatal */
    }
  }

  // 4. One row per guarded client, named the way `repair` names them, so a
  // machine running several can see at a glance which one is unguarded. Each is
  // reported only when that client is actually installed here — a "not
  // registered" row for a tool nobody has is noise, not a finding.
  const claudeReg = isGuardInstalled();
  checks.push({
    name: 'Claude hooks',
    ok: claudeReg,
    detail: claudeReg ? 'guard registered' : 'guard NOT registered - run `solongate repair`',
  });

  // "Registered" was the only thing ever checked, and it is not the question.
  // The two rows below are: can the registered command actually start, and has
  // the client ever run it. A machine where the answer to the first is no looks
  // exactly like a machine with no guard on it — nothing is enforced, nothing
  // is logged, and this page used to say the guard was fine.
  if (claudeReg) {
    const start = hookCanStart();
    checks.push({
      name: 'hook runtime',
      ok: start.ok,
      detail: start.ok
        ? `node ${start.detail}`
        : `${start.detail} - nothing is being enforced or logged`,
    });

    const beat = guardBeat();
    if (!beat) {
      checks.push({
        name: 'guard fired',
        ok: 'warn',
        detail: 'never - open your agent and run one tool call, then check again',
      });
    } else if (beat.node === 'no-node') {
      checks.push({
        name: 'guard fired',
        ok: false,
        detail: `${agoLabel(beat.at)}, but found no node to run with - run \`solongate repair\``,
      });
    } else {
      checks.push({ name: 'guard fired', ok: true, detail: `${agoLabel(beat.at)} · ${beat.node}` });
    }
  }

  if (existsSync(globalPaths().antigravityDir)) {
    const reg = existsSync(globalPaths().antigravityHooksPath);
    checks.push({
      name: 'Antigravity hooks',
      ok: reg,
      detail: reg ? 'guard registered' : 'guard NOT registered - run `solongate repair`',
    });
  }

  // Codex skips a hook it has not been trusted for, so "registered" alone is
  // not enough to say the guard is live there.
  if (codexDetected()) {
    const cx = codexHooksStatus();
    if (!cx.registered) {
      checks.push({ name: 'Codex hooks', ok: false, detail: 'guard NOT registered - run `solongate repair`' });
    } else if (cx.disabled) {
      checks.push({ name: 'Codex hooks', ok: false, detail: 'hooks disabled in ~/.codex/config.toml ([features] hooks = false)' });
    } else if (!cx.trusted) {
      checks.push({ name: 'Codex hooks', ok: 'warn', detail: 'registered - run `/hooks` in Codex once and trust them (Codex skips untrusted hooks)' });
    } else {
      checks.push({ name: 'Codex hooks', ok: true, detail: 'registered + trusted' });
    }
  }

  // OpenCode loads the guard as a plugin module, so the file IS the
  // registration. `opencode --pure` skips external plugins and with them the
  // guard — a per-run flag no check here can see, so the row says so rather
  // than claiming a protection that one argument removes.
  if (opencodeDetected()) {
    const reg = isOpencodeGuardInstalled();
    checks.push({
      name: 'OpenCode hooks',
      ok: reg,
      detail: reg ? 'guard registered (not active under `opencode --pure`)' : 'guard NOT registered - run `solongate repair`',
    });
  }

  // 5. Did the cloud reject the credential a HOOK used? The hooks resolve their
  // key as env → the .env of the folder the agent runs in → the login, so a
  // stale key in a project (or home) .env makes every audit write 401 while
  // enforcement keeps working — invisible unless we say it out loud. The guard
  // drops this marker on a 401/403 and removes it on the next success.
  try {
    const raw = readFileSync(join(homedir(), '.solongate', '.key-rejected.json'), 'utf-8');
    const m = JSON.parse(raw) as { ts?: number; cwd?: string; keySource?: string; apiUrl?: string };
    const ageMin = m.ts ? Math.round((Date.now() - m.ts) / 60_000) : null;
    checks.push({
      name: 'hook credential',
      ok: false,
      detail: `rejected by ${m.apiUrl ?? 'the API'}${ageMin != null ? ` ${ageMin}m ago` : ''} · key from ${m.keySource ?? '?'}${m.cwd ? ` (agent cwd ${m.cwd})` : ''} - nothing is being logged from there`,
    });
  } catch {
    /* no marker → the last cloud call this device made was accepted */
  }

  // 6. local log storage (on-disk). The hooks append into the FOLDER configured
  // in the dashboard, so resolve that file rather than assuming the default.
  const LOCAL_LOG = localLogFile();
  if (existsSync(LOCAL_LOG)) {
    const st = statSync(LOCAL_LOG);
    const ageMin = (Date.now() - st.mtimeMs) / 60_000;
    checks.push({ name: 'local logs', ok: true, detail: `on · ${(st.size / 1024).toFixed(0)}KB · last write ${ageMin < 1 ? 'just now' : Math.round(ageMin) + 'm ago'}` });
  } else {
    checks.push({ name: 'local logs', ok: 'warn', detail: 'no folder configured — the default is ~/.solongate/local-logs' });
  }

  return checks;
}

export async function run(argv: string[]): Promise<number> {
  const { flags } = parse(argv);
  const json = flagBool(flags, 'json');
  const checks = await collectChecks();

  if (json) return printJson(checks), checks.some((c) => c.ok === false) ? 1 : 0;

  err('');
  err(`  ${bold('SolonGate doctor')}`);
  err('');
  for (const c of checks) {
    const mark = c.ok === true ? green('✓') : c.ok === 'warn' ? yellow('!') : red('✗');
    err(`  ${mark} ${c.name.padEnd(16)} ${dim(c.detail)}`);
  }
  err('');
  const bad = checks.filter((c) => c.ok === false).length;
  const warn = checks.filter((c) => c.ok === 'warn').length;
  if (bad) err(`  ${red(`${bad} problem(s)`)}${warn ? dim(` · ${warn} warning(s)`) : ''}`);
  else if (warn) err(`  ${yellow(`${warn} warning(s)`)} ${dim('- guard is working')}`);
  else err(`  ${green('all good')}`);
  return bad ? 1 : 0;
}
