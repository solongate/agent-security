/**
 * SolonGate TUI shell — fullscreen app (alternate screen buffer).
 * Left nav + panel normally; the Live section takes over the ENTIRE terminal
 * when opened (esc/tab returns to the menu).
 */
import { Box, Text, useApp, useInput } from 'ink';
import { useEffect, useState } from 'react';
import { BANNER_FULL } from '../cli-utils.js';
import { KeyHints } from './components.js';
import { theme } from './theme.js';
import { LivePanel } from './panels/Live.js';
import { PoliciesPanel } from './panels/Policies.js';
import { RateLimitPanel } from './panels/RateLimit.js';
import { DlpPanel } from './panels/Dlp.js';
import { AuditPanel } from './panels/Audit.js';
import { SettingsPanel } from './panels/Settings.js';
import { useTermSize } from './hooks.js';
import { enforcingKey, listAccounts, saveAccount, setViewCredentials } from '../api-client/client.js';
import type { SavedAccount } from '../api-client/client.js';
import { api } from '../api-client/index.js';
import { ensureLocalLogOwner } from './local-log.js';

type PanelComponent = (props: { active: boolean; focused: boolean }) => JSX.Element;

/** Shown in the boxed layout while Solo Live is selected but not yet opened. */
function LiveHint(): JSX.Element {
  return (
    <Box flexDirection="column">
      <Text color={theme.accentBright} bold>
        ▶ REALTIME CONSOLE — THIS MACHINE
      </Text>
      <Text color={theme.dim}>Fullscreen live monitor — streaming tool calls, active charts,</Text>
      <Text color={theme.dim}>counters, DLP hits and denial alerts. Updates every 2s.</Text>
      <Box marginTop={1}>
        <Text>
          press <Text color={theme.accent}>enter</Text> to go live
        </Text>
      </Box>
    </Box>
  );
}

/** The sections. */
const SECTIONS: Array<{ label: string; Panel: PanelComponent }> = [
  { label: 'Solo Live', Panel: LiveHint as PanelComponent },
  { label: 'Policies', Panel: PoliciesPanel },
  { label: 'Rate Limit', Panel: RateLimitPanel },
  { label: 'DLP', Panel: DlpPanel },
  { label: 'Audit', Panel: AuditPanel },
  { label: 'Settings', Panel: SettingsPanel },
];

/** The label that takes over the whole terminal when opened. */
const TAKEOVER = new Set(['Solo Live']);

const BANNER_HEX = ['white', 'white', 'white', 'white', 'white', 'white'];

function Banner({ cols }: { cols: number }): JSX.Element {
  const wide = cols >= 82;
  if (!wide) {
    return (
      <Box>
        <Text bold color={theme.accentBright}>
          SolonGate
        </Text>
        <Text color={theme.dim}> — security control center</Text>
      </Box>
    );
  }
  return (
    <Box flexDirection="column">
      {BANNER_FULL.map((line, i) => (
        <Text key={i} bold color={BANNER_HEX[i]}>
          {line}
        </Text>
      ))}
      <Text color={theme.dim}> security control center · manage policies, rate limits, DLP & more</Text>
    </Box>
  );
}

const SETTINGS_SECTION = SECTIONS.findIndex((s) => s.label === 'Settings');

export function App(): JSX.Element {
  const { exit } = useApp();
  // Accounts logged in on this device. `a` cycles which one the dataroom VIEWS
  // (data only — the guard hooks keep using the active key). Bumping viewNonce
  // remounts every panel so it refetches for the newly-viewed account.
  const [accounts, setAccounts] = useState<SavedAccount[]>(() => listAccounts());
  const [viewKey, setViewKey] = useState<string | undefined>(() => accounts[0]?.apiKey);
  const [viewNonce, setViewNonce] = useState(0);
  // With no account yet, land on Settings so the user can log in from here.
  const [section, setSection] = useState(accounts.length === 0 ? SETTINGS_SECTION : 0);
  const [focus, setFocus] = useState<'nav' | 'panel'>('nav');

  const [help, setHelp] = useState(false);

  const acctIdx = Math.max(0, accounts.findIndex((a) => a.apiKey === viewKey));
  const cur = accounts[acctIdx];
  // The account label is the PERSON, not the project: e-mail first (that's who
  // is logged in), then user name, then project. NEVER the API key — until the
  // identity resolves (or offline) show a neutral key-tail reference. Identity
  // comes from /auth/me once and is persisted to accounts.json.
  const rawEmail = cur?.email ?? '';
  // A saved row is not the same as a working session. When the key behind it is
  // gone (signed out elsewhere, revoked, pairing never finished) the header used
  // to keep naming the account while every panel said the opposite, which read
  // as a bug rather than as "you need to sign in".
  const acctLabel = !cur
    ? 'not logged in'
    : rawEmail || cur.user || cur.project || `account …${cur.apiKey.slice(-4)}`;

  useEffect(() => {
    if (!cur || cur.email) return; // e-mail is the primary label — backfill until we have it
    let alive = true;
    api.auth
      .me()
      .then((r) => {
        const project = r.project?.name || cur.project;
        const user = r.user?.name || cur.user;
        const email = r.user?.email || undefined;
        if (!alive || (!project && !user && !email)) return;
        saveAccount({ ...cur, project, user, email });
        setAccounts(listAccounts());
      })
      .catch(() => {
        /* offline — current label stays */
      });
    return () => {
      alive = false;
    };
  }, [cur]);

  const viewAccount = (a: SavedAccount) => {
    setViewCredentials({ apiKey: a.apiKey, apiUrl: a.apiUrl });
    setAccounts(listAccounts());
    setViewKey(a.apiKey);
    setViewNonce((n) => n + 1);
  };
  const switchAccount = () => {
    if (accounts.length < 2) return;
    viewAccount(accounts[(acctIdx + 1) % accounts.length]!);
  };
  // Settings calls this after it mutates the on-disk account set (remove /
  // sign-out). Re-derive from disk so the header, the account count and the
  // locked state stay in lockstep — falling back to a surviving account, or
  // clearing the view entirely when the last account was removed.
  const syncAccounts = () => {
    const list = listAccounts();
    setAccounts(list);
    const next = list.find((a) => a.apiKey === viewKey) ?? list[0];
    setViewCredentials(next ? { apiKey: next.apiKey, apiUrl: next.apiUrl } : null);
    setViewKey(next?.apiKey);
    setViewNonce((n) => n + 1);
  };

  // Locked until a device is paired: with no account, ONLY the Settings panel
  // is reachable — every other section is inert (nothing to show without a key).
  // Accounts on file is the whole test. A selected account is used through the
  // viewing credential, which is module state rather than React state, so
  // reading it during render returned "no key" on the first pass and never
  // corrected itself — the dataroom locked itself out of an account that
  // worked perfectly well.
  // Before any panel reads it, make sure the machine-local log belongs to the
  // account in use — it is one file per machine and carries no account of its
  // own, so a newly paired account would otherwise open onto the last one's
  // calls.
  useEffect(() => {
    try { ensureLocalLogOwner(enforcingKey()); } catch { /* nothing to reconcile */ }
  }, [accounts.length]);

  const locked = accounts.length === 0;
  const effectiveSection = locked ? SETTINGS_SECTION : section;

  useInput((input, key) => {
    if (help) {
      setHelp(false);
      return;
    }
    if (input === '?' && focus === 'nav') {
      setHelp(true);
      return;
    }
    if (locked) {
      // Only entering the Settings panel (and quitting) is allowed.
      if (key.rightArrow || key.return || key.tab) setFocus('panel');
      else if (key.escape) setFocus('nav');
      else if ((input === 'q' || input === 'Q') && focus === 'nav') exit();
      return;
    }
    if (focus === 'nav') {
      if (key.upArrow) setSection((n) => (n - 1 + SECTIONS.length) % SECTIONS.length);
      else if (key.downArrow) setSection((n) => (n + 1) % SECTIONS.length);
      else if (key.rightArrow || key.return || key.tab) setFocus('panel');
      else if (input === 'a' || input === 'A') switchAccount();
      else if ((input === 'q' || input === 'Q')) exit();
    } else {
      if (key.escape || key.tab) setFocus('nav');
      else if ((input === 'q' || input === 'Q') && SECTIONS[section]!.label === 'Live') exit();
    }
  });

  const { cols, rows } = useTermSize();
  const current = SECTIONS[effectiveSection]!;

  if (help) return <HelpOverlay cols={cols} rows={rows} />;

  // ── Live takeover: the console owns the whole terminal ──────────────────
  if (TAKEOVER.has(current.label) && focus === 'panel') {
    // rows - 1, NOT rows: ink falls back to clearTerminal + full rewrite on
    // EVERY render once outputHeight >= stdout.rows (ink.js), which flickers
    // visibly whenever bright content (RL/DLP columns, alert banners) is on
    // screen. One row of headroom keeps ink on its diff path. overflow hidden
    // makes that a hard guarantee even if a panel miscounts its budget.
    return (
      <Box flexDirection="column" width={cols} height={rows - 1} overflow="hidden">
        <LivePanel key={viewNonce} active focused />
      </Box>
    );
  }

  const Panel = current.Panel;
  const panelBody =
    current.label === 'Settings' ? (
      <SettingsPanel active focused={focus === 'panel'} viewApiKey={viewKey} onView={viewAccount} onAccountsChanged={syncAccounts} />
    ) : (
      <Panel active={focus === 'panel' || !TAKEOVER.has(current.label)} focused={focus === 'panel'} />
    );
  return (
    // height rows-1 (not rows): once total output reaches stdout.rows ink stops
    // diffing and clearTerminal-repaints every frame, which slides the banner.
    // overflow hidden makes it a hard guarantee even if a panel over-renders.
    <Box flexDirection="column" width={cols} height={rows - 1} paddingX={1} paddingTop={1} overflow="hidden">
      <Banner cols={cols} />

      <Text wrap="truncate">
        <Text color={theme.dim}>account: </Text>
        <Text color={locked ? theme.warn : theme.accentBright} bold>
          {acctLabel}
        </Text>
        {locked ? (
          <Text color={theme.dim}>{'  · log in from Settings to unlock the dataroom'}</Text>
        ) : accounts.length > 1 ? (
          <Text color={theme.dim}>{`  (${acctIdx + 1}/${accounts.length} · a switch · Settings to manage)`}</Text>
        ) : (
          <Text color={theme.dim}>{'  · Settings to add another'}</Text>
        )}
      </Text>

      <Box key={viewNonce} marginTop={1} flexGrow={1}>
        {/* flexShrink=0: pin the nav at 16 cols. Without it, a panel with very
            wide rows (Audit's dated stream lines) inflates the panel's min-content
            width and Yoga shrinks this fixed-width sibling — the sidebar visibly
            resizes as you move between sections. */}
        <Box flexDirection="column" flexShrink={0} width={16} borderStyle="round" borderColor={focus === 'nav' ? theme.accent : 'gray'} paddingX={1}>
          {SECTIONS.map((s, i) => {
            // When locked, only Settings is reachable — dim the rest with a lock.
            const isCur = i === effectiveSection;
            const disabled = locked && s.label !== 'Settings';
            return (
              <Text key={s.label} color={isCur ? theme.accentBright : disabled ? theme.dim : undefined} bold={isCur} dimColor={disabled}>
                {(isCur ? '▸ ' : disabled ? '⊘ ' : '  ') + s.label}
              </Text>
            );
          })}
        </Box>

        {/* minWidth=0 lets this flex child shrink below its content's intrinsic
            width so wide rows truncate (overflow hidden) instead of pushing the
            layout and squeezing the nav. */}
        <Box flexGrow={1} minWidth={0} borderStyle="round" borderColor={focus === 'panel' ? theme.accent : 'gray'} paddingX={1} paddingY={0} overflow="hidden">
          {panelBody}
        </Box>
      </Box>

      <Box>
        {locked ? (
          <KeyHints hints={[['→/enter', 'open Settings'], ['n', 'log in'], ['q', 'quit']]} />
        ) : focus === 'nav' ? (
          <KeyHints hints={[['↑↓', 'section'], ['→/enter', 'open'], ...(accounts.length > 1 ? [['a', 'account'] as [string, string]] : []), ['?', 'help'], ['q', 'quit']]} />
        ) : (
          <KeyHints hints={[['←/esc', 'back'], ['↑↓', 'in-panel'], ['space/s', 'act']]} />
        )}
      </Box>
    </Box>
  );
}

const HELP: Array<[string, Array<[string, string]>]> = [
  ['Global', [['↑↓', 'move between sections'], ['→ / enter', 'open a section'], ['← / esc', 'back to the menu'], ['?', 'this help'], ['q', 'quit']]],
  ['Solo Live', [['↑↓', 'select a stream row'], ['enter', 'full entry content'], ['w', 'whitelist the selected DENY'], ['b', 'block the selected ALLOW'], ['d / x / r', 'filter denies / dlp / rate-limit'], ['f', 'local / cloud filter'], ['/', 'search'], ['space', 'copy mode (freeze)']]],
  ['Policies', [['↑↓', 'browse / select'], ['a', 'activate (pin) selected policy'], ['x', 'deactivate — no active policy'], ['enter', 'open rules → open a rule'], ['space', 'toggle a rule on/off'], ['e', 'flip effect'], ['n', 'new rule'], ['d', 'delete rule'], ['m', 'flip mode'], ['s', 'save'], ['x', 'discard']]],
  ['Rate limit', [['↑↓', 'field'], ['←→', 'adjust (shift = ±10)'], ['s', 'save']]],
  ['DLP', [['↑↓', 'move'], ['space', 'toggle a built-in pattern on/off'], ['m', 'cycle mode'], ['a', 'add custom pattern (name → glob, * = any chars)'], ['d', 'remove custom pattern'], ['s', 'save · x discard']]],
  ['Audit', [['s', 'source: cloud ↔ local'], ['← →', 'prev / next page (500 each)'], ['↑↓', 'select (list scrolls)'], ['enter', 'full entry'], ['f / g', 'decision / signal filter'], ['t / n / /', 'tool / agent / search'], ['x / X', 'delete entry / ALL (press twice)'], ['c', 'clear filters']]],
  ['Settings', [['↑↓', 'move'], ['enter / space', 'toggle · edit · add'], ['e', 'webhook events'], ['d d', 'delete'], ['r', 'refresh']]],
  ['Accounts', [['a', 'switch account (view another account logged in on this device)'], ['', 'the header shows which account you are viewing; guard/logging keep the active key']]],
];

function HelpOverlay({ cols, rows }: { cols: number; rows: number }): JSX.Element {
  return (
    <Box flexDirection="column" width={cols} height={rows} paddingX={2} paddingTop={1}>
      <Text bold color={theme.accentBright}>
        SolonGate — keyboard shortcuts
      </Text>
      <Box marginTop={1} flexDirection="column">
        {HELP.map(([group, keys]) => (
          <Box key={group} flexDirection="column" marginBottom={1}>
            <Text bold color={theme.accent}>
              {group}
            </Text>
            {keys.map(([k, desc]) => (
              <Text key={k}>
                <Text color={theme.accentBright}>{('  ' + k).padEnd(16)}</Text>
                <Text color={theme.dim}>{desc}</Text>
              </Text>
            ))}
          </Box>
        ))}
      </Box>
      <Text color={theme.dim}>press any key to close</Text>
    </Box>
  );
}
