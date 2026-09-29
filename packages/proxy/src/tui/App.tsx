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
import { api } from '../api-client/index.js';

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


export function App(): JSX.Element {
  const { exit } = useApp();
  // viewNonce remounts every panel, so a change made in one is refetched by the
  // rest. It used to exist for switching between accounts; it still earns its
  // keep, because Settings can delete the policy the other panels are showing.
  const [viewNonce, setViewNonce] = useState(0);
  const [section, setSection] = useState(0);
  const [focus, setFocus] = useState<'nav' | 'panel'>('nav');

  const [help, setHelp] = useState(false);

  // What is being enforced, which is what an account label used to occupy. Read
  // from the policy file, and re-read on viewNonce so deleting the policy in
  // Settings is reflected here rather than leaving a name for a file that is gone.
  const [policyLabel, setPolicyLabel] = useState('reading…');
  useEffect(() => {
    let alive = true;
    api.policies
      .list()
      .then(({ policies }) => {
        if (!alive) return;
        const p = policies[0];
        setPolicyLabel(p ? `${p.name} · ${p.rules.length} ${p.rules.length === 1 ? 'rule' : 'rules'}` : 'none yet');
      })
      .catch((e: unknown) => {
        // An unreadable file is worth saying out loud: the guard reads the same
        // one and enforces nothing when it cannot parse it.
        if (alive) setPolicyLabel(e instanceof Error ? e.message.slice(0, 60) : 'unreadable');
      });
    return () => {
      alive = false;
    };
  }, [viewNonce]);

  const effectiveSection = section;

  useInput((input, key) => {
    if (help) {
      setHelp(false);
      return;
    }
    if (input === '?' && focus === 'nav') {
      setHelp(true);
      return;
    }
    if (focus === 'nav') {
      if (key.upArrow) setSection((n) => (n - 1 + SECTIONS.length) % SECTIONS.length);
      else if (key.downArrow) setSection((n) => (n + 1) % SECTIONS.length);
      else if (key.rightArrow || key.return || key.tab) setFocus('panel');
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
      <SettingsPanel active focused={focus === 'panel'} onChanged={() => setViewNonce((n) => n + 1)} />
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
        <Text color={theme.dim}>policy: </Text>
        <Text color={theme.accentBright} bold>
          {policyLabel}
        </Text>
        <Text color={theme.dim}>{'  · this machine, nothing leaves it'}</Text>
      </Text>

      <Box key={viewNonce} marginTop={1} flexGrow={1}>
        {/* flexShrink=0: pin the nav at 16 cols. Without it, a panel with very
            wide rows (Audit's dated stream lines) inflates the panel's min-content
            width and Yoga shrinks this fixed-width sibling — the sidebar visibly
            resizes as you move between sections. */}
        <Box flexDirection="column" flexShrink={0} width={16} borderStyle="round" borderColor={focus === 'nav' ? theme.accent : 'gray'} paddingX={1}>
          {SECTIONS.map((s, i) => {
            const isCur = i === effectiveSection;
            return (
              <Text key={s.label} color={isCur ? theme.accentBright : undefined} bold={isCur}>
                {(isCur ? '▸ ' : '  ') + s.label}
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
        {focus === 'nav' ? (
          <KeyHints hints={[['↑↓', 'section'], ['→/enter', 'open'], ['?', 'help'], ['q', 'quit']]} />
        ) : (
          <KeyHints hints={[['←/esc', 'back'], ['↑↓', 'in-panel'], ['space/s', 'act']]} />
        )}
      </Box>
    </Box>
  );
}

const HELP: Array<[string, Array<[string, string]>]> = [
  ['Global', [['↑↓', 'move between sections'], ['→ / enter', 'open a section'], ['← / esc', 'back to the menu'], ['?', 'this help'], ['q', 'quit']]],
  ['Solo Live', [['↑↓', 'select a stream row'], ['enter', 'full entry content'], ['w', 'whitelist the selected DENY'], ['b', 'block the selected ALLOW'], ['d / x / r', 'filter denies / dlp / rate-limit'], ['/', 'search'], ['space', 'copy mode (freeze)']]],
  ['Policies', [['↑↓', 'browse / select'], ['a', 'activate (pin) selected policy'], ['x', 'deactivate — no active policy'], ['enter', 'open rules → open a rule'], ['space', 'toggle a rule on/off'], ['e', 'flip effect'], ['n', 'new rule'], ['d', 'delete rule'], ['m', 'flip mode'], ['s', 'save'], ['x', 'discard']]],
  ['Rate limit', [['↑↓', 'field'], ['←→', 'adjust (shift = ±10)'], ['s', 'save']]],
  ['DLP', [['↑↓', 'move'], ['space', 'toggle a built-in pattern on/off'], ['m', 'cycle mode'], ['a', 'add custom pattern (name → glob, * = any chars)'], ['d', 'remove custom pattern'], ['s', 'save · x discard']]],
  ['Audit', [['← →', 'prev / next page (500 each)'], ['↑↓', 'select (list scrolls)'], ['enter', 'full entry'], ['f / g', 'decision / signal filter'], ['t / n / /', 'tool / agent / search'], ['x / X', 'delete entry / ALL (press twice)'], ['c', 'clear filters']]],
  ['Settings', [['↑↓', 'move'], ['enter / space', 'toggle · edit'], ['e', 'edit the log folder'], ['d d', 'delete'], ['r', 'refresh']]],
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
