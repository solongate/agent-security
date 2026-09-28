/**
 * Audit panel — the Live console's tool stream, over the FULL history. Rows use
 * the SAME StreamLine renderer as Live ([HH:MM:SS LOC|CLD] DECISION tool perm
 * eval agent dlp: rl: {args}) and enter opens the SAME entry inspector; the only
 * thing Audit adds over Live is that it shows every log, not just the live
 * buffer: every call, newest first, 500 per page (←→ to page, selection jumps
 * to top on page change). Filters: f decision · g signal · t tool · n agent ·
 * / search · c clear. enter = full entry.
 *
 *   s toggles the source: cloud (API) ↔ local (the JSONL file the hooks write
 *   on this machine).
 *
 * The strip on top shows totals (cloud API, or computed from the local file).
 */
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { useState } from 'react';
import { api } from '../../api-client/index.js';
import type { AuditQuery } from '../../api-client/audit.js';
import type { AuditEntry } from '../../api-client/index.js';
import { DataView, PaneTitle, StreamLine, type StreamRow } from '../components.js';
import { useLoader, usePanelSize, usePoll } from '../hooks.js';
import { localLogFile, parseLocalLines, reasonSignals, tailLines } from '../local-log.js';
import { decisionColor, prettyJson, theme, truncate, wrapLines } from '../theme.js';

const DECISIONS: Array<AuditQuery['filter']> = [undefined, 'DENY', 'ALLOW'];
const SIGNALS: Array<AuditQuery['signal'] | undefined> = [undefined, 'dlp', 'ratelimit'];
const PAGE = 500;
const LOCAL_MAX_BYTES = 16 * 1024 * 1024; // read up to 16MB of local history
const BG = '#12234f'; // ENTRY chrome — matches the Live inspector

/** LogRow → the shared StreamLine shape (identical rows to the Live console). */
const toStream = (e: LogRow): StreamRow => ({
  at: e.at,
  tool: e.tool,
  decision: e.decision,
  permission: (e.permission ?? '').slice(0, 4),
  detail: (e.args ?? e.reason ?? '').replace(/\s+/g, ' '),
  dlp: e.dlp.length > 0,
  burst: e.burst,
  agent: e.agent,
  evalMs: e.evalMs,
  rule: e.rule,
});

type Source = 'cloud' | 'local';
type View = 'logs' | 'detail';

/** One log row, unified across cloud entries and local JSONL lines. */
interface LogRow {
  id: string;
  at: number;
  tool: string;
  decision: string;
  permission: string;
  trust: string;
  agent: string | null;
  session: string | null;
  reason: string | null;
  rule: string | null;
  evalMs: number | null;
  dlp: string[];
  burst: boolean;
  args: string | null; // raw JSON string of the arguments
}

const cloudRow = (e: AuditEntry): LogRow => {
  // Prefer the API's fields; fall back to the reason string so a redacted /
  // blocked DLP or rate-limit hit is still detectable (see reasonSignals).
  const rs = reasonSignals(e.reason);
  return {
    id: e.id,
    at: Date.parse(e.created_at),
    tool: e.tool_name,
    decision: e.decision,
    permission: e.permission,
    trust: e.trust_level,
    agent: e.agent_name,
    session: e.session_id,
    reason: e.reason,
    rule: e.matched_rule_id,
    evalMs: e.evaluation_time_ms,
    dlp: e.dlp_matches?.length ? e.dlp_matches : rs.dlp,
    burst: !!e.rate_limit_burst || rs.burst,
    args: e.arguments_summary ? JSON.stringify(e.arguments_summary) : null,
  };
};

function loadLocalRows(): LogRow[] {
  return parseLocalLines(tailLines(localLogFile(), LOCAL_MAX_BYTES))
    .map((j, i) => {
      // The local hooks don't write dlp/burst fields — derive them from the
      // reason so signal filters work on the local source too.
      const rs = reasonSignals(j.reason);
      const explicitDlp = j.dlp ? (Array.isArray(j.dlp) ? j.dlp.map(String) : ['dlp']) : [];
      return {
        id: 'l:' + j.at + ':' + i,
        at: j.at,
        tool: j.tool ?? '?',
        decision: j.decision ?? 'ALLOW',
        permission: j.permission ?? '—',
        trust: j.trust_level ?? '—',
        agent: j.agent_name ?? null,
        session: j.session_id ?? null,
        reason: j.reason ?? null,
        rule: j.matched_rule_id ?? null,
        evalMs: j.evaluation_time_ms ?? null,
        dlp: explicitDlp.length ? explicitDlp : rs.dlp,
        burst: !!j.rate_limit_burst || rs.burst,
        args: j.arguments ? JSON.stringify(j.arguments) : null,
      };
    })
    .sort((a, b) => b.at - a.at); // newest first, always date-ordered
}

/** Full key reference shown by `?` (any Audit view). */
const AUDIT_HELP: Array<[string, Array<[string, string]>]> = [
  [
    'Logs',
    [
      ['↑↓ / PgUp PgDn', 'select a row (window follows)'],
      ['enter', 'open the FULL entry (reason + arguments)'],
      ['← →', 'previous / next page (500 per page, jumps to top)'],
      ['f', 'decision filter: all → DENY → ALLOW'],
      ['g', 'signal filter: all → dlp → ratelimit'],
      ['t / n', 'tool / agent filter (type, enter done)'],
      ['/', 'free-text search'],
      ['e', 'export this page → ~/.solongate/audit-export-<src>.jsonl'],
      ['E', 'export ALL matched rows (cloud: up to 10k)'],
      ['c', 'clear every filter'],
    ],
  ],
  [
    'Anywhere in Audit',
    [
      ['s', 'switch source cloud ↔ local file'],
      ['space', 'copy mode: freeze screen for mouse selection'],
      ['?', 'this help · any key closes'],
      ['esc', 'back to the menu'],
    ],
  ],
  ['Entry (full content)', [['↑↓ / PgUp PgDn', 'scroll the reason + arguments'], ['space', 'copy mode (freeze, then select)'], ['← / esc', 'back to the list']]],
];


export function AuditPanel({ active, focused }: { active: boolean; focused: boolean }): JSX.Element {
  const { cols, rows } = usePanelSize();
  const [source, setSource] = useState<Source>('cloud');
  const [view, setView] = useState<View>('logs');

  // ── logs filters ───────────────────────────────────────────────────────
  const [di, setDi] = useState(0); // decision: all
  const [gi, setGi] = useState(0); // signal: all
  const [tool, setTool] = useState('');
  const [agent, setAgent] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(0);
  const [sel, setSel] = useState(0);
  const [detailScroll, setDetailScroll] = useState(0);
  const [editing, setEditing] = useState<null | 'tool' | 'agent' | 'search'>(null);

  // There are no delete keys here any more. The audit log is the record of what
  // an agent was allowed to do; one a person can clear is not a record. The API
  // has no delete endpoint left to call either, so this is not a hidden key.
  const [msg, setMsg] = useState<{ text: string; level: 'ok' | 'bad' } | null>(null);
  const [showHelp, setShowHelp] = useState(false);
  // COPY MODE (space): polls stop and keys lock so the screen is pixel-static
  // for terminal mouse selection — same behavior as Live.
  const [frozen, setFrozen] = useState(false);

  const toTop = () => setSel(0); // page/filter change → scroll to top

  // ── data: stats strip ───────────────────────────────────────────────────
  const statsQ = useLoader(() => (source === 'cloud' ? api.stats.get() : Promise.resolve(null)), [source]);
  usePoll(statsQ.reloadQuiet, 15_000, active && source === 'cloud' && !frozen);

  // ── data: logs ────────────────────────────────────────────────────────
  const query: AuditQuery = {
    filter: DECISIONS[di],
    signal: SIGNALS[gi],
    tool: tool || undefined,
    agent_name: agent || undefined,
    search: search || undefined,
    limit: PAGE,
    offset: page * PAGE,
  };
  const cloudQ = useLoader(
    () => (source === 'cloud' ? api.audit.list(query) : Promise.resolve(null)),
    [source, di, gi, tool, agent, search, page],
  );
  // Auto-refresh only page 0 — deeper pages stay put while you read them.
  usePoll(cloudQ.reloadQuiet, 6000, active && source === 'cloud' && view === 'logs' && !editing && page === 0 && !frozen);

  const localQ = useLoader(() => (source === 'local' ? Promise.resolve(loadLocalRows()) : Promise.resolve(null)), [source]);
  usePoll(localQ.reloadQuiet, 6000, active && source === 'local' && view === 'logs' && !editing && page === 0 && !frozen);

  // Unified, filtered, date-sorted rows + totals for the CURRENT page.
  const q = search.trim().toLowerCase();
  const localFiltered = (localQ.data ?? []).filter((r) => {
    if (DECISIONS[di] && r.decision !== DECISIONS[di]) return false;
    if (SIGNALS[gi] === 'dlp' && r.dlp.length === 0) return false;
    if (SIGNALS[gi] === 'ratelimit' && !r.burst) return false;
    if (tool && !r.tool.toLowerCase().includes(tool.toLowerCase())) return false;
    if (agent && (r.agent ?? '').toLowerCase() !== agent.toLowerCase()) return false;
    if (q && !`${r.tool} ${r.agent ?? ''} ${r.reason ?? ''} ${r.args ?? ''}`.toLowerCase().includes(q)) return false;
    return true;
  });
  let pageRows: LogRow[] = [];
  let total = 0;
  if (source === 'cloud') {
    pageRows = (cloudQ.data?.entries ?? []).map(cloudRow).sort((a, b) => b.at - a.at);
    total = cloudQ.data?.total ?? 0;
  } else {
    total = localFiltered.length;
    pageRows = localFiltered.slice(page * PAGE, page * PAGE + PAGE);
  }
  const pages = Math.max(1, Math.ceil(total / PAGE));
  const current = pageRows[Math.min(sel, Math.max(0, pageRows.length - 1))];

  // Visible loading states (also lock the keyboard below so queued keypresses
  // can't double-page or land on the wrong row while data is in flight).
  const logsLoading = (source === 'cloud' ? cloudQ.loading : localQ.loading) && !editing;

  // e = export the current page · E = export EVERYTHING matching the filters.
  const doExport = (kind: 'page' | 'all') => {
    setMsg({ text: 'exporting…', level: 'ok' });
    const run = async (): Promise<{ n: number; file: string }> => {
      const dir = join(homedir(), '.solongate');
      const file = join(dir, `audit-export-${source}.jsonl`);
      let rows: LogRow[];
      if (kind === 'page') rows = pageRows;
      else if (source === 'cloud') {
        const r = await api.audit.list({ ...query, limit: 10_000, offset: 0 });
        rows = r.entries.map(cloudRow).sort((a, b) => b.at - a.at);
      } else rows = localFiltered;
      mkdirSync(dir, { recursive: true });
      writeFileSync(file, rows.map((x) => JSON.stringify(x)).join('\n') + (rows.length ? '\n' : ''));
      return { n: rows.length, file };
    };
    run()
      .then(({ n, file }) => setMsg({ text: `✓ exported ${n} rows → ${file}`, level: 'ok' }))
      .catch((e: unknown) => setMsg({ text: '✗ export failed: ' + (e instanceof Error ? e.message : String(e)), level: 'bad' }));
  };

  // ── keys ────────────────────────────────────────────────────────────────
  useInput(
    (input, key) => {
      // Copy mode first: space toggles; while frozen ONLY space works.
      if (input === ' ') {
        setFrozen((f) => !f);
        return;
      }
      if (frozen) return;
      // ^R — manual refresh: refetch the active source's logs and stats so a
      // change made elsewhere shows up on demand.
      if (key.ctrl && input === 'r') {
        if (source === 'cloud') { cloudQ.reload(); statsQ.reloadQuiet(); }
        else localQ.reload();
        setMsg({ text: `⟳ refreshed ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}`, level: 'ok' });
        return;
      }
      // `?` help works from any view, even mid-load; any key closes it.
      if (showHelp) {
        setShowHelp(false);
        return;
      }
      if (input === '?') {
        setShowHelp(true);
        return;
      }
      if (view === 'detail') {
        if (key.leftArrow || key.escape) setView('logs');
        else if (key.upArrow) setDetailScroll((n) => Math.max(0, n - 1));
        else if (key.downArrow) setDetailScroll((n) => n + 1); // clamped at render
        else if (key.pageUp) setDetailScroll((n) => Math.max(0, n - 10));
        else if (key.pageDown) setDetailScroll((n) => n + 10);
        return;
      }
      // Keyboard LOCK while data is loading: queued keypresses would otherwise
      // double-page or act on rows that are about to be replaced.
      if (logsLoading) return;
      // A leftover message from the last action clears on the next keypress.
      if (msg) {
        setMsg(null);
      }
      // shared toggles
      if (input === 's') {
        setSource((s) => (s === 'cloud' ? 'local' : 'cloud'));
        setPage(0);
        toTop();
        return;
      }
      // logs view
      if (key.upArrow) setSel((n) => Math.max(0, n - 1));
      else if (key.downArrow) setSel((n) => Math.min(pageRows.length - 1, n + 1));
      else if (key.pageUp) setSel((n) => Math.max(0, n - 10));
      else if (key.pageDown) setSel((n) => Math.min(pageRows.length - 1, n + 10));
      else if (key.return) {
        if (current) {
          setDetailScroll(0);
          setView('detail');
        }
      } else if (key.rightArrow) {
        if (page < pages - 1) {
          setPage(page + 1);
          toTop();
        }
      } else if (key.leftArrow) {
        if (page > 0) {
          setPage(page - 1);
          toTop();
        }
      } else if (input === 'f') {
        setDi((n) => (n + 1) % DECISIONS.length);
        setPage(0);
        toTop();
      } else if (input === 'g') {
        setGi((n) => (n + 1) % SIGNALS.length);
        setPage(0);
        toTop();
      } else if (input === 'e') doExport('page');
      else if (input === 'E') doExport('all');
      else if (input === 't') setEditing('tool');
      else if (input === 'n') setEditing('agent');
      else if (input === '/') setEditing('search');
      else if (input === 'c') {
        setDi(0);
        setGi(0);
        setTool('');
        setAgent('');
        setSearch('');
        setPage(0);
        toTop();
      }
    },
    { isActive: focused && !editing },
  );

  // ── stats strip (the merged Stats page) ─────────────────────────────────
  const localAll = localQ.data ?? [];
  const strip =
    source === 'cloud' ? (
      <Text wrap="truncate">
        <Text bold>{statsQ.data ? statsQ.data.total_calls : '····'}</Text>
        <Text color={theme.dim}> calls · </Text>
        <Text color={theme.ok}>{statsQ.data?.allowed ?? '···'} allow</Text>
        <Text color={theme.dim}> · </Text>
        <Text color={theme.bad}>{statsQ.data?.denied ?? '··'} deny</Text>
        <Text color={theme.dim}>{` · ${statsQ.data?.active_policies ?? '·'} policies`}</Text>
      </Text>
    ) : (
      <Text wrap="truncate">
        <Text bold>{localAll.length}</Text>
        <Text color={theme.dim}> calls in local file · </Text>
        <Text color={theme.ok}>{localAll.filter((r) => r.decision === 'ALLOW').length} allow</Text>
        <Text color={theme.dim}> · </Text>
        <Text color={theme.bad}>{localAll.filter((r) => r.decision !== 'ALLOW').length} deny</Text>
        <Text color={theme.dim}> · {localLogFile()}</Text>
      </Text>
    );

  const copyBanner = frozen ? (
    <Text backgroundColor="#123d1f" color="#7bd88f" bold wrap="truncate">
      {' ⏵ COPY MODE — screen frozen, select & copy freely · space resume '}
    </Text>
  ) : null;

  const srcChip = (
    <Text>
      <Text color={theme.dim}>src:</Text>
      <Text color={source === 'local' ? theme.ok : '#4f6db8'} bold>
        {source}
      </Text>
      <Text color={theme.dim}> (s) </Text>
    </Text>
  );

  // ── help overlay (`?`) ───────────────────────────────────────────────────
  // Rendered as TWO columns — the flat list is taller than the panel box and
  // Ink corrupts overflowing lines.
  if (showHelp) {
    const colOf = (groups: typeof AUDIT_HELP) => (
      <Box flexDirection="column" width="50%" paddingRight={2}>
        {groups.map(([group, keys]) => (
          <Box key={group} flexDirection="column" marginBottom={1}>
            <Text bold color={theme.accent}>
              {group}
            </Text>
            {keys.map(([k, desc]) => (
              <Text key={k} wrap="truncate">
                <Text color={theme.accentBright}>{('  ' + k).padEnd(19)}</Text>
                <Text color={theme.dim}>{desc}</Text>
              </Text>
            ))}
          </Box>
        ))}
      </Box>
    );
    return (
      <Box flexDirection="column">
        {copyBanner}
        <Text bold color={theme.accentBright}>
          AUDIT — all keys{' '}
          <Text color={theme.dim}>{frozen ? '· screen frozen — space resumes, other keys are locked' : '· press any key to close · space = copy mode (works here too)'}</Text>
        </Text>
        <Box marginTop={1}>
          {colOf(AUDIT_HELP.slice(0, 1))}
          {colOf(AUDIT_HELP.slice(1))}
        </Box>
      </Box>
    );
  }

  // ── entry inspector — the COMPLETE entry, scrollable (Live-style) ─────────
  if (view === 'detail' && current) {
    const e = current;
    const loc = source === 'local';
    const bodyW = Math.max(20, cols - 4);
    const innerW = cols - 2;
    // FULL CONTENT: surface the denial reason (Audit's forensic value) ABOVE the
    // arguments. Live folds reason into the row only when args are absent, but an
    // audit browser should always show WHY a call was denied.
    const contentLines: string[] = [];
    if (e.reason && e.decision !== 'ALLOW') contentLines.push(...wrapLines('reason: ' + e.reason, bodyW), '');
    const argsText = e.args ? prettyJson(e.args) : e.reason && e.decision === 'ALLOW' ? e.reason : '(no arguments recorded)';
    contentLines.push(...wrapLines(argsText, bodyW));
    const bodyRows = Math.max(4, rows - 7 - (frozen ? 1 : 0)); // ENTRY header (3) + pane title + footer + copyBanner
    const maxScroll = Math.max(0, contentLines.length - bodyRows);
    const off = Math.min(detailScroll, maxScroll);
    const win = contentLines.slice(off, off + bodyRows);
    return (
      <Box flexDirection="column">
        {copyBanner}
        <Text wrap="truncate">
          <Text backgroundColor={BG} color="white" bold>
            {' ENTRY '}
          </Text>
          <Text color={decisionColor(e.decision)} bold>
            {'  ' + e.decision}
          </Text>
          <Text color={theme.accent} bold>
            {'  ' + e.tool}
          </Text>
          <Text color={loc ? theme.ok : 'white'}>{'  ' + (loc ? 'LOC' : 'CLD')}</Text>
          {e.dlp.length ? <Text color={theme.bad}>{'  DLP!'}</Text> : null}
          {e.burst ? <Text color={theme.warn}>{'  BURST'}</Text> : null}
          <Text color={theme.dim}>{'  ← back'}</Text>
        </Text>
        <Text wrap="truncate">
          <Text color={theme.dim}>│ when </Text>
          <Text>{new Date(e.at).toLocaleString()}</Text>
          <Text color={theme.dim}> │ perm </Text>
          <Text>{e.permission || '—'}</Text>
          <Text color={theme.dim}> │ trust </Text>
          <Text>{e.trust || '—'}</Text>
          <Text color={theme.dim}> │ eval </Text>
          <Text color={e.evalMs != null && e.evalMs > 500 ? theme.warn : undefined}>{e.evalMs != null ? `${e.evalMs}ms` : '—'}</Text>
          <Text color={theme.dim}> │ agent </Text>
          <Text>{e.agent ?? '—'}</Text>
          <Text color={theme.dim}> │</Text>
        </Text>
        <Text wrap="truncate">
          <Text color={theme.dim}>│ session </Text>
          <Text color={theme.dim}>{e.session ?? '—'}</Text>
          <Text color={theme.dim}> │ rule </Text>
          <Text color={e.rule && e.decision !== 'ALLOW' ? theme.bad : theme.dim}>{e.rule ?? '—'}</Text>
          <Text color={theme.dim}> │</Text>
        </Text>
        <PaneTitle label="FULL CONTENT" extra={`${contentLines.length} lines${maxScroll ? ` · ▼${maxScroll - off} more · ↑↓ scroll` : ''} · space copy · ← back`} width={innerW} />
        <Box flexDirection="column" height={bodyRows} overflow="hidden">
          {win.map((l, i) => (
            <Text key={off + i} wrap="truncate">
              {l || ' '}
            </Text>
          ))}
        </Box>
        <Text wrap="truncate">
          <Text backgroundColor={BG} color="white" bold>
            {' ENTRY '}
          </Text>
          <Text backgroundColor="#0b1530" color="white">
            {` ${e.id} `}
          </Text>
          <Text backgroundColor={BG} color="white">
            {' ↑↓ scroll · space copy · ? all keys · ← back · esc menu '}
          </Text>
        </Text>
      </Box>
    );
  }

  const chip = (label: string, val: string, on: boolean) => (
    <Text>
      <Text color={theme.dim}>{label}:</Text>
      <Text color={on ? theme.accentBright : theme.dim}>{val}</Text>
      <Text> </Text>
    </Text>
  );

  // ── logs view ────────────────────────────────────────────────────────────
  const headerRows = 6 + (editing ? 1 : 0) + (msg ? 1 : 0) + (frozen ? 1 : 0);
  const listRows = Math.max(4, rows - headerRows);
  const selClamped = Math.min(sel, Math.max(0, pageRows.length - 1));
  const maxStart = Math.max(0, pageRows.length - listRows);
  const start = Math.min(Math.max(0, selClamped - Math.floor((listRows - 1) / 2)), maxStart);
  const windowed = pageRows.slice(start, start + listRows);

  return (
    <DataView loading={logsLoading && !frozen} error={source === 'cloud' ? cloudQ.error : localQ.error}>
      <Box flexDirection="column">
        {strip}
        {copyBanner}
        <Box>
          {srcChip}
          <Text color={theme.accentBright} bold>
            LOGS
          </Text>
          {chip('dec', DECISIONS[di] ?? 'all', di !== 0)}
          {chip('sig', SIGNALS[gi] ?? 'all', gi !== 0)}
          {chip('tool', tool || '·', !!tool)}
          {chip('agent', agent || '·', !!agent)}
          {chip('search', search || '·', !!search)}
        </Box>
        <Text color={theme.dim} wrap="truncate">
          {focused ? '↑↓ select · enter full entry · ←→ page · ^R refresh · ? all keys' : 'press → to browse'}
        </Text>

        {msg ? <Text color={msg.level === 'bad' ? theme.bad : theme.ok}>{truncate(msg.text, cols)}</Text> : null}
        {editing ? (
          <Box>
            <Text color={theme.warn}>{editing}: </Text>
            <TextInput
              value={editing === 'tool' ? tool : editing === 'agent' ? agent : search}
              onChange={(v) => {
                (editing === 'tool' ? setTool : editing === 'agent' ? setAgent : setSearch)(v);
                setPage(0);
                toTop();
              }}
              onSubmit={() => setEditing(null)}
            />
          </Box>
        ) : null}

        <Text color={theme.dim} wrap="truncate">
          {`${total} matched · page ${Math.min(page + 1, pages)}/${pages} · ${PAGE}/page · ${pageRows.length ? selClamped + 1 : 0}/${pageRows.length}${
            start ? ` · ▲${start} newer` : ''
          }${start + listRows < pageRows.length ? ` · ▼${pageRows.length - start - listRows} older` : ''}`}
        </Text>
        <Box flexDirection="column" overflow="hidden">
          {windowed.map((e, i) => (
            <StreamLine key={e.id} e={toStream(e)} loc={source === 'local'} selected={start + i === selClamped && focused} date />
          ))}
        </Box>
        {pageRows.length === 0 ? <Text color={theme.dim}>(no entries{source === 'local' ? ' in the local file' : ''} — c clears filters)</Text> : null}
      </Box>
    </DataView>
  );
}

