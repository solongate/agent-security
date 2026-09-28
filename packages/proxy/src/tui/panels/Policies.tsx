/**
 * Policies panel — three levels, all edits are DRAFT-only until you press `s`:
 *   list   : browse policies (↑↓), open one (→/enter), delete one (d, confirm)
 *   rules  : a policy's rules (↑↓). space toggle · e effect · d delete · m mode
 *            enter → edit a rule · s save · x discard · ← back
 *   rule   : rule editor, mirroring the dashboard — Effect, one Constraint type
 *            (default command), Permissions (←→ move + space toggle, green=on),
 *            Priority, Description, Match value(s) with [ ] wildcard toggles.
 *            allow/deny follows Effect. ↑↓ field, enter edit text, ← back.
 *
 * Nothing is written to the cloud until an explicit save (PUT /policies/:id).
 */
import { Box, Text, useInput } from 'ink';
import TextInput from 'ink-text-input';
import { useEffect, useState } from 'react';
import { api } from '../../api-client/index.js';
import type { Constraint, Permission, PolicyEffect, PolicyMode, PolicyRule } from '../../api-client/index.js';
import { DataView, Table } from '../components.js';
import { useLoader, usePanelSize, usePoll } from '../hooks.js';
import { theme, truncate } from '../theme.js';

type View = 'list' | 'rules' | 'rule' | 'match';
type Group = 'commandConstraints' | 'pathConstraints' | 'filenameConstraints' | 'urlConstraints';

interface Field {
  label: string;
  kind: 'effect' | 'enabled' | 'priority' | 'text' | 'ctype' | 'perms' | 'match';
  get: (r: PolicyRule) => string;
  set?: (r: PolicyRule, val: string) => PolicyRule;
}

// One rule carries ONE constraint type, mirroring the dashboard editor. Which
// list (allowed/denied) a value lands in follows the rule's EFFECT — a DENY rule
// fills `denied`, an ALLOW rule fills `allowed` — so the user never picks a side.
type CType = 'none' | 'command' | 'path' | 'filename' | 'url';
const CTYPES: CType[] = ['none', 'command', 'path', 'filename', 'url'];
const CTYPE_GROUP: Record<Exclude<CType, 'none'>, Group> = {
  command: 'commandConstraints',
  path: 'pathConstraints',
  filename: 'filenameConstraints',
  url: 'urlConstraints',
};
const currentCType = (r: PolicyRule): CType => {
  if (r.filenameConstraints) return 'filename';
  if (r.urlConstraints) return 'url';
  if (r.commandConstraints) return 'command';
  if (r.pathConstraints) return 'path';
  return 'none';
};
const clearConstraints = (r: PolicyRule): PolicyRule => ({
  ...r,
  commandConstraints: undefined,
  pathConstraints: undefined,
  filenameConstraints: undefined,
  urlConstraints: undefined,
});
// Selecting a type clears the others and marks the chosen one present (empty).
const setCType = (r: PolicyRule, t: CType): PolicyRule => {
  const base = clearConstraints(r);
  if (t === 'none') return base;
  const listKey = r.effect === 'ALLOW' ? 'allowed' : 'denied';
  return { ...base, [CTYPE_GROUP[t]]: { [listKey]: [] } };
};
const cValue = (r: PolicyRule): string => {
  const t = currentCType(r);
  if (t === 'none') return '';
  const c = r[CTYPE_GROUP[t]] as Constraint | undefined;
  return [...(c?.allowed ?? []), ...(c?.denied ?? [])].join(', ');
};
const setCValue = (r: PolicyRule, val: string): PolicyRule => {
  const t = currentCType(r);
  if (t === 'none') return r;
  const arr = val.split(',').map((s) => s.trim()).filter(Boolean);
  const listKey = r.effect === 'ALLOW' ? 'allowed' : 'denied';
  return { ...r, [CTYPE_GROUP[t]]: { [listKey]: arr } };
};
// The match value list for a rule's active constraint (both allow+deny sides).
const matchItems = (r: PolicyRule): string[] => {
  const t = currentCType(r);
  if (t === 'none') return [];
  const c = r[CTYPE_GROUP[t]] as Constraint | undefined;
  return [...(c?.allowed ?? []), ...(c?.denied ?? [])];
};
// Write the match value list back to the rule's active constraint (effect side).
const setMatchItems = (r: PolicyRule, items: string[]): PolicyRule => {
  const t = currentCType(r);
  if (t === 'none') return r;
  const listKey = r.effect === 'ALLOW' ? 'allowed' : 'denied';
  return { ...r, [CTYPE_GROUP[t]]: { [listKey]: items } };
};
// Toggle a leading / trailing star on a SINGLE value string.
const flipStar = (v: string, side: 'left' | 'right'): string =>
  side === 'left'
    ? (v.startsWith('*') ? v.replace(/^\*+/, '') : '*' + v)
    : (v.endsWith('*') ? v.replace(/\*+$/, '') : v + '*');
// Flipping the effect moves the current constraint's values to the new side.
const migrateEffect = (r: PolicyRule, nextEffect: PolicyEffect): PolicyRule => {
  const flipped = { ...r, effect: nextEffect };
  const t = currentCType(r);
  if (t === 'none') return flipped;
  const c = r[CTYPE_GROUP[t]] as Constraint | undefined;
  const items = [...(c?.allowed ?? []), ...(c?.denied ?? [])];
  const listKey = nextEffect === 'ALLOW' ? 'allowed' : 'denied';
  return { ...flipped, [CTYPE_GROUP[t]]: { [listKey]: items } };
};

// Permissions mirror the dashboard's READ/WRITE/EXECUTE/NETWORK checkboxes.
// All four selected == "any" == stored as undefined (matches every permission).
const PERMS: Permission[] = ['READ', 'WRITE', 'EXECUTE', 'NETWORK'];
const permList = (r: PolicyRule): Permission[] =>
  !r.permission ? [...PERMS] : Array.isArray(r.permission) ? r.permission : [r.permission];
const permIsAny = (r: PolicyRule): boolean => PERMS.every((p) => permList(r).includes(p));
const togglePerm = (r: PolicyRule, p: Permission): PolicyRule => {
  const cur = permList(r);
  let next = cur.includes(p) ? cur.filter((x) => x !== p) : [...cur, p];
  if (next.length === 0) next = [p]; // never empty — at least one permission
  return { ...r, permission: PERMS.every((x) => next.includes(x)) ? undefined : next };
};
const permDisplay = (r: PolicyRule): string =>
  permIsAny(r) ? 'any (READ WRITE EXECUTE NETWORK)' : permList(r).join(' ');

// A rule with no constraint values AND any-permission matches EVERY request — a
// blanket allow/deny. Almost always a mistake; save() refuses it (as does the
// dashboard). Mirrors the dashboard's isBlanketRule.
const ruleHasValues = (r: PolicyRule): boolean => {
  const t = currentCType(r);
  if (t === 'none') return false;
  const c = r[CTYPE_GROUP[t]] as Constraint | undefined;
  return (c?.allowed?.length ?? 0) + (c?.denied?.length ?? 0) > 0;
};
const isBlanketRule = (r: PolicyRule): boolean => !ruleHasValues(r) && permIsAny(r);

// Editor fields mirror the dashboard RuleEditor exactly: Effect, Constraint type,
// Permissions, Priority, Description, Match. (Enabled is toggled on the rules
// list with space, like the dashboard toggles it on the rule card.)
const FIELDS: Field[] = [
  { label: 'Effect', kind: 'effect', get: (r) => r.effect },
  { label: 'Constraint', kind: 'ctype', get: (r) => currentCType(r) },
  { label: 'Permissions', kind: 'perms', get: permDisplay },
  { label: 'Priority', kind: 'priority', get: (r) => String(r.priority) },
  { label: 'Description', kind: 'text', get: (r) => r.description ?? '', set: (r, v) => ({ ...r, description: v }) },
  { label: 'Match', kind: 'match', get: cValue, set: setCValue },
];

function ruleSummary(r: PolicyRule): string {
  const bits: string[] = [];
  for (const [g, tag] of [['commandConstraints', 'cmd'], ['pathConstraints', 'path'], ['filenameConstraints', 'file'], ['urlConstraints', 'url']] as const) {
    const c = r[g] as Constraint | undefined;
    const n = (c?.allowed?.length ?? 0) + (c?.denied?.length ?? 0);
    if (n) bits.push(`${tag}:${n}`);
  }
  return bits.join(' ');
}

export function PoliciesPanel({ focused }: { active: boolean; focused: boolean }): JSX.Element {
  const list = useLoader(() => api.policies.list());
  const policies = list.data?.policies ?? [];
  // Which policy is ACTIVE right now (pinned / agent / wildcard, or none).
  const activeQ = useLoader(() => api.policies.active());
  const activeId = activeQ.data?.policy?.id ?? null;
  const activeBy = activeQ.data?.matched_by;
  // Available content rows for this panel (banner/nav/borders already subtracted)
  // so long lists window instead of overflowing the box (which would glitch the
  // banner and hide the save/discard hints).
  const { rows: panelRows } = usePanelSize();

  const [view, setView] = useState<View>('list');
  const [pi, setPi] = useState(0);
  const [ri, setRi] = useState(0);
  const [fi, setFi] = useState(0);
  const [rules, setRules] = useState<PolicyRule[]>([]);
  const [mode, setMode] = useState<PolicyMode>('denylist');
  const [dirty, setDirty] = useState(false);
  const [editing, setEditing] = useState(false);
  const [editVal, setEditVal] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [pendingDel, setPendingDel] = useState<string | null>(null); // policy id awaiting a confirm 'd'
  const [permCursor, setPermCursor] = useState(0); // which permission ←→ points at, in the editor
  const [matchSel, setMatchSel] = useState(0); // selected row in the Match value list (view 'match')
  const [busyCreate, setBusyCreate] = useState(false); // a policy create is in flight — suppress the empty state until it lands

  const selected = policies[Math.min(pi, Math.max(0, policies.length - 1))];
  const detail = useLoader(() => (selected ? api.policies.get(selected.id) : Promise.resolve(null)), [selected?.id]);

  // Sync draft from the loaded policy (baseline). Never auto-writes.
  useEffect(() => {
    if (detail.data) {
      setRules(detail.data.rules);
      setMode((detail.data.mode as PolicyMode) ?? 'denylist');
      setDirty(false);
      setRi(0);
    }
  }, [detail.data]);

  // Auto-refresh the policy list + which one is active while the panel is open,
  // so a change made elsewhere (dashboard, another session) shows up without a
  // manual refresh. The open policy's rules are NOT auto-reloaded (that would
  // reset your cursor / clobber unsaved edits) — use `r` for a full refresh.
  usePoll(() => {
    list.reloadQuiet();
    activeQ.reloadQuiet();
  }, 3000);

  const mutate = (nextRules: PolicyRule[], nextMode = mode) => {
    setRules(nextRules);
    setMode(nextMode);
    setDirty(true);
    setStatus(null);
  };

  const save = async () => {
    if (!selected || !detail.data) return;
    const blanket = rules.findIndex(isBlanketRule);
    if (blanket !== -1) {
      setStatus(`✗ rule ${blanket + 1} matches EVERYTHING — pick a Constraint + Match value, or narrow Permissions`);
      return;
    }
    setStatus('Saving…');
    try {
      const res = await api.policies.update(selected.id, {
        id: selected.id,
        name: detail.data.name,
        description: detail.data.description,
        mode,
        agents: detail.data.agents,
        rules,
      });
      setRules(res.rules);
      setDirty(false);
      setStatus('✓ Saved');
      list.reload();
    } catch (e) {
      setStatus('✗ ' + (e instanceof Error ? e.message : String(e)));
    }
  };

  const discard = () => {
    if (detail.data) {
      setRules(detail.data.rules);
      setMode((detail.data.mode as PolicyMode) ?? 'denylist');
    }
    setDirty(false);
    setStatus('discarded');
  };

  // Naming a brand-new policy (list view, `n`). Null when not creating.
  const [creating, setCreating] = useState<string | null>(null);

  function commitNewPolicy(name: string): void {
    const n = name.trim();
    setCreating(null);
    if (!n) return;
    setStatus('Creating…');
    setBusyCreate(true); // keep the empty state hidden until the list shows it
    void api.policies
      .create({ id: `policy-${Date.now()}`, name: n, rules: [], mode: 'denylist' })
      .then(() => {
        setStatus(`✓ created "${n}" - open it and press n to add rules`);
        list.reload();
      })
      .catch((e: unknown) => {
        setBusyCreate(false);
        setStatus('✗ ' + (e instanceof Error ? e.message : String(e)));
      });
  }

  // Once the freshly created policy shows up in the list, drop the busy flag.
  useEffect(() => {
    if (busyCreate && policies.length > 0) setBusyCreate(false);
  }, [busyCreate, policies.length]);

  useInput(
    (input, key) => {
      if (creating !== null) return; // TextInput owns the keys while naming
      // ^R — full manual refresh (list, active, and the open policy's rules).
      if (key.ctrl && input === 'r' && !editing) {
        list.reload();
        activeQ.reload();
        detail.reload();
        setStatus(`⟳ refreshed ${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })}`);
        return;
      }
      if (view === 'list') {
        if (key.upArrow) { setPendingDel(null); setPi((n) => Math.max(0, n - 1)); }
        else if (key.downArrow) { setPendingDel(null); setPi((n) => Math.min(policies.length - 1, n + 1)); }
        else if (key.return || key.rightArrow) {
          setStatus(null);
          setView('rules');
        } else if (input === 'a') {
          if (selected) {
            setStatus('Activating…');
            void api.policies
              .setActive(selected.id)
              .then(() => {
                setStatus(`✓ "${selected.name}" is now the ACTIVE policy (pinned) · reaches agents in ~30s`);
                activeQ.reload();
              })
              .catch((e: unknown) => setStatus('✗ ' + (e instanceof Error ? e.message : String(e))));
          }
        } else if (input === 'n' || input === 'N') {
          setStatus(null);
          setCreating('');
        } else if (input === 'x') {
          setStatus('Deactivating…');
          void api.policies
            .setActive(null)
            .then(() => {
              setStatus('✓ active policy: NONE — no rules enforced, w/b grants are refused');
              activeQ.reload();
            })
            .catch((e: unknown) => setStatus('✗ ' + (e instanceof Error ? e.message : String(e))));
        } else if (input === 'd') {
          if (!selected) return;
          if (pendingDel !== selected.id) {
            setPendingDel(selected.id);
            setStatus(`⚠ d again to DELETE policy "${selected.name}" — cannot be undone`);
            return;
          }
          setPendingDel(null);
          setStatus('Deleting…');
          const name = selected.name;
          void api.policies
            .remove(selected.id)
            .then(() => {
              setStatus(`✓ deleted policy "${name}"`);
              setPi(0);
              list.reload();
              activeQ.reload();
            })
            .catch((e: unknown) => setStatus('✗ ' + (e instanceof Error ? e.message : String(e))));
        }
        return;
      }

      if (view === 'rules') {
        if (key.leftArrow) return setView('list'), void setStatus(null);
        if (key.upArrow) setRi((n) => Math.max(0, n - 1));
        else if (key.downArrow) setRi((n) => Math.min(rules.length - 1, n + 1));
        else if (key.return || key.rightArrow) {
          if (rules[ri]) {
            setFi(0);
            setView('rule');
          }
        } else if (input === ' ') {
          if (rules[ri]) mutate(rules.map((r, i) => (i === ri ? { ...r, enabled: !r.enabled } : r)));
        } else if (input === 'e') {
          if (rules[ri]) mutate(rules.map((r, i) => (i === ri ? migrateEffect(r, r.effect === 'ALLOW' ? 'DENY' : 'ALLOW') : r)));
        } else if (input === 'd') {
          if (rules[ri]) {
            const next = rules.filter((_, i) => i !== ri);
            setRi((n) => Math.max(0, Math.min(n, next.length - 1)));
            mutate(next);
          }
        } else if (input === 'm') {
          mutate(rules, mode === 'denylist' ? 'whitelist' : 'denylist');
        } else if (input === 'n') {
          // Default to a command constraint (like the dashboard) so a fresh rule
          // is never a blanket match — the user just fills in the value.
          const nr: PolicyRule = { id: `rule-${Date.now()}`, description: '', effect: 'DENY', priority: 100, toolPattern: '*', minimumTrustLevel: 'UNTRUSTED', enabled: true, commandConstraints: { denied: [] } };
          mutate([nr, ...rules]);
          setRi(0);
          setFi(0);
          setView('rule');
        } else if (input === 's') void save();
        else if (input === 'x') discard();
        return;
      }

      if (view === 'match') {
        // Multi-value list editor for the current rule's constraint (dashboard parity).
        const r = rules[ri];
        if (!r) return setView('rules');
        const items = matchItems(r);
        if (key.leftArrow || key.escape) return setView('rule');
        if (key.upArrow) setMatchSel((n) => Math.max(0, n - 1));
        else if (key.downArrow) setMatchSel((n) => Math.min(Math.max(0, items.length - 1), n + 1));
        else if (input === 'a') {
          const next = [...items, ''];
          mutate(rules.map((x, i) => (i === ri ? setMatchItems(x, next) : x)));
          setMatchSel(next.length - 1);
          setEditVal('');
          setEditing(true);
        } else if (key.return || input === 'e') {
          if (items.length === 0) {
            mutate(rules.map((x, i) => (i === ri ? setMatchItems(x, ['']) : x)));
            setMatchSel(0);
            setEditVal('');
          } else {
            setEditVal(items[matchSel] ?? '');
          }
          setEditing(true);
        } else if (input === '[' || input === ']') {
          const side = input === '[' ? 'left' : 'right';
          if (items[matchSel] != null) {
            const next = items.map((v, i) => (i === matchSel ? flipStar(v, side) : v));
            mutate(rules.map((x, i) => (i === ri ? setMatchItems(x, next) : x)));
          }
        } else if (input === 'd') {
          if (items.length) {
            const next = items.filter((_, i) => i !== matchSel);
            mutate(rules.map((x, i) => (i === ri ? setMatchItems(x, next) : x)));
            setMatchSel((n) => Math.max(0, Math.min(n, next.length - 1)));
          }
        } else if (input === 's') void save();
        return;
      }

      // view === 'rule' (editing handled by TextInput; ignore keys while editing)
      const rule = rules[ri];
      if (!rule) return setView('rules');
      const field = FIELDS[fi]!;
      if (key.leftArrow) setView('rules');
      else if (key.upArrow) setFi((n) => Math.max(0, n - 1));
      else if (key.downArrow) setFi((n) => Math.min(FIELDS.length - 1, n + 1));
      else if (field.kind === 'effect' && (input === ' ' || key.rightArrow)) {
        mutate(rules.map((r, i) => (i === ri ? migrateEffect(r, r.effect === 'ALLOW' ? 'DENY' : 'ALLOW') : r)));
      } else if (field.kind === 'enabled' && (input === ' ' || key.rightArrow)) {
        mutate(rules.map((r, i) => (i === ri ? { ...r, enabled: !r.enabled } : r)));
      } else if (field.kind === 'ctype' && (input === ' ' || key.rightArrow || key.leftArrow)) {
        const dir = key.leftArrow ? -1 : 1;
        const nextT = CTYPES[(CTYPES.indexOf(currentCType(rule)) + dir + CTYPES.length) % CTYPES.length]!;
        mutate(rules.map((r, i) => (i === ri ? setCType(r, nextT) : r)));
      } else if (field.kind === 'perms' && key.leftArrow) {
        setPermCursor((n) => (n + PERMS.length - 1) % PERMS.length);
      } else if (field.kind === 'perms' && key.rightArrow) {
        setPermCursor((n) => (n + 1) % PERMS.length);
      } else if (field.kind === 'perms' && input === ' ') {
        const p = PERMS[permCursor % PERMS.length]!;
        mutate(rules.map((rr, i) => (i === ri ? togglePerm(rr, p) : rr)));
      } else if (field.kind === 'match' && (key.return || key.rightArrow)) {
        // Match is a multi-value list — open its own sub-editor (like the dashboard).
        setMatchSel(0);
        setView('match');
      } else if (field.kind === 'priority' && (key.rightArrow || key.leftArrow)) {
        const d = key.rightArrow ? 1 : -1;
        mutate(rules.map((r, i) => (i === ri ? { ...r, priority: Math.max(0, r.priority + d) } : r)));
      } else if (field.kind === 'text' && key.return) {
        setEditVal(field.get(rule));
        setEditing(true);
      } else if (input === 's') void save();
    },
    { isActive: focused && !editing },
  );

  // ── render ────────────────────────────────────────────────────────────────
  if (view === 'list') {
    const activeName = activeId ? policies.find((p) => p.id === activeId)?.name ?? activeId : null;
    const lHead = 3 + (status ? 1 : 0) + (creating !== null ? 1 : 0);
    const lBudget = Math.max(3, panelRows - lHead);
    const lStart = Math.min(Math.max(0, pi - Math.floor(lBudget / 2)), Math.max(0, policies.length - lBudget));
    const lWin = policies.slice(lStart, lStart + lBudget);
    const lAbove = lStart;
    const lBelow = Math.max(0, policies.length - (lStart + lBudget));
    return (
      <DataView loading={list.loading && !list.data} error={list.error} empty={!!list.data && policies.length === 0 && creating === null && !busyCreate} emptyText="No policies yet — press n to create one.">
        <Box flexDirection="column">
          <Box>
            <Text color={theme.dim}>active: </Text>
            {activeQ.loading && !activeQ.data ? (
              <Text color={theme.dim}>…</Text>
            ) : activeName ? (
              <>
                <Text color={theme.ok} bold>
                  ● {truncate(activeName, 28)}
                </Text>
                <Text color={theme.dim}>{activeBy ? ` (${activeBy})` : ''}</Text>
              </>
            ) : (
              <Text color={theme.bad} bold>
                ○ NONE — nothing enforced, grants refused
              </Text>
            )}
          </Box>
          <Text color={theme.dim} wrap="truncate">{focused ? `↑↓ select · enter open · n new · a activate · x deactivate · d delete · ^R refresh${lAbove ? ` · ▲${lAbove}` : ''}${lBelow ? ` · ▼${lBelow}` : ''}` : 'press → to browse'}</Text>
          {creating !== null ? (
            <Box>
              <Text color={theme.warn}>{'new policy name: '}</Text>
              <TextInput value={creating} onChange={setCreating} onSubmit={commitNewPolicy} />
            </Box>
          ) : null}
          <Box marginTop={1} flexDirection="column">
            {lWin.map((p, wi) => {
              const i = lStart + wi;
              return (
                <Text key={p.id} color={i === pi ? theme.accentBright : undefined} bold={i === pi}>
                  {(i === pi ? '▸ ' : '  ') + truncate(p.name, 26).padEnd(27)}
                  <Text color={theme.dim}>
                    {p.mode.padEnd(10)} {p.rules.length} rules
                  </Text>
                  {p.id === activeId ? (
                    <Text color={theme.ok} bold>
                      {'  ● ACTIVE'}
                    </Text>
                  ) : null}
                </Text>
              );
            })}
          </Box>
          {status ? <Text color={status.startsWith('✗') ? theme.bad : theme.ok}>{status}</Text> : null}
        </Box>
      </DataView>
    );
  }

  const dirtyTag = dirty ? <Text color={theme.warn}>{'  ● unsaved (s save · x discard)'}</Text> : null;

  if (view === 'rules') {
    // Window the rule list around the cursor so it never overflows the panel
    // (which would glitch the banner and push the save/discard hint off-screen).
    // Reserve: title(1) + hint(1) + marginTop(1) + table header(1) + status(1).
    const rStatusLines = status ? status.split('\n').length : 0;
    const rHead = 4 + rStatusLines;
    const rBudget = Math.max(3, panelRows - rHead);
    const rMaxStart = Math.max(0, rules.length - rBudget);
    const rStart = Math.min(Math.max(0, ri - Math.floor(rBudget / 2)), rMaxStart);
    const rWin = rules.slice(rStart, rStart + rBudget);
    const rAbove = rStart;
    const rBelow = Math.max(0, rules.length - (rStart + rBudget));
    return (
      <DataView loading={detail.loading && !detail.data} error={detail.error}>
        <Box flexDirection="column">
          <Box>
            <Text bold color={theme.accentBright}>{truncate(selected?.name ?? '', 28)}</Text>
            <Text color={theme.dim}>{'  mode: '}</Text>
            <Text color={mode === 'whitelist' ? theme.warn : undefined}>{mode}</Text>
            <Text color={theme.dim}>{`  ${rules.length} rules`}</Text>
            {dirtyTag}
          </Box>
          <Text color={theme.dim} wrap="truncate">{`↑↓ · enter edit · space on/off · e effect · n new · d del · m mode · s save · ← back${rAbove ? ` · ▲${rAbove}` : ''}${rBelow ? ` · ▼${rBelow}` : ''}`}</Text>
          <Box marginTop={1}>
            <Table
              columns={[
                { header: '', width: 2 },
                { header: 'ON', width: 2 },
                { header: 'EFFECT', width: 7 },
                { header: 'PRIO', width: 4 },
                { header: 'DESCRIPTION', width: 38 },
                { header: 'CONSTRAINTS', width: 14 },
              ]}
              rows={rWin.map((r, wi) => {
                const i = rStart + wi;
                return [
                  { value: i === ri ? '▸' : '', color: theme.accentBright },
                  { value: r.enabled ? '●' : '○', color: r.enabled ? theme.ok : theme.dim },
                  { value: r.effect, color: r.effect === 'ALLOW' ? theme.ok : theme.bad, dim: !r.enabled },
                  { value: String(r.priority), dim: true },
                  { value: truncate(r.description || '-', 38), dim: !r.enabled },
                  { value: ruleSummary(r) || '-', dim: true },
                ];
              })}
            />
          </Box>
          {rules.length === 0 ? <Text color={theme.dim}>(no rules)</Text> : null}
          {status ? <Text color={status.startsWith('✗') ? theme.bad : theme.ok}>{status}</Text> : null}
        </Box>
      </DataView>
    );
  }

  // view === 'match' — the current rule's constraint value list (multi-value).
  if (view === 'match') {
    const r = rules[ri];
    const items = r ? matchItems(r) : [];
    const t = r ? currentCType(r) : 'none';
    return (
      <Box flexDirection="column">
        <Box>
          <Text bold color={theme.accentBright}>Match values </Text>
          <Text color={theme.dim}>{r ? `${r.effect} · ${t}` : ''}</Text>
          {dirtyTag}
        </Box>
        <Text color={theme.dim}>↑↓ select · enter/e edit · a add · [ / ] wildcard L/R · d remove · s save · ← back</Text>
        <Box marginTop={1} flexDirection="column">
          {items.length === 0 ? <Text color={theme.dim}>(no values — press a to add one)</Text> : null}
          {items.map((it, i) => {
            const sel = i === matchSel;
            if (sel && editing) {
              const lE = editVal.startsWith('*');
              const rE = editVal.length > 0 && editVal.endsWith('*');
              return (
                <Box key={i}>
                  <Text color={theme.accentBright}>{'▸ '}</Text>
                  <Text color={lE ? theme.ok : theme.dim}>{lE ? '✱ ' : '· '}</Text>
                  <TextInput
                    value={editVal}
                    onChange={setEditVal}
                    onSubmit={(v) => {
                      const val = v.trim();
                      let next = items.map((x, idx) => (idx === i ? val : x));
                      if (val === '') next = next.filter((_, idx) => idx !== i);
                      mutate(rules.map((x, idx) => (idx === ri ? setMatchItems(x, next) : x)));
                      setMatchSel((n) => Math.max(0, Math.min(n, next.length - 1)));
                      setEditing(false);
                    }}
                  />
                  <Text color={rE ? theme.ok : theme.dim}>{rE ? ' ✱' : ' ·'}</Text>
                </Box>
              );
            }
            const lOn = it.startsWith('*');
            const rOn = it.length > 0 && it.endsWith('*');
            return (
              <Box key={i}>
                <Text color={sel ? theme.accentBright : undefined}>{sel ? '▸ ' : '  '}</Text>
                <Text color={lOn ? theme.ok : theme.dim}>{lOn ? '✱ ' : '· '}</Text>
                <Text dimColor={!it}>{it || '(empty)'}</Text>
                <Text color={rOn ? theme.ok : theme.dim}>{rOn ? ' ✱' : ' ·'}</Text>
              </Box>
            );
          })}
        </Box>
        <Text color={theme.dim}>{'  * = wildcard (any run of chars). Type it directly (rm*) or toggle with [ / ]. Green ✱ = active · left & right shown as you type. Multiple values = OR (any one matches).'}</Text>
        {status ? <Text color={status.startsWith('✗') ? theme.bad : theme.ok}>{status}</Text> : null}
      </Box>
    );
  }

  // view === 'rule'
  const rule = rules[ri];
  return (
    <Box flexDirection="column">
      <Box>
        <Text bold color={theme.accentBright}>Rule </Text>
        <Text color={theme.dim}>{rule?.id ?? ''}</Text>
        {dirtyTag}
      </Box>
      <Text color={theme.dim}>↑↓ field · enter edit/open · space toggle · ←→ move/pick · s save · ← back</Text>
      <Box marginTop={1} flexDirection="column">
        {FIELDS.map((f, i) => {
          const active = i === fi;
          const label = (
            <Text color={active ? theme.accentBright : undefined}>{(active ? '▸ ' : '  ') + f.label.padEnd(13)}</Text>
          );
          // Permissions: four chips, green = on / red = off; ←→ moves the cursor.
          if (f.kind === 'perms' && rule) {
            return (
              <Box key={f.label}>
                {label}
                {PERMS.map((p, pi) => {
                  const on = permList(rule).includes(p);
                  const cur = active && pi === permCursor % PERMS.length;
                  return (
                    <Text key={p} color={on ? theme.ok : theme.bad} inverse={cur}>
                      {p}{pi < PERMS.length - 1 ? '  ' : ''}
                    </Text>
                  );
                })}
              </Box>
            );
          }
          // Match: a preview of the value list; enter opens the multi-value editor.
          if (f.kind === 'match' && rule) {
            const items = matchItems(rule);
            const preview = items.join(', ');
            return (
              <Box key={f.label}>
                {label}
                <Text dimColor={!preview}>{preview || '—'}</Text>
                <Text color={theme.dim}>{items.length ? `   (${items.length} value${items.length > 1 ? 's' : ''} · enter: edit)` : '   (enter: add values)'}</Text>
              </Box>
            );
          }
          const val = rule ? f.get(rule) : '';
          return (
            <Box key={f.label}>
              {label}
              {active && editing && f.kind === 'text' ? (
                <TextInput
                  value={editVal}
                  onChange={setEditVal}
                  onSubmit={(v) => {
                    if (rule && f.set) mutate(rules.map((r, idx) => (idx === ri ? f.set!(r, v) : r)));
                    setEditing(false);
                  }}
                />
              ) : (
                <Text
                  color={f.kind === 'effect' ? (val === 'ALLOW' ? theme.ok : theme.bad) : undefined}
                  dimColor={!val}
                >
                  {val || '—'}
                </Text>
              )}
            </Box>
          );
        })}
      </Box>
      {status ? <Text color={status.startsWith('✗') ? theme.bad : theme.ok}>{status}</Text> : null}
    </Box>
  );
}
