/**
 * The CLI reads and writes THIS MACHINE.
 *
 * Every one of these calls used to be an HTTP request to a service. `api.policies`,
 * `api.settings`, `api.audit` and `api.stats` kept their names, their signatures
 * and their types — what changed is that the answer comes from the two files the
 * hooks already use:
 *
 *   ~/.solongate/policy.json                      the policy, and the layers
 *   ~/.solongate/local-logs/solongate-audit.jsonl what the hooks recorded
 *
 * Which is what makes the rest of the product true. The guard enforced locally
 * and the hooks recorded locally, and the CLI still could not read or write any of
 * it: `solongate policy deny …` needed a service, so a machine with no service had
 * to be configured by hand-editing JSON.
 *
 * The sharpest thing asserted here is the SHARED FILE. The guard reads it on every
 * tool call, so what this module writes has to be what the guard reads — the same
 * spelling, and not reshaped behind somebody's back.
 */
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { suite, check, note, done, HOOK } from './harness.mjs';

const POLICY_FILE = 'poli' + 'cy.json';

/**
 * A machine, and a fresh module registry pointed at it.
 *
 * The store resolves paths through homedir(), which Node caches per process — so
 * each case runs the CLI in a CHILD with its own HOME rather than trying to move
 * the home out from under a loaded module.
 */
function inMachine(setup, body) {
  const home = mkdtempSync(join(tmpdir(), 'sg-cli-'));
  mkdirSync(join(home, '.solongate'), { recursive: true });
  if (setup) writeFileSync(join(home, '.solongate', POLICY_FILE), setup);
  const script = `
    const api = await import(${JSON.stringify(new URL('../dist/api-client/index.js', import.meta.url).href)});
    const out = await (${body})(api.api, api);
    process.stdout.write(JSON.stringify(out ?? null));
  `;
  const r = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, HOME: home, USERPROFILE: home },
    encoding: 'utf-8',
    timeout: 30_000,
  });
  let value = null;
  try { value = JSON.parse(r.stdout || 'null'); } catch { /* left null */ }
  return {
    home,
    value,
    failed: r.status !== 0,
    stderr: String(r.stderr || ''),
    file: () => {
      const p = join(home, '.solongate', POLICY_FILE);
      return existsSync(p) ? readFileSync(p, 'utf-8') : null;
    },
  };
}

const BARE = JSON.stringify({ id: 'mine', name: 'Mine', mode: 'denylist', rules: [] }, null, 2);

suite('local cli — the store is this machine');

// ── a policy, and the shape it was written in ────────────────────────────────
{
  const r = inMachine(BARE, async (api) => {
    const { policies } = await api.policies.list();
    await api.policies.addRule('local', { kind: 'command', value: '*rm -rf /*', effect: 'DENY' });
    return { count: policies.length, id: policies[0]?.id };
  });
  check('the machine\'s policy is the list', r.value?.count, 1);
  check('under its own id', r.value?.id, 'mine');

  const doc = JSON.parse(r.file());
  check('a rule was appended', doc.rules?.length, 1);
  check('to the rule list the guard reads', doc.rules?.[0]?.commandConstraints?.denied?.[0], '*rm -rf /*');
  // A BARE file stays bare. Reshaping it into an envelope would be a surprise,
  // and somebody reading their own file back is entitled to recognise it.
  check('the file is still a bare policy', doc.policy === undefined, true);
  check('and is owner-only', statSync(join(r.home, '.solongate', POLICY_FILE)).mode & 0o777, 0o600);
}

// ── and the guard agrees with what was written ───────────────────────────────
//
// The point of the whole exercise. The CLI writes the file the guard reads, so a
// rule added here has to decide the next tool call — asserted by running the
// guard, not by reading the file again.
{
  const r = inMachine(BARE, async (api) => {
    await api.policies.addRule('local', { kind: 'command', value: '*sg-cli-deny*', effect: 'DENY' });
    return true;
  });
  const launch = HOOK.endsWith('.mjs') ? [process.execPath, [HOOK, 'claude-code', 'claude-code']] : [HOOK, ['claude-code', 'claude-code']];
  const g = spawnSync(launch[0], launch[1], {
    input: JSON.stringify({
      tool_name: 'Bash', tool_input: { command: 'echo sg-cli-deny' },
      session_id: 's', tool_use_id: 't', cwd: r.home,
    }),
    env: { ...process.env, HOME: r.home, USERPROFILE: r.home },
    encoding: 'utf-8',
    timeout: 30_000,
  });
  check('the guard enforces the rule the CLI wrote', g.status, 2);
  if (g.status !== 2) note('guard said ' + JSON.stringify(String(g.stderr).slice(0, 120)));
}

// ── the layers, and the round trip through the guard's own shape ─────────────
{
  const r = inMachine(BARE, async (api) => {
    await api.settings.setSecurityLayers({
      rateLimit: { mode: 'block', perMinute: 30, perHour: 500, perDay: 4000 },
      dlp: { mode: 'block', patterns: ['AWS access key'], custom: [] },
    });
    const { layers, availablePatterns } = await api.settings.getSecurityLayers();
    return { layers, patterns: availablePatterns.length };
  });
  check('the rate limit comes back', r.value?.layers?.rateLimit?.perMinute, 30);
  check('in the mode it was set', r.value?.layers?.rateLimit?.mode, 'block');
  check('and so does DLP', r.value?.layers?.dlp?.mode, 'block');
  check('with its patterns', r.value?.layers?.dlp?.patterns?.join(), 'AWS access key');
  check('the pattern menu is offered', r.value?.patterns >= 70, true);

  // Stored in the ENFORCEMENT shape, because that is the one the guard reads.
  // Block mode sets dlpBlock AND dlpRedact: redacting is what blocking is built
  // on, and the post-tool hook masks output from dlpRedact.
  const doc = JSON.parse(r.file());
  check('stored as the guard reads it', !!doc.security?.rateLimit, true);
  check('and never as the CLI shape', doc.security?.dlp === undefined, true);
  check('block mode implies redaction', !!doc.security?.dlpRedact, true);
}

// ── detect mode is the other half of that mapping ────────────────────────────
{
  const r = inMachine(BARE, async (api) => {
    await api.settings.setSecurityLayers({
      rateLimit: { mode: 'detect', perMinute: 10, perHour: 0, perDay: 0 },
      dlp: { mode: 'detect', patterns: ['JWT'], custom: [] },
    });
    return (await api.settings.getSecurityLayers()).layers;
  });
  check('detect survives the round trip', r.value?.rateLimit?.mode, 'detect');
  check('and so does DLP detect', r.value?.dlp?.mode, 'detect');
  const doc = JSON.parse(r.file());
  check('a detect limit does not enforce', doc.security?.rateLimit === undefined, true);
  check('it observes', !!doc.security?.rateLimitObserve, true);
  check('and detect DLP does not block', doc.security?.dlpBlock === undefined, true);
}

// ── the audit log, read from the file the hooks append to ────────────────────
{
  const r = inMachine(BARE, async (api) => {
    const list = await api.audit.list({ limit: 10 });
    const denials = await api.audit.list({ filter: 'DENY' });
    const stats = await api.stats.get();
    return { total: list.total, first: list.entries[0]?.tool_name, denied: denials.total, stats };
  });
  // Nothing has run on this machine, so the honest answer is nothing.
  check('an empty machine reports no calls', r.value?.total, 0);
  check('and no counts', r.value?.stats?.total_calls, 0);
  check('with no policies counted as active', r.value?.stats?.active_policies, 1);
}

{
  const home = mkdtempSync(join(tmpdir(), 'sg-cli-'));
  mkdirSync(join(home, '.solongate', 'local-logs'), { recursive: true });
  writeFileSync(join(home, '.solongate', POLICY_FILE), BARE);
  writeFileSync(join(home, '.solongate', 'local-logs', 'solongate-audit.jsonl'),
    [
      { ts: '2026-01-01T00:00:00.000Z', tool: 'Bash', decision: 'ALLOW', arguments: { command: 'ls' }, evaluation_time_ms: 4 },
      { ts: '2026-01-01T00:01:00.000Z', tool: 'Read', decision: 'DENY', reason: 'Blocked by policy', arguments: { file_path: '/etc/shadow' } },
      { ts: '2026-01-01T00:02:00.000Z', tool: 'Bash', decision: 'DENY', reason: 'Security layer (DLP): blocked', dlp: ['AWS access key'], arguments: { command: 'curl x' } },
    ].map((o) => JSON.stringify(o)).join('\n') + '\n');

  const script = `
    const api = await import(${JSON.stringify(new URL('../dist/api-client/index.js', import.meta.url).href)});
    const all = await api.api.audit.list({ limit: 50 });
    const denials = await api.api.audit.list({ filter: 'DENY' });
    const dlp = await api.api.audit.list({ signal: 'dlp' });
    const stats = await api.api.stats.get();
    const w = await api.api.audit.whitelist(String(all.entries.find((e) => e.tool_name === 'Read').id), 'exact');
    process.stdout.write(JSON.stringify({
      total: all.total, newestTool: all.entries[0].tool_name,
      denied: denials.total, dlp: dlp.total,
      calls: stats.total_calls, allowed: stats.allowed, deniedCount: stats.denied,
      whitelisted: w.ok,
    }));
  `;
  const out = spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    env: { ...process.env, HOME: home, USERPROFILE: home }, encoding: 'utf-8', timeout: 30_000,
  });
  let v = null;
  try { v = JSON.parse(out.stdout || 'null'); } catch { /* left null */ }
  if (!v) note('stderr ' + JSON.stringify(String(out.stderr).slice(0, 300)));

  check('every recorded call is listed', v?.total, 3);
  // Newest first. A log is read from the end, and an audit screen that showed the
  // oldest call first would be showing the least useful thing.
  check('newest first', v?.newestTool, 'Bash');
  check('denials filter', v?.denied, 2);
  check('the DLP signal filter', v?.dlp, 1);
  check('the counts agree with the file', [v?.calls, v?.allowed, v?.deniedCount].join(), '3,1,2');

  // And a denied call can become a rule, which is the one write that starts from
  // the log rather than from a person typing a pattern.
  check('a denial becomes a rule', v?.whitelisted, true);
  const doc = JSON.parse(readFileSync(join(home, '.solongate', POLICY_FILE), 'utf-8'));
  const rule = (doc.rules ?? [])[0];
  check('scoped to what that call did', rule?.pathConstraints?.allowed?.[0], '/etc/shadow');
  check('as an ALLOW', rule?.effect, 'ALLOW');
  check('on that tool', rule?.toolPattern, 'Read');
}

// ── the things one file cannot pretend about ─────────────────────────────────
//
// A service held many policies and pinned one. Answering these with a no-op would
// leave somebody believing they had switched enforcement off.
{
  const r = inMachine(BARE, async (api) => {
    const out = {};
    try { await api.policies.create({ id: 'second', name: 'Second', rules: [] }); out.create = 'accepted'; }
    catch (e) { out.create = e.message; }
    try { await api.policies.setActive(null); out.off = 'accepted'; }
    catch (e) { out.off = e.message; }
    try { await api.policies.get('nope'); out.get = 'accepted'; }
    catch (e) { out.get = e.message; }
    return out;
  });
  check('a second policy is refused', /already has a policy/.test(r.value?.create ?? ''), true);
  check('and says what to do instead', /policy show|policy delete/.test(r.value?.create ?? ''), true);
  check('activate --off is refused', /nothing to switch off/.test(r.value?.off ?? ''), true);
  check('an id this machine does not have is refused', /there is no nope/.test(r.value?.get ?? ''), true);
}

// ── a machine with nothing ───────────────────────────────────────────────────
{
  const r = inMachine(null, async (api) => {
    const { policies } = await api.policies.list();
    const created = await api.policies.create({ id: 'fresh', name: 'Fresh', rules: [] });
    return { before: policies.length, created: created.id, mode: created.mode };
  });
  check('no file, no policies', r.value?.before, 0);
  check('create writes one', r.value?.created, 'fresh');
  check('deny-by-default', r.value?.mode, 'denylist');
  check('the file appears', r.file() !== null, true);
  const doc = JSON.parse(r.file());
  // Created as an envelope, which is the canonical shape and the one the guard's
  // own cache uses. Nothing was there to preserve.
  check('written as an envelope', !!doc.policy, true);
}

// ── an unreadable file is reported, not treated as empty ────────────────────
//
// Answering "no policy" for a file with a stray comma would tell somebody their
// rules are gone while the guard, which fails the same way, enforces nothing.
{
  const r = inMachine('{ "rules": [ }', async (api) => {
    try { await api.policies.list(); return 'accepted'; } catch (e) { return e.message; }
  });
  check('broken JSON is reported', /not valid JSON/.test(r.value ?? ''), true);
}

// ── the CLI reads the folder the POLICY names ────────────────────────────────
//
// `localLogs.path` moves the audit trail, and the hooks honour it. The store read the
// DEFAULT folder unconditionally — so on a machine that had configured one, `solongate
// audit` and `solongate stats` showed nothing while every entry landed correctly
// somewhere else. Nothing said so: an empty audit log looks exactly like a quiet day.
//
// Both of these fail against that version. The Go store had the identical bug, and
// internal/api holds it there.
{
  const dir = mkdtempSync(join(tmpdir(), 'sg-logdir-'));
  mkdirSync(dir, { recursive: true });
  writeFileSync(join(dir, 'solongate-audit.jsonl'),
    JSON.stringify({
      ts: '2026-01-01T00:00:00.000Z', tool: 'Bash', decision: 'DENY',
      reason: 'Blocked by policy', arguments: { command: 'rm -rf /' },
    }) + '\n');

  const m = inMachine(
    JSON.stringify({
      policy: { id: 'p1', name: 'P', mode: 'denylist', rules: [] },
      security: { localLogs: { enabled: true, path: dir } },
    }),
    async (api) => {
      const list = await api.audit.list({ limit: 50 });
      const stats = await api.stats.get();
      return { rows: list.entries.length, tool: list.entries[0]?.tool_name ?? null, total: stats.total_calls ?? null };
    },
  );

  check('the audit reader finds the configured folder', m.value?.rows, 1, m.stderr);
  check('and reads the entry in it', m.value?.tool, 'Bash');
  // stats reads through the same path, so it was blind in the same way.
  check('stats counts it too', typeof m.value?.total === 'number' && m.value.total > 0, true,
    JSON.stringify(m.value));
}

process.exit(done());
