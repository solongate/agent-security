#!/usr/bin/env node
/**
 * Build a local database with the real schema, so the Go ports can be run
 * against data instead of read.
 *
 * The API writes its SQL by hand against twenty-six tables. Reading a query
 * carefully is the wrong kind of confidence for that, and the failures it hides
 * are the ones a reader cannot see — a column renamed, a join on a key that is
 * not there, an aggregate over the wrong type. This builds a file: database with
 * the real shape and enough rows to reach the SQL, in about four seconds.
 *
 * The schema is tools/schema/sqlite.sql, which is GENERATED — do not edit it.
 * Its source is apps/api-go/internal/store/baseschema.sql plus the statements
 * EnsureRuntimeTables runs, and both dialects are regenerated with
 *
 *   cd apps/api-go && go run ./cmd/schemadump -dialect sqlite   > ../../tools/schema/sqlite.sql
 *   cd apps/api-go && go run ./cmd/schemadump -dialect postgres > ../../tools/schema/postgres.sql
 *
 *   node tools/local-db.mjs                 # build it
 *   node tools/local-db.mjs --seed-only     # keep the schema, re-seed
 *
 * It prints the DATABASE_URL and an API key to use.
 *
 * ONE THING WORTH KNOWING before reading a failure as a bug in the Go: sqlite
 * takes ONE writer. Running two processes against this file at once, while one
 * of them is applying a runtime migration, produces SQLITE_BUSY and a 502 that
 * looks exactly like a broken query. PostgreSQL does not have this problem,
 * which is why it is a property of the harness rather than of the code.
 */
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const out = join(repo, '.local-db');
const dbFile = join(out, 'solongate.sqlite');
const seedOnly = process.argv.includes('--seed-only');

// A key with a body the guard's isRealKey accepts: sg_live_ plus hex.
const API_KEY = 'sg_live_' + 'abcdef0123456789'.repeat(3);

function ddl(name) {
  return readFileSync(join(repo, 'tools', 'schema', name), 'utf-8');
}

/**
 * Apply statement by statement, skipping the ones that collide.
 *
 * The separator is `;` followed by a blank line, which is what schemadump emits
 * between statements. Splitting on a bare `;` would be wrong the first time a
 * DEFAULT contains one.
 *
 * The base statements and the runtime ones overlap — EnsureRuntimeTables adds
 * indexes and columns to tables the base schema creates — so a collision here is
 * the correct outcome rather than an error to fix.
 */
function apply(db, sql) {
  let applied = 0, skipped = 0;
  const statements = sql
    .split(/;\r?\n\r?\n/)
    .map((s) => s.replace(/^\s*--[^\n]*\n/gm, '').trim())
    .filter(Boolean)
    .map((s) => s.replace(/;\s*$/, ''));
  for (const stmt of statements) {
    try { db.exec(stmt); applied++; } catch (e) {
      // The two collisions this is allowed to step over, and only these two.
      // "already exists" is a CREATE the base schema got to first. "duplicate
      // column name" is SQLite's answer to ADD COLUMN on a column that is
      // already there — it has no IF NOT EXISTS for that, which is why
      // EnsureRuntimeTables discards the same error at runtime. Anything else
      // is a schema that does not apply and must not read as a clean run.
      if (/already exists|duplicate column name/i.test(e.message)) skipped++;
      else throw e;
    }
  }
  return { applied, skipped };
}

const { DatabaseSync } = await import('node:sqlite');

if (!seedOnly) {
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
}
mkdirSync(out, { recursive: true });

const db = new DatabaseSync(dbFile);

if (!seedOnly) {
  console.log('applying tools/schema/sqlite.sql…');
  const api = apply(db, ddl('sqlite.sql'));
  console.log(`  ${api.applied} statements, ${api.skipped} already present`);
}

// ── seed ────────────────────────────────────────────────────────────────────
// The smallest set of rows that makes the real routes return something. The
// point is not coverage, it is REACHING the SQL.

const now = Math.floor(Date.now() / 1000);
const columns = (t) => db.prepare(`PRAGMA table_info(${t})`).all();

function insert(table, vals) {
  const info = columns(table);
  if (info.length === 0) return;
  const have = new Set(info.map((c) => c.name));
  const use = Object.fromEntries(Object.entries(vals).filter(([k]) => have.has(k)));
  // Fill anything NOT NULL that was not named, so the seeder survives the
  // schema growing a column rather than becoming the thing nobody updates.
  for (const c of info) {
    if (c.name in use || !c.notnull || c.dflt_value !== null) continue;
    const int = /INT/i.test(c.type || '');
    use[c.name] = int ? (c.name.endsWith('_at') ? now : 0) : '';
  }
  const keys = Object.keys(use);
  db.prepare(`INSERT OR REPLACE INTO ${table} (${keys.join(',')}) VALUES (${keys.map(() => '?').join(',')})`)
    .run(...keys.map((k) => use[k]));
}

const rules = [{
  id: 'deny-marker', description: 'Blocked for the local database',
  effect: 'DENY', priority: 10, toolPattern: '*',
  minimumTrustLevel: 'UNTRUSTED', enabled: true,
  commandConstraints: { denied: ['*sg-local-deny*'] },
}];

insert('users', { id: 'u1', email: 'ada@example.com', name: 'Ada', created_at: now, updated_at: now });
insert('organizations', { id: 'org1', name: 'Acme', slug: 'acme', owner_id: 'u1', created_at: now, updated_at: now });
insert('org_members', { id: 'om1', org_id: 'org1', user_id: 'u1', role: 'owner', created_at: now, updated_at: now });
insert('projects', {
  id: 'p1', owner_id: 'u1', org_id: 'org1', name: 'Demo', slug: 'demo',
  description: 'local', token_secret: 's3cr3t', created_at: now, updated_at: now,
});
insert('api_keys', {
  id: 'k1', project_id: 'p1', key_prefix: API_KEY.slice(0, 16),
  key_hash: createHash('sha256').update(API_KEY).digest('hex'),
  name: 'local', is_live: 1, created_at: now,
});
// policy_data holds the WHOLE policy — id, name, mode and rules — which is why
// there is no rules column. Reading that off the real table rather than
// guessing is the entire reason this file exists.
insert('policy_versions', {
  id: 'pv1', project_id: 'p1', version: 1, hash: 'localhash', reason: 'local', created_by: 'u1',
  policy_data: JSON.stringify({ id: 'pv1', name: 'Local policy', mode: 'denylist', rules }),
  created_at: now,
});
insert('agents', {
  id: 'a1', project_id: 'p1', agent_id: 'claude-code', agent_name: 'claude-code',
  first_seen_at: now, last_seen_at: now, total_calls: 3, allowed_calls: 1, denied_calls: 2,
});
for (let i = 0; i < 3; i++) {
  insert('audit_logs', {
    id: `al${i}`, project_id: 'p1', request_id: `req${i}`, session_id: 's1',
    tool_name: 'bash', permission: 'EXECUTE', trust_level: 'TRUSTED',
    decision: i ? 'DENY' : 'ALLOW', reason: 'local row', evaluation_time_ms: 1,
    arguments_summary: 'echo hi', agent_id: 'claude-code', agent_name: 'claude-code',
    api_key_id: 'k1', created_at: now - i * 60,
  });
}

const counted = ['users', 'organizations', 'projects', 'api_keys', 'policy_versions', 'agents', 'audit_logs']
  .map((t) => `${t}=${db.prepare(`SELECT COUNT(*) AS n FROM ${t}`).get().n}`);
console.log('seeded:', counted.join(' '));
db.close();

writeFileSync(join(out, 'api-key.txt'), API_KEY + '\n');

console.log(`
Run the API against it:

  cd apps/api-go && PORT=8098 DATABASE_URL="file:${dbFile}" go run .

  curl -H "Authorization: Bearer ${API_KEY}" http://localhost:8098/api/v1/policies
`);
