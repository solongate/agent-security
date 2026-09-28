package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// The port of src/db/index.ts's `schemaReady`.
//
// Four tables and several columns exist nowhere but here: they were added after
// the drizzle schema stopped being the migration source, and the Next app
// creates them in a promise every route awaits. Reproducing that is not
// optional. This binary and the Next app will run against the same database
// during the cutover, and a table created differently — a missing column, a
// missing index — is a divergence that shows up only as a query failing on one
// of them.
//
// So the statements below are src/db/index.ts's, in its order, including the
// ALTER TABLE calls whose failure is the EXPECTED outcome: they add a column to
// a table that already has it, and SQLite has no ADD COLUMN IF NOT EXISTS.
// That is why they are a separate list — an error from one of them is normal
// and must not stop the run, while an error from a CREATE TABLE is real.

// migrations are the statements that must succeed.
var migrations = []string{
	`CREATE INDEX IF NOT EXISTS audit_logs_session_id_idx ON audit_logs (project_id, session_id)`,
	// COVERING, and that is the whole point: every column the query needs is in
	// the index, so SQLite answers from it and never touches a row.
	//
	// Measured against production, where this project has some twenty thousand
	// audit rows. GET /stats took 1.4 to 5 SECONDS, and its four queries already
	// run in parallel — the cost was one of them, `SELECT decision, COUNT(*) …
	// GROUP BY decision`, walking every row of the project. The existing
	// (project_id, created_at) index finds those rows but still has to read each
	// one to learn its decision. COUNT(*) behind the paged audit list has the
	// same shape and is served by this too.
	//
	// It matters more than a settings page usually would because the dataroom's
	// Live panel opens with five of these calls at once and re-runs stats every
	// eight seconds, so this is the number a person watches the terminal fill in.
	`CREATE INDEX IF NOT EXISTS audit_logs_project_decision_idx ON audit_logs (project_id, decision)`,
	// The burst scan behind every page of the audit log: calls per agent per
	// minute over the window the page spans. Covering for the same reason as the
	// one above — agent_name is the only other column it reads, so with it in
	// the index the group-by never touches a row.
	`CREATE INDEX IF NOT EXISTS audit_logs_project_created_agent_idx ON audit_logs (project_id, created_at, agent_name)`,

	// token_usage: what a turn cost, one row per turn.
	//
	// NOT a column on audit_logs, and the reason is the GRAIN. Tokens are spent
	// per TURN — one exchange with the model — while an audit row is one TOOL
	// CALL, and a turn makes several. Writing a turn's tokens onto its calls
	// multiplies them by however many tools the model happened to reach for.
	//
	// It is scoped the same way audit_logs is — by project, and by api_key_id
	// and user_id within it — so the same WHERE that scopes a person's calls
	// scopes their tokens, and the two numbers cannot end up describing
	// different sets of people.
	//
	// `measure` says what KIND of number this is, because the clients do not
	// all report the same one. See the note on TokenMeasure.
	`CREATE TABLE IF NOT EXISTS token_usage (
      id TEXT PRIMARY KEY,
      project_id TEXT NOT NULL,
      api_key_id TEXT,
      user_id TEXT,
      session_id TEXT,
      agent_id TEXT,
      agent_name TEXT,
      source TEXT,
      measure TEXT NOT NULL DEFAULT 'billed',
      input_tokens INTEGER NOT NULL DEFAULT 0,
      output_tokens INTEGER NOT NULL DEFAULT 0,
      cache_read_tokens INTEGER NOT NULL DEFAULT 0,
      cache_write_tokens INTEGER NOT NULL DEFAULT 0,
      reasoning_tokens INTEGER NOT NULL DEFAULT 0,
      total_tokens INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    )`,
	// The two reads: a project over a window, and one person over a window.
	`CREATE INDEX IF NOT EXISTS token_usage_project_created_idx ON token_usage (project_id, created_at)`,
	`CREATE INDEX IF NOT EXISTS token_usage_project_key_created_idx ON token_usage (project_id, api_key_id, created_at)`,
	// A third read: one sitting, in the order it was spent, so a transcript can
	// show what each exchange cost between the messages.
	`CREATE INDEX IF NOT EXISTS token_usage_session_idx ON token_usage (session_id, created_at)`,

	//
	// The DOCUMENT is stored, not the numbers to rebuild it from. A report is a
	// statement about a period that has ended, and rebuilding one later reads
	// through retention: a span whose audit rows have since been swept would
	// come back thinner than the report a host actually acted on. What is in
	//
	// The id is derived from (project, span, period end) and rows are inserted
	// with OR IGNORE, so two instances ticking at the same second cannot file
	// the same report twice.

	// A host's request to a developer, and the developer's answer.
	//
	// The whole model is in `status`: a row is `pending` until the invited
	// person accepts it, and NOTHING is enforced on their machine before that.
	// because "cannot leave" is the point of the arrangement — and `revoked` is
	// reachable only by the host.
	//
	// somebody who has no account yet. That is why this is not `org_members`
	// with an extra column: a membership row needs a user, and an invitation
	// exists precisely before there is one.
	//
	// It is also not `user_invitations`, which has neither an org nor a project
	// on it, so its token resolves to an email and a role and to nothing that
	// could be joined to a policy. That table has no writer and one reader with
	// no callers.
	// The host's own groups, as things rather than as labels.
	//
	// is what lets one be created EMPTY and filled afterwards, which is the
	// order people actually organise in, and it is the only place a rename or a
	// colour could live. A label that exists only while somebody wears it
	// cannot be made first, renamed, or coloured.
	//
	// Not a foreign key onto an id, deliberately. Every read path in the
	// product resolves a group by its name already — the analytics scope, the
	// filters, the roster — and moving to an id would be a migration of live
	// data plus a rewrite of those queries to buy an atomic rename. See
	// One group per name per project. Two rows under one name would be two
	// answers to "what colour is this group", and the membership — which is
	// the name — could not tell them apart at all.
	// Where the HOST's own group lives.
	//
	// whole difference between them and everybody else on the page. A grant is
	// an arrangement between two people — a token, an invitation, an acceptance,
	// a revocation — and every one of those is meaningless pointed at the person
	// who owns the project, so they get a row that holds a label and nothing
	// else. It is also not a seat, which a grant would be.
	// One outstanding grant per address per project. A host who invites the
	// same developer twice is correcting a typo or resending, not creating a
	// second seat, and two rows would be two answers to "is this person a
	// hold an accepted grant on this project", and it runs on the guard's poll.
	// all, and how many developers they may invite.
	//
	// It is created here as well as in manage-go because either binary may boot
	// first against a fresh database, and a read of a table that does not exist
	// is an error rather than an empty answer. Both CREATEs are IF NOT EXISTS
	// and identical.
	//
	// granted_by is a literal rather than an identity: the admin session token
	// carries {admin:true} and no user at all, and adding a claim to it would
	// change a cookie shape that live browsers already hold.
	//
	// What people paste into a chat assistant in their BROWSER. Every other
	// table above records a machine acting through a guarded CLI; these three
	// record a person acting through Chrome, which is a different actor, a
	//
	// arrangement between two people: it has an email address, a token, an
	// invitation to accept and a revocation. A device has none of those. One
	// person runs three browsers on two laptops and every one of them is its
	// own row here; a browser cannot accept anything, and there is nobody to
	// invite. Reusing the grants table would mean either four grants for one
	// developer, which breaks the seat count a host is billed on, or four
	// browsers hidden behind one row, which is the whole feature gone.
	//
	// user_id and api_key_id are how a device is attributed back to a person
	// when the extension was installed with a key that carries one. Both are
	// nullable, because a browser that has only ever reported and never been
	// paired is still a browser a host needs to see on the roster.
	// The roster is read one way: a project's devices, most recently seen
	// first. The index is that query and nothing else.
	//
	// Per person rather than per device, because an operator adds a PERSON to a
	// this on its heartbeat and applies or removes the managed policy where the
	// machine gives it the rights. Absent is not enforced, which is the safe
	// default: enforcement is opt-in and has to be turned on deliberately.
	//
	// This is the one table in the schema that keeps the actual text - the
	// prompt somebody sent, the assistant's answer, the paste, the copy. Every
	// Sessions feature, where an operator reads what was actually said. It is a
	// deliberate reversal of "the text never leaves the machine", turned on for
	// this feature and this table only.
	//
	// conversation_id groups a thread; seq orders it. role is who spoke. text is
	// the content. detectors and verdict carry what DLP found and did, so a
	// message that was blocked shows why inline.
	// The retention sweep, which is the one read on this table with no project
	// database on a timer, and this is the widest table in the schema because
	//
	// This is the half that was missing, and its absence is why every mistake in
	// a transcript was permanent. A session is built by folding the acts a
	// person performed into the turns the page drew - and the act was DELETED
	// once folded, because it had become a line. So the line was the last copy
	// of it: a fold that put the wrong act in a seat could never be undone, a
	// turn the site renamed took its verdict to the grave, and a row that one
	// bad reading overwrote stayed overwritten for the life of the thread.
	//
	// So the acts live here, untouched by anything the transcript does, and
	// reading of the conversation and this table. Every sync recomputes the
	// whole thread from them. Nothing accumulates, nothing has to be repaired,
	// and a reading that was wrong is wrong exactly until the next one arrives.
	//
	// A session is rebuilt out of the turns the browser reports - which turns
	// there are, in what order, whose they are. That reading arrives on its own
	// schedule, and every act filed BETWEEN two of them had nowhere to be
	// placed until the next one came: a paste sat in the transcript as a loose
	// line, its finding not on the turn it belonged to, for as long as the page
	// happened to stay still. Measured against somebody watching the screen,
	// that is minutes, and the whole point of the feature is that the log and
	// the session agree the moment either of them moves.
	//
	// So the reading is KEPT, and every batch of lines is folded into it as it
	// arrives rather than waiting to be told the thread again. One row per
	// conversation per machine, replaced whole: this is a cache of the last
	// truth, never a history of it.
	// browser agent looked at.
	//
	// NOT audit_logs, and this is the decision the whole feature rests on.
	// That table's twenty-five columns are a TOOL-CALL ledger. Its POST body is
	// a frozen contract with hooks already installed on other people's laptops,
	// so a column cannot be added to it without a version of the hook that
	// nobody has yet; its decision vocabulary is ALLOW and DENY over tool
	// calls, and this one is allow, warn, block and report over a clipboard.
	// The actor is different too: a row there is a machine calling a tool, a
	// row here is a PERSON pasting into a text box. Mixing them would corrupt
	// every count a host reads off the dataroom, because "calls" would silently
	// start including pastes and "denies" would start including warnings.
	//
	// THE PASTED TEXT IS NEVER STORED. Not truncated, not redacted, not
	// encrypted: absent. What is here is the detector NAMES that fired, how
	// many bytes went across, which site it went to, and content_hash, which is
	// what makes "they pasted this same thing again" answerable without the
	// thing being here. The text a person pastes into ChatGPT is the most
	// sensitive payload this service could ever hold, and the only way it stays
	// safe is by not existing. A column added here to hold it, however well
	// meant, is this product becoming the leak it was bought to prevent.
	//
	// detectors is a JSON array of pattern names, so a row records that `tckn`
	// and `iban` matched and not what they matched. It is NOT NULL with a '[]'
	// default because the detector breakdown reads it through json_each, and
	// one malformed row there fails the whole query rather than that row.
	// The audit list, its COUNT, and every window aggregate on the overview.
	//
	// Deliberately not covering, unlike audit_logs_project_decision_idx. The
	// overview also counts DISTINCT devices, sites and people over the same
	// window, and no index answers those without the rows, so carrying verdict
	// along would pay for itself on one aggregate out of four while making
	// every insert on the busiest table in this schema dearer.
	// One device's stream, which is the roster's per-device counts and the
	// The retention sweep, which is the one read here with no project on it.
	// ONE PERSON'S EVENTS. Every per-person screen filters by user_id inside a
	// project and a time window, and without this the query walks the whole
	// project's window to find them. That is survivable while a project is one
	// team and is not survivable at fifteen thousand people: ninety days at
	// four hundred thousand events a day is forty million rows to scan for one
	// person's page.
	//
	// created_at is in the index rather than only in the filter because the
	// same screens order by it, so the index answers the ordering too instead
	// of handing a sort the rows it found.
	//
	// A ROW SAYING A SCREENSHOT CARRIED A NATIONAL ID IS A CLAIM SOMEBODY HAS
	// TO BE ABLE TO CHECK. Until this table the only thing beside it was the
	// RECOGNISED text - an engine's reading of a picture, wrong in the places
	// engines are wrong - and no way at all to answer "what did they actually
	// send". So the picture is kept, reduced to something worth keeping (see
	// sgocr.Thumb), and shown on the row.
	//
	// A SEPARATE TABLE AND NOT A COLUMN, for one reason: every read of the
	// audit list would carry it. The list is the busiest query in this schema
	// and it wants twenty short columns, not a JPEG per row; this is fetched by
	// primary key, once, by somebody who opened one row.
	//
	// AND IT IS KEPT FOR A SUBSET. The agent sends one only for pictures a rule
	// found something in or acted on, never for the clean ones - the same gate
	// the transcript has. A screenshot nobody's rule cared about is not
	// evidence of anything and is the majority of them.
	// The retention sweep, which runs with no project on it exactly as the
	// events one does. A picture that outlived the row it belongs to would be
	// the one thing in this schema nobody could find to delete.
	//
	// NOT policy_versions, and the reason is what the GUARD does with that
	// table. A guarded CLI polls for EVERY policy its project holds and picks
	// downloaded by every installed guard on every poll, forever, to be
	// discarded every time. It would also break ListPolicies, which GROUPs BY
	// policy to find each one's newest version: a row with a different shape
	// and no agent binding is an extra group in a list the dashboard renders
	// as the project's policies.
	//
	// project_id is the primary key because there is exactly one of these per
	// project. That makes the agent's poll a lookup by primary key, which is
	// the request this table serves most and the one that must stay cheap.
	//
	// version is a content hash rather than a counter: the agent polls with the
	// version it holds and a save that changed nothing must not make every
}

// addColumns are the ALTER TABLE statements. Every one of them fails on a
// database that has already been through this, which is every real database, so
// the error is discarded by design.
//
// The split into two phases is about ORDER against the CREATEs between them:
// `addColumnsBefore` runs first and targets tables the base schema already
// created, `addColumnsAfter` runs last so it can also touch anything
// `migrations` has just made. A single list would have to be correct for both
// and would silently stop being so.
var addColumnsBefore = []string{
	`ALTER TABLE policy_versions ADD COLUMN rego_source TEXT`,
	`ALTER TABLE policy_versions ADD COLUMN wasm_bundle TEXT`,
}

var addColumnsAfter = []string{
	// Which agent session a call belonged to. NULL on every row written before
	// the column existed, which is the honest answer: nobody recorded it.
	`ALTER TABLE audit_logs ADD COLUMN session_id TEXT`,

	// Who a key belongs to, as opposed to which project it opens.
	//
	// NULL is what every key issued before this column means, and it reads as
	// "acts as the owner" so nothing already paired changes behaviour.
	//
	// No foreign key: SQLite cannot add one through ALTER TABLE. It is declared
	// in baseschema.sql, which is what a database created from scratch gets.
	`ALTER TABLE api_keys ADD COLUMN user_id TEXT`,

	// The revoke that runs before every sign-in.
	//
	// authSession revokes the previous "Sign-in" key and mints a new one,
	// filtering on (project_id, name). The only index this table had was
	// project_id alone, so that statement narrows to a project and then walks
	// every key it has ever held — and the table only grows, because a revoked
	// key is stamped rather than deleted. On a project signed into for months,
	// that walk IS the sign-in.
	`CREATE INDEX IF NOT EXISTS api_keys_project_name_idx ON api_keys (project_id, name)`,

	// The compiled Rego and wasm for every variant OTHER than the default one,
	// as {"<variantId>": {"rego": "...", "wasm": "<base64>"}}.
	//

	// The duplicate guard org_members never had. It is in this list rather than
	// in migrations because it FAILS on any database that already holds a
	// duplicate row, and that is a real possibility: the check in orgMembersAdd
	// is a read followed by a write, so two concurrent adds both insert.
	//
	// Failing here is the right outcome. It leaves the existing read-then-write
	// guard in place, which is what those databases have today.
	`CREATE UNIQUE INDEX IF NOT EXISTS org_members_org_user_unique ON org_members (org_id, user_id)`,
}

// EnsureRuntimeTables runs the statements above, once per process.
//
// The Next app awaits `schemaReady` inside the routes that need these tables,
// which means a cold start pays for it on the first request. This runs it at
// boot instead: a route slice does not have to remember, and the failure — if
// there is one — is in the deploy log rather than in one unlucky request.
//
// It is idempotent and retried on demand, because the first attempt can fail
// against a database that is briefly unreachable and refusing to serve at all
// in that case would be worse: eleven of these objects already exist in every
// real database.
func (s *Store) EnsureRuntimeTables(ctx context.Context) error {
	s.schemaOnce.Lock()
	defer s.schemaOnce.Unlock()
	if s.schemaDone {
		return nil
	}

	for _, stmt := range addColumnsBefore {
		// Discarded on purpose: see addColumnsBefore.
		_, _ = s.exec(ctx, s.ddl(stmt))
	}
	for _, stmt := range migrations {
		if _, err := s.exec(ctx, s.ddl(stmt)); err != nil {
			// The statement is quoted, not the error alone, because "table
			// already exists" and "no such table: audit_logs" are very
			// different problems and only the statement says which.
			return fmt.Errorf("runtime schema: %.60s...: %w", stmt, err)
		}
	}
	for _, stmt := range addColumnsAfter {
		_, _ = s.exec(ctx, s.ddl(stmt))
	}

	s.schemaDone = true
	return nil
}

// schemaGuard is embedded in Store. It is here rather than in store.go so the
// whole runtime-schema concern reads as one file.
type schemaGuard struct {
	schemaOnce sync.Mutex
	schemaDone bool
}

// RuntimeDDL is every statement EnsureRuntimeTables would run, rendered for a
// dialect, in order.
//
// It exists for one reason: an on-premise installation's DBA wants the whole
// schema in a file they can read, apply, and hand to a change review — and a
// hardened installation does not give the application role CREATE on the
// schema at all. With this, the file they apply is complete and
// EnsureRuntimeTables finds everything already there and does nothing, which
// is the same code path either way.
//
// The optional column additions are included. They are the statements
// EnsureRuntimeTables deliberately ignores errors from, because they are
// ALTERs that have already been applied on any database older than the column;
// rendered for PostgreSQL they carry IF NOT EXISTS and so are safe to apply
// directly.
//
// SQLITE IS DIFFERENT AND THAT USED TO BREAK THE FILE. SQLite has no
// ADD COLUMN IF NOT EXISTS, so each of those ALTERs errored with "duplicate
// column name" against a database created from baseschema.sql — which declares
// all four. Four errors in a file whose whole purpose is to be applied by a DBA,
// and worse than noise: applied by anything that stops on error, the file aborted
// at the FIRST one and left a database missing a table and six indexes, reporting
// a duplicate-column error that pointed nowhere near the real problem.
//
// So RuntimeDDLFor takes the base schema into account. This function keeps the
// unfiltered list, because that is what EnsureRuntimeTables needs: on an OLD
// database the column really is absent and the ALTER really has to run.
func RuntimeDDL(d Dialect) []string {
	out := make([]string, 0, len(addColumnsBefore)+len(migrations)+len(addColumnsAfter))
	for _, group := range [][]string{addColumnsBefore, migrations, addColumnsAfter} {
		for _, stmt := range group {
			out = append(out, ddlFor(d, stmt))
		}
	}
	return out
}

// addColumnRe matches the ALTERs, capturing the table and the column.
var addColumnRe = regexp.MustCompile(`(?i)^ALTER TABLE\s+(\w+)\s+ADD COLUMN\s+(\w+)\b`)

// RuntimeDDLFor is RuntimeDDL with the ALTERs that a FROM-SCRATCH database does
// not need left out.
//
// It is what the schema dump uses when it also emits the base tables. An
// ALTER TABLE ... ADD COLUMN whose column the base schema already declares is not
// merely redundant there: on SQLite, which cannot say IF NOT EXISTS, it is an
// error — and a file that errors is a file a DBA cannot tell has applied.
//
// Only that exact case is dropped. An ALTER naming a column the base schema does
// NOT have still has work to do and is emitted, because the from-scratch database
// needs it too.
func RuntimeDDLFor(d Dialect, base []string) ([]string, error) {
	declared, err := baseColumns(base)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(addColumnsBefore)+len(migrations)+len(addColumnsAfter))
	for _, group := range [][]string{addColumnsBefore, migrations, addColumnsAfter} {
		for _, stmt := range group {
			if m := addColumnRe.FindStringSubmatch(strings.TrimSpace(stmt)); m != nil {
				if declared[strings.ToLower(m[1])+"."+strings.ToLower(m[2])] {
					continue
				}
			}
			out = append(out, ddlFor(d, stmt))
		}
	}
	return out, nil
}

// baseColumns is the set of `table.column` the rendered base schema declares.
//
// Parsed from the rendered CREATE TABLE text rather than from a list kept by
// hand: a hand-kept list is a second place to update and the first one anybody
// forgets, and getting it wrong here silently drops an ALTER a database needs.
func baseColumns(base []string) (map[string]bool, error) {
	out := map[string]bool{}
	for _, stmt := range base {
		m := createTableBodyRe.FindStringSubmatch(stmt)
		if m == nil {
			continue
		}
		table := strings.ToLower(m[1])
		body := m[2]
		depth := 0
		field := strings.Builder{}
		flush := func() {
			line := strings.TrimSpace(field.String())
			field.Reset()
			if line == "" {
				return
			}
			// A constraint clause is not a column.
			switch strings.ToUpper(strings.Fields(line)[0]) {
			case "PRIMARY", "FOREIGN", "UNIQUE", "CHECK", "CONSTRAINT":
				return
			}
			name := strings.Trim(strings.Fields(line)[0], "`\"[]")
			out[table+"."+strings.ToLower(name)] = true
		}
		for _, r := range body {
			switch {
			case r == '(':
				depth++
				field.WriteRune(r)
			case r == ')':
				depth--
				field.WriteRune(r)
			case r == ',' && depth == 0:
				flush()
			default:
				field.WriteRune(r)
			}
		}
		flush()
	}
	if len(out) == 0 {
		return nil, errors.New("store: parsed no columns out of the base schema")
	}
	return out, nil
}

// createTableBodyRe captures a rendered CREATE TABLE's name and its body. Both
// dialects are rendered from the same source, so one expression covers them —
// the quoting differs and the shape does not.
var createTableBodyRe = regexp.MustCompile(`(?is)^\s*CREATE TABLE\s+(?:IF NOT EXISTS\s+)?[\x60"]?(\w+)[\x60"]?\s*\((.*)\)\s*$`)
