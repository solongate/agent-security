// The SQL dialect this store is speaking.
//
// Every statement in this package was written for SQLite, which is what Turso
// serves and what the `file:` path opens. An on-premise installation has
// neither: it has the customer's own PostgreSQL, because that is what their DBA
// already operates, backs up and replicates, and because the audit log is the
// one table nobody may lose.
//
// SO THIS IS A SEAM, NOT A FORK. The 355 statements in this package are
// portable as written; seventeen of them are not, and those seventeen call a
// helper here instead of spelling SQLite out. The helper knows both dialects.
// A new statement that needs a third one will not compile until it is added,
// which is the property a fork cannot give.
//
// What is deliberately NOT here is a general SQL translator. Rewriting
// arbitrary SQL between dialects at runtime is a source of bugs that only
// appear on the customer's data, and a bug in this layer is a wrong answer to
// "who sent that", not a crash. Seventeen named cases can be read and tested;
// a translator cannot.
package store

import (
	"context"
	"database/sql"
	"fmt"
	"regexp"
	"strings"
)

// Dialect is which database the connected Store is talking to.
type Dialect int

const (
	// SQLite is Turso over Hrana and the local `file:` database. It is the
	// zero value so a Store built without a dialect behaves as it always did.
	SQLite Dialect = iota

	// Postgres is the on-premise deployment.
	Postgres
)

func (d Dialect) String() string {
	if d == Postgres {
		return "postgres"
	}
	return "sqlite"
}

// q prepares a statement for the connected dialect.
//
// Everything in this package is written with `?` placeholders because that is
// what SQLite takes. PostgreSQL numbers its parameters, so on that dialect the
// question marks are numbered here — once, at the point of use, rather than in
// 355 hand-edited strings.
func (s *Store) q(query string) string {
	if s.dialect != Postgres {
		return query
	}
	return numberPlaceholders(query)
}

// numberPlaceholders turns ? into $1, $2, … It walks the string rather than
// using a regexp so that a question mark inside a quoted literal is left alone.
// No statement in this package has one today; the day one does, this must not
// quietly corrupt it.
func numberPlaceholders(query string) string {
	var b strings.Builder
	b.Grow(len(query) + 8)

	var (
		n         int
		inSingle  bool
		inDouble  bool
		lineComnt bool
	)
	for i := 0; i < len(query); i++ {
		c := query[i]

		switch {
		case lineComnt:
			if c == '\n' {
				lineComnt = false
			}
		case inSingle:
			if c == '\'' {
				// '' is an escaped quote inside a string, not the end of one.
				if i+1 < len(query) && query[i+1] == '\'' {
					b.WriteByte(c)
					i++
					c = query[i]
				} else {
					inSingle = false
				}
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		case c == '-' && i+1 < len(query) && query[i+1] == '-':
			lineComnt = true
		case c == '?':
			n++
			b.WriteString(fmt.Sprintf("$%d", n))
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// --- the seventeen statements that are not portable ------------------------

// insertOrIgnore begins an INSERT that does nothing when the row is already
// there.
//
// SQLite spells this as a conflict clause on the INSERT itself; PostgreSQL puts
// it at the end, so the caller gets both halves and puts the second one after
// the VALUES.
//
//	q := s.insertOrIgnore("token_usage", "id, project_id, cost") +
//	     " VALUES (?, ?, ?)" + s.orIgnoreTail()
func (s *Store) insertOrIgnore(table, columns string) string {
	if s.dialect == Postgres {
		return "INSERT INTO " + table + " (" + columns + ")"
	}
	return "INSERT OR IGNORE INTO " + table + " (" + columns + ")"
}

// orIgnoreTail closes an insertOrIgnore. Empty on SQLite, where the intent was
// already stated at the front of the statement.
func (s *Store) orIgnoreTail() string {
	if s.dialect == Postgres {
		return " ON CONFLICT DO NOTHING"
	}
	return ""
}

// jsonField reads a top-level string field out of a JSON column.
//
// The path is a LITERAL in every caller and must stay one: it names a field in
// a document this code wrote, not a value from a request. Binding it would also
// not work, since neither dialect takes a parameter there.
func (s *Store) jsonField(column, field string) string {
	if s.dialect == Postgres {
		// ->> yields text, matching json_extract's behaviour for a string
		// field, which is what every caller compares and groups by.
		return fmt.Sprintf("(%s::jsonb ->> '%s')", column, field)
	}
	return fmt.Sprintf("json_extract(%s, '$.%s')", column, field)
}

// dayBucket formats a unix-seconds column as YYYY-MM-DD, in UTC.
//
// UTC is explicit on both sides. SQLite's strftime with 'unixepoch' is already
// UTC; PostgreSQL's to_timestamp yields a timestamptz that to_char would render
// in the session's TimeZone, so a server set to Europe/Istanbul would bucket a
// 01:30 event into the previous day. Every caller compares these strings
// against dates computed in UTC elsewhere.
func (s *Store) dayBucket(column string) string {
	if s.dialect == Postgres {
		return fmt.Sprintf("to_char(to_timestamp(%s) AT TIME ZONE 'UTC', 'YYYY-MM-DD')", column)
	}
	return fmt.Sprintf("strftime('%%Y-%%m-%%d', %s, 'unixepoch')", column)
}

// hourBucket formats a unix-seconds column as the hour of day, 0 to 23, as an
// integer. Same timezone argument as dayBucket.
func (s *Store) hourBucket(column string) string {
	if s.dialect == Postgres {
		return fmt.Sprintf("EXTRACT(HOUR FROM to_timestamp(%s) AT TIME ZONE 'UTC')::int", column)
	}
	return fmt.Sprintf("CAST(strftime('%%H', %s, 'unixepoch') AS INTEGER)", column)
}

// timeBucket formats a unix-seconds column with a granularity chosen at
// runtime. The caller passes one of the Bucket constants rather than a format
// string, because the two dialects spell the formats differently and a format
// string crossing this boundary would have to be translated per value.
//
// THE RENDERED KEYS ARE PART OF THE CONTRACT. A route zero-fills the gaps in
// the series by formatting timestamps in Go and matching them against these
// strings, so "2026-09-01" and "2026-09" are not interchangeable: the shorter
// one misses every row the database returned and the chart reads as all
// zeroes. BucketMonth therefore keeps the day component.
type Bucket int

const (
	BucketHour Bucket = iota
	BucketDay
	BucketMonth
)

func (s *Store) timeBucket(column string, b Bucket) string {
	if s.dialect == Postgres {
		layout := map[Bucket]string{
			BucketHour:  "YYYY-MM-DD HH24:00",
			BucketDay:   "YYYY-MM-DD",
			BucketMonth: "YYYY-MM-01",
		}[b]
		return fmt.Sprintf("to_char(to_timestamp(%s) AT TIME ZONE 'UTC', '%s')", column, layout)
	}
	layout := map[Bucket]string{
		BucketHour:  "%Y-%m-%d %H:00",
		BucketDay:   "%Y-%m-%d",
		BucketMonth: "%Y-%m-01",
	}[b]
	return fmt.Sprintf("strftime('%s', %s, 'unixepoch')", layout, column)
}

// --- the runtime schema ----------------------------------------------------

// ddl prepares one CREATE/ALTER statement for the connected dialect.
//
// The statements in schema.go are written for SQLite and are portable almost as
// they stand: TEXT means the same thing in both, and both take
// `CREATE TABLE IF NOT EXISTS`. Three things differ and all three matter.
//
// INTEGER is 32 bits in PostgreSQL and 64 in SQLite, and the swap is BLANKET
// rather than per column on purpose.
//
// The source cannot tell you which columns need it: SQLite's INTEGER is already
// 64 bits, so a column holding milliseconds since the epoch (about 1.7e12) and a
// column holding a small count are spelled identically and behave identically
// there. Widening the ones somebody remembered would leave the rest to fail as
// an insert error on a customer's database, years in, on the row that finally
// exceeded two billion.
//
// REAL is 32-bit floating point in PostgreSQL and 64-bit in SQLite, so a trust
// score written as 0.8271 would come back as 0.8271000385284424.
//
// A BOOLEAN DEFAULT ON AN INTEGER COLUMN is accepted by SQLite and rejected by
// PostgreSQL. SQLite stores `DEFAULT true` on an integer column as 1 without
// complaint; PostgreSQL types the default expression and refuses "column is of
// type bigint but default expression is of type boolean". The columns are
// integers in both — the Go side scans them as ints — so the DEFAULT is what
// moves, not the type. See integerBoolDefaults.
//
// ADD COLUMN has no IF NOT EXISTS in SQLite, which is why the caller discards
// its errors. PostgreSQL has one, so on that side the statement says what it
// means instead of relying on an error being ignored.
func (s *Store) ddl(stmt string) string { return ddlFor(s.dialect, stmt) }

// ddlFor is ddl without a Store, so the statements can be rendered for a
// dialect the process is not connected to — which is what lets an on-premise
// installation ship the complete schema to its DBA instead of asking the
// application for DDL rights at boot. See RuntimeDDL.
func ddlFor(d Dialect, stmt string) string {
	if d != Postgres {
		return stmt
	}
	out := replaceTypeToken(stmt, "INTEGER", "BIGINT")
	out = replaceTypeToken(out, "REAL", "DOUBLE PRECISION")
	out = replaceTypeToken(out, "BLOB", "BYTEA")
	out = integerBoolDefaults(out)
	if strings.Contains(out, "ADD COLUMN ") && !strings.Contains(out, "IF NOT EXISTS") {
		out = strings.Replace(out, "ADD COLUMN ", "ADD COLUMN IF NOT EXISTS ", 1)
	}
	// Same reasoning for indexes. Inside EnsureRuntimeTables an unguarded
	// CREATE INDEX is merely noisy — it is in the group whose errors are
	// discarded, so it fails on every boot after the first and nobody notices.
	// Rendered into a schema file for a DBA to apply it is not noisy at all:
	// it aborts the transaction and takes the other forty-eight tables with it.
	if strings.HasPrefix(out, "CREATE ") && strings.Contains(out, " INDEX ") && !strings.Contains(out, "IF NOT EXISTS") {
		out = strings.Replace(out, " INDEX ", " INDEX IF NOT EXISTS ", 1)
	}
	return out
}

// integerBoolDefaults rewrites `DEFAULT true` to `DEFAULT 1` on the columns that
// are integers, and leaves every other DEFAULT alone.
//
// It works a LINE at a time, and that is the whole of what makes it safe. The
// type and the default of one column are on one line in every statement this
// package renders, so a line carrying both BIGINT and a boolean default is an
// integer column with a boolean default and nothing else can be. A statement-wide
// substitution would rewrite the default of a real BOOLEAN column two lines down,
// which is the one case that must not move: there are none today, and the first
// one added must not silently become an integer.
//
// Only BIGINT is matched, never INTEGER, because this runs after the widening
// above — so the rule cannot fire on a dialect that was not translated.
func integerBoolDefaults(stmt string) string {
	lines := strings.Split(stmt, "\n")
	for i, line := range lines {
		if !strings.Contains(line, "BIGINT") {
			continue
		}
		lines[i] = boolDefaultRe.ReplaceAllStringFunc(line, func(m string) string {
			if strings.HasSuffix(strings.ToLower(m), "true") {
				return "DEFAULT 1"
			}
			return "DEFAULT 0"
		})
	}
	return strings.Join(lines, "\n")
}

// boolDefaultRe matches a bare boolean default. The word boundary keeps it off
// `DEFAULT 'true'`, which is a quoted string and a text column's business.
var boolDefaultRe = regexp.MustCompile(`(?i)\bDEFAULT\s+(true|false)\b`)

// replaceTypeToken swaps a bare word, leaving quoted strings and identifiers
// alone. A column literally named "integer" would be quoted in the DDL and is
// therefore safe; a DEFAULT '...' containing the word is safe for the same
// reason.
func replaceTypeToken(stmt, from, to string) string {
	var (
		b        strings.Builder
		inSingle bool
		inDouble bool
	)
	b.Grow(len(stmt) + 16)

	isWord := func(c byte) bool {
		return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
	}

	for i := 0; i < len(stmt); {
		c := stmt[i]
		switch {
		case inSingle:
			if c == '\'' {
				inSingle = false
			}
		case inDouble:
			if c == '"' {
				inDouble = false
			}
		case c == '\'':
			inSingle = true
		case c == '"':
			inDouble = true
		default:
			if len(stmt)-i >= len(from) && strings.EqualFold(stmt[i:i+len(from)], from) {
				before := i == 0 || !isWord(stmt[i-1])
				after := i+len(from) >= len(stmt) || !isWord(stmt[i+len(from)])
				if before && after {
					b.WriteString(to)
					i += len(from)
					continue
				}
			}
		}
		b.WriteByte(c)
		i++
	}
	return b.String()
}

// --- the database handle, dialect-aware ------------------------------------
//
// Every statement in this package goes through one of these four rather than
// through s.db directly, so the placeholder style is applied once, at the only
// place a statement can reach the database. Calling s.db.ExecContext is not
// wrong so much as unreviewable: it would work on Turso and fail on a
// customer's PostgreSQL, and nothing in the build would say so.
//
// `make lint` greps for the direct forms.

func (s *Store) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return s.db.ExecContext(ctx, s.q(query), args...)
}

func (s *Store) query(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return s.db.QueryContext(ctx, s.q(query), args...)
}

func (s *Store) queryRow(ctx context.Context, query string, args ...any) *sql.Row {
	return s.db.QueryRowContext(ctx, s.q(query), args...)
}

// txExec, txQuery and txQueryRow are the same for the four transactions in this
// package. They take the Store so the dialect is available; the transaction
// itself carries no dialect of its own.

func (s *Store) txExec(ctx context.Context, tx *sql.Tx, query string, args ...any) (sql.Result, error) {
	return tx.ExecContext(ctx, s.q(query), args...)
}

func (s *Store) txQuery(ctx context.Context, tx *sql.Tx, query string, args ...any) (*sql.Rows, error) {
	return tx.QueryContext(ctx, s.q(query), args...)
}

func (s *Store) txQueryRow(ctx context.Context, tx *sql.Tx, query string, args ...any) *sql.Row {
	return tx.QueryRowContext(ctx, s.q(query), args...)
}

// greatest returns the larger of two values.
//
// SQLite's MAX is both the aggregate and a two-argument scalar; PostgreSQL
// splits them and calls the scalar one GREATEST. The device upsert uses it to
// keep the later of two last_seen timestamps when an agent reports out of
// order.
func (s *Store) greatest(a, b string) string {
	if s.dialect == Postgres {
		return "GREATEST(" + a + ", " + b + ")"
	}
	return "MAX(" + a + ", " + b + ")"
}

// jsonArrayJoin expands a JSON array column into one row per element, bound to
// alias.value.
//
// The detector breakdown counts (event, detector) pairs, which means one row
// per element of a text column holding a JSON array. SQLite has json_each;
// PostgreSQL has jsonb_array_elements_text, and needs LATERAL because the
// expression refers to the row.
//
// The CASE is not defensive styling. Both engines raise on a column that is not
// an array, and one malformed row would otherwise fail the whole query rather
// than that row: a person's breakdown would read as empty because somebody
// else's agent wrote something odd once.
func (s *Store) jsonArrayJoin(column, alias string) string {
	if s.dialect == Postgres {
		return fmt.Sprintf(
			`CROSS JOIN LATERAL jsonb_array_elements_text(CASE WHEN %s ~ '^\s*\[' THEN %s::jsonb ELSE '[]'::jsonb END) AS %s(value)`,
			column, column, alias)
	}
	return fmt.Sprintf(
		`JOIN json_each(CASE WHEN json_valid(%s) THEN %s ELSE '[]' END) %s`,
		column, column, alias)
}
