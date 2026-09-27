package store

import "testing"

func TestNumberPlaceholders(t *testing.T) {
	cases := map[string]string{
		`SELECT * FROM t WHERE a = ? AND b = ?`: `SELECT * FROM t WHERE a = $1 AND b = $2`,
		`INSERT INTO t (a,b,c) VALUES (?,?,?)`:  `INSERT INTO t (a,b,c) VALUES ($1,$2,$3)`,
		`SELECT * FROM t`:                       `SELECT * FROM t`,

		// A question mark inside a literal is not a placeholder. No statement
		// in this package has one today, and the day one does this must not
		// quietly renumber the ones around it.
		`SELECT '?' , a FROM t WHERE b = ?`:         `SELECT '?' , a FROM t WHERE b = $1`,
		`SELECT "we?ird", a FROM t WHERE b = ?`:     `SELECT "we?ird", a FROM t WHERE b = $1`,
		`SELECT 'it''s ?', a FROM t WHERE b = ?`:    `SELECT 'it''s ?', a FROM t WHERE b = $1`,
		"SELECT a FROM t -- is this ?\nWHERE b = ?": "SELECT a FROM t -- is this ?\nWHERE b = $1",
	}
	for in, want := range cases {
		if got := numberPlaceholders(in); got != want {
			t.Errorf("numberPlaceholders(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// The statements are written once and read on two databases. q must be a no-op
// on SQLite or every existing deployment changes behaviour.
func TestQIsANoOpOnSQLite(t *testing.T) {
	s := &Store{dialect: SQLite}
	const q = `SELECT * FROM t WHERE a = ? AND b = ?`
	if got := s.q(q); got != q {
		t.Fatalf("SQLite rewrote a statement: %q", got)
	}
	p := &Store{dialect: Postgres}
	if got := p.q(q); got == q {
		t.Fatal("Postgres did not number the placeholders")
	}
}

// INTEGER is 32 bits in PostgreSQL. device_codes.expires_at holds milliseconds
// since the epoch, which does not fit, so this is the check that keeps a
// customer's database from rejecting inserts.
func TestDDLWidensIntegers(t *testing.T) {
	p := &Store{dialect: Postgres}

	got := p.ddl(`CREATE TABLE IF NOT EXISTS example (
      id TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL DEFAULT 0,
      confidence INTEGER NOT NULL DEFAULT 0,
      trust REAL,
      body TEXT NOT NULL DEFAULT ''
    )`)

	for _, want := range []string{"expires_at BIGINT", "confidence BIGINT", "trust DOUBLE PRECISION", "body TEXT"} {
		if !hasText(got, want) {
			t.Errorf("want %q in:\n%s", want, got)
		}
	}
	if hasText(got, "INTEGER") {
		t.Errorf("an INTEGER survived:\n%s", got)
	}
}

// The word must be replaced as a type, not wherever it appears.
func TestDDLLeavesLiteralsAndIdentifiersAlone(t *testing.T) {
	p := &Store{dialect: Postgres}

	got := p.ddl(`CREATE TABLE t (note TEXT DEFAULT 'an INTEGER value', "integer" TEXT, kind TEXT)`)
	if !hasText(got, `'an INTEGER value'`) {
		t.Errorf("a quoted literal was rewritten:\n%s", got)
	}
	if !hasText(got, `"integer"`) {
		t.Errorf("a quoted identifier was rewritten:\n%s", got)
	}

	// A column whose name merely contains the word is not a type.
	got = p.ddl(`CREATE TABLE t (integer_count BIGINT, my_real TEXT)`)
	if hasText(got, "BIGINT_count") || hasText(got, "my_DOUBLE PRECISION") {
		t.Errorf("a substring was rewritten:\n%s", got)
	}
}

func TestDDLMakesAddColumnIdempotentOnPostgres(t *testing.T) {
	p := &Store{dialect: Postgres}
	got := p.ddl(`ALTER TABLE example ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`)
	want := `ALTER TABLE example ADD COLUMN IF NOT EXISTS expires_at BIGINT NOT NULL DEFAULT 0`
	if got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}

	// SQLite has no such clause, and the caller discards the error instead.
	s := &Store{dialect: SQLite}
	in := `ALTER TABLE example ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0`
	if got := s.ddl(in); got != in {
		t.Errorf("SQLite statement was rewritten: %q", got)
	}
}

func TestDialectHelpers(t *testing.T) {
	sq, pg := &Store{dialect: SQLite}, &Store{dialect: Postgres}

	if got := sq.jsonField("policy_data", "id"); got != `json_extract(policy_data, '$.id')` {
		t.Errorf("sqlite jsonField = %q", got)
	}
	if got := pg.jsonField("policy_data", "id"); got != `(policy_data::jsonb ->> 'id')` {
		t.Errorf("postgres jsonField = %q", got)
	}

	if got := sq.dayBucket("created_at"); got != `strftime('%Y-%m-%d', created_at, 'unixepoch')` {
		t.Errorf("sqlite dayBucket = %q", got)
	}
	// UTC is explicit: a server in Europe/Istanbul would otherwise bucket a
	// 01:30 event into the previous day.
	if got := pg.dayBucket("created_at"); !hasText(got, "AT TIME ZONE 'UTC'") || !hasText(got, "YYYY-MM-DD") {
		t.Errorf("postgres dayBucket = %q", got)
	}

	if got := pg.hourBucket("created_at"); !hasText(got, "EXTRACT(HOUR") || !hasText(got, "UTC") {
		t.Errorf("postgres hourBucket = %q", got)
	}

	// The month key keeps its day component. A route zero-fills the series by
	// formatting timestamps in Go and matching these strings, so "2026-09"
	// would miss every row "2026-09-01" returned.
	if got := pg.timeBucket("created_at", BucketMonth); !hasText(got, "'YYYY-MM-01'") {
		t.Errorf("postgres monthly bucket = %q", got)
	}
	if got := sq.timeBucket("created_at", BucketMonth); !hasText(got, "'%Y-%m-01'") {
		t.Errorf("sqlite monthly bucket = %q", got)
	}

	// Hour and day keys must match what the route's fill produces too.
	if got := sq.timeBucket("created_at", BucketHour); !hasText(got, "'%Y-%m-%d %H:00'") {
		t.Errorf("sqlite hourly bucket = %q", got)
	}
	if got := pg.timeBucket("created_at", BucketHour); !hasText(got, "'YYYY-MM-DD HH24:00'") {
		t.Errorf("postgres hourly bucket = %q", got)
	}
}

func TestInsertOrIgnore(t *testing.T) {
	sq, pg := &Store{dialect: SQLite}, &Store{dialect: Postgres}

	if got := sq.insertOrIgnore("token_usage", "id, cost") + " VALUES (?, ?)" + sq.orIgnoreTail(); got != `INSERT OR IGNORE INTO token_usage (id, cost) VALUES (?, ?)` {
		t.Errorf("sqlite = %q", got)
	}
	if got := pg.insertOrIgnore("token_usage", "id, cost") + " VALUES (?, ?)" + pg.orIgnoreTail(); got != `INSERT INTO token_usage (id, cost) VALUES (?, ?) ON CONFLICT DO NOTHING` {
		t.Errorf("postgres = %q", got)
	}
}

// hasText is a local substring check; the package already has a `contains`
// helper in another test file with a different meaning.
func hasText(haystack, needle string) bool {
	if needle == "" {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
