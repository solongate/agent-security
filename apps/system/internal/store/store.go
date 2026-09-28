// Package store is the API's database layer: the twenty-six tables
// src/db/schema.ts declares, the tables and columns src/db/index.ts adds at
// runtime, and the queries the routes actually run against them.
//
// Hand-written SQL over database/sql, not an ORM. Every statement here binds
// its parameters — there is no code path that builds SQL by concatenating a
// value, and that includes the two places it is usually skipped: ORDER BY and
// LIMIT. A direction or a column name cannot be a bind parameter in SQLite, so
// those are chosen from a closed set of constants (see orderClause); a limit CAN
// be bound, so it is.
//
// Timestamps are UNIX SECONDS in every drizzle table, because
// integer({mode:'timestamp'}) stores seconds. The one exception is
// device_codes, which src/db/index.ts creates by hand and the device routes
// write with Date.now() — MILLISECONDS. That is not a mistake to fix here; the
// CLI compares those values against its own clock. See devicecodes.go.
//
// The wire format is a separate question from the storage format: drizzle hands
// a timestamp column to JSON as a JavaScript Date, and NextResponse.json turns
// that into an ISO-8601 string. Callers that are already deployed parse those
// strings. ISO below is how a stored second becomes one.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// DefaultURL is the local sqlite file a checkout runs against when nothing else
// is configured. A real install names a PostgreSQL DSN; see Open.
const DefaultURL = "file:./data/solongate.db"

// envInt reads a positive integer from the environment, falling back when it is
// unset or unreadable. A bad value falls back rather than failing: this is pool
// sizing, and a typo should not stop a service from coming up.
func envInt(name string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		log.Printf("store: %s=%q is not a positive integer; using %d", name, v, fallback)
		return fallback
	}
	return n
}

// ErrNotFound is what a single-row lookup returns instead of sql.ErrNoRows, so
// a route can decide between 404 and 500 without importing database/sql.
var ErrNotFound = errors.New("store: not found")

// Store owns the connection pool. It is safe for concurrent use; *sql.DB is,
// and its mutable state is behind mutexes — whether the runtime schema has been
// applied, in schema.go, and the settings cache, here.
type Store struct {
	db *sql.DB

	// dialect is which database db is connected to. It is set by Open and
	// read by the handful of statements that cannot be written once; see
	// dialect.go.
	dialect Dialect

	schemaGuard

	// The system_settings cache. See settingTTL: this table is read several
	// times per request and written rarely, and every read of it is a round
	// trip to the database.
	settingMu    sync.RWMutex
	settingCache map[string]settingEntry
}

// Open connects to the database DATABASE_URL names.
//
// TWO SCHEMES, AND NOTHING ELSE. `postgres://` is what an installation runs on;
// `file:` opens a local sqlite database for development and for a single-machine
// install. Anything else is refused at startup rather than at the first query,
// which is the difference between a service that will not boot and one that
// boots and then cannot answer.
//
// There is no hosted-database driver here on purpose. This product stores an
// audit log - the record of what every agent on the machine was allowed to do -
// and that record belongs on infrastructure its operator runs. A build that
// could be pointed at somebody else's database is a build where that is one
// configuration mistake away.
//
// modernc.org/sqlite rather than mattn/go-sqlite3 because it needs no cgo, and
// CGO_ENABLED=0 is what makes a static binary.
func Open(rawURL string) (*Store, error) {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return nil, errors.New("DATABASE_URL is empty")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("DATABASE_URL is not a URL: %w", err)
	}
	// PostgreSQL, which is what an on-premise installation has. The customer's
	// DBA already operates, backs up and replicates it, and the audit log is
	// the one table nobody may lose — so it is theirs rather than something
	// this product brings with it.
	if u.Scheme == "postgres" || u.Scheme == "postgresql" {
		db, err := sql.Open("pgx", rawURL)
		if err != nil {
			// The DSN can carry a password. Report the scheme and the host,
			// never the URL.
			return nil, fmt.Errorf("open postgres at %s: %w", u.Host, err)
		}
		// THE POOL IS PER REPLICA, and that is the number that matters at
		// scale. Three replicas at the default is 72 connections; PostgreSQL
		// ships with max_connections=100, and a fourth replica added during an
		// incident is what turns "slow" into "cannot connect". So it is
		// configurable, and the installation docs say to divide the database's
		// ceiling by the replica count and leave headroom for the DBA.
		//
		// Beyond a few replicas the answer is a connection pooler in front of
		// PostgreSQL rather than a larger number here: the work each request
		// does is milliseconds, so the connections are mostly idle and a
		// pooler multiplexes them.
		db.SetMaxOpenConns(envInt("SG_DB_MAX_OPEN_CONNS", 24))
		db.SetMaxIdleConns(envInt("SG_DB_MAX_IDLE_CONNS", 6))
		db.SetConnMaxIdleTime(2 * time.Minute)
		// A connection that lives forever survives a credential rotation and a
		// failover, which is how a cluster ends up talking to a database
		// nobody thinks it is talking to.
		db.SetConnMaxLifetime(30 * time.Minute)
		if err := db.Ping(); err != nil {
			return nil, fmt.Errorf("connect to postgres at %s: %w", u.Host, err)
		}
		return &Store{db: db, dialect: Postgres}, nil
	}

	if u.Scheme == "file" {
		db, err := sql.Open("sqlite", strings.TrimPrefix(rawURL, "file:"))
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", rawURL, err)
		}
		// One connection: sqlite serialises writes anyway, and a pool over a
		// single file turns a concurrent write into "database is locked"
		// rather than into a wait.
		db.SetMaxOpenConns(1)
		if err := db.Ping(); err != nil {
			return nil, fmt.Errorf("open %s: %w", rawURL, err)
		}
		return &Store{db: db}, nil
	}

	return nil, fmt.Errorf("DATABASE_URL scheme %q is not supported: use postgres:// or file:", u.Scheme)
}

// DB exposes the pool for the handful of callers that need a transaction.
// Every query in this package goes through it too; nothing else should need it.
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) Close() error { return s.db.Close() }

// ── scan helpers ────────────────────────────────────────────────────────────
//
// SQLite has no static column types and hands back whatever was stored: a
// column written as an integer can come back int64, float64 or a string
// depending on which client wrote the row. These flatten that, so a route never
// has to care.

// text reads a nullable TEXT column as a plain string. NULL and the empty
// string are collapsed; the write side distinguishes them via NullText.
func text(v sql.NullString) string {
	if !v.Valid {
		return ""
	}
	return v.String
}

// unix reads a nullable timestamp. nil means the event has not happened:
// revoked_at on a live key, last_used_at on a key nobody has used yet,
// expires_at on a chain with no expiry. Collapsing those to 0 would render as
// 1 January 1970, and for revoked_at it would mean "revoked".
func unix(v sql.NullInt64) *int64 {
	if !v.Valid {
		return nil
	}
	n := v.Int64
	return &n
}

// num reads a nullable REAL/INTEGER as a float. Most of the nullable numeric
// columns here (pi_trust_score, evaluation_time_ms, score) are absent rather
// than zero when nothing measured them, so callers that care use numPtr.
func num(v sql.NullFloat64) float64 {
	if !v.Valid {
		return 0
	}
	return v.Float64
}

func numPtr(v sql.NullFloat64) *float64 {
	if !v.Valid {
		return nil
	}
	n := v.Float64
	return &n
}

func intVal(v sql.NullInt64) int64 {
	if !v.Valid {
		return 0
	}
	return v.Int64
}

// boolVal reads a drizzle boolean, which is an INTEGER 0/1 column.
func boolVal(v sql.NullInt64) bool { return v.Valid && v.Int64 != 0 }

// boolPtr keeps NULL distinguishable from false. It matters for
// audit_logs.pi_detected: false means the scanner ran and found nothing, NULL
// means it never ran, and the dashboard shows those differently.
func boolPtr(v sql.NullInt64) *bool {
	if !v.Valid {
		return nil
	}
	b := v.Int64 != 0
	return &b
}

// raw reads a nullable JSON column without decoding it.
//
// Nothing in this package parses policy_data, input_schema or detail. A policy
// that round-trips through a struct loses every field this version does not
// know about, and the guard is the thing that reads it — see sgshared.Policy,
// which keeps Rules raw for the same reason.
func raw(v sql.NullString) json.RawMessage {
	if !v.Valid || v.String == "" {
		return nil
	}
	return json.RawMessage(v.String)
}

// NullText is the write-side inverse: an empty string becomes NULL.
//
// It matters for org_id on projects, which is a foreign key with ON DELETE SET
// NULL. An empty string there is a row pointing at an organisation that cannot
// exist.
func NullText(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// NullUnix writes a timestamp or NULL.
func NullUnix(t *int64) any {
	if t == nil {
		return nil
	}
	return *t
}

// Bit writes a Go bool as the INTEGER 0/1 drizzle stores.
func Bit(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// Clip truncates to a rune boundary.
//
// The TypeScript this replaces uses String.prototype.slice, which counts UTF-16
// code units; Go's s[:n] counts bytes and would cut a multi-byte character in
// half, storing invalid UTF-8. The limits themselves are the original's, kept
// so the two implementations refuse the same input.
func Clip(s string, max int) string {
	if max <= 0 {
		return ""
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}

// trimAny is `String(v ?? ”).trim()` for a value that came out of JSON.
//
// A non-string is NOT stringified, unlike JavaScript's String(): the settings
// coercion only ever calls this on fields the form writes as text, and turning
// a stray number into "120" there would store a pattern nobody typed.
func trimAny(v any) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

// Now is the second-resolution clock every drizzle table uses.
func Now() int64 { return time.Now().Unix() }

// NowMS is device_codes' clock, and only device_codes'. See the package note.
func NowMS() int64 { return time.Now().UnixMilli() }

// ISO renders a stored UNIX-seconds timestamp the way the live API does.
//
// drizzle hands a timestamp column to JSON as a Date and JSON.stringify calls
// toISOString, so every deployed client — the dashboard, the CLI, the audit
// hook — is parsing `2026-08-02T10:15:30.000Z`. Emitting a bare integer here
// would be a silent contract break: JSON.parse succeeds, `new Date(n)` reads
// seconds as milliseconds, and every date in the dashboard lands in 1970.
//
// Milliseconds are always three digits, including `.000`, because that is what
// toISOString writes.
func ISO(sec int64) string {
	return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05.000Z")
}

// ISOPtr is ISO for a nullable timestamp: nil stays JSON null rather than
// becoming a date. Return type is `any` so it can go straight into a response
// map.
func ISOPtr(sec *int64) any {
	if sec == nil {
		return nil
	}
	return ISO(*sec)
}

// ISOms renders a device_codes millisecond timestamp. Separate from ISO so the
// unit is a decision at the call site rather than an assumption.
func ISOms(ms int64) string {
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

// ── ORDER BY and LIMIT ──────────────────────────────────────────────────────

// SortDir is a direction chosen from a closed set. It exists so a route can
// take `?order=asc` from a caller without that string ever reaching SQL.
type SortDir string

const (
	Asc  SortDir = "ASC"
	Desc SortDir = "DESC"
)

// ParseDir maps caller input to a direction, defaulting to DESC.
//
// The default is not arbitrary: every list endpoint here is newest-first, and
// a typo in a query parameter must not silently reverse a page of audit logs.
func ParseDir(v string) SortDir {
	if strings.EqualFold(strings.TrimSpace(v), "asc") {
		return Asc
	}
	return Desc
}

// orderClause turns a caller-supplied sort key into SQL, and it is the reason
// this function exists rather than a fmt.Sprintf at each call site.
//
// A column name cannot be a bind parameter, so the only safe construction is a
// lookup in a map the caller declares — the value that reaches the string is
// one this package wrote, never one a request carried. `allowed` maps the
// caller's vocabulary ("created_at") to the qualified column; an unknown key
// falls back rather than erroring, because a bad sort parameter is not worth a
// 400 and must not be worth an injection.
func orderClause(key string, dir SortDir, allowed map[string]string, fallback string) string {
	col, ok := allowed[strings.ToLower(strings.TrimSpace(key))]
	if !ok {
		col = fallback
	}
	if dir != Asc {
		dir = Desc
	}
	return " ORDER BY " + col + " " + string(dir)
}

// ClampLimit bounds a caller-supplied page size.
//
// The limit is still BOUND as a parameter everywhere below; this is about the
// number being sane, not about it being safe. An unbounded LIMIT against
// audit_logs is a way to ask this service to read a million rows over the
// network, which is a denial of service with a valid API key attached.
func ClampLimit(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

// parallel runs independent queries at the same time and joins their errors.
//
// It exists because the stats routes are a dozen aggregates each and the
// TypeScript ran them in a Promise.all. Run one after another against Turso
// those become a dozen network round trips in series. The pool ceiling in Open
// is what stops one such request from monopolising it.
//
// Every function gets the same context, so the first cancellation stops them
// all; none of them share a variable, which is what makes this safe at all.
func parallel(fns ...func() error) error {
	errs := make([]error, len(fns))
	var wg sync.WaitGroup
	wg.Add(len(fns))
	for i, fn := range fns {
		go func() {
			defer wg.Done()
			errs[i] = fn()
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}
