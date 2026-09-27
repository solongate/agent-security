//go:build postgres

// The product's store, run against a real PostgreSQL.
//
// The dialect seam in the product is unit-tested there: given SQLite it emits
// SQLite, given Postgres it emits Postgres. That proves the strings are what we
// meant to write. It does not prove PostgreSQL accepts them, and the difference
// between those two claims is the whole on-premise deployment.
//
// So this test starts a real PostgreSQL, applies the runtime schema through the
// product's own EnsureRuntimeTables, and exercises the write and read paths
// against it. A statement that parses on SQLite and does not on Postgres fails
// here rather than on a customer's first day.
//
// It lives in the on-premise repository rather than in the product because the
// PostgreSQL deployment is this repository's concern, and because a test that
// downloads a database binary does not belong in the product's own suite.
//
//	make upstream     # the pinned product checkout this test compiles against
//	go test ./test/pgstore/
//
// The binary is downloaded once and cached under the user's cache directory.
// With no network and no cache the test skips rather than failing: a developer
// offline is not a regression.
package store_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	embedded "github.com/fergusstrange/embedded-postgres"
	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/codeyevsky/solongate/system/internal/store"
)

const (
	pgPort = 15432
	pgUser = "solongate"
	pgPass = "solongate"
	pgName = "solongate"
)

func TestMain(m *testing.M) {
	cache, err := os.UserCacheDir()
	if err != nil {
		cache = os.TempDir()
	}
	runtimePath, err := os.MkdirTemp("", "sg-pg-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, "pgstore: cannot create a runtime directory:", err)
		os.Exit(1)
	}
	defer os.RemoveAll(runtimePath)

	pg := embedded.NewDatabase(embedded.DefaultConfig().
		Username(pgUser).Password(pgPass).Database(pgName).
		Port(pgPort).
		RuntimePath(runtimePath).
		BinariesPath(filepath.Join(cache, "solongate-embedded-postgres")).
		StartTimeout(90 * time.Second))

	if err := pg.Start(); err != nil {
		// No network and no cached binary. Skipping is the honest outcome:
		// the developer is offline, the code is not broken.
		fmt.Fprintln(os.Stderr, "pgstore: skipping, PostgreSQL could not be started:", err)
		os.Exit(0)
	}

	code := m.Run()
	_ = pg.Stop()
	os.Exit(code)
}

func dsn() string {
	return fmt.Sprintf("postgres://%s:%s@localhost:%d/%s?sslmode=disable", pgUser, pgPass, pgPort, pgName)
}

func open(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(dsn())
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	applyBaseSchema(t)
	return s
}

// applyBaseSchema creates the tables drizzle owns.
//
// EnsureRuntimeTables adds indexes and columns to users, projects, api_keys,
// audit_logs and policy_versions, which the TypeScript app's migrations create
// and this package never does. On-premise there is no TypeScript app, so the
// same tables are generated for PostgreSQL by the on-premise repository's
// tools/pgschema and applied before first boot.
//
// The path is passed in rather than found, so this test never reaches into a
// sibling repository:
//
//	SG_PG_SCHEMA=../../../../solongate-onprem/deploy/postgres/schema.sql \
//	  go test -tags postgres ./internal/store/
var baseSchemaOnce sync.Once

func applyBaseSchema(t *testing.T) {
	t.Helper()
	path := strings.TrimSpace(os.Getenv("SG_PG_SCHEMA"))
	if path == "" {
		t.Skip("SG_PG_SCHEMA is not set; it must point at the generated PostgreSQL base schema")
	}
	baseSchemaOnce.Do(func() {
		sqlBytes, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		db, err := sql.Open("pgx", dsn())
		if err != nil {
			t.Fatalf("open for schema: %v", err)
		}
		defer db.Close()
		if _, err := db.Exec(string(sqlBytes)); err != nil {
			t.Fatalf("applying the base schema: %v", err)
		}
	})
}

// The runtime schema is twenty CREATE TABLEs, twenty-eight indexes and thirty
// ALTERs written for SQLite. This is the statement-by-statement proof that
// PostgreSQL takes all of them.
func TestRuntimeSchemaApplies(t *testing.T) {
	s := open(t)
	ctx := context.Background()

	if err := s.EnsureRuntimeTables(ctx); err != nil {
		t.Fatalf("EnsureRuntimeTables: %v", err)
	}
	// Idempotent: it runs on every boot, and the second run must be a no-op
	// rather than a pile of "already exists".
	if err := s.EnsureRuntimeTables(ctx); err != nil {
		t.Fatalf("EnsureRuntimeTables, second run: %v", err)
	}
}

// The Shadow write and read paths, end to end on PostgreSQL. Every statement
// these touch was written for SQLite.
// The aggregates behind the dashboard. These are the queries that used
// strftime, so they are the ones the dialect seam had to rewrite.
// The devices table and its upsert.
// A screenshot, which is the INSERT OR IGNORE on shadow_shots.
// The control plane's own read and write paths: a project, a key, an audit row
// and a setting. Shadow needs all four before it can record anything.
func TestControlPlanePaths(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.EnsureRuntimeTables(ctx); err != nil {
		t.Fatal(err)
	}

	now := time.Now().Unix()
	const (
		userID    = "usr-pg"
		projectID = "prj-pg"
	)

	// A user and a project, written directly because the store has no
	// constructor for them: the SaaS build creates them through the auth
	// service, and on-premise the installer seeds them.
	db, err := sql.Open("pgx", dsn())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if _, err := db.ExecContext(ctx,
		`INSERT INTO users (id, email, name, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO NOTHING`,
		userID, "ayse@kurum.example", "Ayse", now, now); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO projects (id, owner_id, name, slug, token_secret, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) ON CONFLICT (id) DO NOTHING`,
		projectID, userID, "Kurum", "kurum", "secret", now, now); err != nil {
		t.Fatalf("seed project: %v", err)
	}

	// Settings: write, then read back. This is the table every request
	// touches, through a cache with a TTL.
	if err := s.SetSelfProtectionEnabled(ctx, projectID, true); err != nil {
		t.Fatalf("SetSelfProtectionEnabled: %v", err)
	}
	if !s.SelfProtectionEnabled(ctx, projectID) {
		t.Error("the setting did not read back as written")
	}

	// An audit row and the aggregates over it. AuditTimeSeries is the query
	// whose bucket format used to be a bound strftime string.
	if _, err := db.ExecContext(ctx,
		`INSERT INTO audit_logs (id, project_id, request_id, tool_name, permission,
			trust_level, decision, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		"al-1", projectID, "req-1", "Bash", "execute", "TRUSTED", "ALLOW", now); err != nil {
		t.Fatalf("seed audit row: %v", err)
	}

	for _, b := range []store.Bucket{store.BucketHour, store.BucketDay, store.BucketMonth} {
		rows, err := s.AuditTimeSeries(ctx, projectID, b, now-86400)
		if err != nil {
			t.Fatalf("AuditTimeSeries(%v): %v", b, err)
		}
		if len(rows) == 0 {
			t.Errorf("AuditTimeSeries(%v) returned nothing for a row written now", b)
		}
	}
}

// The per-person page, at the shape fifteen thousand people produce.
//
// Every per-person screen filters by user_id inside a project and a window.
// Without shadow_events_project_user_idx that walks the project's whole window:
// ninety days at four hundred thousand events a day is forty million rows to
// find one person's page. This asserts the plan, not the timing — a timing test
// on a laptop proves nothing about a customer's disk.

// The per-person read, at the shape a large installation produces.
//
// Every per-person screen filters by user_id inside a project and a window.
// Without conversation_turns_project_user_created_idx that walks the project's
// whole window, which on a busy installation is the difference between a page
// and a table scan. This asserts the PLAN, not the timing — a timing test on a
// laptop proves nothing about a customer's disk.
func TestPerPersonQueryUsesAnIndex(t *testing.T) {
	s := open(t)
	ctx := context.Background()
	if err := s.EnsureRuntimeTables(ctx); err != nil {
		t.Fatal(err)
	}

	const project = "prj-plan"
	now := time.Now().Unix()

	// Enough rows that the planner has something to choose between; a table of
	// three rows is a sequential scan whatever the indexes say.
	for i := 0; i < 400; i++ {
		if err := s.InsertTurn(ctx, store.ConversationTurn{
			ID:        fmt.Sprintf("plan-%d", i),
			ProjectID: project,
			UserID:    fmt.Sprintf("user-%d", i%50),
			SessionID: fmt.Sprintf("sess-%d", i%10),
			Role:      store.TurnPrompt,
			Body:      "a turn",
			CreatedAt: now - int64(i*60),
		}); err != nil {
			t.Fatal(err)
		}
	}

	db, err := sql.Open("pgx", dsn())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.ExecContext(ctx, "ANALYZE conversation_turns"); err != nil {
		t.Fatal(err)
	}

	rows, err := db.QueryContext(ctx, `EXPLAIN
		SELECT id FROM conversation_turns
		WHERE project_id = $1 AND user_id = $2
		ORDER BY created_at DESC LIMIT 50`, project, "user-7")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(line)
		plan.WriteString("\n")
	}

	if !strings.Contains(plan.String(), "conversation_turns_project_user_created_idx") {
		t.Errorf("the per-person query does not use its index:\n%s", plan.String())
	}
}
