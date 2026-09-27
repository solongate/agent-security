package store

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The two queries behind the dataroom's slowest screen have to be answered from
// an index, not from the rows.
//
// Measured against production, where one project holds some twenty thousand
// audit rows: GET /stats took between 1.4 and 5 seconds. Its four queries
// already run in parallel, so the cost was one of them —
//
//	SELECT decision, COUNT(*) FROM audit_logs WHERE project_id = ? GROUP BY decision
//
// The (project_id, created_at) index finds the project's rows but has to READ
// each one to learn its decision, so the query walked every row. COUNT(*) behind
// the paged audit list has the same shape.
//
// audit_logs_project_decision_idx makes both COVERING: every column the query
// needs is in the index, so SQLite never touches a row.
//
// It is asserted through EXPLAIN QUERY PLAN rather than by timing, because a
// timing test on a fixture with three rows measures nothing — the index only
// matters at the size that made this slow, and the plan is what says whether it
// is being used at all.
func TestTheAuditCountsAreAnsweredFromAnIndex(t *testing.T) {
	db := filepath.Join(t.TempDir(), "plan.sqlite")
	s, err := Open("file:" + db)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// The base schema this package does not own: EnsureRuntimeTables adds the
	// index, but audit_logs itself comes from the migration.
	if _, err := s.db.ExecContext(context.Background(), `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id TEXT PRIMARY KEY,
			project_id TEXT NOT NULL,
			session_id TEXT,
			decision TEXT NOT NULL,
			created_at INTEGER NOT NULL,
			agent_name TEXT
		)`); err != nil {
		t.Fatalf("audit_logs: %v", err)
	}
	if err := s.EnsureRuntimeTables(context.Background()); err != nil {
		t.Fatalf("EnsureRuntimeTables: %v", err)
	}

	for _, c := range []struct {
		what string
		sql  string
		why  string
	}{
		{
			what: "the stats decision counts",
			sql:  `SELECT decision, COUNT(*) FROM audit_logs WHERE project_id = ? GROUP BY decision`,
			why: "this is the query that made GET /stats take seconds. Without a covering index it " +
				"reads every audit row the project has, and the dataroom's Live panel re-runs it every " +
				"eight seconds",
		},
		{
			what: "the paged audit total",
			sql:  `SELECT COUNT(*) FROM audit_logs WHERE project_id = ?`,
			why:  "the count behind every page of the audit log, on the same table and the same shape",
		},
		{
			what: "the burst scan",
			sql: `SELECT agent_name, created_at / 60 AS minute, COUNT(*) FROM audit_logs
			      WHERE project_id = ? AND created_at >= 0 AND created_at <= 0
			      GROUP BY agent_name, minute`,
			why: "the rate-limit burst scan runs on every page of the audit log, over the whole " +
				"window those fifty entries span — which on a busy project is hours of traffic",
		},
	} {
		rows, err := s.db.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+c.sql, "p1")
		if err != nil {
			t.Fatalf("%s: %v", c.what, err)
		}
		var plan strings.Builder
		for rows.Next() {
			var a, b, d int
			var detail string
			if err := rows.Scan(&a, &b, &d, &detail); err != nil {
				rows.Close()
				t.Fatalf("%s: scanning the plan: %v", c.what, err)
			}
			plan.WriteString(detail)
			plan.WriteString(" ")
		}
		rows.Close()

		got := plan.String()
		if strings.Contains(got, "SCAN audit_logs") {
			t.Errorf("%s does a full table SCAN.\n  plan: %s\n  %s", c.what, got, c.why)
			continue
		}
		if !strings.Contains(got, "COVERING INDEX") {
			t.Errorf("%s is not answered from a covering index, so every matching row is read.\n"+
				"  plan: %s\n  %s", c.what, got, c.why)
		}
	}
}

// The audit list must not drag compiled policy across the wire.
//
// It calls the rules history on every page to put a NAME to a matched rule id,
// and it reads policy_data and nothing else. The FULL history selects
// rego_source and wasm_bundle beside it — a compiled WASM bundle per version,
// thirty versions deep — so a request returning fifty audit entries was moving
// megabytes to look up a string.
//
// Asserted on the SQL rather than on a duration: a fixture has no bundles in it,
// so the only thing that can be measured here is whether the column is asked
// for at all.
func TestTheRulesHistoryDoesNotSelectCompiledPolicy(t *testing.T) {
	src, err := os.ReadFile("policies.go")
	if err != nil {
		t.Fatalf("policies.go: %v", err)
	}
	i := strings.Index(string(src), "func (s *Store) PolicyRulesHistory")
	if i < 0 {
		t.Fatal("PolicyRulesHistory is gone; the audit list is back on the full history")
	}
	body := string(src)[i:]
	if j := strings.Index(body[1:], "\nfunc "); j > 0 {
		body = body[:j]
	}
	for _, heavy := range []string{"wasm_bundle", "rego_source"} {
		if strings.Contains(body, heavy) {
			t.Errorf("PolicyRulesHistory selects %s. It exists precisely to avoid that — "+
				"the audit list reads policy_data and nothing else, and a compiled bundle per "+
				"version is what made this request slow", heavy)
		}
	}
}
