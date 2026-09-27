package store

import (
	"regexp"
	"strings"
	"testing"
)

// The base schema converts, and PostgreSQL would accept the result.
//
// Every assertion here is one of the three things the conversion does, plus the
// one it must not do. The reason they are worth pinning is that the failures are
// all silent until somebody applies the file to a production database: a backtick
// is a syntax error, a narrow integer is an insert that fails in a year, and a
// table before its dependency is an error at apply time in the middle of a
// change window.
func TestBaseSchemaConvertsForPostgres(t *testing.T) {
	stmts, err := BaseDDL(Postgres)
	if err != nil {
		t.Fatal(err)
	}
	if len(stmts) == 0 {
		t.Fatal("no statements")
	}
	all := strings.Join(stmts, "\n")

	if strings.Contains(all, "`") {
		t.Error("a backtick survived; PostgreSQL reads it as a syntax error")
	}
	// `integer` in the source is lowercase, which is why the widening is
	// EqualFold rather than a plain replace.
	if regexp.MustCompile(`(?i)\binteger\b`).MatchString(all) {
		t.Error("an integer was not widened to BIGINT")
	}
	if regexp.MustCompile(`(?i)\breal\b`).MatchString(all) {
		t.Error("a real was not widened to DOUBLE PRECISION")
	}
	// The one that was found by applying it: drizzle writes a boolean default on
	// an integer column, and PostgreSQL types the default expression.
	if regexp.MustCompile(`(?i)\bDEFAULT\s+(true|false)\b`).MatchString(all) {
		t.Error("a boolean default survived on an integer column")
	}
}

// SQLite gets the file back as it was written, minus the quoting.
//
// The point is that the conversion is dialect-driven and not a rewrite: asking
// for SQLite must not widen anything, because widening is what PostgreSQL needs
// and SQLite's INTEGER is already 64 bits.
func TestBaseSchemaLeavesSQLiteAlone(t *testing.T) {
	stmts, err := BaseDDL(SQLite)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(stmts, "\n")

	if strings.Contains(all, "BIGINT") || strings.Contains(all, "DOUBLE PRECISION") {
		t.Error("SQLite was handed PostgreSQL types")
	}
	if strings.Contains(all, "`") {
		t.Error("a backtick survived")
	}
}

// A table comes after every table its foreign keys reference.
//
// This is the assertion that would have caught the ordering problem without a
// database: drizzle emits alphabetically, and `org_members` references
// `organizations`, which sorts after it.
func TestBaseSchemaOrdersTablesAfterTheirReferences(t *testing.T) {
	stmts, err := BaseDDL(Postgres)
	if err != nil {
		t.Fatal(err)
	}

	created := map[string]bool{}
	createTable := regexp.MustCompile(`(?is)^\s*CREATE\s+TABLE\s+(\w+)`)
	references := regexp.MustCompile(`(?is)REFERENCES\s+(\w+)`)

	for _, st := range stmts {
		m := createTable.FindStringSubmatch(st)
		if m == nil {
			continue
		}
		table := m[1]
		for _, r := range references.FindAllStringSubmatch(st, -1) {
			target := r[1]
			if target == table {
				// A self-reference is satisfied by this statement.
				continue
			}
			if !created[target] {
				// Only a table this file creates can be waited for; one that
				// belongs to the runtime schema is not this ordering's problem.
				if baseSchemaCreates(stmts, target) {
					t.Errorf("%s references %s, which this file creates later", table, target)
				}
			}
		}
		created[table] = true
	}
}

// baseSchemaCreates reports whether the base schema creates a table at all.
func baseSchemaCreates(stmts []string, table string) bool {
	re := regexp.MustCompile(`(?is)^\s*CREATE\s+TABLE\s+` + regexp.QuoteMeta(table) + `\b`)
	for _, st := range stmts {
		if re.MatchString(st) {
			return true
		}
	}
	return false
}

// An identifier PostgreSQL reserves has to be caught, not emitted bare.
//
// The converter drops every backtick, which is right for the identifiers in this
// schema and wrong the moment somebody adds a column called `order`. It would
// apply to SQLite and fail on PostgreSQL, so the parse refuses instead.
func TestBaseSchemaRefusesAReservedIdentifier(t *testing.T) {
	_, err := parseBaseSchema("CREATE TABLE t (`order` text NOT NULL)")
	if err == nil {
		t.Fatal("a reserved identifier was accepted")
	}
	if !strings.Contains(err.Error(), "order") {
		t.Errorf("the error does not name the identifier: %v", err)
	}

	// And a non-reserved keyword is fine bare, which is why the check is the
	// reserved list rather than the keyword list.
	if _, err := parseBaseSchema("CREATE TABLE t (`key` text NOT NULL)"); err != nil {
		t.Errorf("a non-reserved keyword was refused: %v", err)
	}
}
