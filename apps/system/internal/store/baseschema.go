package store

// The BASE schema, and the one thing this file exists to fix.
//
// baseschema.sql beside this file is drizzle's SQLite output: backtick-quoted
// identifiers, lowercase `text`/`integer`/`real`, and tables in alphabetical
// order. PostgreSQL rejects the first, keeps the second too narrow, and refuses
// the third whenever a table's foreign key names one it has not seen yet.
//
// So a PostgreSQL installation had no base schema in this repository at all. The
// file was applied to SQLite and the PostgreSQL equivalent lived somewhere else,
// which means "this product runs on PostgreSQL" was true of the code and false of
// anything you could check out. This turns the one file into both.
//
// WHAT IT DOES NOT DO: reformat, reorder columns, or improve anything. Every
// statement comes out with the same columns, defaults and constraints it went in
// with. Three mechanical changes and nothing else:
//
//   - backticks dropped. Every identifier in that file is a bare lowercase word;
//     `key` is the only one PostgreSQL knows as a keyword and it is non-reserved,
//     so it needs no quoting. parseBaseSchema REFUSES a reserved one rather than
//     emitting it bare, so a future column called `order` fails here instead of
//     at apply time on somebody's database.
//   - types through the same ddlFor the runtime statements use, so `integer`
//     becomes BIGINT here for exactly the reason it does there.
//   - CREATE TABLE statements sorted so a table follows the ones its foreign
//     keys reference. Indexes keep their place after the tables.

import (
	"embed"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

//go:embed baseschema.sql
var baseSchemaFS embed.FS

// pgReserved is the set a bare identifier may not be, checked at parse time.
//
// It is PostgreSQL's RESERVED list, not its keyword list: the keyword list has
// hundreds of entries most of which are legal as identifiers, and refusing those
// would mean quoting everything to satisfy a check rather than a database.
var pgReserved = map[string]bool{
	"all": true, "analyse": true, "analyze": true, "and": true, "any": true, "array": true,
	"as": true, "asc": true, "asymmetric": true, "both": true, "case": true, "cast": true,
	"check": true, "collate": true, "column": true, "constraint": true, "create": true,
	"current_catalog": true, "current_date": true, "current_role": true, "current_time": true,
	"current_timestamp": true, "current_user": true, "default": true, "deferrable": true,
	"desc": true, "distinct": true, "do": true, "else": true, "end": true, "except": true,
	"false": true, "fetch": true, "for": true, "foreign": true, "from": true, "grant": true,
	"group": true, "having": true, "in": true, "initially": true, "intersect": true,
	"into": true, "lateral": true, "leading": true, "limit": true, "localtime": true,
	"localtimestamp": true, "not": true, "null": true, "offset": true, "on": true,
	"only": true, "or": true, "order": true, "placing": true, "primary": true,
	"references": true, "returning": true, "select": true, "session_user": true,
	"some": true, "symmetric": true, "table": true, "then": true, "to": true,
	"trailing": true, "true": true, "union": true, "unique": true, "user": true,
	"using": true, "variadic": true, "when": true, "where": true, "window": true, "with": true,
}

var (
	backtickIdent = regexp.MustCompile("`([^`]*)`")
	createTableRe = regexp.MustCompile(`(?is)^\s*CREATE\s+TABLE\s+(\w+)`)
	referencesRe  = regexp.MustCompile(`(?is)REFERENCES\s+(\w+)`)
)

// BaseDDL is baseschema.sql rendered for a dialect, in an order PostgreSQL will
// accept.
//
// It returns an error rather than panicking because the failure it can have is a
// real one — a new identifier that has to be quoted — and a caller generating a
// schema file wants to be told, not to lose a stack trace into a redirect.
func BaseDDL(d Dialect) ([]string, error) {
	raw, err := baseSchemaFS.ReadFile("baseschema.sql")
	if err != nil {
		return nil, fmt.Errorf("base schema: %w", err)
	}

	stmts, err := parseBaseSchema(string(raw))
	if err != nil {
		return nil, err
	}
	stmts = orderByDependency(stmts)

	out := make([]string, 0, len(stmts))
	for _, st := range stmts {
		out = append(out, ddlFor(d, st.sql))
	}
	return out, nil
}

// baseStmt is one statement and what the ordering needs to know about it.
type baseStmt struct {
	sql string
	// table is the table a CREATE TABLE creates, empty for anything else.
	table string
	// needs is the tables its foreign keys reference, minus itself: a
	// self-reference is satisfied by the statement that is creating it.
	needs []string
}

// parseBaseSchema splits the file and drops the backticks.
//
// The separator is drizzle's `--> statement-breakpoint`, which is a comment to
// both databases and a delimiter to its own tooling. Splitting on semicolons
// instead would be wrong the first time a DEFAULT contains one.
func parseBaseSchema(src string) ([]baseStmt, error) {
	var out []baseStmt
	for _, chunk := range strings.Split(src, "--> statement-breakpoint") {
		chunk = strings.TrimSpace(chunk)
		chunk = strings.TrimSuffix(chunk, ";")
		chunk = strings.TrimSpace(chunk)
		if chunk == "" {
			continue
		}

		// Unquote, checking each identifier as it goes. A name PostgreSQL would
		// read as a keyword has to be caught here: unquoted it is a syntax error
		// at apply time, in a file somebody is applying to a production database.
		var bad []string
		unquoted := backtickIdent.ReplaceAllStringFunc(chunk, func(m string) string {
			name := m[1 : len(m)-1]
			if pgReserved[strings.ToLower(name)] {
				bad = append(bad, name)
			}
			return name
		})
		if len(bad) > 0 {
			return nil, fmt.Errorf("base schema: %q is reserved in PostgreSQL and was quoted in the "+
				"source; it needs quoting in the output too, which this converter does not do", bad[0])
		}

		st := baseStmt{sql: unquoted}
		if m := createTableRe.FindStringSubmatch(unquoted); m != nil {
			st.table = m[1]
			for _, r := range referencesRe.FindAllStringSubmatch(unquoted, -1) {
				if r[1] != st.table {
					st.needs = append(st.needs, r[1])
				}
			}
		}
		out = append(out, st)
	}
	return out, nil
}

// orderByDependency puts every CREATE TABLE after the tables it references, and
// leaves everything else in place behind the tables.
//
// A cycle cannot be resolved and is emitted in the input's order rather than
// dropped: PostgreSQL would need one of the constraints added separately, and a
// schema that fails loudly at apply time is better than one this silently
// reorders into something else.
func orderByDependency(stmts []baseStmt) []baseStmt {
	var tables, rest []baseStmt
	for _, st := range stmts {
		if st.table != "" {
			tables = append(tables, st)
		} else {
			rest = append(rest, st)
		}
	}

	known := map[string]bool{}
	for _, st := range tables {
		known[st.table] = true
	}

	var ordered []baseStmt
	placed := map[string]bool{}
	remaining := tables
	for len(remaining) > 0 {
		var progressed bool
		var next []baseStmt
		// Sorted so the output is the same on every run: the input order already
		// is, but a map read on the ready set would not be.
		sort.SliceStable(remaining, func(i, j int) bool { return remaining[i].table < remaining[j].table })
		for _, st := range remaining {
			ready := true
			for _, need := range st.needs {
				// A reference to a table this file does not create cannot be
				// waited for. It is either in the runtime schema or it is a
				// mistake, and either way the database will say so.
				if known[need] && !placed[need] {
					ready = false
					break
				}
			}
			if ready {
				ordered = append(ordered, st)
				placed[st.table] = true
				progressed = true
				continue
			}
			next = append(next, st)
		}
		if !progressed {
			// A cycle. Emit the rest as they came.
			ordered = append(ordered, next...)
			break
		}
		remaining = next
	}

	return append(ordered, rest...)
}
