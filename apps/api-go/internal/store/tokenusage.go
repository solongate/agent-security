package store

import (
	"context"
	"strings"
)

// What a turn cost.
//
// Nothing in this product recorded it until now, and the reason it is worth
// stating: a host paying for a fleet's seats can see every call those machines
// made and had no way to see what any of it cost. Calls and tokens are not
// proportional — one Read is a hundred tokens and one long reasoning turn with
// no tools at all is fifty thousand — so a chart of calls is not a chart of
// spend, and reading one as the other is how a bill becomes a surprise.
//
// One row per TURN. See the schema note for why this is its own table.

// TokenMeasure says what KIND of number a row holds, because the four clients
// do not report the same one and summing them as if they did would be
// arithmetic over two different units.
//
//	billed   input + output as the provider counts them for billing, with the
//	         cache split alongside. Claude Code, Codex and OpenCode.
//	context  how much of the context window the turn had consumed. Antigravity
//	         reports this and nothing else; the per-turn figure is the growth
//	         since the previous turn.
//
// They are stored side by side and NEVER added together. A total that mixed
// them would be a number with no unit.
const (
	TokenMeasureBilled  = "billed"
	TokenMeasureContext = "context"
)

// TokenUsage is one turn's cost, as a client reports it.
type TokenUsage struct {
	// ID is the client's own key for this turn, already hashed by the caller.
	// It is the primary key, which is what makes ingest idempotent: a hook that
	// fires twice for one turn writes one row.
	ID        string
	ProjectID string
	APIKeyID  string
	UserID    string
	SessionID string
	AgentID   string
	AgentName string
	Source    string
	Measure   string

	Input      int64
	Output     int64
	CacheRead  int64
	CacheWrite int64
	Reasoning  int64
	Total      int64

	CreatedAt int64
}

// InsertTokenUsage records a turn, once.
//
// INSERT OR IGNORE rather than an upsert. A turn's cost does not change after
// the fact, and a hook that re-sends one is retrying rather than correcting —
// so the first write wins and a duplicate is silently a no-op. An upsert would
// let a partial second report overwrite a complete first one.
func (s *Store) InsertTokenUsage(ctx context.Context, u TokenUsage) error {
	if u.ID == "" || u.ProjectID == "" {
		return nil
	}
	if u.Measure == "" {
		u.Measure = TokenMeasureBilled
	}
	_, err := s.exec(ctx, `
		`+s.insertOrIgnore("token_usage", `
			id, project_id, api_key_id, user_id, session_id, agent_id, agent_name,
			source, measure, input_tokens, output_tokens, cache_read_tokens,
			cache_write_tokens, reasoning_tokens, total_tokens, created_at`)+`
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`+s.orIgnoreTail(),
		u.ID, u.ProjectID, NullText(u.APIKeyID), NullText(u.UserID), NullText(u.SessionID),
		NullText(u.AgentID), NullText(u.AgentName), NullText(u.Source), u.Measure,
		u.Input, u.Output, u.CacheRead, u.CacheWrite, u.Reasoning, u.Total, u.CreatedAt)
	return err
}

// TokenTotals is a window's spend.
//
// Billed and Context are separate fields for the reason on TokenMeasure: they
// are different units and a caller has to choose which it is showing rather
// than be handed a sum.
type TokenTotals struct {
	Billed  int64
	Input   int64
	Output  int64
	Cache   int64
	Context int64
	// Turns is how many turns are behind these numbers, which is what makes an
	// average per turn possible and what says whether a zero means "nothing
	// spent" or "nothing reported".
	Turns int64
	// Reported is whether ANY row was found. A fleet whose clients cannot
	// report tokens must not be shown a zero: zero is a measurement.
	Reported bool
}

// FleetTokensFor is a scope's spend.
//
// It takes the SAME FleetScope every other aggregate here takes, and works
// because token_usage carries api_key_id — so the WHERE that scopes calls to
// one person scopes their tokens identically. Two scopes would be two different
// sets of people under one heading.
// FleetTokensByDay is the spend chart, in the same shape and the same day
// buckets FleetByDay uses — so the two series line up bar for bar rather than
// being two charts that happen to be near each other.
// The join is the one every per-person aggregate here makes: audit rows and
// token rows both record the KEY, and the key knows whose it is.
// Both binaries may boot against a database that has not run EnsureRuntimeTables
// yet, and a fleet page that refuses to render because the newest table is
// young reports an outage where there is none.
func isMissingTable(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such table")
}

// TokenTurn is one exchange's cost, in the order it was spent.
type TokenTurn struct {
	At     int64
	Source string
	Agent  string

	Input      int64
	Output     int64
	CacheRead  int64
	CacheWrite int64
	Reasoning  int64
	Total      int64
}

// tokenSessionTurns bounds one sitting's spend rows. A long day is a few
// hundred turns; past that a transcript is not being read, it is being scrolled.
const tokenSessionTurns = 500

// TokensForSession is what each exchange in one sitting cost.
//
// Scoped as well as keyed by session, for the reason every fleet read is: a
// session id is a value a caller can type, and the scope is what makes reading
// somebody else's sitting impossible rather than merely unlikely.
//
// Only billed rows. A context measurement is the size of a window rather than
// something spent, and adding it to a running total in a transcript would say
// a conversation cost several times what it did.
