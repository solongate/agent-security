package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// The `audit_logs` table: one row per tool call the guard or the audit hook
// reported, and the largest table in the database.
//
// Two rules hold for every query here. It is project-scoped, because a request
// id or a session id is a value another tenant's client chose and there is
// nothing unguessable about it. And it is bounded, because "give me this
// project's audit log" without a limit is a request to stream a million rows
// out of Turso, which any valid key can make.
//
// The DLP and rate-limit signals the dashboard shows are NOT columns here. They
// are derived from `reason` plus the observe-mode hook, so no query below tries
// to filter on them.

// AuditFilter is the query surface of GET /v1/audit-logs.
//
// Every field is caller input. None of it is interpolated: the strings become
// bind parameters, and Order is a key looked up in a closed map rather than a
// column name — see auditSortColumns.
//
// ToolName and ToolLike are both here because the endpoint has both: `?tool=`
// is a substring match in the live route and the agent-detail read wants an
// exact one. Collapsing them would silently widen or narrow a filter somebody's
// dashboard is already using.
type AuditFilter struct {
	SessionID string
	// GuestUserID narrows the log to one person's machines.
	//
	// audit_logs has no user column: a row records which KEY reported it, and
	// the key knows whose it is. So this is a subquery against api_keys rather
	// than a column comparison, which is also why it is the only filter here
	// that touches a second table.
	//
	// It exists for the fleet page, where a host asks what one developer under
	// their policy has been doing. project_id is still in the WHERE beside it,
	// so a host can only ever ask this about their own project.
	UserID    string
	AgentID   string
	AgentName string
	ToolName  string
	ToolLike  string
	Decision  string
	Search    string
	Since     int64
	Until     int64
	Order     string
	Dir       SortDir
	Limit     int
	Offset    int
}

// auditWhere builds the WHERE clause once, for both the page and its count.
//
// One function rather than two copies because the count and the page have to
// agree: a filter applied to the rows and not to the total is a pager that
// shows "1 of 400" over eleven results, and the bug is invisible until somebody
// searches.
func auditWhere(projectID string, f AuditFilter) ([]string, []any) {
	where := []string{"project_id = ?"}
	args := []any{projectID}

	add := func(clause string, values ...any) {
		where = append(where, clause)
		args = append(args, values...)
	}

	if f.SessionID != "" {
		add("session_id = ?", f.SessionID)
	}
	if f.UserID != "" {
		add("api_key_id IN (SELECT id FROM api_keys WHERE user_id = ?)", f.UserID)
	}
	// The host's own rows, by elimination. Their keys predate the user_id
	// column and many carry NULL, so naming the host by account finds nothing
	// for exactly the accounts that have been here longest — see
	// FleetScopeHost, which is the same rule for the aggregates.
	if f.AgentID != "" {
		add("agent_id = ?", f.AgentID)
	}
	if f.AgentName != "" {
		add("agent_name = ?", f.AgentName)
	}
	if f.ToolName != "" {
		add("tool_name = ?", f.ToolName)
	}
	if f.ToolLike != "" {
		add("tool_name LIKE ?", "%"+f.ToolLike+"%")
	}
	if f.Decision != "" {
		add("decision = ?", f.Decision)
	}
	if f.Since > 0 {
		add("created_at >= ?", f.Since)
	}
	if f.Until > 0 {
		add("created_at <= ?", f.Until)
	}
	if f.Search != "" {
		// LIKE with a bound pattern. The wildcards are added to the VALUE, not
		// to the SQL, so the search term stays a parameter; escaping % and _ is
		// deliberately not done, matching the live app — a caller searching for
		// a literal underscore gets a broader match, which is a wrong result
		// rather than an unsafe one.
		//
		// The six columns are the live route's, exactly. Dropping one — the
		// request id is the tempting one — breaks the workflow of pasting an id
		// out of a support ticket into the search box.
		pat := "%" + f.Search + "%"
		add(`(tool_name LIKE ? OR reason LIKE ? OR agent_name LIKE ? OR server_name LIKE ?
			OR arguments_summary LIKE ? OR request_id LIKE ?)`,
			pat, pat, pat, pat, pat, pat)
	}
	return where, args
}

// auditSortColumns is the closed set a caller's `order` may name.
//
// This is the map the file note is about. A column name cannot be a bind
// parameter in SQLite, so the only construction that is safe is a lookup: the
// text that reaches the SQL is a value from THIS map, and an unrecognised key
// falls back to created_at rather than reaching the query.
var auditSortColumns = map[string]string{
	"created_at": "created_at",
	"tool_name":  "tool_name",
	"decision":   "decision",
	"agent_id":   "agent_id",
}

const auditColumns = `id, project_id, request_id, session_id, tool_name, server_name,
	permission, trust_level, decision, matched_rule_id, reason, evaluation_time_ms,
	arguments_hash, arguments_summary, pi_detected, pi_trust_score, pi_blocked,
	pi_categories, pi_stage_scores, agent_id, agent_name, sub_agent_id, sub_agent_name,
	api_key_id, created_at`

// ListAuditLogs is the filtered, ordered, bounded read.
//
// The WHERE is assembled from fixed fragments and a parallel argument slice —
// the shape matters: each `if` appends a constant string AND its bound value,
// so there is no path where a filter contributes text without contributing a
// placeholder. LIMIT and OFFSET are bound too.
func (s *Store) ListAuditLogs(ctx context.Context, projectID string, f AuditFilter) ([]AuditLog, error) {
	where, args := auditWhere(projectID, f)

	// The ceiling is 10000 because that is the live route's, and the dashboard's
	// "export everything" button sends exactly that. Capping lower here would
	// truncate an export silently — the response still says `total`, so nobody
	// would notice the file was short. It is still a CEILING: an unbounded LIMIT
	// on this table is a request to stream a million rows over the network, and
	// any valid key can make it.
	limit := ClampLimit(f.Limit, 50, 10000)
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)

	q := `SELECT ` + auditColumns + ` FROM audit_logs WHERE ` + strings.Join(where, " AND ") +
		orderClause(f.Order, f.Dir, auditSortColumns, "created_at") + ` LIMIT ? OFFSET ?`

	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditLog{}
	for rows.Next() {
		a, err := scanAuditLog(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AuditLogByID is one entry, project-scoped. The block and whitelist routes
// start here: they take an audit id from a caller and must not act on a row
// belonging to somebody else.
func (s *Store) AuditLogByID(ctx context.Context, projectID, id string) (AuditLog, error) {
	rows, err := s.query(ctx,
		`SELECT `+auditColumns+` FROM audit_logs WHERE project_id = ? AND id = ? LIMIT 1`,
		projectID, id)
	if err != nil {
		return AuditLog{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return AuditLog{}, err
		}
		return AuditLog{}, ErrNotFound
	}
	return scanAuditLog(rows)
}

// CountAuditLogs is the total behind a paged list, with the same filter — the
// SAME filter, from auditWhere, for the reason given there.
func (s *Store) CountAuditLogs(ctx context.Context, projectID string, f AuditFilter) (int64, error) {
	where, args := auditWhere(projectID, f)
	var n int64
	err := s.queryRow(ctx,
		`SELECT COUNT(*) FROM audit_logs WHERE `+strings.Join(where, " AND "), args...).Scan(&n)
	return n, err
}

// BurstRow is one row of the rate-limit burst scan: who made the call and when,
// and nothing else. The scan counts calls per agent per minute, so selecting
// the whole row would move megabytes of arguments_summary to count them.
type BurstRow struct {
	AgentName string
	CreatedAt int64
}

// AuditBurstWindow is the per-minute burst scan behind `rate_limit_burst`.
//
// It spans the time range of a page rather than the page itself, because a
// burst is a property of the MINUTE a call landed in: a page filtered to one
// tool shows three calls in a minute that actually carried three hundred, and
// only the unfiltered window can say so.
//
// The live query has no LIMIT, which on a busy project is the whole day. The
// bound here is a real difference and it is deliberate: past the cap the count
// is a lower bound, so a burst can be missed, and missing a badge is a better
// failure than this endpoint reading a million rows to draw one.
// AuditBurstCount is one agent's call count in one minute.
type AuditBurstCount struct {
	AgentName string
	Minute    int64 // floor(created_at / 60)
	Count     int64
}

// AuditBurstCounts groups the window in SQL rather than in Go.
//
// The caller wants calls-per-agent-per-minute and nothing else, and the previous
// shape fetched up to FIFTY THOUSAND rows to count them here. On a project with
// twenty thousand audit rows that was the whole cost of GET /audit-logs — around
// a second, on a request that returns fifty entries — because the rows still had
// to cross the wire from Turso before anything looked at them.
//
// GROUP BY collapses them to one row per agent per minute, which for a list
// spanning a few hours is a few hundred rows instead of tens of thousands. The
// arithmetic is identical: burstKey buckets by created_at/60 and this divides by
// the same 60.
//
// No LIMIT. The old one was a guard against transferring an unbounded number of
// rows, and grouping is that guard now — the result is bounded by the number of
// distinct minutes in the window, not by the traffic in it.
func (s *Store) AuditBurstCounts(ctx context.Context, projectID string, fromSec, toSec int64) ([]AuditBurstCount, error) {
	rows, err := s.query(ctx, `
		SELECT agent_name, created_at / 60 AS minute, COUNT(*)
		FROM audit_logs
		WHERE project_id = ? AND created_at >= ? AND created_at <= ?
		GROUP BY agent_name, minute`,
		projectID, fromSec, toSec)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditBurstCount{}
	for rows.Next() {
		var c AuditBurstCount
		var agent any
		if err := rows.Scan(&agent, &c.Minute, &c.Count); err != nil {
			return nil, err
		}
		if s, ok := agent.(string); ok {
			c.AgentName = s
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) AuditBurstWindow(ctx context.Context, projectID string, fromSec, toSec int64, limit int) ([]BurstRow, error) {
	rows, err := s.query(ctx, `
		SELECT agent_name, created_at FROM audit_logs
		WHERE project_id = ? AND created_at >= ? AND created_at <= ?
		ORDER BY created_at DESC LIMIT ?`,
		projectID, fromSec, toSec, ClampLimit(limit, 20000, 50000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []BurstRow{}
	for rows.Next() {
		var r BurstRow
		var name sql.NullString
		if err := rows.Scan(&name, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.AgentName = text(name)
		out = append(out, r)
	}
	return out, rows.Err()
}

// InsertAuditLog is the write the audit hook drives, one row per reported call.
func (s *Store) InsertAuditLog(ctx context.Context, a AuditLog) error {
	_, err := s.exec(ctx, `
		INSERT INTO audit_logs (`+auditColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ProjectID, a.RequestID, NullText(a.SessionID), a.ToolName, NullText(a.ServerName),
		a.Permission, a.TrustLevel, a.Decision, NullText(a.MatchedRuleID), NullText(a.Reason),
		nullFloat(a.EvaluationTimeMs), NullText(a.ArgumentsHash), NullText(a.ArgumentsSummary),
		nullBool(a.PiDetected), nullFloat(a.PiTrustScore), nullBool(a.PiBlocked),
		NullText(a.PiCategories), NullText(a.PiStageScores),
		NullText(a.AgentID), NullText(a.AgentName), NullText(a.SubAgentID), NullText(a.SubAgentName),
		NullText(a.APIKeyID), a.CreatedAt)
	return err
}

// DeleteAuditLogsByIDs removes a chosen set of entries.
//
// Nothing a user can reach calls this, and that is deliberate: there is no
// delete endpoint and no delete button, because a history the audited party can
// erase is not a history. What is left is the primitive, and its only caller is
// a test that seeds rows into a real project and has to take them back out
// again. If audit retention ever gets a sweeper, it belongs here too — with an
// age on it, run by a schedule rather than by a request.
//
// The ids are BOUND, one placeholder each, and the project clause stays in the
// WHERE: an id list is caller input, and without the project a caller holding
// any valid key could delete another tenant's history by guessing UUIDs.
//
// The caller chunks, because SQLite has a ceiling on bound parameters and a
// delete of ten thousand ids would hit it — this refuses a chunk that is too
// large rather than building a statement the driver will reject halfway
// through a loop.
func (s *Store) DeleteAuditLogsByIDs(ctx context.Context, projectID string, ids []string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	if len(ids) > MaxDeleteChunk {
		return 0, errors.New("store: too many ids in one delete")
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, projectID)
	for _, id := range ids {
		args = append(args, id)
	}
	res, err := s.exec(ctx,
		`DELETE FROM audit_logs WHERE project_id = ? AND id IN (`+placeholders(len(ids))+`)`, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// MaxDeleteChunk is the live route's batch size, and the size a caller must
// chunk to.
const MaxDeleteChunk = 100

// AuditKeyNames maps a project's api-key ids to their names, for the
// `api_key_name` field of the audit list.
//
// REVOKED keys are included, unlike ListAPIKeys, and that is the point: an
// audit entry records which key reported it, and revoking a key must not blank
// the name on a year of history. It lives with the audit queries because it is
// this endpoint's lookup — /v1/keys wants the live keys and their metadata,
// which is a different question.
func (s *Store) AuditKeyNames(ctx context.Context, projectID string) (map[string]string, error) {
	rows, err := s.query(ctx,
		`SELECT id, name FROM api_keys WHERE project_id = ?`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var id string
		var name sql.NullString
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = text(name)
	}
	return out, rows.Err()
}

// AuditKeyUsers maps a project's api key ids to the ACCOUNT each belongs to.
//
// audit_logs records which key reported a call and the key knows whose it is,
// so this is how a row is attributed to a person. One statement for the whole
// page rather than a lookup per row: a fleet console redraws its stream every
// two seconds and a join per line is a query per line.
//
// A key with no user is left out rather than mapped to the empty string. That
// is the host's own oldest keys — they predate the column — and a caller that
// finds nothing here should say so in its own words rather than be handed a
// blank that reads like a real account.
func (s *Store) AuditKeyUsers(ctx context.Context, projectID string) (map[string]string, error) {
	rows, err := s.query(ctx,
		`SELECT id, user_id FROM api_keys WHERE project_id = ?`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]string{}
	for rows.Next() {
		var id string
		var user sql.NullString
		if err := rows.Scan(&id, &user); err != nil {
			return nil, err
		}
		if v := text(user); v != "" {
			out[id] = v
		}
	}
	return out, rows.Err()
}

func scanAuditLog(rows *sql.Rows) (AuditLog, error) {
	var a AuditLog
	var sessionID, serverName, matchedRule, reason, argsHash, argsSummary sql.NullString
	var piCategories, piStages, agentID, agentName, subAgentID, subAgentName, apiKeyID sql.NullString
	var evalMs, piScore sql.NullFloat64
	var piDetected, piBlocked sql.NullInt64

	if err := rows.Scan(&a.ID, &a.ProjectID, &a.RequestID, &sessionID, &a.ToolName, &serverName,
		&a.Permission, &a.TrustLevel, &a.Decision, &matchedRule, &reason, &evalMs,
		&argsHash, &argsSummary, &piDetected, &piScore, &piBlocked,
		&piCategories, &piStages, &agentID, &agentName, &subAgentID, &subAgentName,
		&apiKeyID, &a.CreatedAt); err != nil {
		return AuditLog{}, err
	}

	a.SessionID = text(sessionID)
	a.ServerName = text(serverName)
	a.MatchedRuleID = text(matchedRule)
	a.Reason = text(reason)
	a.EvaluationTimeMs = numPtr(evalMs)
	a.ArgumentsHash = text(argsHash)
	a.ArgumentsSummary = text(argsSummary)
	a.PiDetected = boolPtr(piDetected)
	a.PiTrustScore = numPtr(piScore)
	a.PiBlocked = boolPtr(piBlocked)
	a.PiCategories = text(piCategories)
	a.PiStageScores = text(piStages)
	a.AgentID = text(agentID)
	a.AgentName = text(agentName)
	a.SubAgentID = text(subAgentID)
	a.SubAgentName = text(subAgentName)
	a.APIKeyID = text(apiKeyID)
	return a, nil
}

func nullFloat(v *float64) any {
	if v == nil {
		return nil
	}
	return *v
}

// nullBool writes a *bool as NULL / 0 / 1, keeping "never ran" distinct from
// "ran and found nothing" — see AuditLog.PiDetected.
func nullBool(v *bool) any {
	if v == nil {
		return nil
	}
	return Bit(*v)
}
