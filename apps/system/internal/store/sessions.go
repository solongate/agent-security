package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// The `sessions` table: agent sessions, not authentication sessions.
//
// The primary key is the session id the CLIENT chose, so it is unique across
// the whole table rather than per project. Every read below therefore filters
// on project_id as well — without it, one tenant guessing or reusing another's
// session id reads their counters.

const sessionColumns = `id, project_id, agent_id, agent_name, api_key_id, started_at, last_seen_at,
	total_calls, allowed_calls, denied_calls, dlp_events, rate_limit_events, pi_detections,
	read_calls, write_calls, execute_calls, network_calls`

var sessionSortColumns = map[string]string{
	"last_seen_at": "last_seen_at",
	"started_at":   "started_at",
	"total_calls":  "total_calls",
	"denied_calls": "denied_calls",
}

// ListSessions is GET /v1/sessions. `since` bounds it by activity, which is
// what the live view asks for; the limit is bound and clamped regardless.
func (s *Store) ListSessions(ctx context.Context, projectID string, since int64, order string, dir SortDir, limit int) ([]Session, error) {
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if since > 0 {
		where = append(where, "last_seen_at >= ?")
		args = append(args, since)
	}
	args = append(args, ClampLimit(limit, 100, 1000))

	q := `SELECT ` + sessionColumns + ` FROM sessions WHERE ` + strings.Join(where, " AND ") +
		orderClause(order, dir, sessionSortColumns, "last_seen_at") + ` LIMIT ?`

	rows, err := s.query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// SessionByID is GET /v1/sessions/{id}, project-scoped for the reason in the
// file note.
func (s *Store) SessionByID(ctx context.Context, projectID, id string) (Session, error) {
	rows, err := s.query(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE project_id = ? AND id = ? LIMIT 1`,
		projectID, id)
	if err != nil {
		return Session{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Session{}, err
		}
		return Session{}, ErrNotFound
	}
	return scanSession(rows)
}

// ListSessionsPage is GET /v1/sessions: one page of a project's sessions,
// newest-seen first, optionally narrowed to one agent.
//
// It is a second read next to ListSessions rather than a parameter on it,
// because the two endpoints ask different questions: /agents/live wants
// everything seen inside a window and never pages, and this one pages and
// filters by agent. Both carry the project id and both bind their limit.
//
// The ORDER BY is a constant. This endpoint has no sort parameter in the live
// app and must not grow one here by accident.
func (s *Store) ListSessionsPage(ctx context.Context, projectID, agentID string, limit, offset int) ([]Session, error) {
	where, args := sessionPageWhere(projectID, agentID)
	if offset < 0 {
		offset = 0
	}
	args = append(args, ClampLimit(limit, 50, 500), offset)

	rows, err := s.query(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE `+strings.Join(where, " AND ")+
			` ORDER BY last_seen_at DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Session{}
	for rows.Next() {
		sess, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// CountSessionsPage is the total behind that page, under the SAME filter — one
// builder for both, so a pager cannot say "1 of 400" over eleven rows.
func (s *Store) CountSessionsPage(ctx context.Context, projectID, agentID string) (int64, error) {
	where, args := sessionPageWhere(projectID, agentID)
	var n int64
	err := s.queryRow(ctx,
		`SELECT COUNT(*) FROM sessions WHERE `+strings.Join(where, " AND "), args...).Scan(&n)
	return n, err
}

func sessionPageWhere(projectID, agentID string) ([]string, []any) {
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if agentID != "" {
		where = append(where, "agent_id = ?")
		args = append(args, agentID)
	}
	return where, args
}

// SessionCall is one audit row as the sessions list reads it: five columns out
// of twenty-five, because the page recounts calls and scans argument summaries
// and looks at nothing else. Selecting the whole row would move megabytes of
// prompt-injection scores to count decisions.
type SessionCall struct {
	SessionID        string
	Decision         string
	Reason           string
	ArgumentsSummary string
	CreatedAt        int64
}

// SessionCalls reads the audit rows belonging to a page of sessions.
//
// The session ids come from rows this project owns, and project_id is STILL in
// the WHERE. That is not belt and braces: a session id is a string the client
// chose, so two tenants can hold the same one, and the id list would otherwise
// be enough to read another project's calls.
//
// Every id is bound, one placeholder each. The caller passes at most a page of
// them — the endpoint's ceiling is 500 — which keeps this well under SQLite's
// bound-parameter limit.
func (s *Store) SessionCalls(ctx context.Context, projectID string, sessionIDs []string, limit int) ([]SessionCall, error) {
	if len(sessionIDs) == 0 {
		return []SessionCall{}, nil
	}
	args := make([]any, 0, len(sessionIDs)+2)
	args = append(args, projectID)
	for _, id := range sessionIDs {
		args = append(args, id)
	}
	args = append(args, ClampLimit(limit, 30000, 30000))

	rows, err := s.query(ctx, `
		SELECT session_id, decision, reason, arguments_summary, created_at
		FROM audit_logs
		WHERE project_id = ? AND session_id IN (`+placeholders(len(sessionIDs))+`)
		LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SessionCall{}
	for rows.Next() {
		var c SessionCall
		var sessionID, decision, reason, summary sql.NullString
		if err := rows.Scan(&sessionID, &decision, &reason, &summary, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.SessionID = text(sessionID)
		c.Decision = text(decision)
		c.Reason = text(reason)
		c.ArgumentsSummary = text(summary)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SessionStamp is an id and its last-seen time: what "delete the deactivated
// ones" needs to decide, and nothing else.
type SessionStamp struct {
	ID         string
	LastSeenAt int64
}

// SessionStamps lists a project's sessions as (id, last seen).
//
// The live query is unbounded. This one is capped, and the difference is
// deliberate: past the cap the caller deletes fewer sessions and can press the
// button again, where an unbounded read is a way to ask this service to stream
// every session a busy project has ever had.
func (s *Store) SessionStamps(ctx context.Context, projectID string, limit int) ([]SessionStamp, error) {
	rows, err := s.query(ctx,
		`SELECT id, last_seen_at FROM sessions WHERE project_id = ?
		 ORDER BY last_seen_at DESC LIMIT ?`,
		projectID, ClampLimit(limit, 20000, 50000))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []SessionStamp{}
	for rows.Next() {
		var st SessionStamp
		if err := rows.Scan(&st.ID, &st.LastSeenAt); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// DeleteSessionsByIDs removes a chosen set, project-scoped and bound one
// placeholder per id — the same shape, and the same reasons, as
// DeleteAuditLogsByIDs. The caller chunks to MaxDeleteChunk.
func (s *Store) DeleteSessionsByIDs(ctx context.Context, projectID string, ids []string) (int64, error) {
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
		`DELETE FROM sessions WHERE project_id = ? AND id IN (`+placeholders(len(ids))+`)`, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// UpsertSession creates a session or refreshes its last-seen stamp.
//
// ON CONFLICT rather than select-then-insert: sessions are created by whichever
// reported call arrives first, and several arrive at once from one agent
// starting up. The conflict target is the primary key, and the update
// deliberately does NOT touch project_id — a row already belongs to a project
// and a colliding id from another tenant must not move it.
func (s *Store) UpsertSession(ctx context.Context, sess Session) error {
	_, err := s.exec(ctx, `
		INSERT INTO sessions (id, project_id, agent_id, agent_name, api_key_id, started_at, last_seen_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
		  last_seen_at = excluded.last_seen_at,
		  agent_name = COALESCE(excluded.agent_name, sessions.agent_name)`,
		sess.ID, sess.ProjectID, NullText(sess.AgentID), NullText(sess.AgentName),
		NullText(sess.APIKeyID), sess.StartedAt, sess.LastSeenAt)
	return err
}

// SessionCounterDelta is one call's contribution to a session's tallies. It is
// applied as an increment rather than a read-modify-write so concurrent
// reports from one agent do not lose each other.
type SessionCounterDelta struct {
	Total           int64
	Allowed         int64
	Denied          int64
	DLPEvents       int64
	RateLimitEvents int64
	PiDetections    int64
	Read            int64
	Write           int64
	Execute         int64
	Network         int64
}

// BumpSessionCounters applies a delta. project_id is in the WHERE: an id
// without it would let one tenant inflate another's numbers.
func (s *Store) BumpSessionCounters(ctx context.Context, projectID, sessionID string, d SessionCounterDelta, seenAt int64) error {
	_, err := s.exec(ctx, `
		UPDATE sessions SET
		  total_calls = total_calls + ?,
		  allowed_calls = allowed_calls + ?,
		  denied_calls = denied_calls + ?,
		  dlp_events = dlp_events + ?,
		  rate_limit_events = rate_limit_events + ?,
		  pi_detections = pi_detections + ?,
		  read_calls = read_calls + ?,
		  write_calls = write_calls + ?,
		  execute_calls = execute_calls + ?,
		  network_calls = network_calls + ?,
		  last_seen_at = MAX(last_seen_at, ?)
		WHERE id = ? AND project_id = ?`,
		d.Total, d.Allowed, d.Denied, d.DLPEvents, d.RateLimitEvents, d.PiDetections,
		d.Read, d.Write, d.Execute, d.Network, seenAt, sessionID, projectID)
	return err
}

// DeleteSessions clears a project's sessions, or one of them.
func (s *Store) DeleteSessions(ctx context.Context, projectID, sessionID string) (int64, error) {
	q := `DELETE FROM sessions WHERE project_id = ?`
	args := []any{projectID}
	if sessionID != "" {
		q += ` AND id = ?`
		args = append(args, sessionID)
	}
	res, err := s.exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func scanSession(rows *sql.Rows) (Session, error) {
	var s Session
	var agentID, agentName, apiKeyID sql.NullString
	if err := rows.Scan(&s.ID, &s.ProjectID, &agentID, &agentName, &apiKeyID,
		&s.StartedAt, &s.LastSeenAt, &s.TotalCalls, &s.AllowedCalls, &s.DeniedCalls,
		&s.DLPEvents, &s.RateLimitEvents, &s.PiDetections,
		&s.ReadCalls, &s.WriteCalls, &s.ExecuteCalls, &s.NetworkCalls); err != nil {
		return Session{}, err
	}
	s.AgentID = text(agentID)
	s.AgentName = text(agentName)
	s.APIKeyID = text(apiKeyID)
	return s, nil
}
