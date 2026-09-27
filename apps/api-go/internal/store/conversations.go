package store

import (
	"context"
	"database/sql"
	"strings"
)

// conversation_turns: what a person wrote to their agent, and what it wrote
// back.
//
// Every other table in this package records what a MACHINE did. This one
// records what a PERSON said, and that difference is why the rules around it
// are stricter than anywhere else here:
//
//   - It is written only for a machine in a fleet. The handler refuses a turn
//     from an account with no accepted grant, so installing the guard does not
//     start collecting anybody's conversation.
//   - Secrets are removed before it leaves the machine, not here. A guard that
//     strips a secret out of a tool result and then ships the same secret
//     because somebody pasted it into a prompt would be a leak with the
//     product's name on it.
//   - It expires. Everything else in this schema grows forever; a transcript
//     that does the same is a liability that outlives the arrangement which
//     justified keeping it.

// TurnRole is which half of the exchange a row holds.
//
// Compared as stored strings and not parsed, matching the grant statuses: a
// value some future version writes reads as neither half rather than as the
// wrong one.
const (
	TurnPrompt = "prompt"
	TurnReply  = "reply"
)

// TurnBodyLimit is the most of one turn that is stored, in runes.
//
// Eight thousand is the cap the PostToolUse hook already applies to a single
// tool-input value, so a person pasting a file into a prompt is truncated the
// same way they are when the same file goes through Write. The row records that
// it happened rather than quietly keeping a prefix, because a host reading half
// a sentence should know it is half.
const TurnBodyLimit = 8000

// ConversationTurn is one row.
type ConversationTurn struct {
	ID        string
	ProjectID string
	APIKeyID  string
	UserID    string
	SessionID string
	AgentID   string
	AgentName string
	Source    string
	Role      string
	Body      string
	Redacted  bool
	Truncated bool
	CreatedAt int64
}

// NormaliseTurnRole is the boundary between a request field and the column.
//
// It answers with a bool rather than defaulting, because a value this code does
// not recognise must not be filed as one of the two it does: a prompt stored as
// a reply is a host reading words the agent never said.
func NormaliseTurnRole(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case TurnPrompt:
		return TurnPrompt, true
	case TurnReply:
		return TurnReply, true
	}
	return "", false
}

// ClipTurnBody enforces the cap and says whether it had to.
func ClipTurnBody(body string) (string, bool) {
	runes := []rune(body)
	if len(runes) <= TurnBodyLimit {
		return body, false
	}
	return string(runes[:TurnBodyLimit]), true
}

// InsertTurn writes one half of one exchange.
func (s *Store) InsertTurn(ctx context.Context, t ConversationTurn) error {
	_, err := s.exec(ctx, `
		INSERT INTO conversation_turns
			(id, project_id, api_key_id, user_id, session_id, agent_id, agent_name,
			 source, role, body, redacted, truncated, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.ProjectID, NullText(t.APIKeyID), NullText(t.UserID), t.SessionID,
		NullText(t.AgentID), NullText(t.AgentName), NullText(t.Source),
		t.Role, t.Body, boolInt(t.Redacted), boolInt(t.Truncated), t.CreatedAt)
	return err
}

// TurnsFor is one account's transcripts on one project, newest first.
//
// BOTH COLUMNS ARE THE AUTHORISATION and neither is optional. project_id scopes
// the read to the caller's project; user_id scopes it to the caller. A project
// may have several people's keys on it, and a transcript is the most private
// thing this schema holds — so an empty user_id reads nothing rather than
// reading the project.
//
// Rows written by a key minted before the user_id column carry NULL and are
// therefore unreadable here. That is the safe direction: the alternative is a
// clause that admits NULL, which would hand every one of those rows to whoever
// asks first.
func (s *Store) TurnsFor(ctx context.Context, projectID, userID string, limit int) ([]ConversationTurn, error) {
	if projectID == "" || userID == "" {
		return nil, nil
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.query(ctx, `
		SELECT id, session_id, agent_name, source, role, body, redacted, truncated, created_at
		FROM conversation_turns
		WHERE project_id = ? AND user_id = ?
		ORDER BY created_at DESC
		LIMIT ?`, projectID, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ConversationTurn{}
	for rows.Next() {
		var t ConversationTurn
		var agent, source sql.NullString
		var redacted, truncated int
		if err := rows.Scan(&t.ID, &t.SessionID, &agent, &source, &t.Role, &t.Body,
			&redacted, &truncated, &t.CreatedAt); err != nil {
			return nil, err
		}
		t.AgentName, t.Source = agent.String, source.String
		t.Redacted, t.Truncated = redacted == 1, truncated == 1
		out = append(out, t)
	}
	return out, rows.Err()
}

// PruneTurns deletes everything older than a cutoff.
//
// It exists because nothing else in this schema has one. audit_logs, sessions,
// agents and anomaly_events all grow forever, and that has been survivable
// because a ledger row is small and boring. A stored conversation is neither:
// it is the most sensitive thing this service holds, and keeping it after the
// arrangement that justified it has ended is a liability rather than a feature.
func (s *Store) PruneTurns(ctx context.Context, olderThan int64) (int64, error) {
	res, err := s.exec(ctx,
		`DELETE FROM conversation_turns WHERE created_at < ?`, olderThan)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
