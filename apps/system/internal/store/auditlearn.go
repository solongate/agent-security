package store

import (
	"context"
	"database/sql"
)

// The read behind POST /v1/policies/learn.
//
// It is a second, narrower query over audit_logs rather than a reuse of
// ListAuditLogs: Learn Mode samples up to five thousand rows to derive rules
// from them, and needs seven columns out of twenty-five. Pulling the prompt-injection scores and the
// stage breakdown for every row would be five thousand columns of JSON nobody
// reads, on the endpoint that already reads the most rows.

// LearnRow is one observed call as Learn Mode sees it. There is no agent name
// here on purpose — the synthesiser groups by tool and permission, and the agent
// is a FILTER on this query rather than an output.
type LearnRow struct {
	ID               string
	ToolName         string
	Permission       string
	TrustLevel       string
	Decision         string
	ArgumentsSummary string
	CreatedAt        int64
}

// LearnSample is this project's newest calls, optionally narrowed to one agent.
//
// Two clauses matter and neither is optional. project_id comes from the API key
// and is always in the WHERE, because the whole feature is "derive a policy from
// what I have seen" and a sample that crossed a tenant boundary would write
// another customer's tool arguments into this project's proposed rules — paths,
// commands and URLs, in the response body. agent_id is caller input, so it is a
// bound parameter and an ADDITIONAL narrowing, never a replacement for the
// project clause.
//
// The limit is bounded here as well as at the call site. The route clamps to the
// live route's 1..5000; this repeats the ceiling because an unbounded LIMIT on
// audit_logs is a request to stream the table, and any valid key can make it.
func (s *Store) LearnSample(ctx context.Context, projectID, agentID string, limit int) ([]LearnRow, error) {
	where := `project_id = ?`
	args := []any{projectID}
	if agentID != "" {
		where += ` AND agent_id = ?`
		args = append(args, agentID)
	}
	args = append(args, ClampLimit(limit, 1000, 5000))

	rows, err := s.query(ctx, `
		SELECT id, tool_name, permission, trust_level, decision, arguments_summary, created_at
		FROM audit_logs WHERE `+where+`
		ORDER BY created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []LearnRow{}
	for rows.Next() {
		var r LearnRow
		var permission, trust, summary sql.NullString
		if err := rows.Scan(&r.ID, &r.ToolName, &permission, &trust, &r.Decision,
			&summary, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Permission = text(permission)
		r.TrustLevel = text(trust)
		r.ArgumentsSummary = text(summary)
		out = append(out, r)
	}
	return out, rows.Err()
}
