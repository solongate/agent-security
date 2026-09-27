package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// The agent tables: `agents`, `agent_baselines`, `anomaly_events`,
// `agent_groups`, `agent_group_members`, `agent_relationships` and
// `delegation_chains`.
//
// An agent id is a string the CLIENT chose. It is not unique across the
// database and is not unguessable — "claude-code" is an agent id. So every
// lookup by agent id below is a lookup by the PAIR (project_id, agent_id), and
// none of these functions accepts an agent id without one.

const agentColumns = `id, project_id, agent_id, agent_name, first_seen_at, last_seen_at,
	total_calls, allowed_calls, denied_calls, pi_detections, parent_agent_id, api_key_id, api_key_name`

var agentSortColumns = map[string]string{
	"last_seen_at":  "last_seen_at",
	"first_seen_at": "first_seen_at",
	"total_calls":   "total_calls",
	"denied_calls":  "denied_calls",
	"agent_id":      "agent_id",
}

// ListAgents is GET /v1/agents/live. `since` is the liveness window.
func (s *Store) ListAgents(ctx context.Context, projectID string, since int64, order string, dir SortDir, limit int) ([]Agent, error) {
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if since > 0 {
		where = append(where, "last_seen_at >= ?")
		args = append(args, since)
	}
	args = append(args, ClampLimit(limit, 200, 1000))

	rows, err := s.query(ctx,
		`SELECT `+agentColumns+` FROM agents WHERE `+strings.Join(where, " AND ")+
			orderClause(order, dir, agentSortColumns, "last_seen_at")+` LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// AgentByAgentID resolves the client-chosen id within one project.
func (s *Store) AgentByAgentID(ctx context.Context, projectID, agentID string) (Agent, error) {
	rows, err := s.query(ctx,
		`SELECT `+agentColumns+` FROM agents WHERE project_id = ? AND agent_id = ? LIMIT 1`,
		projectID, agentID)
	if err != nil {
		return Agent{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Agent{}, err
		}
		return Agent{}, ErrNotFound
	}
	return scanAgent(rows)
}

// UpsertAgent records an agent's first and latest sighting.
//
// There is no UNIQUE constraint on (project_id, agent_id) in the schema — only
// an index — so this cannot be an ON CONFLICT. It is an UPDATE that reports
// whether it matched, and the caller inserts when it did not. That is a race:
// two first-ever calls from one agent can both insert. The live app has the
// same shape and the consequence is a duplicate roll-up row rather than a
// wrong decision, so it is reproduced rather than "fixed" with a constraint
// this binary would be adding to a shared database on its own.
func (s *Store) UpsertAgent(ctx context.Context, a Agent) error {
	res, err := s.exec(ctx, `
		UPDATE agents SET
		  agent_name = COALESCE(?, agent_name),
		  last_seen_at = MAX(last_seen_at, ?),
		  api_key_id = COALESCE(?, api_key_id),
		  api_key_name = COALESCE(?, api_key_name)
		WHERE project_id = ? AND agent_id = ?`,
		NullText(a.AgentName), a.LastSeenAt, NullText(a.APIKeyID), NullText(a.APIKeyName),
		a.ProjectID, a.AgentID)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		return nil
	}
	_, err = s.exec(ctx, `
		INSERT INTO agents (id, project_id, agent_id, agent_name, first_seen_at, last_seen_at,
		  total_calls, allowed_calls, denied_calls, pi_detections, parent_agent_id, api_key_id, api_key_name)
		VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, ?, ?)`,
		a.ID, a.ProjectID, a.AgentID, NullText(a.AgentName), a.FirstSeenAt, a.LastSeenAt,
		NullText(a.ParentAgentID), NullText(a.APIKeyID), NullText(a.APIKeyName))
	return err
}

// BumpAgentCounters applies one call's contribution.
func (s *Store) BumpAgentCounters(ctx context.Context, projectID, agentID string, total, allowed, denied, pi int64, seenAt int64) error {
	_, err := s.exec(ctx, `
		UPDATE agents SET
		  total_calls = total_calls + ?,
		  allowed_calls = allowed_calls + ?,
		  denied_calls = denied_calls + ?,
		  pi_detections = pi_detections + ?,
		  last_seen_at = MAX(last_seen_at, ?)
		WHERE project_id = ? AND agent_id = ?`,
		total, allowed, denied, pi, seenAt, projectID, agentID)
	return err
}

// SubAgents lists the agents whose parent is agentID.
//
// A sub-agent is stored as an ordinary agents row with the composite id
// `<parent>::<child>` and parent_agent_id set, so this is a plain lookup rather
// than a recursive walk — one level is all the schema records.
func (s *Store) SubAgents(ctx context.Context, projectID, parentAgentID string) ([]Agent, error) {
	rows, err := s.query(ctx,
		`SELECT `+agentColumns+` FROM agents WHERE project_id = ? AND parent_agent_id = ?
		 ORDER BY last_seen_at DESC LIMIT ?`,
		projectID, parentAgentID, maxSubAgents)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Agent{}
	for rows.Next() {
		a, err := scanAgent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// maxSubAgents bounds the sub-agent fan-out. The live query has no limit, and a
// runaway agent that spawns a sub-agent per task is exactly the situation in
// which somebody opens this page.
const maxSubAgents = 500

// DeleteAgents clears a project's agent roll-ups. It is the `scope=agents` half
// of DELETE /v1/audit-logs and reports how many rows went.
func (s *Store) DeleteAgents(ctx context.Context, projectID string) (int64, error) {
	res, err := s.exec(ctx, `DELETE FROM agents WHERE project_id = ?`, projectID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// AgentCall is one reported tool call's contribution to the agents roll-up.
//
// MatchByKey is the whole reason this is a struct rather than four arguments.
// A top-level agent gets one row PER API KEY — the same "claude-code" seen
// through two keys is two rows, which is what lets the dashboard show which key
// an agent is running under. A sub-agent has no key of its own and gets one row
// per composite id. Applying the key rule to a sub-agent would create a second
// row for it on every key rotation.
type AgentCall struct {
	ProjectID     string
	AgentID       string
	AgentName     string
	APIKeyID      string
	APIKeyName    string
	ParentAgentID string
	MatchByKey    bool

	// NewRowID is used only if no row matches. It is generated by the caller so
	// that id generation stays in one place in this service.
	NewRowID string

	Allowed    bool
	PiDetected bool
	At         int64
}

// RecordAgentCall applies one call to the matching agents row, inserting it if
// there is none.
//
// The UPDATE is BY ROW ID, not by (project_id, agent_id). That distinction is
// the bug this function exists to avoid: several rows can share an agent id —
// one per API key, by design — and `UPDATE ... WHERE agent_id = ?` has no LIMIT
// in SQLite, so it would add the same call to every one of them and inflate the
// totals of every key the agent has ever used.
//
// A missed row is a lost counter, not a wrong decision, so the lookup-then-write
// race the live app has is reproduced rather than closed with a constraint this
// binary would be adding to a shared database on its own.
func (s *Store) RecordAgentCall(ctx context.Context, c AgentCall) error {
	rowID, err := s.agentRowID(ctx, c)
	if err != nil {
		return err
	}

	allowed, denied, pi := int64(0), int64(1), int64(0)
	if c.Allowed {
		allowed, denied = 1, 0
	}
	if c.PiDetected {
		pi = 1
	}

	if rowID != "" {
		// last_seen_at is assigned rather than MAX'd, as the live app assigns it.
		// A clock that went backwards moves the stamp back with it, which is the
		// live behaviour and is visible only as a card sorting oddly.
		_, err := s.exec(ctx, `
			UPDATE agents SET
			  agent_name = COALESCE(?, agent_name),
			  api_key_id = COALESCE(?, api_key_id),
			  api_key_name = COALESCE(?, api_key_name),
			  last_seen_at = ?,
			  total_calls = COALESCE(total_calls, 0) + 1,
			  allowed_calls = COALESCE(allowed_calls, 0) + ?,
			  denied_calls = COALESCE(denied_calls, 0) + ?,
			  pi_detections = COALESCE(pi_detections, 0) + ?
			WHERE id = ?`,
			NullText(c.AgentName), NullText(c.APIKeyID), NullText(c.APIKeyName),
			c.At, allowed, denied, pi, rowID)
		return err
	}

	_, err = s.exec(ctx, `
		INSERT INTO agents (id, project_id, agent_id, agent_name, first_seen_at, last_seen_at,
		  total_calls, allowed_calls, denied_calls, pi_detections, parent_agent_id, api_key_id, api_key_name)
		VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?)`,
		c.NewRowID, c.ProjectID, c.AgentID, NullText(c.AgentName), c.At, c.At,
		allowed, denied, pi,
		NullText(c.ParentAgentID), NullText(c.APIKeyID), NullText(c.APIKeyName))
	return err
}

// agentRowID resolves the row a call belongs to, or "" for none.
//
// The two-step lookup for a keyed agent is the live app's and matters for
// continuity: rows written before api_key_id existed have it NULL, and an agent
// that has been reporting for months would otherwise get a second row and a
// reset history the first time this ran.
func (s *Store) agentRowID(ctx context.Context, c AgentCall) (string, error) {
	if !c.MatchByKey || c.APIKeyID == "" {
		return s.scalarID(ctx,
			`SELECT id FROM agents WHERE project_id = ? AND agent_id = ? LIMIT 1`,
			c.ProjectID, c.AgentID)
	}
	id, err := s.scalarID(ctx,
		`SELECT id FROM agents WHERE project_id = ? AND agent_id = ? AND api_key_id = ? LIMIT 1`,
		c.ProjectID, c.AgentID, c.APIKeyID)
	if err != nil || id != "" {
		return id, err
	}
	return s.scalarID(ctx,
		`SELECT id FROM agents WHERE project_id = ? AND agent_id = ? AND api_key_id IS NULL LIMIT 1`,
		c.ProjectID, c.AgentID)
}

// scalarID reads one id, or "" when nothing matched. No rows is not an error
// here: "this agent has not been seen before" is the normal first call.
func (s *Store) scalarID(ctx context.Context, query string, args ...any) (string, error) {
	var id string
	err := s.queryRow(ctx, query, args...).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return id, nil
}

func scanAgent(rows *sql.Rows) (Agent, error) {
	var a Agent
	var name, parent, keyID, keyName sql.NullString
	if err := rows.Scan(&a.ID, &a.ProjectID, &a.AgentID, &name, &a.FirstSeenAt, &a.LastSeenAt,
		&a.TotalCalls, &a.AllowedCalls, &a.DeniedCalls, &a.PiDetections,
		&parent, &keyID, &keyName); err != nil {
		return Agent{}, err
	}
	a.AgentName = text(name)
	a.ParentAgentID = text(parent)
	a.APIKeyID = text(keyID)
	a.APIKeyName = text(keyName)
	return a, nil
}

// ── agent_baselines ─────────────────────────────────────────────────────────

const baselineColumns = `id, project_id, agent_id, tool_distribution, permission_mix,
	known_paths, known_domains, known_tools, avg_calls_per_hour, deny_rate, sample_size,
	character, trust_score, computed_at`

// BaselineFor is the stored notion of normal for one agent.
func (s *Store) BaselineFor(ctx context.Context, projectID, agentID string) (AgentBaseline, error) {
	var b AgentBaseline
	var toolDist, permMix, paths, domains, tools, character sql.NullString
	var avg, denyRate, trust sql.NullFloat64
	err := s.queryRow(ctx,
		`SELECT `+baselineColumns+` FROM agent_baselines WHERE project_id = ? AND agent_id = ?
		 ORDER BY computed_at DESC LIMIT 1`, projectID, agentID).
		Scan(&b.ID, &b.ProjectID, &b.AgentID, &toolDist, &permMix, &paths, &domains, &tools,
			&avg, &denyRate, &b.SampleSize, &character, &trust, &b.ComputedAt)
	if err == sql.ErrNoRows {
		return AgentBaseline{}, ErrNotFound
	}
	if err != nil {
		return AgentBaseline{}, err
	}
	b.ToolDistribution = raw(toolDist)
	b.PermissionMix = raw(permMix)
	b.KnownPaths = raw(paths)
	b.KnownDomains = raw(domains)
	b.KnownTools = raw(tools)
	b.AvgCallsPerHour = num(avg)
	b.DenyRate = num(denyRate)
	b.Character = text(character)
	// trust_score defaults to 50, not 0. Zero is "completely untrusted" and a
	// row written before the column existed is not that.
	b.TrustScore = 50
	if trust.Valid {
		b.TrustScore = trust.Float64
	}
	return b, nil
}

// UpsertBaseline replaces an agent's baseline. Delete-then-insert inside one
// statement pair rather than ON CONFLICT, because the table has no unique
// constraint on the pair — only an index.
func (s *Store) UpsertBaseline(ctx context.Context, b AgentBaseline) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := s.txExec(ctx, tx,
		`DELETE FROM agent_baselines WHERE project_id = ? AND agent_id = ?`,
		b.ProjectID, b.AgentID); err != nil {
		return err
	}
	if _, err := s.txExec(ctx, tx, `
		INSERT INTO agent_baselines (`+baselineColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.ProjectID, b.AgentID, jsonOrNull(b.ToolDistribution), jsonOrNull(b.PermissionMix),
		jsonOrNull(b.KnownPaths), jsonOrNull(b.KnownDomains), jsonOrNull(b.KnownTools),
		b.AvgCallsPerHour, b.DenyRate, b.SampleSize, NullText(b.Character), b.TrustScore,
		b.ComputedAt); err != nil {
		return err
	}
	return tx.Commit()
}

// ── anomaly_events ──────────────────────────────────────────────────────────

const anomalyColumns = `id, project_id, agent_id, session_id, audit_log_id, kind, severity,
	score, description, detail, created_at`

// ListAnomalies is GET /v1/agents/{id}/anomalies, and the project-wide feed
// when agentID is empty.
func (s *Store) ListAnomalies(ctx context.Context, projectID, agentID string, since int64, limit int) ([]AnomalyEvent, error) {
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if agentID != "" {
		where = append(where, "agent_id = ?")
		args = append(args, agentID)
	}
	if since > 0 {
		where = append(where, "created_at >= ?")
		args = append(args, since)
	}
	args = append(args, ClampLimit(limit, 100, 500))

	rows, err := s.query(ctx,
		`SELECT `+anomalyColumns+` FROM anomaly_events WHERE `+strings.Join(where, " AND ")+
			` ORDER BY created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AnomalyEvent{}
	for rows.Next() {
		var a AnomalyEvent
		var sessionID, auditID, desc, detail sql.NullString
		var score sql.NullFloat64
		if err := rows.Scan(&a.ID, &a.ProjectID, &a.AgentID, &sessionID, &auditID,
			&a.Kind, &a.Severity, &score, &desc, &detail, &a.CreatedAt); err != nil {
			return nil, err
		}
		a.SessionID = text(sessionID)
		a.AuditLogID = text(auditID)
		a.Score = num(score)
		a.Description = text(desc)
		a.Detail = raw(detail)
		out = append(out, a)
	}
	return out, rows.Err()
}

// AnomalyCountsByAgent is the "recent anomalies" number on every live-agent
// card: one COUNT grouped in SQL rather than a page of rows counted in Go.
//
// Grouping in the database is not an optimisation here, it is correctness. The
// alternative is ListAnomalies with a limit, and a limit turns "how many" into
// "how many of the first N", which under-reports exactly on the noisiest agent.
func (s *Store) AnomalyCountsByAgent(ctx context.Context, projectID string, since int64) (map[string]int64, error) {
	rows, err := s.query(ctx, `
		SELECT agent_id, COUNT(*) FROM anomaly_events
		WHERE project_id = ? AND created_at >= ?
		GROUP BY agent_id`, projectID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string]int64{}
	for rows.Next() {
		var agentID string
		var n int64
		if err := rows.Scan(&agentID, &n); err != nil {
			return nil, err
		}
		out[agentID] = n
	}
	return out, rows.Err()
}

// SessionsForAgent is the session list on the agent-detail page.
//
// It queries `sessions` from the agents file on purpose: it exists for one
// endpoint, /v1/agents/{id}, and the alternative — an AgentID field on the
// general session filter — would put a knob on the sessions list that no
// endpoint asks for.
func (s *Store) SessionsForAgent(ctx context.Context, projectID, agentID string, limit int) ([]Session, error) {
	rows, err := s.query(ctx,
		`SELECT `+sessionColumns+` FROM sessions WHERE project_id = ? AND agent_id = ?
		 ORDER BY last_seen_at DESC LIMIT ?`,
		projectID, agentID, ClampLimit(limit, 20, 200))
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

// InsertAnomaly records one deviation from a baseline.
func (s *Store) InsertAnomaly(ctx context.Context, a AnomalyEvent) error {
	if !OneOf(a.Severity, AnomalySeverities) {
		a.Severity = "low"
	}
	_, err := s.exec(ctx, `
		INSERT INTO anomaly_events (`+anomalyColumns+`)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		a.ID, a.ProjectID, a.AgentID, NullText(a.SessionID), NullText(a.AuditLogID),
		a.Kind, a.Severity, a.Score, NullText(a.Description), jsonOrNull(a.Detail), a.CreatedAt)
	return err
}

// ── agent_groups and membership ─────────────────────────────────────────────

// ListAgentGroups returns a project's groups.
func (s *Store) ListAgentGroups(ctx context.Context, projectID string) ([]AgentGroup, error) {
	rows, err := s.query(ctx, `
		SELECT id, project_id, name, description, color, policy_rules, created_at, updated_at
		FROM agent_groups WHERE project_id = ? ORDER BY created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentGroup{}
	for rows.Next() {
		var g AgentGroup
		var desc, color, rules sql.NullString
		if err := rows.Scan(&g.ID, &g.ProjectID, &g.Name, &desc, &color, &rules,
			&g.CreatedAt, &g.UpdatedAt); err != nil {
			return nil, err
		}
		g.Description = text(desc)
		g.Color = text(color)
		g.PolicyRules = raw(rules)
		out = append(out, g)
	}
	return out, rows.Err()
}

// GroupMembers lists one group's agents, scoped to the project as well as the
// group: a group id alone would be enough to read another tenant's membership.
func (s *Store) GroupMembers(ctx context.Context, projectID, groupID string) ([]AgentGroupMember, error) {
	rows, err := s.query(ctx, `
		SELECT id, group_id, agent_id, project_id, created_at
		FROM agent_group_members WHERE project_id = ? AND group_id = ?
		ORDER BY created_at ASC`, projectID, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentGroupMember{}
	for rows.Next() {
		var m AgentGroupMember
		if err := rows.Scan(&m.ID, &m.GroupID, &m.AgentID, &m.ProjectID, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// ── agent_relationships and delegation_chains ───────────────────────────────

// ListRelationships returns the delegation edges of a project.
func (s *Store) ListRelationships(ctx context.Context, projectID string) ([]AgentRelationship, error) {
	rows, err := s.query(ctx, `
		SELECT id, project_id, source_agent_id, target_agent_id, relationship_type, trust_level,
		       allowed_tools, denied_tools, allowed_permissions, max_delegation_depth, enabled,
		       created_at, updated_at
		FROM agent_relationships WHERE project_id = ? ORDER BY created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentRelationship{}
	for rows.Next() {
		var r AgentRelationship
		var relType, trust, allowT, denyT, allowP sql.NullString
		var depth, enabled sql.NullInt64
		if err := rows.Scan(&r.ID, &r.ProjectID, &r.SourceAgentID, &r.TargetAgentID,
			&relType, &trust, &allowT, &denyT, &allowP, &depth, &enabled,
			&r.CreatedAt, &r.UpdatedAt); err != nil {
			return nil, err
		}
		r.RelationshipType = text(relType)
		r.TrustLevel = text(trust)
		if r.TrustLevel == "" {
			r.TrustLevel = "VERIFIED"
		}
		r.AllowedTools = raw(allowT)
		r.DeniedTools = raw(denyT)
		r.AllowedPermissions = raw(allowP)
		r.MaxDelegationDepth = 1
		if depth.Valid {
			r.MaxDelegationDepth = depth.Int64
		}
		r.Enabled = !enabled.Valid || enabled.Int64 != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// ListDelegationChains returns a project's chains, active ones first by recency.
func (s *Store) ListDelegationChains(ctx context.Context, projectID, status string, limit int) ([]DelegationChain, error) {
	where := []string{"project_id = ?"}
	args := []any{projectID}
	if status != "" && OneOf(status, DelegationStatuses) {
		where = append(where, "status = ?")
		args = append(args, status)
	}
	args = append(args, ClampLimit(limit, 100, 500))

	rows, err := s.query(ctx, `
		SELECT id, project_id, chain, origin_agent_id, terminal_agent_id, effective_tools,
		       effective_permissions, status, expires_at, created_at, revoked_at
		FROM delegation_chains WHERE `+strings.Join(where, " AND ")+`
		ORDER BY created_at DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DelegationChain{}
	for rows.Next() {
		var c DelegationChain
		var chain, tools, perms sql.NullString
		var expires, revoked sql.NullInt64
		if err := rows.Scan(&c.ID, &c.ProjectID, &chain, &c.OriginAgentID, &c.TerminalAgentID,
			&tools, &perms, &c.Status, &expires, &c.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		c.Chain = raw(chain)
		c.EffectiveTools = raw(tools)
		c.EffectivePermissions = raw(perms)
		c.ExpiresAt = unix(expires)
		c.RevokedAt = unix(revoked)
		out = append(out, c)
	}
	return out, rows.Err()
}

// jsonOrNull writes a JSON column, or NULL when there is nothing to write.
// An empty string in a JSON column is not valid JSON and json_extract on it
// returns nothing rather than erroring, which is the quiet kind of wrong.
func jsonOrNull(v []byte) any {
	if len(v) == 0 {
		return nil
	}
	return string(v)
}
