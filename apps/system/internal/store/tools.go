package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// The `tools` and `mcp_servers` tables.
//
// Both are project-scoped catalogues the dashboard edits. The one thing worth
// naming here is the tools route's key: /v1/tools/{name} identifies a tool by
// NAME, not by id, and a name is not unique across the database — so the pair
// (project_id, name) is what every lookup uses.

const toolColumns = `id, project_id, name, description, input_schema, permissions, enabled, created_at, updated_at`

func (s *Store) ListTools(ctx context.Context, projectID string) ([]Tool, error) {
	rows, err := s.query(ctx,
		`SELECT `+toolColumns+` FROM tools WHERE project_id = ? ORDER BY name ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Tool{}
	for rows.Next() {
		t, err := scanTool(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// ToolByName is GET /v1/tools/{name}.
func (s *Store) ToolByName(ctx context.Context, projectID, name string) (Tool, error) {
	rows, err := s.query(ctx,
		`SELECT `+toolColumns+` FROM tools WHERE project_id = ? AND name = ? LIMIT 1`,
		projectID, name)
	if err != nil {
		return Tool{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return Tool{}, err
		}
		return Tool{}, ErrNotFound
	}
	return scanTool(rows)
}

func (s *Store) CreateTool(ctx context.Context, t Tool) error {
	_, err := s.exec(ctx, `
		INSERT INTO tools (`+toolColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.ProjectID, t.Name, textArg(t.Description), jsonOrNull(t.InputSchema),
		jsonOrNull(t.Permissions), Bit(t.Enabled), t.CreatedAt, t.UpdatedAt)
	return err
}

// UpdateTool is PUT /v1/tools/{name}. The name is the key, so it is in the
// WHERE and not in the SET — renaming through this endpoint would silently
// create a second tool rather than rename one.
func (s *Store) UpdateTool(ctx context.Context, projectID, name string, t Tool) (bool, error) {
	res, err := s.exec(ctx, `
		UPDATE tools SET description = ?, input_schema = ?, permissions = ?, enabled = ?, updated_at = ?
		WHERE project_id = ? AND name = ?`,
		textArg(t.Description), jsonOrNull(t.InputSchema), jsonOrNull(t.Permissions),
		Bit(t.Enabled), t.UpdatedAt, projectID, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ToolPatch is the SET clause of PUT /v1/tools/{name}, built one column at a
// time — the same construction as ProjectPatch and for the same reason.
//
// The live route passes `body.description` and friends straight into drizzle's
// .set(), and drizzle OMITS a property whose value is undefined. So a PUT that
// mentions only `enabled` leaves the description alone, and a PUT that sends
// `"description": null` clears it. Those two cases are indistinguishable in a
// struct of strings, which is why this exists rather than UpdateTool growing
// arguments.
type ToolPatch struct {
	cols []string
	args []any
}

func (p *ToolPatch) set(col string, v any) {
	p.cols = append(p.cols, col+" = ?")
	p.args = append(p.args, v)
}

// SetDescription takes a pointer so `{"description": null}` writes NULL rather
// than the empty string.
func (p *ToolPatch) SetDescription(v *string) {
	if v == nil {
		p.set("description", nil)
		return
	}
	p.set("description", *v)
}

func (p *ToolPatch) SetInputSchema(v json.RawMessage) { p.set("input_schema", jsonOrNull(v)) }
func (p *ToolPatch) SetPermissions(v json.RawMessage) { p.set("permissions", jsonOrNull(v)) }
func (p *ToolPatch) SetEnabled(v bool)                { p.set("enabled", Bit(v)) }

// UpdateToolPatch applies the patch to the pair (project, name).
//
// updated_at is always written, matching the live route, which puts it in the
// same .set() as everything else — so a PUT carrying an empty body still
// touches the row. `name` is never in the patch: it is the key, and renaming
// through this endpoint would create a second tool rather than rename one.
func (s *Store) UpdateToolPatch(ctx context.Context, projectID, name string, p *ToolPatch, at int64) (bool, error) {
	sets := append(append([]string{}, p.cols...), "updated_at = ?")
	args := append(append([]any{}, p.args...), at, projectID, name)
	res, err := s.exec(ctx,
		`UPDATE tools SET `+strings.Join(sets, ", ")+` WHERE project_id = ? AND name = ?`, args...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) DeleteTool(ctx context.Context, projectID, name string) (bool, error) {
	res, err := s.exec(ctx,
		`DELETE FROM tools WHERE project_id = ? AND name = ?`, projectID, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// textArg writes a nullable text column from a pointer. NullText collapses the
// empty string to NULL, which is right for a command or an org id and wrong
// here: a tool's description is legitimately "" and a client can tell that from
// null.
func textArg(v *string) any {
	if v == nil {
		return nil
	}
	return *v
}

func scanTool(rows *sql.Rows) (Tool, error) {
	var t Tool
	var desc, schema, perms sql.NullString
	var enabled sql.NullInt64
	if err := rows.Scan(&t.ID, &t.ProjectID, &t.Name, &desc, &schema, &perms, &enabled,
		&t.CreatedAt, &t.UpdatedAt); err != nil {
		return Tool{}, err
	}
	t.Description = textPtr(desc)
	t.InputSchema = raw(schema)
	t.Permissions = raw(perms)
	// `enabled` is NOT NULL DEFAULT true in the schema; a NULL here can only
	// come from a row written outside it, and treating that as disabled would
	// remove a tool from the catalogue rather than show it.
	t.Enabled = !enabled.Valid || enabled.Int64 != 0
	return t, nil
}

// ── mcp_servers ─────────────────────────────────────────────────────────────

const mcpColumns = `id, project_id, name, url, status, command, args, created_at, updated_at`

func (s *Store) ListMcpServers(ctx context.Context, projectID string) ([]McpServer, error) {
	rows, err := s.query(ctx,
		`SELECT `+mcpColumns+` FROM mcp_servers WHERE project_id = ? ORDER BY created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []McpServer{}
	for rows.Next() {
		m, err := scanMcp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) McpServerByID(ctx context.Context, projectID, id string) (McpServer, error) {
	rows, err := s.query(ctx,
		`SELECT `+mcpColumns+` FROM mcp_servers WHERE project_id = ? AND id = ? LIMIT 1`,
		projectID, id)
	if err != nil {
		return McpServer{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return McpServer{}, err
		}
		return McpServer{}, ErrNotFound
	}
	return scanMcp(rows)
}

func (s *Store) CreateMcpServer(ctx context.Context, m McpServer) error {
	if !OneOf(m.Status, McpServerStatuses) {
		m.Status = "inactive"
	}
	_, err := s.exec(ctx, `
		INSERT INTO mcp_servers (`+mcpColumns+`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ID, m.ProjectID, m.Name, m.URL, m.Status,
		NullText(m.Command), NullText(m.Args), m.CreatedAt, m.UpdatedAt)
	return err
}

func (s *Store) UpdateMcpServer(ctx context.Context, projectID, id string, m McpServer) (bool, error) {
	if !OneOf(m.Status, McpServerStatuses) {
		m.Status = "inactive"
	}
	res, err := s.exec(ctx, `
		UPDATE mcp_servers SET name = ?, url = ?, status = ?, command = ?, args = ?, updated_at = ?
		WHERE project_id = ? AND id = ?`,
		m.Name, m.URL, m.Status, NullText(m.Command), NullText(m.Args), m.UpdatedAt,
		projectID, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// SetMcpServerStatus is what the reachability check writes back.
func (s *Store) SetMcpServerStatus(ctx context.Context, projectID, id, status string, at int64) error {
	if !OneOf(status, McpServerStatuses) {
		return nil
	}
	_, err := s.exec(ctx,
		`UPDATE mcp_servers SET status = ?, updated_at = ? WHERE project_id = ? AND id = ?`,
		status, at, projectID, id)
	return err
}

func (s *Store) DeleteMcpServer(ctx context.Context, projectID, id string) (bool, error) {
	res, err := s.exec(ctx,
		`DELETE FROM mcp_servers WHERE project_id = ? AND id = ?`, projectID, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func scanMcp(rows *sql.Rows) (McpServer, error) {
	var m McpServer
	var command, args sql.NullString
	if err := rows.Scan(&m.ID, &m.ProjectID, &m.Name, &m.URL, &m.Status, &command, &args,
		&m.CreatedAt, &m.UpdatedAt); err != nil {
		return McpServer{}, err
	}
	m.Command = text(command)
	m.Args = text(args)
	return m, nil
}
