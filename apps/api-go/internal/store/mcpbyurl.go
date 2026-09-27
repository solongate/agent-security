package store

import "context"

// McpServerByURL is the one lookup the /v1/mcp-servers routes need that
// tools.go does not already provide.
//
// It is a separate file rather than an edit to tools.go so two route slices
// landing at once do not collide on the same lines; the queries belong to the
// same table and the same package either way.
//
// The URL is the natural key for a registration. POST /v1/mcp-servers is called
// by the proxy every time it starts in front of an upstream, so the common case
// is a server this project already has — the live route looks it up by
// (project_id, url) and flips the existing row back to active instead of
// accumulating a duplicate per launch.
//
// project_id comes first in the WHERE for the same reason it does everywhere
// else here: a URL is not unique across the database, and a lookup that omitted
// the tenant would hand one project's registration to another's key.
func (s *Store) McpServerByURL(ctx context.Context, projectID, url string) (McpServer, error) {
	rows, err := s.query(ctx,
		`SELECT `+mcpColumns+` FROM mcp_servers WHERE project_id = ? AND url = ? LIMIT 1`,
		projectID, url)
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
