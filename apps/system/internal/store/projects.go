package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// The `projects` table — the tenant boundary.
//
// Two shapes come out of here and the difference is the point. Project carries
// token_secret and is for the one caller that signs with it; ProjectSummary
// does not and is for everything that describes a project to a client. A route
// that reaches for Project when it wanted ProjectSummary is one JSON spread
// away from publishing a signing key.

// ProjectByID is the full row, token secret included. Callers: the capability
// token routes and nothing else.
func (s *Store) ProjectByID(ctx context.Context, id string) (Project, error) {
	var p Project
	var orgID, desc, piMode, piWhitelist, piToolCfg, piPatterns sql.NullString
	var judgeModel, judgeEndpoint sql.NullString
	var piEnabled, judgeEnabled, judgeTimeout sql.NullInt64
	var piThreshold sql.NullFloat64

	err := s.queryRow(ctx, `
		SELECT id, owner_id, org_id, name, slug, description, token_secret,
		       pi_enabled, pi_threshold, pi_mode, pi_whitelist, pi_tool_config,
		       pi_custom_patterns,
		       ai_judge_enabled, ai_judge_model, ai_judge_endpoint, ai_judge_timeout_ms,
		       created_at, updated_at
		FROM projects WHERE id = ? LIMIT 1`, id).
		Scan(&p.ID, &p.OwnerID, &orgID, &p.Name, &p.Slug, &desc, &p.TokenSecret,
			&piEnabled, &piThreshold, &piMode, &piWhitelist, &piToolCfg,
			&piPatterns,
			&judgeEnabled, &judgeModel, &judgeEndpoint, &judgeTimeout,
			&p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Project{}, ErrNotFound
	}
	if err != nil {
		return Project{}, err
	}

	p.OrgID = text(orgID)
	p.Description = text(desc)
	// pi_enabled defaults to TRUE in the schema. A NULL here is a row written
	// before the column existed, and reading it as false would silently turn
	// injection detection off for the oldest projects in the database — the
	// ones most likely to have somebody depending on it.
	p.PiEnabled = !piEnabled.Valid || piEnabled.Int64 != 0
	p.PiThreshold = 0.5
	if piThreshold.Valid {
		p.PiThreshold = piThreshold.Float64
	}
	p.PiMode = text(piMode)
	if p.PiMode == "" {
		p.PiMode = "block"
	}
	p.PiWhitelist = text(piWhitelist)
	p.PiToolConfig = text(piToolCfg)
	p.PiCustomPatterns = text(piPatterns)

	p.AIJudgeEnabled = boolVal(judgeEnabled)
	p.AIJudgeModel = text(judgeModel)
	if p.AIJudgeModel == "" {
		p.AIJudgeModel = "llama-3.1-8b-instant"
	}
	p.AIJudgeEndpoint = text(judgeEndpoint)
	if p.AIJudgeEndpoint == "" {
		p.AIJudgeEndpoint = "https://api.groq.com/openai"
	}
	p.AIJudgeTimeoutMs = 5000
	if judgeTimeout.Valid {
		p.AIJudgeTimeoutMs = judgeTimeout.Int64
	}
	return p, nil
}

// ProjectOwner is the one-column question most routes are actually asking:
// which user does this project belong to. It exists so "who owns this" never
// requires fetching the token secret.
func (s *Store) ProjectOwner(ctx context.Context, projectID string) (string, error) {
	var owner string
	err := s.queryRow(ctx,
		`SELECT owner_id FROM projects WHERE id = ? LIMIT 1`, projectID).Scan(&owner)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return owner, err
}

// ProjectSummaryByID is the safe description of one project.
func (s *Store) ProjectSummaryByID(ctx context.Context, id string) (ProjectSummary, error) {
	var p ProjectSummary
	var orgID, desc sql.NullString
	err := s.queryRow(ctx, `
		SELECT id, owner_id, org_id, name, slug, description, created_at, updated_at
		FROM projects WHERE id = ? LIMIT 1`, id).
		Scan(&p.ID, &p.OwnerID, &orgID, &p.Name, &p.Slug, &desc, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSummary{}, ErrNotFound
	}
	if err != nil {
		return ProjectSummary{}, err
	}
	p.OrgID = text(orgID)
	p.Description = text(desc)
	return p, nil
}

// ProjectsByOwner is GET /v1/projects.
//
// It is scoped to an owner id the caller did NOT supply: the route resolves the
// API key to a project, the project to its owner, and only then lists. Taking
// an owner id from the request would make every project in the database
// readable by anyone holding any valid key.
func (s *Store) ProjectsByOwner(ctx context.Context, ownerID string) ([]ProjectSummary, error) {
	rows, err := s.query(ctx, `
		SELECT id, owner_id, org_id, name, slug, description, created_at, updated_at
		FROM projects WHERE owner_id = ?
		ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProjectSummary{}
	for rows.Next() {
		var p ProjectSummary
		var orgID, desc sql.NullString
		if err := rows.Scan(&p.ID, &p.OwnerID, &orgID, &p.Name, &p.Slug, &desc, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		p.OrgID = text(orgID)
		p.Description = text(desc)
		out = append(out, p)
	}
	return out, rows.Err()
}

// LatestProjectByOwner is the "which project is this person's" question the
// provisioning flows ask before deciding whether to create one.
func (s *Store) LatestProjectByOwner(ctx context.Context, ownerID string) (ProjectSummary, error) {
	var p ProjectSummary
	var orgID, desc sql.NullString
	err := s.queryRow(ctx, `
		SELECT id, owner_id, org_id, name, slug, description, created_at, updated_at
		FROM projects WHERE owner_id = ?
		ORDER BY created_at DESC LIMIT 1`, ownerID).
		Scan(&p.ID, &p.OwnerID, &orgID, &p.Name, &p.Slug, &desc, &p.CreatedAt, &p.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectSummary{}, ErrNotFound
	}
	if err != nil {
		return ProjectSummary{}, err
	}
	p.OrgID = text(orgID)
	p.Description = text(desc)
	return p, nil
}

// ProjectSlugTaken answers /v1/setup's uniqueness check before the insert, so
// the caller gets 409 rather than a constraint error rendered as a 500.
func (s *Store) ProjectSlugTaken(ctx context.Context, slug string) (bool, error) {
	var one int
	err := s.queryRow(ctx, `SELECT 1 FROM projects WHERE slug = ? LIMIT 1`, slug).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// CreateProject inserts a project and its per-project signing secret. The
// secret is generated by the caller (internal/apiauth) and is written here
// once; there is no query in this package that updates it, because rotating it
// would invalidate every capability token in flight.
func (s *Store) CreateProject(ctx context.Context, p Project) error {
	_, err := s.exec(ctx, `
		INSERT INTO projects (id, owner_id, org_id, name, slug, description, token_secret, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.OwnerID, NullText(p.OrgID), p.Name, p.Slug, p.Description, p.TokenSecret,
		p.CreatedAt, p.UpdatedAt)
	return err
}

// ── the /v1/projects endpoints' own view ────────────────────────────────────

// ProjectRow is one project as GET /v1/projects, GET /v1/projects/{id} and PUT
// /v1/projects/{id} describe it.
//
// Every nullable column is a POINTER here, where ProjectSummary flattens them
// to strings, and that is the whole reason this type exists next to that one.
// drizzle hands a NULL column to JSON as `null`, so the deployed dashboard has
// been reading `description: null` and `piWhitelist: null` for as long as these
// endpoints have existed. Collapsing NULL to "" would be invisible in Go and a
// changed body on the wire.
//
// The token secret is absent, as it is from ProjectSummary and for the same
// reason: these three endpoints describe a project to a client.
type ProjectRow struct {
	ID               string
	Name             string
	Slug             string
	Description      *string
	OrgID            *string
	PiEnabled        *bool
	PiThreshold      *float64
	PiMode           *string
	PiWhitelist      *string
	PiToolConfig     *string
	PiCustomPatterns *string
	CreatedAt        int64
	UpdatedAt        int64
}

// ProjectListRow is a ProjectRow plus the owner's name and address, which GET
// /v1/projects left-joins in so the project selector can label a row with a
// person rather than a UUID. Both are pointers because the join is a LEFT one
// and users.name is nullable.
type ProjectListRow struct {
	ProjectRow
	OwnerName  *string
	OwnerEmail *string
}

const projectRowColumns = `p.id, p.name, p.slug, p.description, p.org_id,
	p.pi_enabled, p.pi_threshold, p.pi_mode, p.pi_whitelist, p.pi_tool_config,
	p.pi_custom_patterns, p.created_at, p.updated_at`

// ProjectsForOwner is GET /v1/projects.
//
// The owner id is NOT caller input: the route resolves the API key to a
// project, the project to its owner, and passes that. Reading an owner from the
// request would make every project in the database listable by anyone holding
// any valid key.
//
// There is no ORDER BY, matching the live query. Adding one would be a tidier
// statement and a different order in a project selector somebody is used to.
func (s *Store) ProjectsForOwner(ctx context.Context, ownerID string) ([]ProjectListRow, error) {
	rows, err := s.query(ctx, `
		SELECT `+projectRowColumns+`, u.name, u.email
		FROM projects p LEFT JOIN users u ON p.owner_id = u.id
		WHERE p.owner_id = ?`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ProjectListRow{}
	for rows.Next() {
		var r ProjectListRow
		var desc, orgID, piMode, piWhitelist, piToolCfg, piPatterns sql.NullString
		var ownerName, ownerEmail sql.NullString
		var piEnabled sql.NullInt64
		var piThreshold sql.NullFloat64
		if err := rows.Scan(&r.ID, &r.Name, &r.Slug, &desc, &orgID,
			&piEnabled, &piThreshold, &piMode, &piWhitelist, &piToolCfg,
			&piPatterns, &r.CreatedAt, &r.UpdatedAt,
			&ownerName, &ownerEmail); err != nil {
			return nil, err
		}
		r.ProjectRow = fillProjectRow(r.ProjectRow, desc, orgID, piEnabled, piThreshold,
			piMode, piWhitelist, piToolCfg, piPatterns)
		r.OwnerName = textPtr(ownerName)
		r.OwnerEmail = textPtr(ownerEmail)
		out = append(out, r)
	}
	return out, rows.Err()
}

// ProjectRowForOwner is the id routes' read: one project, matched on the PAIR
// (id, owner).
//
// The owner half is the authorisation. A project id is a UUID a caller can hold
// from any context — an old dashboard tab, a colleague's screenshot — so
// matching on it alone would hand any valid key another tenant's settings.
func (s *Store) ProjectRowForOwner(ctx context.Context, projectID, ownerID string) (ProjectRow, error) {
	var r ProjectRow
	var desc, orgID, piMode, piWhitelist, piToolCfg, piPatterns sql.NullString
	var piEnabled sql.NullInt64
	var piThreshold sql.NullFloat64

	err := s.queryRow(ctx, `
		SELECT `+projectRowColumns+`
		FROM projects p WHERE p.id = ? AND p.owner_id = ? LIMIT 1`, projectID, ownerID).
		Scan(&r.ID, &r.Name, &r.Slug, &desc, &orgID,
			&piEnabled, &piThreshold, &piMode, &piWhitelist, &piToolCfg,
			&piPatterns, &r.CreatedAt, &r.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return ProjectRow{}, ErrNotFound
	}
	if err != nil {
		return ProjectRow{}, err
	}
	return fillProjectRow(r, desc, orgID, piEnabled, piThreshold,
		piMode, piWhitelist, piToolCfg, piPatterns), nil
}

// fillProjectRow moves the nullable columns onto the row. It is one function
// rather than two copies so the list and the detail endpoint cannot disagree
// about which column is which.
func fillProjectRow(r ProjectRow, desc, orgID sql.NullString, piEnabled sql.NullInt64,
	piThreshold sql.NullFloat64, piMode, piWhitelist, piToolCfg, piPatterns sql.NullString) ProjectRow {
	r.Description = textPtr(desc)
	r.OrgID = textPtr(orgID)
	r.PiEnabled = boolPtr(piEnabled)
	r.PiThreshold = numPtr(piThreshold)
	r.PiMode = textPtr(piMode)
	r.PiWhitelist = textPtr(piWhitelist)
	r.PiToolConfig = textPtr(piToolCfg)
	r.PiCustomPatterns = textPtr(piPatterns)
	return r
}

// textPtr keeps a NULL text column distinguishable from an empty one. text()
// collapses the two, which is right for the columns nothing renders as null and
// wrong for these.
func textPtr(v sql.NullString) *string {
	if !v.Valid {
		return nil
	}
	s := v.String
	return &s
}

// ProjectPatch is the SET clause of PUT /v1/projects/{id}, built one column at
// a time.
//
// A patch rather than a whole-row UPDATE because the live route writes only the
// fields the body mentions: a PUT carrying `{"name":"x"}` must leave the
// injection settings alone, and a struct-shaped update would blank them.
//
// The column names are literals inside the methods and every value is bound, so
// nothing a caller sends can reach the statement as text — which is the reason
// a dynamic UPDATE is written this way rather than assembled at the call site.
type ProjectPatch struct {
	cols []string
	args []any
}

func (p *ProjectPatch) set(col string, v any) {
	p.cols = append(p.cols, col+" = ?")
	p.args = append(p.args, v)
}

func (p *ProjectPatch) SetName(v string)        { p.set("name", v) }
func (p *ProjectPatch) SetDescription(v string) { p.set("description", v) }
func (p *ProjectPatch) SetPiEnabled(v bool)     { p.set("pi_enabled", Bit(v)) }
func (p *ProjectPatch) SetPiMode(v string)      { p.set("pi_mode", v) }
func (p *ProjectPatch) SetPiWhitelist(v string) { p.set("pi_whitelist", v) }
func (p *ProjectPatch) SetPiToolConfig(v string) {
	p.set("pi_tool_config", v)
}
func (p *ProjectPatch) SetPiCustomPatterns(v string) {
	p.set("pi_custom_patterns", v)
}

// SetPiThreshold takes a pointer because nil is a real outcome here: the live
// route clamps `Number(body.piThreshold)`, and a non-numeric body gives NaN,
// which SQLite stores as NULL. See the call site.
func (p *ProjectPatch) SetPiThreshold(v *float64) { p.set("pi_threshold", nullFloat(v)) }

// UpdateProjectPatch applies the patch, scoped to (id, owner).
//
// updated_at is always written, even for an empty patch, because the live route
// seeds its update object with it and a PUT that changed nothing still bumps
// the stamp. The row count is not reported: the live route ignores it too and
// decides between 200 and 403 by re-reading the row afterwards, which is the
// only check that also catches a project deleted mid-request.
func (s *Store) UpdateProjectPatch(ctx context.Context, projectID, ownerID string, p *ProjectPatch, at int64) error {
	sets := append(append([]string{}, p.cols...), "updated_at = ?")
	args := append(append([]any{}, p.args...), at, projectID, ownerID)
	_, err := s.exec(ctx,
		`UPDATE projects SET `+strings.Join(sets, ", ")+` WHERE id = ? AND owner_id = ?`, args...)
	return err
}

// DeleteProjectCascade is DELETE /v1/projects/{id}: the project and the rows
// that hang off it, in one transaction.
//
// The tables and their ORDER are the live route's, and the explicit deletes are
// not redundant with the schema's ON DELETE CASCADE — SQLite enforces foreign
// keys only when `PRAGMA foreign_keys` is on, which is off by default, so a
// project deleted on its own would leave its audit history behind as
// unreachable rows.
//
// The caller has already checked that this project belongs to the key's owner.
// That check cannot be folded in here: every statement below keys on
// project_id, which is the tenant column itself.
//
// Five tables the live route does not name are left alone — sessions, agents,
// agent_baselines, anomaly_events and the rest — because reproducing the live
// behaviour matters more than tidiness, and widening a DELETE is not a thing to
// do quietly in a port.
func (s *Store) DeleteProjectCascade(ctx context.Context, projectID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	for _, stmt := range []string{
		`DELETE FROM audit_logs WHERE project_id = ?`,
		`DELETE FROM used_nonces WHERE project_id = ?`,
		`DELETE FROM policy_versions WHERE project_id = ?`,
		`DELETE FROM tools WHERE project_id = ?`,
		`DELETE FROM mcp_servers WHERE project_id = ?`,
		`DELETE FROM api_keys WHERE project_id = ?`,
		`DELETE FROM projects WHERE id = ?`,
	} {
		if _, err := s.txExec(ctx, tx, stmt, projectID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ProjectConfig is what GET /v1/project-config hands the guard: the
// prompt-injection settings, without anything that identifies the project.
type ProjectConfig struct {
	PiEnabled        bool
	PiThreshold      float64
	PiMode           string
	PiWhitelist      string
	PiToolConfig     string
	PiCustomPatterns string
	AIJudgeEnabled   bool
	AIJudgeModel     string
	AIJudgeEndpoint  string
	AIJudgeTimeoutMs int64
}

// ProjectConfigByID reads only the injection-detection settings.
func (s *Store) ProjectConfigByID(ctx context.Context, projectID string) (ProjectConfig, error) {
	p, err := s.ProjectByID(ctx, projectID)
	if err != nil {
		return ProjectConfig{}, err
	}
	return ProjectConfig{
		PiEnabled:        p.PiEnabled,
		PiThreshold:      p.PiThreshold,
		PiMode:           p.PiMode,
		PiWhitelist:      p.PiWhitelist,
		PiToolConfig:     p.PiToolConfig,
		PiCustomPatterns: p.PiCustomPatterns,
		AIJudgeEnabled:   p.AIJudgeEnabled,
		AIJudgeModel:     p.AIJudgeModel,
		AIJudgeEndpoint:  p.AIJudgeEndpoint,
		AIJudgeTimeoutMs: p.AIJudgeTimeoutMs,
	}, nil
}
