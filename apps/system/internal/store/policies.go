package store

import (
	"context"
	"database/sql"
	"encoding/json"
)

// The `policy_versions` table.
//
// Rows are append-only: an edit writes a new version rather than updating one,
// which is what keeps a hash stable once it is issued. Nothing here updates
// policy_data.
//
// The hash travels to the guard and is the integrity check on a cached policy,
// so it must be the hash of the bytes that were STORED. Re-serialising a
// decoded policy to hash it would produce a different string for the same
// policy — different key order, different whitespace — and the guard would
// treat a policy it already has as changed on every poll.

// ActivePolicyRow is the projection GET /v1/policies/active selects: enough to
// choose between versions and to answer with one, and nothing more. wasm_bundle
// in particular is base64 and large, and selecting it on the guard's poll path
// would multiply this service's egress by the size of every project's bundle.
type ActivePolicyRow struct {
	Version    int64
	PolicyData json.RawMessage
	Hash       string
	CreatedAt  int64
}

// PolicyVersionsForSelection is the guard poll's read: every version of every
// policy in the project, newest version first.
//
// It returns ALL rows rather than the latest, because the selection the route
// performs is per-POLICY-ID: the newest version of each distinct policy, then a
// match on agent id, then a wildcard. Filtering to one row here would collapse
// several policies into whichever happened to have the highest version number.
//
// ORDER BY is a constant. The route has no sort parameter and must not grow
// one — this query is on the hot path of every installed guard.
func (s *Store) PolicyVersionsForSelection(ctx context.Context, projectID string) ([]ActivePolicyRow, error) {
	rows, err := s.query(ctx, `
		SELECT version, policy_data, hash, created_at
		FROM policy_versions
		WHERE project_id = ?
		ORDER BY version DESC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []ActivePolicyRow{}
	for rows.Next() {
		var r ActivePolicyRow
		var data sql.NullString
		if err := rows.Scan(&r.Version, &data, &r.Hash, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.PolicyData = raw(data)
		out = append(out, r)
	}
	return out, rows.Err()
}

// LatestPolicyVersion is the newest row in the project, whichever policy it
// belongs to. It is what a route needs before writing version N+1.
func (s *Store) LatestPolicyVersion(ctx context.Context, projectID string) (PolicyVersion, error) {
	return s.policyOne(ctx, `
		SELECT id, project_id, version, policy_data, hash, reason, created_by,
		       rego_source, wasm_bundle, created_at
		FROM policy_versions WHERE project_id = ?
		ORDER BY version DESC LIMIT 1`, projectID)
}

// LatestVersionNumber is the counter the next insert increments. It returns 0
// for a project with no policies, so the first version is 1.
func (s *Store) LatestVersionNumber(ctx context.Context, projectID string) (int64, error) {
	var v sql.NullInt64
	err := s.queryRow(ctx,
		`SELECT MAX(version) FROM policy_versions WHERE project_id = ?`, projectID).Scan(&v)
	if err != nil {
		return 0, err
	}
	return intVal(v), nil
}

// PolicyVersionByID fetches one revision, project-scoped.
//
// The project clause is not redundant with the primary key. A version id is a
// UUID that appears in dashboard URLs and in the version list; without the
// clause, holding any valid API key plus one id read out of a screenshot would
// return another tenant's policy — which is a document naming their paths,
// their commands and their internal URLs.
func (s *Store) PolicyVersionByID(ctx context.Context, projectID, id string) (PolicyVersion, error) {
	return s.policyOne(ctx, `
		SELECT id, project_id, version, policy_data, hash, reason, created_by,
		       rego_source, wasm_bundle, created_at
		FROM policy_versions WHERE project_id = ? AND id = ? LIMIT 1`, projectID, id)
}

// ── selection by LOGICAL policy id ──────────────────────────────────────────
//
// A policy's logical id lives inside policy_data, not in a column, so filtering
// on it means json_extract over every row of the project — a scan. That is why
// the guard's poll path above does NOT do it: it reads every version once and
// picks in Go, because that query runs on every installed guard's interval and
// a scan there is a scan multiplied by the fleet.
//
// The dashboard-facing routes do do it, as the live app's queries do. They are
// human-paced, and the alternative — pulling every version of every policy into
// this process to find one — is more rows over the wire, not fewer.
//
// json_extract's PATH is a literal in the SQL. The policy id is bound. Nothing
// below builds a filter out of caller text; see policyScope, which is the one
// place the two forms of the WHERE clause are written.

// policyScope is the WHERE clause a route's `{id}` selects.
//
// `default` is not a policy id: several routes use it to mean "this project's
// policy history, whatever it is called", and the live app spells that as a
// project-only filter. Anything else is matched against the id inside
// policy_data. The rules routes deliberately do NOT get this treatment — a
// policy genuinely named "default" is what they operate on — so they pass
// scopeByID directly.
func (s *Store) policyScope(projectID, policyID string) (string, []any) {
	if policyID == "default" {
		return `project_id = ?`, []any{projectID}
	}
	return s.scopeByID(projectID, policyID)
}

func (s *Store) scopeByID(projectID, policyID string) (string, []any) {
	return "project_id = ? AND " + s.jsonField("policy_data", "id") + " = ?", []any{projectID, policyID}
}

const policyColumns = `id, project_id, version, policy_data, hash, reason, created_by,
	       rego_source, wasm_bundle, created_at`

// LatestPolicyByID is the newest version of ONE logical policy. It is what the
// rules routes read before appending a rule and what GET /policies/{id}
// answers with.
func (s *Store) LatestPolicyByID(ctx context.Context, projectID, policyID string) (PolicyVersion, error) {
	where, args := s.scopeByID(projectID, policyID)
	return s.policyOne(ctx, `SELECT `+policyColumns+` FROM policy_versions WHERE `+where+
		` ORDER BY version DESC LIMIT 1`, args...)
}

// PolicyVersionAt is one numbered revision within a scope. `default` means the
// project rather than a policy; see policyScope.
func (s *Store) PolicyVersionAt(ctx context.Context, projectID, policyID string, version any) (PolicyVersion, error) {
	where, args := s.policyScope(projectID, policyID)
	args = append(args, version)
	return s.policyOne(ctx, `SELECT `+policyColumns+` FROM policy_versions WHERE `+where+
		` AND version = ? LIMIT 1`, args...)
}

// MaxVersionForPolicy is the counter the next write increments, within a scope.
// Zero for a policy that does not exist yet, so its first version is 1.
func (s *Store) MaxVersionForPolicy(ctx context.Context, projectID, policyID string) (int64, error) {
	where, args := s.policyScope(projectID, policyID)
	var v sql.NullInt64
	err := s.queryRow(ctx,
		`SELECT MAX(version) FROM policy_versions WHERE `+where, args...).Scan(&v)
	if err != nil {
		return 0, err
	}
	return intVal(v), nil
}

// MaxVersionByID is MaxVersionForPolicy without the `default` special case,
// for the rules routes.
func (s *Store) MaxVersionByID(ctx context.Context, projectID, policyID string) (int64, error) {
	where, args := s.scopeByID(projectID, policyID)
	var v sql.NullInt64
	err := s.queryRow(ctx,
		`SELECT MAX(version) FROM policy_versions WHERE `+where, args...).Scan(&v)
	if err != nil {
		return 0, err
	}
	return intVal(v), nil
}

// DeletePolicyByID removes every revision of one logical policy.
func (s *Store) DeletePolicyByID(ctx context.Context, projectID, policyID string) (int64, error) {
	where, args := s.scopeByID(projectID, policyID)
	res, err := s.exec(ctx, `DELETE FROM policy_versions WHERE `+where, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LatestCompiledRego is the newest revision of a policy that HAS a Rego build.
//
// It is not the same as "the newest revision": a version saved while
// compilation was unavailable has a NULL rego_source, and serving that as "no
// Rego for this policy" would throw away a perfectly good build one version
// back. ErrNotFound means nothing is compiled and the route should compile on
// demand.
func (s *Store) LatestCompiledRego(ctx context.Context, projectID, policyID string) (PolicyVersion, error) {
	where, args := s.scopeByID(projectID, policyID)
	return s.policyOne(ctx, `SELECT `+policyColumns+` FROM policy_versions WHERE `+where+
		` AND rego_source IS NOT NULL ORDER BY version DESC LIMIT 1`, args...)
}

// PolicyListRow is GET /policies: the newest version of each distinct policy in
// the project, with the creator resolved through users.
//
// The join is LEFT: created_by is nullable and can also name a user who has
// since been deleted, and either of those becoming an inner-join miss would
// drop the policy from the list entirely.
type PolicyListRow struct {
	Version      int64
	PolicyData   json.RawMessage
	Hash         string
	CreatedBy    string
	CreatorName  string
	CreatorEmail string
	CreatedAt    int64
}

// ListPolicies is that query.
//
// The subquery groups by the id INSIDE policy_data, so two policies in one
// project each contribute their own newest version — which is the difference
// between this and LatestPolicyVersion, and the reason the guard's selection
// cannot just take the highest version number in the project.
func (s *Store) ListPolicies(ctx context.Context, projectID string) ([]PolicyListRow, error) {
	rows, err := s.query(ctx, `
		SELECT pv.version, pv.policy_data, pv.hash, pv.created_by,
		       u.name, u.email, pv.created_at
		FROM policy_versions pv
		INNER JOIN (
			SELECT `+s.jsonField("policy_data", "id")+` AS policy_id, MAX(version) AS max_version
			FROM policy_versions
			WHERE project_id = ?
			GROUP BY `+s.jsonField("policy_data", "id")+`
		) latest
		  ON `+s.jsonField("pv.policy_data", "id")+` = latest.policy_id
		 AND pv.version = latest.max_version
		LEFT JOIN users u ON pv.created_by = u.id
		WHERE pv.project_id = ?
		ORDER BY pv.version DESC`, projectID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PolicyListRow{}
	for rows.Next() {
		var r PolicyListRow
		var data, createdBy, name, email sql.NullString
		if err := rows.Scan(&r.Version, &data, &r.Hash, &createdBy, &name, &email, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.PolicyData = raw(data)
		r.CreatedBy = text(createdBy)
		r.CreatorName = text(name)
		r.CreatorEmail = text(email)
		out = append(out, r)
	}
	return out, rows.Err()
}

// PolicyRulesHistory reads a policy's revisions WITHOUT their payloads.
//
// The limit is BOUND, not interpolated. A LIMIT is the parameter people skip
// because "it is only a number" — until it is `10; DROP TABLE`, or until it is
// 10000000 and this is how somebody reads the whole table.
//
// The audit list calls this on every page to put a NAME to a matched rule id,
// and it only ever reads policy_data. The full history selects rego_source and
// wasm_bundle beside it — a compiled WASM bundle per version, thirty versions
// deep — so a request returning fifty audit entries was pulling megabytes of
// compiled policy across the wire to look up a string. That was most of what was
// left of GET /audit-logs after the burst scan was fixed.
//
// Only id, version and policy_data. Everything else the caller ignored anyway.
func (s *Store) PolicyRulesHistory(ctx context.Context, projectID string, limit int) ([]PolicyVersion, error) {
	rows, err := s.query(ctx, `
		SELECT id, version, policy_data
		FROM policy_versions WHERE project_id = ?
		ORDER BY version DESC LIMIT ?`, projectID, ClampLimit(limit, 50, 500))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PolicyVersion{}
	for rows.Next() {
		var v PolicyVersion
		if err := rows.Scan(&v.ID, &v.Version, &v.PolicyData); err != nil {
			return nil, err
		}
		v.ProjectID = projectID
		out = append(out, v)
	}
	return out, rows.Err()
}

// InsertPolicyVersion appends a revision. Nothing updates one; see the file
// note.
func (s *Store) InsertPolicyVersion(ctx context.Context, p PolicyVersion) error {
	_, err := s.exec(ctx, `
		INSERT INTO policy_versions
		  (id, project_id, version, policy_data, hash, reason, created_by, rego_source, wasm_bundle, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.ProjectID, p.Version, string(p.PolicyData), p.Hash,
		NullText(p.Reason), NullText(p.CreatedBy),
		NullText(p.RegoSource), NullText(p.WasmBundle), p.CreatedAt)
	return err
}

// SetCompiledForms attaches the Rego and WASM builds to an existing revision.
//
// This is the one update in the file and it touches only the derived columns.
// The policy itself and its hash are immutable, so a compilation landing late
// cannot change what the guard verifies.
func (s *Store) SetCompiledForms(ctx context.Context, projectID, id, rego, wasm string) error {
	_, err := s.exec(ctx, `
		UPDATE policy_versions SET rego_source = ?, wasm_bundle = ?
		WHERE id = ? AND project_id = ?`,
		NullText(rego), NullText(wasm), id, projectID)
	return err
}

// DeletePolicyVersions removes every revision of one logical policy id.
//
// The policy id is inside policy_data, so the caller resolves it to row ids
// first and passes them here; there is no json_extract in this package. Row ids
// are bound as placeholders — see TouchKeysUsed for why the list is never
// joined into the string.
func (s *Store) DeletePolicyVersions(ctx context.Context, projectID string, rowIDs []string) (int64, error) {
	if len(rowIDs) == 0 {
		return 0, nil
	}
	args := make([]any, 0, len(rowIDs)+1)
	args = append(args, projectID)
	for _, id := range rowIDs {
		args = append(args, id)
	}
	q := `DELETE FROM policy_versions WHERE project_id = ? AND id IN (` +
		placeholders(len(rowIDs)) + `)`
	res, err := s.exec(ctx, q, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

func (s *Store) policyOne(ctx context.Context, query string, args ...any) (PolicyVersion, error) {
	rows, err := s.query(ctx, query, args...)
	if err != nil {
		return PolicyVersion{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return PolicyVersion{}, err
		}
		return PolicyVersion{}, ErrNotFound
	}
	return scanPolicy(rows)
}

func scanPolicy(rows *sql.Rows) (PolicyVersion, error) {
	var p PolicyVersion
	var data, reason, createdBy, rego, wasm sql.NullString
	if err := rows.Scan(&p.ID, &p.ProjectID, &p.Version, &data, &p.Hash,
		&reason, &createdBy, &rego, &wasm, &p.CreatedAt); err != nil {
		return PolicyVersion{}, err
	}
	p.PolicyData = raw(data)
	p.Reason = text(reason)
	p.CreatedBy = text(createdBy)
	p.RegoSource = text(rego)
	p.WasmBundle = text(wasm)
	return p, nil
}

// placeholders builds `?,?,?` for an IN clause of n bound values. The COUNT is
// ours; none of the values ever touches the string.
func placeholders(n int) string {
	if n <= 0 {
		return ""
	}
	b := make([]byte, 0, n*2-1)
	for i := 0; i < n; i++ {
		if i > 0 {
			b = append(b, ',')
		}
		b = append(b, '?')
	}
	return string(b)
}

// ── per-variant compiled forms ──────────────────────────────────────────────
