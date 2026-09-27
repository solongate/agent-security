package store

import (
	"context"
	"database/sql"
	"errors"
)

// The `organizations` and `org_members` tables.
//
// Membership is the authorisation boundary here and it is not the same one the
// rest of the service uses: an API key resolves to a PROJECT, and an
// organisation is a level above that. So every function below takes the user id
// the key's project resolved to, and none of them takes an organisation id
// without also asking who is holding it — /v1/orgs/{id} with only an id would
// let any valid key read any organisation's member list, addresses included.

func (s *Store) OrgByID(ctx context.Context, id string) (Organization, error) {
	var o Organization
	err := s.queryRow(ctx, `
		SELECT id, name, slug, owner_id, created_at, updated_at
		FROM organizations WHERE id = ? LIMIT 1`, id).
		Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Organization{}, ErrNotFound
	}
	return o, err
}

// OrgsForUser lists the organisations a user belongs to, by membership rather
// than by ownership — an admin who does not own the org still sees it.
func (s *Store) OrgsForUser(ctx context.Context, userID string) ([]Organization, error) {
	rows, err := s.query(ctx, `
		SELECT o.id, o.name, o.slug, o.owner_id, o.created_at, o.updated_at
		FROM organizations o
		INNER JOIN org_members m ON m.org_id = o.id
		WHERE m.user_id = ?
		ORDER BY o.created_at DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Organization{}
	for rows.Next() {
		var o Organization
		if err := rows.Scan(&o.ID, &o.Name, &o.Slug, &o.OwnerID, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// OrgRoleOf is the authorisation question: what is this user to this
// organisation, if anything. ErrNotFound means "not a member", which is the
// answer a route turns into 403 or 404.
func (s *Store) OrgRoleOf(ctx context.Context, orgID, userID string) (string, error) {
	var role string
	err := s.queryRow(ctx,
		`SELECT role FROM org_members WHERE org_id = ? AND user_id = ? LIMIT 1`, orgID, userID).
		Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return role, err
}

// OrgMemberRow is a member joined to the account behind it, which is what the
// members list shows.
type OrgMemberRow struct {
	OrgMember
	Email string
	Name  string
}

// ListOrgMembers is GET /v1/orgs/{id}/members. The caller must have checked
// OrgRoleOf first: this returns email addresses.
func (s *Store) ListOrgMembers(ctx context.Context, orgID string) ([]OrgMemberRow, error) {
	rows, err := s.query(ctx, `
		SELECT m.id, m.org_id, m.user_id, m.role, m.created_at, m.updated_at, u.email, u.name
		FROM org_members m
		INNER JOIN users u ON u.id = m.user_id
		WHERE m.org_id = ?
		ORDER BY m.created_at ASC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OrgMemberRow{}
	for rows.Next() {
		var m OrgMemberRow
		var name sql.NullString
		if err := rows.Scan(&m.ID, &m.OrgID, &m.UserID, &m.Role, &m.CreatedAt, &m.UpdatedAt,
			&m.Email, &name); err != nil {
			return nil, err
		}
		m.Name = text(name)
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) CreateOrg(ctx context.Context, o Organization, firstMemberID string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := s.txExec(ctx, tx, `
		INSERT INTO organizations (id, name, slug, owner_id, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		o.ID, o.Name, o.Slug, o.OwnerID, o.CreatedAt, o.UpdatedAt); err != nil {
		return err
	}
	// The owner is inserted as a member in the same transaction. An
	// organisation whose owner is not a member is one nobody can administer:
	// every other route checks membership, not ownership.
	if _, err := s.txExec(ctx, tx, `
		INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
		VALUES (?, ?, ?, 'owner', ?, ?)`,
		firstMemberID, o.ID, o.OwnerID, o.CreatedAt, o.UpdatedAt); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) UpdateOrg(ctx context.Context, orgID, ownerID, name string, at int64) (bool, error) {
	res, err := s.exec(ctx,
		`UPDATE organizations SET name = ?, updated_at = ? WHERE id = ? AND owner_id = ?`,
		name, at, orgID, ownerID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

func (s *Store) DeleteOrg(ctx context.Context, orgID, ownerID string) (bool, error) {
	res, err := s.exec(ctx,
		`DELETE FROM organizations WHERE id = ? AND owner_id = ?`, orgID, ownerID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// AddOrgMember adds a user with a role from the closed set. An unknown role
// becomes `member`: the column is plain TEXT and would store anything, and a
// role nothing recognises is a member who cannot be reasoned about.
func (s *Store) AddOrgMember(ctx context.Context, m OrgMember) error {
	if !OneOf(m.Role, OrgRoles) {
		m.Role = "member"
	}
	_, err := s.exec(ctx, `
		INSERT INTO org_members (id, org_id, user_id, role, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		m.ID, m.OrgID, m.UserID, m.Role, m.CreatedAt, m.UpdatedAt)
	return err
}

// RemoveOrgMember removes one membership.
//
// It refuses to remove the organisation's owner. The database has no such
// constraint, and an org with no owner cannot be administered or deleted by
// anyone — a state that is easy to reach by accident from a member list and
// impossible to leave.
func (s *Store) RemoveOrgMember(ctx context.Context, orgID, userID string) (bool, error) {
	res, err := s.exec(ctx, `
		DELETE FROM org_members
		WHERE org_id = ? AND user_id = ?
		  AND user_id <> (SELECT owner_id FROM organizations WHERE id = ?)`,
		orgID, userID, orgID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
