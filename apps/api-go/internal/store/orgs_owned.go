package store

import "context"

// One query the organisation routes need that orgs.go does not have.
//
// GET /v1/orgs is the union of the organisations a user OWNS and the ones they
// are a MEMBER of, and those are two different tables. OrgsForUser answers the
// second half; this answers the first. They overlap for almost every row —
// creating an organisation writes both — but not for all of them, and the gap
// is not hypothetical: the live DELETE on /v1/orgs/{id}/members removes a
// membership row by id with no owner check, so a database that has been running
// this long can hold an organisation whose owner has no membership. Listing by
// membership alone would make that organisation disappear from its owner's
// list, and the owner is the only person who can delete it.
func (s *Store) OrgsOwnedBy(ctx context.Context, ownerID string) ([]Organization, error) {
	rows, err := s.query(ctx, `
		SELECT id, name, slug, owner_id, created_at, updated_at
		FROM organizations WHERE owner_id = ?
		ORDER BY created_at DESC`, ownerID)
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
