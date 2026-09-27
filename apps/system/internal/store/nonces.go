package store

import (
	"context"
)

// ── used_nonces ─────────────────────────────────────────────────────────────

// SpendNonce records a capability token's nonce and reports whether it was
// already spent.
//
// The INSERT is the check. The live app does SELECT-then-INSERT, and two
// presentations of one token arriving together both find no row and both
// succeed — which is precisely the replay the table exists to stop. Here the
// primary key refuses the second, and `ON CONFLICT DO NOTHING` turns that
// refusal into a row count rather than an error to interpret.
func (s *Store) SpendNonce(ctx context.Context, nonce, projectID string) (bool, error) {
	res, err := s.exec(ctx, `
		INSERT INTO used_nonces (nonce, project_id, used_at) VALUES (?, ?, ?)
		ON CONFLICT(nonce) DO NOTHING`, nonce, projectID, Now())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// PurgeNonces drops spent nonces older than a cutoff. Tokens live thirty
// seconds, so anything past twice that can never be presented again and the row
// is only taking space.
func (s *Store) PurgeNonces(ctx context.Context, before int64) (int64, error) {
	res, err := s.exec(ctx, `DELETE FROM used_nonces WHERE used_at < ?`, before)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
