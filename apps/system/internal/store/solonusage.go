package store

import (
	"context"
	"database/sql"
	"errors"
)

// The `solon_usage` table and the `used_nonces` table: the two quota-shaped
// things in this database.
//
// solon_usage is keyed by USER, not by project, so a person cannot reset their
// AI allowance by making a new project. used_nonces is keyed by the nonce
// itself, which is what makes a replayed capability token fail on the primary
// key rather than on a check.

// The Solon AI limits, from src/lib/solon-usage.ts. They are constants rather
// than settings on purpose: a per-project override would be a row somebody can
// write, and the whole point of a quota is that its holder cannot raise it.
const (
	SolonChatLimit   = 5
	SolonPolicyLimit = 2
	SolonLockMessage = "You've reached your Solon AI usage limit."
)

// SolonUsageState is what /v1/ai/usage returns and what every AI route checks
// before doing work.
type SolonUsageState struct {
	ChatsUsed    int64 `json:"chatsUsed"`
	PoliciesUsed int64 `json:"policiesUsed"`
	ChatLimit    int64 `json:"chatLimit"`
	PolicyLimit  int64 `json:"policyLimit"`
	Locked       bool  `json:"locked"`
}

func solonState(chats, policies int64) SolonUsageState {
	return SolonUsageState{
		ChatsUsed:    chats,
		PoliciesUsed: policies,
		ChatLimit:    SolonChatLimit,
		PolicyLimit:  SolonPolicyLimit,
		// Either counter alone locks the whole feature, which is the original's
		// rule and not an obvious one: running out of policy generations stops
		// chat too.
		Locked: chats >= SolonChatLimit || policies >= SolonPolicyLimit,
	}
}

// SolonUsageFor reads a user's counters. A missing row is zero used, not an
// error: nobody has a row until their first request.
func (s *Store) SolonUsageFor(ctx context.Context, userID string) (SolonUsageState, error) {
	var chats, policies int64
	err := s.queryRow(ctx,
		`SELECT chats_used, policies_used FROM solon_usage WHERE user_id = ? LIMIT 1`, userID).
		Scan(&chats, &policies)
	if errors.Is(err, sql.ErrNoRows) {
		return solonState(0, 0), nil
	}
	if err != nil {
		return SolonUsageState{}, err
	}
	return solonState(chats, policies), nil
}

// IncrementSolonChat spends one chat and returns the state after spending.
//
// It is an upsert that increments in the same statement rather than
// ensure-row-then-update. Two requests from one user arriving together would
// otherwise both read 4, both write 5, and the fifth chat would be free — a
// quota that leaks under exactly the load it exists to bound.
func (s *Store) IncrementSolonChat(ctx context.Context, userID string) (SolonUsageState, error) {
	return s.bumpSolon(ctx, userID, 1, 0)
}

// IncrementSolonPolicy spends `by` policy generations. `by` is a count this
// service computed, never a number from a request body.
func (s *Store) IncrementSolonPolicy(ctx context.Context, userID string, by int64) (SolonUsageState, error) {
	if by <= 0 {
		by = 1
	}
	return s.bumpSolon(ctx, userID, 0, by)
}

func (s *Store) bumpSolon(ctx context.Context, userID string, chats, policies int64) (SolonUsageState, error) {
	_, err := s.exec(ctx, `
		INSERT INTO solon_usage (user_id, chats_used, policies_used, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(user_id) DO UPDATE SET
		  chats_used = solon_usage.chats_used + ?,
		  policies_used = solon_usage.policies_used + ?,
		  updated_at = excluded.updated_at`,
		userID, chats, policies, Now(), chats, policies)
	if err != nil {
		return SolonUsageState{}, err
	}
	return s.SolonUsageFor(ctx, userID)
}

// ResetSolonUsage is POST /v1/ai/usage/reset.
func (s *Store) ResetSolonUsage(ctx context.Context, userID string) (SolonUsageState, error) {
	_, err := s.exec(ctx, `
		INSERT INTO solon_usage (user_id, chats_used, policies_used, updated_at)
		VALUES (?, 0, 0, ?)
		ON CONFLICT(user_id) DO UPDATE SET chats_used = 0, policies_used = 0, updated_at = excluded.updated_at`,
		userID, Now())
	if err != nil {
		return SolonUsageState{}, err
	}
	return solonState(0, 0), nil
}

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
