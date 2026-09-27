package store

import (
	"context"
	"database/sql"
	"errors"
)

// The `device_codes` table: the CLI's device-authorisation flow.
//
// Two things about it are unlike everything else in this package.
//
// The timestamps are MILLISECONDS. src/db/index.ts creates the table by hand
// and the routes write Date.now(); storing seconds here would make every code
// look decades expired the moment it was issued. NowMS is the clock for this
// file and nothing else uses it.
//
// And the api_key column holds a LIVE project key in plaintext, from the moment
// the browser approves the pairing until the CLI's next poll collects it. That
// window is the design of the flow — there is nowhere else to put a value the
// CLI has not asked for yet — and everything here is arranged to keep it short:
// ClaimDeviceCode reads and clears it in one statement, so a replayed poll gets
// nothing, and no function in this package returns the column in a list.

// DeviceCodeStatus is the pending row check behind GET /v1/auth/device/check.
type DeviceCodeStatus struct {
	Status      string
	ExpiresAtMS int64
}

// StartDeviceCode issues a pending pairing.
func (s *Store) StartDeviceCode(ctx context.Context, deviceCode, userCode string, createdMS, expiresMS int64) error {
	_, err := s.exec(ctx, `
		INSERT INTO device_codes (device_code, user_code, status, created_at, expires_at)
		VALUES (?, ?, 'pending', ?, ?)`, deviceCode, userCode, createdMS, expiresMS)
	return err
}

// DeviceCodeByUserCode is the browser's side: the short code a person typed.
func (s *Store) DeviceCodeByUserCode(ctx context.Context, userCode string) (DeviceCode, error) {
	var d DeviceCode
	var apiKey, projectID, projectName, email, name sql.NullString
	err := s.queryRow(ctx, `
		SELECT device_code, user_code, status, api_key, project_id, project_name,
		       user_email, user_name, created_at, expires_at
		FROM device_codes WHERE user_code = ? LIMIT 1`, userCode).
		Scan(&d.DeviceCode, &d.UserCode, &d.Status, &apiKey, &projectID, &projectName,
			&email, &name, &d.CreatedAtMS, &d.ExpiresAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceCode{}, ErrNotFound
	}
	if err != nil {
		return DeviceCode{}, err
	}
	d.APIKey = text(apiKey)
	d.ProjectID = text(projectID)
	d.ProjectName = text(projectName)
	d.UserEmail = text(email)
	d.UserName = text(name)
	return d, nil
}

// DeviceCodeStatusByUserCode answers the polling check without touching the
// key column at all. The check endpoint is unauthenticated and rate-limited by
// IP; there is no reason for a key to be in the query plan, let alone in a row
// this returns.
func (s *Store) DeviceCodeStatusByUserCode(ctx context.Context, userCode string) (DeviceCodeStatus, error) {
	var st DeviceCodeStatus
	err := s.queryRow(ctx,
		`SELECT status, expires_at FROM device_codes WHERE user_code = ? LIMIT 1`, userCode).
		Scan(&st.Status, &st.ExpiresAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceCodeStatus{}, ErrNotFound
	}
	return st, err
}

// ApproveDeviceCode attaches a freshly minted key to a pending pairing.
//
// `AND status = 'pending'` is in the WHERE, not checked beforehand. Two browser
// tabs approving the same code would otherwise both mint a key and the second
// would overwrite the first — leaving a live key nobody will ever collect and
// nobody knows to revoke. Only one UPDATE can match.
func (s *Store) ApproveDeviceCode(ctx context.Context, userCode, apiKey, projectID, projectName, email, name string) (bool, error) {
	res, err := s.exec(ctx, `
		UPDATE device_codes
		SET status = 'approved', api_key = ?, project_id = ?, project_name = ?,
		    user_email = ?, user_name = ?
		WHERE user_code = ? AND status = 'pending'`,
		apiKey, projectID, projectName, email, name, userCode)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// ClaimDeviceCode is the CLI's poll: it hands back the key exactly once.
//
// The claim is the UPDATE, not a preceding SELECT. `status = 'approved'` in the
// WHERE means only one of two racing polls can match; the loser gets no row.
// The live app does SELECT then UPDATE and both polls receive the key through
// that gap — which is one pairing handing a live project credential to two
// machines, and only one of them is the person who approved it.
//
// The status change and the key are one statement because RETURNING reports
// the values AFTER the update in SQLite: clearing api_key here would return
// NULL. So the column is left alone by this statement and blanked by the next
// one. If that second statement fails the row is still `consumed` and
// unclaimable, so the worst case is a spent key sitting in a row nobody can
// reach rather than a key that can be collected twice.
//
// (found=false) means: no such code, not approved yet, or already claimed. The
// caller cannot tell those apart, which matches the existing contract — an
// unapproved code and a consumed one both answer `pending`.
func (s *Store) ClaimDeviceCode(ctx context.Context, deviceCode string) (DeviceCode, bool, error) {
	var d DeviceCode
	var apiKey, projectID, projectName, email, name sql.NullString
	err := s.queryRow(ctx, `
		UPDATE device_codes SET status = 'consumed'
		WHERE device_code = ? AND status = 'approved' AND api_key IS NOT NULL
		RETURNING device_code, user_code, api_key, project_id, project_name,
		          user_email, user_name, created_at, expires_at`, deviceCode).
		Scan(&d.DeviceCode, &d.UserCode, &apiKey, &projectID, &projectName,
			&email, &name, &d.CreatedAtMS, &d.ExpiresAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceCode{}, false, nil
	}
	if err != nil {
		return DeviceCode{}, false, err
	}

	// Best effort, and deliberately not fatal: the row is already consumed.
	_, _ = s.exec(ctx,
		`UPDATE device_codes SET api_key = NULL WHERE device_code = ?`, deviceCode)

	d.Status = "approved"
	d.APIKey = text(apiKey)
	d.ProjectID = text(projectID)
	d.ProjectName = text(projectName)
	d.UserEmail = text(email)
	d.UserName = text(name)
	return d, true, nil
}

// PollDeviceCode is the status-only read the poll route needs before deciding
// between not_found, expired, pending and approved. It does not select api_key.
func (s *Store) PollDeviceCode(ctx context.Context, deviceCode string) (DeviceCodeStatus, error) {
	var st DeviceCodeStatus
	err := s.queryRow(ctx,
		`SELECT status, expires_at FROM device_codes WHERE device_code = ? LIMIT 1`, deviceCode).
		Scan(&st.Status, &st.ExpiresAtMS)
	if errors.Is(err, sql.ErrNoRows) {
		return DeviceCodeStatus{}, ErrNotFound
	}
	return st, err
}

// PurgeExpiredDeviceCodes drops pairings nobody completed.
//
// The live app has no such sweep, so rows accumulate forever — including
// approved ones that were never collected, each holding a live key in
// plaintext. This is a divergence and it is the safe direction: a code past its
// expiry is unusable by the CLI already, so deleting it removes only a stored
// credential nobody can spend.
func (s *Store) PurgeExpiredDeviceCodes(ctx context.Context, beforeMS int64) (int64, error) {
	res, err := s.exec(ctx,
		`DELETE FROM device_codes WHERE expires_at < ?`, beforeMS)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
