package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// The `api_keys` table.
//
// This is the file the whole service's authorisation rests on: AuthLookup is
// how a bearer token becomes a project id, and every other query in this
// package trusts that project id to be the tenant boundary. It does no
// comparison of its own — see internal/apiauth, which does the constant-time
// part — because a lookup that returned "yes" would put the decision in two
// places.

// KeyIdentity is one row of the api_keys ⋈ projects join the authenticator
// needs. It carries the stored hash so the caller can compare it in constant
// time, and the project's token secret so a capability-token route does not
// have to fetch the project again.
//
// Both of those are credentials. Nothing in this package logs a KeyIdentity,
// and nothing outside internal/apiauth should hold one.
type KeyIdentity struct {
	KeyID     string
	ProjectID string
	OwnerID   string
	KeyPrefix string
	KeyHash   string
	KeyName   string
	IsLive    bool

	// UserID is who this key was issued TO, which is not the same question as
	// who owns the project it opens.
	//
	// Empty for every key minted before api_keys.user_id existed, and empty is
	// read as "acts as the owner" so nothing already paired changes. The two
	// answers only diverge for a guest: a developer working under somebody
	// else's policy holds a key on that project and is not its owner, and
	// without this column there is nothing in a request that could tell.
	UserID string

	// TokenSecret signs this project's capability tokens.
	TokenSecret string
}

// AuthLookup finds the live key with this prefix, joined to its project.
//
// The prefix is the first sixteen characters of the key and is indexed; the
// SECRET part of the key is not queried at all. That is deliberate and is the
// shape the live app has: looking a key up BY its hash would make the database
// do the comparison, and a database comparison is not constant-time, is visible
// in query logs, and turns a timing question into an index-probe question.
// The hash comes back and internal/apiauth compares it.
//
// `revoked_at IS NULL` is part of the WHERE rather than a check afterwards, so
// a revoked key cannot be distinguished from a nonexistent one by response time
// or by anything else.
//
// A prefix collision between a live and a revoked key would return at most one
// row; LIMIT 1 matches the original, which takes result[0].
func (s *Store) AuthLookup(ctx context.Context, keyPrefix string) (KeyIdentity, error) {
	var k KeyIdentity
	var isLive sql.NullInt64
	// user_id is NULL on every key issued before the column existed, which is
	// most of them, so it is scanned through a NullString rather than into the
	// field. An empty answer is a real answer here: see KeyIdentity.UserID.
	var userID sql.NullString
	err := s.queryRow(ctx, `
		SELECT k.id, k.project_id, p.owner_id, k.key_prefix, k.key_hash, k.name, k.is_live, k.user_id, p.token_secret
		FROM api_keys k
		INNER JOIN projects p ON k.project_id = p.id
		WHERE k.key_prefix = ? AND k.revoked_at IS NULL
		LIMIT 1`, keyPrefix).
		Scan(&k.KeyID, &k.ProjectID, &k.OwnerID, &k.KeyPrefix, &k.KeyHash, &k.KeyName, &isLive, &userID, &k.TokenSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return KeyIdentity{}, ErrNotFound
	}
	if err != nil {
		return KeyIdentity{}, err
	}
	k.IsLive = boolVal(isLive)
	k.UserID = userID.String
	return k, nil
}

// TouchKeysUsed stamps last_used_at on a batch of key ids.
//
// Batched because it is a write on the hot path of every authenticated request,
// and this service is polled by every installed guard on a timer. The live app
// buffers these for a minute and flushes the set; internal/apiauth does the
// same and calls this. A failure here is not an authentication failure — the
// caller puts the ids back and tries again — so nothing about it reaches the
// response.
//
// The id list is expanded into placeholders rather than joined into the SQL.
// The ids come from rows this process read, so interpolating them would be
// "safe" today and would stop being safe the first time somebody reuses the
// helper; there is no version of that trade worth making.
func (s *Store) TouchKeysUsed(ctx context.Context, ids []string, at int64) error {
	if len(ids) == 0 {
		return nil
	}
	args := make([]any, 0, len(ids)+1)
	args = append(args, at)
	for _, id := range ids {
		args = append(args, id)
	}
	q := `UPDATE api_keys SET last_used_at = ? WHERE id IN (` +
		strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",") + `)`
	_, err := s.exec(ctx, q, args...)
	return err
}

// ListAPIKeys is GET /v1/keys: the live keys of one project, oldest first.
//
// key_hash is not selected. There is no route that needs it and a column that
// is never read cannot be leaked by a handler that forgets which fields it is
// spreading into a response — which is exactly how the live app's
// `select({...})` list protects this.
func (s *Store) ListAPIKeys(ctx context.Context, projectID string) ([]APIKey, error) {
	rows, err := s.query(ctx, `
		SELECT id, project_id, key_prefix, name, is_live, last_used_at, created_at
		FROM api_keys
		WHERE project_id = ? AND revoked_at IS NULL
		ORDER BY created_at ASC`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []APIKey{}
	for rows.Next() {
		var k APIKey
		var isLive, lastUsed sql.NullInt64
		if err := rows.Scan(&k.ID, &k.ProjectID, &k.KeyPrefix, &k.Name, &isLive, &lastUsed, &k.CreatedAt); err != nil {
			return nil, err
		}
		k.IsLive = boolVal(isLive)
		k.LastUsedAt = unix(lastUsed)
		out = append(out, k)
	}
	return out, rows.Err()
}

// LiveKeyIDs is the set of unrevoked key ids for a project, which is what
// prunes the per-device guard-version map: a device is identified by the key it
// authenticated with, so revoking the key retires the device.
func (s *Store) LiveKeyIDs(ctx context.Context, projectID string) (map[string]bool, error) {
	rows, err := s.query(ctx,
		`SELECT id FROM api_keys WHERE project_id = ? AND revoked_at IS NULL`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

// CreateAPIKey stores a new key. The plaintext is the caller's to return once
// and then forget; only its hash and its prefix arrive here.
func (s *Store) CreateAPIKey(ctx context.Context, k APIKey) error {
	_, err := s.exec(ctx, `
		INSERT INTO api_keys (id, project_id, key_prefix, key_hash, name, is_live, user_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.ProjectID, k.KeyPrefix, k.KeyHash, k.Name, Bit(k.IsLive), nullString(k.UserID), k.CreatedAt)
	return err
}

// nullString writes an empty string as NULL.
//
// It matters for api_keys.user_id specifically: the column means "issued to
// nobody in particular, so act as the owner", and an empty STRING is a user id
// that matches no user and would make a key act as a person who does not exist.
func nullString(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// RevokeAPIKey retires one key, scoped to the project that owns it.
//
// The project_id in the WHERE is what makes this safe. Without it a caller
// could revoke any key in the database by id, which is a denial of service
// against another tenant with nothing but a guessed UUID.
//
// It reports whether a row changed, so a route can answer 404 for a key that is
// not this project's rather than a cheerful 200.
func (s *Store) RevokeAPIKey(ctx context.Context, projectID, keyID string, at int64) (bool, error) {
	res, err := s.exec(ctx, `
		UPDATE api_keys SET revoked_at = ?
		WHERE id = ? AND project_id = ? AND revoked_at IS NULL`, at, keyID, projectID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}

// RevokeAPIKeysNamed retires every live key of a project with a given name.
//
// The device-approve and dashboard-session flows both mint a key under a fixed
// name and expect the previous one to stop working. Doing it in one statement
// rather than select-then-update-each closes the window where two are valid.
func (s *Store) RevokeAPIKeysNamed(ctx context.Context, projectID, name string, at int64) error {
	_, err := s.exec(ctx, `
		UPDATE api_keys SET revoked_at = ?
		WHERE project_id = ? AND name = ? AND is_live = 1 AND revoked_at IS NULL`,
		at, projectID, name)
	return err
}

// RenameAPIKey is PATCH /v1/keys/{id}, project-scoped for the same reason
// RevokeAPIKey is.
func (s *Store) RenameAPIKey(ctx context.Context, projectID, keyID, name string) (bool, error) {
	res, err := s.exec(ctx,
		`UPDATE api_keys SET name = ? WHERE id = ? AND project_id = ?`, name, keyID, projectID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
