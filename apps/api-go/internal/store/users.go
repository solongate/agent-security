package store

import (
	"context"
	"database/sql"
	"errors"
)

// The `users` table.
//
// Accounts arrive three ways — /v1/setup, /v1/auth register, and the Supabase
// handshake in /v1/auth/session — and only the second sets a password hash. A
// row with no hash is not a broken account; it is an account that signs in
// somewhere else, which is why UserByEmail returns the column rather than a
// boolean.

// UserByEmail resolves an address to a row.
//
// The address is bound and matched exactly, NOT lowercased here. The callers
// lowercase before calling (both /v1/auth/session and device/approve do
// `.trim().toLowerCase()`), and /v1/auth and /v1/setup do not — so lowercasing
// inside this function would make this binary find rows the live app does not,
// on exactly the addresses that were stored with capitals.
func (s *Store) UserByEmail(ctx context.Context, email string) (User, error) {
	var u User
	var name, hash sql.NullString
	err := s.queryRow(ctx, `
		SELECT id, email, name, password_hash, created_at, updated_at
		FROM users WHERE email = ? LIMIT 1`, email).
		Scan(&u.ID, &u.Email, &name, &hash, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.Name = text(name)
	u.PasswordHash = text(hash)
	return u, nil
}

// UserByID is what /v1/auth/me uses to describe a project's owner.
func (s *Store) UserByID(ctx context.Context, id string) (User, error) {
	var u User
	var name, hash sql.NullString
	err := s.queryRow(ctx, `
		SELECT id, email, name, password_hash, created_at, updated_at
		FROM users WHERE id = ? LIMIT 1`, id).
		Scan(&u.ID, &u.Email, &name, &hash, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	u.Name = text(name)
	u.PasswordHash = text(hash)
	return u, nil
}

// CreateUser inserts an account. PasswordHash empty writes NULL, which is what
// distinguishes a Supabase or setup account from one that can log in with a
// password — see the NO_PASSWORD branch in /v1/auth.
func (s *Store) CreateUser(ctx context.Context, u User) error {
	_, err := s.exec(ctx, `
		INSERT INTO users (id, email, name, password_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		u.ID, u.Email, NullText(u.Name), NullText(u.PasswordHash), u.CreatedAt, u.UpdatedAt)
	return err
}

// UpdateUserProfile is PUT /v1/auth/profile. Only the display name is
// writable; the address is the identity Supabase vouches for and changing it
// here would let a project owner point their account at somebody else's.
func (s *Store) UpdateUserProfile(ctx context.Context, id, name string, at int64) (bool, error) {
	res, err := s.exec(ctx,
		`UPDATE users SET name = ?, updated_at = ? WHERE id = ?`, NullText(name), at, id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n > 0, err
}
