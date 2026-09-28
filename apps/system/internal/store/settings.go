package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

// The `system_settings` table.
//
// It has no project_id column. Everything per-project stored in it is
// namespaced by a key of the form `<name>:<projectId>`, and that namespacing is
// the ONLY thing keeping one tenant's self-protection flag out of another's.
//
// So the rule this file exists to enforce: a key is built from a constant in
// this package plus a project id the API key resolved to. Nothing takes a key
// from a request. The typed accessors below are the whole public surface for
// exactly that reason — expose SettingGet(key) to the route slices and the
// first `?key=` parameter that reaches it reads any project's settings, or
// writes them.

const (
	settingSelfProtection = "self_protection_enabled"
	settingSecurityLayers = "security_layers"
	settingLocalLogs      = "local_logs"
	settingLocalLogsView  = "local_logs_view"
	settingActivePolicy   = "active_policy"
	settingGuardVersions  = "guard_versions"
	settingRateLimitHist  = "ratelimit_history"
)

// scopedKey is the one place a settings key is assembled.
//
// THE KEY IS THE ONLY TENANCY. system_settings has no project_id column: what
// scopes a row to one tenant is the `<name>:<projectId>` key and nothing else.
// So a caller-supplied key must never reach this table.
//
// projectID is not sanitised and does not need to be: it came out of the
// api_keys ⋈ projects join, so it is a stored UUID rather than caller input.
// What matters is that the NAME half is a constant from the list above.
func scopedKey(name, projectID string) string { return name + ":" + projectID }

// settingTTL is how long a settings row is reused without asking again.
//
// This table is read several times per request on the busy paths and written
// rarely. One audit page load reads security_layers, ratelimit_history and both
// local-log rows; the guard's policy poll reads active_policy and
// self_protection_enabled. Each of those is a separate HTTP POST to Turso,
// because the driver sends one request per statement — so on a page whose
// database work is a millisecond, most of the wall clock is spent asking the
// same four rows whether they have changed.
//
// Five seconds, and every write through this package drops the entry, so a
// change made on this instance is visible to it immediately. What the window
// really bounds is a change made by ANOTHER instance: at worst one guard poll
// sees the previous value, which is a state this table already tolerates — the
// guard polls on thirty seconds and the note on GetSecurityLayers says the same
// thing about a failed read.
const settingTTL = 5 * time.Second

// settingRead fetches one row's value. A missing row is ("", false, nil) — an
// absent setting is the normal state for a project nobody has configured, not
// an error, and every caller below has a default for it.
//
// A miss is cached as a miss. Most projects have no row for most of these keys,
// and caching only the hits would leave exactly those projects paying the round
// trip every time.
func (s *Store) settingRead(ctx context.Context, key string) (string, bool, error) {
	if v, ok, fresh := s.settingCached(key); fresh {
		return v, ok, nil
	}
	var v string
	err := s.queryRow(ctx,
		`SELECT value FROM system_settings WHERE key = ? LIMIT 1`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		s.settingRemember(key, "", false)
		return "", false, nil
	}
	if err != nil {
		// An error is not cached: the next caller has to be able to find out
		// that the database is answering again.
		return "", false, err
	}
	s.settingRemember(key, v, true)
	return v, true, nil
}

type settingEntry struct {
	value  string
	found  bool
	loaded time.Time
}

func (s *Store) settingCached(key string) (string, bool, bool) {
	s.settingMu.RLock()
	e, ok := s.settingCache[key]
	s.settingMu.RUnlock()
	if !ok || time.Since(e.loaded) > settingTTL {
		return "", false, false
	}
	return e.value, e.found, true
}

func (s *Store) settingRemember(key, value string, found bool) {
	s.settingMu.Lock()
	if s.settingCache == nil {
		s.settingCache = map[string]settingEntry{}
	}
	// The map is one entry per (setting, project) and both halves are bounded —
	// the names are constants in this file — so it grows with the number of
	// projects this instance serves and not with traffic. The cap is a backstop
	// for an instance that has served an implausible number of them.
	if len(s.settingCache) >= settingCacheMax {
		s.settingCache = map[string]settingEntry{}
	}
	s.settingCache[key] = settingEntry{value: value, found: found, loaded: time.Now()}
	s.settingMu.Unlock()
}

// settingForget drops one key. Every write in this package calls it, so a value
// this instance changed is never read back stale from its own cache.
func (s *Store) settingForget(key string) {
	s.settingMu.Lock()
	delete(s.settingCache, key)
	s.settingMu.Unlock()
}

const settingCacheMax = 8192

// settingWrite is the upsert every setter goes through.
//
// ON CONFLICT rather than delete-then-insert: two dashboards saving at once
// would otherwise race through a window where the row does not exist and a
// concurrent guard poll reads the default — which for self-protection means
// reading "enabled" for a project that turned it off.
//
// updated_at is written because the column is NOT NULL and drizzle's
// $defaultFn only runs on the JavaScript side; an insert from here without it
// fails outright.
func (s *Store) settingWrite(ctx context.Context, key, value, description string) error {
	// Dropped BEFORE the write, not after, and dropped even when the write
	// fails. A reader that arrives mid-statement must not be handed a value
	// this instance already knows is being replaced, and a failed write may
	// still have landed.
	s.settingForget(key)
	_, err := s.exec(ctx, `
		INSERT INTO system_settings (key, value, description, updated_at)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, NullText(description), Now())
	s.settingForget(key)
	return err
}

// ── self-protection ─────────────────────────────────────────────────────────

// SelfProtectionEnabled is the flag the guard reads off /policies/active as
// `self_protection_enabled`.
//
// The default is TRUE and so is the error path. A project with no row has
// self-protection on; a database blip must not answer "off", because "off" is
// the answer that lets a hook be tampered with. The live app returns true from
// its catch block for the same reason and the error is swallowed rather than
// propagated so one unreadable setting cannot fail the whole policy poll.
func (s *Store) SelfProtectionEnabled(ctx context.Context, projectID string) bool {
	v, ok, err := s.settingRead(ctx, scopedKey(settingSelfProtection, projectID))
	if err != nil || !ok {
		return true
	}
	return v != "false" && v != "0"
}

func (s *Store) SetSelfProtectionEnabled(ctx context.Context, projectID string, enabled bool) error {
	v := "false"
	if enabled {
		v = "true"
	}
	return s.settingWrite(ctx, scopedKey(settingSelfProtection, projectID), v,
		"Self-protection (tamper guard) enabled")
}

// ── active policy override ──────────────────────────────────────────────────

// ActivePolicyNone is the sentinel stored when a project deliberately has NO
// active policy. It has to be distinguishable from "no override set", which
// means fall back to recency selection — the difference between a guard that
// enforces nothing on purpose and one that enforces the newest policy.
const ActivePolicyNone = "__none__"

// ActivePolicyOverride returns the pinned policy id, ActivePolicyNone, or "".
// Errors are swallowed to "" so an unreadable setting degrades to the default
// selection rather than to no policy at all.
func (s *Store) ActivePolicyOverride(ctx context.Context, projectID string) string {
	v, ok, err := s.settingRead(ctx, scopedKey(settingActivePolicy, projectID))
	if err != nil || !ok {
		return ""
	}
	return v
}

// SetActivePolicyOverride pins a policy, or pins "none" when policyID is empty.
func (s *Store) SetActivePolicyOverride(ctx context.Context, projectID, policyID string) error {
	value := policyID
	if value == "" {
		value = ActivePolicyNone
	}
	return s.settingWrite(ctx, scopedKey(settingActivePolicy, projectID), value,
		"Active policy override (id, or __none__ = deactivated)")
}

// ── raw scoped settings, for the route slices that own a specific key ────────

// SettingJSON reads one project-scoped setting by NAME, where the name must be
// one of the constants above. An unknown name is refused rather than passed
// through, so this cannot become the caller-supplied-key hole the file note
// warns about.
func (s *Store) SettingJSON(ctx context.Context, name, projectID string) (string, bool, error) {
	if !knownSetting(name) {
		return "", false, errors.New("store: unknown setting " + name)
	}
	return s.settingRead(ctx, scopedKey(name, projectID))
}

// SetSettingJSON is SettingJSON's write side, with the same closed set.
func (s *Store) SetSettingJSON(ctx context.Context, name, projectID, value, description string) error {
	if !knownSetting(name) {
		return errors.New("store: unknown setting " + name)
	}
	return s.settingWrite(ctx, scopedKey(name, projectID), value, description)
}

// SettingNames is the closed set. Adding a per-project setting means adding it
// here and to the constants, which is the point: the list is short enough to
// read and a new key cannot appear by accident.
var SettingNames = []string{
	settingSelfProtection, settingSecurityLayers, settingLocalLogs, settingLocalLogsView,
	settingActivePolicy, settingGuardVersions, settingRateLimitHist,
}

func knownSetting(name string) bool {
	name = strings.TrimSpace(name)
	for _, n := range SettingNames {
		if n == name {
			return true
		}
	}
	return false
}

// The setting names, exported so a route slice names one rather than spelling
// the string. The value shapes belong to whichever slice owns the endpoint.
const SettingGuardVersions = settingGuardVersions
