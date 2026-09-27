package store

import "context"

// The read behind GET /v1/policies/{id}/wasm.
//
// It lives in its own file rather than next to LatestCompiledRego because the
// two answer different questions and one is on a machine's path: the guard hook
// downloads this bundle and evaluates it, so serving the wrong revision is a
// laptop enforcing a policy nobody wrote.

// LatestCompiledWasm is the newest revision of one logical policy that HAS a
// WASM build.
//
// Not the newest revision — the newest COMPILED one. A version saved while the
// compiler was unavailable has a NULL wasm_bundle, and treating that as "this
// policy has no bundle" would throw away a working build one version back and
// send the guard to on-demand compilation for a policy that is already built.
// ErrNotFound means nothing in this policy's history is compiled, which is the
// route's cue to build it now.
//
// The project clause is not redundant with the id. The `{id}` in the path is a
// policy id a caller supplies, and without the scope any valid key plus an id
// out of a screenshot would fetch another tenant's compiled rules — which is
// their command denylist, their path globs and their internal hostnames, in a
// form that runs.
func (s *Store) LatestCompiledWasm(ctx context.Context, projectID, policyID string) (PolicyVersion, error) {
	where, args := s.scopeByID(projectID, policyID)
	return s.policyOne(ctx, `SELECT `+policyColumns+` FROM policy_versions WHERE `+where+
		` AND wasm_bundle IS NOT NULL ORDER BY version DESC LIMIT 1`, args...)
}
