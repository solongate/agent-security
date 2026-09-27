package main

// POST /api/v1/projects/{id}/key — a key for another of your own workspaces.
//
// THE CLI HAD NO WORKSPACES AT ALL. A machine pairs once, is handed a key for
// one project, and that is the only workspace it can ever see: the dataroom
// lists policies, the fleet, the audit and the settings of whichever project the
// pairing happened to land on, with no way to say "the other one". Somebody with
// two workspaces had to unpair and pair again to look at the second, and the
// guard on that machine moved with them whether they meant it or not.
//
// The dashboard has the same problem solved a different way: it holds a Supabase
// session, so it can ask /auth/session for a key for any project it owns. A CLI
// has no session - it has a key - so this is the equivalent for a caller that
// only ever holds one.
//
// The rule is narrower than the rest of projects.go on purpose. Those routes
// scope to the key's project's OWNER, so a guest holding a key for somebody
// else's project can read and rename that owner's other projects. Reading is one
// thing; minting a live credential for a workspace is another, so this asks that
// the ACTING USER own the target - a guest gets the same answer as a stranger.

import (
	"errors"
	"net/http"
	"strings"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

func init() {
	Register("POST /api/v1/projects/{id}/key", func(s *server) http.Handler {
		return s.auth.WithAuth(s.mintProjectKey)
	})
}

func (s *server) mintProjectKey(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	id := strings.TrimSpace(r.PathValue("id"))
	if id == "" {
		apiauth.BadRequest(w, "Missing required field: id")
		return
	}

	project, err := s.store.ProjectSummaryByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		projectNotFound(w)
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	// A workspace somebody else owns is answered exactly as one that does not
	// exist, which is what stops this from being a way to test whether a project
	// id is real.
	if project.OwnerID == "" || project.OwnerID != key.ActingUser() {
		projectNotFound(w)
		return
	}

	// The same revoke-then-mint the two pairing flows do, under the same name,
	// so a machine that switches workspaces twice does not leave a live key
	// behind in each one it has visited.
	if err := s.store.RevokeAPIKeysNamed(r.Context(), project.ID, authCLIKeyName, store.Now()); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	liveKey, _, err := s.authMintKey(r.Context(), project.ID, key.ActingUser(), authCLIKeyName)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// The shape /auth/session answers with, so a CLI that already knows how to
	// read a sign-in can read this without learning a second one.
	apiauth.JSON(w, http.StatusOK, map[string]any{
		"api_key": liveKey,
		"project": map[string]any{"id": project.ID, "name": project.Name},
	})
}
