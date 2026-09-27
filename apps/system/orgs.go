package main

// GET and POST /v1/orgs, GET, PUT and DELETE /v1/orgs/{id}, GET, POST and
// DELETE /v1/orgs/{id}/members.
//
// AUTHORISATION is the whole subject of this file, because an organisation is
// the one thing in this service that an API key does NOT resolve to. A key
// names a project; a project names an owner; and it is that owner's membership
// that decides which organisation they may read. The organisation id comes from
// the URL, so it is caller input in every route here — an endpoint that acts on
// it without asking what the caller is to that organisation is a cross-tenant
// read of a member list, addresses included.
//
// Every handler therefore starts the same way: resolve the key to the owner,
// then ask store.OrgRoleOf. The one route where the live app skips that step is
// GET /v1/orgs/{id}/members, and it is not skipped here — see orgMembersList.

import (
	"errors"
	"net/http"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

func init() {
	Register("GET /api/v1/orgs", func(s *server) http.Handler { return s.auth.WithAuth(s.orgsList) })
	Register("POST /api/v1/orgs", func(s *server) http.Handler { return s.auth.WithAuth(s.orgsCreate) })
	Register("GET /api/v1/orgs/{id}", func(s *server) http.Handler { return s.auth.WithAuth(s.orgGet) })
	Register("PUT /api/v1/orgs/{id}", func(s *server) http.Handler { return s.auth.WithAuth(s.orgUpdate) })
	Register("DELETE /api/v1/orgs/{id}", func(s *server) http.Handler { return s.auth.WithAuth(s.orgDelete) })
	Register("GET /api/v1/orgs/{id}/members", func(s *server) http.Handler { return s.auth.WithAuth(s.orgMembersList) })
	Register("POST /api/v1/orgs/{id}/members", func(s *server) http.Handler { return s.auth.WithAuth(s.orgMembersAdd) })
	Register("DELETE /api/v1/orgs/{id}/members", func(s *server) http.Handler { return s.auth.WithAuth(s.orgMembersRemove) })
}

const (
	orgMaxNameLen = 50
	orgMaxSlugLen = 100

	// orgNotAuthorized is one message for "no such organisation" and "not
	// yours", and the live app writes it that way on purpose: telling the two
	// apart turns any valid key into a probe for which organisation ids exist.
	orgNotAuthorized = "Organization not found or not authorized"

	orgNotAMember = "You must be a member of this organization"
)

// orgJSON is drizzle's `select().from(organizations)`: the whole row, in its
// schema order, with the two timestamps as ISO strings.
type orgJSON struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Slug      string `json:"slug"`
	OwnerID   string `json:"ownerId"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

func orgJSONOf(o store.Organization) orgJSON {
	return orgJSON{
		ID: o.ID, Name: o.Name, Slug: o.Slug, OwnerID: o.OwnerID,
		CreatedAt: store.ISO(o.CreatedAt), UpdatedAt: store.ISO(o.UpdatedAt),
	}
}

// orgMemberJSON is `select().from(orgMembers)`, which GET /v1/orgs/{id}
// returns whole.
type orgMemberJSON struct {
	ID        string `json:"id"`
	OrgID     string `json:"orgId"`
	UserID    string `json:"userId"`
	Role      string `json:"role"`
	CreatedAt string `json:"createdAt"`
	UpdatedAt string `json:"updatedAt"`
}

// Every handler here opens with authProjectOwner (auth.go): the key names a
// project, the project names a user, and that user is who the membership
// questions below are about. The owner id is never read from the request.

// orgMemberOrOwner is the read gate: a member of the organisation, or the
// person who owns it.
//
// Ownership counts separately from membership because the two are separate
// tables and can disagree. The live DELETE on the members route removes a
// membership row by id with no owner check, so an owner who has been removed
// from their own member list still has to be able to read it — otherwise the
// organisation becomes unadministrable by anybody.
//
// It returns false with the response already written.
func (s *server) orgMemberOrOwner(w http.ResponseWriter, r *http.Request, orgID, userID string, refusal string) bool {
	if _, err := s.store.OrgRoleOf(r.Context(), orgID, userID); err == nil {
		return true
	} else if !errors.Is(err, store.ErrNotFound) {
		apiauth.Internal(w, "api", err)
		return false
	}

	org, err := s.store.OrgByID(r.Context(), orgID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusForbidden, refusal)
			return false
		}
		apiauth.Internal(w, "api", err)
		return false
	}
	if org.OwnerID != userID {
		authBadRequest(w, http.StatusForbidden, refusal)
		return false
	}
	return true
}

// orgsList is the union of the organisations the caller owns and the ones they
// belong to, owned first, without duplicates.
func (s *server) orgsList(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()

	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}

	owned, err := s.store.OrgsOwnedBy(ctx, userID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	member, err := s.store.OrgsForUser(ctx, userID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	seen := make(map[string]bool, len(owned))
	out := make([]orgJSON, 0, len(owned)+len(member))
	for _, o := range owned {
		seen[o.ID] = true
		out = append(out, orgJSONOf(o))
	}
	for _, o := range member {
		if !seen[o.ID] {
			out = append(out, orgJSONOf(o))
		}
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{"organizations": out})
}

// orgsCreate makes an organisation and puts its owner in it.
//
// The membership row is written in the same transaction as the organisation.
// An organisation whose owner is not a member is one nobody can administer,
// because every other route here checks membership.
func (s *server) orgsCreate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()

	var body map[string]any
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}
	raw, present := body["name"]
	if !present || !authJSTruthy(raw) {
		apiauth.BadRequest(w, "Missing required field: name")
		return
	}
	name := authJSString(raw)
	if n := authUTF16Len(name); n < 2 || n > orgMaxNameLen {
		apiauth.BadRequest(w, "Organization name must be 2-50 characters")
		return
	}

	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}

	orgID, memberID, slugSuffix := authNewID(), authNewID(), authNewID()
	if orgID == "" || memberID == "" || slugSuffix == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}

	now := store.Now()
	org := store.Organization{
		ID:      orgID,
		Name:    store.Clip(name, orgMaxNameLen),
		Slug:    store.Clip(authSlugify(name)+"-"+slugSuffix[:8], orgMaxSlugLen),
		OwnerID: userID, CreatedAt: now, UpdatedAt: now,
	}
	if err := s.store.CreateOrg(ctx, org, memberID); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusCreated, map[string]any{"organization": orgJSONOf(org)})
}

// orgGet returns the organisation and its members, to a member or the owner.
func (s *server) orgGet(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	orgID := r.PathValue("id")

	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}

	org, err := s.store.OrgByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusNotFound, "Organization not found")
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}
	if !s.orgMemberOrOwner(w, r, orgID, userID, orgNotAuthorized) {
		return
	}

	members, err := s.store.ListOrgMembers(ctx, orgID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	rows := make([]orgMemberJSON, 0, len(members))
	for _, m := range members {
		rows = append(rows, orgMemberJSON{
			ID: m.ID, OrgID: m.OrgID, UserID: m.UserID, Role: m.Role,
			CreatedAt: store.ISO(m.CreatedAt), UpdatedAt: store.ISO(m.UpdatedAt),
		})
	}

	apiauth.JSON(w, http.StatusOK, map[string]any{
		"organization": orgJSONOf(org),
		"members":      rows,
	})
}

// orgUpdate renames an organisation. OWNER only, not any member: the live route
// matches on `id AND ownerId` and a member who could rename the organisation
// out from under its owner is not a member, it is a co-owner.
func (s *server) orgUpdate(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	orgID := r.PathValue("id")

	var body map[string]any
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}

	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}

	org, err := s.store.OrgByID(ctx, orgID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusForbidden, orgNotAuthorized)
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}
	if org.OwnerID != userID {
		authBadRequest(w, http.StatusForbidden, orgNotAuthorized)
		return
	}

	// `if (body.name) updates.name = …`: an absent or falsy name leaves the
	// name alone and still stamps updated_at, which is what the original's
	// unconditional `updatedAt` does.
	name := org.Name
	if raw, present := body["name"]; present && authJSTruthy(raw) {
		name = store.Clip(authJSString(raw), orgMaxNameLen)
	}

	now := store.Now()
	if _, err := s.store.UpdateOrg(ctx, orgID, userID, name, now); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	org.Name, org.UpdatedAt = name, now
	apiauth.JSON(w, http.StatusOK, map[string]any{"organization": orgJSONOf(org)})
}

// orgDelete removes an organisation, owner only.
//
// The ownership check is the DELETE's own WHERE rather than a SELECT before it,
// so there is no window in which ownership changes between the two. A statement
// that changed nothing means either "no such organisation" or "not yours", and
// both answer the same 403 — the live route's behaviour and the right one.
func (s *server) orgDelete(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}
	deleted, err := s.store.DeleteOrg(r.Context(), r.PathValue("id"), userID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !deleted {
		authBadRequest(w, http.StatusForbidden, orgNotAuthorized)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// orgMembersList returns the member list with the accounts behind it.
//
// THIS ROUTE HAS A MEMBERSHIP CHECK AND THE LIVE ONE DOES NOT. The deployed
// handler takes the organisation id straight out of the URL and lists it for
// any valid API key, so today every holder of any key can read the email
// address and display name of every member of every organisation in the
// database by iterating ids. That is a cross-tenant leak of personal data, the
// two sibling routes in the same file already refuse exactly this, and the
// wording below is theirs.
//
// The cost of the divergence is that a caller who was reading another tenant's
// members now gets 403 — which is the entire point — and that a request for an
// organisation that does not exist answers 403 instead of an empty list.
func (s *server) orgMembersList(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	orgID := r.PathValue("id")

	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}
	if !s.orgMemberOrOwner(w, r, orgID, userID, orgNotAMember) {
		return
	}

	members, err := s.store.ListOrgMembers(ctx, orgID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	type row struct {
		ID        string `json:"id"`
		UserID    string `json:"userId"`
		CreatedAt string `json:"createdAt"`
		Email     string `json:"email"`
		Name      any    `json:"name"`
	}
	rows := make([]row, 0, len(members))
	for _, m := range members {
		rows = append(rows, row{
			ID: m.ID, UserID: m.UserID, CreatedAt: store.ISO(m.CreatedAt),
			Email: m.Email, Name: authNullable(m.Name),
		})
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"members": rows})
}

// orgMembersAdd invites an existing account into the organisation, by address.
//
// The caller must already be a member. The target must already have an account:
// this route does not create one, so it cannot be used to discover whether an
// arbitrary address is registered without first being a member of something.
func (s *server) orgMembersAdd(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	orgID := r.PathValue("id")

	var body map[string]any
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}
	raw, present := body["email"]
	if !present || !authJSTruthy(raw) {
		apiauth.BadRequest(w, "Missing required field: email")
		return
	}
	// Matched exactly, not lowercased. The live route passes body.email through
	// untouched, and lowercasing here would find rows it does not — on exactly
	// the addresses that were stored with capitals.
	email := authJSString(raw)

	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}
	if !s.orgMemberOrOwner(w, r, orgID, userID, orgNotAMember) {
		return
	}

	target, err := s.store.UserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			authBadRequest(w, http.StatusNotFound, "User not found with this email")
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}

	if _, err := s.store.OrgRoleOf(ctx, orgID, target.ID); err == nil {
		authBadRequest(w, http.StatusConflict, "User is already a member")
		return
	} else if !errors.Is(err, store.ErrNotFound) {
		apiauth.Internal(w, "api", err)
		return
	}

	memberID := authNewID()
	if memberID == "" {
		apiauth.Internal(w, "api", authErrNoID)
		return
	}
	now := store.Now()
	if err := s.store.AddOrgMember(ctx, store.OrgMember{
		ID: memberID, OrgID: orgID, UserID: target.ID, Role: "member",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusCreated, map[string]any{
		"member": map[string]any{
			"id":     memberID,
			"userId": target.ID,
			"email":  target.Email,
			"name":   authNullable(target.Name),
		},
	})
}

// orgMembersRemove removes one membership, named by its row id in the body.
//
// The member id is resolved WITHIN this organisation before anything is
// deleted, which the live route does not do: it deletes by id alone, so a
// member of one organisation can delete a membership row belonging to another
// by naming its id. Resolving through this organisation's member list makes an
// id from elsewhere a 404 rather than a cross-tenant write.
//
// The organisation's OWNER cannot be removed, and that refusal is this port's,
// not the original's. An organisation whose owner is not a member is a state
// that is easy to reach from a member list by accident and impossible to leave:
// every route here checks membership, so nobody can administer it and nobody
// can delete it. It answers 409 — a state conflict, not a missing row, because
// the row is right there.
func (s *server) orgMembersRemove(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	ctx := r.Context()
	orgID := r.PathValue("id")

	var body map[string]any
	if !apiauth.DecodeJSON(w, r, &body, false) {
		return
	}
	raw, present := body["member_id"]
	if !present || !authJSTruthy(raw) {
		apiauth.BadRequest(w, "Missing required field: member_id")
		return
	}
	memberID := authJSString(raw)

	userID, ok := s.authProjectOwner(w, r, key)
	if !ok {
		return
	}
	if !s.orgMemberOrOwner(w, r, orgID, userID, orgNotAMember) {
		return
	}

	members, err := s.store.ListOrgMembers(ctx, orgID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	targetUserID := ""
	for _, m := range members {
		if m.ID == memberID {
			targetUserID = m.UserID
			break
		}
	}
	if targetUserID == "" {
		authBadRequest(w, http.StatusNotFound, "Member not found")
		return
	}

	removed, err := s.store.RemoveOrgMember(ctx, orgID, targetUserID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !removed {
		// The row was there a moment ago and the statement matched nothing, so
		// the owner clause is what refused it.
		authBadRequest(w, http.StatusConflict, "The organization owner cannot be removed")
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"deleted": true})
}
