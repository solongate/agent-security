package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// A CLI HAS NO WORKSPACES WITHOUT THIS.
//
// A machine pairs once and is handed a key for one project, and that key is the
// only workspace it can ever see - the dataroom's policies, fleet, audit and
// settings all belong to whichever project the pairing landed on. The dashboard
// solves the same problem with its Supabase session; a CLI holds a key, so this
// is the equivalent for a caller that only ever holds one.
func TestAWorkspaceKeyIsMintedForAnotherOfYourOwnProjects(t *testing.T) {
	s := authSessionServer(t)
	ctx := context.Background()

	// One account, two workspaces, and a key belonging to the first.
	_, first, _ := authSessionPost(t, s, `{"access_token":"ada@example.com","project_name":"First"}`)
	if first.Project == nil {
		t.Fatal("the fixture has no workspace")
	}
	owner, err := s.store.ProjectOwner(ctx, first.Project.ID)
	if err != nil {
		t.Fatal(err)
	}
	now := store.Now()
	if err := s.store.CreateProject(ctx, store.Project{
		ID: "p-second", OwnerID: owner, Name: "Second", Slug: "second-0001",
		TokenSecret: "secret", CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}

	mint := func(target string, key apiauth.KeyInfo) (int, map[string]any) {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/projects/"+target+"/key", strings.NewReader("{}"))
		r.SetPathValue("id", target)
		w := httptest.NewRecorder()
		s.mintProjectKey(w, r, key)
		var out map[string]any
		if w.Code == http.StatusOK {
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatalf("the answer is not JSON: %v\n%s", err, w.Body.String())
			}
		}
		return w.Code, out
	}

	mine := apiauth.KeyInfo{ProjectID: first.Project.ID, OwnerID: owner, ActingUserID: owner}
	status, out := mint("p-second", mine)
	if status != http.StatusOK {
		t.Fatalf("switching to my own workspace = %d, want 200", status)
	}
	if key, _ := out["api_key"].(string); key == "" {
		t.Fatal("no key came back, so there is nothing to switch with")
	}
	// The name and the id, because the CLI writes both into the account it
	// stores and shows the name in its own chrome.
	project, _ := out["project"].(map[string]any)
	if project == nil || project["id"] != "p-second" || project["name"] != "Second" {
		t.Errorf("the answer describes %+v", project)
	}
	// Exactly one live key per workspace: switching back and forth must not
	// leave a credential behind in every workspace a machine has visited.
	if again, _ := mint("p-second", mine); again != http.StatusOK {
		t.Fatalf("switching twice = %d", again)
	}
	if n := authSessionCount(t, s,
		`SELECT count(*) FROM api_keys WHERE project_id = ? AND name = ? AND revoked_at IS NULL`,
		"p-second", authCLIKeyName); n != 1 {
		t.Errorf("%d live keys on the workspace after two switches, want 1", n)
	}

	// A WORKSPACE SOMEBODY ELSE OWNS IS NOT MINTABLE, and is answered exactly
	// as one that does not exist - so this is not a way to test whether a
	// project id is real either.
	_, mallory, _ := authSessionPost(t, s, `{"access_token":"mallory@example.com","project_name":"Mallory's"}`)
	if mallory.Project == nil {
		t.Fatal("the second account has no workspace")
	}
	if status, _ := mint(mallory.Project.ID, mine); status != http.StatusNotFound {
		t.Errorf("minting a key for somebody else's workspace = %d, want 404", status)
	}
	if status, _ := mint("no-such-project", mine); status != http.StatusNotFound {
		t.Errorf("minting for a workspace that does not exist = %d, want 404", status)
	}

	// A GUEST IS A STRANGER HERE. The other project routes scope to the key's
	// project's owner, so a guest can read and rename that owner's projects;
	// reading is one thing and minting a live credential is another.
	guest := apiauth.KeyInfo{ProjectID: first.Project.ID, OwnerID: owner, ActingUserID: "guest-9"}
	if status, _ := mint("p-second", guest); status != http.StatusNotFound {
		t.Errorf("a guest minted a key for the host's other workspace: %d", status)
	}
}
