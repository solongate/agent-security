package api

// The workspaces this account owns, and moving this machine between them.
//
// THE CLI HAD NO WORKSPACES. A machine pairs once, is handed a key for one
// project, and every screen in the dataroom - policies, fleet, audit, settings -
// belongs to whichever project the pairing landed on. Somebody with two of them
// had to remove the account and add it again to see the second, which also moved
// the guard on that machine whether they meant it or not.
//
// The dashboard does not have this problem because it holds a session and can
// ask for a key for any workspace it owns. A CLI holds a key, so the API grew
// the equivalent for a caller that only ever holds one: POST /projects/{id}/key,
// which mints for another workspace of the SAME owner and refuses everything
// else exactly as it refuses a workspace that does not exist.

import (
	"context"
	"net/url"
)

type ProjectsAPI struct{ c *Client }

// Workspace is one project as this CLI needs it: what to show and what to
// switch to.
type Workspace struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// List is every workspace the key's owner has, including the one the key is
// for. The API resolves the owner from the key, so nothing here names a person.
func (p ProjectsAPI) List(ctx context.Context) ([]Workspace, error) {
	var out struct {
		Projects []Workspace `json:"projects"`
	}
	if err := p.c.get(ctx, "/projects", nil, &out); err != nil {
		return nil, err
	}
	return out.Projects, nil
}

// Switch mints a key for another of the owner's workspaces and returns it with
// the workspace's name.
//
// It does NOT write anything. Which account file this lands in, and whether the
// guard on this machine follows, are decisions for the caller - and they are
// different decisions: looking at another workspace in the dataroom is not the
// same act as moving what this machine enforces.
func (p ProjectsAPI) Switch(ctx context.Context, id string) (key string, ws Workspace, err error) {
	var out struct {
		APIKey  string    `json:"api_key"`
		Project Workspace `json:"project"`
	}
	if err := p.c.post(ctx, "/projects/"+url.PathEscape(id)+"/key", map[string]any{}, &out); err != nil {
		return "", Workspace{}, err
	}
	return out.APIKey, out.Project, nil
}
