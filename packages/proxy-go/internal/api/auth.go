package api

import "context"

// AuthAPI is the one namespace here that still speaks to a service, and it has
// one caller: the MCP proxy checking a configured key before it forwards
// anything (internal/proxy/cloud.go). Everything else in this package reads and
// writes this machine.
type AuthAPI struct{ c *Client }

// Me is who the key in use belongs to: the project it selects and the owner.
type Me struct {
	User *struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	} `json:"user"`
	Project *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Slug string `json:"slug"`
	} `json:"project"`
}

func (a AuthAPI) Me(ctx context.Context) (Me, error) {
	var out Me
	return out, a.c.get(ctx, "/auth/me", nil, &out)
}
