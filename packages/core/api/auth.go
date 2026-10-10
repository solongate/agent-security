// SPDX-License-Identifier: Apache-2.0

package api

import "context"

// AuthAPI answered "who does this key belong to".
//
// It was the last namespace here that spoke to a service, and its one caller was the
// MCP proxy checking a configured key before it forwarded anything — a licence check
// against /auth/me, refusing to start on a 401 or a 403. What it licensed is deleted.
//
// It stays as a stub rather than being removed because the TUI's own account
// header was the other consumer, and something a person could reasonably re-add — a
// machine identity that is not a service's — would land here. Answering nothing is
// the honest version of that until then.
type AuthAPI struct{ c *Client }

// Me is who the machine belongs to, which nothing on it knows.
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
	_ = ctx
	return Me{}, nil
}
