// SPDX-License-Identifier: Apache-2.0

package api

// The Client is a handle onto THIS MACHINE, not a connection to anything.
//
// It was an HTTP client: a credential resolver, a retry that distinguished a
// dropped socket from an answer, an error envelope decoder, and one method per
// route. All of that is gone with the service — the namespaces below read and write
// two files (see localstore.go), and the struct survives because every command and
// every panel is written against `c.Policies.List(ctx)` and there is nothing to gain
// from renaming that.
//
// The sub-APIs are FIELDS rather than free functions so a call site still reads like
// what it does, and so a future second store cannot share state with this one by
// accident.

// Error is what a failure looks like to a caller.
//
// It kept its shape — a code, a message, an HTTP status — because two callers branch
// on it (internal/commands and the Live panel), and because Status is still the
// honest way to say "this is a not-found" without inventing a second vocabulary.
// Nothing sets Status from a response any more; a local failure leaves it zero.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Message }

// IsAuth answered "is this a 401 or a 403". Nothing produces one now; it is kept so
// the callers that check it keep compiling, and it is always false.
func (e *Error) IsAuth() bool { return e.Status == 401 || e.Status == 403 }

// ErrNotAuthenticated was returned when no credential could be resolved. Nothing
// returns it any more — there is nothing to authenticate to — and it stays because
// internal/commands still recognises it when printing an error.
var ErrNotAuthenticated = errString("not logged in")

type errString string

func (e errString) Error() string { return string(e) }

// Client holds the four namespaces. Each one is backed by the two files.
type Client struct {
	Auth     AuthAPI
	Policies PoliciesAPI
	Settings SettingsAPI
	Stats    StatsAPI
	Audit    AuditAPI
}

// New builds a client. It takes nothing: there is no address to point it at and no
// credential to resolve.
func New() *Client {
	c := &Client{}
	c.Auth = AuthAPI{c}
	c.Policies = PoliciesAPI{c}
	c.Settings = SettingsAPI{c}
	c.Stats = StatsAPI{c}
	c.Audit = AuditAPI{c}
	return c
}

// Authenticated reports whether this machine has an account. It never has one, and
// the surfaces that used to gate on it — the dataroom's lock, doctor's first check —
// do not ask any more.
func (c *Client) Authenticated() bool { return false }
