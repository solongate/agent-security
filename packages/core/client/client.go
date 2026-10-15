// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package client

// The Client is a handle onto THIS MACHINE, not a connection to anything.
//
// It was an HTTP client: a credential resolver, a retry that distinguished a
// dropped socket from an answer, an error envelope decoder, and one method per
// route. All of that is gone with the service, the namespaces below read and write
// two files (see localstore.go), and the struct survives because every command and
// every panel is written against `c.Policies.List(ctx)` and there is nothing to gain
// from renaming that.
//
// The sub-APIs are FIELDS rather than free functions so a call site still reads like
// what it does, and so a future second store cannot share state with this one by
// accident.

// Error is what a failure looks like to a caller.
//
// It kept its shape, a code, a message, an HTTP status, because two callers branch
// on it (cli and the Live panel), and because Status is still the
// honest way to say "this is a not-found" without inventing a second vocabulary.
// Nothing sets Status from a response any more; a local failure leaves it zero.
type Error struct {
	Code    string
	Message string
	Status  int
}

func (e *Error) Error() string { return e.Message }

// THE AUTHENTICATION SURFACE IS GONE, not stubbed. What stood here was an
// `Auth` namespace with a `Me` call, an `Authenticated()` that returned a
// hardcoded false, an `ErrNotAuthenticated` nothing returned, and an `IsAuth()`
// reading a `Status` field no response ever set. Each was kept so a caller would
// keep compiling, and together they read as an account system that was merely
// switched off, `grep Authenticated` found a method, and the method was a lie
// about there being something to authenticate to.
//
// There is no service and no account. The three callers that asked have been
// changed to not ask: cli/commands.go no longer tests for an error that cannot
// be returned, and nothing gates on a login. A reader now finds no auth surface,
// which is the accurate thing to find.

// Client holds the four namespaces. Each one is backed by the two files.
type Client struct {
	Policies Policies
	Settings Settings
	Stats    StatsClient
	Audit    Audit
}

// New builds a client. It takes nothing: there is no address to point it at and no
// credential to resolve.
func New() *Client {
	c := &Client{}
	c.Policies = Policies{c}
	c.Settings = Settings{c}
	c.Stats = StatsClient{c}
	c.Audit = Audit{c}
	return c
}