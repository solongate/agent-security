package main

import (
	"net/http"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/hookbundle"
)

// GET /api/v1/hooks/{guard,audit,shield} — the port of
// src/app/api/v1/hooks/*/route.ts.
//
// Three routes, one line of logic each in the original, and the most
// consequential endpoints in this service. Every installed guard, audit hook
// and shield polls one of them to update itself; there is no other channel. A
// fix to the guard reaches a laptop because this endpoint answered, and reaches
// nothing if it did not.
//
// The failure mode is what makes them worth this much comment. The hook
// verifies a SHA-256 over the decoded payload and, on a mismatch, returns
// without a word — no error to this service, no log line on the device, no
// telemetry. So a bad bundle does not look like an outage. It looks like a
// fleet where nothing ever updates again, discovered when a security fix does
// not land. internal/hookbundle owns the encoding and its tests are the check;
// this file does nothing but authenticate and serve.
//
// The whole payload is served to any valid key. That is the live behaviour and
// it is correct: the bundles are the same three files for every project, they
// are what `npx @solongate/proxy` writes to disk on install, and there is
// nothing tenant-specific in them. No project id is read here for that reason —
// there is nothing to scope.

func init() {
	// One registration per hook, from the same list internal/hookbundle serves,
	// so a fourth hook added to the generator cannot be one with no route. The
	// route table in routes.go lists exactly these three; a name that is not in
	// it is registered anyway and logged as an extra, which is louder than a
	// hook silently missing.
	for _, name := range hookbundle.Names() {
		Register("GET /api/v1/hooks/"+name, buildHookBundle(name))
	}
}

func buildHookBundle(name string) func(*server) http.Handler {
	return func(s *server) http.Handler {
		return s.auth.WithAuth(func(w http.ResponseWriter, r *http.Request, _ apiauth.KeyInfo) {
			bundle, ok := hookbundle.Get(name)
			if !ok {
				// Unreachable: the name came from hookbundle.Names(). It is
				// handled rather than ignored because the alternative is serving
				// a zero Bundle — version 0, empty content, empty checksum — and
				// a hook reads that as "nothing newer than what I have" and stops
				// asking. A 404 at least shows up in a log.
				apiauth.NotFound(w, "Hook bundle not found")
				return
			}
			apiauth.JSON(w, http.StatusOK, bundle)
		})
	}
}
