// Package apiauth is the port of src/lib/auth.ts, src/lib/rate-limit.ts and
// src/lib/error-handler.ts: how a request becomes a project, how often it is
// allowed to, and how every failure is written down.
//
// It is one package rather than three because the three are one decision. The
// live app's withAuth authenticates, rate-limits and renders its own errors,
// and splitting those here would let a route slice authenticate without
// limiting, or render a 401 in a shape the dashboard does not recognise.
//
// The response shapes in this file are a CONTRACT with software that is already
// installed. The Node guard on somebody's laptop, the audit hook, the CLI and
// the dashboard all read `error.code` out of a failure body and none of them
// will be redeployed alongside this. A different code, a different status or a
// missing Retry-After is a broken client, not a cosmetic difference.
package apiauth

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
)

// JSON writes a value as the live app's NextResponse.json does.
//
// Two details are deliberate and both are about matching JSON.stringify.
//
// HTML escaping is OFF. Go's encoder rewrites the three characters < > & into
// their \u00xx forms by default; JavaScript's JSON.stringify does not. Policy
// rules are full of them — a command constraint like `sh -c 'a && b'`, a path
// glob, a URL with a query string. Both spellings parse to the same string, but
// the guard hashes the bytes it receives, so a policy that round-trips through
// this service has to come back byte-identical or the cached-policy check fails
// on every poll.
//
// The trailing newline the encoder appends is trimmed for the same reason.
func JSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// Encoding failed after nothing was written, so the error response is
		// still available. The value is NOT logged: this is the path a policy
		// body or a settings blob takes, and those carry customer data.
		log.Printf("api: response encode failed: %v", err)
		Error(w, http.StatusInternalServerError, "INTERNAL_ERROR",
			"An internal error occurred. Please try again later.")
		return
	}
	body := bytes.TrimRight(buf.Bytes(), "\n")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// ErrorBody is the failure shape every deployed client parses:
// {"error":{"code":"...","message":"..."}}. Nothing else in this service
// invents an error envelope.
type ErrorBody struct {
	Error ErrorDetail `json:"error"`
}

type ErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error writes that shape. The default code in the live app is the literal
// string "ERROR", which is why BadRequest passes it explicitly rather than
// leaving it empty.
func Error(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, ErrorBody{Error: ErrorDetail{Code: code, Message: message}})
}

// The failures that appear in more than one place, so four route slices cannot
// write four spellings of them. The strings are the live app's, exactly.

// Unauthorized is what an absent, malformed, unknown or revoked key gets.
//
// One message for all four cases, on purpose: distinguishing "no such key"
// from "revoked key" tells whoever is probing which half of a stolen credential
// is still worth trying.
func Unauthorized(w http.ResponseWriter) {
	Error(w, http.StatusUnauthorized, "AUTHENTICATION_ERROR", "Invalid API key")
}

// BadRequest is the default `errorResponse(msg, 400)`.
func BadRequest(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, "ERROR", message)
}

// ValidationError is the code the dashboard's forms branch on.
func ValidationError(w http.ResponseWriter, message string) {
	Error(w, http.StatusBadRequest, "VALIDATION_ERROR", message)
}

// NotFound is the shape /v1/auth/me and the id routes answer with.
func NotFound(w http.ResponseWriter, message string) {
	Error(w, http.StatusNotFound, "NOT_FOUND", message)
}

// Internal is src/lib/error-handler.ts's handleApiError.
//
// The error is logged with its context and a GENERIC message is sent, because
// the alternative has a history: a database error quotes the statement, which
// quotes the table and column names, and an error from the libsql driver can
// quote the DSN. `context` names the route in the log so the generic body is
// still traceable.
//
// The live app leaks the real message when NODE_ENV is development. That
// behaviour is not reproduced: a Go deploy has no reason to set NODE_ENV at
// all, so the flag would be missing rather than false, and "missing" is exactly
// the state in which it must not leak.
func Internal(w http.ResponseWriter, context string, err error) {
	log.Printf("[API:%s] %v", context, err)
	Error(w, http.StatusInternalServerError, "INTERNAL_ERROR",
		"An internal error occurred. Please try again later.")
}

// DecodeJSON reads a request body into v.
//
// A malformed body is (false) with the 400 already written, matching the live
// app's `await request.json()` throwing into the route's catch — except that
// this answers 400 rather than 500, because a body this service cannot parse is
// the caller's error and telling them it is ours sends them looking in the
// wrong place.
//
// Several live routes use `.catch(() => ({}))` and treat an unparseable body as
// an empty one. Those pass allowEmpty.
func DecodeJSON(w http.ResponseWriter, r *http.Request, v any, allowEmpty bool) bool {
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		if allowEmpty {
			return true
		}
		BadRequest(w, "Invalid JSON body")
		return false
	}
	return true
}
