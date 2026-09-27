package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
	"github.com/codeyevsky/solongate/api/internal/store"
)

// /api/v1/mcp-servers — the port of src/app/api/v1/mcp-servers/{route,check,[id]}.ts.
//
// The project's catalogue of MCP upstreams. Three callers matter and they want
// different things from it:
//
//   - packages/proxy registers a server on every launch (POST). The URL is the
//     key, so a relaunch flips the existing row back to active rather than
//     adding a duplicate — see the dedupe in postMcpServers.
//   - the CLI lists them (GET) and reads `servers[].{id,name,url,command,status}`.
//   - the dashboard lists, edits, deletes, and calls /check.
//
// Everything is scoped to KeyInfo.ProjectID. A URL is not unique across the
// database, so every statement here carries the project id and none of them
// takes an identifier from the request as a tenant.

func init() {
	Register("GET /api/v1/mcp-servers", func(s *server) http.Handler {
		return s.auth.WithAuth(s.listMcpServers)
	})
	Register("POST /api/v1/mcp-servers", func(s *server) http.Handler {
		return s.auth.WithAuth(s.createMcpServer)
	})
	Register("POST /api/v1/mcp-servers/check", func(s *server) http.Handler {
		return s.auth.WithAuth(s.checkMcpServer)
	})
	Register("GET /api/v1/mcp-servers/{id}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.getMcpServer)
	})
	Register("PUT /api/v1/mcp-servers/{id}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.putMcpServer)
	})
	Register("DELETE /api/v1/mcp-servers/{id}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.deleteMcpServer)
	})
}

// The column widths the live routes clip to. They are String.prototype.slice
// lengths, so they count characters and not bytes — store.Clip cuts on a rune
// boundary for exactly that reason.
const (
	mcpNameMax    = 200
	mcpURLMax     = 500
	mcpStatusMax  = 20
	mcpCommandMax = 500
	mcpArgsMax    = 2000
)

// mcpNotFound is the id routes' 404. One message and one code, as the original.
func mcpNotFound(w http.ResponseWriter) {
	apiauth.Error(w, http.StatusNotFound, "NOT_FOUND", "MCP server not found")
}

// mcpView is one row on the wire.
//
// Command and Args are pointers because the columns are nullable and the
// deployed clients treat null and "" the same only by accident: proxy-go's
// McpServer decodes `command,omitempty`, the dashboard's type has `command?:
// string`. drizzle sends null for a NULL column, so this does too rather than
// flattening it to an empty string.
//
// created_at and updated_at are ISO-8601 strings, not the integers the column
// holds. Both are NOT NULL in schema.ts, so neither is ever absent.
type mcpView struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	URL       string  `json:"url"`
	Status    string  `json:"status"`
	Command   *string `json:"command"`
	Args      *string `json:"args"`
	CreatedAt string  `json:"created_at"`
	UpdatedAt string  `json:"updated_at"`
}

func mcpToView(m store.McpServer) mcpView {
	return mcpView{
		ID:        m.ID,
		Name:      m.Name,
		URL:       m.URL,
		Status:    m.Status,
		Command:   nullableText(m.Command),
		Args:      nullableText(m.Args),
		CreatedAt: store.ISO(m.CreatedAt),
		UpdatedAt: store.ISO(m.UpdatedAt),
	}
}

// nullableText turns the store's collapsed empty string back into JSON null.
//
// The write side stores an empty command as NULL (see the falsy check in the
// live route), so the two are the same value and this cannot lose information.
func nullableText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// GET /api/v1/mcp-servers
func (s *server) listMcpServers(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	rows, err := s.store.ListMcpServers(r.Context(), key.ProjectID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	// A project with no servers answers {"servers":[]} and not {"servers":null}:
	// the CLI ranges over the array without checking, and null there is a nil
	// slice on one side and a crash on the other.
	servers := make([]mcpView, 0, len(rows))
	for _, m := range rows {
		servers = append(servers, mcpToView(m))
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"servers": servers})
}

// POST /api/v1/mcp-servers
//
// The dedupe is the whole point of this handler. packages/proxy calls it every
// time it starts in front of an upstream, so without it a developer who
// restarts their proxy twenty times has twenty rows. The URL is the key: an
// existing row is flipped back to `active` and returned with 200, a new one is
// created and returned with 201, and the caller tells the two apart by the
// status code (packages/proxy-go/internal/proxy/cloud.go reads exactly that).
func (s *server) createMcpServer(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}

	name, ok := mcpRequiredString(w, body, "name", "Missing required field: name")
	if !ok {
		return
	}

	// `!body.url && !body.command` in the original: either identifies the
	// upstream, and a stdio server has no URL of its own.
	rawURL, hasURL := jsTruthyString(body["url"])
	rawCommand, hasCommand := jsTruthyString(body["command"])
	if !hasURL && !hasCommand {
		apiauth.BadRequest(w, "Either url or command is required")
		return
	}

	// `body.url || \`stdio://${body.command}\`` — a stdio server is addressed by
	// a synthetic URL so that one column can be the key for both kinds.
	target := rawURL
	if !hasURL {
		target = "stdio://" + rawCommand
	}

	// Clipped BEFORE the lookup, unlike the original, which searches for the
	// full URL and then inserts a 500-character prefix of it. A URL longer than
	// that therefore never matches the row it created, so the live route adds a
	// fresh duplicate on every proxy launch. Searching for the value that would
	// actually be stored is what makes the dedupe work at all.
	existing, err := s.store.McpServerByURL(r.Context(), key.ProjectID, store.Clip(target, mcpURLMax))
	switch {
	case err == nil:
		now := store.Now()
		if err := s.store.SetMcpServerStatus(r.Context(), key.ProjectID, existing.ID, "active", now); err != nil {
			apiauth.Internal(w, "api", err)
			return
		}
		// The row is echoed with the values it had, except for the two the
		// update just wrote. The live route does the same rather than reading
		// the row back, and the difference is visible: `name` is NOT updated
		// from the request here, so re-registering under a new name keeps the
		// old one until somebody PUTs it.
		view := mcpToView(existing)
		view.Status = "active"
		view.UpdatedAt = store.ISO(now)
		apiauth.JSON(w, http.StatusOK, view)
		return
	case !errors.Is(err, store.ErrNotFound):
		apiauth.Internal(w, "api", err)
		return
	}

	id := randomUUIDv4()
	if id == "" {
		apiauth.Internal(w, "api", errors.New("could not read random bytes for an mcp server id"))
		return
	}

	now := store.Now()
	row := store.McpServer{
		ID:        id,
		ProjectID: key.ProjectID,
		Name:      store.Clip(name, mcpNameMax),
		URL:       store.Clip(target, mcpURLMax),
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}
	if hasCommand {
		row.Command = store.Clip(rawCommand, mcpCommandMax)
	}
	if args, hasArgs := jsTruthyString(body["args"]); hasArgs {
		row.Args = store.Clip(args, mcpArgsMax)
	}

	if err := s.store.CreateMcpServer(r.Context(), row); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusCreated, mcpToView(row))
}

// GET /api/v1/mcp-servers/{id}
func (s *server) getMcpServer(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	row, err := s.store.McpServerByID(r.Context(), key.ProjectID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		mcpNotFound(w)
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, mcpToView(row))
}

// PUT /api/v1/mcp-servers/{id}
//
// A partial update: only the fields the body mentions change. The distinction
// that matters is between a key that is ABSENT and a key that is present and
// empty — `{"command": ""}` clears the column, `{}` leaves it alone — which is
// why the body is decoded as a map and probed for presence rather than into a
// struct of pointers, where the two are indistinguishable.
//
// The row is read first and written whole, because the store's update sets
// every column. That read-then-write is the live route's shape too (it selects
// the row before updating), so the race is the same one and not a new one.
func (s *server) putMcpServer(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	id := r.PathValue("id")

	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}

	current, err := s.store.McpServerByID(r.Context(), key.ProjectID, id)
	if errors.Is(err, store.ErrNotFound) {
		mcpNotFound(w)
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	next := current
	next.UpdatedAt = store.Now()

	if raw, present := body["name"]; present {
		v, ok := mcpText(w, raw, "name")
		if !ok {
			return
		}
		next.Name = store.Clip(v, mcpNameMax)
	}
	if raw, present := body["url"]; present {
		v, ok := mcpText(w, raw, "url")
		if !ok {
			return
		}
		next.URL = store.Clip(v, mcpURLMax)
	}
	if raw, present := body["status"]; present {
		v, ok := mcpText(w, raw, "status")
		if !ok {
			return
		}
		v = store.Clip(v, mcpStatusMax)
		// schema.ts declares this column as an enum and SQLite does not enforce
		// it, so a value outside the three would be stored happily and read back
		// as something the dashboard has no colour for. The live route stores
		// whatever arrives; refusing it here is the smaller surprise, and the
		// store layer would silently rewrite it to "inactive" otherwise.
		if !store.OneOf(v, store.McpServerStatuses) {
			apiauth.ValidationError(w, "status must be one of "+strings.Join(store.McpServerStatuses, ", "))
			return
		}
		next.Status = v
	}
	// command and args take the original's falsy rule: anything falsy — absent
	// string, empty string, null, 0, false — clears the column.
	if _, present := body["command"]; present {
		v, _ := jsTruthyString(body["command"])
		next.Command = store.Clip(v, mcpCommandMax)
	}
	if _, present := body["args"]; present {
		v, _ := jsTruthyString(body["args"])
		next.Args = store.Clip(v, mcpArgsMax)
	}

	found, err := s.store.UpdateMcpServer(r.Context(), key.ProjectID, id, next)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !found {
		// Deleted between the read and the write. 404 rather than a body
		// describing a row that no longer exists.
		mcpNotFound(w)
		return
	}
	apiauth.JSON(w, http.StatusOK, mcpToView(next))
}

// DELETE /api/v1/mcp-servers/{id}
func (s *server) deleteMcpServer(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	deleted, err := s.store.DeleteMcpServer(r.Context(), key.ProjectID, r.PathValue("id"))
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !deleted {
		// The store's DELETE already carries the project id, so a row belonging
		// to somebody else is not deleted and is reported as not found — the same
		// answer a caller gets for an id that never existed, which is the point.
		mcpNotFound(w)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ── POST /api/v1/mcp-servers/check ──────────────────────────────────────────

// mcpCheckTimeout is the original's AbortController budget.
const mcpCheckTimeout = 5 * time.Second

// checkMcpServer reports whether a URL answers.
//
// This handler makes THIS SERVICE issue an HTTP request to an address the
// caller chose, which is a server-side request forgery primitive and is worth
// naming rather than leaving for somebody to find. It is kept because it is the
// deployed behaviour and the dashboard's "check" button is it; what bounds it:
//
//   - an API key is required, so the caller is a known project, not the internet
//   - only http:// and https:// are attempted; everything else is answered
//     without a request at all
//   - the response body is never read and never returned. The caller learns a
//     status code and a reason phrase, not content
//   - the request has a five-second deadline and no retry
//
// It is NOT bounded by a private-address filter, so an authenticated caller can
// still probe what this service can reach — the cloud metadata endpoint, a
// private subnet — one status code at a time, including through a redirect. The
// live app has the same hole. Closing it is a deliberate change to make with
// the people who own the dashboard's expectations, not a thing to slip into a
// port.
func (s *server) checkMcpServer(w http.ResponseWriter, r *http.Request, _ apiauth.KeyInfo) {
	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}

	target, ok := mcpRequiredString(w, body, "url", "Missing required field: url")
	if !ok {
		return
	}

	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		// 200, not 400. A stdio server is a legitimate thing to have registered
		// and the dashboard renders this reason next to it rather than an error.
		apiauth.JSON(w, http.StatusOK, map[string]any{
			"reachable": false,
			"reason":    "Only HTTP/HTTPS URLs can be health-checked. Stdio servers must be tested locally.",
		})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), mcpCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		apiauth.JSON(w, http.StatusOK, map[string]any{
			"reachable": false,
			"reason":    "Connection failed",
		})
		return
	}
	req.Header.Set("User-Agent", "SolonGate-HealthCheck/1.0")

	resp, err := mcpCheckClient.Do(req)
	if err != nil {
		apiauth.JSON(w, http.StatusOK, map[string]any{
			"reachable": false,
			"reason":    transportReason(ctx, err),
		})
		return
	}
	// The body is drained to a small ceiling and closed rather than read: it is
	// never returned to the caller, and leaving it unread leaks the connection.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()

	apiauth.JSON(w, http.StatusOK, map[string]any{
		"reachable":  true,
		"status":     resp.StatusCode,
		"statusText": reasonPhrase(resp),
	})
}

// mcpCheckClient is a dedicated client so a health check cannot borrow — or
// poison — a connection pool anything else uses. The transport limits are what
// stop one slow target from holding a socket open past this handler's deadline.
var mcpCheckClient = &http.Client{
	Timeout: mcpCheckTimeout,
	Transport: &http.Transport{
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   mcpCheckTimeout,
		ResponseHeaderTimeout: mcpCheckTimeout,
		ExpectContinueTimeout: time.Second,
	},
}

// reasonPhrase recovers `res.statusText`.
//
// Go keeps the wire reason phrase in Status ("200 OK") and offers no separate
// field for it, so the code is trimmed off the front. HTTP/2 carries no reason
// phrase at all and Go synthesises one from the code, which is also what a
// browser's fetch reports, so the two agree where it matters.
func reasonPhrase(resp *http.Response) string {
	prefix := strconv.Itoa(resp.StatusCode) + " "
	if strings.HasPrefix(resp.Status, prefix) {
		return strings.TrimPrefix(resp.Status, prefix)
	}
	return http.StatusText(resp.StatusCode)
}

// transportReason renders a failed request as one short sentence.
//
// The URL is stripped out of the message. Go wraps every transport error in a
// *url.Error whose text repeats the whole target, and echoing a caller-supplied
// string back into a response body is a habit worth not having even when the
// caller is the one who sent it.
func transportReason(ctx context.Context, err error) string {
	if ctx.Err() != nil {
		return "Connection failed: timed out after 5s"
	}
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return "Connection failed: " + uerr.Err.Error()
	}
	return "Connection failed"
}

// ── request-body helpers shared by this file's handlers ─────────────────────

// decodeJSONObject reads a JSON object body, or writes the 400 and returns
// false.
//
// A map rather than a struct because these routes need to tell an ABSENT key
// from one that is present and null — see putMcpServer. json.RawMessage keeps
// each value undecoded so a value of the wrong type is the field's problem
// rather than the whole body's.
func decodeJSONObject(w http.ResponseWriter, r *http.Request) (map[string]json.RawMessage, bool) {
	var body map[string]json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiauth.BadRequest(w, "Invalid JSON body")
		return nil, false
	}
	if body == nil {
		// `null` and a bodyless request both parse; the live routes then read
		// properties off it and throw. An empty map answers the same 400 from
		// the required-field check below instead of a 500.
		body = map[string]json.RawMessage{}
	}
	return body, true
}

// mcpRequiredString is the original's `if (!body.x) return errorResponse(...)`
// followed by `String(body.x)`: the falsy check and the coercion in one step,
// because the coercion is only ever reached for a truthy value.
func mcpRequiredString(w http.ResponseWriter, body map[string]json.RawMessage, field, message string) (string, bool) {
	v, ok := jsTruthyString(body[field])
	if !ok {
		apiauth.BadRequest(w, message)
		return "", false
	}
	return v, true
}

// mcpText is the PUT path's `String(body.x)`: the field is present, so it is
// used whatever it holds.
//
// One deliberate difference from the original. JavaScript's String() turns null
// into the four characters "null" and false into "false", so `{"name": null}`
// on the live route renames a server to the literal text `null`. That is a bug
// with a database row behind it, not a contract, so a non-string here is
// refused instead.
func mcpText(w http.ResponseWriter, raw json.RawMessage, field string) (string, bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		apiauth.ValidationError(w, field+" must be a string")
		return "", false
	}
	s, ok := v.(string)
	if !ok {
		if n, isNum := v.(float64); isNum {
			return jsNumberString(n), true
		}
		apiauth.ValidationError(w, field+" must be a string")
		return "", false
	}
	return s, true
}

// jsTruthyString evaluates a JSON value the way `x ? String(x) : …` does.
//
// The two halves are together because they are always used together: the live
// routes test a value for truthiness and only stringify it if it passed, so a
// falsy value's string form is never observable. Objects and arrays are the one
// case not reproduced — JavaScript would store `[object Object]` — and are
// reported as absent rather than written to a column.
func jsTruthyString(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, t != ""
	case float64:
		if t == 0 || math.IsNaN(t) {
			return "", false
		}
		return jsNumberString(t), true
	case bool:
		if !t {
			return "", false
		}
		return "true", true
	default:
		// null, object, array.
		return "", false
	}
}

// jsNumberString is String(n) for the numbers JSON can carry.
//
// 'f' with -1 precision is the shortest decimal that round-trips, which is what
// JavaScript's Number-to-string produces for the ordinary range. It differs for
// magnitudes JavaScript would print in exponent form; nothing sends those to
// these fields, and "1e21" versus "1000000000000000000000" in a server name is
// not a difference any caller reads.
func jsNumberString(n float64) string {
	return strconv.FormatFloat(n, 'f', -1, 64)
}

// randomUUIDv4 is crypto.randomUUID(): a version 4 UUID from the system CSPRNG.
//
// It returns empty on failure and the caller refuses to write, rather than
// falling back to a clock. A predictable row id is one an outsider can name
// before it exists.
func randomUUIDv4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		log.Printf("api: could not read random bytes for an id: %v", err)
		return ""
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
