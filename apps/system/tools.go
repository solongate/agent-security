package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// /api/v1/tools and /api/v1/tools/{name} — the port of
// src/app/api/v1/tools/route.ts and tools/[name]/route.ts.
//
// The registry the MCP proxy consults. packages/proxy POSTs every tool it
// discovers on each launch and treats 409 as success, so the duplicate check
// below is load-bearing rather than defensive: without it a developer who
// restarts their proxy twenty times has twenty rows, and with the wrong status
// code the proxy reports a failed registration every time.
//
// A tool is addressed by NAME, and a name is not unique across the database —
// two projects both have a "Bash". The pair (project, name) is the key of every
// statement here, and the project half always comes from the API key. An
// endpoint that looked up a tool by name alone would let any valid key read and
// edit another tenant's catalogue.

func init() {
	Register("GET /api/v1/tools", func(s *server) http.Handler {
		return s.auth.WithAuth(s.listTools)
	})
	Register("POST /api/v1/tools", func(s *server) http.Handler {
		return s.auth.WithAuth(s.createTool)
	})
	Register("GET /api/v1/tools/{name}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.getTool)
	})
	Register("PUT /api/v1/tools/{name}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.putTool)
	})
	Register("DELETE /api/v1/tools/{name}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.deleteTool)
	})
}

// toolNotFound is `errorResponse('Tool not found', 404)` — code "ERROR", the
// errorResponse default, not NOT_FOUND.
func toolNotFound(w http.ResponseWriter) {
	apiauth.Error(w, http.StatusNotFound, "ERROR", "Tool not found")
}

// toolView is a row as `db.select().from(tools)` renders it: drizzle's FIELD
// names, which are camelCase, not the column names. `projectId` and
// `inputSchema` are what a deployed client parses.
//
// inputSchema and permissions are declared `{ mode: 'json' }` in schema.ts, so
// drizzle hands them back PARSED — an object and an array, not strings. The
// stored bytes are re-emitted verbatim here, which is the same value and saves a
// round trip through a Go map that would reorder its keys.
//
// description is a POINTER, because this endpoint can produce both values: POST
// stores `body.description || ”` and a PUT carrying `"description": null`
// clears the column. store.Tool keeps them apart for that reason.
type toolView struct {
	ID          string          `json:"id"`
	ProjectID   string          `json:"projectId"`
	Name        string          `json:"name"`
	Description *string         `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
	Permissions json.RawMessage `json:"permissions"`
	Enabled     bool            `json:"enabled"`
	CreatedAt   string          `json:"createdAt"`
	UpdatedAt   string          `json:"updatedAt"`
}

func toolToView(t store.Tool) toolView {
	return toolView{
		ID:          t.ID,
		ProjectID:   t.ProjectID,
		Name:        t.Name,
		Description: t.Description,
		InputSchema: t.InputSchema,
		Permissions: t.Permissions,
		Enabled:     t.Enabled,
		CreatedAt:   store.ISO(t.CreatedAt),
		UpdatedAt:   store.ISO(t.UpdatedAt),
	}
}

// ── GET /api/v1/tools ───────────────────────────────────────────────────────

func (s *server) listTools(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	rows, err := s.store.ListTools(r.Context(), key.ProjectID)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	// A project with no tools answers {"tools":[]}, not null.
	out := make([]toolView, 0, len(rows))
	for _, t := range rows {
		out = append(out, toolToView(t))
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"tools": out})
}

// ── POST /api/v1/tools ──────────────────────────────────────────────────────

func (s *server) createTool(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	// The live route parses the body inside its try, so a malformed one is a 500
	// there and a 400 here — see apiauth.DecodeJSON for why that difference is
	// the deliberate one.
	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}

	name, ok := jsTruthyString(body["name"])
	if !ok {
		apiauth.BadRequest(w, "Missing required field: name")
		return
	}

	ctx := r.Context()
	switch _, err := s.store.ToolByName(ctx, key.ProjectID, name); {
	case err == nil:
		// 409 is what packages/proxy checks for. Answering 400 or 200 here would
		// turn every proxy relaunch into a reported registration failure.
		apiauth.Error(w, http.StatusConflict, "ERROR", "Tool with this name already exists")
		return
	case !errors.Is(err, store.ErrNotFound):
		apiauth.Internal(w, "api", err)
		return
	}

	description := ""
	if v, truthy := jsTruthyString(body["description"]); truthy {
		description = v
	}

	// `body.permissions || ['READ']` — a tool with no declared permissions is a
	// read-only tool, not an unrestricted one.
	permissions := json.RawMessage(`["READ"]`)
	if rawTruthy(body["permissions"]) {
		permissions = storedJSONValue(body["permissions"])
	}

	now := store.Now()
	row := store.Tool{
		ID:          uuid.NewString(),
		ProjectID:   key.ProjectID,
		Name:        name,
		Description: &description,
		InputSchema: storedJSONValue(body["input_schema"]),
		Permissions: permissions,
		// `body.enabled !== false`: a tool is enabled unless the body says
		// exactly false, so an absent flag registers a working tool.
		Enabled:   !isJSONFalse(body["enabled"]),
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := s.store.CreateTool(ctx, row); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// Read back rather than echo, as the live route does: the response is then
	// what the next GET will show, including whatever the column did to the
	// stored JSON.
	created, err := s.store.ToolByName(ctx, key.ProjectID, name)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusCreated, toolToView(created))
}

// ── GET /api/v1/tools/{name} ────────────────────────────────────────────────

func (s *server) getTool(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	row, err := s.store.ToolByName(r.Context(), key.ProjectID, r.PathValue("name"))
	if errors.Is(err, store.ErrNotFound) {
		toolNotFound(w)
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, toolToView(row))
}

// ── PUT /api/v1/tools/{name} ────────────────────────────────────────────────

// putTool is a partial update, and the partiality is not a design choice made
// here: the live route passes `body.description` and friends straight into
// drizzle's .set(), and drizzle omits a property whose value is undefined. So a
// body that mentions only `enabled` leaves the description alone, and one that
// sends `"description": null` clears it. Presence is what separates them, which
// is why the body is a map rather than a struct of pointers.
func (s *server) putTool(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	name := r.PathValue("name")

	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}

	ctx := r.Context()
	if _, err := s.store.ToolByName(ctx, key.ProjectID, name); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			toolNotFound(w)
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}

	patch := &store.ToolPatch{}
	if raw, present := body["description"]; present {
		v, ok := toolDescription(w, raw)
		if !ok {
			return
		}
		patch.SetDescription(v)
	}
	if raw, present := body["input_schema"]; present {
		patch.SetInputSchema(storedJSONValue(raw))
	}
	if raw, present := body["permissions"]; present {
		patch.SetPermissions(storedJSONValue(raw))
	}
	if raw, present := body["enabled"]; present {
		patch.SetEnabled(rawTruthy(raw))
	}

	found, err := s.store.UpdateToolPatch(ctx, key.ProjectID, name, patch, store.Now())
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	if !found {
		// Deleted between the check and the write.
		toolNotFound(w)
		return
	}

	updated, err := s.store.ToolByName(ctx, key.ProjectID, name)
	if errors.Is(err, store.ErrNotFound) {
		toolNotFound(w)
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, toolToView(updated))
}

// ── DELETE /api/v1/tools/{name} ─────────────────────────────────────────────

// deleteTool answers `{"deleted":true}` whether or not a row went, which is the
// live behaviour: the DELETE is scoped to (project, name) and matching nothing
// is not an error. It also means this endpoint cannot be used to find out
// whether another project has a tool by that name, because the answer is the
// same either way.
func (s *server) deleteTool(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	if _, err := s.store.DeleteTool(r.Context(), key.ProjectID, r.PathValue("name")); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ── body values ─────────────────────────────────────────────────────────────

// storedJSONValue re-serialises a body value for one of the `mode: 'json'`
// columns.
//
// drizzle writes those with JSON.stringify, so policyjson does it here: it keeps
// an object's key order and does not escape < > &, both of which encoding/json
// would change. An input schema is a document somebody wrote and a re-ordered
// copy of it is a diff on every save.
//
// An absent value and an explicit null are both NULL. drizzle omits an
// undefined property, leaving the column at its default, and a stored JSON
// `null` reads back as null anyway — so the two agree on the wire.
func storedJSONValue(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	v, err := policyjson.Parse(raw)
	if err != nil || v == nil {
		return nil
	}
	return json.RawMessage(policyjson.Stringify(v, nil))
}

// isJSONFalse is the `!== false` in `enabled: body.enabled !== false`: only the
// literal false counts, so `"false"` and 0 leave a tool enabled.
func isJSONFalse(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	b, isBool := v.(bool)
	return isBool && !b
}

// toolDescription reads the PUT body's description. nil means "write NULL",
// which is what `{"description": null}` asks for.
//
// A number or a boolean is stringified, because SQLite's TEXT affinity does the
// same to the value drizzle would pass. An object or an array is REFUSED rather
// than stored: the live route hands it to the driver, which errors, and the
// caller gets a 500 describing nothing. A 400 naming the field is the same
// rejection with a usable message.
func toolDescription(w http.ResponseWriter, raw json.RawMessage) (*string, bool) {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		apiauth.ValidationError(w, "description must be a string")
		return nil, false
	}
	switch t := v.(type) {
	case nil:
		return nil, true
	case string:
		return &t, true
	case bool, float64, json.Number:
		s := jsString(v)
		return &s, true
	default:
		apiauth.ValidationError(w, "description must be a string")
		return nil, false
	}
}
