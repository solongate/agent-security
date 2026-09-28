package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policyjson"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// /api/v1/projects, /api/v1/projects/{id} and /api/v1/project-config — the port
// of src/app/api/v1/projects/route.ts, projects/[id]/route.ts and
// project-config/route.ts.
//
// The dashboard's project selector and the CLI read these; the guard reads
// /project-config on its polling loop.
//
// The scoping rule is the whole security story of this file and it is NOT
// "everything the key's project owns". The API key resolves to ONE project, that
// project resolves to an OWNER, and the owner is what these routes list and
// address by id. So a key for project A can read, rename and delete project B
// when both belong to the same person, and can do none of those to a project
// belonging to anybody else. That is what the live app does; it is neither
// widened nor narrowed here, because narrowing would break the selector — which
// is a list of the owner's other projects, fetched with one project's key — and
// widening would be a cross-tenant read.
//
// The owner id therefore comes out of the DATABASE, never off the request. It is
// looked up from KeyInfo.ProjectID on every one of these handlers, which is why
// projectOwner exists rather than a field somebody could forget to set.

func init() {
	Register("GET /api/v1/projects", func(s *server) http.Handler {
		return s.auth.WithAuth(s.listProjects)
	})
	Register("GET /api/v1/projects/{id}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.getProject)
	})
	Register("PUT /api/v1/projects/{id}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.putProject)
	})
	Register("DELETE /api/v1/projects/{id}", func(s *server) http.Handler {
		return s.auth.WithAuth(s.deleteProject)
	})
	Register("GET /api/v1/project-config", func(s *server) http.Handler {
		return s.auth.WithAuth(s.getProjectConfig)
	})
}

// The column widths the live route clips to. String.prototype.slice counts
// UTF-16 code units, so store.Clip is what cuts on a rune boundary instead of
// halving a multi-byte character.
const (
	projectNameMax        = 100
	projectDescriptionMax = 1000
	piPatternMax          = 512
	piPatternNameMax      = 50
	piPatternPreviewMax   = 50
	piMaxPatterns         = 100
)

// projectNotFound is `errorResponse('Project not found', 404)`.
//
// The code is "ERROR", not "NOT_FOUND": errorResponse defaults to it and this
// call site does not override it. apiauth.NotFound writes NOT_FOUND, so using it
// here would be a different body for a client that branches on the code.
func projectNotFound(w http.ResponseWriter) {
	apiauth.Error(w, http.StatusNotFound, "ERROR", "Project not found")
}

// projectForbidden is the id routes' second failure: the project exists as far
// as the caller knows, but it is not this owner's. 403 and this message are the
// live route's, and it is a different answer from projectNotFound on purpose —
// the live app draws that distinction and the dashboard reports it.
func projectForbidden(w http.ResponseWriter) {
	apiauth.Error(w, http.StatusForbidden, "ERROR", "Project not found or not authorized")
}

// projectOwner resolves the API key's project to its owner, which is the
// authorisation subject for every route in this file. A key whose project row
// has been deleted gets the 404 the live route gives.
func (s *server) projectOwner(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) (string, bool) {
	owner, err := s.store.ProjectOwner(r.Context(), key.ProjectID)
	if errors.Is(err, store.ErrNotFound) {
		projectNotFound(w)
		return "", false
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return "", false
	}
	return owner, true
}

// ── the wire shapes ─────────────────────────────────────────────────────────
//
// The three responses carry three different column sets and the field ORDER is
// the live select's, because JSON.stringify emits an object in insertion order
// and a year of stored responses look like this. That is why the structs repeat
// fields instead of embedding a common one: embedding would put the shared
// fields first and move ownerName to the end.
//
// Every nullable column is a pointer. drizzle sends NULL as `null` and the
// dashboard branches on it.

type projectView struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Slug             string   `json:"slug"`
	Description      *string  `json:"description"`
	OrgID            *string  `json:"orgId"`
	PiEnabled        *bool    `json:"piEnabled"`
	PiThreshold      *float64 `json:"piThreshold"`
	PiMode           *string  `json:"piMode"`
	PiWhitelist      *string  `json:"piWhitelist"`
	PiToolConfig     *string  `json:"piToolConfig"`
	PiCustomPatterns *string  `json:"piCustomPatterns"`
	CreatedAt        string   `json:"createdAt"`
	UpdatedAt        string   `json:"updatedAt"`
}

// projectListView is projectView plus the joined owner, and the `owner_name`
// the live route appends after the spread — the one snake_case key in this
// file, kept because the selector renders it.
type projectListView struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Slug             string   `json:"slug"`
	Description      *string  `json:"description"`
	OrgID            *string  `json:"orgId"`
	OwnerName        *string  `json:"ownerName"`
	OwnerEmail       *string  `json:"ownerEmail"`
	PiEnabled        *bool    `json:"piEnabled"`
	PiThreshold      *float64 `json:"piThreshold"`
	PiMode           *string  `json:"piMode"`
	PiWhitelist      *string  `json:"piWhitelist"`
	PiToolConfig     *string  `json:"piToolConfig"`
	PiCustomPatterns *string  `json:"piCustomPatterns"`
	CreatedAt        string   `json:"createdAt"`
	UpdatedAt        string   `json:"updatedAt"`
	OwnerLabel       string   `json:"owner_name"`
}

// projectMetaView is what PUT answers with: the identity columns only. The live
// route re-selects exactly these after the update, which is why the settings it
// just wrote are absent from its own response.
type projectMetaView struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Slug        string  `json:"slug"`
	Description *string `json:"description"`
	OrgID       *string `json:"orgId"`
	CreatedAt   string  `json:"createdAt"`
	UpdatedAt   string  `json:"updatedAt"`
}

func projectToView(p store.ProjectRow) projectView {
	return projectView{
		ID: p.ID, Name: p.Name, Slug: p.Slug,
		Description:      p.Description,
		OrgID:            p.OrgID,
		PiEnabled:        p.PiEnabled,
		PiThreshold:      p.PiThreshold,
		PiMode:           p.PiMode,
		PiWhitelist:      p.PiWhitelist,
		PiToolConfig:     p.PiToolConfig,
		PiCustomPatterns: p.PiCustomPatterns,
		CreatedAt:        store.ISO(p.CreatedAt),
		UpdatedAt:        store.ISO(p.UpdatedAt),
	}
}

func projectToMetaView(p store.ProjectRow) projectMetaView {
	return projectMetaView{
		ID: p.ID, Name: p.Name, Slug: p.Slug,
		Description: p.Description,
		OrgID:       p.OrgID,
		CreatedAt:   store.ISO(p.CreatedAt),
		UpdatedAt:   store.ISO(p.UpdatedAt),
	}
}

func projectToListView(p store.ProjectListRow) projectListView {
	v := projectListView{
		ID: p.ID, Name: p.Name, Slug: p.Slug,
		Description:      p.Description,
		OrgID:            p.OrgID,
		OwnerName:        p.OwnerName,
		OwnerEmail:       p.OwnerEmail,
		PiEnabled:        p.PiEnabled,
		PiThreshold:      p.PiThreshold,
		PiMode:           p.PiMode,
		PiWhitelist:      p.PiWhitelist,
		PiToolConfig:     p.PiToolConfig,
		PiCustomPatterns: p.PiCustomPatterns,
		CreatedAt:        store.ISO(p.CreatedAt),
		UpdatedAt:        store.ISO(p.UpdatedAt),
	}
	// `p.ownerName || p.ownerEmail || 'Unknown'` — falsy, so a NULL name and an
	// empty one fall through alike.
	switch {
	case p.OwnerName != nil && *p.OwnerName != "":
		v.OwnerLabel = *p.OwnerName
	case p.OwnerEmail != nil && *p.OwnerEmail != "":
		v.OwnerLabel = *p.OwnerEmail
	default:
		v.OwnerLabel = "Unknown"
	}
	return v
}

// ── GET /api/v1/projects ────────────────────────────────────────────────────

func (s *server) listProjects(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	owner, ok := s.projectOwner(w, r, key)
	if !ok {
		return
	}

	rows, err := s.store.ProjectsForOwner(r.Context(), owner)
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	// An owner with no projects answers {"projects":[]} rather than null: the
	// selector maps over the array without checking.
	out := make([]projectListView, 0, len(rows))
	for _, p := range rows {
		out = append(out, projectToListView(p))
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"projects": out})
}

// ── GET /api/v1/projects/{id} ───────────────────────────────────────────────

func (s *server) getProject(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	owner, ok := s.projectOwner(w, r, key)
	if !ok {
		return
	}

	row, err := s.store.ProjectRowForOwner(r.Context(), r.PathValue("id"), owner)
	if errors.Is(err, store.ErrNotFound) {
		// A project belonging to somebody else is reported the same way as one
		// that does not exist, which is what stops this endpoint from being a way
		// to test whether a project id is real.
		projectNotFound(w)
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"project": projectToView(row)})
}

// ── PUT /api/v1/projects/{id} ───────────────────────────────────────────────

// putProject is a partial update: only the fields the body mentions are
// written. A key that is ABSENT and one that is present and null are different
// requests — `{"description": null}` clears the column, `{}` leaves it — which
// is why the body is a map probed for presence rather than a struct.
//
// The UPDATE is issued before the row is checked to belong to this owner, as
// the live route does, and that is safe rather than sloppy: the statement itself
// carries `owner_id = ?`, so a foreign project matches nothing. The re-read
// afterwards is what turns "matched nothing" into the 403.
func (s *server) putProject(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	id := r.PathValue("id")

	// The live route parses the body inside its try, so a malformed one becomes a
	// 500. This answers 400 for the reason in apiauth.DecodeJSON: a body this
	// service cannot parse is the caller's problem and saying it is ours sends
	// them looking in the wrong place.
	body, ok := decodeJSONObject(w, r)
	if !ok {
		return
	}

	owner, ok := s.projectOwner(w, r, key)
	if !ok {
		return
	}

	patch := &store.ProjectPatch{}

	// `if (body.name)` — a truthy check, so an empty name is ignored rather than
	// stored. That is the live behaviour and it is also the only thing stopping a
	// stray `{"name":""}` from leaving a project unnamed in the selector.
	if v, truthy := jsTruthyString(body["name"]); truthy {
		patch.SetName(store.Clip(v, projectNameMax))
	}
	if _, present := body["description"]; present {
		v, truthy := jsTruthyString(body["description"])
		if !truthy {
			// `String(body.description || '')`: null, false and 0 all become "".
			v = ""
		}
		patch.SetDescription(store.Clip(v, projectDescriptionMax))
	}
	if raw, present := body["piEnabled"]; present {
		patch.SetPiEnabled(rawTruthy(raw))
	}
	if raw, present := body["piThreshold"]; present {
		patch.SetPiThreshold(piThreshold(raw))
	}
	if raw, present := body["piMode"]; present {
		patch.SetPiMode(piMode(raw))
	}
	if raw, present := body["piWhitelist"]; present {
		// `JSON.stringify(Array.isArray(x) ? x : [])` — anything that is not an
		// array is stored as an empty one rather than refused.
		patch.SetPiWhitelist(stringifyArrayOrEmpty(raw))
	}
	if raw, present := body["piToolConfig"]; present {
		patch.SetPiToolConfig(stringifyObjectOrEmpty(raw))
	}
	if raw, present := body["piCustomPatterns"]; present {
		patterns, ok := piCustomPatterns(w, raw)
		if !ok {
			return
		}
		patch.SetPiCustomPatterns(patterns)
	}
	if err := s.store.UpdateProjectPatch(r.Context(), id, owner, patch, store.Now()); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}

	row, err := s.store.ProjectRowForOwner(r.Context(), id, owner)
	if errors.Is(err, store.ErrNotFound) {
		projectForbidden(w)
		return
	}
	if err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"project": projectToMetaView(row)})
}

// ── DELETE /api/v1/projects/{id} ────────────────────────────────────────────

func (s *server) deleteProject(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	id := r.PathValue("id")

	owner, ok := s.projectOwner(w, r, key)
	if !ok {
		return
	}

	// Only existence matters here; the row is read to prove the pair (id, owner)
	// exists before anything is deleted.
	if _, err := s.store.ProjectRowForOwner(r.Context(), id, owner); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			projectForbidden(w)
			return
		}
		apiauth.Internal(w, "api", err)
		return
	}

	if err := s.store.DeleteProjectCascade(r.Context(), id); err != nil {
		apiauth.Internal(w, "api", err)
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]any{"deleted": true})
}

// ── GET /api/v1/project-config ──────────────────────────────────────────────

// projectConfigView is what the guard polls for. The JSON columns are handed
// back PARSED — the guard reads piWhitelist as an array — unlike the projects
// endpoints, which return the stored strings.
type projectConfigView struct {
	PiEnabled        bool            `json:"piEnabled"`
	PiThreshold      float64         `json:"piThreshold"`
	PiMode           string          `json:"piMode"`
	PiWhitelist      json.RawMessage `json:"piWhitelist"`
	PiToolConfig     json.RawMessage `json:"piToolConfig"`
	PiCustomPatterns json.RawMessage `json:"piCustomPatterns"`
}

func (s *server) getProjectConfig(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	// The defaults are the live route's `?? true`, `?? 0.5`, `?? 'block'`, and
	// they stand in for a MISSING ROW as well as for a NULL column: the live
	// route reads `project[0]?.x`, so a key whose project has been deleted gets
	// 200 and the defaults rather than an error. That matters because the guard
	// polls this — a 404 would be read as "no configuration", one round trip
	// later, and the defaults are what it would fall back to anyway.
	cfg := store.ProjectConfig{PiEnabled: true, PiThreshold: 0.5, PiMode: "block"}
	got, err := s.store.ProjectConfigByID(r.Context(), key.ProjectID)
	switch {
	case err == nil:
		cfg = got
	case errors.Is(err, store.ErrNotFound):
		// keep the defaults
	default:
		apiauth.Internal(w, "api", err)
		return
	}

	apiauth.JSON(w, http.StatusOK, projectConfigView{
		PiEnabled:        cfg.PiEnabled,
		PiThreshold:      cfg.PiThreshold,
		PiMode:           cfg.PiMode,
		PiWhitelist:      storedJSON(cfg.PiWhitelist, "[]"),
		PiToolConfig:     storedJSON(cfg.PiToolConfig, "{}"),
		PiCustomPatterns: storedJSON(cfg.PiCustomPatterns, "[]"),
	})
}

// storedJSON is the live route's `try { JSON.parse(v) } catch { fallback }`.
//
// A column that will not parse is the fallback rather than an error, and that is
// not defensive coding for its own sake: these columns are written by three
// versions of a settings form and the guard's poll must not fail because one of
// them stored something odd.
func storedJSON(stored, fallback string) json.RawMessage {
	if stored == "" || !json.Valid([]byte(stored)) {
		return json.RawMessage(fallback)
	}
	return json.RawMessage(stored)
}

// ── the PUT body's coercions ────────────────────────────────────────────────

// rawTruthy is `Boolean(v)` for a value that arrived as JSON.
func rawTruthy(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return false
	}
	return jsTruthy(v)
}

// piThreshold is `Math.max(0, Math.min(1, Number(v)))`.
//
// nil means NaN, which is what Number() gives for a non-numeric body — and NaN
// is what the live route then writes. SQLite stores a NaN double as NULL, so nil
// here produces the same column value rather than an invented 0. It reads back
// as the schema default of 0.5, which is why this is worth reproducing exactly
// instead of clamping to something that looks tidier.
func piThreshold(raw json.RawMessage) *float64 {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	f, ok := jsNumber(v)
	if !ok {
		return nil
	}
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	return &f
}

// piMode is `['block','log-only'].includes(v) ? v : 'block'` — a strict match,
// so anything else lands on the safe mode rather than being stored.
func piMode(raw json.RawMessage) string {
	var v any
	if err := json.Unmarshal(raw, &v); err == nil {
		if s, isStr := v.(string); isStr && (s == "block" || s == "log-only") {
			return s
		}
	}
	return "block"
}

// stringifyArrayOrEmpty and stringifyObjectOrEmpty re-serialise a body value
// into the column.
//
// policyjson rather than encoding/json because this is JSON.stringify's job and
// the two differ where it shows: Go sorts an object's keys and escapes < > &.
// piToolConfig is a map of tool names to booleans that the dashboard renders
// back in the order the user's form produced, and a re-ordered column is a diff
// on every save of an unchanged setting.
func stringifyArrayOrEmpty(raw json.RawMessage) string {
	v, err := policyjson.Parse(raw)
	if err != nil {
		return "[]"
	}
	arr, isArr := policyjson.Array(v)
	if !isArr {
		return "[]"
	}
	return policyjson.Stringify(arr, nil)
}

func stringifyObjectOrEmpty(raw json.RawMessage) string {
	v, err := policyjson.Parse(raw)
	if err != nil || !policyjson.Truthy(v) {
		// `body.piToolConfig || {}` — falsy is an empty object, and an empty
		// object is itself truthy, so `{}` round-trips as `{}`.
		return "{}"
	}
	return policyjson.Stringify(v, nil)
}

// The ReDoS heuristic, ported expression for expression from the live route.
// Both are RE2-compatible as written, so they mean here what they mean there.
var (
	nestedQuantifier      = regexp.MustCompile(`(\+|\*|\{[^}]+\})\s*(\+|\*|\{[^}]+\}|\))`)
	nestedGroupQuantifier = regexp.MustCompile(`\([^)]*(\+|\*)[^)]*\)\s*(\+|\*|\{)`)
)

// piCustomPatterns validates and normalises the custom injection patterns, or
// writes the 400 and returns false.
//
// The three refusals are the live route's, in its order, and each one is a
// denial-of-service guard rather than a style rule: a 4 kB regex, one that does
// not compile, and one with nested quantifiers that the scanner would run over
// every tool argument this project ever sends.
//
// One difference has to be named. The live check is `new RegExp(p.pattern)`,
// which is JavaScript's engine; this is Go's RE2, which refuses lookahead,
// lookbehind and backreferences. A pattern using those is stored by the live app
// and refused here with "Invalid regex pattern". RE2 covers what a secret
// detector needs and the alternative is shipping a JavaScript regex parser, but
// it is a real difference for a caller who has one of those saved.
func piCustomPatterns(w http.ResponseWriter, raw json.RawMessage) (string, bool) {
	v, err := policyjson.Parse(raw)
	if err != nil {
		return "[]", true
	}
	items, isArr := policyjson.Array(v)
	if !isArr {
		// `Array.isArray(x) ? x : []`, and the loop below then has nothing to do.
		return "[]", true
	}

	for _, item := range items {
		obj, isObj := item.(*policyjson.Object)
		if !isObj {
			// `if (!p || typeof p.pattern !== 'string') continue` — a non-object
			// element is left exactly as it arrived and stored with the rest.
			continue
		}
		pattern, isStr := obj.Get("pattern").(string)
		if !isStr {
			continue
		}

		if len([]rune(pattern)) > piPatternMax {
			// The live check is `p.pattern.length`, which counts UTF-16 code
			// units; runes are the closest thing that is not bytes, and the
			// difference only shows for astral-plane characters in a regex.
			apiauth.BadRequest(w, "Regex pattern too long (max 512 chars)")
			return "", false
		}
		if _, err := regexp.Compile(pattern); err != nil {
			apiauth.BadRequest(w, "Invalid regex pattern: "+store.Clip(pattern, piPatternPreviewMax))
			return "", false
		}
		if nestedQuantifier.MatchString(pattern) || nestedGroupQuantifier.MatchString(pattern) {
			apiauth.BadRequest(w, "Unsafe regex pattern (nested quantifiers): "+
				store.Clip(pattern, piPatternPreviewMax))
			return "", false
		}

		// `Math.max(0, Math.min(1, Number(p.weight) || 0.5))`. The `|| 0.5` is
		// before the clamp, so a weight of exactly 0 becomes 0.5 — a quirk, but
		// changing it here would silently re-weight every pattern that has one.
		weight, ok := jsNumber(obj.Get("weight"))
		if !ok || weight == 0 {
			weight = 0.5
		}
		if weight < 0 {
			weight = 0
		}
		if weight > 1 {
			weight = 1
		}
		obj.Set("weight", weight)

		name := "custom"
		if policyjson.Truthy(obj.Get("name")) {
			name = jsString(obj.Get("name"))
		}
		obj.Set("name", store.Clip(name, piPatternNameMax))
	}

	if len(items) > piMaxPatterns {
		items = items[:piMaxPatterns]
	}
	return policyjson.Stringify(items, nil), true
}
