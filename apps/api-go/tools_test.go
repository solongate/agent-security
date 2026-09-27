package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/codeyevsky/solongate/api/internal/store"
)

// The registry's wire shape is drizzle's FIELD names, which are camelCase and
// not the column names. packages/proxy and the CLI read these.
func TestToolViewMatchesTheLiveShape(t *testing.T) {
	description := "run things"
	row := store.Tool{
		ID:          "tool_1",
		ProjectID:   "proj_1",
		Name:        "Bash",
		Description: &description,
		InputSchema: json.RawMessage(`{"type":"object"}`),
		Permissions: json.RawMessage(`["EXECUTE"]`),
		Enabled:     true,
		CreatedAt:   1_754_000_000,
		UpdatedAt:   1_754_000_600,
	}

	raw, err := json.Marshal(toolToView(row))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, field := range []string{"id", "projectId", "name", "description",
		"inputSchema", "permissions", "enabled", "createdAt", "updatedAt"} {
		if _, ok := got[field]; !ok {
			t.Errorf("%s is missing; drizzle's select() returns it", field)
		}
	}
	// The JSON columns are declared `mode: 'json'`, so they are objects on the
	// wire rather than strings.
	if _, isObj := got["inputSchema"].(map[string]any); !isObj {
		t.Errorf("inputSchema = %T, want a parsed object", got["inputSchema"])
	}
	if got["createdAt"] != "2025-07-31T22:13:20.000Z" {
		t.Errorf("createdAt = %v, want an ISO-8601 instant", got["createdAt"])
	}

	// A NULL description is null and an empty one is "". Both are reachable:
	// POST stores `body.description || ''`, and a PUT sending null clears the
	// column.
	empty := ""
	for _, c := range []struct {
		description *string
		want        any
	}{{nil, nil}, {&empty, ""}} {
		row.Description = c.description
		raw, _ = json.Marshal(toolToView(row))
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if got["description"] != c.want {
			t.Errorf("description = %v, want %v", got["description"], c.want)
		}
	}
}

// `enabled: body.enabled !== false` — a strict comparison, so only the literal
// false disables a tool. A client sending the string "false" registers a
// working one, which is the live behaviour and the safer reading of an
// ambiguous body.
func TestIsJSONFalseIsStrict(t *testing.T) {
	cases := map[string]bool{
		`false`:   true,
		`true`:    false,
		`"false"`: false,
		`0`:       false,
		`null`:    false,
	}
	for in, want := range cases {
		if got := isJSONFalse(json.RawMessage(in)); got != want {
			t.Errorf("isJSONFalse(%s) = %v, want %v", in, got, want)
		}
	}
	if isJSONFalse(nil) {
		t.Error("an absent enabled must leave a tool enabled")
	}
}

// The JSON columns are written with JSON.stringify, so key order survives a
// round trip. An input schema is a document somebody wrote.
func TestStoredJSONValueKeepsKeyOrder(t *testing.T) {
	got := storedJSONValue(json.RawMessage(`{"z":{"b":1,"a":2},"y":[1,2]}`))
	if string(got) != `{"z":{"b":1,"a":2},"y":[1,2]}` {
		t.Errorf("stored = %s, want the key order preserved", got)
	}
	// An absent value and an explicit null are both NULL: drizzle omits an
	// undefined property, and a stored JSON null reads back as null anyway.
	if got := storedJSONValue(nil); got != nil {
		t.Errorf("absent = %s, want nil", got)
	}
	if got := storedJSONValue(json.RawMessage(`null`)); got != nil {
		t.Errorf("null = %s, want nil", got)
	}
}

func TestToolDescriptionRefusesNonScalars(t *testing.T) {
	rec := httptest.NewRecorder()
	got, ok := toolDescription(rec, json.RawMessage(`null`))
	if !ok || got != nil {
		t.Errorf("null = (%v, %v), want (nil, true) — the column is cleared", got, ok)
	}

	rec = httptest.NewRecorder()
	got, ok = toolDescription(rec, json.RawMessage(`7`))
	if !ok || got == nil || *got != "7" {
		t.Errorf("number = (%v, %v), want the stringified value SQLite would store", got, ok)
	}

	// The live route hands an object to the driver and the caller gets a 500
	// describing nothing. A 400 naming the field is the same rejection, usable.
	rec = httptest.NewRecorder()
	if _, ok := toolDescription(rec, json.RawMessage(`{"a":1}`)); ok {
		t.Error("an object description was accepted")
	}
	if rec.Code != 400 {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}
