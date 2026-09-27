package core

import (
	"encoding/json"
	"strings"
	"testing"
)

func schemaOf(t *testing.T, raw string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func inputOf(t *testing.T, raw string) any {
	t.Helper()
	var out any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestUnknownFieldsAreRejectedNotIgnored(t *testing.T) {
	// The one behaviour the whole file exists for. A field the tool author
	// never declared reaching the tool is how an argument arrives that no
	// policy rule was written against.
	schema := schemaOf(t, `{"type":"object","properties":{"path":{"type":"string"}}}`)
	result := ValidateToolInput(schema, inputOf(t, `{"path":"/tmp/x","sudo":true}`), SchemaValidatorOptions{})

	if result.Valid {
		t.Fatal("an undeclared field was accepted")
	}
	if !containsSubstring(result.Errors, "sudo") {
		t.Fatalf("errors do not name the offending field: %v", result.Errors)
	}
}

func TestAdditionalPropertiesTrueAllowsExtras(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","additionalProperties":true,"properties":{"path":{"type":"string"}}}`)
	result := ValidateToolInput(schema, inputOf(t, `{"path":"/tmp/x","extra":1}`), SchemaValidatorOptions{})
	if !result.Valid {
		t.Fatalf("errors = %v", result.Errors)
	}
}

func TestStripUnknownRemovesRatherThanRejects(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","properties":{"path":{"type":"string"}}}`)
	result := ValidateToolInput(schema, inputOf(t, `{"path":"/tmp/x","sudo":true}`),
		SchemaValidatorOptions{StripUnknown: true})
	if !result.Valid {
		t.Fatalf("errors = %v", result.Errors)
	}
	if _, present := result.Sanitized["sudo"]; present {
		t.Fatal("the stripped field is still in the sanitized output")
	}
}

func TestRequiredFieldsAreEnforced(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","required":["path"],"properties":{"path":{"type":"string"}}}`)
	result := ValidateToolInput(schema, inputOf(t, `{}`), SchemaValidatorOptions{})
	if result.Valid {
		t.Fatal("a missing required field was accepted")
	}
	if !containsSubstring(result.Errors, "required") {
		t.Fatalf("errors = %v", result.Errors)
	}
}

func TestTypeMismatchesAreRejected(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","properties":{"count":{"type":"number"}}}`)
	result := ValidateToolInput(schema, inputOf(t, `{"count":"seven"}`), SchemaValidatorOptions{})
	if result.Valid {
		t.Fatal("a string was accepted for a number field")
	}
}

func TestNestedObjectsAndArraysAreWalked(t *testing.T) {
	schema := schemaOf(t, `{
	  "type":"object",
	  "properties":{
	    "files":{"type":"array","items":{"type":"object","properties":{"name":{"type":"string"}}}}
	  }
	}`)
	result := ValidateToolInput(schema, inputOf(t, `{"files":[{"name":"a"},{"name":"b","mode":"777"}]}`),
		SchemaValidatorOptions{})
	if result.Valid {
		t.Fatal("an undeclared field inside an array item was accepted")
	}
	if !containsSubstring(result.Errors, "files.1.mode") {
		t.Fatalf("the error does not point at the offending path: %v", result.Errors)
	}
}

func TestEnumsAreEnforced(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","properties":{"mode":{"type":"string","enum":["read","write"]}}}`)
	if ValidateToolInput(schema, inputOf(t, `{"mode":"delete"}`), SchemaValidatorOptions{}).Valid {
		t.Fatal("a value outside the enum was accepted")
	}
	if !ValidateToolInput(schema, inputOf(t, `{"mode":"read"}`), SchemaValidatorOptions{}).Valid {
		t.Fatal("a value inside the enum was rejected")
	}
}

func TestOversizedInputIsRejectedBeforeTheSchemaRuns(t *testing.T) {
	schema := schemaOf(t, `{"type":"object","properties":{"blob":{"type":"string"}}}`)
	big := map[string]any{"blob": strings.Repeat("x", 200)}
	result := ValidateToolInput(schema, big, SchemaValidatorOptions{MaxSizeBytes: 100})
	if result.Valid {
		t.Fatal("an oversized payload was accepted")
	}
	if len(result.Errors) != 1 || !strings.Contains(result.Errors[0], "exceeds maximum") {
		t.Fatalf("errors = %v", result.Errors)
	}
}

func TestSizeIsMeasuredInBytesNotCharacters(t *testing.T) {
	// A payload of non-ASCII text is bigger on the wire than it looks, which is
	// the whole reason the TypeScript reaches for TextEncoder.
	schema := schemaOf(t, `{"type":"object","additionalProperties":true}`)
	// Six three-byte runes plus the quotes and key: comfortably over 20 bytes,
	// comfortably under 20 characters.
	input := map[string]any{"t": "日本語日本語"}
	if ValidateToolInput(schema, input, SchemaValidatorOptions{MaxSizeBytes: 20}).Valid {
		t.Fatal("multi-byte text was measured as characters")
	}
}

func TestDeeplyNestedInputIsRejected(t *testing.T) {
	// Without the depth cap this is a stack overflow rather than a rejection.
	deep := any("leaf")
	for i := 0; i < 40; i++ {
		deep = map[string]any{"next": deep}
	}
	result := ValidateToolInput(schemaOf(t, `{"type":"object"}`), deep, SchemaValidatorOptions{})
	if result.Valid {
		t.Fatal("a payload past the depth limit was accepted")
	}
	if !containsSubstring(result.Errors, "depth") {
		t.Fatalf("errors = %v", result.Errors)
	}
}

func TestATooWithNoDeclaredSchemaAcceptsAnything(t *testing.T) {
	// An MCP server may declare a tool with no input schema. Refusing those in
	// the name of validating them blocks working tools.
	result := ValidateToolInput(nil, inputOf(t, `{"anything":1}`), SchemaValidatorOptions{})
	if !result.Valid {
		t.Fatalf("errors = %v", result.Errors)
	}
}

func TestErrorOrderIsStable(t *testing.T) {
	// Go randomises map iteration; an error list whose order changes between
	// runs is one nobody can write a test against.
	schema := schemaOf(t, `{"type":"object","properties":{"a":{"type":"string"}}}`)
	input := inputOf(t, `{"z":1,"y":2,"x":3}`)
	first := ValidateToolInput(schema, input, SchemaValidatorOptions{}).Errors
	for i := 0; i < 20; i++ {
		next := ValidateToolInput(schema, input, SchemaValidatorOptions{}).Errors
		if len(next) != len(first) {
			t.Fatalf("error count changed between runs: %d then %d", len(first), len(next))
		}
		for j := range first {
			if first[j] != next[j] {
				t.Fatalf("error order changed: %v then %v", first, next)
			}
		}
	}
}

func containsSubstring(items []string, needle string) bool {
	for _, s := range items {
		if strings.Contains(s, needle) {
			return true
		}
	}
	return false
}
