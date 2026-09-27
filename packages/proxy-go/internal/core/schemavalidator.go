package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Schema validation for tool input, ported from
// packages/proxy/src/core/schema-validator.ts.
//
// The TypeScript validates against a Zod schema. There is no Zod here, and the
// thing a tool actually declares over MCP is a JSON Schema, so this validates
// against that instead. What is preserved is the STRICTNESS, which is the whole
// point of the file:
//
//   - unknown fields are REJECTED, never ignored and never stripped
//   - type mismatches are REJECTED
//   - required fields are ENFORCED
//   - nesting depth is capped
//   - argument size is capped
//
// The first of those is the one worth naming: a schema that quietly accepts
// extra properties is how an argument the tool author never declared reaches
// the tool, and a policy rule written against the declared arguments never sees
// it.

// SchemaValidationResult is the outcome. Errors are always structured, so a
// caller can act on them rather than parse a sentence.
type SchemaValidationResult struct {
	Valid     bool
	Errors    []string
	Sanitized map[string]any
}

// SchemaValidatorOptions overrides the defaults. A zero field means "use the
// default": neither limit has a meaningful zero, and a maxSize of 0 would
// reject every call.
type SchemaValidatorOptions struct {
	MaxDepth     int
	MaxSizeBytes int
	// StripUnknown removes undeclared fields instead of rejecting them. Off by
	// default and it should stay off — see the note above about what an
	// undeclared field does to a policy rule.
	StripUnknown bool
}

func (o SchemaValidatorOptions) resolved() SchemaValidatorOptions {
	if o.MaxDepth == 0 {
		o.MaxDepth = MaxArgumentDepth
	}
	if o.MaxSizeBytes == 0 {
		o.MaxSizeBytes = MaxArgumentsSizeBytes
	}
	return o
}

// ValidateToolInput checks input against a tool's declared JSON Schema.
//
// The order is size, then depth, then shape, and it is not cosmetic: both of
// the first two exist to stop a payload that would make the third expensive, so
// running the schema first would defeat them.
func ValidateToolInput(schema map[string]any, input any, options SchemaValidatorOptions) SchemaValidationResult {
	opts := options.resolved()

	if err := checkInputSize(input, opts.MaxSizeBytes); err != "" {
		return SchemaValidationResult{Valid: false, Errors: []string{err}}
	}
	if err := checkInputDepth(input, opts.MaxDepth); err != "" {
		return SchemaValidationResult{Valid: false, Errors: []string{err}}
	}

	var errs []string
	sanitized := validateAgainst(schema, input, "root", opts, &errs)
	if len(errs) > 0 {
		return SchemaValidationResult{Valid: false, Errors: errs}
	}

	obj, _ := sanitized.(map[string]any)
	if obj == nil {
		obj = map[string]any{}
	}
	return SchemaValidationResult{Valid: true, Errors: []string{}, Sanitized: obj}
}

// checkInputSize measures the serialised bytes, not the character count.
//
// The TypeScript uses TextEncoder for the same reason: a payload of non-ASCII
// text is longer on the wire than it is in characters, and the limit is there
// to bound what has to be held in memory.
func checkInputSize(input any, maxBytes int) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Go escapes <, > and & as < and friends by default, which inflates
	// the measurement against JSON.stringify for any argument containing HTML
	// or a shell redirect. Turning it off makes the two agree.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(input); err != nil {
		return "Input cannot be serialized to JSON"
	}
	// Encode appends a newline that JSON.stringify does not produce.
	size := buf.Len() - 1
	if size > maxBytes {
		return fmt.Sprintf("Input size %d bytes exceeds maximum %d bytes", size, maxBytes)
	}
	return ""
}

func checkInputDepth(input any, maxDepth int) string {
	depth := measureDepth(input, 0)
	if depth > maxDepth {
		return fmt.Sprintf("Input depth %d exceeds maximum %d", depth, maxDepth)
	}
	return ""
}

// measureDepth stops descending once it is past the limit. Without the early
// exit a crafted payload nested tens of thousands deep is a stack overflow, and
// this function is the one that was supposed to prevent it.
func measureDepth(value any, currentDepth int) int {
	if currentDepth > MaxArgumentDepth+1 {
		return currentDepth
	}
	switch v := value.(type) {
	case nil:
		return currentDepth
	case []any:
		maxChild := currentDepth + 1
		for _, item := range v {
			if d := measureDepth(item, currentDepth+1); d > maxChild {
				maxChild = d
			}
		}
		return maxChild
	case map[string]any:
		maxChild := currentDepth + 1
		for _, key := range sortedKeys(v) {
			if d := measureDepth(v[key], currentDepth+1); d > maxChild {
				maxChild = d
			}
		}
		return maxChild
	default:
		return currentDepth
	}
}

// sortedKeys makes the walk deterministic. Go randomises map iteration, and an
// error list whose order changes between runs is one nobody can write a test
// against.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// validateAgainst walks one schema node. It returns the accepted value, which
// differs from the input only when StripUnknown is on.
func validateAgainst(schema map[string]any, value any, path string, opts SchemaValidatorOptions, errs *[]string) any {
	if schema == nil {
		// No declared schema means nothing to check against. The value is
		// accepted as-is rather than rejected: an MCP server is allowed to
		// declare a tool with no input schema, and refusing those would block
		// working tools in the name of validating them.
		return value
	}

	switch schemaType(schema) {
	case "object":
		return validateObject(schema, value, path, opts, errs)
	case "array":
		return validateArray(schema, value, path, opts, errs)
	case "string":
		if s, ok := value.(string); ok {
			return validateEnum(schema, s, path, errs)
		}
		*errs = append(*errs, path+": expected string")
	case "number", "integer":
		if n, ok := asNumber(value); ok {
			return n
		}
		*errs = append(*errs, path+": expected number")
	case "boolean":
		if b, ok := value.(bool); ok {
			return b
		}
		*errs = append(*errs, path+": expected boolean")
	case "null":
		if value == nil {
			return nil
		}
		*errs = append(*errs, path+": expected null")
	default:
		// An untyped schema node — a bare `enum`, a `$ref`, a composed
		// `anyOf` — is passed through. Guessing at a shape this validator does
		// not model would reject a call the tool would have accepted.
		return value
	}
	return value
}

func validateObject(schema map[string]any, value any, path string, opts SchemaValidatorOptions, errs *[]string) any {
	obj, ok := value.(map[string]any)
	if !ok {
		if value == nil {
			// An absent argument object is an empty one. A tool with no
			// required fields is callable with nothing.
			obj = map[string]any{}
		} else {
			*errs = append(*errs, path+": expected object")
			return value
		}
	}

	properties, _ := schema["properties"].(map[string]any)
	required := stringSlice(schema["required"])

	for _, name := range required {
		if _, present := obj[name]; !present {
			*errs = append(*errs, childPath(path, name)+": required")
		}
	}

	out := make(map[string]any, len(obj))
	for _, key := range sortedKeys(obj) {
		child, declared := properties[key]
		if !declared {
			if allowsAdditional(schema) {
				out[key] = obj[key]
				continue
			}
			if opts.StripUnknown {
				continue
			}
			*errs = append(*errs, childPath(path, key)+": unrecognized key")
			continue
		}
		childSchema, _ := child.(map[string]any)
		out[key] = validateAgainst(childSchema, obj[key], childPath(path, key), opts, errs)
	}
	return out
}

// allowsAdditional reads additionalProperties. ABSENT MEANS FALSE here, which
// is the opposite of what JSON Schema says.
//
// That inversion is the port's whole reason for existing: the TypeScript this
// replaces builds `z.object().strict()`, so a field nobody declared is
// rejected. Following the JSON Schema default instead would turn the strict
// validator into a permissive one while every comment still claimed otherwise.
func allowsAdditional(schema map[string]any) bool {
	raw, present := schema["additionalProperties"]
	if !present {
		return false
	}
	switch v := raw.(type) {
	case bool:
		return v
	case map[string]any:
		return true
	}
	return false
}

func validateArray(schema map[string]any, value any, path string, opts SchemaValidatorOptions, errs *[]string) any {
	arr, ok := value.([]any)
	if !ok {
		*errs = append(*errs, path+": expected array")
		return value
	}
	itemSchema, _ := schema["items"].(map[string]any)
	if itemSchema == nil {
		return arr
	}
	out := make([]any, len(arr))
	for i, item := range arr {
		out[i] = validateAgainst(itemSchema, item, fmt.Sprintf("%s.%d", path, i), opts, errs)
	}
	return out
}

func validateEnum(schema map[string]any, value string, path string, errs *[]string) any {
	options := stringSlice(schema["enum"])
	if len(options) == 0 {
		return value
	}
	for _, o := range options {
		if o == value {
			return value
		}
	}
	*errs = append(*errs, path+": expected one of "+strings.Join(options, ", "))
	return value
}

func schemaType(schema map[string]any) string {
	switch t := schema["type"].(type) {
	case string:
		return t
	case []any:
		// A union type is only checked when every member agrees, which is
		// almost never. Treating it as untyped passes the value through rather
		// than picking one member and rejecting the others.
		return ""
	}
	return ""
}

func asNumber(v any) (any, bool) {
	switch n := v.(type) {
	case float64, float32, int, int64, int32:
		return n, true
	case json.Number:
		return n, true
	}
	return nil, false
}

func stringSlice(v any) []string {
	raw, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func childPath(parent, key string) string {
	if parent == "root" {
		return key
	}
	return parent + "." + key
}
