package proxy

import (
	"bytes"
	"encoding/json"
	"sort"

	"github.com/codeyevsky/solongate/proxy/internal/api"
	"github.com/codeyevsky/solongate/proxy/internal/core"
)

// PolicyDoc is one policy held two ways at once.
//
// Set is the interpretable view: what gets logged, compared and handed to the
// evaluator. Fields is the document exactly as it arrived, which is what gets
// written back to disk and pushed to the cloud.
//
// Both are needed because this proxy is not the only thing that reads these
// documents. A policy carries fields this build has never heard of — the
// dashboard adds them faster than any one binary is rebuilt — and a
// read-modify-write that goes through a struct silently deletes every one of
// them. The npm proxy round-trips the parsed JSON object, so it keeps them by
// accident; here it has to be on purpose.
type PolicyDoc struct {
	Set    core.PolicySet
	Fields map[string]json.RawMessage
	// Unreadable counts rules that would not decode. They are still in Fields
	// and still pushed back untouched; the count exists so the proxy can say so
	// out loud instead of quietly enforcing fewer rules than the dashboard shows.
	Unreadable int
}

// DecodePolicyDoc reads a policy document from bytes.
//
// Rules are decoded ONE AT A TIME. Decoding the array in a single call means a
// single mistyped field anywhere — a `denied` written as a bare string, a
// quoted priority — fails the whole decode, and the caller sees a policy with
// no rules while the dashboard still shows them as active. The guard learned
// this the expensive way, where an empty rule list means allow everything.
func DecodePolicyDoc(raw []byte) (PolicyDoc, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return PolicyDoc{}, err
	}

	doc := PolicyDoc{Fields: fields}
	doc.Set.ID = stringField(fields, "id")
	doc.Set.Name = stringField(fields, "name")
	doc.Set.Description = stringField(fields, "description")
	doc.Set.CreatedAt = firstString(fields, "createdAt", "_created_at")
	doc.Set.UpdatedAt = stringField(fields, "updatedAt")
	doc.Set.Version = firstInt(fields, "version", "_version")

	if rulesRaw, ok := fields["rules"]; ok {
		var rules api.Rules
		if err := json.Unmarshal(rulesRaw, &rules); err == nil {
			doc.Unreadable = rules.Unreadable
			doc.Set.Rules = toCoreRules(rules.Items)
		}
	}
	if doc.Set.Rules == nil {
		doc.Set.Rules = []core.PolicyRule{}
	}
	return doc, nil
}

// PolicyDocFromSet wraps a policy the CLI already decoded — the local file read
// by internal/config, or the built-in default. Nothing is lost that was not
// already lost by that decode, and the document view exists so the sync path
// has one shape to work with rather than two.
func PolicyDocFromSet(set core.PolicySet) PolicyDoc {
	raw, err := json.Marshal(set)
	if err != nil {
		return PolicyDoc{Set: set, Fields: map[string]json.RawMessage{}}
	}
	doc, err := DecodePolicyDoc(raw)
	if err != nil {
		return PolicyDoc{Set: set, Fields: map[string]json.RawMessage{}}
	}
	// The decode above re-reads what was just written, so the interpretable
	// view is kept as the caller had it rather than round-tripped twice.
	doc.Set = set
	return doc
}

func indentJSON(raw []byte) ([]byte, error) {
	var buf bytes.Buffer
	if err := json.Indent(&buf, raw, "", "  "); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// RawRules is the rules array exactly as it arrived, for pushing back.
func (d PolicyDoc) RawRules() json.RawMessage {
	if r, ok := d.Fields["rules"]; ok {
		return r
	}
	return json.RawMessage("[]")
}

// WithoutID is the document minus its id, which is what gets written to the
// local policy file: the cloud id is owned by the --policy-id flag, and writing
// it into the file makes the file the second place it is configured.
func (d PolicyDoc) WithoutID() map[string]json.RawMessage {
	out := make(map[string]json.RawMessage, len(d.Fields))
	for k, v := range d.Fields {
		if k == "id" {
			continue
		}
		out[k] = v
	}
	return out
}

// EncodeIndented writes a policy document as the local file holds it: two-space
// indentation and a trailing newline, so a file this proxy rewrote still reads
// as one a person edited.
//
// KEY ORDER IS ALPHABETICAL, not the order the fields arrived in — Go has no
// ordered object. That changes the bytes of the file without changing the
// document, and nothing on either side reads these files positionally.
func EncodeIndented(fields map[string]json.RawMessage) ([]byte, error) {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	ordered := make([]byte, 0, 256)
	ordered = append(ordered, '{')
	for i, k := range keys {
		if i > 0 {
			ordered = append(ordered, ',')
		}
		key, err := json.Marshal(k)
		if err != nil {
			return nil, err
		}
		ordered = append(ordered, key...)
		ordered = append(ordered, ':')
		ordered = append(ordered, fields[k]...)
	}
	ordered = append(ordered, '}')

	var pretty []byte
	pretty, err := indentJSON(ordered)
	if err != nil {
		return nil, err
	}
	return append(pretty, '\n'), nil
}

// SetVersion replaces the version in both views at once. Updating only one of
// them is how a policy gets pushed to the cloud under a number the local file
// does not have, which makes the next poll look like a change and the two ends
// bounce a version between them forever.
func (d *PolicyDoc) SetVersion(v int) {
	d.Set.Version = v
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	if d.Fields == nil {
		d.Fields = map[string]json.RawMessage{}
	}
	d.Fields["version"] = b
}

// RulesEqual compares two policies the way the sync does: by name and by the
// rules themselves.
//
// The comparison is over the RAW rules, not the decoded ones. A rule this build
// could not decode still differs from a different undecodable rule, and
// comparing the decoded view would call two genuinely different policies equal
// and skip the update.
func RulesEqual(a, b PolicyDoc) bool {
	if a.Set.Name != b.Set.Name {
		return false
	}
	if len(a.Set.Rules) != len(b.Set.Rules) {
		return false
	}
	return string(canonicalJSON(a.RawRules())) == string(canonicalJSON(b.RawRules()))
}

// canonicalJSON removes formatting differences so a policy that was merely
// re-indented does not read as a changed one.
func canonicalJSON(raw json.RawMessage) []byte {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return raw
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

func toCoreRules(items []api.PolicyRule) []core.PolicyRule {
	out := make([]core.PolicyRule, 0, len(items))
	for _, r := range items {
		rule := core.PolicyRule{
			ID:                  r.ID,
			Description:         r.Description,
			Effect:              core.PolicyEffect(r.Effect),
			Priority:            r.Priority,
			ToolPattern:         r.ToolPattern,
			MinimumTrustLevel:   core.TrustLevel(r.MinimumTrustLevel),
			Enabled:             r.Enabled,
			CommandConstraints:  (*core.Constraint)(r.CommandConstraints),
			FilenameConstraints: (*core.Constraint)(r.FilenameConstraints),
			URLConstraints:      (*core.Constraint)(r.URLConstraints),
			PathConstraints:     (*core.PathConstraint)(r.PathConstraints),
		}
		// A rule may carry several permissions and core.PolicyRule holds one.
		// The first is kept for display; the RAW rule is what an evaluator
		// should compile, and that is untouched. See the caveat about sharing
		// the engine rather than the decoded shape.
		if perms := r.Permissions(); len(perms) > 0 {
			rule.Permission = perms[0]
		}
		if len(r.ArgumentConstraints) > 0 {
			var ac map[string]any
			if json.Unmarshal(r.ArgumentConstraints, &ac) == nil {
				rule.ArgumentConstraints = ac
			}
		}
		out = append(out, rule)
	}
	return out
}

func stringField(fields map[string]json.RawMessage, key string) string {
	raw, ok := fields[key]
	if !ok {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

func firstString(fields map[string]json.RawMessage, keys ...string) string {
	for _, k := range keys {
		if v := stringField(fields, k); v != "" {
			return v
		}
	}
	return ""
}

func firstInt(fields map[string]json.RawMessage, keys ...string) int {
	for _, k := range keys {
		raw, ok := fields[k]
		if !ok {
			continue
		}
		var n int
		if json.Unmarshal(raw, &n) == nil && n != 0 {
			return n
		}
	}
	return 0
}
