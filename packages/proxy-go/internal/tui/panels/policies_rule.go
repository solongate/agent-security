// SPDX-License-Identifier: Apache-2.0

package panels

import (
	"encoding/json"
	"strings"

	"github.com/solongate/agent-security/packages/proxy-go/internal/api"
)

// The rule model behind the Policies panel, ported from the helpers at the top
// of tui/panels/Policies.tsx.
//
// A rule is an EFFECT, ONE constraint type, and a set of permissions. Which
// list a match value lands in — allowed or denied — follows the effect, so the
// user never picks a side: a DENY rule fills `denied`, an ALLOW rule fills
// `allowed`. Flipping the effect moves the values across.
//
// A rule with no constraint values AND every permission matches every request.
// That is a blanket allow or a blanket deny, it is almost always a mistake, and
// saving one is refused here exactly as the dashboard refuses it.

// cType is the one constraint type a rule carries.
type cType string

const (
	cNone     cType = "none"
	cCommand  cType = "command"
	cPath     cType = "path"
	cFilename cType = "filename"
	cURL      cType = "url"
)

var cTypes = []cType{cNone, cCommand, cPath, cFilename, cURL}

// permsAll is the dashboard's four checkboxes. All four selected means "any",
// which is stored as no permission field at all.
var permsAll = []string{"READ", "WRITE", "EXECUTE", "NETWORK"}

// ruleDoc holds one rule BOTH ways: decoded for the editor, and as the exact
// bytes it arrived as.
//
// The bytes are what gets written back for a rule nobody touched. Round-tripping
// every rule through this version's struct would silently drop any field it does
// not model — the wire rule already carries argumentConstraints and timestamps,
// and a policy edited from the terminal must not come back narrower than it went
// in. Only an edited rule is re-serialised, and even then the merge writes over
// the original object rather than replacing it.
type ruleDoc struct {
	rule   api.PolicyRule
	raw    json.RawMessage
	edited bool
}

func (d ruleDoc) marshal() (json.RawMessage, error) {
	if !d.edited && len(d.raw) > 0 {
		return d.raw, nil
	}
	obj := map[string]any{}
	if len(d.raw) > 0 {
		_ = json.Unmarshal(d.raw, &obj)
	}
	r := d.rule
	obj["id"] = r.ID
	obj["description"] = r.Description
	obj["effect"] = r.Effect
	obj["priority"] = r.Priority
	obj["toolPattern"] = r.ToolPattern
	obj["minimumTrustLevel"] = r.MinimumTrustLevel
	obj["enabled"] = r.Enabled
	if len(r.Permission) > 0 {
		obj["permission"] = r.Permission
	} else {
		// Absent, not null: "any permission" is the absence of the field, and a
		// null here compiles to a rule that matches nothing.
		delete(obj, "permission")
	}
	setOrDelete(obj, "commandConstraints", r.CommandConstraints)
	setOrDelete(obj, "filenameConstraints", r.FilenameConstraints)
	setOrDelete(obj, "urlConstraints", r.URLConstraints)
	if r.PathConstraints != nil {
		obj["pathConstraints"] = r.PathConstraints
	} else {
		delete(obj, "pathConstraints")
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(b), nil
}

func setOrDelete(obj map[string]any, key string, c *api.Constraint) {
	if c != nil {
		obj[key] = c
	} else {
		delete(obj, key)
	}
}

// currentCType reads which constraint a rule carries. The order is the one the
// dashboard uses; a rule that somehow carries two answers the first.
func currentCType(r api.PolicyRule) cType {
	switch {
	case r.FilenameConstraints != nil:
		return cFilename
	case r.URLConstraints != nil:
		return cURL
	case r.CommandConstraints != nil:
		return cCommand
	case r.PathConstraints != nil:
		return cPath
	}
	return cNone
}

func clearConstraints(r *api.PolicyRule) {
	r.CommandConstraints = nil
	r.PathConstraints = nil
	r.FilenameConstraints = nil
	r.URLConstraints = nil
}

// allowSide reports whether values belong in `allowed` for this rule's effect.
func allowSide(r api.PolicyRule) bool { return r.Effect == "ALLOW" }

// setCType selects a constraint type: the others are cleared and the chosen one
// is created empty, on the side the effect dictates.
// setCType changes WHICH KIND of thing a rule matches, CARRYING THE PATTERNS ACROSS.
//
// It used to write an empty list, so cycling the constraint type threw the rule's
// patterns away. The field is cycled with ← and → while moving around the editor, so a
// person navigating a rule could land on Constraint, press an arrow, and watch `curl*`
// become `—`. Nothing warned them and nothing could bring it back; the only clue was the
// Match row turning into a dash two lines below where they were looking.
//
// A command pattern reinterpreted as a filename is a strange rule, but it is the one the
// person typed and it is one keystroke from being fixed. Silently discarding it is not.
func setCType(r *api.PolicyRule, t cType) {
	items := matchItems(*r)
	clearConstraints(r)
	if t == cNone {
		return
	}
	writeItems(r, t, items)
}

// writeItems puts the value list on the effect's side of the given constraint.
func writeItems(r *api.PolicyRule, t cType, items []string) {
	allowed, denied := items, []string(nil)
	if !allowSide(*r) {
		allowed, denied = nil, items
	}
	switch t {
	case cCommand:
		r.CommandConstraints = &api.Constraint{Allowed: allowed, Denied: denied}
	case cFilename:
		r.FilenameConstraints = &api.Constraint{Allowed: allowed, Denied: denied}
	case cURL:
		r.URLConstraints = &api.Constraint{Allowed: allowed, Denied: denied}
	case cPath:
		r.PathConstraints = &api.PathConstraint{Allowed: allowed, Denied: denied}
	}
}

// matchItems is the rule's value list, both sides together — a rule saved under
// the other effect still shows its values instead of looking empty.
func matchItems(r api.PolicyRule) []string {
	switch currentCType(r) {
	case cCommand:
		return append(append([]string(nil), r.CommandConstraints.Allowed...), r.CommandConstraints.Denied...)
	case cFilename:
		return append(append([]string(nil), r.FilenameConstraints.Allowed...), r.FilenameConstraints.Denied...)
	case cURL:
		return append(append([]string(nil), r.URLConstraints.Allowed...), r.URLConstraints.Denied...)
	case cPath:
		return append(append([]string(nil), r.PathConstraints.Allowed...), r.PathConstraints.Denied...)
	}
	return nil
}

func setMatchItems(r *api.PolicyRule, items []string) {
	t := currentCType(*r)
	if t == cNone {
		return
	}
	writeItems(r, t, items)
}

// cValue is the comma-joined preview of the value list.
func cValue(r api.PolicyRule) string { return strings.Join(matchItems(r), ", ") }

// migrateEffect flips the effect and carries the current constraint's values to
// the new side, so an ALLOW rule turned into a DENY still denies what it used to
// allow rather than quietly becoming an empty rule.
func migrateEffect(r *api.PolicyRule, next string) {
	t := currentCType(*r)
	items := matchItems(*r)
	r.Effect = next
	if t == cNone {
		return
	}
	writeItems(r, t, items)
}

// flipStar toggles a leading or trailing wildcard on ONE value.
func flipStar(v, side string) string {
	if side == "left" {
		if strings.HasPrefix(v, "*") {
			return strings.TrimLeft(v, "*")
		}
		return "*" + v
	}
	if strings.HasSuffix(v, "*") {
		return strings.TrimRight(v, "*")
	}
	return v + "*"
}

// permListOf is the rule's permissions, with "no permission field" expanded to
// all four — that is what an absent field MEANS to the policy compiler, and a
// display that showed it as empty would read as "this rule matches nothing".
func permListOf(r api.PolicyRule) []string {
	ps := r.Permissions()
	if len(ps) == 0 {
		return append([]string(nil), permsAll...)
	}
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, string(p))
	}
	return out
}

func permIsAny(r api.PolicyRule) bool {
	have := permListOf(r)
	for _, p := range permsAll {
		if !containsString(have, p) {
			return false
		}
	}
	return true
}

// togglePerm flips one permission. The list is never left empty — a rule with
// no permission at all matches nothing, which is not what unticking the last
// box means — and all four collapses back to the absent field.
func togglePerm(r *api.PolicyRule, p string) {
	cur := permListOf(*r)
	var next []string
	if containsString(cur, p) {
		for _, x := range cur {
			if x != p {
				next = append(next, x)
			}
		}
	} else {
		next = append(append([]string(nil), cur...), p)
	}
	if len(next) == 0 {
		next = []string{p}
	}
	all := true
	for _, x := range permsAll {
		if !containsString(next, x) {
			all = false
			break
		}
	}
	if all {
		r.Permission = nil
		return
	}
	b, err := json.Marshal(next)
	if err != nil {
		return
	}
	r.Permission = json.RawMessage(b)
}

func permDisplay(r api.PolicyRule) string {
	if permIsAny(r) {
		return "any (READ WRITE EXECUTE NETWORK)"
	}
	return strings.Join(permListOf(r), " ")
}

func ruleHasValues(r api.PolicyRule) bool { return len(matchItems(r)) > 0 }

// isBlanketRule mirrors the dashboard's isBlanketRule.
func isBlanketRule(r api.PolicyRule) bool { return !ruleHasValues(r) && permIsAny(r) }

// ruleSummary is the CONSTRAINTS column: which constraint the rule carries and
// how many values are in it.
func ruleSummary(r api.PolicyRule) string {
	var bits []string
	if c := r.CommandConstraints; c != nil {
		if n := len(c.Allowed) + len(c.Denied); n > 0 {
			bits = append(bits, "cmd:"+itoa(n))
		}
	}
	if c := r.PathConstraints; c != nil {
		if n := len(c.Allowed) + len(c.Denied); n > 0 {
			bits = append(bits, "path:"+itoa(n))
		}
	}
	if c := r.FilenameConstraints; c != nil {
		if n := len(c.Allowed) + len(c.Denied); n > 0 {
			bits = append(bits, "file:"+itoa(n))
		}
	}
	if c := r.URLConstraints; c != nil {
		if n := len(c.Allowed) + len(c.Denied); n > 0 {
			bits = append(bits, "url:"+itoa(n))
		}
	}
	return strings.Join(bits, " ")
}
