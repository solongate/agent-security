// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package panels

import (
	"encoding/json"
	"strings"

	"github.com/solongate/agent-security/packages/core/client"
)

type cType string

const (
	cNone     cType = "none"
	cCommand  cType = "command"
	cPath     cType = "path"
	cFilename cType = "filename"
	cURL      cType = "url"
)

var cTypes = []cType{cNone, cCommand, cPath, cFilename, cURL}

var permsAll = []string{"READ", "WRITE", "EXECUTE", "NETWORK"}

type ruleDoc struct {
	rule   client.PolicyRule
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

func setOrDelete(obj map[string]any, key string, c *client.Constraint) {
	if c != nil {
		obj[key] = c
	} else {
		delete(obj, key)
	}
}

func currentCType(r client.PolicyRule) cType {
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

func clearConstraints(r *client.PolicyRule) {
	r.CommandConstraints = nil
	r.PathConstraints = nil
	r.FilenameConstraints = nil
	r.URLConstraints = nil
}

func allowSide(r client.PolicyRule) bool { return r.Effect == "ALLOW" }

func setCType(r *client.PolicyRule, t cType) {
	items := matchItems(*r)
	clearConstraints(r)
	if t == cNone {
		return
	}
	writeItems(r, t, items)
}

func writeItems(r *client.PolicyRule, t cType, items []string) {
	allowed, denied := items, []string(nil)
	if !allowSide(*r) {
		allowed, denied = nil, items
	}
	switch t {
	case cCommand:
		r.CommandConstraints = &client.Constraint{Allowed: allowed, Denied: denied}
	case cFilename:
		r.FilenameConstraints = &client.Constraint{Allowed: allowed, Denied: denied}
	case cURL:
		r.URLConstraints = &client.Constraint{Allowed: allowed, Denied: denied}
	case cPath:
		r.PathConstraints = &client.PathConstraint{Allowed: allowed, Denied: denied}
	}
}

func matchItems(r client.PolicyRule) []string {
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

func setMatchItems(r *client.PolicyRule, items []string) {
	t := currentCType(*r)
	if t == cNone {
		return
	}
	writeItems(r, t, items)
}

func cValue(r client.PolicyRule) string { return strings.Join(matchItems(r), ", ") }

func migrateEffect(r *client.PolicyRule, next string) {
	t := currentCType(*r)
	items := matchItems(*r)
	r.Effect = next
	if t == cNone {
		return
	}
	writeItems(r, t, items)
}

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

func permListOf(r client.PolicyRule) []string {
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

func permIsAny(r client.PolicyRule) bool {
	have := permListOf(r)
	for _, p := range permsAll {
		if !containsString(have, p) {
			return false
		}
	}
	return true
}

func togglePerm(r *client.PolicyRule, p string) {
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

func permDisplay(r client.PolicyRule) string {
	if permIsAny(r) {
		return "any (READ WRITE EXECUTE NETWORK)"
	}
	return strings.Join(permListOf(r), " ")
}

func ruleHasValues(r client.PolicyRule) bool { return len(matchItems(r)) > 0 }

func isBlanketRule(r client.PolicyRule) bool { return !ruleHasValues(r) && permIsAny(r) }

func ruleSummary(r client.PolicyRule) string {
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