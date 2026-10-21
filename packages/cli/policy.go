// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/solongate/agent-security/packages/core/client"
)

func policyUsage() string {
	return usageWith("solongate policy", "read and edit this machine's policy", []usageRow{
		row("policy list", "list all policies"),
		row("policy create <name>", "create a new empty policy"),
		row("policy delete <id>", "delete a policy"),
		row("policy show <id>", "show one policy (rules, mode)"),
		row("policy allow <id> [--command|--path|--filename|--url <val>]", "append an ALLOW rule"),
		row("policy deny  <id> [--command|--path|--filename|--url <val>]", "append a DENY rule"),
		row("policy revoke <id> <ruleId>", "remove a rule"),
		row("policy active", "show the resolved active policy"),
		row("", ""),
		row("  --permission READ,WRITE,EXECUTE,NETWORK", "scope allow/deny to a class of call"),
		row("", ""),
		row("policy mode <id> <denylist|whitelist>", "switch a policy between deny-by-default and allow-by-default"),
		row("policy rule <id> <ruleId> <enable|disable>", "turn one rule on or off without deleting it"),
		row("", ""),
		row("policy activate <id> | --off", "pin the active policy, or enforce nothing"),
		row("", ""),
		row("policy protect <path>", "add a path, and lock it with the OS"),
		row("policy protect list", "every protected path, and what is holding it"),
		row("policy protect remove <path>", "drop a path and lift its lock"),
		row("policy protect require-sandbox on|off", "refuse calls from agents not started by `solongate run`"),
	}, "Add --json to any read command for machine-readable output.")
}

func parsePermissions(raw string) (perms []string, bad string) {
	known := map[string]string{"read": "READ", "write": "WRITE", "execute": "EXECUTE", "network": "NETWORK"}
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, ",") {
		t := strings.ToLower(strings.TrimSpace(part))
		if t == "" {
			continue
		}
		name, ok := known[t]
		if !ok {
			return nil, strings.TrimSpace(part)
		}
		if !seen[name] {
			seen[name] = true
			perms = append(perms, name)
		}
	}
	return perms, ""
}

func runPolicy(ctx context.Context, c *client.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	jsonOut := p.flagBool("json")

	switch sub {
	case "", "help":
		errln(policyUsage())

		if sub == "" {
			return 1, nil
		}
		return 0, nil

	case "protect":
		return runProtect(ctx, c, parsedArgs{positionals: p.positionals[1:], flags: p.flags})

	case "list":
		policies, err := c.Policies.List(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(policies)
			return 0, nil
		}
		if len(policies) == 0 {
			errln(dim("  No policies. `solongate policy create <name>` makes one."))
			return 0, nil
		}
		rows := make([][]string, 0, len(policies))
		for _, pol := range policies {
			mode := "denylist"
			if pol.Mode == client.ModeWhitelist {
				mode = green("whitelist")
			}
			by := pol.CreatedBy
			if by == "" {
				by = "-"
			}
			rows = append(rows, []string{
				cyan(pol.ID),
				truncate(pol.Name, 28),
				mode,
				strconv.Itoa(rulesCount(pol.Rules)),
				dim(truncate(by, 20)),
			})
		}
		table([]string{"ID", "NAME", "MODE", "RULES", "UPDATED BY"}, rows)
		return 0, nil

	case "show":
		id := p.positional(1)
		if id == "" {
			return usageErr("Usage: policy show <id>")
		}
		pol, err := c.Policies.Get(ctx, id, 0)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(pol)
			return 0, nil
		}
		errln("")
		errln("  " + bold(pol.Name) + " " + dim("("+pol.ID+")"))
		if pol.Description != "" {
			errln("  " + dim(pol.Description))
		}
		mode := "denylist"
		if pol.Mode == client.ModeWhitelist {
			mode = green("whitelist")
		}
		errln("  mode: " + mode + "   rules: " + strconv.Itoa(rulesCount(pol.Rules)))
		errln("")
		printRules(pol.Rules)
		return 0, nil

	case "create":
		name := p.rest(1)
		if name == "" {
			return usageErr("Usage: policy create <name>")
		}

		res, err := c.Policies.Create(ctx, client.PolicySet{
			ID:   "policy-" + strconv.FormatInt(nowMillis(), 10),
			Name: name,
			Mode: client.ModeDenylist,
		})
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(res)
			return 0, nil
		}
		errln(green(`  ✓ Created "`+name+`"`) + dim(" ("+res.ID+")"))
		return 0, nil

	case "delete":
		id := p.positional(1)
		if id == "" {
			return usageErr("Usage: policy delete <id>")
		}

		if err := c.Policies.Remove(ctx, id); err != nil {
			return 1, err
		}
		res := struct {
			PolicyID string `json:"policy_id"`
		}{PolicyID: id}
		if jsonOut {
			printJSON(mustJSON(map[string]any{"deleted": true, "policy_id": id}))
			return 0, nil
		}
		okf("Deleted %s", res.PolicyID)
		return 0, nil

	case "allow", "deny":
		effect := "DENY"
		if sub == "allow" {
			effect = "ALLOW"
		}
		id := p.positional(1)
		if id == "" {
			return usageErr("Usage: policy " + sub + " <id> [--command|--path|--filename|--url <val>]")
		}

		spec := client.RuleSpec{ToolPattern: "*", Kind: "tool", Effect: effect}
		for _, k := range []string{"command", "path", "filename", "url"} {
			if v, ok := p.flags[k].(string); ok {
				spec.Kind = k
				spec.Value = v
			}
		}

		if raw, ok := p.flags["permission"].(string); ok {
			perms, bad := parsePermissions(raw)
			if bad != "" {
				return usageErr(`Unknown permission "` + bad + `". One or more of: READ, WRITE, EXECUTE, NETWORK`)
			}
			spec.Permission = perms
		}
		res, err := c.Policies.AddRule(ctx, id, spec)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(res)
			return 0, nil
		}
		if res.Deduped {
			errln(green("  ✓ ") + dim("Equivalent "+effect+" rule already present."))
			return 0, nil
		}
		ruleID := ""
		if res.Rule != nil {
			ruleID = res.Rule.ID
		}
		errln(green("  ✓ "+effect+" rule added") + dim(" ("+ruleID+")"))
		return 0, nil

	case "mode":

		id, mode := p.positional(1), strings.ToLower(p.positional(2))
		if id == "" || (mode != "denylist" && mode != "whitelist") {
			return usageErr("Usage: policy mode <id> <denylist|whitelist>")
		}
		pol, err := c.Policies.Get(ctx, id, 0)
		if err != nil {
			return 1, err
		}

		next := pol.PolicySet
		next.Mode = client.PolicyMode(mode)
		saved, err := c.Policies.Update(ctx, id, next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved)
			return 0, nil
		}
		okf("%s is now a %s policy", saved.ID, mode)
		if mode == "whitelist" && rulesCount(saved.Rules) == 0 {
			errln(dim("    It has no ALLOW rules, so it currently blocks everything."))
		}
		return 0, nil

	case "rule":

		id, ruleID, action := p.positional(1), p.positional(2), strings.ToLower(p.positional(3))
		if id == "" || ruleID == "" || (action != "enable" && action != "disable") {
			return usageErr("Usage: policy rule <id> <ruleId> <enable|disable>")
		}
		pol, err := c.Policies.Get(ctx, id, 0)
		if err != nil {
			return 1, err
		}
		next, found := setRuleEnabled(pol.PolicySet, ruleID, action == "enable")
		if !found {
			errln(red("  ✗ ") + `No rule "` + ruleID + `" in ` + id)
			if n := rulesCount(pol.Rules); n > 0 {
				errln(dim("  Rules in this policy:"))
				for _, r := range pol.Rules.Items {
					errln("    " + dim("•") + " " + r.ID)
				}
			}
			return 1, nil
		}
		saved, err := c.Policies.Update(ctx, id, next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(saved)
			return 0, nil
		}
		okf("Rule %s %sd", ruleID, action)
		return 0, nil

	case "revoke":
		id, ruleID := p.positional(1), p.positional(2)
		if id == "" || ruleID == "" {
			return usageErr("Usage: policy revoke <id> <ruleId>")
		}
		res, err := c.Policies.RevokeRule(ctx, id, ruleID)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(res)
			return 0, nil
		}
		okf("Revoked %s", ruleID)
		return 0, nil

	case "active":
		a, err := c.Policies.Active(ctx, "")
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(a)
			return 0, nil
		}
		if a.Policy == nil {
			errln(dim("  No active policy resolves for this project."))
			return 0, nil
		}
		errln("")
		errln("  Active: " + bold(a.Policy.Name) + " " + dim("("+a.Policy.ID+")"))
		matched := a.MatchedBy
		if matched == "" {
			matched = "-"
		}
		selfProt := dim("off")
		if a.SelfProtectionEnabled {
			selfProt = green("on")
		}
		errln("  matched by: " + cyan(matched) + "   self-protection: " + selfProt)
		if a.Security != nil && a.Security.RateLimit != nil {
			rl := a.Security.RateLimit
			errln("  rate limit: " + strconv.Itoa(rl.PerMinute) + "/min  " +
				strconv.Itoa(rl.PerHour) + "/h  " + strconv.Itoa(rl.PerDay) + "/day")
		}
		if a.Security != nil && a.Security.DLPBlock != nil {
			errln("  DLP block: " + strconv.Itoa(len(a.Security.DLPBlock.Patterns)) + " patterns")
		}
		return 0, nil

	case "activate":

		off := p.flagBool("off") || p.flagBool("clear")
		body := map[string]any{"policyId": ""}
		if !off {
			id := p.positional(1)
			if id == "" {
				return usageErr("Usage: policy activate <id>  |  policy activate --off")
			}
			body["policyId"] = id
		}
		id := ""
		if v, ok := body["policyId"].(string); ok {
			id = v
		}
		if err := c.Policies.SetActive(ctx, id); err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(mustJSON(map[string]any{"ok": true, "active": id}))
			return 0, nil
		}
		if off {
			okf("Deactivated. This project now enforces no policy.")
			errln(dim("    Pin one again with: solongate policy activate <id>"))
			return 0, nil
		}
		okf("Enforcing %s, it is this machine's policy file.", id)
		return 0, nil

	}

	return unknownSub("policy", sub, policyUsage())
}

func permScope(r client.PolicyRule) string {
	perms := r.Permissions()
	if len(perms) == 0 {
		return dim("any")
	}
	parts := make([]string, 0, len(perms))
	for _, p := range perms {
		parts = append(parts, string(p))
	}
	sort.Strings(parts)
	return strings.Join(parts, "+")
}

func printRules(rules client.Rules) {
	if rulesCount(rules) == 0 {
		errln(dim("  (no rules)"))
		return
	}
	out := make([][]string, 0, len(rules.Items))
	for _, r := range rules.Items {
		effect := decisionColor("DENY")
		if r.Effect == "ALLOW" {
			effect = green("ALLOW")
		}
		desc := r.Description
		if desc == "" {
			desc = "-"
		}
		kind, pattern := ruleMatch(r)
		out = append(out, []string{
			effect,
			strconv.Itoa(r.Priority),
			dim(r.ID),
			kind,
			permScope(r),
			truncate(pattern, 32),
			truncate(desc, 28),
		})
	}
	table([]string{"EFFECT", "PRIO", "ID", "ON", "PERM", "PATTERN", "DESCRIPTION"}, out)

	if rules.Unreadable > 0 {
		errln(dim("  (" + strconv.Itoa(rules.Unreadable) + " rule(s) this version cannot read, they are kept, and visible in ~/.solongate/policy.json)"))
	}
}

func rulesCount(r client.Rules) int {
	if r.Raw != nil {
		return len(r.Raw)
	}
	return len(r.Items)
}

func setRuleEnabled(pol client.PolicySet, ruleID string, enabled bool) (client.PolicySet, bool) {
	found := false
	raw := make([]json.RawMessage, len(pol.Rules.Raw))
	copy(raw, pol.Rules.Raw)

	for i, r := range raw {
		var probe struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(r, &probe) != nil || probe.ID != ruleID {
			continue
		}
		var obj map[string]json.RawMessage
		if json.Unmarshal(r, &obj) != nil {
			continue
		}
		obj["enabled"] = json.RawMessage(strconv.FormatBool(enabled))
		encoded, err := json.Marshal(obj)
		if err != nil {
			continue
		}
		raw[i] = encoded
		found = true
		break
	}
	if !found {
		return pol, false
	}
	pol.Rules = client.Rules{Raw: raw, Items: pol.Rules.Items}
	return pol, true
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func ruleMatch(r client.PolicyRule) (kind, pattern string) {
	for _, c := range []struct {
		name string
		set  *client.Constraint
	}{
		{"command", r.CommandConstraints},
		{"filename", r.FilenameConstraints},
		{"url", r.URLConstraints},
	} {
		if c.set == nil {
			continue
		}
		if len(c.set.Denied) > 0 {
			return c.name, strings.Join(c.set.Denied, ", ")
		}
		if len(c.set.Allowed) > 0 {
			return c.name, strings.Join(c.set.Allowed, ", ")
		}
	}
	if p := r.PathConstraints; p != nil {
		if len(p.Denied) > 0 {
			return "path", strings.Join(p.Denied, ", ")
		}
		if len(p.Allowed) > 0 {
			return "path", strings.Join(p.Allowed, ", ")
		}
	}
	if r.ToolPattern != "" && r.ToolPattern != "*" {
		return "tool", r.ToolPattern
	}
	return "tool", "*"
}