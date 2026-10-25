// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package policy

import (
	"context"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

var nowMillis = func() int64 { return time.Now().UnixMilli() }

func policyUsage() string {
	return cliutil.UsageWith("solongate policy", "read and edit this machine's policy", []cliutil.UsageRow{
		cliutil.Row("policy list", "list all policies"),
		cliutil.Row("policy create <name>", "create a new empty policy"),
		cliutil.Row("policy delete <id>", "delete a policy"),
		cliutil.Row("policy show <id>", "show one policy (rules, mode)"),
		cliutil.Row("policy allow <id> [--command|--path|--filename|--url <val>]", "append an ALLOW rule"),
		cliutil.Row("policy deny  <id> [--command|--path|--filename|--url <val>]", "append a DENY rule"),
		cliutil.Row("policy revoke <id> <ruleId>", "remove a rule"),
		cliutil.Row("policy active", "show the resolved active policy"),
		cliutil.Row("", ""),
		cliutil.Row("  --permission READ,WRITE,EXECUTE,NETWORK", "scope allow/deny to a class of call"),
		cliutil.Row("", ""),
		cliutil.Row("policy mode <id> <denylist|whitelist>", "switch a policy between deny-by-default and allow-by-default"),
		cliutil.Row("policy rule <id> <ruleId> <enable|disable>", "turn one rule on or off without deleting it"),
		cliutil.Row("", ""),
		cliutil.Row("policy activate <id> | --off", "pin the active policy, or enforce nothing"),
		cliutil.Row("", ""),
		cliutil.Row("policy protect <path>", "add a path, and lock it with the OS"),
		cliutil.Row("policy protect list", "every protected path, and what is holding it"),
		cliutil.Row("policy protect remove <path>", "drop a path and lift its lock"),
		cliutil.Row("policy protect require-sandbox on|off", "refuse calls from agents not started by `solongate run`"),
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

func Run(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	sub := p.Positional(0)
	jsonOut := p.FlagBool("json")

	switch sub {
	case "", "help":
		cliutil.Errln(policyUsage())

		if sub == "" {
			return 1, nil
		}
		return 0, nil

	case "protect":
		return runProtect(ctx, c, p.Tail(1))

	case "list":
		policies, err := c.Policies.List(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(policies)
			return 0, nil
		}
		if len(policies) == 0 {
			cliutil.Errln(cliutil.Dim("  No policies. `solongate policy create <name>` makes one."))
			return 0, nil
		}
		rows := make([][]string, 0, len(policies))
		for _, pol := range policies {
			mode := "denylist"
			if pol.Mode == client.ModeWhitelist {
				mode = cliutil.Green("whitelist")
			}
			by := pol.CreatedBy
			if by == "" {
				by = "-"
			}
			rows = append(rows, []string{
				cliutil.Cyan(pol.ID),
				cliutil.Truncate(pol.Name, 28),
				mode,
				strconv.Itoa(rulesCount(pol.Rules)),
				cliutil.Dim(cliutil.Truncate(by, 20)),
			})
		}
		cliutil.Table([]string{"ID", "NAME", "MODE", "RULES", "UPDATED BY"}, rows)
		return 0, nil

	case "show":
		id := p.Positional(1)
		if id == "" {
			return cliutil.UsageErr("Usage: policy show <id>")
		}
		pol, err := c.Policies.Get(ctx, id, 0)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(pol)
			return 0, nil
		}
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Bold(pol.Name) + " " + cliutil.Dim("("+pol.ID+")"))
		if pol.Description != "" {
			cliutil.Errln("  " + cliutil.Dim(pol.Description))
		}
		mode := "denylist"
		if pol.Mode == client.ModeWhitelist {
			mode = cliutil.Green("whitelist")
		}
		cliutil.Errln("  mode: " + mode + "   rules: " + strconv.Itoa(rulesCount(pol.Rules)))
		cliutil.Errln("")
		printRules(pol.Rules)
		return 0, nil

	case "create":
		name := p.Rest(1)
		if name == "" {
			return cliutil.UsageErr("Usage: policy create <name>")
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
			cliutil.PrintJSON(res)
			return 0, nil
		}
		cliutil.Errln(cliutil.Green(`  ✓ Created "`+name+`"`) + cliutil.Dim(" ("+res.ID+")"))
		return 0, nil

	case "delete":
		id := p.Positional(1)
		if id == "" {
			return cliutil.UsageErr("Usage: policy delete <id>")
		}

		if err := c.Policies.Remove(ctx, id); err != nil {
			return 1, err
		}
		res := struct {
			PolicyID string `json:"policy_id"`
		}{PolicyID: id}
		if jsonOut {
			cliutil.PrintJSON(mustJSON(map[string]any{"deleted": true, "policy_id": id}))
			return 0, nil
		}
		cliutil.Okf("Deleted %s", res.PolicyID)
		return 0, nil

	case "allow", "deny":
		effect := "DENY"
		if sub == "allow" {
			effect = "ALLOW"
		}
		id := p.Positional(1)
		if id == "" {
			return cliutil.UsageErr("Usage: policy " + sub + " <id> [--command|--path|--filename|--url <val>]")
		}

		spec := client.RuleSpec{ToolPattern: "*", Kind: "tool", Effect: effect}
		for _, k := range []string{"command", "path", "filename", "url"} {
			if v, ok := p.FlagStrOK(k); ok {
				spec.Kind = k
				spec.Value = v
			}
		}

		if raw, ok := p.FlagStrOK("permission"); ok {
			perms, bad := parsePermissions(raw)
			if bad != "" {
				return cliutil.UsageErr(`Unknown permission "` + bad + `". One or more of: READ, WRITE, EXECUTE, NETWORK`)
			}
			spec.Permission = perms
		}
		res, err := c.Policies.AddRule(ctx, id, spec)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(res)
			return 0, nil
		}
		if res.Deduped {
			cliutil.Errln(cliutil.Green("  ✓ ") + cliutil.Dim("Equivalent "+effect+" rule already present."))
			return 0, nil
		}
		ruleID := ""
		if res.Rule != nil {
			ruleID = res.Rule.ID
		}
		cliutil.Errln(cliutil.Green("  ✓ "+effect+" rule added") + cliutil.Dim(" ("+ruleID+")"))
		return 0, nil

	case "mode":

		id, mode := p.Positional(1), strings.ToLower(p.Positional(2))
		if id == "" || (mode != "denylist" && mode != "whitelist") {
			return cliutil.UsageErr("Usage: policy mode <id> <denylist|whitelist>")
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
			cliutil.PrintJSON(saved)
			return 0, nil
		}
		cliutil.Okf("%s is now a %s policy", saved.ID, mode)
		if mode == "whitelist" && rulesCount(saved.Rules) == 0 {
			cliutil.Errln(cliutil.Dim("    It has no ALLOW rules, so it currently blocks everything."))
		}
		return 0, nil

	case "rule":

		id, ruleID, action := p.Positional(1), p.Positional(2), strings.ToLower(p.Positional(3))
		if id == "" || ruleID == "" || (action != "enable" && action != "disable") {
			return cliutil.UsageErr("Usage: policy rule <id> <ruleId> <enable|disable>")
		}
		pol, err := c.Policies.Get(ctx, id, 0)
		if err != nil {
			return 1, err
		}
		next, found := setRuleEnabled(pol.PolicySet, ruleID, action == "enable")
		if !found {
			cliutil.Errln(cliutil.Red("  ✗ ") + `No rule "` + ruleID + `" in ` + id)
			if n := rulesCount(pol.Rules); n > 0 {
				cliutil.Errln(cliutil.Dim("  Rules in this policy:"))
				for _, r := range pol.Rules.Items {
					cliutil.Errln("    " + cliutil.Dim("•") + " " + r.ID)
				}
			}
			return 1, nil
		}
		saved, err := c.Policies.Update(ctx, id, next)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(saved)
			return 0, nil
		}
		cliutil.Okf("Rule %s %sd", ruleID, action)
		return 0, nil

	case "revoke":
		id, ruleID := p.Positional(1), p.Positional(2)
		if id == "" || ruleID == "" {
			return cliutil.UsageErr("Usage: policy revoke <id> <ruleId>")
		}
		res, err := c.Policies.RevokeRule(ctx, id, ruleID)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(res)
			return 0, nil
		}
		cliutil.Okf("Revoked %s", ruleID)
		return 0, nil

	case "active":
		a, err := c.Policies.Active(ctx, "")
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(a)
			return 0, nil
		}
		if a.Policy == nil {
			cliutil.Errln(cliutil.Dim("  No active policy resolves for this project."))
			return 0, nil
		}
		cliutil.Errln("")
		cliutil.Errln("  Active: " + cliutil.Bold(a.Policy.Name) + " " + cliutil.Dim("("+a.Policy.ID+")"))
		matched := a.MatchedBy
		if matched == "" {
			matched = "-"
		}
		selfProt := cliutil.Dim("off")
		if a.SelfProtectionEnabled {
			selfProt = cliutil.Green("on")
		}
		cliutil.Errln("  matched by: " + cliutil.Cyan(matched) + "   self-protection: " + selfProt)
		if a.Security != nil && a.Security.RateLimit != nil {
			rl := a.Security.RateLimit
			cliutil.Errln("  rate limit: " + strconv.Itoa(rl.PerMinute) + "/min  " +
				strconv.Itoa(rl.PerHour) + "/h  " + strconv.Itoa(rl.PerDay) + "/day")
		}
		if a.Security != nil && a.Security.DLPBlock != nil {
			cliutil.Errln("  DLP block: " + strconv.Itoa(len(a.Security.DLPBlock.Patterns)) + " patterns")
		}
		return 0, nil

	case "activate":

		off := p.FlagBool("off") || p.FlagBool("clear")
		body := map[string]any{"policyId": ""}
		if !off {
			id := p.Positional(1)
			if id == "" {
				return cliutil.UsageErr("Usage: policy activate <id>  |  policy activate --off")
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
			cliutil.PrintJSON(mustJSON(map[string]any{"ok": true, "active": id}))
			return 0, nil
		}
		if off {
			cliutil.Okf("Deactivated. This project now enforces no policy.")
			cliutil.Errln(cliutil.Dim("    Pin one again with: solongate policy activate <id>"))
			return 0, nil
		}
		cliutil.Okf("Enforcing %s, it is this machine's policy file.", id)
		return 0, nil

	}

	return cliutil.UnknownSub("policy", sub, policyUsage())
}

func permScope(r client.PolicyRule) string {
	perms := r.Permissions()
	if len(perms) == 0 {
		return cliutil.Dim("any")
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
		cliutil.Errln(cliutil.Dim("  (no rules)"))
		return
	}
	out := make([][]string, 0, len(rules.Items))
	for _, r := range rules.Items {
		effect := cliutil.DecisionColor("DENY")
		if r.Effect == "ALLOW" {
			effect = cliutil.Green("ALLOW")
		}
		desc := r.Description
		if desc == "" {
			desc = "-"
		}
		kind, pattern := ruleMatch(r)
		out = append(out, []string{
			effect,
			strconv.Itoa(r.Priority),
			cliutil.Dim(r.ID),
			kind,
			permScope(r),
			cliutil.Truncate(pattern, 32),
			cliutil.Truncate(desc, 28),
		})
	}
	cliutil.Table([]string{"EFFECT", "PRIO", "ID", "ON", "PERM", "PATTERN", "DESCRIPTION"}, out)

	if rules.Unreadable > 0 {
		cliutil.Errln(cliutil.Dim("  (" + strconv.Itoa(rules.Unreadable) + " rule(s) this version cannot read, they are kept, and visible in ~/.solongate/policy.json)"))
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
