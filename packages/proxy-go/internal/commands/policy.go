package commands

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func policyUsage() string {
	return usageWith("solongate policy", "manage cloud policies", []usageRow{
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
		row("policy dry-run <id|file.json> [--limit N] [--mode denylist|whitelist]", "replay recent traffic against rules"),
	}, "Add --json to any read command for machine-readable output.")
}

// parsePermissions reads `--permission read,WRITE` into the four classes the
// guard derives, or names the first value it does not recognise.
//
// Case-insensitive and comma-separated, and a typo is refused rather than
// dropped: a permission the guard has no name for would be stored, never match,
// and leave a rule that reads correctly in `policy show` and enforces nothing.
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

func runPolicy(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	jsonOut := p.flagBool("json")

	switch sub {
	case "", "help":
		errln(policyUsage())
		// A bare `policy` is a mistake and exits 1; `policy help` is what was
		// asked for and exits 0.
		if sub == "" {
			return 1, nil
		}
		return 0, nil

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
			errln(dim("  No policies. Create one at https://dashboard.solongate.com"))
			return 0, nil
		}
		rows := make([][]string, 0, len(policies))
		for _, pol := range policies {
			mode := "denylist"
			if pol.Mode == api.ModeWhitelist {
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
		if pol.Mode == api.ModeWhitelist {
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
		// The id is generated here rather than by the API, matching the Node CLI.
		// Changing that would give two clients two id schemes for the same action.
		res, err := c.Policies.Create(ctx, api.PolicySet{
			ID:   "policy-" + strconv.FormatInt(nowMillis(), 10),
			Name: name,
			Mode: api.ModeDenylist,
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
		// Raw, because the typed Remove discards the body and the confirmation
		// line echoes the id the API says it deleted rather than the one asked
		// for — the difference matters when the API resolves an alias.
		var raw json.RawMessage
		if err := c.Do(ctx, http.MethodDelete, "/policies/"+esc(id), api.RequestOptions{}, &raw); err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(raw)
			return 0, nil
		}
		var res struct {
			PolicyID string `json:"policy_id"`
		}
		_ = json.Unmarshal(raw, &res)
		if res.PolicyID == "" {
			res.PolicyID = id
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
		// No constraint flag means a rule about the TOOL itself, which is what
		// `kind: tool` with no value means to the API. The last flag given wins,
		// matching the loop in the TypeScript.
		spec := api.RuleSpec{ToolPattern: "*", Kind: "tool", Effect: effect}
		for _, k := range []string{"command", "path", "filename", "url"} {
			if v, ok := p.flags[k].(string); ok {
				spec.Kind = k
				spec.Value = v
			}
		}

		// Permission scoping, which until now was reachable only from the
		// dataroom -- so a rule set could not be written down as commands, which
		// is what a runbook and a CI check both need.
		//
		// It is worth knowing what you are asking for before you use it. The
		// class comes from the TOOL NAME, so it is a statement about which tools
		// a rule covers, not about what the call does: Codex has no read tool and
		// shells out instead, so a READ-scoped rule matches nothing there, and
		// Antigravity's URL tool is `read_url_content`, which classifies as READ
		// rather than NETWORK. Scope by constraint unless you specifically mean
		// "only calls made with this kind of tool".
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
		// The mode was a dataroom toggle, so a whitelist policy could not be set
		// up from a script at all -- and whitelist is the mode with the most
		// consequential default: nothing is allowed until a rule says so.
		id, mode := p.positional(1), strings.ToLower(p.positional(2))
		if id == "" || (mode != "denylist" && mode != "whitelist") {
			return usageErr("Usage: policy mode <id> <denylist|whitelist>")
		}
		pol, err := c.Policies.Get(ctx, id, 0)
		if err != nil {
			return 1, err
		}
		// The rules go back as the RAW bytes that arrived. Re-encoding them
		// through this version's struct would quietly drop any field it does not
		// know about, and a policy edited by a newer dashboard is exactly the
		// case where that matters.
		next := pol.PolicySet
		next.Mode = api.PolicyMode(mode)
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
		// Turning a rule off without deleting it: the dataroom has always had
		// this and the CLI had only revoke, which loses the rule.
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
		// The typed SetActive discards `{ ok, active }`, and `active` is both the
		// confirmation line and the whole --json document.
		//
		// `--off` does not return the project to automatic selection. An empty
		// policyId makes the server store its `__none__` sentinel, which means
		// "this project enforces nothing" -- a different state from having no
		// override at all, and there is no route back to the latter short of
		// pinning a policy again. Calling that "cleared the pin" sent people
		// looking for a policy that had in fact been switched off.
		off := p.flagBool("off") || p.flagBool("clear")
		body := map[string]any{"policyId": ""}
		if !off {
			id := p.positional(1)
			if id == "" {
				return usageErr("Usage: policy activate <id>  |  policy activate --off")
			}
			body["policyId"] = id
		}
		var raw json.RawMessage
		if err := c.Do(ctx, http.MethodPost, "/policies/active", api.RequestOptions{Body: body}, &raw); err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(raw)
			return 0, nil
		}
		if off {
			okf("Deactivated - this project now enforces no policy.")
			errln(dim("    Pin one again with: solongate policy activate <id>"))
			return 0, nil
		}
		var res struct {
			Active *string `json:"active"`
		}
		_ = json.Unmarshal(raw, &res)
		active := body["policyId"].(string)
		if res.Active != nil {
			active = *res.Active
		}
		okf("Pinned active policy → %s", active)
		return 0, nil

	case "dry-run":
		target := p.positional(1)
		if target == "" {
			return usageErr("Usage: policy dry-run <id|file.json> [--limit N]")
		}
		rules, err := resolveRules(ctx, c, target)
		if err != nil {
			return 1, err
		}
		res, err := c.Policies.DryRun(ctx, api.DryRunBody{
			Rules: rules,
			Mode:  api.PolicyMode(p.flagStr("mode")),
			Limit: p.flagNum("limit"),
		})
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(res)
			return 0, nil
		}
		errln("")
		errln("  Replayed " + bold(strconv.Itoa(res.Evaluated)) + " recent calls against " +
			strconv.Itoa(len(rules)) + " rule(s)")
		errln("  would allow: " + green(strconv.Itoa(res.WouldAllow)) +
			"   would deny: " + decisionColor("DENY") + " " + strconv.Itoa(res.WouldDeny))
		errln("  " + green("newly allowed") + ": " + strconv.Itoa(res.NewlyAllowed) +
			"   " + decisionColor("DENY") + dim(" newly blocked") + ": " + strconv.Itoa(res.NewlyBlocked) +
			"   unchanged: " + strconv.Itoa(res.Unchanged))
		if len(res.SampleNewlyBlocked) > 0 {
			errln(dim("\n  Sample newly-blocked:"))
			for _, s := range res.SampleNewlyBlocked[:min(8, len(res.SampleNewlyBlocked))] {
				errln("    " + decisionColor("DENY") + " " + s.Tool + "  " + dim(truncate(s.Preview, 50)))
			}
		}
		return 0, nil
	}

	return unknownSub("policy", sub, policyUsage())
}

func printRules(rules api.Rules) {
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
		out = append(out, []string{
			effect,
			strconv.Itoa(r.Priority),
			dim(r.ID),
			truncate(desc, 40),
		})
	}
	table([]string{"EFFECT", "PRIO", "ID", "DESCRIPTION"}, out)
	// A rule that will not decode is still enforced by the cloud. Printing the
	// readable ones and saying nothing would show a policy that looks narrower
	// than the one actually in force.
	if rules.Unreadable > 0 {
		errln(dim("  (" + strconv.Itoa(rules.Unreadable) + " rule(s) this version cannot read — see them in the dashboard)"))
	}
}

// rulesCount is how many rules the API sent, including any this version could
// not decode. len(Items) would under-report exactly when it matters most.
func rulesCount(r api.Rules) int {
	if r.Raw != nil {
		return len(r.Raw)
	}
	return len(r.Items)
}

// resolveRules reads a dry-run target: a local JSON file, or a policy id whose
// rules are fetched.
//
// The rules are passed through as the raw bytes they arrived as. Decoding and
// re-encoding them would drop any field this version does not model, and the
// replay would then be run against a policy that is not the one on screen.
func resolveRules(ctx context.Context, c *api.Client, target string) ([]json.RawMessage, error) {
	if strings.HasSuffix(target, ".json") {
		b, err := os.ReadFile(target)
		if err != nil {
			return nil, err
		}
		var parsed struct {
			Rules []json.RawMessage `json:"rules"`
		}
		if err := json.Unmarshal(b, &parsed); err != nil {
			return nil, err
		}
		return parsed.Rules, nil
	}
	pol, err := c.Policies.Get(ctx, target, 0)
	if err != nil {
		return nil, err
	}
	return pol.Rules.Raw, nil
}

// setRuleEnabled flips one rule's `enabled` flag, returning the policy to send
// back and whether the rule was there at all.
//
// It edits the RAW rule bytes rather than re-encoding this version's struct.
// Rules.MarshalJSON writes Raw back when it is held, so a policy carrying a
// field this build does not know about survives the round trip -- and a rule
// editor in a newer dashboard is exactly what puts one there. Rewriting the
// whole array through PolicyRule would silently drop it.
func setRuleEnabled(pol api.PolicySet, ruleID string, enabled bool) (api.PolicySet, bool) {
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
	pol.Rules = api.Rules{Raw: raw, Items: pol.Rules.Items}
	return pol, true
}
