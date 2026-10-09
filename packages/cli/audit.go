// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"strconv"

	"github.com/solongate/agent-security/packages/core/api"
)

func auditUsage() string {
	return usage("solongate audit", "audit log", []usageRow{
		line("audit [--filter ALLOW|DENY] [--tool <substr>] [--signal dlp|ratelimit]"),
		line("      [--search <text>] [--agent-name <name>] [--limit N]"),
		row("audit whitelist <logId> [--scope exact|tool]", "turn a denied call into an ALLOW rule"),
		row("audit block <logId> [--scope exact|tool]", "turn a call into a DENY rule"),
	})
}

func runAudit(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	jsonOut := p.flagBool("json")
	sub := p.positional(0)

	if sub == "help" {
		errln(auditUsage())
		return 0, nil
	}

	// whitelist and block are the same shape in both directions: take one logged
	// call and turn it into a rule. Which rule depends on `--scope`, and the
	// default is the narrow one — a whitelist that widened to the whole tool by
	// default would be a very quiet way to disarm a policy.
	if sub == "whitelist" || sub == "block" {
		id := p.positional(1)
		if id == "" {
			return usageErr("Usage: audit " + sub + " <logId> [--scope exact|tool]")
		}
		scope := p.flagStr("scope")
		if scope == "" {
			scope = "exact"
		}
		var (
			res  api.RuleMutation
			err  error
			verb = "Whitelisted"
			kind = "ALLOW"
		)
		if sub == "whitelist" {
			res, err = c.Audit.Whitelist(ctx, id, scope)
		} else {
			verb, kind = "Blocked", "DENY"
			res, err = c.Audit.Block(ctx, id, scope)
		}
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(res)
			return 0, nil
		}
		if res.Deduped {
			errln(green("  ✓ ") + dim("Equivalent "+kind+" already present."))
			return 0, nil
		}
		errln(green("  ✓ "+verb+" ("+scope+")") +
			dim(" → "+res.PolicyID+" v"+strconv.Itoa(res.PolicyVersion)))
		return 0, nil
	}

	limit, ok := p.flagNumOK("limit")
	if !ok {
		limit = 30
	}
	res, err := c.Audit.List(ctx, api.AuditQuery{
		Filter:    p.flagStr("filter"),
		Tool:      p.flagStr("tool"),
		Signal:    p.flagStr("signal"),
		Search:    p.flagStr("search"),
		AgentName: p.flagStr("agent-name"),
		Limit:     limit,
	})
	if err != nil {
		return 1, err
	}
	if jsonOut {
		printJSON(res)
		return 0, nil
	}
	errln("")
	errln("  " + bold(strconv.Itoa(res.Total)) + " matching entries " +
		dim("(showing "+strconv.Itoa(len(res.Entries))+")"))
	if len(res.Entries) == 0 {
		return 0, nil
	}
	rows := make([][]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		dlp := dim("0")
		if len(e.DLPMatches) > 0 {
			dlp = red(strconv.Itoa(len(e.DLPMatches)))
		}
		rows = append(rows, []string{
			decisionColor(e.Decision),
			cyan(truncate(e.ToolName, 22)),
			dim(truncate(deref(e.AgentName, "-"), 16)),
			truncate(deref(e.Reason, "-"), 30),
			dlp,
			dim(e.CreatedAt),
			dim(truncate(e.ID, 10)),
		})
	}
	table([]string{"DECISION", "TOOL", "AGENT", "REASON", "DLP", "WHEN", "ID"}, rows)
	return 0, nil
}

// deref renders an optional string, falling back when the API sent null. It is
// the `?? '-'` that appears in nearly every table cell.
func deref(s *string, fallback string) string {
	if s == nil || *s == "" {
		return fallback
	}
	return *s
}
