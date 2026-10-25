// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package observability

import (
	"context"
	"strconv"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

func auditUsage() string {
	return cliutil.Usage("solongate audit", "audit log", []cliutil.UsageRow{
		cliutil.Line("audit [--filter ALLOW|DENY] [--tool <substr>] [--signal dlp|ratelimit]"),
		cliutil.Line("      [--search <text>] [--agent-name <name>] [--limit N]"),
		cliutil.Row("audit whitelist <logId> [--scope exact|tool]", "turn a denied call into an ALLOW rule"),
		cliutil.Row("audit block <logId> [--scope exact|tool]", "turn a call into a DENY rule"),
	})
}

func RunAudit(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	jsonOut := p.FlagBool("json")
	sub := p.Positional(0)

	if sub == "help" {
		cliutil.Errln(auditUsage())
		return 0, nil
	}

	if sub == "whitelist" || sub == "block" {
		id := p.Positional(1)
		if id == "" {
			return cliutil.UsageErr("Usage: audit " + sub + " <logId> [--scope exact|tool]")
		}
		scope := p.FlagStr("scope")
		if scope == "" {
			scope = "exact"
		}
		var (
			res  client.RuleMutation
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
			cliutil.PrintJSON(res)
			return 0, nil
		}
		if res.Deduped {
			cliutil.Errln(cliutil.Green("  ✓ ") + cliutil.Dim("Equivalent "+kind+" already present."))
			return 0, nil
		}
		cliutil.Errln(cliutil.Green("  ✓ "+verb+" ("+scope+")") +
			cliutil.Dim(" → "+res.PolicyID+" v"+strconv.Itoa(res.PolicyVersion)))
		return 0, nil
	}

	limit, ok := p.FlagNumOK("limit")
	if !ok {
		limit = 30
	}
	res, err := c.Audit.List(ctx, client.AuditQuery{
		Filter:    p.FlagStr("filter"),
		Tool:      p.FlagStr("tool"),
		Signal:    p.FlagStr("signal"),
		Search:    p.FlagStr("search"),
		AgentName: p.FlagStr("agent-name"),
		Limit:     limit,
	})
	if err != nil {
		return 1, err
	}
	if jsonOut {
		cliutil.PrintJSON(res)
		return 0, nil
	}
	cliutil.Errln("")
	cliutil.Errln("  " + cliutil.Bold(strconv.Itoa(res.Total)) + " matching entries " +
		cliutil.Dim("(showing "+strconv.Itoa(len(res.Entries))+")"))
	if len(res.Entries) == 0 {
		return 0, nil
	}
	rows := make([][]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		dlp := cliutil.Dim("0")
		if len(e.DLPMatches) > 0 {
			dlp = cliutil.Red(strconv.Itoa(len(e.DLPMatches)))
		}
		rows = append(rows, []string{
			cliutil.DecisionColor(e.Decision),
			cliutil.Cyan(cliutil.Truncate(e.ToolName, 22)),
			cliutil.Dim(cliutil.Truncate(deref(e.AgentName, "-"), 16)),
			cliutil.Truncate(deref(e.Reason, "-"), 30),
			dlp,
			cliutil.Dim(e.CreatedAt),
			cliutil.Dim(cliutil.Truncate(e.ID, 10)),
		})
	}
	cliutil.Table([]string{"DECISION", "TOOL", "AGENT", "REASON", "DLP", "WHEN", "ID"}, rows)
	return 0, nil
}

func deref(s *string, fallback string) string {
	if s == nil || *s == "" {
		return fallback
	}
	return *s
}
