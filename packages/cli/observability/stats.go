// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package observability

import (
	"context"
	"strconv"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/core/client"
)

func statsUsage() string {
	return cliutil.Usage("solongate stats", "traffic & security stats", []cliutil.UsageRow{
		cliutil.Row("stats", "overview (totals, recent activity)"),
		cliutil.Line("stats timeseries [--period 24h|7d|30d|all]"),
		cliutil.Row("stats drift [--days N]", "denials rising/falling vs previous window"),
	})
}

func RunStats(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error) {
	sub := p.Positional(0)
	if sub == "" {
		sub = "overview"
	}
	jsonOut := p.FlagBool("json")

	switch sub {
	case "help":
		cliutil.Errln(statsUsage())
		return 0, nil

	case "overview":
		s, err := c.Stats.Get(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(s)
			return 0, nil
		}
		cliutil.Errln("")
		cliutil.Errln("  " + cliutil.Bold(strconv.Itoa(s.TotalCalls)) + " calls   " +
			cliutil.Green(strconv.Itoa(s.Allowed)) + " allowed   " +
			cliutil.Red(strconv.Itoa(s.Denied)) + " denied")
		cliutil.Errln("  " + cliutil.Dim(strconv.Itoa(s.ActivePolicies)+" active policies · "+
			strconv.Itoa(s.RegisteredTools)+" tools"))
		if len(s.RecentActivity) > 0 {
			cliutil.Errln(cliutil.Dim("\n  Recent:"))
			rows := make([][]string, 0, len(s.RecentActivity))
			for _, a := range s.RecentActivity {
				ms := "-"
				if a.EvaluationTimeMs != nil {
					ms = cliutil.Num(*a.EvaluationTimeMs)
				}
				rows = append(rows, []string{
					cliutil.DecisionColor(a.Decision),
					cliutil.Cyan(cliutil.Truncate(a.ToolName, 24)),
					cliutil.Dim(a.TrustLevel),
					ms,
					cliutil.Dim(a.CreatedAt),
				})
			}
			cliutil.Table([]string{"DECISION", "TOOL", "TRUST", "MS", "WHEN"}, rows)
		}
		return 0, nil

	case "timeseries":
		period := p.FlagStr("period")
		if period == "" {
			period = "24h"
		}

		ts, err := c.Stats.Timeseries(ctx, period, "")
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(ts)
			return 0, nil
		}
		total := make([]int, 0, len(ts.Timeseries))
		allowed := make([]int, 0, len(ts.Timeseries))
		denied := make([]int, 0, len(ts.Timeseries))
		peak := 0
		for _, pt := range ts.Timeseries {
			total = append(total, pt.Total)
			allowed = append(allowed, pt.Allowed)
			denied = append(denied, pt.Denied)
			peak = max(peak, pt.Total)
		}
		cliutil.Errln("")
		cliutil.Errln("  Timeseries " + cliutil.Dim("("+ts.Period+", per "+ts.Granularity+")"))
		cliutil.Errln("  total    " + cliutil.Cyan(cliutil.Sparkline(total)) + "  " + cliutil.Dim("max "+strconv.Itoa(peak)))
		cliutil.Errln("  allowed  " + cliutil.Green(cliutil.Sparkline(allowed)))
		cliutil.Errln("  denied   " + cliutil.Red(cliutil.Sparkline(denied)))
		return 0, nil

	case "drift":
		d, err := c.Stats.Drift(ctx, p.FlagNum("days"))
		if err != nil {
			return 1, err
		}
		if jsonOut {
			cliutil.PrintJSON(d)
			return 0, nil
		}
		cliutil.Errln("")
		cliutil.Errln("  Denial drift " + cliutil.Dim("("+strconv.Itoa(d.Days)+"d: "+
			strconv.Itoa(d.TotalCurrent)+" now vs "+strconv.Itoa(d.TotalPrevious)+" prev)"))
		if len(d.Rules) == 0 {
			cliutil.Errln(cliutil.Dim("  No denials in window."))
			return 0, nil
		}
		rows := make([][]string, 0, min(20, len(d.Rules)))
		for _, r := range d.Rules[:min(20, len(d.Rules))] {
			delta := strconv.Itoa(r.Delta)
			switch {
			case r.IsNew:
				delta = cliutil.Green("NEW")
			case r.Spike:
				delta = cliutil.Red("+" + strconv.Itoa(r.Delta))
			}
			ruleID := "-"
			if r.RuleID != nil && *r.RuleID != "" {
				ruleID = *r.RuleID
			}
			reason := "-"
			if r.Reason != nil && *r.Reason != "" {
				reason = *r.Reason
			} else if r.LastTool != nil && *r.LastTool != "" {
				reason = *r.LastTool
			}
			rows = append(rows, []string{
				cliutil.Bold(strconv.Itoa(r.Current)),
				cliutil.Dim(strconv.Itoa(r.Previous)),
				delta,
				cliutil.Cyan(cliutil.Truncate(ruleID, 22)),
				cliutil.Truncate(reason, 36),
			})
		}
		cliutil.Table([]string{"NOW", "PREV", "Δ", "RULE", "REASON"}, rows)
		return 0, nil
	}

	return cliutil.UnknownSub("stats", sub, statsUsage())
}
