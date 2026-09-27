package commands

import (
	"context"
	"strconv"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func statsUsage() string {
	return usage("solongate stats", "traffic & security stats", []usageRow{
		row("stats", "overview (totals, recent activity)"),
		line("stats timeseries [--period 24h|7d|30d|all]"),
		row("stats drift [--days N]", "denials rising/falling vs previous window"),
	})
}

func runStats(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "" {
		sub = "overview"
	}
	jsonOut := p.flagBool("json")

	switch sub {
	case "help":
		errln(statsUsage())
		return 0, nil

	case "overview":
		s, err := c.Stats.Get(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(s)
			return 0, nil
		}
		errln("")
		errln("  " + bold(strconv.Itoa(s.TotalCalls)) + " calls   " +
			green(strconv.Itoa(s.Allowed)) + " allowed   " +
			red(strconv.Itoa(s.Denied)) + " denied")
		errln("  " + dim(strconv.Itoa(s.ActivePolicies)+" active policies · "+
			strconv.Itoa(s.RegisteredTools)+" tools"))
		if len(s.RecentActivity) > 0 {
			errln(dim("\n  Recent:"))
			rows := make([][]string, 0, len(s.RecentActivity))
			for _, a := range s.RecentActivity {
				ms := "-"
				if a.EvaluationTimeMs != nil {
					ms = num(*a.EvaluationTimeMs)
				}
				rows = append(rows, []string{
					decisionColor(a.Decision),
					cyan(truncate(a.ToolName, 24)),
					dim(a.TrustLevel),
					ms,
					dim(a.CreatedAt),
				})
			}
			table([]string{"DECISION", "TOOL", "TRUST", "MS", "WHEN"}, rows)
		}
		return 0, nil

	case "timeseries":
		period := p.flagStr("period")
		if period == "" {
			period = "24h"
		}
		// Granularity is the API's choice: it is derived from the period, and
		// sending one would let a caller ask for a bucket size the period cannot
		// fill.
		ts, err := c.Stats.Timeseries(ctx, period, "")
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(ts)
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
		errln("")
		errln("  Timeseries " + dim("("+ts.Period+", per "+ts.Granularity+")"))
		errln("  total    " + cyan(sparkline(total)) + "  " + dim("max "+strconv.Itoa(peak)))
		errln("  allowed  " + green(sparkline(allowed)))
		errln("  denied   " + red(sparkline(denied)))
		return 0, nil

	case "drift":
		d, err := c.Stats.Drift(ctx, p.flagNum("days"))
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(d)
			return 0, nil
		}
		errln("")
		errln("  Denial drift " + dim("("+strconv.Itoa(d.Days)+"d: "+
			strconv.Itoa(d.TotalCurrent)+" now vs "+strconv.Itoa(d.TotalPrevious)+" prev)"))
		if len(d.Rules) == 0 {
			errln(dim("  No denials in window."))
			return 0, nil
		}
		rows := make([][]string, 0, min(20, len(d.Rules)))
		for _, r := range d.Rules[:min(20, len(d.Rules))] {
			delta := strconv.Itoa(r.Delta)
			switch {
			case r.IsNew:
				delta = green("NEW")
			case r.Spike:
				delta = red("+" + strconv.Itoa(r.Delta))
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
				bold(strconv.Itoa(r.Current)),
				dim(strconv.Itoa(r.Previous)),
				delta,
				cyan(truncate(ruleID, 22)),
				truncate(reason, 36),
			})
		}
		table([]string{"NOW", "PREV", "Δ", "RULE", "REASON"}, rows)
		return 0, nil
	}

	return unknownSub("stats", sub, statsUsage())
}
