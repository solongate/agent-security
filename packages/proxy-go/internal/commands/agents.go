package commands

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func statusColor(s string) string {
	switch s {
	case "active":
		return green(s)
	case "idle":
		return yellow(s)
	}
	return dim(s)
}

// runSessions is `solongate sessions` — the live feed.
func runSessions(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	res, err := c.Agents.Live(ctx, p.flagNum("limit"), p.flagBool("all"))
	if err != nil {
		return 1, err
	}
	if p.flagBool("json") {
		printJSON(res)
		return 0, nil
	}
	errln("")
	errln("  Sessions   " + green(strconv.Itoa(res.Counts.Active)) + " active   " +
		yellow(strconv.Itoa(res.Counts.Idle)) + " idle   " +
		dim(strconv.Itoa(res.Counts.Deactivated)+" off"))
	if len(res.Agents) == 0 {
		errln(dim("  No agent sessions."))
		return 0, nil
	}
	rows := make([][]string, 0, len(res.Agents))
	for _, a := range res.Agents {
		// The identity falls back twice: a session that has not named itself is
		// still worth a row, and its session id is the only handle the operator
		// has for `solongate session <id>`.
		name := a.SessionID
		if a.AgentID != nil && *a.AgentID != "" {
			name = *a.AgentID
		}
		if a.AgentName != nil && *a.AgentName != "" {
			name = *a.AgentName
		}
		denied := dim("0")
		if a.DeniedCalls != 0 {
			denied = red(strconv.Itoa(a.DeniedCalls))
		}
		dlp := dim("0")
		if a.DLPEvents != 0 {
			dlp = red(strconv.Itoa(a.DLPEvents))
		}
		character := a.Character
		if character == "" {
			character = "-"
		}
		rows = append(rows, []string{
			statusColor(a.Status),
			cyan(truncate(name, 20)),
			strconv.Itoa(a.TotalCalls),
			denied,
			dlp,
			num(a.TrustScore),
			dim(truncate(character, 22)),
		})
	}
	table([]string{"STATUS", "AGENT", "CALLS", "DENY", "DLP", "TRUST", "CHARACTER"}, rows)
	return 0, nil
}

// agentDetail is the slice of /agents/:id this view renders. The endpoint's
// payload is rich and still moving, which is why the client hands back raw JSON;
// narrowing it here rather than in the client keeps the next field the API adds
// from being dropped for every other caller.
type agentDetail struct {
	AgentID  string `json:"agent_id"`
	Status   string `json:"status"`
	Baseline *struct {
		Character  string   `json:"character"`
		TrustScore *float64 `json:"trustScore"`
		DenyRate   float64  `json:"denyRate"`
	} `json:"baseline"`
	RecentFeed []struct {
		Decision  string  `json:"decision"`
		Tool      string  `json:"tool"`
		Reason    *string `json:"reason"`
		CreatedAt string  `json:"created_at"`
	} `json:"recent_feed"`
}

// runSession is `solongate session <id>` — deep detail for one agent.
func runSession(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	id := p.positional(0)
	if id == "" {
		return usageErr("Usage: solongate session <id> [--json]")
	}
	raw, err := c.Agents.Get(ctx, id, false)
	if err != nil {
		return 1, err
	}
	if p.flagBool("json") {
		printJSON(raw)
		return 0, nil
	}
	var a agentDetail
	if err := json.Unmarshal(raw, &a); err != nil {
		return 1, err
	}
	errln("")
	errln("  " + bold(a.AgentID) + "   status: " + statusColor(a.Status))
	if a.Baseline != nil {
		trust := "-"
		if a.Baseline.TrustScore != nil {
			trust = num(*a.Baseline.TrustScore)
		}
		errln("  " + dim(a.Baseline.Character) + "   trust " + bold(trust) + "/100   deny-rate " +
			fixed0(a.Baseline.DenyRate*100) + "%")
	}
	if len(a.RecentFeed) > 0 {
		errln(dim("\n  Recent:"))
		feed := a.RecentFeed[:min(15, len(a.RecentFeed))]
		rows := make([][]string, 0, len(feed))
		for _, f := range feed {
			decision := red(f.Decision)
			if f.Decision == "ALLOW" {
				decision = green("ALLOW")
			}
			rows = append(rows, []string{
				decision,
				cyan(truncate(f.Tool, 22)),
				truncate(deref(f.Reason, "-"), 30),
				dim(f.CreatedAt),
			})
		}
		table([]string{"DECISION", "TOOL", "REASON", "WHEN"}, rows)
	}
	return 0, nil
}
