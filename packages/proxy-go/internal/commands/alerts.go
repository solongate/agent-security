package commands

import (
	"context"
	"strconv"
	"strings"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func alertsUsage() string {
	return usage("solongate alerts", "spike alerts (Telegram / email)", []usageRow{
		line("alerts list"),
		line("alerts add --signal deny|dlp|ratelimit|any --threshold N --window S"),
		line("             (--email <a> | --telegram <chatId> | --slack <url>)"),
		line("alerts remove <id>"),
	})
}

func runAlerts(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "" {
		sub = "list"
	}
	jsonOut := p.flagBool("json")

	switch sub {
	case "help":
		errln(alertsUsage())
		return 0, nil

	case "list":
		rules, err := c.Settings.GetAlerts(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(rules)
			return 0, nil
		}
		if len(rules) == 0 {
			errln(dim("  No alert rules."))
			return 0, nil
		}
		rows := make([][]string, 0, len(rules))
		for _, r := range rules {
			on := dim("○")
			if r.Enabled {
				on = green("●")
			}
			// Slack URLs are listed as the word "slack" and never printed: an
			// incoming-webhook URL is a credential, and this list is the kind of
			// output that ends up in a support thread.
			channels := append([]string{}, r.Emails...)
			for _, t := range r.Telegram {
				channels = append(channels, "tg:"+t)
			}
			for range r.SlackUrls {
				channels = append(channels, "slack")
			}
			joined := strings.Join(channels, " ")
			if joined == "" {
				joined = "-"
			}
			rows = append(rows, []string{
				dim(r.ID),
				on,
				cyan(r.Signal),
				strconv.Itoa(r.Threshold),
				strconv.Itoa(r.WindowSeconds) + "s",
				dim(joined),
			})
		}
		table([]string{"ID", "ON", "SIGNAL", "THRESH", "WINDOW", "CHANNELS"}, rows)
		return 0, nil

	case "add":
		email, telegram, slack := p.flagStr("email"), p.flagStr("telegram"), p.flagStr("slack")
		if email == "" && telegram == "" && slack == "" {
			return usageErr("Need a channel: --email / --telegram / --slack")
		}
		signal := p.flagStr("signal")
		if signal == "" {
			signal = "deny"
		}
		threshold, ok := p.flagNumOK("threshold")
		if !ok {
			threshold = 5
		}
		window, ok := p.flagNumOK("window")
		if !ok {
			window = 300
		}
		body := map[string]any{
			"signal":        signal,
			"threshold":     threshold,
			"windowSeconds": window,
		}
		if email != "" {
			body["emails"] = []string{email}
		}
		if telegram != "" {
			body["telegram"] = []string{telegram}
		}
		if slack != "" {
			body["slackUrl"] = slack
		}
		rule, err := c.Settings.CreateAlert(ctx, body)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(rule)
			return 0, nil
		}
		okf("Alert added (%s, %d/%ds)", rule.Signal, rule.Threshold, rule.WindowSeconds)
		return 0, nil

	case "remove":
		id := p.positional(1)
		if id == "" {
			return usageErr("Usage: alerts remove <id>")
		}
		if err := c.Settings.DeleteAlert(ctx, id); err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(map[string]any{"ok": true, "id": id})
			return 0, nil
		}
		okf("Removed %s", id)
		return 0, nil
	}

	return unknownSub("alerts", sub, alertsUsage())
}
