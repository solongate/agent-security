package commands

import (
	"context"

	"github.com/codeyevsky/solongate/proxy/internal/api"
)

func webhooksUsage() string {
	return usage("solongate webhooks", "event webhooks", []usageRow{
		line("webhooks list"),
		line("webhooks add --url <https://…> [--events denials|allowed|all]"),
		line("webhooks remove <id>"),
	})
}

func runWebhooks(ctx context.Context, c *api.Client, p parsedArgs) (int, error) {
	sub := p.positional(0)
	if sub == "" {
		sub = "list"
	}
	jsonOut := p.flagBool("json")

	switch sub {
	case "help":
		errln(webhooksUsage())
		return 0, nil

	case "list":
		hooks, err := c.Settings.GetWebhooks(ctx)
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(hooks)
			return 0, nil
		}
		if len(hooks) == 0 {
			errln(dim("  No webhooks."))
			return 0, nil
		}
		rows := make([][]string, 0, len(hooks))
		for _, w := range hooks {
			on := dim("○")
			if w.Enabled {
				on = green("●")
			}
			rows = append(rows, []string{dim(w.ID), on, cyan(w.Events), dim(truncate(w.URL, 46))})
		}
		table([]string{"ID", "ON", "EVENTS", "URL"}, rows)
		return 0, nil

	case "add":
		url := p.flagStr("url")
		if url == "" {
			return usageErr("Usage: webhooks add --url <https://…> [--events denials|allowed|all]")
		}
		events := p.flagStr("events")
		if events == "" {
			events = "denials"
		}
		w, err := c.Settings.CreateWebhook(ctx, map[string]any{"url": url, "events": events})
		if err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(w)
			return 0, nil
		}
		okf("Webhook added (%s) → %s", w.Events, w.URL)
		return 0, nil

	case "remove":
		id := p.positional(1)
		if id == "" {
			return usageErr("Usage: webhooks remove <id>")
		}
		if err := c.Settings.DeleteWebhook(ctx, id); err != nil {
			return 1, err
		}
		if jsonOut {
			printJSON(map[string]any{"ok": true, "id": id})
			return 0, nil
		}
		okf("Removed %s", id)
		return 0, nil
	}

	return unknownSub("webhooks", sub, webhooksUsage())
}
