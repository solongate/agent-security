// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"
	"errors"
	"net/url"
	"os"
	"os/signal"
	"strconv"

	"github.com/solongate/agent-security/packages/cli/cliutil"
	"github.com/solongate/agent-security/packages/cli/confine"
	"github.com/solongate/agent-security/packages/cli/maintenance"
	"github.com/solongate/agent-security/packages/cli/observability"
	"github.com/solongate/agent-security/packages/cli/policy"
	"github.com/solongate/agent-security/packages/cli/security"
	"github.com/solongate/agent-security/packages/core/client"
)

var Names = []string{
	"policy", "ratelimit", "dlp", "stats", "audit",
	"doctor", "trace", "watch",
}

var LocalNames = []string{}

var (
	RunAgent     = confine.RunAgent
	SandboxAgent = confine.SandboxAgent
	RunRepair    = maintenance.RunRepair
	RunUpdate    = maintenance.RunUpdate
)

type handler func(ctx context.Context, c *client.Client, p cliutil.ParsedArgs) (int, error)

func handlers() map[string]handler {
	return map[string]handler{
		"policy":    policy.Run,
		"ratelimit": security.RunRateLimit,
		"dlp":       security.RunDLP,
		"stats":     observability.RunStats,
		"audit":     observability.RunAudit,
		"doctor":    maintenance.RunDoctor,
		"trace":     observability.RunTrace,
		"watch":     observability.RunWatch,
		"range":     maintenance.RunRange,
	}
}

func Run(name string, argv []string) int {
	h, ok := handlers()[name]
	if !ok {
		cliutil.Errln("  Unknown command: " + name)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	code, err := h(ctx, client.New(), cliutil.Parse(argv))

	if ctx.Err() != nil {
		return 130
	}
	if err != nil {
		return report(err)
	}
	return code
}

func Runner(name string) func([]string) int {
	return func(argv []string) int { return Run(name, argv) }
}

func report(e error) int {
	if errors.Is(e, context.Canceled) {

		return 130
	}
	var ae *client.Error
	if errors.As(e, &ae) {
		msg := ae.Message
		if ae.Status != 0 {
			msg += " (" + strconv.Itoa(ae.Status) + ")"
		}
		cliutil.Errln(cliutil.Red("  ✗ ") + msg)
		return 1
	}
	cliutil.Errln(cliutil.Red("  ✗ ") + e.Error())
	return 1
}

func esc(s string) string { return url.PathEscape(s) }
