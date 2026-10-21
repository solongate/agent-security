// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 the SolonGate contributors

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/solongate/agent-security/packages/core/client"
)

var Names = []string{
	"policy", "ratelimit", "dlp", "stats", "audit",
	"doctor", "trace", "watch",
}

var LocalNames = []string{}

type handler func(ctx context.Context, c *client.Client, p parsedArgs) (int, error)

func handlers() map[string]handler {
	return map[string]handler{
		"policy":    runPolicy,
		"ratelimit": runRateLimit,
		"dlp":       runDLP,
		"stats":     runStats,
		"audit":     runAudit,
		"doctor":    runDoctor,
		"trace":     runTrace,
		"watch":     runWatch,
		"range":     runRange,
	}
}

func Run(name string, argv []string) int {
	h, ok := handlers()[name]
	if !ok {
		errln("  Unknown command: " + name)
		return 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	code, err := h(ctx, client.New(), parse(argv))

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
		errln(red("  ✗ ") + msg)
		return 1
	}
	errln(red("  ✗ ") + e.Error())
	return 1
}

func usageErr(msg string) (int, error) {
	errln("  " + msg)
	return 1, nil
}

func okf(format string, a ...any) {
	errln(green("  ✓ " + fmt.Sprintf(format, a...)))
}

func esc(s string) string { return url.PathEscape(s) }

var nowMillis = func() int64 { return time.Now().UnixMilli() }