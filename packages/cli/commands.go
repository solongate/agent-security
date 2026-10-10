// SPDX-License-Identifier: Apache-2.0

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

	"github.com/solongate/agent-security/packages/core/api"
)

// Names is the subcommand set this router owns. main.go uses it to decide what
// to hand over; nothing else should be maintaining a second copy of the list.
var Names = []string{
	"policy", "ratelimit", "dlp", "stats", "audit",
	"doctor", "trace", "watch",
}

// LocalNames are the commands that talk to THIS MACHINE rather than to the API.
//
// They are a separate list because Names carries an invariant: every name in it
// has a handler taking a context and an API client, and a test asserts the two
// agree. A local command has neither, and forcing one into that shape would
// mean `browser status` building a client and refusing on a laptop nobody has
// paired yet, which is exactly the machine somebody runs it on.
//
// Both lists together are what "implemented" means, and main's stub test reads
// both. A command in neither reads as a placeholder that should exit 69.
var LocalNames = []string{}

// handler is one command. It returns the process exit code, and an error only
// for failures that should be rendered the same way everywhere — an API
// rejection, an unreachable cloud, a missing login. A command that simply has
// nothing to show returns (0, nil) and prints its own line.
type handler func(ctx context.Context, c *api.Client, p parsedArgs) (int, error)

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
		"protect":   runProtect,
		"range":     runRange,
	}
}

// Run executes one management command and returns an exit code. It never
// panics out to the caller and never prints a stack trace: an operator looking
// at their security posture should see one line saying what went wrong, so the
// CLI reads like a tool rather than a crash.
func Run(name string, argv []string) int {
	h, ok := handlers()[name]
	if !ok {
		errln("  Unknown command: " + name)
		return 1
	}

	// Ctrl+C has to reach the in-flight HTTP request rather than only the
	// process: `watch` runs until interrupted, and a one-shot command sitting on
	// a slow API should stop when asked instead of finishing its 15-second
	// timeout first.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	code, err := h(ctx, api.New(), parse(argv))
	// Ctrl+C during a request makes that request fail, and the API layer
	// describes the failure as "cannot reach SolonGate". It was reached; the
	// user stopped waiting. Checking the context first keeps an interrupt from
	// being reported as an outage.
	if ctx.Err() != nil {
		return 130
	}
	if err != nil {
		return report(err)
	}
	return code
}

// Runner adapts one command to the signature main.go's command table holds.
func Runner(name string) func([]string) int {
	return func(argv []string) int { return Run(name, argv) }
}

// report turns an error into the single line the user sees.
//
// The three cases are kept apart because they need different next steps: not
// logged in tells you to log in, an API rejection carries the status that
// explains it, and anything else is printed as-is rather than dressed up as
// something this layer understands.
func report(e error) int {
	if errors.Is(e, context.Canceled) {
		// Ctrl+C is not a failure and must not print one. 130 is what a shell
		// reports for a process the user interrupted.
		return 130
	}
	if errors.Is(e, api.ErrNotAuthenticated) {
		errln(red("  ✗ ") + e.Error())
		return 1
	}
	var ae *api.Error
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

// usageErr is what a command returns when the arguments do not name anything it
// can do. It prints and exits 1 without going through report, because a usage
// mistake is not an error from the API and should not be prefixed as one.
func usageErr(msg string) (int, error) {
	errln("  " + msg)
	return 1, nil
}

// okf prints a confirmation line, the one shape every mutating command shares.
func okf(format string, a ...any) {
	errln(green("  ✓ " + fmt.Sprintf(format, a...)))
}

// esc escapes a path segment. The api package keeps its own copy unexported, and
// the two raw calls in policy.go build their paths the same way the typed
// methods do so an id with a slash in it cannot walk out of its route.
func esc(s string) string { return url.PathEscape(s) }

// nowMillis is the clock the generated policy ids use. Split out so a test can
// pin it rather than matching a timestamp.
var nowMillis = func() int64 { return time.Now().UnixMilli() }
