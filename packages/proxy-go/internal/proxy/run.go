package proxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codeyevsky/solongate/proxy/internal/config"
	"github.com/codeyevsky/solongate/proxy/internal/sdk"
	"github.com/codeyevsky/solongate/proxy/internal/term"
)

// The entry point the CLI hands a proxy invocation to.
//
//	solongate [proxy options] -- <upstream command> [args...]
//	solongate --upstream-url https://… [proxy options]
//	solongate --config proxy.config.json
//
// which is the same invocation packages/proxy/src/index.ts routes into
// SolonGateProxy, so a client's .mcp.json entry works against either binary
// without being rewritten.

const (
	ExitOK    = 0
	ExitFatal = 1
	// ExitNotPorted is neither 0 nor 1 on purpose: 0 would tell a script the
	// proxy ran, and 1 is indistinguishable from a proxy that ran and failed. A
	// script that sees 69 knows it asked this binary for something it does not
	// have yet.
	ExitNotPorted = 69
)

// DefaultEvaluator is the policy evaluator this build enforces with.
//
// It is the SAME engine the guard hooks decide with. That was the whole
// difficulty: the compiler and the four extractors lived in packages/guard-go,
// which is `package main` in its own module, so this runtime had the entire
// pipeline and nothing to put in the middle of it and refused to start rather
// than start and deny everything.
//
// They live in packages/sgpolicy now and both import it. One compiler, one set
// of extractors, one mode table — so a rule cannot mean one thing to a hook and
// another to the proxy, which is a divergence nothing would have reported.
func DefaultEvaluator() sdk.PolicyEvaluator { return NewSharedEvaluator() }

// Run parses a proxy invocation and serves it.
func Run(args []string, evaluator sdk.PolicyEvaluator) int {
	now := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	cfg, err := config.ParseProxyArgs(args, now)
	if err != nil {
		// Argument and credential errors are reported exactly as the Node
		// implementation reports them, wording included: someone who searches
		// the message should land on the same answer whichever binary printed
		// it.
		fmt.Fprintf(os.Stderr, "[SolonGate] Fatal: %s\n", err)
		return ExitFatal
	}

	if evaluator == nil {
		reportNoEvaluator()
		return ExitNotPorted
	}

	p, err := New(Options{Config: cfg, Evaluator: evaluator})
	if err != nil {
		if errors.Is(err, ErrNoEvaluator) {
			reportNoEvaluator()
			return ExitNotPorted
		}
		fmt.Fprintf(os.Stderr, "[SolonGate] Fatal: %s\n", err)
		return ExitFatal
	}

	// SIGINT and SIGTERM end the proxy the way the client closing stdin does.
	// Without this the upstream child process survives the parent on some
	// shells and keeps holding whatever the tool server was holding.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := p.Start(ctx); err != nil {
		if errors.Is(err, errReported) {
			return ExitFatal
		}
		fmt.Fprintf(os.Stderr, "[SolonGate] Fatal: %s\n", err)
		return ExitFatal
	}
	return ExitOK
}

// reportNoEvaluator says what is missing and what to run instead.
//
// It names the npm package rather than only apologising, because the rule this
// port is written under is that a Go path which cannot do its job falls back to
// the Node implementation and never to no protection at all.
func reportNoEvaluator() {
	w := func(s string) { fmt.Fprintln(os.Stderr, s) }
	w("")
	w("  " + term.Yellow + "not ported yet" + term.Reset + ": " + term.Bold + "policy evaluation for the MCP proxy" + term.Reset)
	w("  " + term.Dim + "The proxy runtime is here — transports, interception, audit, policy sync —" + term.Reset)
	w("  " + term.Dim + "but the engine that decides ALLOW or DENY lives in packages/guard-go and" + term.Reset)
	w("  " + term.Dim + "cannot be imported yet. Starting without it would mean a proxy that denies" + term.Reset)
	w("  " + term.Dim + "every call, so it does not start." + term.Reset)
	w("")
	w("  " + term.Dim + "Use the npm proxy meanwhile:" + term.Reset + " " + term.Cyan + "npx @solongate/proxy -- <your server>" + term.Reset)
	w("")
}
