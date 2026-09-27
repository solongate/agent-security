// SolonGate's API, in Go.
//
// This is the backend every other piece of the product talks to. The guard on
// somebody's laptop polls it for policy, the audit hook posts to it, the CLI
// pairs against it, and the dashboard is a view of it. None of those will be
// redeployed alongside this binary, so apps/api stays the reference for what
// every endpoint returns: a response shape, a status code, a header and an
// error body are each a contract with software that is already installed.
//
// Routing is net/http's own ServeMux. Go 1.22 patterns cover method and path,
// and the precedence rule — a literal segment beats a wildcard — is what lets
// /v1/policies/active and /v1/policies/{id} coexist without an ordering
// convention of our own. A router dependency here would buy nothing but a
// version to track.
//
// This file is the shell: configuration, the database handle, the
// authenticator, and the server they hang off. The routes are in routes.go and
// all but one of them are stubs, which is the honest state of the port and is
// why they answer 501.
package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/store"
)

type config struct {
	addr            string
	databaseURL     string
	allowedOrigins  []string
	development     bool
	shutdownTimeout time.Duration
}

// server is what a route slice receives. Everything a handler needs hangs off
// it, and nothing is reachable through a package-level variable — so a slice
// cannot acquire a database handle without going through the struct that also
// carries the authenticator.
type server struct {
	cfg   config
	store *store.Store
	auth  *apiauth.Authenticator
}

// env reads a variable, preferring the NEXT_PUBLIC_ form.
//
// Those names are not a Next.js detail here — they are what is set in Railway
// for this service today, and this binary has to come up on that environment
// unchanged or the deploy is a rollback waiting to happen.
func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv("NEXT_PUBLIC_" + name)); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

// loadDotEnv fills in variables that are not already set, from the same files
// Next reads.
//
// The third path is temporary: while the port is partial the configuration of
// record still lives next to the Next.js app. Anything already in the
// environment wins, so a real deploy never reads a file.
func loadDotEnv() {
	for _, path := range []string{".env.local", ".env", "../api/.env.local"} {
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			key, value, ok := strings.Cut(line, "=")
			if !ok {
				continue
			}
			key = strings.TrimSpace(key)
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			if _, set := os.LookupEnv(key); !set && key != "" {
				_ = os.Setenv(key, value)
			}
		}
	}
}

// defaultOrigins is the list that ships when ALLOWED_ORIGINS is unset: the
// dashboard on the loopback port it listens on, and nothing else.
//
// A self-hosted install serves the dashboard from its own hostname, so anything
// other than local development has to name it in ALLOWED_ORIGINS. That is the
// safe direction for a CORS allow-list — a wrong entry here would let another
// origin read this API with a browser's credentials, and a missing one presents
// as a dashboard that cannot call its own API, which is loud.
const defaultOrigins = "http://127.0.0.1:3005,http://localhost:3005"

// localOrigins are added only in development, as the original adds them. Six
// ports, because six apps in this monorepo run locally at once.
var localOrigins = []string{
	"http://localhost:3000", "http://localhost:3001", "http://localhost:3002",
	"http://localhost:3003", "http://localhost:3004", "http://localhost:3005",
}

func loadConfig() (config, error) {
	loadDotEnv()

	// NODE_ENV is read for one thing: whether to trust localhost origins. The
	// original tests `=== 'production'` in places and `=== 'development'` here;
	// this tests for development, so a missing variable — which is the normal
	// state for a Go deploy — fails CLOSED and does not whitelist localhost on
	// a production service.
	development := strings.EqualFold(os.Getenv("NODE_ENV"), "development")

	origins := splitList(env("ALLOWED_ORIGINS", defaultOrigins))
	if development {
		origins = append(origins, localOrigins...)
	}

	c := config{
		addr:            ":" + env("PORT", "3002"),
		databaseURL:     env("DATABASE_URL", store.DefaultURL),
		allowedOrigins:  origins,
		development:     development,
		shutdownTimeout: 20 * time.Second,
	}

	if c.databaseURL == "" {
		// This service is nothing but its database, and a process that starts
		// without one answers every route with a 500 while reporting itself
		// healthy.
		return c, errors.New("DATABASE_URL is required")
	}
	return c, nil
}

func splitList(raw string) []string {
	var out []string
	for _, o := range strings.Split(raw, ",") {
		if o = strings.TrimSpace(o); o != "" {
			out = append(out, o)
		}
	}
	return out
}

func main() {
	log.SetFlags(0)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("api: %v", err)
	}

	db, err := store.Open(cfg.databaseURL)
	if err != nil {
		log.Fatalf("api: %v", err)
	}
	defer db.Close()

	srv := &server{
		cfg:   cfg,
		store: db,
		auth:  apiauth.New(db, apiauth.NewLimiter()),
	}

	// The runtime tables, once at startup rather than inside the first request
	// that needs one — which is what src/db/index.ts's `schemaReady` does, and
	// what makes a cold start pay for it. A failure is logged and NOT fatal:
	// every one of these objects already exists in the live database, the Next
	// app creates them too, and refusing to start over a CREATE TABLE IF NOT
	// EXISTS would take the API down for something already done.
	//
	// EnsureRuntimeTables stays retryable after a failure, so a route slice
	// that touches device_codes, sessions, agent_baselines, anomaly_events or
	// solon_usage should call it first — that is what `await schemaReady` at
	// the top of those routes means.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	if err := db.EnsureRuntimeTables(ctx); err != nil {
		log.Printf("api: runtime tables not ready, routes that need them will retry: %v", err)
	}
	cancel()

	// The background context for the process, cancelled on shutdown.
	root, stopRoot := context.WithCancel(context.Background())
	defer stopRoot()

	// last_used_at is buffered and flushed on a timer; see the comment on
	// StartLastUsedFlusher for why it is not written per request.
	go srv.auth.StartLastUsedFlusher(root)

	// The one table in this schema that expires. Everything else here grows
	// forever, which is survivable for a ledger row and is not for a stored
	// conversation; see TurnRetention.
	startTurnPurge(srv)

	httpServer := &http.Server{
		Addr:    cfg.addr,
		Handler: srv.routes(),

		// ReadHeaderTimeout alone is not enough, and believing otherwise has
		// been wrong elsewhere in this repository: net/http CLEARS it once the
		// headers are in, so with no ReadTimeout the body has no deadline at
		// all and a client can dribble four bytes a minute forever.
		//
		// The write budget is the generous one because /v1/stats runs a dozen
		// aggregates against Turso and /v1/hooks/* serves a base64 bundle; a
		// slow response there must not be turned into a truncated one, because
		// a truncated hook bundle fails its own sha256 check on the far end.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	// Shut down on the signal the platform sends, so an in-flight write
	// finishes rather than being cut off mid-transaction — and so the buffered
	// last-used stamps get their final flush.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), cfg.shutdownTimeout)
		defer cancel()
		_ = httpServer.Shutdown(ctx)
		stopRoot()
	}()

	// The listen address is logged and nothing else is. Not DATABASE_URL, which
	// names the Turso host; not the auth token. This service's startup log is
	// not a place to write down how to reach its database.
	log.Printf("api: listening on %s", cfg.addr)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("api: %v", err)
	}
}

// health is GET /api/health, ported in full.
//
// It reports the process, NOT the database, and that is the live behaviour
// rather than an oversight to improve on: this endpoint is what Railway's
// health check reads, and making it fail on a Turso blip would take a healthy
// instance out of rotation over a dependency it would have recovered from. The
// version string is apps/api's package.json version, which is what deployed
// tooling compares against.
//
// The per-IP limit is the original's 60 a minute. A health endpoint with no
// limit is a free way to make this process do work.
func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if !s.auth.LimitByIP(w, r, apiauth.LimitHealth, "") {
		return
	}
	apiauth.JSON(w, http.StatusOK, map[string]string{
		"status":    "healthy",
		"version":   "0.1.0",
		"timestamp": store.ISO(store.Now()),
	})
}
