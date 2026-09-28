package main

import (
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
)

// The routes.
//
// Every route.ts under src/app/api is here — 68 files, one entry each, read off
// the tree rather than guessed. All but one are stubs the route slices replace;
// /api/health is ported in full because it is four lines and because a platform
// health check answering 501 is a service that never comes up.
//
// The OPTIONS handlers those files export are NOT registered. src/middleware.ts
// intercepts every preflight before routing, so those exports are unreachable
// in the live app too; the CORS layer in middleware.go answers them here.
//
// `auth` and `limit` on each entry are not decoration. They record what the
// live route does before it does anything, so a slice landing a handler applies
// the same gate rather than deciding again — and so a route that is currently
// unauthenticated is visible as such in one list instead of being discovered
// one file at a time.

// authKind is how a route establishes who is calling.
type authKind string

const (
	// authKey is withAuth: an sg_live_/sg_test_ key, resolved to a project.
	// Anything the handler reads or writes is scoped to KeyInfo.ProjectID.
	authKey authKind = "key"

	// authIP is withRateLimit and nothing else: the route is PUBLIC and its
	// only protection is a per-IP limit. Six routes are in this state and every
	// one of them is a provisioning or pairing endpoint, which is why they are
	// worth naming rather than burying.
	authIP authKind = "ip"

	// authWebhookSecret is the Telegram webhook: a shared secret in
	// x-telegram-bot-api-secret-token, and a bare 200 for everything else so a
	// prober learns nothing.
	authWebhookSecret authKind = "webhook-secret"
)

// limitName picks one of apiauth's named configs. Empty means the route does no
// limiting of its own beyond whatever authKey applies.
type limitName string

const (
	limStandard   limitName = "standard"
	limValidation limitName = "validation"
	limSetup      limitName = "setup"
	limAuth       limitName = "auth"
	limHealth     limitName = "health"
	limAI         limitName = "ai"
	limDevicePoll limitName = "devicePoll"
)

func (l limitName) config() apiauth.Config {
	switch l {
	case limValidation:
		return apiauth.LimitValidation
	case limSetup:
		return apiauth.LimitSetup
	case limAuth:
		return apiauth.LimitAuth
	case limHealth:
		return apiauth.LimitHealth
	case limAI:
		return apiauth.LimitAI
	case limDevicePoll:
		return apiauth.LimitDevicePoll
	default:
		return apiauth.LimitStandard
	}
}

// route is one route.ts file.
type route struct {
	path    string
	methods []string
	// source names the file still to be ported, and goes on the stub so
	// whoever lands there knows what is missing without reading a log.
	source string
	auth   authKind
	limit  limitName
	// ipPrefix is withRateLimit's third argument: the bucket namespace, so
	// device-start and device-poll do not share one IP's budget.
	ipPrefix string
	// done marks a route this file serves in full rather than stubbing.
	done bool
}

// routes is src/app/api, in `find`'s order, plus what this service has grown
// since the port.
//
// The table began as a record of the Next app being replaced: every row named
// the file still to be ported, and a handler with no row was a handler nobody
// had accounted for, which is what the startup warning exists to say. Routes
// written HERE have no such file, and inventing one would be a lie in the
// column whose whole job is to say where something came from.
//
// So they carry no source and are marked done. They are in the table for the
// two things it is read for now: the auth column, which records how a route
// decides who is calling, and the warning, which should fire for a route
// nobody thought about rather than for a dozen that were.
var routes = []route{
	{path: "/api/health", methods: []string{"GET"}, source: "src/app/api/health/route.ts", auth: authIP, limit: limHealth, done: true},

	{path: "/api/v1/audit-logs/{id}/block", methods: []string{"POST"}, source: "src/app/api/v1/audit-logs/[id]/block/route.ts", auth: authKey},
	{path: "/api/v1/audit-logs/{id}/whitelist", methods: []string{"POST"}, source: "src/app/api/v1/audit-logs/[id]/whitelist/route.ts", auth: authKey},
	// No DELETE. The live route had one; this service deliberately does not, so
	// the verb is off the table as well as out of the file — a method listed
	// here with no handler behind it answers 501 "not ported yet", which would
	// read as a promise to bring the delete back.
	{path: "/api/v1/audit-logs", methods: []string{"GET", "POST"}, source: "src/app/api/v1/audit-logs/route.ts", auth: authKey},

	// Which identity provider a CLI should sign in against. Public by nature —
	// an issuer URL and a public client id — and answered before any credential
	// exists, so it is per-IP limited like the rest of the pre-credential
	// routes. See auth_config.go.
	{path: "/api/v1/auth/config", methods: []string{"GET"}, auth: authIP, limit: limAuth, ipPrefix: "auth-config", done: true},
	{path: "/api/v1/auth/me", methods: []string{"GET"}, source: "src/app/api/v1/auth/me/route.ts", auth: authKey},
	{path: "/api/v1/auth/profile", methods: []string{"GET", "PUT"}, source: "src/app/api/v1/auth/profile/route.ts", auth: authKey},
	{path: "/api/v1/auth", methods: []string{"POST"}, source: "src/app/api/v1/auth/route.ts", auth: authIP, limit: limAuth},
	{path: "/api/v1/auth/session", methods: []string{"POST"}, source: "src/app/api/v1/auth/session/route.ts", auth: authIP, limit: limSetup},

	{path: "/api/v1/github/token", methods: []string{"POST"}, source: "src/app/api/v1/github/token/route.ts", auth: authKey},

	{path: "/api/v1/hooks/audit", methods: []string{"GET"}, source: "src/app/api/v1/hooks/audit/route.ts", auth: authKey},
	{path: "/api/v1/hooks/guard", methods: []string{"GET"}, source: "src/app/api/v1/hooks/guard/route.ts", auth: authKey},
	{path: "/api/v1/hooks/shield", methods: []string{"GET"}, source: "src/app/api/v1/hooks/shield/route.ts", auth: authKey},
	// No TypeScript original: the token reader became self-updating here, so a
	// machine could get a newer one without a reinstall.
	{path: "/api/v1/hooks/tokens", methods: []string{"GET"}, auth: authKey, done: true},

	{path: "/api/v1/keys/{id}", methods: []string{"PATCH", "DELETE"}, source: "src/app/api/v1/keys/[id]/route.ts", auth: authKey},
	{path: "/api/v1/keys", methods: []string{"GET", "POST"}, source: "src/app/api/v1/keys/route.ts", auth: authKey},

	{path: "/api/v1/mcp-servers/check", methods: []string{"POST"}, source: "src/app/api/v1/mcp-servers/check/route.ts", auth: authKey},
	{path: "/api/v1/mcp-servers/{id}", methods: []string{"GET", "PUT", "DELETE"}, source: "src/app/api/v1/mcp-servers/[id]/route.ts", auth: authKey},
	{path: "/api/v1/mcp-servers", methods: []string{"GET", "POST"}, source: "src/app/api/v1/mcp-servers/route.ts", auth: authKey},

	{path: "/api/v1/orgs/{id}/members", methods: []string{"GET", "POST", "DELETE"}, source: "src/app/api/v1/orgs/[id]/members/route.ts", auth: authKey},
	{path: "/api/v1/orgs/{id}", methods: []string{"GET", "PUT", "DELETE"}, source: "src/app/api/v1/orgs/[id]/route.ts", auth: authKey},
	{path: "/api/v1/orgs", methods: []string{"GET", "POST"}, source: "src/app/api/v1/orgs/route.ts", auth: authKey},

	{path: "/api/v1/policies/active", methods: []string{"GET", "POST"}, source: "src/app/api/v1/policies/active/route.ts", auth: authKey},
	{path: "/api/v1/policies/backtest", methods: []string{"POST"}, source: "src/app/api/v1/policies/backtest/route.ts", auth: authKey, limit: limValidation},
	{path: "/api/v1/policies/dry-run", methods: []string{"POST"}, source: "src/app/api/v1/policies/dry-run/route.ts", auth: authKey, limit: limValidation},
	{path: "/api/v1/policies/{id}/rego", methods: []string{"GET"}, source: "src/app/api/v1/policies/[id]/rego/route.ts", auth: authKey},
	{path: "/api/v1/policies/{id}/rules/{ruleId}", methods: []string{"DELETE"}, source: "src/app/api/v1/policies/[id]/rules/[ruleId]/route.ts", auth: authKey},
	{path: "/api/v1/policies/{id}/rules", methods: []string{"POST"}, source: "src/app/api/v1/policies/[id]/rules/route.ts", auth: authKey},
	{path: "/api/v1/policies/{id}/wasm", methods: []string{"GET"}, source: "src/app/api/v1/policies/[id]/wasm/route.ts", auth: authKey},
	{path: "/api/v1/policies/{id}", methods: []string{"GET", "PUT", "DELETE"}, source: "src/app/api/v1/policies/[id]/route.ts", auth: authKey},
	{path: "/api/v1/policies/learn", methods: []string{"POST"}, source: "src/app/api/v1/policies/learn/route.ts", auth: authKey, limit: limValidation},
	{path: "/api/v1/policies", methods: []string{"GET", "POST"}, source: "src/app/api/v1/policies/route.ts", auth: authKey},

	{path: "/api/v1/project-config", methods: []string{"GET"}, source: "src/app/api/v1/project-config/route.ts", auth: authKey},
	// No source route: this one has no Next.js original. It is what gives a CLI
	// - which holds a key rather than a session - the workspace switch the
	// dashboard gets from /auth/session. See projectswitch.go.
	{path: "/api/v1/projects/{id}/key", methods: []string{"POST"}, auth: authKey, done: true},
	{path: "/api/v1/projects/{id}", methods: []string{"GET", "PUT", "DELETE"}, source: "src/app/api/v1/projects/[id]/route.ts", auth: authKey},
	{path: "/api/v1/projects", methods: []string{"GET"}, source: "src/app/api/v1/projects/route.ts", auth: authKey},

	{path: "/api/v1/settings/denial-alerts", methods: []string{"GET", "POST", "PATCH", "DELETE"}, source: "src/app/api/v1/settings/denial-alerts/route.ts", auth: authKey},
	{path: "/api/v1/settings/denial-webhook/send-test", methods: []string{"POST"}, source: "src/app/api/v1/settings/denial-webhook/send-test/route.ts", auth: authKey},
	{path: "/api/v1/settings/denial-webhook", methods: []string{"GET", "POST", "PATCH", "DELETE"}, source: "src/app/api/v1/settings/denial-webhook/route.ts", auth: authKey},
	{path: "/api/v1/settings/guard-status", methods: []string{"GET"}, source: "src/app/api/v1/settings/guard-status/route.ts", auth: authKey},
	{path: "/api/v1/settings/local-logs-view", methods: []string{"GET", "PUT"}, source: "src/app/api/v1/settings/local-logs-view/route.ts", auth: authKey},
	{path: "/api/v1/settings/local-logs", methods: []string{"GET", "PUT"}, source: "src/app/api/v1/settings/local-logs/route.ts", auth: authKey},
	{path: "/api/v1/settings/rate-limit-history", methods: []string{"GET", "DELETE"}, source: "src/app/api/v1/settings/rate-limit-history/route.ts", auth: authKey},
	{path: "/api/v1/settings/security-layers", methods: []string{"GET", "PUT"}, source: "src/app/api/v1/settings/security-layers/route.ts", auth: authKey},
	{path: "/api/v1/settings/self-protection", methods: []string{"GET", "PUT"}, source: "src/app/api/v1/settings/self-protection/route.ts", auth: authKey},

	{path: "/api/v1/setup", methods: []string{"POST"}, source: "src/app/api/v1/setup/route.ts", auth: authIP, limit: limSetup},

	{path: "/api/v1/stats/drift", methods: []string{"GET"}, source: "src/app/api/v1/stats/drift/route.ts", auth: authKey},
	{path: "/api/v1/stats/security-insights", methods: []string{"GET"}, source: "src/app/api/v1/stats/security-insights/route.ts", auth: authKey},
	{path: "/api/v1/stats/timeseries", methods: []string{"GET"}, source: "src/app/api/v1/stats/timeseries/route.ts", auth: authKey},
	{path: "/api/v1/stats", methods: []string{"GET"}, source: "src/app/api/v1/stats/route.ts", auth: authKey},

	{path: "/api/v1/telegram/webhook", methods: []string{"POST"}, source: "src/app/api/v1/telegram/webhook/route.ts", auth: authWebhookSecret},

	{path: "/api/v1/tokens/verify", methods: []string{"POST"}, source: "src/app/api/v1/tokens/verify/route.ts", auth: authKey},
	{path: "/api/v1/tokens", methods: []string{"POST"}, source: "src/app/api/v1/tokens/route.ts", auth: authKey},

	// What a turn cost, reported by a hook. No TypeScript original: this
	// service is where token accounting was added.
	{path: "/api/v1/token-usage", methods: []string{"POST"}, auth: authKey, done: true},

	{path: "/api/v1/tools/{name}", methods: []string{"GET", "PUT", "DELETE"}, source: "src/app/api/v1/tools/[name]/route.ts", auth: authKey},
	{path: "/api/v1/tools", methods: []string{"GET", "POST"}, source: "src/app/api/v1/tools/route.ts", auth: authKey},

	{path: "/api/v1/validate", methods: []string{"POST"}, source: "src/app/api/v1/validate/route.ts", auth: authKey, limit: limValidation},
}

// routeCount is how many rows the table must have. It is asserted at startup,
// so a route deleted during a merge is a failure to boot rather than a 404
// somebody finds in production.
//
// Keeping one number rather than two is deliberate. The check exists to notice
// a row disappearing, and a row is a row whoever wrote it; splitting the count
// into "ported" and "ours" would make the assertion weaker in exchange for a
// distinction the source column already draws.
const routeCount = 57

// routeHandlers is how a finished route slice replaces a stub.
//
// A slice registers into it from an init() in its own file, so landing a route
// is one entry in one place rather than an edit to the table above — which
// matters while four slices are being written into this package at once and
// every shared line is a merge conflict.
//
// The key is `METHOD /path`, exactly as the table spells it: "GET
// /api/v1/policies/active". A key that matches no table entry is registered
// anyway and logged as an extra, because silently dropping a handler somebody
// wrote is worse than serving a route the list does not mention.
var routeHandlers = map[string]func(*server) http.Handler{}

// Register is the entry point for a route slice's init().
//
//	func init() { Register("GET /api/v1/policies/active", buildActivePolicy) }
func Register(pattern string, build func(*server) http.Handler) {
	if _, dup := routeHandlers[pattern]; dup {
		// Two slices claiming one route is a merge accident, and whichever won
		// would be arbitrary. Failing loudly at init is the only moment this is
		// cheap to fix.
		log.Fatalf("api: %s registered twice", pattern)
	}
	routeHandlers[pattern] = build
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()

	if len(routes) != routeCount {
		log.Fatalf("api: route table has %d entries, expected %d — a route was added or dropped without updating routeCount", len(routes), routeCount)
	}

	claimed := map[string]bool{}
	stubbed := 0
	for _, rt := range routes {
		for _, method := range rt.methods {
			pattern := method + " " + rt.path
			claimed[pattern] = true

			if build, ok := routeHandlers[pattern]; ok {
				mux.Handle(pattern, build(s))
				continue
			}
			if rt.done {
				mux.Handle(pattern, s.builtin(rt))
				continue
			}
			mux.Handle(pattern, s.notPorted(rt, method))
			stubbed++
		}
	}

	// A handler registered for something the table does not list. It is served
	// rather than dropped; see routeHandlers.
	extra := []string{}
	for pattern := range routeHandlers {
		if !claimed[pattern] {
			extra = append(extra, pattern)
		}
	}
	sort.Strings(extra)
	for _, pattern := range extra {
		log.Printf("api: %s is registered but not in the route table", pattern)
		mux.Handle(pattern, routeHandlers[pattern](s))
	}

	mux.HandleFunc("/", notFound)

	log.Printf("api: %d routes, %d still stubs", routeCount, stubbed)

	// Outermost first, and every layer is here for a reason:
	//
	//   recoverPanic   so a crash below it is a 500 and not a dead connection
	//   cors           sets the security headers and answers preflights before
	//                  anything can write a body
	//   limitBody      before any handler can read one
	//   mux            last
	return recoverPanic(s.cors(limitBody(mux)))
}

// builtin serves a route this file implements in full. There is one.
func (s *server) builtin(rt route) http.Handler {
	if rt.path == "/api/health" {
		return http.HandlerFunc(s.health)
	}
	log.Fatalf("api: %s is marked done but has no handler", rt.path)
	return nil
}

// notPorted is the placeholder.
//
// 501, not 200 and not 404. A route slice that has not landed must not be
// mistaken for one that has — by a person, by a smoke test, or by whoever is
// deciding whether the cutover is done. 404 would be worse than either: it
// reads as "this endpoint does not exist", which for a deployed client is a
// reason to stop calling it.
//
// The gate is applied even here. A stub that answered 501 to an unauthenticated
// caller would tell anyone who asked which endpoints this service has and what
// state the port is in, and — more to the point — a route that becomes real by
// somebody replacing its handler should not be a route that becomes
// authenticated at the same moment.
func (s *server) notPorted(rt route, method string) http.Handler {
	body := map[string]any{
		"error": map[string]string{
			"code":    "NOT_IMPLEMENTED",
			"message": "This endpoint has not been ported to the Go API yet.",
		},
		"route":  method + " " + rt.path,
		"source": rt.source,
	}
	respond := func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		apiauth.JSON(w, http.StatusNotImplemented, body)
	}

	switch rt.auth {
	case authKey:
		return s.auth.WithAuthLimit(rt.limit.config(), func(w http.ResponseWriter, r *http.Request, _ apiauth.KeyInfo) {
			respond(w, r)
		})
	case authIP, authWebhookSecret:
		// The webhook route authenticates on a shared secret this stub has no
		// business checking, so it gets the public route's per-IP limit and
		// nothing else. It answers 501 either way; the limit is what stops the
		// stub from being a free amplifier.
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !s.auth.LimitByIP(w, r, rt.limit.config(), rt.ipPrefix) {
				return
			}
			respond(w, r)
		})
	default:
		return http.HandlerFunc(respond)
	}
}

// RoutePatterns lists every registered pattern, for tests and for the startup
// log. Sorted so the output is stable.
func RoutePatterns() []string {
	out := make([]string, 0, len(routes)*2)
	for _, rt := range routes {
		for _, m := range rt.methods {
			out = append(out, m+" "+rt.path)
		}
	}
	sort.Strings(out)
	return out
}

// PathsUnderPrefix is a small helper for the slices: the table filtered to one
// area, so a slice can assert it has claimed everything it was given.
func PathsUnderPrefix(prefix string) []string {
	out := []string{}
	for _, rt := range routes {
		if strings.HasPrefix(rt.path, prefix) {
			out = append(out, rt.path)
		}
	}
	sort.Strings(out)
	return out
}
