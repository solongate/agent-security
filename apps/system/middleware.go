package main

import (
	"log"
	"net/http"
	"runtime/debug"
	"strings"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
)

// The port of src/middleware.ts.
//
// Next runs that file for `/api/:path*`, which in this service is every path,
// and it does three things: it answers preflights, it echoes an allowed origin,
// and it stamps the security headers on everything. All three are contracts
// with a browser that is already running the deployed dashboard, so the header
// values below are the original's verbatim.

// securityHeaders is src/middleware.ts's SECURITY_HEADERS, in its order.
//
// The CSP is `default-src 'self'` on a service that returns nothing but JSON,
// which does effectively nothing — but it is what is deployed, and a header a
// browser already caches is not the place to make an unrelated change.
var securityHeaders = [][2]string{
	{"X-Frame-Options", "DENY"},
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "strict-origin-when-cross-origin"},
	{"Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload"},
	{"Permissions-Policy", "camera=(), microphone=(), geolocation=()"},
	{"Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"},
}

const (
	corsMethods = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
	corsHeaders = "Content-Type, Authorization, X-API-Key, X-Requested-With, Accept"
	corsMaxAge  = "86400"
)

// cors answers preflights and echoes the origin on everything else.
//
// The origin is compared against a whitelist and ECHOED rather than answered
// with `*`, because the response also carries
// Access-Control-Allow-Credentials: true and a wildcard is illegal with
// credentials. An unknown origin gets no CORS headers at all — not a rejection,
// just silence, which the browser turns into the block. That is the live app's
// behaviour and it is the right one: a non-browser caller (the guard, the CLI)
// sends no Origin and is unaffected.
//
// OPTIONS is answered HERE and never reaches the mux, exactly as the Next
// middleware short-circuits it. That is why the route table below registers no
// OPTIONS patterns even though 60 of the route files export one: those handlers
// are unreachable in the live app too.
func (s *server) cors(next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(s.cfg.allowedOrigins))
	for _, o := range s.cfg.allowedOrigins {
		allowed[o] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		h := w.Header()

		if origin != "" && allowed[origin] {
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Access-Control-Allow-Credentials", "true")
		}
		for _, kv := range securityHeaders {
			h.Set(kv[0], kv[1])
		}

		if r.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", corsMethods)
			h.Set("Access-Control-Allow-Headers", corsHeaders)
			h.Set("Access-Control-Max-Age", corsMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// maxBodyBytes bounds every request body.
//
// It has no counterpart in the live app, where the platform imposes its own
// ceiling, and it is here because this process reads bodies into memory. The
// number is set by /v1/upload, which accepts images up to 5 MB and wraps them
// in a multipart envelope; everything else on this service is JSON measured in
// kilobytes.
const maxBodyBytes = 16 << 20

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, r)
	})
}

// recoverPanic turns a crash in one handler into a 500 for that request.
//
// Without it net/http closes the connection with no response, and the caller —
// a guard polling for policy — sees a network error rather than a server error.
// The two are not the same to a client that falls back to a cached policy on
// one and retries on the other.
//
// The stack goes to the log and never to the caller: it names file paths,
// function names and the shape of this binary.
func recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				// The URL is logged without its query string. Query strings on
				// this service carry agent ids and device codes.
				log.Printf("api: panic on %s %s: %v\n%s", r.Method, r.URL.Path, rec, debug.Stack())
				apiauth.Error(w, http.StatusInternalServerError, "INTERNAL_ERROR",
					"An internal error occurred. Please try again later.")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// notFound answers a path nothing claimed.
//
// JSON rather than HTML: every caller of this service is a program. Next
// answers unmatched API paths with its own 404 and no deployed client branches
// on the body, so the shape here is the service's own error envelope.
func notFound(w http.ResponseWriter, r *http.Request) {
	apiauth.Error(w, http.StatusNotFound, "NOT_FOUND", "Not found")
}

// isAPIPath mirrors the Next matcher `/api/:path*`. Nothing outside it is
// served by this binary, but the check keeps the middleware honest about what
// it is claiming to reproduce.
func isAPIPath(p string) bool { return p == "/api" || strings.HasPrefix(p, "/api/") }
