package main

// GET /api/v1/auth/config — which identity provider a CLI should sign in
// against.
//
// THE CLI IS NOT CONFIGURED. That is the whole reason this exists. An operator
// sets SG_OIDC_ISSUER once, on the service, and every machine that installs the
// guard learns where to send somebody from the service it is already pointed at.
// Putting the issuer in a CLI flag or a dotfile instead would mean configuring
// the identity provider on every laptop, and getting it wrong on one of them is
// a person signing in somewhere nobody meant.
//
// NOTHING HERE IS A SECRET, and that is worth stating because the endpoint is
// unauthenticated. The issuer is a URL that serves a public discovery document.
// The client id is the public half of an OAuth client — it is in every
// authorization URL the provider ever redirects through, and a device-flow
// client is public by definition: it runs on a laptop and can hold no secret.
// What authorises anything is the token the provider issues afterwards, which
// this service verifies against the provider's own keys. See authVerifyOIDCToken.
//
// It is answered BEFORE any credential exists, so it is rate-limited by IP like
// the other pre-credential routes rather than gated on a key the caller is
// trying to obtain.

import (
	"net/http"
	"os"
	"strings"

	"github.com/codeyevsky/solongate/api/internal/apiauth"
)

func init() {
	Register("GET /api/v1/auth/config", func(s *server) http.Handler {
		return http.HandlerFunc(s.authConfig)
	})
}

func (s *server) authConfig(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		// `oidc` is the question the CLI actually has: can I sign somebody in
		// here at all. A deployment with no provider configured answers false
		// and the CLI says so in one line, instead of failing later with a
		// discovery error nobody can act on.
		"oidc": oidcConfigured(),
	}
	if oidcConfigured() {
		out["issuer"] = strings.TrimRight(strings.TrimSpace(os.Getenv("SG_OIDC_ISSUER")), "/")
		// Empty when unset, and the CLI reports that rather than guessing: a
		// device authorization request without a client id is refused by every
		// provider, and "invalid_client" from a stranger's server is a worse
		// thing to hand somebody than a sentence naming the variable.
		out["client_id"] = strings.TrimSpace(os.Getenv("SG_OIDC_CLIENT_ID"))
		// The scopes the provider is asked for. Sent by the service rather than
		// compiled into the CLI so a directory that names its address claim
		// something unusual can be accommodated by configuration instead of by
		// a release. openid is required by the specification; email is what the
		// account is keyed on here.
		scopes := strings.Fields(strings.ReplaceAll(strings.TrimSpace(os.Getenv("SG_OIDC_SCOPES")), ",", " "))
		if len(scopes) == 0 {
			scopes = []string{"openid", "profile", "email"}
		}
		out["scopes"] = scopes
	}

	// No caching. The answer changes when an operator changes the service's
	// configuration, and a CLI that cached a stale issuer would send somebody to
	// a provider the service no longer trusts — which fails at the far end, in a
	// browser, with nothing on screen explaining why.
	w.Header().Set("Cache-Control", "no-store")
	apiauth.JSON(w, http.StatusOK, out)
}
