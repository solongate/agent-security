package main

// Verifying a session against the customer's own identity provider.
//
// The SaaS build asks Supabase who a token belongs to: one HTTP call to
// GoTrue's /auth/v1/user, cached for thirty seconds. An on-premise installation
// has no Supabase and must not acquire one — the only identity authority there
// is the customer's, and the only network path out of the control plane is to
// it.
//
// So this is the second implementation of the same question. It is selected by
// configuration, not by a build tag: a binary that behaves differently
// depending on how it was compiled is a binary whose behaviour cannot be read
// off its configuration, and the deployment that matters here is somebody
// else's.
//
//	SG_OIDC_ISSUER set     -> verify the ID token against that issuer
//	otherwise              -> Supabase, exactly as before
//
// The token is verified LOCALLY, against the issuer's published keys. There is
// no per-request call to the identity provider: an enterprise IdP is not
// something to put in the path of every dashboard poll, and a signature is
// checkable without asking anybody.

import (
	"context"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

// oidcVerifier is built once, lazily, on the first session that needs it.
//
// Lazily rather than at startup because this service starts in deployments that
// have no OIDC configured at all, and because an identity provider that is
// briefly unreachable should delay the first sign-in rather than stop the
// process from coming up.
var (
	oidcOnce     sync.Once
	oidcVerifier *oidc.IDTokenVerifier
	oidcErr      error
)

func oidcConfigured() bool {
	return strings.TrimSpace(os.Getenv("SG_OIDC_ISSUER")) != ""
}

func authOIDCVerifier(ctx context.Context) (*oidc.IDTokenVerifier, error) {
	oidcOnce.Do(func() {
		issuer := strings.TrimRight(strings.TrimSpace(os.Getenv("SG_OIDC_ISSUER")), "/")
		clientID := strings.TrimSpace(os.Getenv("SG_OIDC_CLIENT_ID"))

		discovery, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()

		provider, err := oidc.NewProvider(discovery, issuer)
		if err != nil {
			oidcErr = err
			return
		}
		oidcVerifier = provider.Verifier(&oidc.Config{
			ClientID: clientID,
			// An audience check needs a client id. Without one the token is
			// still verified — signature, issuer and expiry — but it could
			// have been minted for a different application at the same
			// provider, so the deployment is told rather than left to assume.
			SkipClientIDCheck: clientID == "",
		})
		if clientID == "" {
			log.Print("[auth/session] SG_OIDC_CLIENT_ID is not set: tokens are verified but their audience is not checked")
		}
	})
	return oidcVerifier, oidcErr
}

// authVerifyOIDCToken is the OIDC half of authVerifyAccessToken.
//
// It returns the address the same way the Supabase path does — lowercased and
// trimmed — because everything downstream compares and stores that form, and a
// session that provisioned under two spellings of one address is two accounts.
func authVerifyOIDCToken(ctx context.Context, token string) (string, bool) {
	if token == "" {
		return "", false
	}
	if email, ok := authVerifiedLookup(token); ok {
		return email, true
	}

	verifier, err := authOIDCVerifier(ctx)
	if err != nil || verifier == nil {
		// Discovery failed. Said once per failure rather than swallowed: this
		// is the dependency every sign-in waits on, and it used to be the kind
		// of thing that showed up as "the dashboard is empty".
		log.Printf("[auth/session] OIDC discovery failed: %v", err)
		return "", false
	}

	idToken, err := verifier.Verify(ctx, token)
	if err != nil {
		// The token is never logged, and neither is the error verbatim: a JWT
		// error message quotes the token in some libraries.
		log.Print("[auth/session] the presented token did not verify")
		return "", false
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"`
		UPN           string `json:"upn"`
		PreferredName string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return "", false
	}

	// ADFS puts the address in upn and not in email unless a claim rule says
	// otherwise, and preferred_username is an address on several providers.
	// Taking the first one that looks like an address is what makes this work
	// against a directory nobody is going to reconfigure for us.
	email := firstAddress(claims.Email, claims.UPN, claims.PreferredName)
	if email == "" {
		log.Print("[auth/session] the token carried no address claim (email, upn or preferred_username)")
		return "", false
	}

	authVerifiedRemember(token, email)
	return email, true
}

func firstAddress(candidates ...string) string {
	for _, c := range candidates {
		c = strings.ToLower(strings.TrimSpace(c))
		if c != "" && strings.Contains(c, "@") {
			return c
		}
	}
	return ""
}

// authIdentityConfigured reports whether this deployment can prove who somebody
// is. It is the gate on /auth/session: without one there is nothing to verify a
// token against, and a sign-in that cannot be verified must not mint anything.
func authIdentityConfigured() bool {
	return oidcConfigured() || authSupabaseBase() != ""
}
