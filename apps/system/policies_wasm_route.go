package main

import (
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strconv"

	"github.com/codeyevsky/solongate/system/internal/apiauth"
	"github.com/codeyevsky/solongate/system/internal/policycompile"
	"github.com/codeyevsky/solongate/system/internal/store"
)

// GET /api/v1/policies/{id}/wasm — src/app/api/v1/policies/[id]/wasm/route.ts.
//
// The file is NOT called policies_wasm.go, and that is not a style choice: `go
// build` reads a trailing `_wasm.go` as the GOARCH=wasm build constraint and
// drops the file from every other target. It compiled, it vetted, and the route
// answered 501 from the placeholder with nothing to say why.
//
// This is the delivery half of the compiler in internal/policycompile: the
// guard hook fetches this URL, gunzips the body, walks the tar for
// `policy.wasm` and instantiates it. Everything it needs is decided here and
// none of it is visible in a 200:
//
//   - The BYTES are the OPA bundle exactly as it was built. wasm_bundle stores
//     it base64 and this route decodes it — serving the base64 text would be a
//     200 the hook cannot gunzip.
//   - The CONTENT TYPE is application/wasm, which is what the deployed hook
//     expects to see even though the body is a gzipped tar rather than a bare
//     module. It is the live header and it is not ours to correct.
//   - The response is NOT compressed again. Nothing in this binary wraps a
//     handler in gzip, and if anything ever did, this route would have to opt
//     out: the hook gunzips exactly once.
//
// A wrong answer here fails on somebody's laptop, inside a WebAssembly
// instantiation error, not in this service's logs. That is why the fallback
// below compiles rather than 404s where it can.

func init() {
	Register("GET /api/v1/policies/{id}/wasm", buildPolicyHandler((*server).policyWasm))
}

func (s *server) policyWasm(w http.ResponseWriter, r *http.Request, key apiauth.KeyInfo) {
	policyID := r.PathValue("id")
	ctx := r.Context()

	bundleB64 := ""
	var version int64

	// The bundle for the NEWEST revision, or none.
	//
	// This used to serve the newest revision that HAPPENED to have a bundle,
	// falling back through the history until it found one. The reasoning was
	// that a policy saved while compilation was unavailable carries a NULL
	// wasm_bundle and one version back is a working build — but "a working
	// build" of a policy the user has since changed is the wrong policy. It
	// enforces rules they deleted and misses the ones they just wrote, and the
	// denial cites a rule id that is no longer in their policy at all.
	//
	// Whatever this serves, a guard will enforce as though it were current. So
	// it is the current one or nothing: with no bundle the guard falls through
	// to its deterministic evaluator, which reads the policy it actually holds.
	// Slower and correct beats fast and enforcing a deleted rule.
	latest, err := s.store.LatestPolicyByID(ctx, key.ProjectID, policyID)
	switch {
	case err == nil:
		bundleB64, version = latest.WasmBundle, latest.Version
	case !errors.Is(err, store.ErrNotFound):
		apiauth.Internal(w, "api", err)
		return
	}

	if bundleB64 == "" && err == nil {
		// Not compiled yet: build THIS revision now and store both forms, so
		// whichever of /rego and /wasm is asked first fills in the other.
		// Caching is best-effort — a policy that compiles but cannot be written
		// back is still a policy this request can answer with, and failing here
		// would leave a guard with no bundle over a database hiccup.
		if opa, ok := policycompile.Compile(ctx, latest.PolicyData); ok {
			if err := s.store.SetCompiledForms(ctx, key.ProjectID, latest.ID,
				opa.RegoSource, opa.WasmBundleB64); err != nil {
				log.Printf("[API:api] could not cache the compiled policy: %v", err)
			}
			bundleB64 = opa.WasmBundleB64
		}
	}

	if bundleB64 == "" {
		// The message names the OPA CLI because that is what is missing in the
		// live app, and the CLI's install instructions are what the operator
		// reading it needs. This binary links the compiler instead, so reaching
		// here means the policy itself would not build — but the string is a
		// contract with whatever is parsing it and is left alone.
		apiauth.Error(w, http.StatusNotFound, "ERROR",
			"No compiled WASM bundle found for this policy and on-demand compilation is unavailable (OPA CLI missing). Re-save the policy to trigger compilation.")
		return
	}

	// Buffer.from(b64, 'base64') never fails — it discards what it cannot
	// decode and returns a short buffer. Go's decoder says so instead, and that
	// is the better failure: a truncated bundle is a 200 the hook downloads,
	// gunzips halfway and dies on, with nothing on this side to explain it.
	bundle, err := base64.StdEncoding.DecodeString(bundleB64)
	if err != nil {
		// The bundle itself is NOT logged. It is a compiled form of the
		// project's rules and it is large.
		apiauth.Internal(w, "api", errors.New("stored wasm bundle is not valid base64"))
		return
	}

	w.Header().Set("Content-Type", "application/wasm")
	w.Header().Set("Content-Length", strconv.Itoa(len(bundle)))
	w.Header().Set("X-Policy-Version", strconv.FormatInt(version, 10))
	// no-cache, not no-store: the hook is allowed to keep the bundle and
	// revalidate. It polls for the policy hash separately and refetches when
	// that moves, so a cached body that is checked each time is the intended
	// behaviour and is what the live header asks for.
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(bundle)
}

// policyWasmVariant is which variant this caller enforces, and empty whenever
// the answer is "the one already in wasm_bundle".
//
// variantBundle is the cached build for one variant, compiled on the first ask.
//
