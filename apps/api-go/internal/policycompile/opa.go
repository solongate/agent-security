package policycompile

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/open-policy-agent/opa/compile"
)

// The port of src/lib/opa-compiler.ts and src/lib/opa/rego-compiler.ts.
//
// The live app shells out to the `opa` CLI and returns null when it is not on
// the PATH, which is why every policy write carries `_opa_compiled` and why the
// wasm column is NULL for a lot of rows. This binary links OPA's compiler
// instead, so there is no external program to be missing — but the failure
// SHAPE is kept: a compilation that does not work returns ok=false, the policy
// is still saved, and `_opa_compiled` is false. Refusing to save a policy
// because its WASM build failed would be a new way for this endpoint to reject
// work the old one accepted.
//
// The entrypoint and the bundle format are a contract with an installed client:
// guard.mjs fetches /policies/{id}/wasm, gunzips it, walks the tar for
// `policy.wasm` and evaluates `solongate/policy/decision`. That is what `opa
// build -t wasm -e solongate/policy/decision` produces and what this reproduces
// — a bare .wasm file here would be a 200 the guard cannot read.

// Result is what a successful compilation yields: the Rego source that was
// compiled and the gzipped OPA bundle around it, base64 as the column stores
// it.
type Result struct {
	RegoSource      string
	WasmBundleB64   string
	WasmUnavailable bool
}

// Entrypoint is the rule guard.mjs evaluates. Changing it makes every installed
// hook evaluate `undefined`, which it reads as "no decision" and treats as
// allow.
const Entrypoint = "solongate/policy/decision"

// compileTimeout matches the live app's execFileSync timeout. A policy that
// takes longer than this to build is one nobody is waiting on any more, and the
// request that triggered it is holding a Turso connection while it waits.
const compileTimeout = 30 * time.Second

// regoHelpers is rego-compiler.ts's second file, verbatim.
//
// It defines path_matches_any and list_matches_any, which convertPolicySetToRego
// ALSO emits — so the compiled module carries each of them twice. That is not a
// bug to fix here: Rego allows a function to have several definitions, the two
// are identical, and removing this file would change the bundle this service
// has been serving. It is the input the live compiler is given, so it is the
// input this one is given.
const regoHelpers = `package solongate.policy

import rego.v1

# Helper: checks if a path matches any pattern in a list.
# Segment semantics, compiled to a regex by sgpolicy.PathPatternRegex — see the
# note there. This definition and the one convertPolicySetToRego emits are both
# in the module, and Rego ORs a function's definitions together: leaving the old
# glob.match one here would keep matching the paths the new one deliberately
# stopped matching, which is precisely the bug being fixed.
path_matches_any(path, patterns) if {
    some pattern in patterns
    regex.match(pattern, path)
}

# Helper: checks if an item matches any pattern in a list using glob
list_matches_any(item, patterns) if {
    some pattern in patterns
    glob.match(pattern, [], item)
}
`

// ErrNoRules is what a policy whose `rules` will not decode as an array gets.
// The original throws out of `[...policySet.rules]` and the catch turns it into
// null; naming it here keeps the caller's branch readable.
var ErrNoRules = errors.New("policycompile: policy has no rules array")

// Compile turns a stored policy into its Rego source and its WASM bundle.
//
// ok=false means the policy could not be compiled AT ALL — no rules array —
// and matches `compilePolicyToOpa` returning null. A policy that compiles to
// Rego but not to WASM comes back ok=true with WasmUnavailable set and an empty
// bundle, because the Rego is still worth storing and /policies/{id}/rego is
// still worth answering.
func Compile(ctx context.Context, policyData json.RawMessage) (Result, bool) {
	rules, ok := rulesOf(policyData)
	if !ok {
		return Result{}, false
	}
	rego := ConvertRulesToRego(rules)

	wasm, err := CompileRegoToWasm(ctx, rego)
	if err != nil {
		return Result{RegoSource: rego, WasmUnavailable: true}, true
	}
	return Result{RegoSource: rego, WasmBundleB64: base64.StdEncoding.EncodeToString(wasm)}, true
}

// rulesOf pulls the `rules` array out of a policy without decoding the rest of
// it. Nothing here needs the policy's other fields, and decoding them into a
// struct is how a policy loses whatever this version does not know about.
func rulesOf(policyData json.RawMessage) ([]PolicyRule, bool) {
	if len(policyData) == 0 {
		return nil, false
	}
	var envelope struct {
		Rules json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(policyData, &envelope); err != nil {
		return nil, false
	}
	return ParsePolicyRules(envelope.Rules)
}

// CompileRegoToWasm builds the OPA bundle.
//
// The compiler reads from a directory rather than from memory because that is
// the interface OPA's own `build` command uses and the one its loader is
// exercised by. The directory is under os.MkdirTemp and removed on the way out,
// including on the error path — a failed build that leaves its working files
// behind fills a container's disk one policy save at a time.
func CompileRegoToWasm(ctx context.Context, regoSource string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, compileTimeout)
	defer cancel()

	dir, err := os.MkdirTemp("", "solongate-opa-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	if err := os.WriteFile(filepath.Join(dir, "policy.rego"), []byte(regoSource), 0o600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "helpers.rego"), []byte(regoHelpers), 0o600); err != nil {
		return nil, err
	}

	var out bytes.Buffer
	c := compile.New().
		WithTarget(compile.TargetWasm).
		WithEntrypoints(Entrypoint).
		WithPaths(dir).
		WithOutput(&out)
	if err := c.Build(ctx); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
