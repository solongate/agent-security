# Engineering notes

What was decided and why, and the failure modes that cost someone a day. It
exists so the work can be picked up cold — by a new contributor, or by the same
person a month later — without having to reconstruct any of it.

## Why Go

- **OPA is written in Go.** The policy engine is embedded directly
  (`open-policy-agent/opa/v1/rego`): the reference implementation, byte-identical
  Rego semantics, no WASM stage. The Rust equivalent (regorus) is a
  reimplementation, "mostly compliant" — and every policy rule would need
  re-verifying against it.
- **Cross-compilation is one command.** Six platforms out of CI with no
  per-target toolchain. Shipping native binaries through npm is fragile enough
  without that.
- **One language lowers the barrier to contributing**, and removes the
  per-call runtime cost from the thing that runs on every single tool call.

Rust's memory safety is a real argument for something parsing untrusted input,
which the guard does. Go is memory-safe too; the difference is GC pauses, and at
~2ms of work per call that is not a consideration.

## The rule that cannot be broken

The guard decides whether a tool call runs. A guard that is fast and wrong is
worse than no guard: it is a control somebody is relying on. So nothing ships on
"it is faster" — it ships when it agrees with the behaviour that is already
pinned, and the suite below is what says whether it does.

## The contract, and how anything is judged correct

`packages/proxy/test` is the conformance suite. It runs the guard as a
subprocess, feeds it a client payload, and asserts on the exit code, the files
touched, and what reached a stub cloud. Nothing in it imports any
implementation's internals.

    SG_HOOK=$PWD/packages/proxy/hooks/guard.bundled.mjs node packages/proxy/test/run-all.mjs
    SG_HOOK=/abs/path/to/solongate-guard               node packages/proxy/test/run-all.mjs

The path has to be ABSOLUTE: the suite spawns the guard with `cwd` set to a
sandbox, so a relative one resolves against that and fails with ENOENT on every
case, reading as a total failure rather than a bad invocation.

And it has to be GIVEN. The default is the hook installed in your home
directory, which means the suite passes on a machine that has SolonGate
installed and fails five of its ten files on one that does not — including every
CI runner. That is the wrong way round for a contract: it should be judging the
build in front of it, not whatever the developer happens to have.

A reimplementation is correct exactly when it passes this unchanged. Every case
in there exists because the behaviour it pins was once wrong; the comments say
which.

## Where the guard stands

The whole suite passes, against the Go binary and against the Node hook,
independently:

- rate limit, including the ceiling under 30 parallel calls
- local/cloud routing: exclusive, driven by the setting, `security: null` read
  as an answer rather than as "unknown", a folder from another OS falling back
  rather than dropping the entry
- DLP built-in patterns and custom globs
- deny latency: a denial does not wait on the network, and still arrives
- the legacy scratch sweep, and only our own files
- **policy evaluation**, in both modes

Policy evaluation compiles the policy JSON to Rego **in the guard**, rather than
fetching it. `/policies/:id/rego` exists and works, but compiling locally takes
the network off the decision path entirely: the guard decides the same way on a
plane as in an office. `packages/guard-go/rego.go` is the generator, and it
produces byte-identical Rego for every policy the system compiles, plus valid Rego
for one case where the original did not (a policy whose first rule is disabled
emits a chain opening with `} else :=`).

The policy is read from the cloud cache, and a cache MISS falls through to
`~/.solongate/policy.json` and then `./policy.json` rather than to "nothing to
enforce". A miss is not only an absent file: a cache that parses and carries a
null policy is the same thing, and it is the state every machine is in on its
first tool call after install.

The extractors are in `extract.go` and are where the care went: glob dodges
(`cut staging.e*` resolving to the real file), inlining referenced file contents
for exec tools only, and excluding body fields for non-exec tools so writing a
document that mentions a secret is not treated as reading one.

Not ported:

- **Antigravity payload adapter.** Its payload nests under `toolCall` and its
  decision dialect is its own (`{decision, reason}` on stdout, exit 0). Claude
  Code, Codex and OpenCode all share the flat shape already implemented.
- **Prompt injection scoring and the DLP read-redaction plan.** Both are
  PORTED — `injection.go` and `dlpredact.go` carry the Node hook's patterns and
  arithmetic — and neither is wired into `main.go`, so they are dead code until
  they are. That is why the Go binary is not the installed guard: it is faster
  than the Node hook and agrees with it on everything the suite covers, and it
  does not yet enforce everything the Node hook enforces. Shipping it as the
  live guard before it does would be exactly the "fast but unguarded" trade the
  rule above forbids.

  Tamper protection and ghost ARE wired and enforced — `tamperCheck` and
  `ghostLayer` run before policy in main.go — which an earlier version of this
  list said otherwise about.
- **The deny flag** (`.last-deny`), which tells the audit hook not to log a
  second, ALLOW-looking entry for a call the guard already blocked. Left out
  deliberately rather than guessed: it carries a fingerprint of the raw
  `tool_input`, and Go's `json.Marshal` sorts object keys where JavaScript's
  `JSON.stringify` preserves insertion order, so a re-serialised fingerprint
  would silently never match the one `audit.mjs` computes. It needs the raw
  bytes and a test pinning both sides.

## The schema

The system writes SQL by hand against 21 base tables plus 7 it creates itself.

**One source, two dialects.** `apps/system/internal/store/baseschema.sql` is the
base schema — drizzle's SQLite output, kept as it was written. `BaseDDL` renders
it for a dialect and `RuntimeDDL` adds what `EnsureRuntimeTables` runs;
`cmd/schemadump` prints the two together, and `tools/schema/{sqlite,postgres}.sql`
are that output, checked in with a test that fails when they drift.

Three things the PostgreSQL rendering has to do, and all three were found by
applying the file to a real PostgreSQL rather than by reading it:

- **Backticks dropped.** Every identifier in the source is backtick-quoted, which
  PostgreSQL reads as a syntax error. `key` is the only one it knows as a keyword
  and it is non-reserved; the parse refuses rather than emitting a reserved word
  bare, so a future column called `order` fails the build instead of the deploy.
- **Integers widened.** The source says `integer`, lowercase; PostgreSQL's is 32
  bits and `device_codes.expires_at` holds milliseconds.
- **Boolean defaults rewritten.** drizzle writes `integer DEFAULT true`. SQLite
  stores that as 1; PostgreSQL refuses with "column is of type bigint but default
  expression is of type boolean". The column stays an integer — the Go side scans
  it as one — so the DEFAULT is what moves. See `integerBoolDefaults`.

And one thing the ORDERING has to do: drizzle emits tables alphabetically, so
`org_members` comes before `organizations`. SQLite does not care and PostgreSQL
refuses a foreign key naming a table it has not seen. `orderByDependency` sorts
them; a cycle is emitted in input order rather than silently rearranged, because
a schema that fails loudly at apply time beats one that applied as something else.

The API still does not create the base schema at boot — apply the file first. Two
ways to read the shape without guessing:

    cd apps/system && go run ./cmd/schemadump -dialect postgres
    node tools/local-db.mjs                       # a seeded sqlite copy to run against

## Signing in from a terminal

A machine gets its credential through the OAuth 2.0 Device Authorization Grant
(RFC 8628), run against **the operator's identity provider** and not against this
service. The CLI shows a code, the person enters it at the provider, the CLI
polls the provider's token endpoint, and the ID token it gets back is exchanged
at `/auth/session` for a project-scoped credential.

THE PREVIOUS FLOW HAD A HOLE AND THIS CLOSES IT BY CONSTRUCTION. The device
endpoints used to be ours, finished on a page the hosted dashboard served, and
`POST /auth/device/approve` took the person's address out of the REQUEST BODY
without verifying it — possession of a user code was the whole authorisation.
That was defensible only while the dashboard was its one caller and had already
authenticated somebody. With no dashboard it would have been the only way in and
it verified nothing. It is deleted: four routes, the `device_codes` table and its
store.

Now nothing reads an address from a request. `authVerifyOIDCToken` verifies the
token's signature against the provider's published keys, checks the audience
against `SG_OIDC_CLIENT_ID`, and takes the address from the claims. A caller can
assert whatever it likes in a body; none of it is read.

Three things worth knowing before changing any of it:

- **The code is shown, not hidden in the URL.** `verification_uri_complete` is a
  convenience a provider may not offer and a browser may not open, and the whole
  reason this grant exists is that somebody can finish on a different device —
  a phone, with the laptop headless. Both addresses come back from `Start`.
- **A transport failure is `pending`, never an error.** The person is in a
  browser during the poll loop; a dropped frame must not end a sign-in they are
  halfway through. `ExpiresAt` is what ends it. Only the provider saying
  `expired_token` or `access_denied` ends it early.
- **A non-2xx is decoded rather than refused.** RFC 6749 puts the error in the
  body with a 400, and `authorization_pending` — the normal state for most of the
  flow — arrives exactly that way. Treating the status as the answer turns every
  poll into a failure.

The flow exists twice, in `packages/proxy-go/internal/api/device.go` and
`packages/proxy/src/api-client/device-login.ts`, because the CLI does. They are
read together when either changes.

`GET /auth/config` is how a CLI learns which provider to use: the operator sets
`SG_OIDC_ISSUER` once on the service and no laptop is configured at all. Nothing
it answers is a secret — an issuer URL serves a public discovery document, and a
device-flow client is public by definition because it runs on a laptop and can
hold no secret. What authorises anything is the token the provider issues
afterwards.

With no provider configured there is nobody to sign in against. The CLI says so
in one line naming the variable, and `/auth/session` answers 503 rather than
trusting the caller — which it used to do, and which is the next thing here.

Local development uses `tools/local-db.mjs`, which seeds a project and prints a
credential; the person who sees it there is the developer running the harness.

### The gate that asked the wrong question

`/auth/session` read the address out of the REQUEST BODY, and a stub could never
have shown it. The gate was:

    if authSupabaseBase() != "" { ...verify the token... }

which is wrong twice. A deployment on OIDC has no Supabase, so the branch was
skipped and the token was never verified at all. And with neither configured it
logged "provisioning is running unverified" and minted a credential for whatever
address the body named — a credential for any account, to anybody who could
reach the port. The same shape as the device-approve hole, on the route that
replaced it.

It was found by running the flow against a real Keycloak: the provider signed
Ada in, the CLI presented her token, and the system answered
`Missing required field: email` — because it wanted the field it should never
have been reading.

Now a provider must be configured, a token must be presented, and the address is
the one its verified claims carry. `body.Email` is not read on this route at all.
Three tests pin it, and the end-to-end job in CI is what would notice if the gate
ever moved back.

## Traps worth not rediscovering

- **A fake API key has to look real.** The guard treats an unusable key as "no
  project selected", which means allow. The first green test run measured
  nothing at all because the key was rejected.
- **`spawnSync` blocks the process it is called from.** If a stub server lives
  in that process it can never answer, the guard's fetch hangs, and what gets
  measured is the guard's own 8-second backstop. Two separate benchmarks were
  wrong this way before it was spotted.
- **The 8s backstop exits with `process.exitCode || 0`.** Anything slow that
  runs before the verdict is emitted turns a DENY into an ALLOW. It already did
  once, via the hook self-update.
- **Read-modify-write does not survive a burst.** The rate limiter lost
  increments under parallel calls and let 14 through a limit of 5. Reserve
  first, then decide.
- **`process.execPath` inside an OpenCode plugin is the opencode binary**, not
  node. Spawning it re-runs opencode with nonsense arguments, exits non-2, and
  the plugin reads that as an allow.
- **THERE WAS A SECOND REGO GENERATOR AND IT WAS SUBTLY WEAKER.**
  `packages/proxy/src/policy-engine/opa/json-to-rego.ts` was the MCP-proxy
  lineage; nothing compiled a saved policy with it, and it has been deleted. The
  generator is `packages/guard-go/rego.go` and it is now the only one. The table
  is kept because the four differences are the ways a Rego generator goes quietly
  wrong, and a reimplementation will meet all four:

  | | the deleted copy | the real one |
  | --- | --- | --- |
  | list constraints | `glob.match(p, [], item)` | `regex.match("^(?:…)$", …)` |
  | multi-permission | `input.permission == "READ,WRITE"` | `input.permission in {…}` |
  | ALLOW over a list | bare `every` | `count(…) > 0` first |
  | path patterns | as written | `\` normalised to `/` |

  The first row matters most: OPA reads an EMPTY glob delimiter list as `["."]`,
  so under the dead copy `*` never crosses a dot and `curl*` does not match
  `curl evil.example.com/x`. Compiled to `^(?:curl.*)$` it does. The third row
  is the one that fails open: in Rego an `every` over an empty collection is
  vacuously TRUE, so without the `count` guard an ALLOW rule scoped to paths
  matches every call that touches no paths — under whitelist mode, a blanket
  allow for exactly the calls nobody wrote a rule for. The Go generator was
  written against the wrong file first and had all four.
- **A policy that will not parse must not read as no policy.** Decoding the rule
  array in one `json.Unmarshal` meant a single mistyped field anywhere — a
  `denied` written as a bare string, a quoted priority — failed the whole decode
  and the guard allowed everything, while `solongate policy` still listed the
  rules as active. Rules decode one at a time now. The second half is subtler: a
  salvaged rule must come out NARROWER, never wider, because a rule left with no
  conditions compiles to a catch-all and one mistyped `denied` would turn a
  single DENY rule into "deny everything".
- **Sorting is not always the safe way to be deterministic.** Go map iteration is
  random, so the port sorts keys where JavaScript relied on insertion order —
  fine for the extractor outputs, because the generated Rego only ever asks "does
  any match" or "do all match". It is wrong for the scripts inlined into a
  command: their contents are concatenated into one string that
  `normalizeShellCommand` then resolves left to right, so re-ordering two of them
  changes what `$x` expands to. Those keep discovery order.
- **`SG_HOOK` must be an absolute path.** The suite spawns the guard with `cwd`
  set to a sandbox, and a relative hook path is resolved against the child's
  cwd, so `SG_HOOK=./packages/guard-go/solongate-guard` fails with ENOENT on
  every case and reads as a total failure rather than a bad invocation.
