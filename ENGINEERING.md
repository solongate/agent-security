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

    node packages/proxy/test/run-all.mjs                    # installed hook
    SG_HOOK=/abs/path/to/solongate-guard node ...           # a candidate

The path has to be absolute: the suite spawns the guard with `cwd` set to a
sandbox, so a relative one resolves against that and fails with ENOENT.

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
produces byte-identical Rego for every policy the API compiles, plus valid Rego
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
- **The layers that run before policy**: tamper protection, ghost, prompt
  injection, and the DLP read-redaction plan. This is why the Go binary is not
  the installed guard. It is faster than the Node hook and agrees with it on
  everything the suite covers, but it does not yet cover everything the Node
  hook enforces, and shipping it as the live guard before it does would be
  exactly the "fast but unguarded" trade the rule above forbids.
- **The deny flag** (`.last-deny`), which tells the audit hook not to log a
  second, ALLOW-looking entry for a call the guard already blocked. Left out
  deliberately rather than guessed: it carries a fingerprint of the raw
  `tool_input`, and Go's `json.Marshal` sorts object keys where JavaScript's
  `JSON.stringify` preserves insertion order, so a re-serialised fingerprint
  would silently never match the one `audit.mjs` computes. It needs the raw
  bytes and a test pinning both sides.

## The schema

The API writes SQL by hand against 21 base tables plus 7 it creates itself.

**One source, two dialects.** `apps/api-go/internal/store/baseschema.sql` is the
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

    cd apps/api-go && go run ./cmd/schemadump -dialect postgres
    node tools/local-db.mjs                       # a seeded sqlite copy to run against

## Pairing is unfinished

A machine gets its credential by device flow: the CLI asks the API for a code,
the person approves it, and the CLI polls until a credential comes back. Two
things about that are not finished, and they are the same thing seen twice.

**There is no page to approve on.** `POST /auth/device/start` answers with a
`verification_uri` built from `DASHBOARD_URL`, pointing at a `/cli` page the web
dashboard served. That dashboard is not part of this build. With `DASHBOARD_URL`
unset the API now OMITS the two URI fields rather than emitting a relative path a
CLI would try to open — absent keys are something a caller can detect, a
malformed URL is not — but omitting them does not give anybody somewhere to click.

**And approve trusts the request body.** `POST /auth/device/approve` takes
`{user_code, email}` and mints a live credential for that address WITHOUT
verifying it. Possession of a pending user code is the whole authorisation; the
only other protection is a per-IP rate limit. That was defensible while the
dashboard was the one caller, because the dashboard had already authenticated the
person. With no dashboard it is the only way in and it verifies nothing.

Either shape closes both:

- **Serve the approval page from the API.** Keeps the contract the installed CLIs
  already speak, and `approve` starts requiring a verified session — the email
  comes from the token instead of the body. Needs the OIDC authorization-code
  flow, which the deleted dashboard had and this service does not.
- **Drop the device flow.** The operator provisions the credential and the
  machine reads it from the environment. Smaller, and it fits a CLI-only product
  — but it puts a credential in somebody's hands, which is the thing the pairing
  flow exists to avoid.

Until one of them lands, treat this build as running only where a credential is
placed by hand: `SOLONGATE_API_KEY`, or a row seeded by `tools/local-db.mjs`.

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
