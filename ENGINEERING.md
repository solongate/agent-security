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
touched, and what a stub server does NOT receive. Nothing in it imports any
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

The whole suite passes against the Go binary and against the Node hook, and CI
runs it twice for that reason — which of the two decides a call depends only on
whether a machine has the binary, so certifying one certifies half the machines:

- rate limit, including the ceiling under 30 parallel calls
- where the record goes: the configured folder, the default when none is named,
  and a folder from another OS falling back rather than dropping the entry
- DLP built-in patterns and custom globs, and the 70 names agreeing across five
  copies of the list
- deny latency: a denial is answered without waiting for anything, and is recorded
- the legacy scratch sweep, and only our own files
- **policy evaluation**, in both modes, and the MCP proxy's engine agreeing with the
  guard case for case
- tamper protection by every route a tool can take, not only the shell

THE POLICY IS A FILE, and there are exactly two:

- `~/.solongate/policy.json` — this machine's own. The whole file: rules, the
  layers in `security`, and the tamper flag.
- `./policy.json` beside the working directory, read when the machine has no file
  of its own, and carrying RULES ONLY. It lives inside a repository the agent can
  write to, so `selfProtect` and `security` are stripped from it — either would be
  a way for the agent to switch a protection off from inside the checkout.

Both are read in two spellings: the bare policy document, and an envelope
`{policy, security, selfProtect}`. The PRESENCE of a `policy` key is what tells
them apart, even when its value is null — a file carrying layers and no rules is a
real configuration, and requiring a non-null policy threw one away in Go while the
hook accepted it.

There was a policy CACHE in front of all this, holding a service's answer with a
TTL, a last-known-good fallback and a background refresh. It is gone, and while it
remained it was worse than dead: a service answering with an EMPTY security block
outranked the file by design, so a machine whose own file configured DLP had it
switched off by a reply that said nothing about it.

Evaluation compiles the policy JSON to Rego IN the guard, which is the reason the
decision never needed a network. `packages/guard-go/rego.go` is the generator, and
it emits valid Rego for a case the original did not (a policy whose first rule is
disabled emits a chain opening with `} else :=`). The hook and the MCP proxy share
`packages/proxy/hooks/policy-eval.mjs` rather than carrying an evaluator each.

The extractors are in `extract.go` and are where the care went: glob dodges
(`cut staging.e*` resolving to the real file), inlining referenced file contents
for exec tools only, and excluding body fields for non-exec tools so writing a
document that mentions a secret is not treated as reading one.

Not ported:

- **The deny flag** (`.last-deny`), which tells the audit hook not to log a
  second, ALLOW-looking entry for a call the guard already blocked. Left out
  deliberately rather than guessed: it carries a fingerprint of the raw
  `tool_input`, and Go's `json.Marshal` sorts object keys where JavaScript's
  `JSON.stringify` preserves insertion order, so a re-serialised fingerprint
  would silently never match the one `audit.mjs` computes. It needs the raw
  bytes and a test pinning both sides.

That list was longer and two of its entries were wrong, which is worth recording
because both read as caution and were staleness. The Antigravity adapter IS
ported (`clients.go`), and so is the DLP read-redaction plan, which `main.go`
calls for any client that cannot redact a tool's output itself. Prompt injection
scoring was the third: it was never wired into either implementation after the PI
layer was removed, so `injection.go` and the hook's `detectPromptInjection` were
both dead code, and they are gone rather than described.

The OPA WASM path is not on the list either, and not because it was never written.
It read a bundle a SERVICE compiled; with none to fetch, what decided was always
the local evaluator. The bundle READER is still there, being pure and tested.

Tamper protection IS wired and enforced — `tamperCheck` runs before policy in
main.go — which an even earlier version of this list said otherwise about.

## What the server left behind

Two sections here described `apps/system` — the schema generated for two dialects,
and the OAuth device grant a terminal signs in with. The server is deleted and they
went with it. Three things it taught are not about a server at all:

- **A provisioning endpoint trusted an e-mail in the REQUEST BODY.** It logged
  "provisioning is running unverified" and minted a credential for whatever address
  the body named — a credential for any account, to anybody who could reach it. It
  was found by the CI job that signed a device in against a real Keycloak, which no
  amount of reading had found. A test against a stub could not have: the stub was
  written to the same wrong assumption.
- **A schema applied to a real database is not the same as one that compiles.**
  Applying the DDL to a real PostgreSQL and a real SQLite caught three conversion
  bugs that every unit test had passed.
- **A build tag is where broken code hides.** The store's PostgreSQL tests were
  behind `//go:build postgres`, so they compiled nowhere in CI until a job was
  added to vet them — and one of them was broken when it was.

## Traps worth not rediscovering

- **A TEST CAN PIN A BROKEN PRODUCT AND STAY GREEN.** `Install()` resolved a
  credential first and returned `no login on this device — add an account first
  (Accounts → + add)` when it found none. Nothing writes a credential on this build
  and the Accounts panel is deleted, so it found none on every machine: the one
  command that arms the guard refused to run, and `solongate repair` refused with
  it. A test required exactly that refusal, and passed. So did its sibling, which
  required `repair` to exit non-zero and print "no login on this device".
  Both tests were correct when written and became a specification for a product
  that could not be installed. When behaviour is removed, the tests that described
  it do not fail — they start guarding the wrong thing.
- **`go test` caches a PASS for a test whose subject was deleted.** A test that
  read every Dockerfile and required a COPY per replaced Go module refused to pass
  vacuously — "the test passed without testing anything" — so deleting the last
  Dockerfile made it FAIL, exactly as it should. Then the cache served the previous
  result until an unrelated edit in another package invalidated it. CI runs
  `go test -count=1` now; a cached pass is not evidence.
- **`spawnSync` blocks the process it is called from.** If a stub server lives
  in that process it can never answer, the guard's request hangs, and what gets
  measured is the guard's own 8-second backstop. Two separate benchmarks were
  wrong this way before it was spotted.
- **The 8s backstop exits with `process.exitCode || 0`.** Anything slow that
  runs before the verdict is emitted turns a DENY into an ALLOW. It already did
  once, via the hook self-update — 8043ms, exit 0, on a call DLP had refused. The
  self-update is gone; the rule is not.
- **A DENY WINS OVER AN ALLOW, whatever the priorities say.** The priority orders
  rules of one effect. Sorting the Rego chain by priority alone let an ALLOW
  written above a DENY win, in both modes, and made REORDERING RULES change what
  was enforced with no number anywhere to explain why. The Node hook and
  FallbackEvaluate both ran a DENY pass first; only the Rego generator did not, and
  it is the one that decides.
- **A second implementation is a second set of answers.** Five divergences have
  been found between the Go guard and the Node hook, every one by running the same
  conformance suite against both: the tamper globs disagreeing about `*` after a
  `**`, the DLP list running 14 patterns against 70, the Rego ordering above, a
  policy file carrying layers with no rules that one side threw away, and the
  EGRESS check — a `curl -d @creds.env` uploading a file full of keys, which the Go
  guard blocked and the Node hook allowed. None was visible from either side alone.
- **Dead code in a security path is not inert, it is a hole.** The egress
  divergence was not a difference in the check; it was that the Node hook ran it
  only inside a fast path gated on reading a policy CACHE, and nothing had written
  one since the refresh was removed. The gate was false on every call, so the
  check never ran. Two more readers of that same cache were doing something worse
  than nothing: one let a stale cache OUTRANK the policy file and switch off the
  DLP it configured, and one fell back to "every built-in pattern, no custom ones"
  on the only surface that sees the prompt. When something stops being written, the
  question is not whether its readers still compile — it is what each of them does
  when the answer is always missing.
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
