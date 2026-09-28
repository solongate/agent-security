# SolonGate

A policy gate for AI coding agents. It sits in front of every tool call an agent
makes — every shell command, every file read, every write — and decides whether
it runs, against rules you wrote.

The decision happens **on the machine**, in a hook the agent calls before it
acts. There is no round trip on the decision path: the policy is compiled to
Rego and evaluated locally, so a laptop on a plane enforces the same rules as one
in an office.

Supported agents: **Claude Code**, **Codex**, **OpenCode**, **Antigravity**.

## What is here

| | |
| --- | --- |
| `packages/guard-go` | The hook. Runs on every tool call and decides. |
| `packages/proxy` | The CLI and TUI (npm package `@solongate/proxy`, command `solongate`). |
| `packages/proxy-go` | The same CLI in Go, which is what ships as the binary. |
| `packages/sgpolicy` | The policy engine: JSON rules → Rego. |
| `apps/system` | The optional server side: policies and the audit log for many machines, and sign-in. |
| `packages/sgshared` | Shapes more than one program has to agree about. |
| `packages/aicatalog` | The model catalogue. |

Everything runs on infrastructure you operate. There is no hosted service, and no
default in this repository points at one.

## Running it on one machine

Nothing else is needed for this: no database, no server, no account, no sign-in.
Install the guard, write a file, and the next tool call is decided against it.

```bash
npm i -g @solongate/proxy
solongate                    # the dataroom; install the guard from Settings
```

Then `~/.solongate/policy.json`:

```json
{
  "mode": "denylist",
  "rules": [
    {
      "id": "no-force-push",
      "description": "Rewriting shared history is not an agent's decision",
      "effect": "DENY",
      "priority": 10,
      "enabled": true,
      "toolPattern": "*",
      "minimumTrustLevel": "UNTRUSTED",
      "commandConstraints": { "denied": ["*push --force*", "*push -f*"] }
    }
  ]
}
```

`git push --force` and `git push -f` are refused from that point; `git push` is
not. Denials are appended to
`~/.solongate/local-logs/solongate-audit.jsonl`, owner-only, and nothing leaves
the machine — with no credential there is nothing to send anywhere and no attempt
is made.

The same file can also carry the rate limit, the egress rules and the DLP
scanner. Wrap the policy and add `security`, which is the shape a service sends:

```json
{
  "policy": { "mode": "denylist", "rules": [] },
  "security": { "rateLimit": { "mode": "enforce", "perMinute": 60 } }
}
```

A `policy.json` beside your working directory is read when the machine has no file of
its own. It may add **rules and nothing else**: it lives in a repository the agent
can write to, so `selfProtect` and `security` are ignored there.

## Running the service

Optional, and what it adds is one place to keep the policy and the audit log for
many machines, plus sign-in so it knows who is asking. The decision still happens
on each machine, against a policy cached there.

### 1. The database

PostgreSQL, or a local sqlite file. Apply the schema for your dialect — both are
generated from one source and checked in:

```bash
createdb solongate
psql solongate -v ON_ERROR_STOP=1 -f tools/schema/postgres.sql
```

Do not edit those files. Regenerate them, and read the complete schema for either
dialect without starting anything, with:

```bash
cd apps/system && go run ./cmd/schemadump -dialect postgres
```

A hardened installation can apply the file and never give the application CREATE
rights: the system's own `EnsureRuntimeTables` then finds everything already there
and does nothing, which is the same code path either way.

For a seeded sqlite database to develop against, with a credential printed:

```bash
node tools/local-db.mjs
```

### 2. The API

```bash
cp .env.example .env      # then fill in DATABASE_URL
cd apps/system && go run .
```

It listens on `:3002`. Every option is in [`.env.example`](.env.example); the
only required one is `DATABASE_URL`.

Sign-in is against **your** identity provider, and it is required: with none
configured `/auth/session` answers 503 rather than trusting the caller.

Set `SG_OIDC_ISSUER` and `SG_OIDC_CLIENT_ID`. The client needs two properties and
no others:

- the **device authorization grant** enabled — it is the only sign-in a terminal
  can complete
- **public**, with no client secret, which is correct for one that runs on a
  laptop and can hold none

The system verifies the ID tokens that provider issues, and
`GET /api/v1/auth/config` is how each CLI learns where to send somebody, so
nothing is configured per machine.

<details>
<summary>Keycloak, as a worked example</summary>

```bash
KC=http://localhost:8080
TOKEN=$(curl -s -d client_id=admin-cli -d username=admin -d password=admin \
          -d grant_type=password "$KC/realms/master/protocol/openid-connect/token" \
        | python3 -c "import json,sys;print(json.load(sys.stdin)['access_token'])")

curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$KC/admin/realms" -d '{"realm":"solongate","enabled":true}'

curl -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  "$KC/admin/realms/solongate/clients" \
  -d '{"clientId":"solongate-cli","publicClient":true,"standardFlowEnabled":false,
       "attributes":{"oauth2.device.authorization.grant.enabled":"true"}}'
```

Then `SG_OIDC_ISSUER=$KC/realms/solongate` and `SG_OIDC_CLIENT_ID=solongate-cli`.
CI runs exactly this against a real Keycloak and signs in end to end, so these
instructions are executed rather than believed.

</details>

Without `SG_OIDC_ISSUER` there is nobody to sign in against and the CLI says so.
For local development, `tools/local-db.mjs` seeds a project and prints a
credential to use directly.

With Docker instead:

```bash
docker build -f Dockerfile.system -t solongate-system .
docker run -p 3002:8080 -e DATABASE_URL=… solongate-system
```

### 3. Each developer's machine joins it

The guard is already installed from the section above; what is left is pointing it
at the service. That is an account, added from the same Settings panel, and it
signs in **against your identity provider**, not against us.
The CLI shows a code, the person enters it at the provider — on the laptop, or on
a phone if the laptop is headless — and the provider issues a token the service
verifies against the provider's own keys. That is the OAuth device grant
(RFC 8628), the same flow `gh` and `az` use, and for the same reason: a terminal
cannot receive a redirect, and a browser is the only place anybody should type a
password.

```
  Enter this code:
  WDJB-MJHT

  at:
  https://idp.example.com/activate
```

Nobody types a credential. The exchange writes one and every command reads it
from there.

Point it at your API:

```bash
export SOLONGATE_API_URL=https://solongate.internal.example.com
```

It defaults to `http://127.0.0.1:3002`.

## The CLI

```
solongate                    the dataroom (policies, audit, settings)
solongate policy             list, create, edit and activate policies
solongate ratelimit          show and edit rate limits
solongate dlp                show and edit secret detection
solongate audit              browse the audit log
solongate watch              live-tail tool calls
solongate trace              what the guard saw in this directory
solongate stats              traffic and security statistics
solongate doctor             health check: policy, guard, local logs
solongate repair             restore the guard, hooks and settings files
```

Every one of these reads or changes a security posture, so they refuse to run
without an interactive terminal and refuse when an agent marker is in the
environment. A prompt-injected agent must not be able to switch off the thing
watching it.

## Developing

Go 1.25 and Node 22.5+ (tools/local-db.mjs seeds through `node:sqlite`).

```bash
pnpm install

cd apps/system       && go test ./...
cd packages/guard-go && go test ./...
cd packages/proxy-go && go test ./...
cd packages/proxy    && npx tsc --noEmit -p tsconfig.json

node tools/dev-go.mjs        # build and run the system locally
```

**The conformance suite is the contract.** It runs the guard as a subprocess,
feeds it a client payload, and asserts on the exit code, the files touched and
what reached a stub cloud — without importing any implementation's internals.

Two things it needs, and neither announces itself:

- `dist/` has to exist — it imports the built JavaScript, and on a fresh clone it
  fails to resolve a module rather than saying so.
- `SG_HOOK` has to name a guard. The default is the hook installed in your home
  directory, so a machine with SolonGate installed passes and a fresh one fails
  five of the ten files against a path that is not there.

```bash
cd packages/proxy && npx tsc -p tsconfig.json    # once, or after a change
SG_HOOK=$PWD/packages/proxy/hooks/guard.bundled.mjs \
  node packages/proxy/test/run-all.mjs
```

The bundled build is the one that ships — the installer prefers it, with
opa-wasm inlined — so it is the one worth judging. Point `SG_HOOK` at any other
implementation to judge that instead; nothing in the suite imports internals.

A change to the guard is correct exactly when this passes unchanged. Every case
in it exists because the behaviour it pins was once wrong, and the comments say
which.

[ENGINEERING.md](ENGINEERING.md) is the rest: why Go, where the guard stands, and
the failure modes that cost somebody a day.

## Licence

MIT. See [LICENSE](LICENSE).
