# Security policy

SolonGate decides whether an AI agent's tool call runs. A hole in it is not a
bug in a feature, it is a control that somebody is relying on and that is not
there. Reports are welcome, taken seriously, and never held against the reporter.

## Reporting a vulnerability

**Use GitHub private vulnerability reporting:**

[Report a vulnerability](https://github.com/solongate/agent-security/security/advisories/new)

That link opens a private advisory, visible only to you and the maintainers. It
is the preferred route because the discussion, the fix and the credit all live in
one place.

If you cannot use GitHub advisories, write to **cinar@solongate.com** with
`security` in the subject.

**Please do not** open a public issue, a pull request, or a discussion thread for
a bypass, and please do not post it on social media before a fix is out.

### What to include

Tell us what the control was supposed to do and what it did instead, the
policy that was in force (secrets removed), and the exact tool call or agent
prompt that triggered it. Also say which client and OS you were on, whether
the Go binary or the Node hook made the call (`solongate doctor` shows this,
and it matters since the two are separate implementations), and your version
(`solongate --version`, or the commit hash).

A reproducer helps but isn't required; a clear description is enough for us
to try it ourselves.

## Disclosure

We work to coordinated disclosure:

1. You report privately.
2. We confirm, fix, and prepare a release.
3. We publish the advisory and the release together, crediting you by the name
   or handle you choose, or anonymously if you prefer.
4. If a fix will take longer than 90 days from confirmation, we agree a date
   with you rather than letting it drift.

If an issue is already public, or being exploited, we skip straight to shipping
and documenting it.

## Supported versions

This project is pre 1.0 and distributed over git. Only the newest release gets
fixes.

| Version | Supported |
| --- | --- |
| The [latest release](https://github.com/solongate/agent-security/releases/latest) | yes |
| Anything older | no, update first |

`solongate update` pulls the newest source into the checkout it was installed
from and reinstalls. There are no backported patches, so a report against an old
version is checked against the current one before anything else.

## In scope

A way around any of these is a vulnerability:

- Guard bypass: a call a policy should refuse, running anyway.
- The Go guard and the Node hook disagreeing on the same call.
- Tampering with the guard's own state, through any tool.
- An agent reaching the CLI by any route.
- A secret matching a built-in pattern reaching the model or leaving the machine.
- A transfer command uploading a secret while `dlpBlock` is on.
- A denied call leaving no record, or a wrong one.
- The rate limit being bypassable, including in parallel.
- The installer or hooks writing outside their documented locations.
- A project's `policy.json` changing more than adding rules.

## Out of scope

Not because they don't matter, but because they aren't claims this project makes:

- A permissive policy doing what it's configured to do.
- DLP missing a secret with no distinctive shape.
- Anything the model already had in context before SolonGate was installed.
- An attacker who already has your shell.
- Vulnerabilities in the agents themselves.
- Resource exhaustion from an agent generating work.
- Dependency advisories with no reachable path in this code.

## Known limits

Stated here so nobody has to find them the expensive way:

- The guard only runs once the client calls it: a terminal already open
  before install isn't guarded.
- What clients can do differs: some can mask a secret inside a file the
  agent reads, others just block instead.
- `selfProtect: false` turns off tamper protection, by design, from the
  machine's own policy file.
- A policy that fails to compile doesn't disarm the guard; it falls back to
  a deterministic evaluator.
- The prompt shim carries the agent's own model credential, not SolonGate's;
  there's no SolonGate account anywhere in this project. A per-run token
  guards every request, the hop is TLS-encrypted, and it fails open (a
  request it can't parse goes through unmasked rather than breaking the
  agent).
- `solongate run` blocks named paths but isn't a box; `solongate sandbox` is
  the closed-box version (Linux, needs `bwrap`) and still keeps the network,
  since that's the DLP and egress layers' job.

## Credit

Reporters are credited in the advisory and the release notes, by whatever name
they choose. Tell us if you would rather stay anonymous.