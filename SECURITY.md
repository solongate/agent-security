# Security policy

SolonGate decides whether an AI agent's tool call runs. A hole in it is not a
bug in a feature, it is a control that somebody is relying on and that is not
there. Reports are welcome, taken seriously, and never held against the reporter.

## Reporting a vulnerability

**Use GitHub private vulnerability reporting:**

[Report a vulnerability](https://github.com/codeyevsky/solongate-oss/security/advisories/new)

That link opens a private advisory, visible only to you and the maintainers. It
is the preferred route because the discussion, the fix and the credit all live in
one place.

If you cannot use GitHub advisories, write to **hello@solongate.com** with
`security` in the subject.

**Please do not** open a public issue, a pull request, or a discussion thread for
a bypass, and please do not post it on social media before a fix is out. A public
report on this project tells every prompt injected agent in the world how to
switch off the thing watching it.

### What to include

As much of this as you have:

- What the control was supposed to do, and what it did instead.
- The policy that was in force, with secrets removed.
- The exact tool call, or the agent prompt that produced it.
- Which client (Claude Code, Codex, OpenCode, Antigravity) and which operating
  system.
- Whether the Go binary or the Node hook decided the call. `solongate doctor`
  prints this, and it matters: the two are separate implementations and a hole
  in one is not automatically a hole in the other.
- The version. `solongate --version`, or the commit hash if you built from
  source.

A reproducer is ideal and not required. A clear description of the mechanism is
enough for us to try it ourselves.

## Response

| Stage | Target |
| --- | --- |
| Acknowledgement | within 3 working days |
| First assessment, with a severity and a plan | within 10 working days |
| Fix for a confirmed high severity issue | as fast as we can, and we will tell you the date we are working to |

This is a small project. If you have not heard anything in a week, send a
reminder rather than assuming the report was dismissed.

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
| The [latest release](https://github.com/codeyevsky/solongate-oss/releases/latest) | yes |
| Anything older | no, update first |

`solongate update` pulls the newest source into the checkout it was installed
from and reinstalls. There are no backported patches, so a report against an old
version is checked against the current one before anything else.

## In scope

These are the things this project claims to do, so a way around any of them is a
vulnerability:

- **Guard bypass.** A tool call that a policy should refuse and that runs anyway.
- **Divergence between the two implementations.** The same policy and the same
  call reaching different verdicts in Go and in the Node hook.
- **Tamper protection bypass.** Reading, writing or deleting the guard's own
  state from a tool call, by any path spelling or any tool.
- **The human only gate.** An agent reaching the CLI, by any route, including an
  environment variable or a wrapper that makes a tool call look interactive.
- **DLP evasion that leaks a secret.** A secret that matches a built in pattern
  reaching the model, or leaving the machine, while the configured mode says it
  should not. Splitting a secret across string literals counts, and is tested.
- **Egress bypass.** A transfer command that uploads a local file holding a
  secret while `dlpBlock` is configured.
- **Audit suppression or forgery.** A denied call that leaves no record, or a
  record that misstates what happened.
- **Rate limit bypass**, including through parallel calls.
- **Privilege or path escalation through the installer**, the hooks, or the shell
  shim: anything that writes outside the documented locations, or that a
  non privileged local process can use to get code into a guarded session.
- **A policy file inside a repository changing anything it is not allowed to
  change.** A project `policy.json` may add rules and nothing else, because the
  agent can write to it.

## Out of scope

Not because they do not matter, but because they are not claims this project
makes:

- **A permissive policy.** If a rule allows something, the guard allowing it is
  the control working. We will happily discuss whether a documented default is
  the wrong default, as a normal issue.
- **DLP false negatives for secrets with no distinctive shape.** The scanner is
  pattern based. A password that looks like an English word, or a token format
  nobody has published a prefix for, will not be detected. Missing a format that
  does have a distinctive prefix is a feature request, and a welcome one.
- **What the model already has.** SolonGate sits in front of tool calls, and for
  Claude Code in front of the outbound prompt body. Anything the client swept
  into context before SolonGate was installed, and anything the model infers, is
  outside the path.
- **An attacker who already has your shell.** Everything here is a control over
  an agent's tool calls, running with your own privileges. Someone with
  unmediated local execution as your user can edit the policy, and that is the
  threat model's boundary, not a flaw in it.
- **Vulnerabilities in the agents themselves**, or in their hook mechanisms.
  Report those to their vendors, and tell us if it changes what we should assume.
- **Filling a disk, or exhausting memory**, by making the agent generate work.
- **Dependency advisories with no reachable path** in this code. Send them in as
  normal issues and we will update anyway.

## Known limits

Stated here so nobody has to find them the expensive way:

- **The guard runs when the client calls it.** Hooks load at session start, so a
  terminal that was already open before installation is not guarded. Open a new
  one.
- **Capabilities differ per client.** Masking a secret that is inside a file the
  agent reads needs a post tool stage that can rewrite the result. Clients that
  cannot do that get a block instead, which is the safe direction but a different
  experience.
- **`selfProtect: false` turns tamper protection off**, by design, and only from
  the machine's own policy file. Do not set it unless you know why you are
  setting it.
- **A policy that will not compile does not disarm the guard.** Evaluation falls
  back to a deterministic evaluator rather than allowing. If you find a policy
  shape where it does allow, that is in scope above.

## Credit

Reporters are credited in the advisory and the release notes, by whatever name
they choose. Tell us if you would rather stay anonymous.
