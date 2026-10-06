# Governance

SolonGate is a small project with a simple structure. This document says who
decides what, so nobody has to guess.

## Maintainers

| Who | GitHub | Scope |
| --- | --- | --- |
| Çınar Yıldırım | [@codeyevsky](https://github.com/codeyevsky) | Everything: the guard, the policy engine, the CLI, releases |

Maintainers have commit access, cut releases, and are responsible for security
reports and Code of Conduct enforcement.

Adding a maintainer: sustained, good quality contribution, plus agreement from
the existing maintainers. There is no fixed contribution count. What is looked
for is judgement about the decision path, because that is where a mistake is
expensive.

Stepping down is normal and needs no justification. A maintainer who has been
unreachable for six months is moved to the list below.

### Emeritus

Nobody yet.

## How decisions are made

Most changes need nothing more than a pull request and a review.

- **Ordinary changes** (a fix, a new DLP pattern, documentation, a test): one
  maintainer approves, and it lands.
- **Changes to what a policy means**: a maintainer approves, and the change is
  called out in the release notes, because somebody's live policy will behave
  differently afterwards.
- **Changes to the decision path** (the guard, the policy engine, tamper
  protection, the human only gate): these land in both implementations together,
  with conformance cases, or they do not land. See
  [CONTRIBUTING.md](CONTRIBUTING.md).
- **Anything that would send data off the machine**: this project has no such
  code path and is not going to grow one by accident. A change that adds a
  network call on any path other than an explicit, user initiated update needs an
  issue, a stated reason, and agreement from the maintainers before any code is
  written.

Disagreements are settled by discussion in the issue or pull request. If a
discussion stalls, the maintainers decide, and the reasoning goes in the thread
rather than in a private channel.

## The things that are not up for a vote

A few properties are what this project is, rather than choices to be revisited
per release:

1. **The decision happens on the machine.** No network call on the path between
   an agent asking to run a tool and the answer.
2. **Two implementations, indistinguishable.** Which one decides a call depends
   only on whether a machine has the Go binary, so a behaviour in one and not
   the other is a bug by definition.
3. **The conformance suite is the contract.** A change to the guard is correct
   exactly when the suite passes unchanged against both implementations. Changing
   an existing case means explaining why the behaviour it pinned was wrong.
4. **Failing closed.** A policy that will not compile, a pattern that cannot be
   applied, a masking step that cannot run: each of those blocks rather than
   allows. Slow but guarded, never fast but unguarded.
5. **No telemetry.** Nothing counts, measures or reports anything to anyone.

A proposal that breaks one of these is not refused out of hand, but it starts
from a much higher bar than an ordinary change, and it needs an issue before
code.

## Releases

Any maintainer can cut a release. The process, the checks and what makes a
version visible are in [RELEASING.md](RELEASING.md).

Versions are pre 1.0 and move in patch steps. A release is cut when there is
something worth installing, not on a schedule.

## Issue and pull request handling

- Issues are triaged when a maintainer gets to them. There is no on call
  rotation.
- An issue with no reproducer and no response from the reporter for 30 days may
  be closed, and reopening it with more detail is always welcome.
- A pull request that sits unreviewed for two weeks deserves a ping in the
  thread.
- Security reports are handled privately and first. See
  [SECURITY.md](SECURITY.md).

## Code of Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to everyone, maintainers
included. Reports go to hello@solongate.com and are handled by the maintainers.
A report concerning a maintainer is handled without that maintainer taking part.

## Licence and ownership

The project is MIT licensed. Contributors keep copyright in their own
contributions, licensed under the same terms. There is no CLA and no copyright
assignment, which also means no single party can relicense the project away from
MIT.
