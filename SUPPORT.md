# Getting help

## Start here

Run this first, and paste its output into whatever you open:

```bash
solongate doctor
```

It checks the policy file, the guard binary, the hook registrations and the local
log folder, and it names the version of each. Most reports turn out to be one of
the three things it checks.

`solongate doctor --json` is the same answer in machine readable form.

## Then check the docs

| Your question | Where it is answered |
| --- | --- |
| It installed, and nothing is being blocked | [docs/troubleshooting.md](docs/troubleshooting.md) |
| Everything is being blocked | [docs/troubleshooting.md](docs/troubleshooting.md) |
| How do I write a rule for X | [docs/policy.md](docs/policy.md) |
| Why did my pattern not match | [docs/policy.md](docs/policy.md), the matching section |
| Which secrets are detected | [docs/dlp.md](docs/dlp.md) |
| Where is the log, and what is in it | [docs/audit.md](docs/audit.md) |
| What does this command do | [docs/cli.md](docs/cli.md) |
| Does my agent support this | [docs/clients.md](docs/clients.md) |
| How do I run it in front of an MCP server | [docs/mcp-proxy.md](docs/mcp-proxy.md) |
| Why is it built this way | [ENGINEERING.md](ENGINEERING.md) |

The one answer that resolves the largest share of reports: **hooks load when a
session starts.** A terminal that was open before you installed SolonGate is not
guarded. Open a new one.

## Where to ask

- **A question, or something that might be a misconfiguration**: open a
  [discussion](https://github.com/codeyevsky/solongate-oss/discussions). No
  template, no ceremony.
- **A bug**: open an
  [issue](https://github.com/codeyevsky/solongate-oss/issues/new/choose). The
  template asks for the output of `solongate doctor`, which client you are using,
  and the policy in force.
- **A vulnerability**: do not use either of the above. Follow
  [SECURITY.md](SECURITY.md), which uses GitHub private advisories.
- **A feature**: an issue with the feature template. New DLP patterns are
  welcome and easy to add.

## What makes a report quick to answer

- The output of `solongate doctor`.
- Which client, and which operating system.
- The policy that was in force, with secrets removed.
- The exact tool call or prompt, and what you expected instead.
- Whether a new terminal was opened after installing.

If a call was decided wrongly, `solongate trace` shows what the guard saw in that
directory, allows included, and the line it prints is usually the whole answer.

## What this project does not offer

There is no commercial support contract, no service level agreement and no
private support channel. Everything happens in the open repository, from the
maintainers listed in [GOVERNANCE.md](GOVERNANCE.md), on their own time.

The one exception is security reports, which are private by design.
