<table align="center">
  <tr>
    <td align="center" bgcolor="#0d1117">
      <img src="assets/general/hero.png" alt="SolonGate Agent Security. Open-source security for AI agent actions." width="700">
    </td>
  </tr>
</table>

<table align="center">
  <tr>
    <td align="center">
      <a href="https://github.com/solongate/agent-security/actions/workflows/ci.yaml"><img src="https://github.com/solongate/agent-security/actions/workflows/ci.yaml/badge.svg" alt="ci"></a>
      <a href="https://github.com/solongate/agent-security/actions/workflows/codeql.yaml"><img src="https://github.com/solongate/agent-security/actions/workflows/codeql.yaml/badge.svg" alt="codeql"></a>
      <a href="https://github.com/solongate/agent-security/releases"><img src="https://img.shields.io/github/v/release/solongate/agent-security?color=3ba9ee&label=release" alt="release"></a>
      <a href="LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="license: Apache 2.0"></a>
      <a href="https://go.dev"><img src="https://img.shields.io/badge/go-1.26%2B-00ADD8.svg" alt="Go 1.26+"></a>
    </td>
  </tr>
  <tr>
    <td align="center">
      <sub><b>Security Badges</b></sub><br>
      <a href="https://www.bestpractices.dev/projects/15333"><img src="https://www.bestpractices.dev/badge_static/passing" alt="OpenSSF Best Practices Passing" height="20"></a>
      <a href="https://www.bestpractices.dev/projects/15333"><img src="https://www.bestpractices.dev/badge_static/silver" alt="OpenSSF Best Practices Silver" height="20"></a>
      <a href="https://www.bestpractices.dev/projects/15333"><img src="https://www.bestpractices.dev/badge_static/gold" alt="OpenSSF Best Practices Gold" height="20"></a><br>
      <a href="https://www.bestpractices.dev/projects/15333/baseline-1"><img src="https://www.bestpractices.dev/badge_static/baseline-1" alt="OpenSSF Baseline 1" height="20"></a>
      <a href="https://www.bestpractices.dev/projects/15333/baseline-2"><img src="https://www.bestpractices.dev/badge_static/baseline-2" alt="OpenSSF Baseline 2" height="20"></a>
      <a href="https://www.bestpractices.dev/projects/15333/baseline-3"><img src="https://www.bestpractices.dev/badge_static/baseline-3" alt="OpenSSF Baseline 3" height="20"></a><br>
      <a href="https://scorecard.dev/viewer/?uri=github.com/solongate/agent-security"><img src="https://api.securityscorecards.dev/projects/github.com/solongate/agent-security/badge" alt="OpenSSF Scorecard" height="20"></a>
      <a href="https://github.com/ossf/allstar"><img src="https://img.shields.io/badge/openssf-Allstar-3ba9ee.svg" alt="openssf Allstar" height="20"></a><br><br>
      <a href="https://github.com/solongate/agent-security/attestations"><img src="https://img.shields.io/badge/SLSA-Level%201-3ba9ee.svg" alt="SLSA Build Level 1" height="20"></a>
      <a href="https://github.com/solongate/agent-security/attestations"><img src="https://img.shields.io/badge/SLSA-Level%202-3ba9ee.svg" alt="SLSA Build Level 2" height="20"></a>
      <a href="https://github.com/solongate/agent-security/attestations"><img src="https://img.shields.io/badge/SLSA-Level%203-3ba9ee.svg" alt="SLSA Build Level 3" height="20"></a><br><br>
      <a href="https://api.reuse.software/info/github.com/solongate/agent-security"><img src="https://api.reuse.software/badge/github.com/solongate/agent-security" alt="REUSE status" height="20"></a><br><br>
      <a href="https://sonarcloud.io/summary/new_code?id=solongate_agent-security"><img src="https://sonarcloud.io/api/project_badges/measure?project=solongate_agent-security&metric=security_rating" alt="Security Rating" height="20"></a>
      <a href="https://sonarcloud.io/summary/new_code?id=solongate_agent-security"><img src="https://sonarcloud.io/api/project_badges/measure?project=solongate_agent-security&metric=reliability_rating" alt="Reliability Rating" height="20"></a>
      <a href="https://sonarcloud.io/summary/new_code?id=solongate_agent-security"><img src="https://sonarcloud.io/api/project_badges/measure?project=solongate_agent-security&metric=sqale_rating" alt="Maintainability Rating" height="20"></a><br>
      <a href="https://sonarcloud.io/summary/new_code?id=solongate_agent-security"><img src="https://sonarcloud.io/api/project_badges/measure?project=solongate_agent-security&metric=alert_status" alt="Quality Gate" height="20"></a>
      <a href="https://sonarcloud.io/summary/new_code?id=solongate_agent-security"><img src="https://sonarcloud.io/api/project_badges/measure?project=solongate_agent-security&metric=coverage" alt="Coverage" height="20"></a>
    </td>
  </tr>
</table>

---

**SolonGate Agent Security** is SolonGate's open source, local first security
gateway for AI coding agents. It checks tool calls against your policies before
they run, with secret detection, rate limits and a local audit trail.

This repository is the Agent Security gateway. The rest of the portfolio is at
[solongate.com](https://solongate.com).

Everything stays on the machine. The policy is a file, the audit trail is a
file, and the guard makes no network calls. No account, no telemetry.

<div align="center">
  <img src="assets/general/flow.gif" alt="A tool call from an AI agent passes through SolonGate, which runs a policy check, DLP scan, rate limit and logging, then allows or blocks it before the tool runs" width="900">
</div>

## Install and use

Requires `git` to clone this repo. Go 1.26+ is needed too; `install.sh`
downloads the official go.dev build for you if it is not already there,
regardless of OS.

```bash
git clone https://github.com/solongate/agent-security.git
cd agent-security
./scripts/install.sh
solongate
```

Then open a new terminal. Hooks load when a session starts, so an already open
one is not guarded yet.

## What it looks like when it fires

A real Claude Code session: the agent reaches for a `.env`, the guard refuses it,
and the agent says so rather than quietly working around it.

<div align="center">
  <img src="assets/general/claudecode.gif" alt="A Claude Code session in which SolonGate blocks access to a .env file and Claude reports the refusal instead of working around it" width="900">
</div>

## What it does

| Layer | What it does |
| --- | --- |
| **Policy rules** | Allow or deny by path, command, filename or URL, scoped to READ, WRITE, EXECUTE or NETWORK. |
| **DLP** | 70+ built in secret patterns plus your own, in four modes: `off`, `detect`, `redact`, `block`. |
| **Egress** | In block mode, refuses an upload whose file holds a secret, which pattern matching on the call alone cannot see. |
| **Rate limits** | A cap per minute, hour or day. |
| **The prompt** | A shim masks the outbound request body on Claude Code, which no tool call hook can reach. |
| **Tamper protection** | The guard's own state is unreachable from a tool call, and a policy in a repository cannot switch it off. |
| **Protected paths** | A path the OS itself refuses the agent, rather than a rule matched against the words in a tool call. |
| **Sandbox** | The agent's whole root is a new, minimal filesystem holding only the project; everything else is not refused, it is not there. |

## The CLI

```
solongate                        the TUI: policies, audit, settings
solongate policy                 list, create and edit the policy
solongate dlp                    secret detection
solongate ratelimit              the rate limit
solongate policy protect <path>  lock a path, and say what the lock is worth
solongate policy protect list    what is actually holding each path, read from disk
solongate sandbox list           the boxes this machine has, and their ids
solongate sandbox 001 claude     start the agent inside box 001
solongate sandbox --explain 001  everything that is in that box
solongate run claude             start an agent with protected paths out of reach
solongate audit                  browse the audit trail
solongate watch                  live tail tool calls
solongate trace                  what the guard saw in this directory
solongate doctor                 health check
solongate repair                 restore the guard, hooks and settings
solongate update                 pull the newest version and reinstall
solongate range                  how far an update is allowed to move
solongate range short            every commit on the branch
solongate range long             tagged releases only, reliable (the default)
```

## Supported agents

<table cellspacing="0" cellpadding="0" border="0" align="center">
  <tr>
    <td><a href="https://claude.com/claude-code"><img src="assets/cells/claude.png" width="200" alt="Claude Code"></a></td>
    <td><a href="https://openai.com/codex"><img src="assets/cells/codex.png" width="200" alt="Codex CLI"></a></td>
    <td><a href="https://antigravity.google"><img src="assets/cells/antigravity.png" width="200" alt="Antigravity CLI"></a></td>
    <td><a href="https://opencode.ai"><img src="assets/cells/opencode.png" width="200" alt="OpenCode"></a></td>
  </tr>
  <tr>
    <td><a href="https://openclaw.ai"><img src="assets/cells/openclaw.png" width="200" alt="OpenClaw (soon)"></a></td>
    <td><a href="https://hermes.nousresearch.com"><img src="assets/cells/hermes.png" width="200" alt="Hermes (soon)"></a></td>
    <td><a href="https://chainabit.com"><img src="assets/cells/chainabit.png" width="200" alt="Chainabit (soon)"></a></td>
    <td><a href="https://github.com/solongate/agent-security/issues"><img src="assets/cells/yourtool.png" width="200" alt="Your tool"></a></td>
  </tr>
</table>

## Contributors ✨

Thanks to these wonderful people. Without their help, this project would not
have made it this far.

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/codeyevsky"><img src="https://avatars.githubusercontent.com/u/175152758?v=4&size=100" width="100px" height="100px" alt="codeyevsky"/><br /><sub><b>codeyevsky</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=codeyevsky" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/qarademir"><img src="https://avatars.githubusercontent.com/u/261046371?v=4&size=100" width="100px" height="100px" alt="Emirhan Demir"/><br /><sub><b>Emirhan Demir</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=qarademir" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tnalbant"><img src="https://avatars.githubusercontent.com/u/182372382?v=4&size=100" width="100px" height="100px" alt="tnalbant"/><br /><sub><b>tnalbant</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=tnalbant" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/sahilkhedkar"><img src="https://avatars.githubusercontent.com/u/178520446?v=4&size=100" width="100px" height="100px" alt="Sahil"/><br /><sub><b>Sahil</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=sahilkhedkar" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/LetMeSleep8h"><img src="https://avatars.githubusercontent.com/u/183817470?v=4&size=100" width="100px" height="100px" alt="Sleep8h"/><br /><sub><b>Sleep8h</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=LetMeSleep8h" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Nelmad"><img src="https://avatars.githubusercontent.com/u/17722412?v=4&size=100" width="100px" height="100px" alt="Nikita Dereglazov"/><br /><sub><b>Nikita Dereglazov</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=Nelmad" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/Oscar-Williams"><img src="https://avatars.githubusercontent.com/u/319719771?v=4&size=100" width="100px" height="100px" alt="Oscar"/><br /><sub><b>Oscar</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=Oscar-Williams" title="Code">💻</a></td>
    </tr>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/tianxingjian2406"><img src="https://avatars.githubusercontent.com/u/247943876?v=4&size=100" width="100px" height="100px" alt="Liu XingJian"/><br /><sub><b>Liu XingJian</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=tianxingjian2406" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/webgo-oss"><img src="https://avatars.githubusercontent.com/u/210721517?v=4&size=100" width="100px" height="100px" alt="Hamza"/><br /><sub><b>Hamza</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=webgo-oss" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/bfs2021"><img src="https://avatars.githubusercontent.com/u/101915083?v=4&size=100" width="100px" height="100px" alt="zgy"/><br /><sub><b>zgy</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=bfs2021" title="Code">💻</a></td>
      <td align="center" valign="top" width="14.28%"><a href="https://github.com/NopeCharon"><img src="https://avatars.githubusercontent.com/u/115794254?v=4&size=100" width="100px" height="100px" alt="Asish"/><br /><sub><b>Asish</b></sub></a><br /><a href="https://github.com/solongate/agent-security/commits?author=NopeCharon" title="Code">💻</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome.