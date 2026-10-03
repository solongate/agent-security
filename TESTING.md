# Testing SolonGate

A policy gate has an awkward property: when it works, nothing happens. Every check
below is written so that a pass and a failure look different — "nothing was
blocked" is never evidence on its own.

Three things are being tested and they need different methods:

| | |
| --- | --- |
| **The CLI** | Only a person can run it. It refuses without a terminal, by design. |
| **Enforcement** | Only an agent can trigger it. The guard runs on tool calls and nowhere else. |
| **The clients** | Four of them, each with its own wire format. |

So most rows here are a **pair**: you set something in your terminal, then ask
your agent to do something, and the two answers together are the test. Neither
half proves anything alone.

---

## 0. What is already automated — don't hand-test this

`pnpm test` in `packages/proxy` runs 22 conformance files against the Node hook,
and CI runs the same suite a second time against the Go binary. Between them they
already prove:

| File | What it settles |
| --- | --- |
| `policy-mode` | denylist allows unless a DENY matched; whitelist is the reverse |
| `ratelimit` | sequential calls against a per-minute limit |
| `dlp-coverage` | every ported pattern actually fires |
| `dlp-parity` | one pattern list, and both hooks use it |
| `tamper-path` | the guard's own files are unreachable by every path spelling |
| `cli-invocation` | an agent cannot reach the CLI, and can still mention it |
| `proxy-parity` | the MCP proxy and the guard reach the same verdict |
| `reason-parity` | one policy explains itself the same way in both |
| `go-delegation` | a missing, stale, crashed or hanging binary falls back to Node |
| `routing`, `log-location` | what gets written, and where the viewers look |
| `scratch-dir` | the working directory is left alone |
| `post-tool-hook`, `token-usage` | the audit and token hooks |
| `glob-blowup` | a pathological pattern cannot hang a scan |
| `release-shape` | the platform packages track the version |

**Run it before anything else.** If this is red, hand-testing is measuring the
wrong thing:

```bash
cd packages/proxy && pnpm test
```

What it does **not** cover, and what the rest of this file is for: the CLI's own
commands, the TUI, the four clients end to end, and the install lifecycle.

---

## 1. The CLI surface

All of these need your terminal. Each row is one command and the thing worth
looking at — not just "does it exit 0".

### Policy

```bash
solongate policy list
solongate policy create "Test"            # note the id it prints
solongate policy show <id>
solongate policy deny <id> --command 'curl *'
solongate policy deny <id> --path '/etc/*'
solongate policy allow <id> --url 'https://api.github.com/*'
solongate policy deny <id> --filename '*.pem'
solongate policy deny <id> --command 'npm *' --permission EXECUTE
solongate policy show <id>                # every rule above, with its id
solongate policy rule <id> <ruleId> disable
solongate policy show <id>                # that rule marked off
solongate policy rule <id> <ruleId> enable
solongate policy revoke <id> <ruleId>     # gone from show
solongate policy mode <id> whitelist      # allow-by-default → deny-by-default
solongate policy mode <id> denylist
solongate policy activate <id>
solongate policy active                   # resolves to <id>
solongate policy activate --off           # enforcing nothing
solongate policy active                   # says so
solongate policy delete <id>
```

Worth checking specifically:

- **`--permission` with a typo** — `--permission EXECUT` must be refused, not
  stored. A permission the guard has no name for would read correctly in `show`
  and enforce nothing.
- **`--json` on every read command** — `list`, `show`, `active` — parses as JSON.
- **Two policies, one active.** Create two, activate each in turn, confirm
  `active` follows and that rules from the inactive one stop applying (section 2
  is how you confirm the second half).

### DLP

```bash
solongate dlp show                        # mode + which of the 70 patterns are on
solongate dlp mode detect                 # record, don't block
solongate dlp mode block
solongate dlp mode off
solongate dlp disable "AWS access key"
solongate dlp enable "AWS access key"
solongate dlp add-custom --name internal-id --re 'ACME-[0-9]{6}'
solongate dlp show                        # the custom pattern listed
solongate dlp remove-custom internal-id
```

- **A bad regex must be refused at add time**, not stored and skipped later.
- **`detect` and `block` must differ.** Section 2 has the pair that shows it.

In the TUI's DLP panel the seventy built-ins tile **four to a row** — `↑↓` steps a
whole row, `←→` steps one cell, `A` turns every built-in on and `U` turns every
one off. Check the pair: `A` then `s` then `dlp show` should list all seventy as
on, and `U` then `s` should list none. Neither touches your custom patterns.

### Rate limits

```bash
solongate ratelimit show
solongate ratelimit set --minute 5
solongate ratelimit set --minute 60 --hour 500 --day 2000 --mode block
solongate ratelimit set --mode detect
solongate ratelimit history               # the changes above, in order
solongate ratelimit set --mode off
```

The TUI's Rate limit panel is draft-only like Policies and DLP: `s` writes, `x`
throws the draft away. Nudge a limit with `←→`, press `x`, and the panel must
return to the saved number with the unsaved marker gone — then `esc` back out.

### The rest

```bash
solongate doctor      # every row green, guard version matching the hook
solongate audit       # browse; filters
solongate stats       # traffic and security counters
solongate trace       # what the guard saw in this directory
solongate watch       # live tail — leave it running for section 2
solongate             # the dataroom: Solo Live, Policies, Audit, Settings
```

In the dataroom specifically:

- **HEARTBEAT** (top right) moves while nothing is happening — flat trace,
  marching left. If it is static, the console is not live.
- **TOOL STREAM** gains a row within ~2s of an agent tool call.
- **LAYERS** reflects what you set above: rate limit, DLP, their modes.
- `/` searches the stream; `space` copies; `l` inspects layers; `?` lists keys.

---

## 2. Enforcement — the paired tests

Set the left column in your terminal; ask your agent for the right column. The
expected result is the whole point of each row.

| You set | Ask the agent to run | Expect |
| --- | --- | --- |
| `policy deny <id> --command 'curl *'` | `curl https://example.com` | **blocked**, reason names the rule |
| same | `echo curl` | **allowed** — mentioning is not running |
| `policy deny <id> --path '/etc/*'` | read `/etc/hosts` | **blocked** |
| `policy deny <id> --filename '*.pem'` | read any `.pem` | **blocked** |
| `policy mode <id> whitelist` | anything not explicitly allowed | **blocked** |
| `policy allow <id> --command 'ls *'` (whitelist) | `ls` | **allowed**, `cat` still blocked |
| `policy activate --off` | the previously blocked command | **allowed** — nothing is enforced |
| `ratelimit set --minute 3 --mode block` | four quick commands | 4th **blocked** |
| `ratelimit set --mode detect` | the same four | all **allowed**, all **recorded** |
| `dlp mode block` + a key in a file | read that file | **blocked** / redacted |
| `dlp mode detect` | the same read | **allowed**, hit recorded |
| `dlp add-custom --name x --re 'ACME-[0-9]{6}'` | echo `ACME-123456` | **caught** |
| nothing | `cat ~/.solongate/policy.json` | **blocked** — tamper protection |
| nothing | `solongate policy delete <id>` | **refused** — human-only |
| nothing | `script -c "solongate policy delete <id>"` | **refused** — a fake tty is still an agent |
| nothing | `git commit -m "fix the solongate docs"` | **allowed** — naming is not running |

After each block, check it reached the record:

```bash
solongate audit        # the DENY, with its reason
solongate trace        # what the guard saw here
```

**The two failure directions.** A rule that blocks nothing is obvious. A rule
that blocks too much is not — the agent just seems unhelpful. Every "allowed"
row above exists for that direction, and they matter more than the blocks.

---

## 3. The four clients

Each client speaks its own wire format, and the guard has one adapter per client.
A policy that works in Claude Code and not in Codex is an adapter bug, and it is
invisible from any single client.

**The cheap way, which covers the translation:** your agent can send each
client's payload to the installed guard directly and compare verdicts. Ask it to
drive `claude-code`, `codex`, `opencode` and `antigravity` against one policy and
show you the four exit codes. They must agree.

**The expensive way, which covers the registration:** actually run each client
and have it attempt a blocked call.

```bash
solongate doctor       # all four rows must say "guard registered"
```

| Client | Registered in | Check |
| --- | --- | --- |
| Claude Code | `~/.claude/settings.json` | a blocked command is refused mid-session |
| Codex | `~/.codex/hooks.json` | same — **and** run `/hooks` inside Codex once to trust them, or it skips every hook |
| OpenCode | `~/.config/opencode/` | same |
| Antigravity | `~/.gemini/config/hooks.json` | same |

Codex is the one that fails silently: an untrusted hook is not run and nothing
says so. `solongate doctor` reports it.

**Hooks load at session start.** A client that was already open when you
installed is not guarded. Restart it before concluding anything.

---

## 3.1 The run sheet — every constraint type, on every client

Section 2 proves each rule kind once and section 3 proves each client speaks.
This is the cross product, because that is where it actually breaks: a constraint
type can work on three clients and not the fourth, and nothing in a single-client
session would tell you. Ten checks per client, forty in all.

Each client gets the SAME ten. Work one client all the way down before moving on
— a client has to be restarted to pick the guard up, so switching clients mid
column costs a restart every time.

**Before each client's column:** restart that client (hooks load at session
start), then run `solongate doctor` and confirm its row says *guard registered*.

**Both directions on every row.** Each row below has a call that must be refused
AND a call that must go through. A rule that blocks everything passes every
"was it blocked?" check ever written, so the second half of each row is the half
that finds walls.

### The ten checks

| # | Constraint | You set | Ask the agent | Expect |
| --- | --- | --- | --- | --- |
| 1 | command · DENY | `policy deny <id> --command 'curl *'` | `curl https://example.com` | **blocked**, reason names the rule |
| 2 | command · ALLOW | `policy mode <id> whitelist` + `policy allow <id> --command 'ls *'` | `ls` then `cat /etc/hosts` | `ls` **allowed**, `cat` **blocked** |
| 3 | path · DENY | `policy deny <id> --path '/etc/*'` | read `/etc/hosts` | **blocked** |
| 4 | path · ALLOW | `policy mode <id> whitelist` + `policy allow <id> --path '<repo>/*'` | read a repo file, then `~/.ssh/config` | repo file **allowed**, `~/.ssh` **blocked** |
| 5 | filename · DENY | `policy deny <id> --filename '*.pem'` | read any `.pem`, then a `.txt` *containing* the text `.pem` | `.pem` **blocked**, `.txt` **allowed** (name, not content) |
| 6 | filename · ALLOW | `policy mode <id> whitelist` + `policy allow <id> --filename '*.ts'` | read a `.ts`, then a `.env` | `.ts` **allowed**, `.env` **blocked** |
| 7 | url · DENY | `policy deny <id> --url '*example.com*'` | fetch `https://example.com`, then `https://anthropic.com` | example.com **blocked**, the other **allowed** |
| 8 | url · ALLOW | `policy mode <id> whitelist` + `policy allow <id> --url '*docs.anthropic.com*'` | fetch the allowed host, then any other | allowed host **allowed**, other **blocked** |
| 9 | DLP | `dlp mode block` + a real-looking key in a file | read that file, then re-run under `dlp mode detect` | **blocked**/redacted, then **allowed** + hit recorded |
| 10 | rate limit | `ratelimit set --minute 3 --mode block` | four quick commands, then the same under `--mode detect` | 4th **blocked**, then all four **allowed** + recorded |

`<id>` is your policy id (`solongate policy list`). Whitelist mode belongs to the
ALLOW rows only — flip back with `policy mode <id> blacklist` before the next
DENY row, or every DENY row passes for the wrong reason.

After every blocked row: `solongate audit` must carry the DENY with its reason,
and `solongate trace` must show what the guard saw. A block the record missed is
a failure even though the call was refused.

### The branches

- [ ] **Claude Code** — registered in `~/.claude/settings.json`
  - [ ] restarted since install · `doctor` says guard registered
  - [ ] 1. command · DENY
  - [ ] 2. command · ALLOW
  - [ ] 3. path · DENY
  - [ ] 4. path · ALLOW
  - [ ] 5. filename · DENY
  - [ ] 6. filename · ALLOW
  - [ ] 7. url · DENY
  - [ ] 8. url · ALLOW
  - [ ] 9. DLP
  - [ ] 10. rate limit

- [ ] **Codex** — registered in `~/.codex/hooks.json` — run `/hooks` once inside Codex to trust them, or every hook is skipped **silently**
  - [ ] restarted since install · `doctor` says guard registered
  - [ ] 1. command · DENY
  - [ ] 2. command · ALLOW
  - [ ] 3. path · DENY
  - [ ] 4. path · ALLOW
  - [ ] 5. filename · DENY
  - [ ] 6. filename · ALLOW
  - [ ] 7. url · DENY
  - [ ] 8. url · ALLOW
  - [ ] 9. DLP
  - [ ] 10. rate limit

- [ ] **Antigravity** — registered in `~/.gemini/config/hooks.json` — denies with **exit 0** and a JSON body, so watch the agent's behaviour, not an exit code
  - [ ] restarted since install · `doctor` says guard registered
  - [ ] 1. command · DENY
  - [ ] 2. command · ALLOW
  - [ ] 3. path · DENY
  - [ ] 4. path · ALLOW
  - [ ] 5. filename · DENY
  - [ ] 6. filename · ALLOW
  - [ ] 7. url · DENY
  - [ ] 8. url · ALLOW
  - [ ] 9. DLP
  - [ ] 10. rate limit

- [ ] **OpenCode** — registered in `~/.config/opencode/` — the plugin refuses by throwing in-process; the refusal reads as a tool error
  - [ ] restarted since install · `doctor` says guard registered
  - [ ] 1. command · DENY
  - [ ] 2. command · ALLOW
  - [ ] 3. path · DENY
  - [ ] 4. path · ALLOW
  - [ ] 5. filename · DENY
  - [ ] 6. filename · ALLOW
  - [ ] 7. url · DENY
  - [ ] 8. url · ALLOW
  - [ ] 9. DLP
  - [ ] 10. rate limit

Forty boxes, and the four columns must agree box for box. A row that passes on
one client and fails on another is an **adapter** bug, not a policy bug — the
rule is the same file in both cases. `packages/proxy/test/matrix.mjs` sweeps the
same cross product against the guard directly; if a box fails here but the matrix
is green, the policy is reaching the guard and the break is in that client's
registration or payload, not in the rule.

---

## 4. Install and update

```bash
solongate doctor                  # before
solongate update                  # pulls, rebuilds, reinstalls
solongate doctor                  # after: version moved, rows still green
```

- Run `update` **twice**. The second says it is already current rather than
  reporting an update it did not make.
- Delete `~/.solongate/hooks/guard.mjs` and run `solongate repair`. The before/
  after report should show it missing, then restored.
- Open a new terminal and confirm `solongate` still resolves to the new build —
  `which solongate` should lead to `~/.solongate/bin/solongate`.

---

## 5. What a failure looks like

Worth knowing before you start, so a real failure is not mistaken for a pass:

- **Exit 2 is the only block.** Every client reads anything else — including the
  crash codes 1 and 7 — as *allowed*. A guard that dies on a malformed policy is
  a guard that is not there, and from the outside it looks like a quiet machine.
- **A silent fallback is not a failure, but it is worth knowing.** If the Go
  binary's version does not match the hook's, every call is decided in Node
  instead. Both answers are the same; only speed differs, and nothing announces
  it. `solongate doctor` compares the two.
- **An empty TOOL STREAM means no calls, not no enforcement.** Check the
  HEARTBEAT: if it is moving, the console is live and the machine is simply idle.
