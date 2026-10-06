# Rate limits

A ceiling on how many tool calls an agent makes, per minute, per hour and per
day. A runaway loop stops at the cap instead of making four thousand calls.

## Setting one

```bash
solongate ratelimit show
solongate ratelimit set --minute 60 --hour 900 --day 5000 --mode block
solongate ratelimit history
```

Unset fields keep their current value, so `--minute 30` on its own changes only
the per minute cap.

In the policy file:

```json
{
  "policy": { "mode": "denylist", "rules": [] },
  "security": {
    "rateLimit": { "perMinute": 60, "perHour": 900, "perDay": 5000 }
  }
}
```

A window set to `0` or left out is not enforced. All three may be set at once,
and the first one crossed is the one that refuses the call.

## The three modes

| Mode | On disk | What happens |
| --- | --- | --- |
| `off` | neither key | Nothing is counted. |
| `detect` | `rateLimitObserve` | Calls are counted and recorded. Nothing is refused. |
| `block` | `rateLimit` | A call past the cap is refused. |

Exactly one of the two keys is ever on disk, so an observing limit cannot
accidentally enforce.

**Start on `detect`.** You almost certainly do not know what your normal call
volume looks like, and a cap set below it reads as the product being broken. Run
for a day, then read `solongate stats` and set the cap above what you saw.

In detect mode on a client with no post tool stage, the guard records the count
itself, because nothing else runs there and an observing layer that records
nothing observes nothing.

## What is counted

**Every attempt, per agent.** A refused call occupies a slot too, which is the
honest reading: thirty attempts in a minute is thirty calls a minute whatever
came back.

The counter is keyed per agent, so Claude Code and Codex running at the same
time do not consume each other's budget.

Windows are rolling, not calendar aligned. The per minute cap is the number of
calls in the last 60000 milliseconds, not the number so far this minute.

## Why it holds under parallel calls

Each call appends one fixed width record to an append only log, then counts the
window and refuses if the count is past the limit. The reservation happens
**before** the decision: every process appends, then counts, and the ones past
the limit are the ones refused.

The alternative, a counter that is read, incremented and written back, loses
increments between parallel guard processes, and the limit stops holding exactly
when it matters most. That was measured on the earlier implementation: limit 5,
30 calls fired at once, and across five rounds 7, 8, 5, 14 and 11 calls got
through.

A conformance case pins the ceiling under 30 parallel calls for this reason.

The log is compacted once it passes 4 MB, written beside and renamed so a reader
never sees a half written file. Records older than a day are dropped during
compaction.

## The refusal

The reason the agent gets names the window and the limit:

```
Security layer (rate limit): exceeded 60 calls/minute for this agent.
Blocked by SolonGate (rate limit).
```

It is recorded with `signal: ratelimit`, so:

```bash
solongate audit --signal ratelimit
```

## If the guard cannot account for a call

If the counter file cannot be opened or written, the call is **allowed**.

That is a deliberate asymmetry with the rest of the product, which fails closed.
A rate limit is a resource ceiling rather than a security boundary: refusing
every call because a log file is unwritable would turn a disk problem into a
total outage, and nothing is protected by doing so. Policy rules, DLP and tamper
protection do not behave this way.

## Worth knowing

- **The window is per agent, not per project.** Two repositories open in the same
  client share a budget.
- **`ratelimit history`** shows recent changes to the limits, which answers "who
  turned this down to 10" without reading the file.
- **A cap in the low tens will interrupt ordinary work.** An agent reading a
  handful of files and running a test suite easily makes dozens of calls a
  minute.
