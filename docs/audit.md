# The audit trail

Every decision is written down, on this machine, in a file you can read with
`cat`.

## Where it goes

```
~/.solongate/local-logs/solongate-audit.jsonl
```

Owner only (`0600`), one JSON object per line, appended.

```json
"security": {
  "localLogs": { "path": "/where/the/audit/trail/goes" }
}
```

**Recording is not optional.** `localLogs.path` chooses the folder and nothing
more, because there is nowhere else for an entry to go. There used to be a
service to send entries to instead, and that setting could switch disk logging
off; with the service gone, honouring it would mean losing the record entirely.

Two cases fall back to the default folder rather than failing:

- A **relative** path. Node would resolve it against the agent's working
  directory and create a log folder inside whatever repository happened to be
  open.
- A path **from another operating system**. A Windows path arriving on a Linux
  machine is not a location there. The entry matters more than the location.

## Who writes a line

| Writer | When |
| --- | --- |
| The guard | Before it answers the agent, for every denial. A denial is on disk even if the client crashes immediately afterwards. |
| The post tool hook | For calls that ran, on clients that have a post tool stage. |
| The guard, again | For an **allowed** call that carried a signal worth keeping, on clients with no post tool stage. Otherwise a detect mode hit there would be recorded nowhere. |

## The fields

```json
{
  "ts": "2026-10-06T12:34:56.789012345Z",
  "tool": "Bash",
  "arguments": { "command": "git push --force origin main" },
  "decision": "DENY",
  "reason": "[SolonGate OPA] Rewriting shared history is not an agent's decision",
  "permission": "EXECUTE",
  "source": "claude-code-guard",
  "agent_id": "claude-code",
  "agent_name": "Claude Code",
  "session_id": "1f2e3d4c",
  "evaluation_time_ms": 2
}
```

| Field | What it is |
| --- | --- |
| `ts` | When, in RFC 3339 with nanoseconds, UTC. |
| `tool` | The client's own name for the tool, verbatim. Clients name the same capability differently, so this is for reading rather than for matching. |
| `arguments` | The call's arguments, as they arrived. |
| `decision` | `ALLOW` or `DENY`. |
| `reason` | Why it was refused. **Absent on an allowed call** that had nothing to account for. |
| `permission` | The neutral class: `READ`, `WRITE`, `EXECUTE`, `NETWORK`. This is what rules match on. |
| `source` | Which writer produced the line, as `<agent>-guard`. |
| `agent_id`, `agent_name` | Which client. |
| `session_id` | The client's session, for grouping a run. |
| `evaluation_time_ms` | How long the decision took. |

`reason` being absent on an allowed call is a fix rather than an omission. Every
allowed call used to be written with the reason `allowed`, so an entry with
something real to say printed it and then undid it:

```
flagged   DLP: AWS access key
reason    allowed
```

The second line restates the decision on the row above and explains nothing. A
reason accounts for a refusal; where there is nothing to account for, the field
is gone and the view falls through to the arguments.

## What a turn cost

```
~/.solongate/local-logs/token-usage-<date>.jsonl
```

One line per turn, with the model and the turn id, read from whatever each client
already records. Nothing counts tokens for you, and nothing is sent anywhere.

## Reading it

```bash
solongate audit                                   # most recent first
solongate audit --filter DENY
solongate audit --filter ALLOW --tool Bash
solongate audit --signal dlp
solongate audit --signal ratelimit
solongate audit --search 'force'
solongate audit --agent-name 'Claude Code'
solongate audit --limit 200
solongate audit --json
```

And three commands that read the same file for different questions:

```bash
solongate watch                  # live tail, as calls are decided
solongate watch --filter DENY
solongate trace                  # what the guard saw in THIS directory, allows included
solongate trace --limit 50
solongate stats                  # totals, by tool, by decision, by signal
```

`solongate trace` is the one to reach for when a call was decided in a way you
did not expect. It shows the call as the guard saw it, after path resolution and
glob expansion, which is usually the whole explanation.

## Turning a line into a rule

```bash
solongate audit whitelist <logId>                  # an ALLOW rule for that call
solongate audit whitelist <logId> --scope tool     # ... for the whole tool
solongate audit block <logId>                      # a DENY rule
solongate audit block <logId> --scope tool
```

The default is `--scope exact`, not `--scope tool`. A whitelist that widened to
the whole tool by default would be a very quiet way to disarm a policy.

## The graded report

A second binary reads the AI transcripts already on this machine and grades what
they show against the OWASP Agentic Top 10:

```bash
solongate-audit                      # scan and show the report
solongate-audit --detailed           # per category analysis
solongate-audit --logs 100           # the last N tool calls
solongate-audit --watch              # live monitoring with a log feed
solongate-audit --json               # machine readable

solongate-audit --export json|csv|html|pdf|all

solongate-audit --search             # find AI tool logs on this system
solongate-audit --list-dirs
solongate-audit --add-dir <path>
solongate-audit --remove-dir <path>
```

The ten checks:

| | |
| --- | --- |
| ASI01 | Goal Hijacking |
| ASI02 | Tool Misuse |
| ASI03 | Identity Abuse |
| ASI04 | Supply Chain |
| ASI05 | Code Execution |
| ASI06 | Memory Poisoning |
| ASI07 | Inter Agent Comms |
| ASI08 | Cascading Failures |
| ASI09 | Human Agent Trust |
| ASI10 | Rogue Agents |

Its configuration is `~/.solongate-audit/config.json`, which is where the extra
log directories are remembered.

Two things that are easy to get wrong about this command:

- **It is not the hook.** The post tool hook runs on every single call and shares
  no code with this. This is a report a person runs: it reads a lot of disk and
  takes as long as it takes.
- **It is not gated to humans**, unlike every other command. It only reads
  transcripts and writes a report, so gating it would stop a CI job producing an
  audit without protecting anything.

## Known difference between the two implementations

The Node hook keeps a deny flag that tells the post tool hook not to file a
second, allow looking entry for a call the guard already blocked. The Go guard
does not carry it yet, so on a machine decided by the Go binary you may see both
rows for one denied call.

It was left out deliberately rather than guessed at: the flag carries a
fingerprint of the raw tool input, and Go sorts object keys where JavaScript
preserves insertion order, so a re-serialised fingerprint would silently never
match. It needs the raw bytes and a test pinning both sides.

## Worth knowing

- **The guard writes a denial before answering the agent**, not after. A denied
  call is recorded even if everything downstream falls over.
- **`arguments` is the call as it arrived**, so a secret that was in the
  arguments is in this file unless DLP masked it. The file is owner only for that
  reason. If you point `localLogs.path` somewhere shared, you are choosing that.
- **Nothing rotates these files.** They are append only JSONL; archive them
  yourself if you care about size.
