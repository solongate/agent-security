# Guard conformance suite

These tests describe what the guard **must do**, not how it does it. They run
the hook as a real subprocess, feed it the payload a client would, and check the
exit code, the files it touched and what it sent to a stub cloud.

That makes them the contract. Any reimplementation — a daemon, a Go binary, a
rewrite of the hot path — is correct exactly when it passes this suite
unchanged. Nothing here imports the guard's internals, so nothing here has to be
rewritten alongside it.

Every case in here exists because the behaviour it pins was once wrong. The
comments say which, so a future change knows what it is protecting.

## Running

    node test/run-all.mjs               # against the installed hook
    SG_HOOK=/path/to/guard node test/run-all.mjs   # against a candidate build

`SG_HOOK` is how a second implementation gets tested: point it at the new binary
and the same expectations apply.

## What each file pins

| file | the behaviour, and the bug behind it |
| --- | --- |
| `routing.mjs` | local vs cloud is exclusive, and driven by the SETTING. `security: null` is an answer ("no local config"), not "unknown" — reading it as unknown sent entries to a stale device-wide marker and kept logs on disk after local storage was switched off. |
| `ratelimit.mjs` | the limit holds under a burst. The counter was a read-modify-write on one JSON file, so parallel hooks lost each other's increments: 14 calls passed a limit of 5. |
| `deny-latency.mjs` | a denial does not wait on the network. The audit POST was awaited before the verdict, so a blocked call took 1643ms against 78ms with the API unreachable — and the record must still arrive. |
| `scratch-dir.mjs` | per-call flags stay out of the user's directories, and the folders older versions left behind get swept — but only ours, and only if that empties the folder. |
| `policy-mode.mjs` | the policy MODE decides the default. The compiled Rego always carries `default decision := DENY`, so mode has to be re-applied on top of the engine's answer; read a denylist as that default and every ordinary call is blocked, read a whitelist as it and the strict policy a user switched on enforces nothing. Both directions, plus DENY outranking a matching ALLOW. |

## Writing a new one

Assert on what a client can observe: exit code, stderr, files, what reached the
stub cloud. Do not reach into the implementation. A test that knows how the
guard works internally stops being a contract the moment anyone rewrites it.

One trap, hit twice while writing these: `spawnSync` blocks the process it is
called from. If the stub cloud lives in that same process it can never answer,
the guard's fetch hangs, and what gets measured is the guard's 8s backstop.
Spawn asynchronously whenever a stub server is involved.
