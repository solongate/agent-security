# Changelog

Every entry says what changed for somebody running this, not which file was
edited. Entries marked **behaviour** change what gets blocked, so read those
before updating.

This project is pre 1.0 and distributed over git. `solongate update` pulls the
newest source into the checkout it was installed from and reinstalls. Releases
are listed at
[github.com/codeyevsky/solongate-oss/releases](https://github.com/codeyevsky/solongate-oss/releases).

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## Unreleased

The version in `packages/proxy/package.json` is `0.0.6`. The release workflow
refuses a tag that does not match it, so the next tag is `v0.0.6`.

### Fixed

- **behaviour.** DLP `block` mode no longer degrades to masking on the clients
  that can rewrite their own tool output, which is most of them. Reading a file
  that holds a secret came back masked and allowed, because the pre tool file
  scan was gated on the client lacking a post tool stage. Masking can be
  deferred to that stage; refusing cannot, because by then the file has already
  been read. The gate now applies to `redact` only, and `block` runs the scan on
  every client. This costs something deliberately: in `block` mode a read of any
  file holding a secret is refused outright, and `redact` is the mode for letting
  the call through with the value hidden. Hook version 106 to 107.
- The DLP summary in the layer views drew one bar per pattern, each scaled
  against the busiest, which makes the busiest full width by construction. With
  one pattern configured that was a full width red bar for seven hits: it read as
  an emergency and measured nothing. The ten column label also cut
  `AWS access key` to `AWS acces…`, so the name beside the bar named nothing
  while sitting next to what was really the total. Both views now print the
  number of hits and the window on one line. Which pattern fired belongs on the
  entry that fired it.

## 0.0.5

### Fixed

- Every allowed call was recorded with the reason `allowed`, so an entry with
  something real to say printed it and then undid it: a `flagged` line naming a
  DLP hit, followed by `reason allowed`. The field is now absent where there is
  nothing to account for, and the view falls through to the arguments.
- The layers panel drew a full width red bar for a single DLP pattern, for the
  reason described under Unreleased. With two or more patterns the comparison is
  real, so the bars stay.

## 0.0.4

### Fixed

- **behaviour.** The prompt shim was the third place that masks text on this
  machine, and it had not been told that `detect` observes rather than masks. A
  detect mode read still came back as `[REDACTED: …]`, because the shim's config
  loader looked for `dlpRedact` or `dlpBlock`, found neither, and fell back to
  masking with every built in pattern. That fallback is right for a machine with
  no policy at all, and wrong for `dlpObserve`, which is DLP configured in the
  one mode that exists to change nothing: the weakest mode was the most
  aggressive. Detect now returns no plan, which is a different answer from
  nothing configured.

## 0.0.3

### Fixed

- **behaviour.** Four more readers and writers collapsed the three DLP modes back
  into one. Two of them filled the redacting key for every mode that was not
  off, in two languages with the same line, so a policy set to `detect` was
  handed downstream as a redact config and acted on. One reported `redact` as
  `detect` in `doctor`. Both halves being wrong in the same way is precisely what
  a shared conformance suite cannot catch, because the two agreed.

## 0.0.2

### Fixed

- **behaviour.** Two behaviours wore three names, and neither was the one you
  picked. `detect` set `dlpRedact`, so it masked the model's view of every secret
  it found, which is redacting. `block` set both, so the only difference between
  them was whether an argument hit also refused the call, and a read whose secret
  was in the file behaved identically in both: allowed, masked, recorded as
  clean. Each mode now does the thing its name says. `detect` observes through
  the new `dlpObserve` key, `redact` masks, `block` refuses, and exactly one of
  the three shapes is ever on disk.

## 0.0.1

First tagged release. Before it, nothing on GitHub said which version a checkout
was, there were no tags, and the only way to learn what a version number meant
was to read the commit that typed it.

The numbering restarts here on purpose: this is not the package the code was
carved out of, and continuing that package's sequence would have implied an
upgrade path that does not exist.

### What it is

- The guard: a pre tool hook that decides every tool call against a policy file,
  on the machine, with no network call on the decision path.
- Two implementations, in Go and in bundled JavaScript, judged by one conformance
  suite that runs against both.
- The policy engine: JSON rules compiled to Rego and evaluated in process, with
  a deterministic fallback evaluator for a policy that will not compile, so a bad
  policy never disarms the guard.
- Policy layers: rules by path, command, filename and URL, in denylist or
  whitelist mode.
- Security layers: rate limiting per minute, hour and day, DLP over 70 built in
  patterns plus custom expressions, an egress check that reads the files a
  transfer command would upload, a prompt shim that masks the outbound request
  body, and tamper protection over the guard's own state.
- The CLI and the dataroom TUI: policy, ratelimit, dlp, audit, stats, watch,
  trace, doctor, repair and update, all refused to anything without an
  interactive terminal.
- Four client adapters: Claude Code, Codex, OpenCode and Antigravity, plus a
  conservative generic adapter for anything else.
- The MCP proxy: the same evaluator in front of an MCP server's tool calls.
- The audit trail: one JSON object per line, owner only, with token usage
  recorded beside it.

### Removed before this release

- The cloud half, in full: the service, the API client's remote paths, the policy
  cache that could let an empty reply outrank a machine's own file, and every
  code path that sent an audit entry or a token count anywhere. Removed rather
  than disabled.
- Prompt injection scoring, which was dead code in both implementations after the
  layer that used it was removed.
