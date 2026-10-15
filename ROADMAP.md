# Roadmap

What this project intends to do, and not do, over the next year. Dates aren't
promised; order roughly reflects priority.

## Now

- Broaden [supported agents](README.md#supported-agents) past the four
  already wired up — OpenClaw, Hermes, and Chainabit are the next three hook
  integrations in progress.
- Keep closing the gap on [OSPS Baseline](https://www.bestpractices.dev/projects/15333/baseline)
  and the classic Best Practices badge: each unmet criterion either gets a
  real fix in the repo or stays honestly unmet, never a false self-certification.
- Harden the release pipeline further (attestation, SBOM, signed checksums)
  as new Sigstore/SLSA tooling matures.

## Next

- Expand sandbox coverage (Landlock, Seatbelt, the Windows deny) as new
  platforms or confinement primitives become available.
- Grow the fuzz target suite around policy parsing and the DLP matcher,
  where malformed input is most likely to reach untrusted-feeling code.
- Keep growing the maintainer group past @codeyevsky and @qarademir as the
  project's surface area grows.

## Not doing

- No SolonGate account, server, or telemetry. The guard decides on-device;
  that's a design commitment, not a missing feature (see [SECURITY.md](SECURITY.md)).
- No new dependency on the guard's decision path (`packages/guard`,
  `packages/policy`, `packages/shared`) without a justification in the pull
  request that adds it (see [CONTRIBUTING.md](CONTRIBUTING.md#dependencies)).

Found something missing from this list, or disagree with the priority? Open
an issue — that's also how "Your tool" in the supported-agents table above
becomes a real integration.