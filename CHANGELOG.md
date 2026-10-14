# Changelog

Human-written summary of what changed in each release and what it means for
someone upgrading. release.yml pulls the matching `## vX.Y.Z` section into the
GitHub release notes; a tag with no matching section here fails the release
rather than falling back to a commit dump.

## v0.0.7

### Added
- OpenSSF Scorecard workflow and badge.
- Release attestation bundles are now attached to each archive individually,
  so `gh attestation verify --bundle` works offline, not just against the
  Sigstore transparency log.
- Fuzz targets for policy-file glob and shell-command parsing.

### Changed
- The guard and hook are now implemented in Go; the previous TypeScript
  CLI/TUI is gone and packages were split and renamed to match.
- `solongate run` gates on a real guard decision instead of a human prompt.
- Sandbox CI checks (the box, Seatbelt) cover the userns and
  unlink-through-directory cases they were missing before.

### Fixed
- Per-archive attestation bundles were clobbering each other during release
  builds; each archive now gets its own.
- Vulnerable Go module versions bumped; release.yml permissions scoped to
  job level instead of workflow level.

### Removed
- `solongate-audit` (was never built) and the old TypeScript CLI/TUI.

## v0.0.6

### Added
- Docs clarifying that SolonGate is not an MCP gateway, plus a guide for how
  to use and contribute to the project.

### Changed
- Node floor raised to 22 (20 is end of life); OPA bumped to 1.21.1, which
  needs Go 1.26; ink 5→8, react 18→19, zod 3→4.
- Dependabot grouping fixed so the same update no longer opens two PRs.
- Repository moved to an org; links and module paths updated to match.

### Fixed
- The rate limit held its ceiling but dropped its floor.
- The DLP bar named one secret pattern when it meant all of them.
- A denied call was silently degrading to redact on the most common clients.

### Removed
- Two dependencies nothing in the repository imported.