# Changelog

This project follows semantic versioning for its public Python API. Release
dates are added when a GitHub release is actually published.

## [Unreleased]

## [0.10.0-beta.3] - 2026-08-22

### Authority drift

- Add `verb-authority diff` for direct comparison of raw tool-schema exports or
  existing non-redacted JSON reports, including inferred policies, declared
  controls, server-fixed exposure, bound mutability, tool risk, and human
  confirmation requirements.
- Add compact text and machine-readable JSON output plus a CI-friendly
  `--fail-on-increase` threshold that does not fail on review-only or
  protection-increasing changes.
- Preserve whether each schema rejects unknown arguments in every scan report,
  and treat a closed-to-open change as an authority increase.
- Add a root composite GitHub Action that installs the pinned repository
  revision and fails a workflow when the diff reports an authority increase.

## [0.10.0-beta.2] - 2026-08-21

### Scanner evidence

- Accept a separate, versioned control-declaration file for constrained,
  caller-free, locked, and server-fixed arguments; validate references and
  bound mutability before including them in a report.
- Keep author-supplied evidence visibly separate from inferred policy, label it
  as independently unverified, fingerprint it, and support name-redacted JSON
  and Markdown output.
- Build and smoke-test both command-line entry points from the wheel in CI, and
  retain the source and wheel distributions as workflow artifacts.
- Add the attributed `avp9-nexus` financial-tool fixture and a regression oracle
  that preserves `bidWei` as constrained authority and `destination` as a
  server-fixed declaration.

### Distribution

- Generate and verify SHA-256 checksums for every wheel and source archive.
- Test release tags from a clean checkout and attach the verified distributions
  plus `SHA256SUMS` to each GitHub release.

## [0.10.0-beta.1] - 2026-08-20

### Scanner and Atlas

- Add a zero-dependency local scanner for exported MCP, OpenAI, and Anthropic
  tool schemas without starting servers or sending schemas over the network.
- Produce Markdown or JSON authority reports that omit descriptions, examples,
  defaults, runtime values, and input filenames; add optional name redaction
  and a CI-friendly review exit status.
- Seed the Tool Authority Atlas with ten tools normalized from source-pinned
  official MCP memory and filesystem reference servers.

### Evidence

- Add a reproducible offline corpus covering 12 representative tool schemas
  across 10 categories and 18 mixed-trust calls.
- Report current inference misses instead of hiding them: two policy false
  allows, two policy false blocks, two call false allows, and one call false
  block in the initial reviewer-recorded baseline.
- Position PACT as the closest published argument-level provenance baseline.

## [0.9.0] - 2026-08-19 

### Security model

- Define per-parameter authority as `trusted_fixed`, `typed_bounded`, or
  `outbound_payload`, with uncertain consequential parameters locked for
  review.
- Classify tool verbs by risk and require a caller-controlled confirmation step
  for financial, destructive, and code-execution actions.
- Add declared sink capabilities for overloaded tool parameters.
- Add an optional provenance ledger for exact reuse and contained email/URL
  extraction from tool results.
- Add canonicalization and mixed-script rejection after the adaptive attacker
  found a homograph bypass; the included attacker's observed break moved from
  tier 2 to tier 5.

### Evidence

- Cover inference, dispatch, verb risk, provenance, containment, and lexical
  disguise handling with 35 pytest tests.
- Include offline schema validation, chain, adversarial, adaptive, and
  capability demonstrations.
- Document the first known break—semantic rewrite—alongside provenance,
  confidentiality, and output-side boundaries.

### Distribution and project infrastructure

- Add minimal `pyproject.toml` packaging while preserving the
  `verb_authority.py` module and API.
- Add CI for Python 3.10 through 3.14, installation instructions, a 60-second
  quickstart, contribution and security guidance, and a focused bypass/tool
  schema issue form.

[Unreleased]: https://github.com/yairsabag/verb-authority/compare/v0.10.0-beta.3...HEAD
[0.10.0-beta.3]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.3
[0.10.0-beta.2]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.2
[0.10.0-beta.1]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.1
[0.9.0]: https://github.com/yairsabag/verb-authority/releases/tag/v0.9.0
