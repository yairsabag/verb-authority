# Changelog

This project follows semantic versioning for its public Python API. Release
dates are added when a GitHub release is actually published.

## [Unreleased]

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

[Unreleased]: https://github.com/yairsabag/verb-authority/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/yairsabag/verb-authority/releases/tag/v0.9.0
