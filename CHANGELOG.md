# Changelog

This project follows semantic versioning for its public Python API. Release
dates are added when a GitHub release is actually published.

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

[0.9.0]: https://github.com/yairsabag/verb-authority/releases/tag/v0.9.0
