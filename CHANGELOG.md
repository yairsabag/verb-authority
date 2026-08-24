# Changelog

This project follows semantic versioning for its public Python API. Release
dates are added when a GitHub release is actually published.

## [Unreleased]

## [0.10.0-beta.8]

`0.10.0-beta.7` was an unpublished release candidate. It was withheld after
an independent pre-release audit found runtime and diff-contract blockers; no
tag or GitHub release was created, and the version is intentionally not reused.

### Runtime integration

- Add a synchronous guarded runner that enforces the decision immediately
  before a registered callable, fails closed when confirmation is unavailable,
  and records successful results in the session ledger.
- Require explicit trusted-map membership before an argument can be promoted;
  a proposed `None` no longer matches an absent trusted key through two
  `dict.get()` defaults.
- Add a minimal trusted-choice resolver for exact
  `key -> (value, evidence)` lookups, with explicit not-found and ambiguous
  outcomes and no fuzzy, path, endpoint, or authorization policy.
- Pin the approved-choice control-flow limit in documentation and regression
  tests: untrusted content may still influence which already approved catalog
  entry is selected even though it cannot author the resulting destination.
- State the separate compositional-authority boundary: independently valid
  recipient, account, amount, and purpose values do not establish that their
  action-instance combination is authorized; surrounding policy must enforce
  cross-argument and sequence rules.
- Snapshot plain built-in JSON-shaped tool inputs and capture the registered
  callable before confirmation, so callback-side mutation cannot change the
  call that passed the gate.
- Bind confirmation to an immutable request containing canonical
  `arguments_json`, effective and declared risk evidence, conflict state,
  registration and executable identities, ledger version, and an action
  identity. Serialize arguments as canonical ASCII-escaped JSON for stable
  transport. A trusted confirmation renderer must neutralize bidi/control
  characters and escape its output context; without one, display the canonical
  ASCII-escaped JSON verbatim rather than decoded fields.
  The public executable identity is an address-free code/signature digest, and
  the action identity is a content commitment rather than a nonce or replay
  control.
  Visible registered metadata/policy changes, callable object/code replacement,
  and confirmation-time ledger drift deny execution instead of applying a
  stale decision; configuration drift requires a new runner. Derived risk,
  evidence, conflict, and minimum-confirmation state cannot be weakened in a
  caller-supplied `PolicySet`; only derived parameter-review entries may be
  overridden, while confirmation may be made stricter. Ledger stores are
  private exact built-ins, omitted from `repr`, and bound against replacement.
  Callable globals,
  closure contents, and bound-instance state remain trusted application state,
  not semantically frozen action material.
- Compare trusted values recursively with exact types instead of Python's
  coercive equality, preventing `True`, `1`, and `1.0` from sharing authority;
  enforce finite number, integer, boolean, enum, and bounded-string checks for
  every authority policy, including `trusted_fixed`.
- Fail closed on malformed normalized calls and on values outside the runner's
  plain built-in JSON-shaped boundary. Bound paths to 64 list/dict containers
  and integers to 512 decimal digits before confirmation serialization;
  overdeep or oversized tool results become `unsupported_result` after
  invocation rather than escaping as encoder/recursion exceptions.
- Require every registered runtime parameter to be explicit. The application
  must materialize provider or callable defaults before gating and must also
  place protected materialized values in `trusted_args`; `required=False`
  remains beta schema/API metadata and no longer authorizes implicit defaults.
- Validate callable signatures against the registration, reject coroutine and
  async-generator implementations before invocation, reject awaitable results,
  safely close native coroutine results without invoking arbitrary awaitable
  hooks, and require successful results to be plain finite JSON.
  Limit beta.8 implementations to exact plain Python functions; reject forged
  signature metadata, bound methods, callable objects/classes, builtins, and
  partials whose hidden state is not represented by declared arguments.
  Add `invoked` and `contract_violation` to `ExecutionResult` so a callable-side
  contract failure is distinct from successful execution and ledger recording.
  Convert ordinary implementation exceptions to a generic
  `invocation_exception` result while leaving confirmation-callback exceptions
  and process-control `BaseException` subclasses to propagate.
- Enforce declared type and length bounds on outbound payloads without
  changing their data-authorable authority.
- Propagate ledger taint through exact type-tagged JSON scalar leaves, every
  exact object key, and exact list/object containers including empty values;
  keep non-exact containment/canonical matching restricted to risk-shaped
  strings; recognize anchored HTTP(S),
  FTP, WS(S), protocol-relative, and `www.` URI forms; cover Unicode Cyrillic
  supplement/extended characters after NFKC normalization; reject mixed-script
  homographs recursively inside locked JSON; and fail closed on cyclic or
  polymorphic containers.
- Add a source-pinned, non-executing AgentDojo schema exporter and record the
  first static scan across all four public tool suites (74 suite exposures,
  118 parameters) without presenting it as an attack or utility benchmark.

### Distribution

- Build the wheel from the extracted source distribution, run the complete
  suite from that extracted source, and copy the installed-wheel smoke outside
  the checkout so source imports cannot mask missing package contents.
- Exercise all audited pre-release blocker families from the installed wheel,
  plus report-v2 migration rejection and diff
  `--fail-on-increase`/`--fail-on-review` thresholds; assert the installed
  version and module locations.
- Fail a release before checksumming or upload unless its tag normalizes to the
  project version and exactly one wheel plus one source distribution carry the
  expected name and version; refuse unexpected local or pre-existing release
  assets.
- Include the research landscape, installed-wheel audit smoke, and release
  identity verifier in the source distribution.

### Scanner and Authority Diff

- Introduce report format v3 and diff format v2. Named reports now retain exact
  `maximum` and `maxLength` values plus enum-member SHA-256 fingerprints, and
  their global, per-tool, and per-argument schema-material fingerprints commit
  to full validation material after annotations are removed. Separate
  unmodeled-schema fingerprints keep unsupported validation changes visible.
- Treat numeric/string-bound and enum widening or removal as authority
  increases, tightening as protection, and incomparable enum replacements as
  review. Unsupported or ambiguously ordered schema changes still require
  independent review; Authority Diff is not a complete JSON Schema checker.
- Add an independent diff `--fail-on-review` threshold and expose it through
  the composite action as `fail_on_review`. Both action thresholds default to
  fail closed and validate their `true`/`false` inputs independently.
- Refuse legacy report v2 inputs because their omitted constraints cannot be
  migrated safely; users must rescan the original schemas under v3.
- Make redacted v3 reports shape-only for these constraints: presence and enum
  count are retained, while exact numeric values, enum hashes, and exact schema
  material fingerprints are omitted. Named enum and schema hashes omit raw
  values but remain dictionary-guessable and correlatable for low-entropy
  material.
- Replace the ambiguous `examples_or_values_included` privacy field with
  explicit examples/defaults/runtime-value booleans and publish whether schema
  material and unmodeled-schema fingerprints are present, dictionary-guessable,
  and scoped to full named validation material or redacted modeled shape.

### Documentation

- Add a reproducible external-beta case study covering the beta.4 name-derived
  risk failure, beta.5 independent rerun, beta.6 report-contract closure, and
  the remaining limits of static schema evidence.

## [0.10.0-beta.6] - 2026-08-22

### Risk conflict clarity

- Recognize `eval` only as a complete tool-name token for advisory
  `code_exec` evidence while keeping `evaluate`, `evaluation`, and
  `revaluate` outside the match.
- Keep the effective risk at `unknown` when a declared tier conflicts with a
  matched name heuristic, report `conflict_safe_default` as its source, and
  retain review plus confirmation until the conflict is resolved.

## [0.10.0-beta.5] - 2026-08-22

### Risk evidence and safe gating

- Stop treating an author-controlled tool name as proof of runtime behavior.
  Undeclared tools now keep an effective `unknown` risk, require review, and
  retain runtime confirmation until the application declares a tier.
- Replace substring rules with complete snake-, kebab-, and camel-case token
  hints, so `revaluate` no longer becomes code execution while bid mutations
  such as `place_bid`, `buy_bid`, and `submit_bid` remain visible financial
  heuristics rather than silent verdicts.
- Add explicit runtime risk declarations and version-1 sidecar risk evidence
  with a tier, evidence label, and concrete effect list. Reports now separate
  effective, inferred, and declared risk; show caller mutability, confidence,
  conflicts, review status, and confirmation behavior.
- Keep confirmation enabled when a declaration lowers a matched high-risk
  heuristic, include risk review/conflicts in `--fail-on-review`, and compare
  risk sources, evidence, effects, inference, and conflicts in Authority Diff.
- Extend the attributed `avp9-nexus` positive control with attested financial
  effects and add mutation regressions for every reported bid/evaluation name,
  description and parameter non-signals, read-only declarations, and conflict
  fail-safes.

## [0.10.0-beta.4] - 2026-08-22

### Operational control evidence

- Preserve a per-bound `operational_status` of `enforced` or `specified` in
  control declarations and reports; legacy declarations remain valid and are
  rendered as `not_stated` rather than assumed active.
- Make Authority Diff fail on loss or weakening of currently enforced bounds,
  report activation as a protection increase, and keep changes to specified or
  unstated bounds in the review category.
- Correct the attributed `avp9-nexus` fixture to record two currently enforced
  server/platform bounds and two specified bounds from an undeployed contract
  revision without collapsing `bidWei` out of `constrained` authority.

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

[Unreleased]: https://github.com/yairsabag/verb-authority/compare/v0.10.0-beta.8...HEAD
[0.10.0-beta.8]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.8
[0.10.0-beta.6]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.6
[0.10.0-beta.5]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.5
[0.10.0-beta.4]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.4
[0.10.0-beta.3]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.3
[0.10.0-beta.2]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.2
[0.10.0-beta.1]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.1
[0.9.0]: https://github.com/yairsabag/verb-authority/releases/tag/v0.9.0
