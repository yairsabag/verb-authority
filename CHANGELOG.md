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
- Bind confirmation to an immutable request containing exact-order
  `arguments_json`, effective and declared risk evidence, conflict state,
  registration and executable identities, ledger version, and an action
  identity. Serialize arguments as ASCII-escaped JSON while preserving signed
  zero and object insertion order for exact observable action identity and safe
  transport. A trusted confirmation renderer must neutralize bidi/control
  characters and escape its output context; without one, display the
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
  keep signed zero and object insertion order distinct for trusted-value
  equality and confirmation action identities;
  enforce finite number, integer, boolean, enum, and bounded-string checks for
  every authority policy, including `trusted_fixed`.
- Evaluate authority-bearing names before broad numeric, enum, boolean, or
  payload rules. Numeric account identifiers and explicit destinations remain
  locked, while ambiguous identifier selectors stay locked and enter the
  consequential-tool review queue. Tokenize sink, selector, and payload names
  consistently across snake-, kebab-, dotted-, slashed-, camel-case, and
  acronym styles, so names such as `messageId`, `message-id`, `messageID`,
  `replyTo`, `contentURL`, `idempotencyPath`, and `apiKey` cannot fall through
  to broad numeric authority while `messageBody` remains data-fillable.
  Match complete tokens rather than substrings, normalize compatible fullwidth
  forms, and keep non-Latin, mixed-script, or otherwise unmodeled identifiers
  locked for review unless the application explicitly declares `sink=False`.
  Treat numeric suffixes and complete `identifier` tokens as boundaries, and
  conservatively recognize every compact selector suffix plus UUID/GUID selectors, so
  `messageIdentifier`, `MESSAGEID`, `messageId2`, `messageUUID`, `account2`, and
  `recipient1` cannot become broadly caller-authorable. Flatcase suffixes fail
  closed without relying on a finite entity-prefix list; `sink=False` remains
  the explicit release valve for an ordinary word that shares a suffix.
  Implement tokenization as a bounded linear pass rather than a backtracking
  uppercase-name expression.
- Normalize valid string-valued policy/risk enum entries consistently in the
  direct gate, dispatcher, and guarded runner; malformed policy material now
  returns a closed decision from direct APIs instead of escaping an exception.
  Escape controls, bidi characters, and other non-ASCII label text in runtime
  decision reasons before they reach logs or terminals.
- Fail closed on malformed normalized calls and on values outside the runner's
  plain built-in JSON-shaped boundary. Bound paths to 64 list/dict containers
  and integers to 512 decimal digits before confirmation serialization. Bound
  each logical snapshot to 100,000 total values/object keys and 8 MiB of
  conservatively estimated ASCII-escaped JSON material, shared across the tool
  name, proposed input, and trusted arguments and charged incrementally before
  full encoding. Repeated-scalar arrays, oversized strings, and unknown
  argument/tool floods therefore stop before invocation or ledger-history
  scans; overdeep or oversized tool results become `unsupported_result` after
  invocation with explicit no-retry telemetry rather than escaping as
  encoder/recursion exceptions.
- Require every registered runtime parameter to be explicit. The application
  must materialize provider or callable defaults before gating and must also
  place protected materialized values in `trusted_args`; `required=False`
  remains beta schema/API metadata and no longer authorizes implicit defaults.
- Validate callable signatures against the registration, reject coroutine and
  async-generator implementations before invocation, reject awaitable results,
  validate arbitrary result objects against the exact plain-JSON boundary
  before classifying only exact native async types, safely close those through
  unbound interpreter methods without consulting spoofed `__class__`,
  `close`, or `aclose` hooks, and require successful results to be plain finite
  JSON.
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
  polymorphic containers. Reject aliased Python container graphs as non-JSON
  before a compact shared DAG can expand exponentially; separately decoded
  equal JSON subtrees remain valid.
- Bound each ledger session to 10,000 retained entries and 8 MiB of UTF-8 text
  material. Capacity preflight is atomic and fail-closed: no old taint is
  evicted, overflow saturates the session, the already-invoked call reports
  `ledger_capacity_exceeded` with an explicit no-retry instruction, and later
  calls require a fresh ledger.
- Canonicalize a rejected runtime enum candidate once rather than once per
  declared member. Skip ledger-history containment scans when no exact trusted
  candidate could promote provenance, and share a deterministic 16-MiB
  character-work budget across the remaining lookups in one dispatch; budget
  exhaustion conservatively keeps the candidate data-authored.
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
  expected name and version; require the exact pure-Python
  `py3-none-any` wheel filename, matching internal `WHEEL` metadata, an exact
  name/version-bound `.dist-info` root, and an exact name/version-bound source
  root. Reject unsafe, ambiguous, duplicate, case-colliding, encrypted, or
  foreign-metadata wheel members and apply compressed, per-member, aggregate,
  and member-count ceilings. Reject unsafe source-archive paths, duplicate or
  portable-colliding names, GNU/PAX sparse files, special members, and archive
  bombs under equivalent ceilings. Traverse gzip data through a decompressed
  byte cap, bound extension-header size/depth/count, and validate each tar
  header before advancing, so oversized regular, directory, PAX, or GNU
  extension payloads cannot consume unbounded work
  before rejection; verify the source distribution before extraction in
  CI/release jobs, and refuse unexpected local or pre-existing release assets.
- Isolate both composite-action Python entry points with `-I` and remove
  `PYTHONPATH`/`PYTHONHOME`, so consumer-workspace `pip.py`,
  `verb_authority.py`, or a planted console script cannot turn a real widening
  into a false pass. Put schema paths behind an explicit end-of-options boundary
  so option-looking filenames cannot request CLI help and false-pass. Exercise
  both module-shadow and option-looking path cases in CI.
- Apply the same isolated-Python and scrubbed-environment boundary to installed
  wheel installation and smoke checks, their child process,
  metadata/assertion helpers, and installed console commands. CI plants a
  hostile module beside the copied smoke script and requires proof that it was
  never imported.
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
- Parse JSON decimals without a binary-float round trip, preserve maxima parsed
  from decimal tokens as canonical text in serializable v3 reports, and commit
  exact decimal enum values to distinct fingerprints. Direct Python floats
  retain their already-rounded shortest round-tripping representation.
- Reject every report-shaped input with missing markers, malformed v3 fields,
  or a legacy version instead of reinterpreting it as a raw schema. Preserve
  annotation-named data nested under unsupported schema keywords in unmodeled
  fingerprints, reject over-deep schemas cleanly, and terminal-escape controls
  and bidirectional formatting in text diff output.
- Surface unresolved references, combinators, conditional/dependent schemas,
  dynamic property shapes, and nested unmodeled schemas as an explicit
  per-tool review obligation on the first scan. Include that obligation in
  `--fail-on-review` and Authority Diff instead of allowing hidden arguments to
  produce a clean baseline. Apply the same obligation to required names absent
  from `properties` and to multi-type unions whose constraints are conditional
  on the selected JSON type. Preserve every argument in direct-shape exports
  when an argument name collides with `type`, `enum`, or another wrapper
  keyword, and flag that unavoidable shape ambiguity instead of emitting a
  clean empty audit. Keep the structurally indistinguishable `properties`
  collision as explicit review debt rather than silently claiming full
  coverage.
- Recompute author-supplied control fingerprints before comparison and require
  duplicated risk, schema-closure, argument-policy, and review fields to agree
  across their report locations. Treat removal of a modeled argument from an
  open schema as an authority increase because the unknown name remains
  caller-visible. Order enforced bound chains by independently controlled
  strength before count, so multiple caller-controlled bounds cannot replace
  one trusted or immutable bound and appear stronger.
- Escape active Markdown link/image syntax and neutralize bare-URL autolinks,
  mentions, and issue-reference markers in schema-controlled cells as well as
  terminal and bidirectional controls.
- Add scanner-specific aggregate budgets for JSON nodes/material, tool
  definitions, exposed and unexposed arguments, enum members, and
  report-expanding control collections. Reject oversized files before parsing,
  enforce the same ceilings across every public scanner entry point, recheck
  generated reports, and bound loaded reports before Authority Diff indexes
  them. Load CLI schema paths lazily under that same aggregate budget so a long
  path list cannot be decoded into memory before rejection; CLI over-limit
  failures exit 2 without a traceback.

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
