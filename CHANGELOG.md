# Changelog

This project follows semantic versioning for its public Python API. Release
dates are added when a GitHub release is actually published.

## [Unreleased]

_No unreleased changes._

## [0.10.0-beta.13] - 2026-08-30

### 60-second demo

- Add an offline `verb_authority quickstart` path that scans one exported MCP
  tool schema, prints the inferred per-argument authority, and blocks an
  untrusted recipient before execution. A safe local implementation and
  invocation counter prove the blocked call never reaches the tool while the
  approved control executes exactly once. The trusted runtime registration
  also carries and enforces the schema's `maxLength` bound.

### External regression evidence

- Strengthen Verb Authority through external adversarial testing. A frozen MCP
  fixture exposed an ambiguous-argument edge case; the policy was corrected
  and permanently covered by regression tests.
- Preserve Sankalp Gilda's technical contribution of the external two-arm
  Playwright `browser_tabs` fixture, including the unchanged beta.10 and
  beta.11 reports and their SHA-256 manifest. Record the Apache-2.0 upstream
  source, immutable Playwright MCP commit, independent byte-for-byte scanner
  reproduction, and the limits of the contributor-attested capture chronology.
- Extend the derived regression to verify the frozen bundle before use and to
  pin report v5's tool-level `review_required` aggregate and structured sources
  on the same real schema. Keep the full external evidence repository-only so
  Python distributions remain within the existing release archive contract.

## [0.10.0-beta.12] - 2026-08-30

### Scanner report v5

- Publish the v0.10.0-beta.12 scanner contract by bumping named and redacted
  reports from v4 to v5. Add a derived `review_required` boolean and structured
  `review_sources` index to every tool, covering flagged arguments plus schema,
  risk, risk-conflict, MCP annotation-conflict, and selector-branch review
  obligations already represented elsewhere in the report.
- Keep `summary.review_required` as the number of flagged arguments and add
  `summary.review_required_tools` as the number of tools with any static review
  debt. Keep that aggregate distinct from `needs_confirmation`, which remains
  a runtime approval requirement and does not by itself mean that policy or
  schema review is outstanding.
- Validate every v5 aggregate and its summary counter against the underlying
  evidence when Authority Diff imports a report. Continue to accept complete
  v4 reports for observational comparison by deriving the aggregate only in an
  internal normalized index, without mutating or rewriting caller-owned input.
  Diff output remains format v2, so a v4-to-v5 comparison with unchanged
  semantics has no synthetic change. Report v3 remains rejected and must be
  regenerated from raw inputs with the v5 scanner.

## [0.10.0-beta.11] - 2026-08-27

### Exact selector branch risk

- Add a deliberately narrow runtime model for one exact scalar enum selector.
  Trusted registration must enumerate every selector value exactly once and
  bind it to an effective risk tier plus the complete active-argument set.
  Missing, unknown, duplicate, non-scalar, non-exhaustive, or inactive
  arguments fail closed. Branch declarations do not grant model authorship;
  releasing the selector still requires explicit trusted configuration such as
  `Param(..., sink=False)`.
- Resolve risk, confirmation, and accepted arguments from the selected branch
  before execution. Bind selector identity, its type-exact value, active
  arguments, and effective branch risk into frozen policy material,
  registration fingerprints, action IDs, confirmation requests, and approval
  replay checks. `list` can therefore remain read-only while `close` requires
  confirmation, without trusting the selector value through the provenance
  ledger.
- Extend scanner control declarations and report v4 with exact branch evidence.
  Raw selector values are omitted from reports and replaced by stable SHA-256
  fingerprints; their low entropy and dictionary-guessability are stated in
  the privacy metadata. A likely operation-selector enum without branch
  evidence remains a review obligation. Authority Diff validates, reconciles,
  and compares the complete branch structure rather than flattening it.
- Treat every unequal replacement of a branch's active-argument set as an
  authority increase rather than allowing incomparable additions and removals
  to fall into review only. Existing branch and ordinary review debt now also
  trips `--fail-on-review`, and imported all-read-only branch reports cannot
  relax protected arguments through an inference tuple the scanner would not
  emit. The CLI distinguishes review-classified changes from pre-existing
  candidate review debt and explains the latter on stderr without contaminating
  JSON output.
- Support finite exact JSON-scalar `Literal[...]` annotations in the pinned
  Pydantic AI schema adapter and carry branch identity into deferred approval
  metadata. Add core, scanner, diff, adapter, mutation, drift, and installed
  smoke regressions for exact selector substitution and approval binding.
- Preserve the broader boundary: branch maps express local risk and argument
  applicability only. They do not establish selection intent, arbitrary
  cross-argument relationships, sequence policy, business authorization, or
  action-instance authorization.

### Safe-default authority inference

- Stop treating primitive representation or a raw string-length bound as proof
  of authorship. Undeclared enum, number, integer, boolean, and ambiguously
  named string arguments now remain locked with uncertain confidence and review
  on consequential or unknown-risk tools, even when a string carries
  `maxLength`. Explicit
  `Param(..., sink=False)` in trusted application registration remains the
  deliberate release, and a non-conflicting declared read-only tool may still
  auto-relax an ambiguous primitive.
- Preserve the existing corpus truth labels while recording the stricter
  trade-off: the current development baseline has no false allows, with eight
  conservative policy false blocks and six call false blocks.
- Add a synthetic Playwright `browser_tabs` regression covering an operation
  selector, an unbounded numeric index, and a protected URL. Data-authored
  `action="close"` and `index=0` no longer pass merely because their JSON
  representations are valid.
- Stop accepting raw-schema `x-verb-authority-sink` metadata as verified
  authority control. The scanner preserves changes to that author-controlled
  extension in its schema fingerprints but cannot use it to unlock an
  argument. Runtime `Param.sink` remains trusted application configuration.
- Reject report header and per-tool sentinels wherever a supported raw tool
  collection can appear. A malformed or legacy report entry can no longer be
  reinterpreted as a fresh raw schema by nesting it in a direct list, `tools`,
  `result.tools`, or `sources[*].tools` envelope.

### Scanner report v4

- Bump named and redacted scanner reports from v3 to v4. Preserve each
  recognized boolean MCP tool annotation as a structured
  `annotation_assessments` entry containing the hint value, comparison source
  and value, assessment state, `evidence_source: "mcp_tool_annotation"`, and
  `trust: "unverified_hint"`. Server annotations remain advisory hints even
  when an assessment is `consistent`; they never become verified enforcement
  evidence.
- Distinguish `consistent`, `conflict`, `unresolved`, and `inapplicable`
  annotation states. Unknown effective risk leaves applicable hints unresolved
  rather than creating a false conflict, while read-only hints make effect
  hints inapplicable. Derived conflicts remain review evidence and continue to
  fail `--fail-on-review`.
- Require report v4 for imported-report comparison. Legacy report v3 lacks the
  structured annotation evidence needed to preserve this distinction and is
  rejected with rescan guidance rather than accepted through a compatibility
  default. Extend the installed-wheel smoke to pin report v4, its annotation
  assessment structure, and explicit legacy-v3 rejection.

### Pydantic AI runtime integration

- Add an optional, fail-closed adapter pinned to Pydantic AI 2.35.0,
  Pydantic 2.13.4, and pydantic-core 2.46.4. Direct local
  tools created by `pydantic_schema_tool` are permanently inert schema surfaces;
  the exact synchronous implementation frozen in `GuardedToolRunner` is the
  sole executable. A sealed `PydanticAuthorityAgent` installs and verifies the
  static capability root before every run. It rebuilds each caller-owned schema
  helper as a private inert tool and validator graph, so later helper mutation
  cannot affect execution. Revalidate that graph against its construction-time
  seal immediately before argument validation and again before guarded
  execution, closing callback-time mutation windows before an executable
  validator or Registry implementation can run. Accept both exact validator
  shapes produced by the pinned Pydantic release: its direct core-validator
  fast path in clean installations and its exact plugin container only when
  every validation entry point still delegates directly to the sealed core.
- Add application-owned runtime sessions for hidden fixed values, closed
  trusted-choice resolution, per-session provenance ledgers, and approvals
  bound to the exact tool call, action, arguments, executable, registration,
  and ledger version. Pending approvals retain fixed-size commitments, remove
  denied entries automatically, expose explicit cancellation cleanup, and
  accept resume input only as exact boolean decisions for currently pending
  IDs. Reject external deferred results and caller-supplied deferred metadata
  before Pydantic can surface them to the model. Bind raw decisions to the
  immediately following normalized resume node with a one-use run marker,
  preserve already-settled siblings in mixed batches, and bound approval/tool
  batches to 256 entries.
- Snapshot selector identity and branch shape from the runner's authoritative
  frozen registration into an external session seal. Permit construction no
  longer consults the mutable public inspection alias; empty or bogus alias
  replacement cannot disable raw selector exactness, while mutation or
  replacement of the authoritative registration fails closed before tool or
  ledger activity.
- Reject unregistered tools, generated-schema drift, provider-native tools,
  runtime or remote toolsets, async implementations, wrong session deps, and
  all application-supplied static or per-run capabilities. Reject them before
  lifecycle, enter, or binding hooks can execute. Seal the exact Pydantic-owned
  capability tree and its pristine infrastructure children against replacement
  and instance-method shadowing without dispatching through the mutable root.
  Bind one exact application session identity for the complete run so a session
  getter cannot switch registries or tenants between hooks.
  Reject manual/per-run gate installation, capability-root replacement or
  mutation, `override(spec=...)`, tool-boundary overrides, post-construction
  registration, arbitrary executable Pydantic tools, and declarative agent
  construction paths that do not preserve the sealed subclass.
  Reject realtime sessions, validation-time external deferral, and
  handler-owned timeouts whose semantics the guarded synchronous runner cannot
  preserve. Explicitly reject `run_stream`, `run_stream_sync`, and
  `run_stream_events`, plus per-run `event_stream_handler` callbacks; consume
  and reject Pydantic's mutable event-stream run binding before the sealed
  iter-entry grant exists.
- Keep construction seals outside the mutable Agent object, seal the live
  AgentRun, backing GraphRun, graph iterator, graph dependencies, ToolManager aliases, and
  execution state, and require an exact current node for public graph driving.
  A retained private GraphRun with swapped dependency aliases is rejected
  before any capability hook, Registry implementation, or ledger mutation.
  Consume a one-use entry grant before base `Agent.iter` proceeds, and require
  the corresponding live run-transition token again at tool validation and
  execution. Bind the entry grant and node-lifecycle driver to the exact
  asyncio task, claim every exact node once in the external run seal before
  any callback or await, and snapshot retry configuration before minting the
  entry grant. A child task with a copied context therefore cannot re-enter a
  node and re-arm consumed authority. Mint a separate one-use execution permit
  only for each exact call in the exact current `CallToolsNode`; bind it to raw
  and validated arguments plus any pending action commitment, then consume it
  before resolvers, callbacks, ledger writes, or Registry invocation. Accepted
  callbacks therefore cannot borrow a live transition for another call.
  Require the exact sealed `AgentRun` step function for every node, so an event
  handler or replaced driver cannot observe a context while a permit is live,
  including through an explicit unbound base-API call.
  Explicit base-descriptor calls and direct ToolManager calls fail before the
  Registry implementation, ledger, or pending approval can change.
  Keep approval-transition state in the external run-root seal so rewriting an
  instance marker cannot authorize a call.
- Limit schema annotations and defaults to a non-executable exact JSON-shaped
  subset; reject `Annotated` validators, custom classes, `Field` metadata,
  factories, and mutable defaults. Require exact bounded model tool-call
  identities and snapshot raw arguments and provider details to isolated plain
  JSON before Pydantic argument validation. Treat the local Python model/provider
  implementation as trusted application code; the adapter does not sandbox a
  malicious in-process `Model` implementation.
- Preserve the explicit boundary that independently valid arguments do not
  establish selection intent, tuple, sequence, or action-instance
  authorization.
- Add an offline Pydantic integration evaluation and end-to-end regression
  coverage for canonical resolution, fail-closed lookup, exact deferred
  approval, drift, no-unwrapped-tool invariants, provenance laundering, and
  the intentional control-flow limitation.

## [0.10.0-beta.10]

`0.10.0-beta.9` was an assetless release candidate. Its build job passed the
complete suite and produced valid distributions, but the fresh-runner verifier
correctly rejected candidate-download and verification directories created
inside the Git worktree as untracked source selection. The release was returned
to draft, no assets were uploaded, and its public tag is not moved or reused.
Beta.10 keeps all download, verification, and staging directories under the
isolated runner temporary directory, outside the trusted checkout.

## [0.10.0-beta.9]

`0.10.0-beta.8` was an assetless release candidate. Its release workflow
passed all 1,071 product tests but exposed a missing `setuptools` bootstrap
for one real-build contract test under Python 3.12. The release was returned
to draft, no assets were uploaded, and its public tag is not moved or reused.
Beta.9 installs the declared build backend before the no-isolation contract
test and keeps the full build, fresh-runner verification, and minimal
publisher boundary intact. Package behavior is otherwise unchanged from the
independently audited beta.8 candidate.

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
  outcomes and no fuzzy, path, endpoint, or authorization policy. Validate and
  snapshot finite plain-JSON catalog values at construction, retain no caller
  aliases, and return a fresh snapshot per lookup so one consumer cannot poison
  later trusted resolutions. Require exact bounded built-in strings for keys,
  evidence, and normalization results; reject hostile subclasses, surrogates,
  oversized lookups, and non-string coercion before caller hooks can run.
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
  caller-supplied `PolicySet`; only derived parameter-review entries whose
  bounded inference completed may be overridden, while a resource-limit review
  requires an explicit schema declaration and rebuild. Confirmation may be
  made stricter. Require exact built-in
  policy queues, exact plain-string queue entries, and a valid initial and
  current live-policy snapshot before execution; expose a separate slotted
  inspection view whose policy/risk mapping containers are copied rather than
  aliased to the frozen policy object enforced by the runner. Give every
  confirmation request its own risk-evidence value so callback-side mutation
  cannot poison later requests or retained registration evidence. Expose public
  policy, risk, and risk-confidence leaves as detached canonical strings rather
  than process-wide Enum singletons, and retain the pre-callback ledger version
  privately so mutation of the display request cannot forge the revalidation
  commitment. Commit exact
  registry iteration order to the registration binding because bounded policy
  inference consumes one shared normalization budget in that order; an
  in-place dictionary reorder is therefore detected as configuration drift
  before it can reclassify a resource-limit lock or remove confirmation.
  Ledger stores are
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
  Also compare an alphanumeric-only identifier view so separator-split suffixes
  such as `messageI_D`, `messageI-D`, and `walletK_eY` cannot bypass the same
  selector boundary. Apply the same compact boundary before numeric and
  long-string payload rules, so flatcase authority names such as
  `destinationurl`, `targethost`, `runcommand`, and `accesscredential` remain
  locked unless `sink=False` explicitly releases an overloaded application
  name. Preserve the boundary through common flattened qualifiers such as
  `value`, `address`, `override`, `default`, and `schema`, while bounding both
  identifier length and qualifier depth. Document that lexical inference is a
  finite conservative heuristic and unusual labels need an explicit sink
  declaration.
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
- Put a pre-normalization work ceiling on every NFKC path. Long non-ASCII tool
  results retain exact/raw taint and build a bounded per-code-point ASCII
  compatibility skeleton, preserving disguised ASCII email/URI containment
  without blocking unrelated ASCII destinations; non-ASCII destinations remain
  fail-closed while whole-string canonicalization is incomplete. Convert
  bracketed `(at)`/`[at]` and `(dot)`/`[dot]` separators before disguise
  stripping so the documented lexical transform is actually enforced.
  Share a cumulative 32,768-character NFKC budget across each policy
  inference, gate, ledger publication or lookup, cache repeated identifier and
  result decisions, and keep an identifier whose bounded inference could not
  complete distinct from an ordinary lexical miss. Such a tool remains
  effective `unknown` with review and confirmation, while such an undeclared
  parameter remains `trusted_fixed` with review even on a declared read-only
  tool. Reject data-authored locked sinks before traversing their nested
  Unicode values. Bound the partial ASCII skeleton's output as
  well as its distinct code points, so long Unicode cannot amplify memory.
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
  CI/release jobs, and refuse unexpected local assets. Re-running only a failed
  publisher can resume from the same immutable staged artifact, and only from
  an exact name/size/SHA-256/state-matching subset of the three independently
  verified release assets; any conflicting or additional remote asset fails
  closed. A full rebuild may produce different archive bytes and intentionally
  requires manual cleanup rather than mixing attempts.
- Pin every nonzero raw source-archive header to the exact USTAR magic/version
  and canonical octal size grammar before `tarfile` parses any member. Require
  exactly eleven octal digits plus one NUL, rejecting leading spaces,
  all-space fields, multiple terminators, unterminated fields, and base-256.
  Reject V7, GNU, and arbitrary-magic alternatives that different mainstream
  extractors can interpret with incompatible name/prefix rules.
- Parse source archives through one bounded verifier/extractor that accepts only
  the build backend's local `mtime` PAX field, rejects global PAX, size/path
  overrides and sparse metadata before allocation, and validates every portable
  path before writing. Require the exact source manifest and byte payloads from
  the trusted checkout, permitting only a fixed, independently validated set of
  generated setuptools metadata; the extracted verifier, build configuration,
  tests, and smoke script therefore cannot become their own root of trust.
  Require exactly one gzip member, drain the complete stream, validate its
  CRC/trailer, and reject non-zero bytes after the tar end marker before
  trusting the archive. Reject Windows device aliases including `CONIN$`, `CONOUT$`,
  `CLOCK$`, and superscript COM/LPT forms. Derive an exact wheel allowlist from
  project metadata;
  validate every `RECORD` row, entry point, top-level marker, compression method
  and payload; and require wheel modules, license and core metadata to match the
  verified source distribution.
- Validate sdist and wheel core metadata against the trusted `pyproject.toml`,
  including Metadata-Version, name, version, Requires-Python, runtime
  dependencies, optional dependencies, and extras. Require the supported
  `Wheel-Version: 1.0`; matching attacker-edited PKG-INFO/METADATA copies are no
  longer sufficient.
- Parse dependency and marker material with an explicit ASCII PEP 508 boundary;
  reject non-ASCII whitespace instead of accepting metadata that pip and
  `packaging` reject. Bind the expected project configuration, manifest, and
  source payloads to an immutable Git commit snapshot rather than the mutable
  post-build filesystem, so untracked matching files or build-time source
  mutation cannot become verifier-approved release content.
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
- Split release authority across three fresh runners: build/test and independent
  verification/staging retain read-only repository access, while the minimal
  publisher alone receives `contents: write` and executes no project code. Pass
  distributions only by immutable Actions artifact ID with digest validation,
  bind upload and postflight checks to the numeric release event ID and current
  tag commit, require the beta release to remain a non-draft prerelease both
  before and after upload, and compare the remote asset names, sizes, SHA-256
  digests, and states before accepting publication.
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
- Reject inputs that simultaneously match multiple supported envelopes,
  tool-definition dialects, nested/direct definitions, or schema aliases.
  Scanner and Diff no longer choose a benign branch by precedence while an
  application could consume a competing authority-bearing branch.
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
  across their report locations. Reject duplicate declared bounds, require
  exact identity before an enforced bound counts as retained, and order a
  structured mutability change only when that same bound remains. Treat
  removal of a modeled argument from an open schema as an authority increase
  because the unknown name remains
  caller-visible; moving it behind dynamic `patternProperties` cannot appear as
  protection merely because `additionalProperties` is false.
  Treat an exposed-to-declared-unexposed transition as an authority increase
  when the candidate schema remains open, as review when closure is uncertain,
  and as protection only after unknown arguments are demonstrably closed. Mark
  an unexposed declaration on an open schema as review debt in the scanner.
- Reconcile every imported v3 tool's complete risk state before diffing:
  inference source/confidence/mutability/tokens, declared tier, conflict,
  effective tier/source/evidence, review, and confirmation must form a state
  the scanner can emit. Reject declared risk after control metadata is removed,
  recompute every report summary counter, and classify every coherent effective
  risk change as review rather than assuming a monotonic risk ordering. Clarify
  that report SHA-256 values are content commitments, not authentication of an
  artifact an attacker can replace wholesale. Validate the stable argument
  confidence/policy/review matrix, preserve the exact author-declaration warning,
  and reject an open schema with unexposed controls if its required schema-review
  marker is false or omitted.
- Require every imported v3 report to carry the per-tool
  `schema_review_required` field and matching
  `summary.schema_review_required_tools` counter; intermediate unpublished v3
  reports that omit them now require a rescan instead of receiving a false
  default. Classify clearing an unresolved schema-review obligation as review,
  never as a protection increase, and exercise both explicit-false and omitted
  variants through the isolated installed-wheel CLI.
- Match imported risk-effect validation to scanner output by rejecting empty,
  whitespace-padded, or duplicate effects; reject zero-tool v3 reports that the
  scanner cannot emit. Require scanner-normalized declaration text, canonical
  declaration ordering (including numeric redacted placeholders), and the
  scanner's aggregate cardinality ceilings when importing reports. Reject
  duplicate declared bounds instead of carrying a legacy-v3 review path.
  Detach the confirmation request's compatibility `Decision`
  from the decision returned on callback denial. Remove the inaccurate
  `Typing :: Typed` classifier while the distribution remains a set of top-level
  modules, which PEP 561 cannot mark as an inline-typed package.
- Restrict `--fail-on-increase`, `--fail-on-review`, and the composite
  action's enforcement path to raw schemas that Authority Diff scans locally.
  Keep imported-report comparison observational only because coherent,
  unkeyed report fingerprints are content commitments rather than provenance;
  update CI and release smoke tests to exercise raw inputs at every threshold.
- Escape active Markdown link/image syntax and neutralize bare-URL autolinks,
  mentions, issue-reference markers, GitHub `GH-NNN` shorthand, and raw commit
  identifiers in schema-controlled cells as well as terminal and bidirectional
  controls. Insert a zero-width non-joiner inside GitHub reference tokens;
  entity-encoding the punctuation alone is insufficient after GFM decoding.
- Add scanner-specific aggregate budgets for JSON nodes/material, tool
  definitions, exposed and unexposed arguments, enum members, and
  report-expanding control collections. Reject oversized files before parsing,
  enforce the same ceilings across every public scanner entry point, recheck
  generated reports, and bound loaded reports before Authority Diff indexes
  them. Load CLI schema paths lazily under that same aggregate budget so a long
  path list cannot be decoded into memory before rejection. Additionally cap
  one CLI invocation at 500 input documents and 16 MiB of raw UTF-8 across
  schemas, controls and stdin, including CRLF bytes before newline translation;
  CLI over-limit failures exit 2 without a traceback.

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

[Unreleased]: https://github.com/yairsabag/verb-authority/compare/v0.10.0-beta.13...HEAD
[0.10.0-beta.13]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.13
[0.10.0-beta.12]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.12
[0.10.0-beta.11]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.11
[0.10.0-beta.10]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.10
[0.10.0-beta.9]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.9
[0.10.0-beta.8]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.8
[0.10.0-beta.6]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.6
[0.10.0-beta.5]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.5
[0.10.0-beta.4]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.4
[0.10.0-beta.3]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.3
[0.10.0-beta.2]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.2
[0.10.0-beta.1]: https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.1
[0.9.0]: https://github.com/yairsabag/verb-authority/releases/tag/v0.9.0
