# Schema scanner and Authority Diff

Verb Authority scans exported schemas locally. It does not start a tool server,
upload a schema, inspect an implementation, or turn author-supplied declarations
into verified runtime evidence. This page preserves the complete scanner,
control-sidecar, privacy, resource-limit, and diff contracts.

## Scan your tool schemas locally

Export the tool definitions your client already receives, then scan them
without starting a tool server or uploading the schema:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority scan tools.json --output authority-report.md
```

The scanner accepts MCP `tools/list` responses, OpenAI function tools, and
Anthropic tool definitions. An input must select exactly one recognized
envelope and tool-definition dialect; competing schema aliases are rejected
instead of applying a precedence rule that could hide a second interpretation.
An unambiguous OpenAI function may omit `parameters` to declare no arguments;
MCP and Anthropic definitions still require their explicit schema alias.
Its report separates effective risk, an advisory
tool-name heuristic, and author-supplied risk evidence. Tool names are mutable
labels, so a name alone never establishes runtime behavior: without a risk
declaration the effective tier is `unknown`, review is required, and the gate
requires confirmation. Reports also contain per-argument authority, but omit
descriptions, examples, defaults, runtime values, and the input filename. For a
report intended for public sharing, also remove tool and parameter names:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority scan tools.json \
  --redact-names --format json --output authority-report.json
```

MCP tool annotations are server-supplied, unverified hints, not enforcement
evidence. Report v6 retains each recognized boolean hint in a structured
`annotation_assessments` entry with its value, comparison source and value,
and explicit `trust: "unverified_hint"`. The assessment state is `consistent`
when a hint agrees with established effective-risk evidence, `conflict` when
it disagrees, `unresolved` when the scanner lacks a supported comparison, and
`inapplicable` when an effect hint does not apply to a tool marked read-only.
Even a `consistent` hint remains unverified. Conflicts remain visible in
`annotation_conflicts` and count toward `--fail-on-review`; unknown effective
risk leaves applicable hints unresolved instead of manufacturing a conflict.
For MCP's conditional semantics, `destructiveHint` is assessed only when
`readOnlyHint` is false; an effect hint on a read-only tool is recorded as
inapplicable rather than contradictory.

Scanner inputs have their own fail-closed resource boundary. Each JSON file is
limited to 8 MiB of UTF-8 before parsing. The CLI additionally limits one scan
to 500 input documents and 16 MiB of actual UTF-8 input shared lazily across
all schema files, stdin, and the control sidecar. One logical scan is limited
to 100,000 JSON values
and object keys, 2 MiB of conservatively estimated ASCII-safe JSON material,
500 tool definitions, 2,000 schema or unexposed arguments, 10,000 enum members,
and 2,000 declaration collection members across risk effects and argument
bounds. The generated report is checked against the same node/material limits.
Identifier inference also shares one bounded NFKC work budget across the whole
scan and reuses cached decisions, so many individually valid Unicode names
cannot multiply normalization work.
`parse_tool_definitions`, `scan_definitions`, `scan_documents`, and the CLI
enforce these boundaries; Authority Diff applies the JSON boundaries to loaded
reports before indexing them. An over-limit CLI input exits with status 2 and
is not partially scanned or compared.

**Unreleased source note:** the published beta.14 package emits report v5 and
does not contain remediation fields. Report v6 below is the contract of this
unreleased source checkout and will apply only when a release that includes it
is published.

Named JSON reports use report format v6. For the constraints understood by
Authority Diff, they retain exact `maximum` and `maxLength` values and a
SHA-256 fingerprint for each enum member. Raw enum members are omitted, but
hashes of low-entropy values are dictionary-guessable and repeated hashes are
correlatable, so named reports should normally remain local. The report's
global schema fingerprint commits to full validation material with annotations
removed, including those exact numeric values and enum-member hashes. Named
reports also include per-tool and per-argument
`schema_material_fingerprint_sha256` and
`unmodeled_schema_fingerprint_sha256` commitments. These exact schema hashes
can likewise be dictionary-guessed or correlated.

Report v6 retains the explicit review aggregate introduced in v5 for each
tool. Its `review_required` boolean is derived from `review_sources`, which
identifies flagged argument names in `arguments` plus the `schema`, `risk`,
`risk_conflict`, `annotation_conflicts`, and `branch_risk` sources already
present elsewhere in the report. `summary.review_required` remains the number
of flagged arguments; `summary.review_required_tools` counts tools
with any of those review obligations. This static review debt is deliberately
separate from `needs_confirmation`: a well-classified consequential call can
require runtime approval without needing policy review.

Report v6 also attaches remediation metadata to each `trusted_fixed`
argument. When that argument has `review_required: false`, the JSON contract
is:

```json
{
  "remediation_status": "recommended",
  "preferred_remediation": "remove_from_model_schema_and_inject_from_application",
  "fallback_remediation": "bind_trusted_value_at_runtime",
  "remediation_review_reason": null
}
```

When the same authority result still has `review_required: true`, the scanner
does not turn an uncertain classification into implementation advice:

```json
{
  "remediation_status": "review_required",
  "preferred_remediation": null,
  "fallback_remediation": null,
  "remediation_review_reason": "selector_semantics_require_review"
}
```

The review reason is `selector_semantics_require_review` when an enum argument
has a selector-like name and may represent an operation the model is intended
to choose. For other uncertain protected arguments it is
`authority_inference_requires_review`. Every `trusted_fixed` argument includes
`remediation_review_reason`; recommended rows use `null`.

Markdown reports render equivalent human-readable status, remedy identifiers
when present, and the review reason. These fields are advisory: they do not
prove that independently trusted application state
exists, remove an argument from a provider schema, create a wrapper, bind a
runtime value, or change gate behavior. A `recommended` result applies only
after the developer verifies that trusted application code can supply the
value independently of untrusted content. The application must review and
implement either path. See the optional
[schema-projection design proposal](schema-projection-design.md).

When Authority Diff imports a named v4, v5, or v6 report, it recomputes summary
counters and reconciles the complete risk tuple (declaration, advisory
inference, conflict, effective tier, evidence, review, and confirmation) before
comparing it. It also checks the stable argument policy/confidence/review
combinations, preserves the scanner's declaration-verification warning, and
refuses an open schema with declared unexposed controls unless schema review
remains explicit.
For v5 and v6 it additionally requires the per-tool review aggregate and its
summary counter to match the underlying evidence exactly. For v6 it also
validates each `trusted_fixed` remediation tuple against the argument's review
state. Complete v4 and v5 reports remain accepted for observational
comparison; Authority Diff derives only missing presentation metadata in its
internal comparison index and neither mutates nor rewrites the caller's
report. This catches internally impossible or partially edited reports. The
unkeyed SHA-256 fields are content commitments, not
authentication: a party
that can replace an entire stored report can fabricate a different coherent
report and matching hashes. For an untrusted pull request or artifact, rescan
the raw schema/control inputs in CI or require a separately signed/attested
report rather than trusting a checked-in report alone.

JSON decimal constraints are parsed without first rounding through a binary
float. A `maximum` parsed from a decimal or exponent token uses a canonical
decimal string in the JSON report so the exact value remains serializable and
comparable; JSON integer tokens remain integers. Callers of the Python API that
supply a native `float` have already accepted Python's binary rounding, and the
scanner records that float's shortest round-tripping decimal representation.

`--redact-names` also removes exact numeric constraint values and enum-member
hashes, plus all exact per-tool and per-argument schema-material hashes. A
redacted constraint record exposes only shape: whether `maximum` or
`maxLength` is present and how many enum members exist. Its schema fingerprint
therefore commits only to modeled constraint presence and enum count, not the
exact constraint values or unmodeled validation material. Review any remaining
author-written evidence before sharing. Redacted reports are intentionally not
accepted as diff inputs.

Declared selector branches are also emitted with SHA-256 fingerprints instead
of raw selector values. These hashes are deliberately stable for comparison,
but low-entropy values such as `close` are dictionary-guessable. They remain in
both named and name-redacted reports, and the `privacy` object says so
explicitly.

The v6 `privacy` object retains the machine-readable contract introduced in
v4. It keeps separate `examples_included: false`,
`defaults_included: false`, and
`runtime_values_included: false` fields rather than the old combined
`examples_or_values_included` field. Named reports set
`schema_material_fingerprints_included`,
`schema_material_fingerprints_dictionary_guessable`, and
`unmodeled_schema_fingerprints_included` to `true`, with
`schema_fingerprint_material_scope` set to
`full_validation_material_excluding_annotations`. Redacted reports set those
three booleans to `false` and use the scope
`modeled_presence_and_enum_count_only`.

Use `--fail-on-review` in CI to return a non-zero status when ambiguous risks,
arguments, likely operation selectors without branch evidence, risk conflicts,
MCP annotation conflicts, or unresolved JSON Schema composition need attention.
The v6 per-tool aggregate is an index over those existing obligations, not a
new inference or a substitute for inspecting their underlying evidence.
The scanner does not resolve `$ref`, `allOf`,
`anyOf`, `oneOf`, or conditional/dependent schemas. It instead sets
`schema_review_required` on the tool and counts it in
`summary.schema_review_required_tools`, so authority-bearing properties hidden
behind those constructs cannot produce a silent clean result. The same flag is
set for required names absent from the modeled `properties` map, multi-type
unions, dynamic `patternProperties`, and ambiguous direct-shape exports whose
argument names collide with JSON Schema wrapper keywords. A schema with
dynamic property admission is not reported as closed to unknown arguments.
An argument containing a nonempty nested property map also requires schema
review: only root arguments receive individual authority policies, so a
payload-named object can contain destinations or selectors whose ownership
has not been assessed. This review flag does not infer nested ownership or
change the outer argument's policy. Object-valued enum members and unused
schema definitions remain instance data or inert helpers, not extra arguments.
Direct-shape collisions preserve the arguments
in the report rather than silently replacing them with an empty list. The
structurally indistinguishable `properties` collision remains an explicit
review obligation instead of a clean empty audit. Static inference is a review
aid, not a vulnerability verdict; the scanner does not inspect tool
implementations or verify the surrounding application's authorization and
provenance wiring.

Both schema-review fields are mandatory in imported v4, v5, and v6 reports. In
v5 and v6, each tool's `review_required` and `review_sources` fields and
`summary.review_required_tools` are also mandatory and must be coherent with
the underlying argument, schema, risk, annotation, and branch evidence. A
report that omits any required field must be regenerated from the original
schema with the current scanner; omission is not interpreted as `false`. When
Authority Diff sees an explicit schema-review obligation change in either
direction, it keeps the change in the review queue. In particular, clearing
`true` to `false` is not treated as proof that protection increased when only
report evidence is available.

### Add implementation-level control evidence

A JSON Schema cannot show that a caller-selected value is constrained by a
runtime allowlist, or that the server supplies an argument which is not exposed
to the model. Add a separate, reviewable declaration when you have that
implementation evidence:

```json
{
  "version": 1,
  "attribution": {
    "name": "security review",
    "source": "implementation and integration tests"
  },
  "tools": {
    "create_export": {
      "risk": {
        "tier": "write",
        "evidence": "attested",
        "effects": ["writes_export_file"]
      },
      "arguments": {
        "destination_path": {
          "authority": "constrained",
          "evidence": "attested",
          "bounds": [
            {
              "source": "approved export root",
              "bounds_mutability": "trusted_party",
              "operational_status": "enforced",
              "enforcement": "runtime path containment"
            }
          ]
        }
      },
      "unexposed_arguments": {
        "tenant_id": {
          "exposure": "server_fixed",
          "enforced_by": "authenticated session",
          "evidence": "observed"
        }
      }
    }
  }
}
```

Pass that file separately from the exported schemas:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority scan tools.json \
  --controls controls.json --output authority-report.md
```

Risk declarations require a `tier` (`read_only`, `write`, `financial`,
`destructive`, or `code_exec`), an evidence label, and a non-empty list of
unique, non-blank concrete effects. Surrounding whitespace is stripped during
normalization. Effects are preserved as author-written evidence and are not
parsed into a verdict. A non-conflicting declaration resolves the `unknown`
fail-safe. If it disagrees with a matched name heuristic, the report preserves
both claims, keeps the effective tier `unknown`, marks the source as
`conflict_safe_default`, and retains confirmation until a human reviews the
conflict. The declaration and its evidence remain visible under
`declared_risk`; they are not relabeled as evidence for the effective
safe-default tier.

Exposed arguments may be `locked`, `constrained`, or `free`. A constrained
argument must name at least one bound and say whether the bound is
`immutable`, controlled by a `trusted_party`, or controlled by the `caller`.
Each bound may also state whether it is running now (`enforced`) or belongs to
a design that is not running (`specified`). If omitted, the report preserves
the absence as `not_stated` rather than assuming the control is active.
Evidence may be `observed`, `declared`, or `attested`. Unexposed arguments
currently support the explicit `server_fixed` control.
Declaring an argument unexposed does not close an otherwise open or dynamic
schema: that contradiction remains `schema_review_required`, and moving a
previously exposed argument to such a declaration is not reported as a
protection increase unless the candidate schema actually closes unknown
arguments.

These declarations are author-supplied evidence: the scanner validates their
shape, fingerprints them, and displays them alongside (not instead of) its
inferred policy. It does not inspect the enforcement or treat a declaration as
proof. With `--redact-names`, tool and argument names plus attribution are
removed, but author-written bound sources, enforcement text, and notes remain;
review a redacted report before sharing it.

A polymorphic tool may declare exact risk and argument applicability for one
enum selector instead of one flattened tool risk. The cases must cover every
enum value exactly once, use JSON scalars, include the selector in every
argument list, and name only schema arguments. A tool-level `risk` and
`branches` are mutually exclusive:

```json
{
  "version": 1,
  "tools": {
    "browser_tabs": {
      "branches": {
        "selector": "action",
        "cases": [
          {
            "value": "list",
            "risk": {
              "tier": "read_only",
              "evidence": "observed",
              "effects": ["reads_tabs"]
            },
            "arguments": ["action"]
          },
          {
            "value": "close",
            "risk": {
              "tier": "destructive",
              "evidence": "observed",
              "effects": ["closes_tab"]
            },
            "arguments": ["action", "index"]
          }
        ]
      }
    }
  }
}
```

The example is abbreviated: a real declaration must include every selector
enum member. The report summarizes the worst branch at tool level, exposes
each case's risk and active arguments with only a selector-value fingerprint,
and compares MCP annotations against that worst established tier. Branch
evidence never unlocks the selector. Model authorship still requires trusted
runtime registration such as `Param("action", "enum", sink=False)`; the branch
map then supplies per-call risk and confirmation, not value provenance.

The public [`avp9-nexus` financial fixture](../fixtures/README.md) includes a tool
schema, attributed control sidecar, and expected classification used as a
regression oracle.

## Catch authority drift between versions

Compare two exported tool schemas directly. Verb Authority scans both inputs
locally, then reports only authority-relevant changes:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority diff tools-main.json tools-pr.json
```

Example output:

```text
[AUTHORITY INCREASE] purchase_bid.destination
  A previously unexposed argument became caller-visible.
  schema_exposure: unexposed -> exposed
```

Without a failure threshold, the command also accepts two non-redacted JSON
reports for observational comparison. Diff output format v2 is paired with
scanner report format v6 and accepts complete report v4, v5, or v6 inputs. For
a v4 input, Authority Diff derives the later tool-level review aggregate only
in its internal index; it does not mutate or rewrite the supplied report, and
this derived presentation field does not create a semantic diff by itself.
For v4 and v5 inputs, absent v6 remediation metadata is not invented as
implementation evidence and does not create a semantic diff. Report v3 did
not preserve the structured provenance and assessment state of MCP
annotation hints, so it is rejected rather than upgraded by inference. Report
v2 also omitted constraint values and cannot be migrated without inventing
evidence. Rescan the original raw schema with the v6 scanner before comparing
it. When implementation controls are part of a
raw-schema comparison, pass the sidecars with `--before-controls` and
`--after-controls`. Control evidence remains visibly author-supplied; a diff
does not turn a declaration into verified enforcement.
Malformed or legacy report-shaped input is rejected as a report and is never
reinterpreted as a raw tool schema. This includes report header or per-tool
sentinels hidden inside a direct tool list, `tools`, `result.tools`, or an Atlas
`sources[*].tools` collection.
Intermediate, unpublished v4 reports that predate the mandatory
`schema_review_required` and `summary.schema_review_required_tools` fields must
also be rescanned rather than compared under an optimistic default.
Imported v4, v5, and v6 reports must contain at least one tool, matching the
scanner's own output boundary; a fabricated empty report is rejected with
rescan guidance.
They must also preserve scanner-normalized declaration text and canonical
declaration order, and remain within the scanner's aggregate limits for tools,
arguments, enum members, effects, and bounds. A report outside those emitter
boundaries is rejected instead of being treated as a scanner-produced report.

Imported-report comparison is advisory: report coherence and unkeyed hashes do
not authenticate the schema from which a report came. If either CLI threshold
is present, both inputs must therefore be raw schemas; report-shaped input is
rejected before output, and Authority Diff scans both raw inputs locally.
`diff_reports()` callers have the same responsibility to derive reports from
trusted raw inputs or authenticate them independently.

The two CLI thresholds are independent. `--fail-on-increase` returns status 2
only for authority increases; review-only and protection increases remain
visible without tripping that flag. Add `--fail-on-review` when any ambiguous
or unmodeled change, or review debt already present in the candidate scan,
should also return status 2:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority diff tools-main.json tools-pr.json \
  --fail-on-increase --fail-on-review
```

Or add the repository's zero-configuration composite action after exporting
the baseline and candidate schemas in your workflow:

```yaml
- uses: actions/checkout@v7
- uses: actions/setup-python@v7
  with:
    python-version: "3.12"
- uses: yairsabag/verb-authority@v0.10.0-beta.14
  with:
    before: tools-main.json
    after: tools-pr.json
```

The workflow must obtain the baseline schema from a protected revision or
artifact, not from candidate-controlled replacement data, and the candidate
export must correspond to the implementation that will run. Raw-only
thresholds remove unauthenticated derived reports from the gate; they do not
prove either of those surrounding CI bindings.

The action fails the step on an authority increase and review debt by default.
Set both `fail_on_increase: "false"` and `fail_on_review: "false"` for an
observation-only rollout. Starting with beta.8, the two thresholds are
independent, so an unmodeled or ambiguously ordered schema change fails closed
instead of passing because it is not an authority increase:

```yaml
with:
  before: tools-main.json
  after: tools-pr.json
  fail_on_increase: "true"
  fail_on_review: "true"
```

Both inputs accept only the exact strings `"true"` or `"false"`. The beta.14
pin in the example above supports both thresholds. The action removes
`PYTHONPATH` and `PYTHONHOME` and uses Python isolated mode for both installation
and comparison, preventing modules in the consumer checkout from shadowing
`pip` or the installed Verb Authority package.

The v6 comparison orders `maximum`, `maxLength`, and enum changes. Widening or
removing one is an authority increase; tightening one is a protection
increase; and enum replacements without a strict subset relationship require
review. Any effective risk-tier change also requires review; tiers are not
treated as a safe monotonic ordering. Authority Diff is not a complete JSON
Schema equivalence checker.
Removing a modeled argument counts as protection only when the candidate schema
also rejects unknown arguments; in an open schema the same name remains
caller-visible without its modeled policy, so the change is an authority
increase. Enforced bound chains retain exact control identity: adding an exact
independently controlled bound is protection, removing one is weakening, and
replacing an author-written bound with a different claim remains review rather
than being ordered by mutability label or raw count. A mutability change on the
same retained enforced bound is ordered explicitly (`immutable` is stronger
than `trusted_party`, which is stronger than `caller`), and exact duplicate
bounds are rejected rather than counted twice.
Schema changes outside the modeled vocabulary are surfaced through the
unmodeled-schema fingerprint as `REVIEW`; any change it cannot order safely
requires independent review rather than an assumption that no reported
increase means safe.

Name-redacted reports cannot be correlated safely across versions, so diff
them locally before applying `--redact-names` to a report intended for sharing.

The [`Tool Authority Atlas`](../atlas/README.md) checks in the same analysis for a
small, source-pinned set of public MCP reference tools. It is the seed of a
community corpus, not a ranking of MCP servers.

## Related boundaries

- [Security model](security-model.md)
- [Limits and boundaries](limits-and-boundaries.md)
