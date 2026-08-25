# Verb-Authority Gate

[![CI](https://github.com/yairsabag/verb-authority/actions/workflows/ci.yml/badge.svg)](https://github.com/yairsabag/verb-authority/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776AB.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

A small Python gate that prevents untrusted agent data from authoring sensitive
tool-call arguments—without classifying prompts.

**Data selects. Never authors.**

> **Exact guarantee:** under the gate's provenance model, untrusted data cannot
> author tool-call arguments whose policy is `trusted_fixed`. The decision is
> enforced before the tool runs; the gate does not try to decide whether a
> prompt is malicious.

> **Control-flow boundary:** Verb Authority constrains who may author a
> sensitive argument's value. It does not prevent untrusted content from
> influencing whether a tool is called or which member of an already approved
> set is selected. If an untrusted email says “send this to Dana” and Dana is
> in the application's trusted contact directory, the current value-level gate
> can allow the directory-supplied address. Preventing that control-flow
> influence requires planner- or session-level information-flow control.

> **Compositional-authority boundary:** conformance is per argument, not an
> authorization decision for the action instance as a whole. A recipient,
> account, amount, and purpose can each have valid provenance while their
> particular combination is still forbidden. The surrounding application must
> enforce cross-argument, transaction, sequence, and business-policy rules
> before execution; Verb Authority does not infer those relationships.

The per-argument boundary is the intended utility tradeoff: an application can
lock `to` while still allowing untrusted text to fill `body`, instead of
disabling the entire `send_email` tool after untrusted content enters context.

This is a research-grade boundary, not a claim that prompt injection is
impossible. The optional ledger catches exact reuse, emails and URLs extracted
from returned text, nested JSON values, every exact object key, exact
containers (including empty ones), and several lexical disguises. It does
**not** follow a value through semantic
reconstruction—for example,
turning “attacker at evil dot com” into an address. A developer can also defeat
the guarantee by marking untrusted input as trusted without using the ledger.
Systems such as CaMeL and FIDES use interpreter- or planner-level
information-flow tracking to cover that deeper boundary.

## Install

Verb Authority is not published on PyPI. Install the current source directly
from GitHub:

```bash
python -I -m pip install "verb-authority @ git+https://github.com/yairsabag/verb-authority.git@v0.10.0-beta.8"
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority
```

The second command runs the built-in demo. The package has no runtime
dependencies and keeps the existing `verb_authority.py` module and import API.

The [beta.8 release](https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.8)
also includes a wheel, source archive, and `SHA256SUMS`. After downloading all
three files, verify them with `sha256sum --check SHA256SUMS` on Linux or
`shasum -a 256 -c SHA256SUMS` on macOS before installing the wheel.

The `verb-authority`, `verb-authority-scan`, and `verb-authority-diff` console
shortcuts are convenient in a trusted interpreter environment, but a console
script cannot enable Python isolation for itself and can honor a hostile
`PYTHONPATH`. When the current directory or environment is not fully trusted,
use the isolated `env -u ... python -I -m verb_authority` form shown above.

For a local checkout instead:

```bash
git clone https://github.com/yairsabag/verb-authority.git
cd verb-authority
python -I -m pip install .
```

## 60-second quickstart

The gate accepts a normalized tool call shaped as `{"name": ..., "input":
...}`. Provider-specific tool-call objects should be converted to that small
shape before dispatch.

```python
from verb_authority import Param, Registry, Risk, Tool, build_policy, dispatch

registry = Registry()
registry.add(
    Tool(
        "send_email",
        [Param("to", "email"), Param("body", "string")],
        risk=Risk.WRITE,
    )
)
policy = build_policy(registry)

# The model proposes an attacker-controlled recipient. The only trusted value
# is the recipient the application obtained from a trusted/user-approved flow.
tool_call = {
    "name": "send_email",
    "input": {"to": "attacker@evil.com", "body": "Meeting summary"},
}
decision = dispatch(
    registry,
    policy,
    tool_call,
    trusted_args={"to": "alice@company.com"},
)

print(decision.allow)   # False
print(decision.reason)  # param 'to' is a locked sink; data may not author it
```

`dispatch` is a decision-only API. Call it immediately before tool execution,
execute only when `decision.allow` is true, and request human approval when
`decision.needs_confirm` is true. A direct-dispatch integration owns the
atomic relationship between that decision, the exact arguments it executes,
confirmation, callable identity, and result recording. Use the guarded runner
below when those properties need to be enforced as one runtime boundary.

## Execute tools and resolve trusted choices

`GuardedToolRunner` is the synchronous integration point for a real tool loop.
It calls `dispatch` immediately before the registered function, fails closed
when required confirmation is unavailable, and records successful results in
one session ledger. Provider-specific calls still need to be normalized to the
small `name`/`input` shape shown above.

The runner accepts plain built-in JSON-shaped values (`dict`, `list`, strings,
finite numbers, booleans, and `None`). Normalize framework containers before
calling it. A root-to-leaf path is limited to 64 list/dict containers,
including the root input object, and integers are limited to 512 decimal
digits. Each logical snapshot is also limited to 100,000 total JSON values and
object keys and 8 MiB of conservatively estimated ASCII-escaped JSON material.
The tool name, proposed input, and `trusted_args` share one such budget. It is
charged incrementally, so one oversized string or a million repeated scalar
values fails without first expanding or serializing the whole value. Values
outside any portable serialization bound fail closed before confirmation or
invocation. Every registered parameter must appear explicitly in the tool
call, including a parameter declared with `Param(..., required=False)`. If the
provider or Python callable has a default, the application must materialize
that value before the gate. A protected materialized value must also appear,
with the same exact JSON type and value, in `trusted_args`. `required=False`
is retained as beta schema/API metadata; it is not permission to execute an
implicit default. The runner also rejects registered callables that consume an
undeclared parameter or rely on an undeclared default. Beta.8 accepts only an
exact plain Python function as an implementation. Bound methods, callable
instances or classes, builtins, and partials are rejected because their hidden
receiver or bound state is not a declared tool argument; materialize that
state as explicit parameters instead.

Before confirmation, the runner isolates the tool call and trusted arguments
and snapshots registration/policy metadata. The callback receives an
immutable `ConfirmationRequest` whose ASCII-escaped, insertion-order-preserving
`arguments_json` encodes the exact private argument snapshot that can run.
Its compatibility `decision` object is also a detached snapshot, so even a
trusted callback that forcibly mutates its display object cannot rewrite the
decision metadata returned by the runner on denial.
Signed `0.0`/`-0.0` and nested object member order remain distinct in both the
snapshot and `action_id`, because Python tool implementations can observe
those differences. Runtime `Decision.reason` text ASCII-escapes control,
bidirectional, and non-ASCII characters from tool and parameter labels before
it reaches a log or terminal. A UI
may decode and show individual fields only through a trusted renderer that
neutralizes bidi/control characters and escapes each output context. Without
such a renderer, show the ASCII-escaped JSON verbatim; never inject
decoded fields directly into markup or a terminal. The request also contains
the effective risk and its evidence, the declared-risk conflict state, and
`registration_id`, `executable_id`, `ledger_version`, and `action_id`
commitments. The public inspection view and confirmation request expose policy,
risk, and risk-confidence values as detached canonical strings rather than the
process-wide Enum members retained by enforcement; compare these fields by
value (for example, `request.risk == "financial"`), not by Enum identity.
`executable_id` is an address-free SHA-256 digest of the function's
module/qualified name, code content, and raw non-unwrapped binding signature; a
separate private binding token detects replacement of the live function object
without exposing its address. `action_id` is a content commitment, not a
one-time nonce or replay-prevention mechanism. Applications must provide any
required request freshness or replay control. Approval requires the exact
boolean `True`.

Visible mutation of registered `Tool`/`Param`/policy material or replacement
of the function object/code denies the action and requires rebuilding the
runner. Derived risk, risk evidence, conflicts, and required confirmations
cannot be weakened in a caller-supplied `PolicySet`; a parameter policy can be
overridden only when that parameter appears in the derived review queue and
its bounded identifier inference completed. A review caused by an inference
resource limit remains locked; intentionally releasing it requires an explicit
`sink=False` declaration in the schema/registration and a rebuilt policy.
Required confirmation may be made stricter. The ledger's private stores and
lock are exact built-ins, are excluded from its representation, and replacement
of one after runner construction is detected. Direct in-process mutation of
private attributes remains trusted-application behavior. This is not a
semantic snapshot of module globals or closure contents.
Those are trusted application state: serialize their changes with tool
execution and rebuild the runner when they change action configuration. The
confirmation callback is likewise
trusted control-plane code; keep it synchronous and side-effect-safe, and do
not let untrusted code run inside it. Exceptions from that callback propagate
to its trusted caller. Public evidence snapshots do not alias enforcement
state, but arbitrary imported code in the same Python process remains inside
the trusted application boundary and can still interfere with module globals,
classes, or private objects. The session ledger owns a re-entrant lock. The runner
holds that shared lock from final revalidation through invocation and atomic
result publication, so multiple runners using the same ledger serialize that
critical action section. It deliberately releases the lock while human
confirmation may block, then reacquires it and rechecks configuration and the
ledger epoch. This is not a lock for globals, databases, or other application
state; externally synchronize those resources and avoid unsynchronized
mutation during a call.

The public `gate` and `dispatch` paths apply the same frozen-policy validation
as the runner: valid string forms such as `"trusted_fixed"` and `"financial"`
are normalized to their enums, while malformed, unbound, or weakened policy
material produces a closed `Decision` instead of escaping a runtime exception.

One session ledger retains at most 10,000 exact/search-index entries and 8 MiB
of UTF-8 text material. It never evicts old taint. If publishing a completed
tool result would exceed either budget, that write is not partially committed,
the ledger becomes permanently saturated, and every later call is denied until
the application starts a new session with a fresh ledger. The already-entered
tool must not be retried: the runner reports `invoked=True`, `executed=False`,
and `contract_violation="ledger_capacity_exceeded"` with that instruction.
Unicode normalization is bounded twice: no individual NFKC input may exceed
4,096 characters, and one policy-inference, gate, ledger-publication, or lookup
operation shares a cumulative 32,768-character work budget across all of its
nested values. Repeated result strings are normalized once per publication.
Budget exhaustion fails closed; data-authored locked sinks are rejected before
their nested values enter normalization at all.

The runner is deliberately synchronous. It rejects coroutine and async-
generator implementations before invocation, rejects awaitable results, and
closes native coroutine results without invoking hooks on arbitrary awaitable
objects. A successful result must also be plain finite JSON; it is
deep-snapshotted before being returned and recorded. `ExecutionResult.invoked`
says whether the callable was entered, `executed` says it completed the
synchronous JSON-result contract and was recorded, and `contract_violation`
distinguishes an awaitable or unsupported result. A callable can therefore be
`invoked=True` but `executed=False`. If a tool implementation raises an
ordinary `Exception`, the runner returns a generic denial with `invoked=True`,
`executed=False`, `result=None`, and
`contract_violation="invocation_exception"`; exception details are not placed
in the result. Process-control `BaseException` subclasses still propagate.
Never automatically retry when `invoked=True`, even if `executed=False`: the
implementation may have produced an external side effect before raising or
violating the result contract. A result beyond the JSON depth or integer bound
or the total node/material snapshot budget is reported after invocation as
`contract_violation="unsupported_result"` without exposing the result. A
snapshot-budget denial also carries an explicit no-retry instruction.
Free outbound payloads may be authored by data, but they still must satisfy
their declared runtime type and bounds such as `max_len`.

When a model supplies a human label such as a contact name, resolve that label
against an application-owned catalog first. `TrustedResolver` implements only
an exact `key -> (value, evidence)` lookup after trimming and case-folding. It
does not perform fuzzy matching, authorization, endpoint policy, or path/prefix
checks. Unknown and ambiguous keys remain unresolved. Catalog values must be
finite plain JSON. The resolver snapshots them at construction and returns a
fresh snapshot for each successful lookup, so mutating the constructor input or
one resolution cannot redefine a later trusted choice. Keys, evidence, and
normalizer results must be bounded built-in strings; string subclasses,
surrogates, oversized lookup keys, and non-string keys fail closed before
caller-controlled conversion or normalization hooks can run.

```python
from verb_authority import (
    GuardedToolRunner, Param, Registry, Risk, Tool,
    TrustedChoice, TrustedResolver,
)

contacts = TrustedResolver([
    TrustedChoice(
        "Dana",
        "dana@company.com",
        "authenticated company directory: contact-17",
    ),
])

registry = Registry()
registry.add(Tool(
    "send_email",
    [Param("to", "email"), Param("body", "string")],
    fn=send_email,
    risk=Risk.WRITE,
))
runner = GuardedToolRunner(registry)

resolution = contacts.resolve(model_selected_contact)
if not resolution.resolved:
    return {"error": resolution.status.value}

tool_call = {
    "name": "send_email",
    "input": {"to": resolution.value, "body": model_generated_body},
}
execution = runner.run(
    tool_call,
    trusted_args={"to": resolution.value},
)
```

The application must populate the catalog from a genuinely trusted source;
the `evidence` string is retained for review but is not verified by Verb
Authority. The lookup key may itself be influenced by untrusted content. The
control-flow example at the top of this page is therefore an explicit product
boundary, not an inference that the request was user-authorized.

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

Named JSON reports use report format v3. For the constraints understood by
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

When Authority Diff imports a named v3 report, it recomputes summary counters
and reconciles the complete risk tuple (declaration, advisory inference,
conflict, effective tier, evidence, review, and confirmation) before comparing
it. It also checks the stable argument policy/confidence/review combinations,
preserves the scanner's declaration-verification warning, and refuses an open
schema with declared unexposed controls unless schema review remains explicit.
This catches internally impossible or partially edited reports. The
unkeyed SHA-256 fields are content commitments, not authentication: a party
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

The v3 `privacy` object makes that contract machine-readable. It replaces the
old combined `examples_or_values_included` field with
`examples_included: false`, `defaults_included: false`, and
`runtime_values_included: false`. Named reports set
`schema_material_fingerprints_included`,
`schema_material_fingerprints_dictionary_guessable`, and
`unmodeled_schema_fingerprints_included` to `true`, with
`schema_fingerprint_material_scope` set to
`full_validation_material_excluding_annotations`. Redacted reports set those
three booleans to `false` and use the scope
`modeled_presence_and_enum_count_only`.

Use `--fail-on-review` in CI to return a non-zero status when ambiguous risks,
arguments, risk conflicts, MCP annotation conflicts, or unresolved JSON Schema
composition need attention. The scanner does not resolve `$ref`, `allOf`,
`anyOf`, `oneOf`, or conditional/dependent schemas. It instead sets
`schema_review_required` on the tool and counts it in
`summary.schema_review_required_tools`, so authority-bearing properties hidden
behind those constructs cannot produce a silent clean result. The same flag is
set for required names absent from the modeled `properties` map, multi-type
unions, dynamic `patternProperties`, and ambiguous direct-shape exports whose
argument names collide with JSON Schema wrapper keywords. A schema with
dynamic property admission is not reported as closed to unknown arguments.
Direct-shape collisions preserve the arguments
in the report rather than silently replacing them with an empty list. The
structurally indistinguishable `properties` collision remains an explicit
review obligation instead of a clean empty audit. Static inference is a review
aid, not a vulnerability verdict; the scanner does not inspect tool
implementations or verify the surrounding application's authorization and
provenance wiring.

Both schema-review fields are mandatory in imported v3 reports. A report that
omits either field must be regenerated from the original schema with the
current scanner; omission is not interpreted as `false`. When Authority Diff
sees an explicit schema-review obligation change in either direction, it keeps
the change in the review queue. In particular, clearing `true` to `false` is
not treated as proof that protection increased when only report evidence is
available.

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

The public [`avp9-nexus` financial fixture](fixtures/README.md) includes a tool
schema, attributed control sidecar, and expected classification used as a
regression oracle.

## Case studies

- [External beta test: when a tool name put confirmation on the wrong
  call](docs/case-studies/external-beta-risk-evidence.md) — a public,
  independently rerun example of under-reporting, over-reporting, and the
  evidence-model redesign that followed.

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

The command also accepts two non-redacted JSON reports. Diff output format v2
is paired with scanner report format v3. Earlier report v2 omitted constraint
values and cannot be migrated without inventing evidence; rescan the original
raw schema with the v3 scanner before comparing it. When implementation
controls are part of the comparison, pass the sidecars with
`--before-controls` and `--after-controls`. Control evidence remains visibly
author-supplied; a diff does not turn a declaration into verified enforcement.
Malformed or legacy report-shaped input is rejected as a report and is never
reinterpreted as a raw tool schema.
Intermediate, unpublished v3 reports that predate the mandatory
`schema_review_required` and `summary.schema_review_required_tools` fields must
also be rescanned rather than compared under an optimistic default.
Imported v3 reports must contain at least one tool, matching the scanner's own
output boundary; a fabricated empty report is rejected with rescan guidance.
They must also preserve scanner-normalized declaration text and canonical
declaration order, and remain within the scanner's aggregate limits for tools,
arguments, enum members, effects, and bounds. A report outside those emitter
boundaries is rejected instead of being treated as a scanner-produced report.

The two CLI thresholds are independent. `--fail-on-increase` returns status 2
only for authority increases; review-only and protection increases remain
visible without tripping that flag. Add `--fail-on-review` when any ambiguous
or unmodeled change should also return status 2:

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
- uses: yairsabag/verb-authority@v0.10.0-beta.8
  with:
    before: tools-main.json
    after: tools-pr.json
```

The action fails the step on an authority increase by default. Set
`fail_on_increase: "false"` for an observation-only rollout. Starting with
beta.8, its separate `fail_on_review` input also defaults to `"true"`, so an
unmodeled or ambiguously ordered schema change fails closed instead of passing
because it is not an authority increase. Set either boolean independently:

```yaml
with:
  before: tools-main.json
  after: tools-pr.json
  fail_on_increase: "true"
  fail_on_review: "true"
```

Both inputs accept only the exact strings `"true"` or `"false"`. The beta.8
pin in the example above supports both thresholds. The action removes
`PYTHONPATH` and `PYTHONHOME` and uses Python isolated mode for both installation
and comparison, preventing modules in the consumer checkout from shadowing
`pip` or the installed Verb Authority package.

The v3 comparison orders `maximum`, `maxLength`, and enum changes. Widening or
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

The [`Tool Authority Atlas`](atlas/README.md) checks in the same analysis for a
small, source-pinned set of public MCP reference tools. It is the seed of a
community corpus, not a ranking of MCP servers.

## What the gate does

The project is one importable module with five cooperating pieces:

- **Per-parameter policies.** Sensitive sinks such as recipients, URLs,
  accounts, paths, and commands default to `trusted_fixed`; bounded values are
  type-checked; free-text bodies are treated as outbound payloads.
- **Safe-by-default inference.** Policies are inferred from the existing tool
  schema. Ambiguous parameters on consequential tools stay locked and appear in
  a one-time review queue. Authority-bearing names are evaluated before broad
  numeric or payload rules: an integer `account_id` and a string `reply_to`
  remain locked, while an ambiguous `message_id` remains locked for review.
  Payload names are token-bound rather than matched as arbitrary substrings.
  Flattened names such as `destinationurlvalue` and
  `destinationurloverride` conservatively retain the underlying URL boundary,
  with bounded parsing and `sink=False` as the explicit release valve. This is
  still a finite label heuristic, not semantic proof: unusual author-chosen
  names must declare their sink role explicitly.
- **Declared capabilities.** `Param(..., sink=True|False)` lets a tool schema
  resolve overloaded names such as `path` without relying on the heuristic.
- **Declared verb-risk tiers.** Applications declare tools as read-only, write,
  financial, destructive, or code execution. Undeclared tools remain `unknown`
  and require review plus confirmation. A complete-token name heuristic is
  reported only as caller-mutable evidence; it never establishes authority.
- **Optional provenance ledger.** Values returned by tools are recorded as
  untrusted. Exact, type-tagged JSON scalar leaves (`null`, booleans, integers,
  finite floats, and strings), every exact object key, and exact list/object
  containers (including empty or container-only values) are forced back to
  data provenance even if `trusted_args` was wired incorrectly. `True`, `1`,
  and `1.0` do not share a ledger identity.
  Containment recognizes email addresses and anchored HTTP, HTTPS, FTP, WS,
  WSS, protocol-relative, and `www.` URI forms extracted verbatim from returned
  text. NFKC normalization and recursive script detection reject a locked JSON
  string or key containing more than one of the tracked Latin, Greek, and
  Cyrillic scripts.
  Every NFKC call has a pre-normalization work ceiling. A longer non-ASCII tool
  result is still retained for exact and raw-substring taint. A bounded,
  per-code-point compatibility skeleton also preserves ASCII email and URI
  disguises without normalizing the hostile whole string, so unrelated ASCII
  destinations are not blocked merely because long Unicode appeared earlier.
  Non-ASCII destinations remain fail-closed while that full canonical index is
  incomplete; if even the bounded ASCII skeleton cannot be completed, ASCII
  destination promotion fails closed too.
  The ledger is bounded and fail-closed: capacity exhaustion saturates the
  session instead of evicting old evidence, so callers must create a fresh
  session and must not retry the tool call that already produced the result.

The gate rejects unknown tools, unknown arguments, and every omitted registered
parameter. `Param.required` remains schema metadata, not an implicit-default
execution path. URI containment is not a general URI/IDN validator, and the
mixed-script check is not a complete Unicode-confusables implementation. The
gate also does not replace complete JSON Schema validation or the tool
implementation's own authorization checks, including cross-argument and
action-instance authorization.

## Integrating a tool loop

`trusted_args` is an application provenance declaration: an argument is marked
trusted only when it equals the corresponding application-supplied value.
Everything else is data.

```python
from verb_authority import Param, ProvenanceLedger, Registry, Risk, Tool
from verb_authority import build_policy, dispatch

registry = Registry()
registry.add(
    Tool(
        "send_email",
        [Param("to", "email"), Param("subject"), Param("body")],
        risk=Risk.WRITE,
    )
)
policy = build_policy(registry)
ledger = ProvenanceLedger()

# After normalizing the model/provider tool call:
decision = dispatch(
    registry,
    policy,
    tool_call,
    trusted_args={"to": user_confirmed_email},
    ledger=ledger,
)
if not decision.allow:
    return {"error": decision.reason}
if decision.needs_confirm and not ask_user(decision.reason):
    return {"error": "user denied"}

result = run_tool(tool_call)
ledger.record_result(result)
```

This direct-dispatch example leaves confirmation-to-execution atomicity,
callable identity, result validation, and result capture to the application.
Thread one ledger through the session and record each plain JSON result
immediately after the tool returns. If `record_result` raises a capacity error,
the tool has already run: do not retry it, discard the saturated session, and
start a fresh ledger. Prefer `GuardedToolRunner` when those
operations should share the frozen runtime boundary described above. The
ledger is a containment layer, not sound taint tracking: it recognizes values
(including every exact key, exact containers, and typed scalar leaves nested
in JSON) and selected risk-shaped lexical forms, not arbitrary transformations
or control flow.

## Evidence and demos

The complete pytest suite covers policy inference, declared capabilities, verb
risk, the gate, dispatch, ledger containment, canonicalization, schema import,
report redaction, and the reproducible Atlas baseline:

```bash
python -m pytest -v
```

Additional executable evaluations are intentionally kept as small scripts:

```bash
python validate_v01.py   # 11 schemas / 31 parameters; 0 silent-unsafe outcomes
python chain_demo.py     # laundering without vs. with the ledger
python adversarial.py    # known successes and failures by attack family
python adaptive.py       # adaptive resistance depth and first observed break
python capability_demo.py
python trusted_choice_demo.py  # trusted lookup -> gate -> actual local function
```

The adaptive evaluation found a mixed-script homograph bypass in the earlier
implementation. The included current attacker holds tiers 1–6 and first breaks
at tier 7, where a Base64 value would be interpreted or decoded downstream.
That is a semantic/representation boundary rather than the original destination
string reaching the gate.
That result describes this test arsenal, not a universal security score.

`agent_demo.py` and `resolve_live.py` are optional Anthropic-backed demos and
require `ANTHROPIC_API_KEY`. The core module, tests, and offline evaluations do
not require an API key.

## Security boundary and known limitations

This project deliberately publishes its failure modes:

- **Provenance must be real.** Without a ledger, `trusted_args` is only as
  trustworthy as the application code that supplies it. Data mislabeled as
  trusted can reach a locked sink.
- **Semantic rewrites are not tracked.** The ledger matches exact values,
  contained risk-shaped strings, and canonicalized lexical variants. It cannot
  track a value the model interprets and reconstructs.
- **Approved-choice control flow is not tracked.** Untrusted content can still
  influence whether a tool runs or which already approved catalog entry is
  selected. The gate constrains the resulting value; it does not establish
  that the user's intent selected that key.
- **Integrity, not confidentiality.** The gate controls whether untrusted data
  can author sensitive arguments. It does not track secrets or stop private
  data from leaving through an otherwise authorized channel.
- **Tool calls, not model output.** Text returned to a human is not audited, so
  untrusted content can still social-engineer the user through the agent's
  reply.
- **Heuristics need review.** Undeclared parameter policies are inferred from
  names and types. Tool-name risk is only a caller-mutable review signal;
  undeclared tools stay `unknown`. Review both `PolicySet.review` and
  `PolicySet.risk_review`, declare tool risk and overloaded sink capabilities,
  and keep the registry accurate.
- **Application controls still apply.** Required arguments, authentication,
  authorization, rate limits, sandboxing, and human confirmation must still be
  enforced by the surrounding system.

Run `python adversarial.py` to see the known gaps exercised rather than hidden.
Please report new bypasses with the repository's focused issue template; keep
sensitive deployment details out of public issues and follow
[`SECURITY.md`](SECURITY.md).

## Related work and positioning

Verb Authority is a minimal, drop-in experiment inspired by Google DeepMind's
**CaMeL** (“Defeating Prompt Injections by Design,” arXiv:2503.18813,
Apache-2.0). It trades CaMeL's interpreter-level soundness for adoption in an
existing tool loop.

The closest structural approaches make different tradeoffs:

- **CaMeL** tracks taint through a custom interpreter.
- **FIDES** propagates content-level integrity and confidentiality labels
  through Agent Framework middleware and enforces policy at sensitive tools.
- **Progent** enforces a policy over tool calls; it is complementary to this
  project's value-provenance question.
- **NeuroTaint** performs semantic taint analysis offline rather than blocking
  calls at runtime.
- Detector-based guardrails classify content or intent and can be layered with
  this approach, but they provide a different kind of control.

[`LANDSCAPE.md`](LANDSCAPE.md) contains the detailed field map, citations, and
the places where this project does less than the research systems. If you need
sound transformation tracking or confidentiality enforcement, choose one of
those deeper systems rather than this module.

## Project status

v0.9.0 is the latest stable release. This source tree describes
v0.10.0-beta.8 for the local schema scanner, control evidence, Authority Diff,
Tool Authority Atlas, and runtime-integration boundary; beta.7 was withheld
and is not reused.
This remains early, research-grade work and is not described as
production-ready. See
[`CHANGELOG.md`](CHANGELOG.md) for release notes and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for focused contribution guidance.

Licensed under Apache-2.0.
