# External beta test: when a tool name put confirmation on the wrong call

An external beta tester found a failure with an unusually clear operational
consequence: a tool that committed funds did not require confirmation, while a
tool that only fetched metadata and called a model did.

This case study records the evidence, the redesign, and the independent rerun.
It is not a customer testimonial. The tester, [`avp9-nexus`](https://github.com/avp9-nexus),
provided the redacted fixture and allowed public attribution. Every technical
claim below links to the public issue, implementation, or release that supports
it.

> Editorial disclosure: the maintainer used AI assistance to structure and
> edit this write-up. The test evidence, code changes, release artifacts, and
> checksums are public and independently reproducible.

## The starting point

Verb Authority began with two separate questions:

1. **Argument authority:** which tool-call arguments may untrusted data fill?
2. **Tool risk:** what kind of effect does the tool have, and should the call
   require human confirmation?

The argument model already kept evidence and confidence visible. A bounded bid
amount could remain `constrained`; an unexposed destination could remain an
author-supplied `server_fixed` declaration; enforced and specified bounds could
stay distinct.

The risk model was weaker. In beta.4, the effective tool tier came from lexical
matching over the tool name. That made a caller-controlled label act like a
behavioral verdict.

## The external finding

The tester installed the checksummed beta.4 wheel in an isolated environment,
ran the public fixture as a positive control, and then scanned three deployed
tools: a bid tool, an evaluation tool, and a read-only chain scanner.

All three were misclassified:

| Tool behavior | Name | beta.4 result | Operational consequence |
|---|---|---|---|
| Signs and broadcasts a transaction that commits funds | `place_bid` | `write`; no confirmation | Under-reported the action and left the human gate off |
| Fetches metadata and calls a model; executes no code | evaluation-shaped name | `code_exec`; confirmation | Over-reported the action and put a gate on the wrong call |
| Reads chain state and accepts no caller arguments | neutral scanner name | `write`; no confirmation | Reported a read-only tool as state-changing |

The tester then varied one signal at a time. The same bid schema and description
changed tier when only the name changed. A financial description did not affect
the result. Parameter names such as `amountWei` and `payment` did not affect it
either. `revaluate` demonstrated that the old `eval` rule was a substring match.

That mutation set established the root cause: the risk tier rested on a mutable
label rather than evidence about the action. The full report is in the
[`beta.4` issue comment](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5379248294).

## Why this was more than a classification typo

A wrong label in a report is annoying. A wrong confirmation boundary is a
control failure.

The beta.4 direction was inverted where it mattered most:

- the call that could commit funds did not ask for confirmation;
- a call that signed nothing did ask for confirmation; and
- an operator following the report would spend human attention on the wrong
  action.

Adding more keywords would have preserved the same trust mistake. The fix had
to change which evidence was allowed to establish the effective tier.

## The beta.5 redesign

[PR #13](https://github.com/yairsabag/verb-authority/pull/13) changed the trust
boundary:

- a tool name became advisory evidence only;
- matching moved from substrings to complete snake-, kebab-, and camel-case
  tokens;
- an undeclared tool kept effective risk `unknown`, required review, and kept
  confirmation enabled;
- a version-1 control sidecar could declare a tier, evidence status, and
  concrete effects;
- effective, inferred, and declared risk remained separate in the report; and
- a declaration/name conflict could not turn confirmation off.

The complete mutation set became regression tests. The release did not parse
descriptions into a verdict or treat an author-supplied sidecar as verified
runtime behavior.

## The independent rerun

The tester recomputed the beta.5 checksums, repeated both requested passes, and
reran the complete mutation set.

The under-reporting list was empty.

Without risk declarations, all three deployed tools returned:

```text
risk: unknown
risk_source: safe_default
risk_review_required: true
needs_confirmation: true
```

With explicit declarations, the bid tool returned `financial` with
confirmation, while the evaluation tool and chain scanner returned `read_only`
without confirmation. The former name-driven inversion was gone.

The conflict control also held: declaring `transfer_funds` as `read_only`
produced a visible conflict, required review, and kept confirmation enabled.
The declaration could not disarm the gate.

The rerun found two remaining report-contract issues:

1. bare `eval` did not match even though the documentation described
   complete-token matching; and
2. a conflict displayed the declared `read_only` tier as effective even while
   the enforcement correctly behaved as untrusted.

The complete rerun is in the
[`beta.5` issue comment](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5379744620).

## The beta.6 closure

[PR #15](https://github.com/yairsabag/verb-authority/pull/15) made the display
and enforcement model agree:

- bare `eval` is a complete-token advisory `code_exec` signal;
- `evaluate`, `evaluation`, and `revaluate` remain unmatched;
- an undeclared `eval` tool still stays effective `unknown` with confirmation;
- any declaration/name conflict stays effective `unknown` until review;
- the effective source is reported as `conflict_safe_default`;
- the conflicting declaration and its evidence remain visible separately
  under `declared_risk`; and
- uncertain arguments are not auto-relaxed as if a conflicting `read_only`
  declaration had already been accepted.

The resulting conflict shape is:

```text
risk: unknown
risk_source: conflict_safe_default
risk_conflict: true
risk_review_required: true
needs_confirmation: true
```

## Before and after

| Case | Inferred evidence | Effective risk | Review | Confirmation |
|---|---|---|---|---|
| Undeclared `place_bid` in beta.4 | Name verdict | `write` | no | no |
| Undeclared `place_bid` in beta.5+ | Advisory `financial` | `unknown` | yes | yes |
| Declared bid tool | Advisory `financial` + attested effects | `financial` | no | yes |
| Declared evaluation/scanner | No matching name signal + attested effects | `read_only` | no | no |
| `transfer_funds` declared `read_only` in beta.6 | Advisory `financial` conflicts with declaration | `unknown` | yes | yes |
| Undeclared bare `eval` in beta.6 | Advisory `code_exec` | `unknown` | yes | yes |

## What the result does not prove

This test does not prove that a static scanner knows what an implementation
does. It demonstrates the opposite boundary:

- names are mutable hints, not proof;
- sidecars are author-supplied claims, not independent observation;
- the scanner does not execute the server or parse prose into behavioral truth;
- a schema only exposes arguments that are present; and
- semantic rewrites remain outside this drop-in gate's provenance boundary.

The safe result is therefore not “the scanner inferred every tool correctly.”
It is “missing or conflicting evidence could no longer silently lower the
confirmation boundary.”

## Reproduce the public control

Download the wheel, source archive, and `SHA256SUMS` from
[`v0.10.0-beta.6`](https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.6),
recompute the hashes, install the wheel in an isolated environment, and run:

```bash
verb-authority-scan fixtures/avp9_nexus_financial_tool.json \
  --controls fixtures/avp9_nexus_financial_controls.json \
  --format json \
  --output authority-report.json
```

The expected classification is pinned in
[`fixtures/avp9_nexus_expected.json`](../../fixtures/avp9_nexus_expected.json).
The release workflow rebuilds from the tag, runs the complete suite, installs
the wheel, exercises both CLIs, verifies checksums, and attaches the resulting
artifacts.

## Bring the next case

The next useful input is not another invented demo. It is one redacted tool
schema whose real behavior you already understand.

Verb Authority scans exported MCP, OpenAI, or Anthropic tool schemas locally.
It does not start the server or send the schema over the network. If the report
overstates or understates a real control, share the smallest reproducible shape
in the
[`schema clinic` discussion](https://github.com/yairsabag/verb-authority/discussions/14).

One tool schema and one honest disagreement are enough.
