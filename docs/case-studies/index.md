# Case studies and executable evidence

External evidence is kept separate from derived regression fixtures. A case
study records what a test established and, just as importantly, what it did not
establish.

## Case studies

- [External beta test: when a tool name put confirmation on the wrong
  call](external-beta-risk-evidence.md) — a public,
  independently rerun example of under-reporting, over-reporting, and the
  evidence-model redesign that followed.

- [External Playwright `browser_tabs` fixture](../../fixtures/external/sankalp-gilda/playwright-browser-tabs/README.md)
  — frozen two-arm evidence for argument-authority and MCP annotation findings,
  kept separately from reduced regression material.

- [Assisted external composition: Verb Authority and
  SpendShield](spendshield-assisted-composition.md) — a source-pinned,
  co-designed integration exercising seven pre-dispatch cases and separate
  source-bound grant checks. It is not a production-deployment or
  customer-adoption claim.

## Evidence and demos

The complete pytest suite covers policy inference, declared capabilities, verb
risk, the gate, dispatch, ledger containment, canonicalization, schema import,
report redaction, and the reproducible Atlas baseline:

```bash
python -m pytest -v
```

Additional executable evaluations are intentionally kept as small scripts:

```bash
python -I -m verb_authority quickstart  # schema -> report -> blocked call
python validate_v01.py   # 11 schemas / 31 parameters; 0 silent-unsafe outcomes
python chain_demo.py     # laundering without vs. with the ledger
python adversarial.py    # known successes and failures by attack family
python adaptive.py       # adaptive resistance depth and first observed break
python capability_demo.py
python trusted_choice_demo.py  # trusted lookup -> gate -> actual local function
python pydantic_ai_demo.py     # optional extra; offline 6-case runtime evaluation
```

The adaptive evaluation found a mixed-script homograph bypass in the earlier
implementation. The included current attacker holds tiers 1–6 and first breaks
at tier 7, where a Base64 value would be interpreted or decoded downstream.
That is a semantic/representation boundary rather than the original destination
string reaching the gate.
That result describes this test arsenal, not a universal security score.

`pydantic_ai_demo.py` requires the `pydantic` extra but uses Pydantic's local
`FunctionModel`; it performs no network request and needs no API key.
`agent_demo.py` and `resolve_live.py` are optional Anthropic-backed demos and
require `ANTHROPIC_API_KEY`. The core module, tests, and other offline
evaluations do not require an API key.

## Submit a real or redacted schema

Issue [#7](https://github.com/yairsabag/verb-authority/issues/7) is the public
schema clinic. A single MCP, OpenAI, or Anthropic schema plus the expected
authority boundary is enough to report a missed lock, unnecessary lock,
incorrect risk tier, or wrong confirmation decision.
