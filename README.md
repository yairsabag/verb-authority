# Verb Authority

[![CI](https://github.com/yairsabag/verb-authority/actions/workflows/ci.yml/badge.svg)](https://github.com/yairsabag/verb-authority/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/verb-authority?include_prereleases=true)](https://pypi.org/project/verb-authority/)
[![Python 3.10–3.14](https://img.shields.io/badge/python-3.10%E2%80%933.14-3776AB.svg)](https://www.python.org/downloads/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](https://github.com/yairsabag/verb-authority/blob/main/LICENSE)

**Prevent untrusted data from authoring protected tool-call arguments.**

Consider a tool exposed to an AI agent:

~~~python
send_email(to: str, body: str)
~~~

The model may write `body`. The recipient `to` must come from trusted
application code, such as an authenticated session or an application-owned
directory. If a webpage, retrieved document, model response, or prior tool
result supplies a different recipient, the call must stop before
`send_email` runs.

**Tool schemas validate shape. They do not prove who may supply each value.**

Verb Authority scans exported tool schemas, produces a reviewable
per-argument authority map, and provides a small local runtime gate. It does
not invoke tools while scanning and does not upload schemas.

## Install beta.14

Install the dependency-free core from PyPI:

~~~bash
python -m pip install "verb-authority==0.10.0b14"
~~~

Or install the same release tag directly from GitHub:

~~~bash
python -I -m pip install "verb-authority @ git+https://github.com/yairsabag/verb-authority.git@v0.10.0-beta.14"
~~~

The dependency-free core supports Python 3.10 through 3.14. See
[installation and package-integrity details](https://github.com/yairsabag/verb-authority/blob/main/docs/runtime-gate.md#install) for
isolated-environment guidance, local checkout installation, wheel hashes, and
the optional Pydantic AI extra.

## Run the offline quickstart

~~~bash
python -I -m verb_authority quickstart
~~~

The command uses no model, network, or email service. It scans one exported
schema and routes three local calls through the runtime boundary.

Expected result excerpts:

~~~text
1) SCAN THE EXPORTED TOOL SCHEMA
   send_email.to    -> trusted_fixed
   send_email.body  -> outbound_payload

3) GATE RUNS IMMEDIATELY BEFORE EXECUTION
   BLOCKED - param 'to' is a locked sink; data may not author it
   local tool invocations=0

4) THE SCHEMA LIMIT IS ALSO ENFORCED AT RUNTIME
   body length=2001; registered maxLength=2000
   BLOCKED - param 'body' failed its type/bounds check
   local tool invocations=0

ALLOWED - within authority
local tool invocations=1
~~~

The demo implementation only increments an in-memory counter. It never sends
email. In the allowed control, the recipient value is supplied independently
by application code; the demo does not implement a human approval workflow.

## Why this boundary matters

A provider typically gives every model-visible argument the same JSON Schema
surface:

~~~json
{
  "name": "send_email",
  "inputSchema": {
    "type": "object",
    "properties": {
      "to": {"type": "string"},
      "body": {"type": "string", "maxLength": 2000}
    },
    "required": ["to", "body"]
  }
}
~~~

Both fields are strings, but they carry different authority:

| Argument | Intended author | Example policy |
|---|---|---|
| `to` | trusted application code | `trusted_fixed` |
| `body` | model or other data source | `outbound_payload` |

Verb Authority makes that distinction explicit and checks it immediately
before execution.

### Preferred remediation: keep protected arguments out of the model schema

When the application already owns the recipient, prefer exposing a smaller
tool to the model:

~~~text
# Canonical tool registered by the application
send_email(to: str, body: str)

# Conceptual model-visible interface
send_reply(body: str)
~~~

The application restores `to` from state established independently of
untrusted content; the canonical registration and implementation stay intact.
`send_reply` is a conceptual interface, not a beta.14 wrapper or alias API.

If the schema cannot change, materialize the application-owned value in the
canonical call and pass the same exact value in `trusted_args`. It verifies a
match; it never inserts or overwrites input. See the complete
[runtime contract](https://github.com/yairsabag/verb-authority/blob/main/docs/runtime-gate.md#preferred-remediation-remove-protected-arguments-from-model-view)
and the optional [projection design][schema-projection-design].

## Scan a real MCP schema

Export the `tools/list` JSON your client already receives. Then run:

~~~bash
python -I -m verb_authority scan tools.json --output authority-report.md
~~~

The scanner accepts:

- MCP `tools/list` responses;
- OpenAI function-tool definitions; and
- Anthropic tool definitions.

It keeps the schema local, never starts the MCP server, and never invokes a
tool. The report separates argument authority, review obligations, effective
risk, advisory name signals, and author-supplied control evidence.

From a repository checkout, try the frozen 23-tool Playwright MCP fixture:

~~~bash
python -I -m verb_authority scan fixtures/external/sankalp-gilda/playwright-browser-tabs/frozen/tools-list.json --format json --output authority-report.json
~~~

Use `--redact-names` before sharing a report, then still review the output.
Stable hashes and author-written evidence can remain correlatable or
dictionary-guessable. See the full
[scanner and report privacy contract](https://github.com/yairsabag/verb-authority/blob/main/docs/schema-scanner.md).

### Have one real or redacted schema?

Issue [#7: Real-schema clinic](https://github.com/yairsabag/verb-authority/issues/7)
is the main feedback path. Report one missed lock, unnecessary lock, incorrect
risk tier, or wrong confirmation decision. A small redacted fixture is enough;
do not post secrets or private deployment data.

## Put the gate before execution

`GuardedToolRunner` freezes the registered tool and policy state, calls the
gate immediately before the registered synchronous function, binds any
confirmation to the exact arguments and callable, and records successful
plain-JSON results in one session ledger.

~~~python
from verb_authority import GuardedToolRunner, Param, Registry, Risk, Tool

def send_email(to: str, body: str) -> dict:
    # Trusted application implementation.
    return {"sent": True, "to": to}

registry = Registry()
registry.add(
    Tool(
        "send_email",
        [
            Param("to", "email", sink=True),
            Param("body", "string", max_len=2000, sink=False),
        ],
        fn=send_email,
        risk=Risk.WRITE,
    )
)

runner = GuardedToolRunner(registry)

# Read independently from authenticated application state—not model content.
session_recipient = "alice@company.com"

tool_call = {
    "name": "send_email",
    "input": {
        "to": session_recipient,
        "body": "Meeting summary",
    },
}

execution = runner.run(
    tool_call,
    trusted_args={"to": session_recipient},
)
assert execution.executed, execution.decision.reason
~~~

Normalize provider-specific calls to the small
`{"name": ..., "input": ...}` shape before dispatch. Every execution route
must pass through the runner. Risk tiers that require confirmation also need a
trusted synchronous `confirm` callback. The surrounding application remains
responsible for authentication, business authorization, request freshness,
rate limits, and external-state synchronization.

Read the complete [runtime gate contract](https://github.com/yairsabag/verb-authority/blob/main/docs/runtime-gate.md) before a real
integration. It covers exact argument snapshots, confirmation binding, callable
identity, resource budgets, ledger saturation, error/no-retry behavior, trusted
catalog resolution, selector branches, and the pinned Pydantic AI adapter.

## Pydantic AI

Beta.14 includes an optional, narrowly pinned Pydantic AI adapter. It keeps
protected values out of the model-visible function or resolves model-visible
keys through an application-owned catalog before entering
`GuardedToolRunner`.

~~~bash
python -m pip install "verb-authority[pydantic]==0.10.0b14"
~~~

The adapter supports only the audited local, synchronous paths documented for
the pinned dependency versions. Unsupported remote, runtime-added, streaming,
async, realtime, and native execution paths fail closed. See
[Pydantic AI 2.35 runtime adapter](https://github.com/yairsabag/verb-authority/blob/main/docs/runtime-gate.md#pydantic-ai-235-runtime-adapter).

No JavaScript/TypeScript runtime adapter is published in beta.14. JavaScript
applications may export JSON schemas for an offline scan, but runtime
enforcement must sit in a trusted server-side boundary rather than a browser
bundle. See the [JavaScript and TypeScript evaluation path][js-ts-evaluation].

[js-ts-evaluation]: https://github.com/yairsabag/verb-authority/blob/main/docs/javascript-typescript.md
[schema-projection-design]: https://github.com/yairsabag/verb-authority/blob/main/docs/schema-projection-design.md

## Catch authority drift in CI

Compare a protected baseline schema with the candidate schema:

~~~bash
python -I -m verb_authority diff tools-main.json tools-pr.json --fail-on-increase --fail-on-review
~~~

Or use the composite GitHub Action:

~~~yaml
- uses: actions/checkout@v7
- uses: actions/setup-python@v7
  with:
    python-version: "3.12"
- uses: yairsabag/verb-authority@v0.10.0-beta.14
  with:
    before: tools-main.json
    after: tools-pr.json
    fail_on_increase: "true"
    fail_on_review: "true"
~~~

The baseline must come from a protected revision or trusted artifact, and the
candidate export must correspond to the implementation that will run. A diff
does not authenticate either input or verify implementation behavior. See the
full [Authority Diff contract](https://github.com/yairsabag/verb-authority/blob/main/docs/schema-scanner.md#catch-authority-drift-between-versions).

## Promise boundary

- The enforced claim is **per-argument provenance before execution**.
- A schema scan infers a reviewable policy; it does not prove what an
  implementation does.
- The gate does not classify prompts or prevent every prompt-injection effect.
- It is not business authorization and does not validate arbitrary
  cross-argument, transaction, tenant, sequence, or purpose rules.
- Untrusted content can still influence whether a tool is called or which
  member of an already trusted catalog is selected.
- The optional ledger recognizes exact, contained, and selected lexical forms;
  it does not track arbitrary semantic rewrites.
- The gate provides argument-integrity control, not confidentiality, secret
  tracking, or model-output filtering.
- Any execution route that bypasses the gate is outside the guarantee.
- No real incident is claimed covered without an exact replay and regression;
  see the [incident coverage matrix](https://github.com/yairsabag/verb-authority/blob/main/LANDSCAPE.md#real-incidents-and-control-coverage).

Read [Limits and boundaries](https://github.com/yairsabag/verb-authority/blob/main/docs/limits-and-boundaries.md) before using a
report or allowed decision as security evidence.

## How policy inference works

The scanner and core use conservative, reviewable defaults:

- destination-like arguments such as recipients, URLs, accounts, paths, and
  commands default to `trusted_fixed`;
- free-text payloads such as bodies may be `outbound_payload`;
- ambiguous arguments on consequential tools remain locked and require review;
- type membership, an enum, or a numeric type does not by itself grant model
  authorship;
- raw schema extensions cannot unlock an argument;
- tool names are mutable advisory signals, not proof of runtime risk; and
- undeclared or conflicting tool risk stays `unknown` and keeps confirmation
  enabled.

Trusted registration code can resolve an overloaded argument with
`Param(..., sink=True|False)`. A reviewed control sidecar can add implementation
evidence to a scan, but the scanner labels that evidence as author-supplied
rather than verified.

For exact selector branches, one trusted map can bind every value of one scalar
enum selector to risk and active arguments. That map controls applicability and
confirmation. It does not authorize the action instance or prove user intent.

See [Security model](https://github.com/yairsabag/verb-authority/blob/main/docs/security-model.md) for the complete model.

## Documentation

- [Security model](https://github.com/yairsabag/verb-authority/blob/main/docs/security-model.md)
- [Runtime gate and Pydantic AI adapter](https://github.com/yairsabag/verb-authority/blob/main/docs/runtime-gate.md)
- [JavaScript and TypeScript teams](https://github.com/yairsabag/verb-authority/blob/main/docs/javascript-typescript.md)
- [Schema scanner, control evidence, privacy, and Authority Diff](https://github.com/yairsabag/verb-authority/blob/main/docs/schema-scanner.md)
- [Limits and boundaries](https://github.com/yairsabag/verb-authority/blob/main/docs/limits-and-boundaries.md)
- [Case studies and executable evidence](https://github.com/yairsabag/verb-authority/blob/main/docs/case-studies/index.md)
- [Research/product landscape, citations, and incident coverage](https://github.com/yairsabag/verb-authority/blob/main/LANDSCAPE.md)
- [Fixture contribution layout](https://github.com/yairsabag/verb-authority/blob/main/fixtures/README.md)
- [Security reporting](https://github.com/yairsabag/verb-authority/blob/main/SECURITY.md)
- [Changelog](https://github.com/yairsabag/verb-authority/blob/main/CHANGELOG.md)

## Evidence and project status

The test suite covers inference, declared capabilities, tool risk, selector
branches, dispatch, the guarded runner, confirmation binding, ledger
containment, schema import, report redaction, Authority Diff, the Pydantic AI
adapter, packaging, and frozen external regressions.

Public case material is preserved separately from CI reductions:

- [external risk-tier case study](https://github.com/yairsabag/verb-authority/blob/main/docs/case-studies/external-beta-risk-evidence.md);
- [frozen Playwright `browser_tabs` contribution](https://github.com/yairsabag/verb-authority/blob/main/fixtures/external/sankalp-gilda/playwright-browser-tabs/README.md);
- [Tool Authority Atlas](https://github.com/yairsabag/verb-authority/blob/main/atlas/README.md),
  including a 117-tool source-pinned GitHub MCP corpus and its manual
  scanner-calibration review rather than a ranking of MCP servers; and
- [executable demos](https://github.com/yairsabag/verb-authority/blob/main/docs/case-studies/index.md#evidence-and-demos).

`v0.9.0` is the latest stable release.
`v0.10.0-beta.14` is the latest public prerelease and the first PyPI
distribution. Beta.14 makes the existing schema-to-gate behavior easier to
install, evaluate, and integrate without changing the security promise or
policy-inference behavior. It retains the beta.13 offline quickstart and frozen
external regression evidence. The beta.7, beta.8, and beta.9 identifiers were
withheld and will not be reused.
This remains early, research-grade work and is not described as
production-ready.

## Contributing

Start with one public or redacted schema fixture and one expected authority
boundary. [CONTRIBUTING.md](https://github.com/yairsabag/verb-authority/blob/main/CONTRIBUTING.md) explains the fixture format,
provenance expectations, tests, and focused contribution process.

For sensitive vulnerabilities, do not open a public issue; follow
[SECURITY.md](https://github.com/yairsabag/verb-authority/blob/main/SECURITY.md).

For real-schema product feedback, use
[Issue #7](https://github.com/yairsabag/verb-authority/issues/7).

Licensed under [Apache-2.0](https://github.com/yairsabag/verb-authority/blob/main/LICENSE).
