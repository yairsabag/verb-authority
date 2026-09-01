# JavaScript and TypeScript teams

Verb Authority's scanner is language-agnostic at its input boundary: it reads
exported JSON tool definitions. The supported Beta 14 runtime gate is Python.
There is no npm package in this beta. An unpublished, source-only TypeScript
prototype now provides a narrow server-side runtime boundary for external
evaluation; it is not production-ready and does not infer policy from schemas.

That split lets a Node, TypeScript, or browser-oriented repository evaluate its
tool schemas today without claiming that a Python decision protects a separate
JavaScript execution path.

## What works today

- Scan exported MCP `tools/list`, OpenAI function-tool, or Anthropic tool JSON.
- Keep the schema local; the scanner has no networking code and never invokes a
  tool.
- Review which arguments require trusted application authorship.
- Compare a baseline and candidate export in CI to detect authority increases.
- Evaluate the experimental server-side TypeScript gate directly from this
  repository, with explicit trusted registration in application code.

## What does not work today

- Installing a supported Verb Authority package from npm.
- Turning scanner output directly into trusted TypeScript runtime policy.
- Enforcing this boundary in a browser bundle.
- Treating a browser-side check as the security boundary for a server-side
  capability.
- Applying this boundary to an application that only sends prompts or messages
  and has no model-visible function/tool schema or server-side tool dispatcher;
  there is nothing for Verb Authority to scan or enforce in that path today.

Runtime enforcement belongs in trusted server code immediately before the
exact tool implementation runs. The experimental prototype preserves that
decision-to-execution binding by privately capturing each registered handler;
translating only scanner output is not enough.

## Experimental server-side TypeScript gate

The source prototype lives in
[`packages/node/`](https://github.com/yairsabag/verb-authority/tree/main/packages/node).
It is intentionally absent from the Python wheel and sdist, so a repository
checkout is required. It has no runtime dependencies and requires Node.js 22
or newer. Clone the repository, then run:

```bash
cd packages/node
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run quickstart
```

The offline quickstart demonstrates three cases against a local in-memory
handler:

- an untrusted recipient is blocked with zero handler invocations;
- a registered length bound is enforced with zero invocations; and
- the application-supplied exact recipient is allowed with one invocation.

The prototype requires a trusted server module to register each tool's risk,
argument authority, type, enum, and bounds explicitly. A call is routed through
`runner.run(...)` immediately before the privately captured handler. Protected
`trusted_fixed` values must match `trustedArgs` exactly; elevated risks require
confirmation tied to the exact frozen call.

This is deliberately smaller than Python's `GuardedToolRunner`. It has no
schema inference, result-provenance ledger, selector branches, catalog
resolver, framework adapter, browser support, streaming, or reusable approval
tokens. It does not provide business authorization or complete prompt-
injection protection. Read the prototype's
[complete contract and example](https://github.com/yairsabag/verb-authority/blob/main/packages/node/README.md)
before testing it in a real dispatcher.

## Two-minute schema scan

No MCP server is required. Save the exact tool definitions already sent to the
model as `tools.json`. For example, an OpenAI function-tool export can look
like this:

```json
[
  {
    "type": "function",
    "function": {
      "name": "send_email",
      "description": "Send a message",
      "parameters": {
        "type": "object",
        "properties": {
          "to": {"type": "string", "format": "email"},
          "body": {"type": "string", "maxLength": 2000}
        },
        "required": ["to", "body"],
        "additionalProperties": false
      }
    }
  }
]
```

Install Beta 14 into a disposable Python environment, then scan the JSON
without changing the JavaScript application:

```bash
python -m venv .verb-authority-venv
. .verb-authority-venv/bin/activate
python -m pip install "verb-authority==0.10.0b14"
env -u PYTHONPATH -u PYTHONHOME \
  python -I -m verb_authority scan tools.json --output authority-report.md
```

Windows users can activate the virtual environment with
`.verb-authority-venv\\Scripts\\activate` and run the module without the
POSIX-only `env -u ...` prefix.

The report is a review aid. It does not prove that a JavaScript application
routes calls through a runtime gate, and it does not inspect the tool
implementation.

## Export without changing the schema

Write the same array or envelope supplied to the model. Do not simplify it for
the scanner: aliases, required fields, enums, bounds, and MCP annotations are
part of the evidence.

```js
import { writeFileSync } from "node:fs";

// `tools` is the exact JSON-serializable definition array supplied to the LLM.
writeFileSync("tools.json", JSON.stringify(tools, null, 2));
```

Supported top-level forms include:

- an array of MCP, OpenAI, or Anthropic tool definitions;
- `{ "tools": [...] }` or an MCP `{ "result": { "tools": [...] } }`;
- OpenAI `{ "functions": [...] }`; and
- one direct function-tool object.

One input must use one unambiguous dialect. Competing schema aliases fail
closed instead of being guessed.

## Pull-request authority diff

Commit or generate a trusted baseline export separately from the proposed
export. The repository's composite action rescans both raw JSON inputs; it does
not trust a checked-in report:

```yaml
permissions:
  contents: read

steps:
  - uses: actions/checkout@v4
  - uses: actions/setup-python@v5
    with:
      python-version: "3.12"
  - uses: yairsabag/verb-authority@v0.10.0-beta.14
    with:
      before: security/tool-schemas/main.json
      after: security/tool-schemas/pr.json
      fail_on_increase: "true"
      fail_on_review: "true"
```

Pin third-party actions to immutable commits in a production workflow. The
version tags above keep the example readable; the project's own CI uses commit
pins.

## Give one useful result

Open [Issue #7](https://github.com/yairsabag/verb-authority/issues/7) with a
public schema link or a reviewed, redacted report when the scanner:

- misses an argument that should require trusted authorship;
- locks an argument the model must be allowed to author;
- assigns the wrong risk or confirmation behavior; or
- reports an annotation or schema-review obligation incorrectly.

Do not post private schemas, credentials, customer data, runtime values, or
production endpoints. If a Node/TypeScript service has a real server-side tool
dispatcher, report whether the source prototype missed a lock, added an
unnecessary lock, chose the wrong confirmation boundary, or could be bypassed
before the handler. That is the relevant design-partner evidence before any
npm package is considered.
