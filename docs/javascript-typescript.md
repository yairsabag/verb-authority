# JavaScript and TypeScript teams

Verb Authority's scanner is language-agnostic at its input boundary: it reads
exported JSON tool definitions. The runtime gate is currently Python-only.
There is no npm package and no JavaScript runtime enforcement in this beta.

That split lets a Node, TypeScript, or browser-oriented repository evaluate its
tool schemas today without claiming that a Python decision protects a separate
JavaScript execution path.

## What works today

- Scan exported MCP `tools/list`, OpenAI function-tool, or Anthropic tool JSON.
- Keep the schema local; the scanner has no networking code and never invokes a
  tool.
- Review which arguments require trusted application authorship.
- Compare a baseline and candidate export in CI to detect authority increases.

## What does not work today

- Importing Verb Authority into a Node or browser bundle.
- Enforcing a decision inside a JavaScript tool dispatcher.
- Treating a browser-side check as the security boundary for a server-side
  capability.
- Applying this boundary to an application that only sends prompts or messages
  and has no model-visible function/tool schema or server-side tool dispatcher;
  there is nothing for Verb Authority to scan or enforce in that path today.

Runtime enforcement belongs in trusted server code immediately before the
exact tool implementation runs. A future Node adapter must preserve that
decision-to-execution binding; translating only the scanner output is not
enough.

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

Install the published Beta 13 tag into a disposable Python environment, then
scan the JSON without changing the JavaScript application:

```bash
python -m venv .verb-authority-venv
. .verb-authority-venv/bin/activate
python -I -m pip install \
  "verb-authority @ git+https://github.com/yairsabag/verb-authority.git@v0.10.0-beta.13"
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
  - uses: yairsabag/verb-authority@v0.10.0-beta.13
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
dispatcher and you are willing to test a native runtime boundary, say so in
the issue; that is the relevant design-partner case for a future JS adapter.
