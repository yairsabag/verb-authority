# Contributing

Focused contributions are welcome, especially:

- minimal bypass cases with a regression test;
- public tool schemas pinned to their source commit;
- redacted scanner reports that expose inference mistakes;
- documentation corrections and precise related-work citations; and
- small changes that preserve the module's drop-in API.

Participation is governed by the project
[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

For sensitive findings, follow [`SECURITY.md`](SECURITY.md) before opening a
public issue.

## Local setup

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -v
```

Run the offline evaluations when a change touches provenance, inference, or
claims made in the documentation:

```bash
python validate_v01.py
python chain_demo.py
python adversarial.py
python adaptive.py
python capability_demo.py
```

Keep pull requests narrow. Explain the security assumption being tested, add a
failing test before a behavioral fix, and report both blocks and known slips.
Do not include API keys, proprietary schemas, user data, or claims such as
“unbreakable” or “production-ready.”

## Share an inference result safely

Prefer a redacted report over the original schema:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority scan tools.json \
  --redact-names --output authority-report.md
```

The redacted report omits source metadata and replaces tool and parameter names
with report-local identifiers. Read it before posting: unusual combinations of
types and policies can still reveal context. If the schema is already public,
link to an immutable source commit instead of copying descriptions or runtime
examples.

Atlas additions must be reproducible and neutral. Preserve input types and MCP
annotations, record manual normalization, and describe results as inference
findings rather than vulnerabilities in the upstream project.

## Add a public or redacted schema fixture

Start with the smallest case that preserves the behavior. Prefer an immutable
public source URL. If the original is private, contribute only a reduced or
redacted derivative that you have the right to publish; do not imply that a
derivative is the original evidence.

Use this layout for an external evidence bundle:

```text
fixtures/external/<contributor>/<case>/
├── README.md
├── PROVENANCE.md
├── EXPECTED.json
└── frozen/
    ├── tools-list.json
    ├── controls.json          # when used
    ├── COMMANDS.md
    └── MANIFEST.sha256
```

Keep contributor-supplied originals byte-for-byte under `frozen/`. Put reduced
CI inputs, probes, and oracles outside that directory and label them as derived.
Do not rewrite a frozen artifact to make a test convenient.

`PROVENANCE.md` should record:

- contributor name and requested attribution;
- upstream project, immutable version or commit, and license;
- capture/export command and relevant environment facts;
- which expectation was fixed before which run;
- SHA-256 coverage and what the manifest does **not** prove; and
- permission to include the contributed material under this repository's
  Apache-2.0 license.

For a reduced public fixture, add a short transformation log and ensure the
reduction still fails against the affected version before it passes against the
fix. A regression must state the narrow claim it pins; it is not a general
vulnerability claim about the upstream tool.

JavaScript and TypeScript projects do not need MCP or a Python application to
contribute scanner evidence. See
[`docs/javascript-typescript.md`](docs/javascript-typescript.md) for exporting
OpenAI, Anthropic, or MCP JSON from a JS codebase. The runtime gate itself
remains Python-only in this beta.
