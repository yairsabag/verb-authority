# Contributing

Focused contributions are welcome, especially:

- minimal bypass cases with a regression test;
- public tool schemas pinned to their source commit;
- redacted scanner reports that expose inference mistakes;
- documentation corrections and precise related-work citations; and
- small changes that preserve the module's drop-in API.

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
