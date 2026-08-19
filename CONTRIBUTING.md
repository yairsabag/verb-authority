# Contributing

Focused contributions are welcome, especially:

- minimal bypass cases with a regression test;
- sanitized, real tool schemas that expose inference mistakes;
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
