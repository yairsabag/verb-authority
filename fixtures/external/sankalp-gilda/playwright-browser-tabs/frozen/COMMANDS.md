# Commands, as run

Both arms take the same two inputs from this directory and differ only in
whether `--controls` is passed. Nothing else changes between them, and nothing
changed between the 0.10.0b10 run and the 0.10.0b11 run except the installed
package.

The scanner was installed from the tag rather than from a working tree, and the
version was read back from package metadata rather than from `pyproject.toml`:

```
git -C <clone> archive v0.10.0-beta.11 | tar -x -C <build-dir>
uv venv <build-dir>/.venv
uv pip install --python <build-dir>/.venv/bin/python <build-dir>
<build-dir>/.venv/bin/python -c "import importlib.metadata as m; print(m.version('verb-authority'))"
```

That last line printed `0.10.0b11` for the run recorded here, and `0.10.0b10`
for the earlier one.

## Arm 1, nothing declared

```
python -m verb_authority_scan \
  --format json \
  --output report-0.10.0b11-undeclared.json \
  tools-list.json
```

## Arm 2, the tool declared a write

```
python -m verb_authority_scan \
  --format json \
  --controls controls.json \
  --output report-0.10.0b11-declared-write.json \
  tools-list.json
```

## The exit-status check

Run separately, because it writes no report and its result is the exit status:

```
python -m verb_authority_scan \
  --format json \
  --controls controls.json \
  --fail-on-review \
  --output /dev/null \
  tools-list.json
```

On 0.10.0b11 this exits `2`. That is the part that makes the argument-level
review reach a CI consumer, and it is checked rather than assumed, because
`schema_review_required` on the tool is `false` in the same report.

## What was deliberately left out

No branch declaration was added for `browser_tabs`, even though 0.10.0b11
introduces one and the tool is the obvious candidate for it. Adding it would
have changed a semantic input between the two versions and the comparison would
no longer isolate the release.

## Verifying the inputs before a rerun

```
sha256sum -c MANIFEST.sha256
```

`tools-list.json` hashes to `1e615213d0fcc71246febecd281ce85fb11fc8cce3e8f636d9fbc255021a2c44`,
which is the value recorded when it was captured over stdio from
`@playwright/mcp@0.0.76` on 2026-08-26, before either run.
