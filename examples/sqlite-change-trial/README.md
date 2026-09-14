# SQLite change trial

Optional, synthetic source example. Obtain this directory from the repository
or source distribution; installing the wheel does not install this example.
This is not a production security gate or the main Verb Authority quickstart.

Compare two implementations of one small ticket-update contract. The checker
uses fictional data in fresh temporary SQLite databases, then observes what
actually changed. The supplied healthy application binds tenant and ticket in
ordinary server code. The deliberately faulty version omits the tenant condition
in its update. The checker should flag the resulting cross-tenant write.

This is an effect-checking demonstration, not proof that VA prevents that SQL
fault. The bundled application does not invoke VA's runtime argument gate.

## Requirements

- Initial trial target: macOS, Python 3.11 with sqlite3 and venv/pip.
- Linux is not validated by this trial. Native Windows is unsupported because
  worker cleanup requires POSIX process groups. Do not infer WSL support.
- A writable temporary directory and permission to manage your own child process
  group. Run only trusted synchronous application code. This is not a sandbox.
- The worker deadline is 15 seconds and SQLite lock timeout is 0.2 seconds.
  A slow or contended host may produce INCOMPLETE; do not weaken these controls
  just to obtain a pass.
- Installed `verb-authority==0.10.0b17`. The checker checks this exact version,
  including for the ordinary server-injected example. No optional extras, model,
  API key, GPU or service account are needed.

## Setup

From this example's root directory, create an isolated environment:

```sh
python3.11 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: --no-deps -r requirements.txt
.venv/bin/python -m pip check
```

The installation command contacts the package index. The comparisons below do
not require network access. If you already have the exact pinned wheel locally,
install offline by adding `--no-index --find-links /path/to/wheel-directory` to
the installation command. The wheel must match the hash in requirements.txt.

## Run the bounded acceptance check

Select the isolated interpreter explicitly:

```sh
.venv/bin/python -I -B check_acceptance.py --python .venv/bin/python
```

The script installs nothing. It checks the supported platform and exact installed
runtime, then creates fresh evidence paths and runs exactly the two comparisons
below. It independently checks the saved reports and reopens the 28 resulting
databases read-only. Successful acceptance means the healthy control passes and
the deliberately faulty control is detected; it does not mean the faulty SQL is
safe. The script prints the retained evidence directory. A prerequisite or
acceptance failure is nonzero, not a skipped success; do not automatically retry.
Use `--preflight-only` with the same `--python` argument to check prerequisites
without running applications.

This fixed example remains pinned to b17 even when the repository version moves.
Its actual acceptance is separate from the repository's pure pytest suite, which
does not establish Linux/Windows/WSL compatibility or exercise the database workers.

## The two underlying comparisons

These commands are alternatives for inspecting each comparison directly, not
additional required runs after successful acceptance.

Healthy against healthy should print PASS and exit 0:

```sh
.venv/bin/python -I -B sqlite-change-check/check_sqlite.py \
  --baseline-config sqlite-change-check/healthy.json \
  --candidate-config sqlite-change-check/healthy.json \
  --expectations sqlite-change-check/expectations.json \
  --output healthy-result.json
```

Healthy against the known faulty candidate should print REGRESSION and exit 1:

```sh
.venv/bin/python -I -B sqlite-change-check/check_sqlite.py \
  --baseline-config sqlite-change-check/healthy.json \
  --candidate-config sqlite-change-check/omit-tenant.json \
  --expectations sqlite-change-check/expectations.json \
  --output fault-result.json
```

Exit 1 is the expected result of this deliberate fault control, not a setup
failure. It should show four unexpected changes to tenant_beta/ticket_1 while
the application returns `ok`. The three denial cases should leave rows unchanged.
Each arm has seven cases; these two comparisons are not 28 different attacks.

Existing result files are never overwritten. For a later run choose new output
names. Do not automatically retry an incomplete operation or delete evidence
just to obtain a passing result.

- PASS / 0: both versions met this tested contract.
- REGRESSION / 1: a comparable working baseline and a candidate effect or
  functionality failure. Inspect the named case and expected/observed row values.
- INCOMPLETE / 2: an execution, observation, baseline, comparability or identity
  problem prevents a complete conclusion. Existing writes still appear in the
  evidence. Incomplete is not safe, success or rollback.

## Connect another implementation of this exact contract

Select trusted source files with `--baseline /absolute/old_app.py` and
`--candidate /absolute/new_app.py`. Defaults select the included subject_app.py.
Both must export `tool_schema(interface)` and
`build(sqlite_connection, trusted_config)`, returning a synchronous callable.
The supplied example supports only the literal `server_injection` interface.

The callable receives the named proposal, not bare arguments:

```json
{"name":"update_ticket","input":{"text":"Resolved: printer is working."}}
```

Its declared schema permits only required string `text` and sets
`additionalProperties` to false. Reject selector fields in the submitted input.
Trusted `config.host.tenant` and `config.host.ticket_id` come separately from
the caller's proposal. If host authority is missing, return `denied` with no
write. Otherwise use the supplied connection to the existing table
`tickets(tenant TEXT, ticket_id TEXT, text TEXT, PRIMARY KEY(tenant,ticket_id))`.
Commit a successful update before returning exactly `ok`. Exceptions must
propagate, not become a false denial. See the complete included subject_app.py.

Do not recreate the table, seed rows, read expected answers inside the app or
edit expectations to make a candidate pass. The fixture, target and seven cases
are fixed. Other tools or business contracts require separately designed tests;
this is not an arbitrary-schema scanner or a general database adapter.

## Evidence and limits

The report includes baseline/candidate paths and hashes, dependency identities,
schemas, proposals, SQL traces, errors and before/expected/observed row snapshots.
The parent reopens each database after worker completion and cleanup. Temporary
databases are retained at the location printed in the report.

Reports may include local paths and application data. Review them before sharing;
they are not automatically redacted. Nothing is uploaded by the checker.

Observations cover final fixture rows and named schema objects, not every read,
transient/rolled-back write, external service, process escaping its group, or
concurrent writer. No automated fix or rollback is provided. A team's ordinary
row assertions can detect this known fault too; no superiority, time saving,
general compatibility or production-readiness claim follows from this trial.

## Maintenance and license

The sibling `integration-change-check/comparison.py` is the single shared
classification helper for this example. Its filesystem-report compatibility
function does not include or imply a filesystem/MCP workflow here. Keep this
directory's layout intact; review source and test changes together rather than
silently replacing its helper or loosening runtime/cleanup requirements.

This example follows the repository's Apache-2.0 license. An unchanged copy of
the [license](LICENSE) is included so the terms remain with a copied directory.
The pinned dependency is installed separately, not vendored into this example.
