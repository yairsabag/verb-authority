# Synthetic payment tuple boundary

Larry Peseckis contributed the historical evidence in `frozen/` in
[PR #19](https://github.com/yairsabag/verb-authority/pull/19), at commit
`beb5ad0e01f6df0ebbbc7c35bface3137b1a49cb`. The files are preserved byte-for-byte,
including their original line endings, with the contributor's Apache-2.0
permission in `frozen/LICENSE-NOTE.txt`.

This is **external synthetic scanner evidence, not production adoption or a
runtime security test**. The maintainer regression outside `frozen/` is a
separate internal verification, not another independent external run.

## What it establishes

All four payment cases satisfy the individual types, enums and numeric bounds.
The separate business-policy oracle nevertheless allows A and D and denies B
and C: a valid account and recipient need not be an allowed combination, and a
global amount ceiling need not be the ceiling for that particular account.

Only `tools.json` and `controls.json` are supplied to the scanner. Neither the
four calls nor the relational policy is supplied to it. Consequently, a scan
must not be interpreted as authorizing those calls. The controls' descriptions
of "enforced" checks are contributor declarations, not verified enforcement.
No payment handler or `GuardedToolRunner` is invoked by this fixture.

The recorded beta.6 report classifies all four arguments as `typed_bounded`.
The beta.10 report changes `account` and `recipient` to `trusted_fixed`.
The current report-v6 regression expects all four protected, with `amount`
and `purpose` explicitly requiring review. It does not relax the current
policy to match historical results. These classifications still do not decide
the external business-policy oracle.

## Run the maintained regression

From a repository checkout with the development dependencies installed:

```sh
python -m pytest -q test_external_tuple_boundary.py
```

The maintainer-written tests pin all 18 contributed files, check the historical
reports against their recorded summaries, independently evaluate the four
fixed schema/oracle cases, and assert the current scanner's significant fields,
declaration warning, Markdown interpretation boundary and CLI review exit code.
They do not import or execute the historical runner. Automated assertions cover
these specific contracts; they are not a general detector of misleading prose.

To produce a fresh report separately, without writing into `frozen/`:

```sh
python -m verb_authority scan \
  fixtures/external/larry-peseckis/tuple-boundary/frozen/fixture/tools.json \
  --controls fixtures/external/larry-peseckis/tuple-boundary/frozen/fixture/controls.json \
  --format json --output /tmp/va-tuple-current-report.json
```

Record the checked-out commit and installed version when sharing a run. A
current report is not expected to match beta.6/beta.10 byte-for-byte. External
evidence is repository-only, omitted from wheel and source distributions; the
regression skips those checks when the bundle is absent from an sdist checkout.

## Historical reproduction limits

- The preserved `runner.py` expects the five input files beside itself, while
  the committed bundle places them in `fixture/`. Do not run it in place or
  rearrange the frozen originals to make it work.
- The beta.10 command record invokes a `run.ps1` that was not contributed.
  The included runner hard-codes a beta.6 target, while the beta.10 result
  names beta.10. The frozen commands also use normalized paths instead of the
  absolute paths emitted by the included runner. The record is therefore not a
  self-contained, unchanged, byte-for-byte reproduction of the old environment.
- Its `fixture_validation: PASS` checks fixture/oracle consistency and scan
  invocation, not all report semantics or the absence of authorization claims.
  The full reports require a separate scope assessment.
- The expected map describes itself as preregistered. These files arrived
  together in the contribution commit; this repository does not independently
  establish preregistration timing or the originally installed artifact hashes.

These limitations are retained alongside useful, internally consistent
historical results. They are not evidence of a current runtime bypass. See
[limits and boundaries](../../../../docs/limits-and-boundaries.md) for the
product's separate per-argument and application-authorization responsibilities.
