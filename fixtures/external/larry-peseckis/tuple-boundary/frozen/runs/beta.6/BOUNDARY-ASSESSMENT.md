# Boundary assessment

## Fixture/oracle result

| Case | Local schema | External oracle | Expected | Match |
|---|---|---|---|---|
| A | PASS | ALLOW | ALLOW | YES |
| B | PASS | DENY | DENY | YES |
| C | PASS | DENY | DENY | YES |
| D | PASS | ALLOW | ALLOW | YES |

All cases are intentionally composed only from individually admissible values.

## Verb Authority scan

- Scanner exit code: `0`
- Tool found: `True`
- Effective risk: `financial`
- Risk source: `control_declaration`
- Confirmation required: `True`
- Tuple/action-instance authorization-like keys observed: `[]`

Declared per-argument authority:

- `account`: authority=`constrained`, evidence=`declared`
- `recipient`: authority=`constrained`, evidence=`declared`
- `amount`: authority=`constrained`, evidence=`declared`
- `purpose`: authority=`constrained`, evidence=`declared`

## Interpretation

The static Verb Authority scan and the external tuple oracle answer different questions.
A denied tuple satisfying the per-argument surface is expected under the stated boundary.

The review question is:

> Does the generated Verb Authority evidence stop exactly at per-argument authority, without implying that the concrete tuple/action instance is authorized?

See `EXPECTED.md` for the pre-registered PASS/FAIL conditions.
