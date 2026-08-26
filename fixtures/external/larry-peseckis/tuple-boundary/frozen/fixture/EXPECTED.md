# Pre-registered expected result

## Question under test

Does Verb Authority stop its conformance/evidence claim at **per-argument authority**, or can a reader reasonably interpret the report as establishing **cross-argument / action-instance authorization**?

This fixture is deliberately **not** a test of whether Verb Authority denies the bad tuples. Yair Sabag has stated that cross-argument authorization is outside the current boundary. A denied tuple passing all per-argument checks is therefore expected behavior, not a bypass.

## Fixed application rule

The authoritative tuple-level policy for this fixture lives only in `policy.json` and is **not** supplied to Verb Authority:

- **R1:** `ops-account` may pay `vendor-alpha` up to `10000` for `software-license`.
- **R2:** `project-account` may pay `vendor-beta` up to `5000` for `travel`.

`tools.json` and `controls.json` intentionally contain only the individually admissible vocabulary / per-argument controls. They do not encode R1 or R2.

## Pre-registered cases

| Case | Account | Recipient | Amount | Purpose | External action-instance oracle |
|---|---|---:|---:|---|---|
| A | ops-account | vendor-alpha | 7500 | software-license | ALLOW (R1) |
| B | ops-account | vendor-beta | 7500 | software-license | DENY |
| C | project-account | vendor-beta | 7500 | travel | DENY |
| D | project-account | vendor-beta | 4000 | travel | ALLOW (R2) |

Every value above is individually admitted by the schema/local constraint vocabulary. The authorization difference is relational.

## PASS condition

A PASS candidate has all of these properties:

1. Verb Authority reports the schema/control evidence at the per-argument level.
2. The report does **not** assert that satisfying those per-argument controls establishes the authorization of a concrete action instance or tuple.
3. The external oracle independently produces A=ALLOW, B=DENY, C=DENY, D=ALLOW.
4. The denied tuples do not require any individually invalid argument to become denied.

The expected conclusion is:

> Both allowed and denied tuples can satisfy the same per-argument authority surface. Tuple/action-instance authorization remains **NOT ESTABLISHED** by this test and must be enforced elsewhere.

## FAIL condition

This boundary test fails if the generated evidence/report makes a stronger claim than the mechanism supports—for example, if it represents satisfaction of the per-argument controls as evidence that a denied tuple is authorized as a whole.

A scanner error, `unknown`, or review-required result caused by a malformed fixture is **not** a boundary failure; fix the fixture and rerun.

## Important interpretation note

Verb Authority's schema scanner is static. It does not consume `cases.json` as runtime tool calls. `runner.py` therefore does two separate things:

1. runs Verb Authority against `tools.json` + `controls.json`; and
2. evaluates A-D against the independent relational oracle in `policy.json`.

The useful observation is the difference in **claim scope**, not whether the static scanner somehow produces four runtime authorization decisions.
