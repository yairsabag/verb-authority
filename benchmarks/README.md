# Offline schema corpus

This corpus measures two separate things:

1. whether the policy inferred from a sanitized representative tool schema
   matches the policy a reviewer recorded for that schema; and
2. whether mixed-trust calls produce the desired allow, block, or confirmation
   decision.

It deliberately retains misses. A benchmark containing only cases the current
implementation passes would not help decide where the boundary needs work.

Run it without an API key or network access:

```bash
python -m benchmarks.run_schema_corpus
```

Use `--json` for machine-readable results. The corpus is small and curated; it
is not an AgentDojo result, a universal security score, or evidence of
production readiness. The adjacent `atlas/` dataset starts replacing
representative cases with source-pinned public MCP schemas, while the local
scanner lets users report classification errors without sharing the original
schema. The next evidence milestones are to expand that public corpus, obtain
reviewed redacted reports, and express compatible scenarios in AgentDojo where
practical.

The [`agentdojo/`](agentdojo/) exercise is the first source-pinned half-step:
it exports and scans all four public AgentDojo tool suites without running an
agent or claiming an attack benchmark result.

## Current development baseline after primitive-authority tightening

| Measure | Result |
|---|---:|
| Schemas / categories | 12 / 10 |
| Policy matches | 26 / 34 |
| Policy false allows | 0 |
| Policy false blocks | 8 |
| Call-decision matches | 12 / 18 |
| Call false allows | 0 |
| Call false blocks | 6 |

The desired corpus labels were deliberately left unchanged. The stricter rule
that primitive type membership alone does not establish data authorship removes
the former payment-amount false allow: undeclared enums, numbers, and booleans
on consequential tools now remain locked for review. Rejecting raw string
length as authority evidence also closes the untrusted SQL-query false allow.
The current corpus therefore contains no policy or call false allows.

That result has an explicit usability cost rather than a
silently improved score. The conservative false-block set grows to eight policy
cases and six calls, including operation selectors, primitive values, and
ambiguously named strings whose intended data authorship cannot be established
from representation alone. Applications can release a reviewed value through trusted control-plane
configuration; the benchmark does not add `sink=False` merely to make the
current implementation match. Exact one-selector branch risk now covers a
reviewed polymorphic-tool shape, but it does not change these corpus truth
labels or silently infer authorability from a schema. The retained mismatches
remain evidence for broader integration work, not mislabeled successes.
