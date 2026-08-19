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
production readiness. The next evidence milestone is to replace or supplement
these representative cases with contributed, sanitized schemas and to express
compatible scenarios in AgentDojo where practical.

## v0.9.0 baseline

| Measure | Result |
|---|---:|
| Schemas / categories | 12 / 10 |
| Policy matches | 30 / 34 |
| Policy false allows | 2 |
| Policy false blocks | 2 |
| Call-decision matches | 15 / 18 |
| Call false allows | 2 |
| Call false blocks | 1 |

The two security-relevant misses are an untrusted SQL query inferred as an
outbound payload and an untrusted payment amount inferred as merely
type-bounded. Both calls still request confirmation because their verbs are
high risk, but confirmation is not the same guarantee as preventing untrusted
data from authoring the argument. The retained false block is a calendar title
that the reviewer marked as data-fillable but the conservative inference keeps
locked. These are proposed v0.10.0 evidence targets, not silently corrected
v0.9.0 behavior.
