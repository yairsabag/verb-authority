# AgentDojo static schema scan

This is a source-pinned **scanner exercise**, not an AgentDojo security score.
No agent, task, environment, or tool implementation was run. Verb Authority
scanned the JSON Schemas that AgentDojo itself derives from its public Python
tool definitions.

## Source and method

- Repository: <https://github.com/ethz-spylab/agentdojo>
- Commit: `089ed468cf3ed0322acc66b0211f26d9d90dbf60`
- Benchmark version represented by the checkout: `v1.2.2`
- Suites: workspace, travel, banking, and Slack
- Total suite tool exposures: 74 (69 unique names)
- Total exposed parameters: 118

The suites are exported and scanned separately because five tool names are
shared between suites. The exporter reads each official `TOOLS` list, imports
only its tool-definition modules, and calls AgentDojo's own `make_function`
schema builder. It neither imports task environments nor invokes a tool.

```bash
git clone https://github.com/ethz-spylab/agentdojo.git
git -C agentdojo checkout 089ed468cf3ed0322acc66b0211f26d9d90dbf60

python -m benchmarks.export_agentdojo_schemas agentdojo \
  --output-dir /tmp/agentdojo-schemas

for suite in workspace travel banking slack; do
  env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority scan "/tmp/agentdojo-schemas/${suite}.json" \
    --format json --output "/tmp/${suite}-authority-report.json"
done
```

The export step requires AgentDojo's schema-generation dependencies to be
available. They are benchmark-only dependencies and are not added to Verb
Authority's zero-dependency runtime package.

## Observed scanner results

| Suite | Tools | Parameters | Protected | Data-fillable | Parameter review | Risk review | Fingerprint |
|---|---:|---:|---:|---:|---:|---:|---|
| workspace | 24 | 37 | 33 | 4 | 32 | 24 | `da99e34b5f7a724516d5bdf1a8ee38dfdbb9a9d7f0f5aa0a7dfa1ce1274a6a77` |
| travel | 28 | 44 | 42 | 2 | 41 | 28 | `247fc70595af7cbb1d6ff3b0259afc5ba3ca742e9be04711c3812ae933f59ec6` |
| banking | 11 | 22 | 17 | 5 | 12 | 11 | `67ae1104cc91153a9b7e12b291de89f2f967482468525c96824673ccaaca8382` |
| Slack | 11 | 15 | 12 | 3 | 9 | 11 | `dcc21e60fda12aa6bc5f6d6a80e8cf42327d6dcb2e321d15c5d2f2ab67074cc5` |

All 74 suite tool exposures retain effective risk `unknown` and confirmation.
That is expected: these public schemas do not include Verb Authority control
sidecars, and a mutable tool name is only advisory evidence. Supplying a
source-pinned schema does not prove its runtime effects.

The scan immediately identified concrete high-confidence protected arguments:

- email and bank recipients;
- Slack direct-message recipients;
- webpage URLs;
- a banking file path; and
- a password update value.

It also produced the manual-review queue needed before deeper AgentDojo
integration: contact and calendar participants, Slack users/channels, booking
choices, file identifiers, financial subjects/dates, and profile fields. These
are not all one policy type. Contacts and booking inventory are candidates for
trusted-choice resolution; file paths and endpoints need future constrained
prefix/pattern enforcement rather than the resolver.

## What this evidence does not establish

This run does not measure attack success, task utility, runtime provenance,
human-confirmation behavior, or whether the inferred locks are correct. It is
a reproducible foreign-schema input that exposes where author declarations and
runtime integration evidence are still required. A full AgentDojo evaluation
comes after trusted-choice wiring can be expressed in compatible tasks.
