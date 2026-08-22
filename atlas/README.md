# Tool Authority Atlas

The Atlas is a reproducible, public-data companion to Verb Authority. It asks
one narrow question of each tool schema: which arguments can carry authority,
and which may safely be authored by untrusted agent data under the current
inference model?

The starter dataset contains ten tools manually normalized from the official
MCP memory and filesystem reference servers. Each source URL is pinned to the
exact upstream commit. Descriptions, implementations, output schemas, example
values, and runtime data are not copied into the dataset because the scanner
does not use them.

Regenerate the checked-in report locally:

```bash
python -m verb_authority scan atlas/public_mcp_schemas.json \
  --format markdown --output atlas/public_mcp_report.md
```

The report is an inference map, not a vulnerability ranking or a claim about
the upstream projects. The dataset has no implementation risk sidecar, so tool
risks remain `unknown`, name-token matches are shown only as caller-mutable
heuristics, and confirmation stays enabled. Annotation conflicts are useful
review prompts, not proof that either declaration is wrong.

## Contributing a public schema

Add only schemas that are already public and licensed for reuse. Pin the source
to a commit, preserve the declared input types and MCP annotations, remove
descriptions and examples, and state any manual normalization. Never submit
private configuration, credentials, user data, runtime values, or production
endpoints.

For a private schema, keep the original local and share only a redacted report:

```bash
python -m verb_authority scan private-tools.json \
  --redact-names --output verb-authority-report.md
```
