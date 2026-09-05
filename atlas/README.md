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
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority scan atlas/public_mcp_schemas.json \
  --format markdown --output atlas/public_mcp_report.md
```

The report is an inference map, not a vulnerability ranking or a claim about
the upstream projects. The dataset has no implementation risk sidecar, so tool
risks remain `unknown`, name-token matches are shown only as caller-mutable
heuristics, and confirmation stays enabled. Annotation conflicts are useful
review prompts, not proof that either declaration is wrong.

## GitHub MCP corpus

[`github_mcp_schemas.json`](github_mcp_schemas.json) expands the same exercise
to all 117 JSON tool snapshots checked into GitHub's official MCP server at the
pinned upstream commit. The mechanically generated
[`github_mcp_report.md`](github_mcp_report.md) covers 623 exposed parameters.
It is a candidate-discovery corpus, not a labeled authority oracle.

The first run is intentionally uncomfortable: 597 parameters stay protected,
but 587 of those are uncertain and require review. Only ten protected
parameters receive high-confidence lexical treatment. The accompanying
[`manual review`](github_mcp_review.md) finds that every one of those ten still
depends on deployment context. A `path` may be application-fixed in a narrow
automation and legitimately model-selected in a coding agent. The schema alone
does not decide between those designs.

That result is evidence about the scanner as well as the input. Do not report
597 vulnerabilities, or even 597 confirmed unsafe arguments. Use the corpus to
reduce unjustified confidence, design explicit authority manifests, and select
runtime cases for a separate impact test.

Rebuild the source document from a pinned checkout without building or running
the upstream server:

```bash
git clone https://github.com/github/github-mcp-server.git
git -C github-mcp-server checkout 12d16ed05310876a1e6988701b109da63d69dd49

python scripts/build_github_mcp_corpus.py \
  github-mcp-server/pkg/github/__toolsnaps__ \
  --output atlas/github_mcp_schemas.json

python verb_authority_scan.py atlas/github_mcp_schemas.json \
  --format markdown --output atlas/github_mcp_report.md
```

The upstream snapshots and extracted schemas are MIT licensed. The generated
corpus preserves the exact upstream URL, commit, and a deterministic manifest
hash over the 117 source snapshot files.

## Contributing a public schema

Add only schemas that are already public and licensed for reuse. Pin the source
to a commit, preserve the declared input types and MCP annotations, remove
descriptions and examples, and state any manual normalization. Never submit
private configuration, credentials, user data, runtime values, or production
endpoints.

For a private schema, keep the original local and share only a redacted report:

```bash
env -u PYTHONPATH -u PYTHONHOME python -I -m verb_authority scan private-tools.json \
  --redact-names --output verb-authority-report.md
```
