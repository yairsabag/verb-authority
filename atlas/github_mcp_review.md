# GitHub MCP corpus: first manual authority review

This note reviews the first high-confidence candidates produced by Verb
Authority over GitHub's official MCP server tool snapshots. It is a scanner
calibration exercise, not a vulnerability report about GitHub MCP Server.

## Reproducible baseline

- Upstream commit: `12d16ed05310876a1e6988701b109da63d69dd49`
- Tool snapshots: 117
- Exposed parameters: 623
- `trusted_fixed`: 597
- `outbound_payload`: 26
- Uncertain parameters requiring review: 587
- High-confidence `trusted_fixed` candidates: 10
- High-confidence `outbound_payload` candidates: 26

The large protected count is a fail-closed review queue. It is not a finding
count. In particular, the 587 uncertain locks must not be described as
confirmed controls or vulnerabilities.

## Review of every high-confidence protected candidate

| Tool | Argument | Why the lexical rule locked it | Manual review |
|---|---|---|---|
| `add_comment_to_pending_review` | `path` | complete `path` token | Context-dependent. A review agent normally selects the file it comments on. |
| `add_pull_request_review_comment` | `path` | complete `path` token | Context-dependent. A review agent normally selects the file it comments on. |
| `create_or_update_file` | `path` | complete `path` token | Context-dependent. Fixed in a narrow automation; model-selected in a coding agent. |
| `delete_file` | `path` | complete `path` token | Consequential selector, but not universally application-fixed. It needs scope and authorization evidence. |
| `get_file_blame` | `path` | complete `path` token | Usually a model-selected read query inside an already authorized repository. |
| `get_file_contents` | `path` | complete `path` token | Usually a model-selected read query inside an already authorized repository. |
| `get_repository_tree` | `path_filter` | complete `path` token | Query filter, not inherently an application-owned destination. |
| `list_commits` | `path` | complete `path` token | Query filter, not inherently an application-owned destination. |
| `list_secret_scanning_alerts` | `secret_type` | complete `secret` token | The value selects alert categories; it is not itself a secret or destination. |
| `push_files` | `files` | complete `files` token | Mixed nested payload containing both paths and contents. Whole-argument locking loses that distinction. |

None of the ten candidates supports a universal high-confidence
`trusted_fixed` conclusion from the exported schema alone. That does not prove
that every candidate should be model-authored. It proves that a deployment
profile or explicit authority declaration is required before recommending
schema projection or runtime binding.

## Product implications

1. **Do not headline the raw count.** “597 unsafe arguments” would be false.
2. **Separate confidence from fail-closed behavior.** A protected fallback is
   operationally different from a supported remediation recommendation.
3. **Make deployment context first-class.** The same schema can serve a narrow
   workflow with application-fixed selectors or an open coding agent that must
   choose them.
4. **Model nested authority.** `push_files.files[*].path` and
   `push_files.files[*].content` can need different policies even though MCP
   exposes one top-level array.
5. **Test impact separately.** A schema review identifies candidates. A safe
   local runtime experiment must still show that an unauthorized value reaches
   execution without the proposed control.

## What could become a publishable security finding

A candidate graduates only when all of the following are demonstrated:

- the application intends the argument to be application-controlled;
- untrusted content or the model can nevertheless supply or replace it;
- existing authorization, scoping, confirmation, DLP, gateway, and server-side
  checks do not already prevent the effect;
- a safe reproduction shows the tool executes with the unauthorized value;
- the proposed authority binding blocks that attempt without breaking the
  legitimate control case; and
- the affected maintainer has an opportunity to review the report before
  public disclosure.

Until then, use **authority candidate**, **design gap**, or **review mismatch**,
not **vulnerability**.
