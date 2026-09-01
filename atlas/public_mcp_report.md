# Verb Authority schema report

> Local static analysis only: no server was executed and no network was used.
> Descriptions, examples, defaults, and runtime values are not included.
> Enum members are always omitted. Non-redacted reports use stable SHA-256
> fingerprints for comparison; these are guessable for low-entropy values.
> Non-redacted reports also fingerprint full schema validation material,
> excluding annotations; those hashes are correlatable and may be guessable.
> Redacted reports omit exact constraint values and all exact schema hashes.

## Summary

| Measure | Count |
|---|---:|
| Tools | 10 |
| Parameters | 14 |
| Protected (`trusted_fixed`) | 13 |
| Data-fillable | 1 |
| Parameters requiring review | 9 |
| Tools requiring review | 10 |
| Schemas requiring review | 5 |
| Tools requiring confirmation | 10 |
| Tool risks requiring review | 10 |
| Branch risks requiring review | 0 |
| Tool risk conflicts | 0 |
| Annotation conflicts | 0 |

Schema fingerprint: `cd706cd542612e359452daccbcf49af52274fea8ee6b59501c2e0fb2a321128f`
Names redacted: `no`

## Sources

| Source | Pinned URL |
|---|---|
| official-mcp-filesystem-reference | https&#58;//github.com/modelcontextprotocol/servers/blob/599dafc1054550a6eeb8&#8204;7a6545c1e1b03b3ca827/src/filesystem/index.ts |
| official-mcp-memory-reference | https&#58;//github.com/modelcontextprotocol/servers/blob/599dafc1054550a6eeb8&#8204;7a6545c1e1b03b3ca827/src/memory/index.ts |

## Tool review summary

> Static review debt is separate from runtime confirmation.

| Tool | Review required | Arguments | Schema | Risk | Risk conflict | Annotation conflicts | Branch risk |
|---|---|---|---|---|---|---|---|
| create_entities | yes | entities | yes | yes | no | — | no |
| add_observations | yes | observations | yes | yes | no | — | no |
| delete_entities | yes | entityNames | yes | yes | no | — | no |
| read_graph | yes | — | no | yes | no | — | no |
| search_nodes | yes | query | no | yes | no | — | no |
| open_nodes | yes | names | yes | yes | no | — | no |
| read_text_file | yes | tail, head | no | yes | no | — | no |
| write_file | yes | — | no | yes | no | — | no |
| edit_file | yes | edits, dryRun | yes | yes | no | — | no |
| get_file_info | yes | — | no | yes | no | — | no |

## Tool risk evidence

| Tool | Effective risk | Source | Name heuristic | Mutability | Declared effects | Conflict | Risk review | Schema review | Confirmation |
|---|---|---|---|---|---|---|---|---|---|
| create_entities | unknown | safe_default | write via create (heuristic) | caller | — | no | yes | yes | yes |
| add_observations | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | yes | yes |
| delete_entities | unknown | safe_default | destructive via delete (heuristic) | caller | — | no | yes | yes | yes |
| read_graph | unknown | safe_default | read_only via read (heuristic) | caller | — | no | yes | no | yes |
| search_nodes | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | no | yes |
| open_nodes | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | yes | yes |
| read_text_file | unknown | safe_default | read_only via read (heuristic) | caller | — | no | yes | no | yes |
| write_file | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | no | yes |
| edit_file | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | yes | yes |
| get_file_info | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |

## MCP annotation evidence

> Tool annotations are unverified server hints, not enforcement evidence.

| Tool | Annotation | Value | State | Comparison source | Comparison value |
|---|---|---|---|---|---|
| create_entities | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_entities | destructiveHint | false | unresolved | effective_risk | unknown |
| create_entities | idempotentHint | false | unresolved | none | — |
| create_entities | openWorldHint | false | unresolved | none | — |
| add_observations | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_observations | destructiveHint | false | unresolved | effective_risk | unknown |
| add_observations | idempotentHint | false | unresolved | none | — |
| add_observations | openWorldHint | false | unresolved | none | — |
| delete_entities | readOnlyHint | false | unresolved | effective_risk | unknown |
| delete_entities | destructiveHint | true | unresolved | effective_risk | unknown |
| delete_entities | idempotentHint | true | unresolved | none | — |
| delete_entities | openWorldHint | false | unresolved | none | — |
| read_graph | readOnlyHint | true | unresolved | effective_risk | unknown |
| read_graph | destructiveHint | false | inapplicable | readOnlyHint | true |
| read_graph | idempotentHint | true | inapplicable | readOnlyHint | true |
| read_graph | openWorldHint | false | unresolved | none | — |
| search_nodes | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_nodes | destructiveHint | false | inapplicable | readOnlyHint | true |
| search_nodes | idempotentHint | true | inapplicable | readOnlyHint | true |
| search_nodes | openWorldHint | false | unresolved | none | — |
| open_nodes | readOnlyHint | true | unresolved | effective_risk | unknown |
| open_nodes | destructiveHint | false | inapplicable | readOnlyHint | true |
| open_nodes | idempotentHint | true | inapplicable | readOnlyHint | true |
| open_nodes | openWorldHint | false | unresolved | none | — |
| read_text_file | readOnlyHint | true | unresolved | effective_risk | unknown |
| read_text_file | openWorldHint | false | unresolved | none | — |
| write_file | readOnlyHint | false | unresolved | effective_risk | unknown |
| write_file | destructiveHint | true | unresolved | effective_risk | unknown |
| write_file | idempotentHint | true | unresolved | none | — |
| write_file | openWorldHint | false | unresolved | none | — |
| edit_file | readOnlyHint | false | unresolved | effective_risk | unknown |
| edit_file | destructiveHint | true | unresolved | effective_risk | unknown |
| edit_file | idempotentHint | false | unresolved | none | — |
| edit_file | openWorldHint | false | unresolved | none | — |
| get_file_info | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_file_info | openWorldHint | false | unresolved | none | — |

## Remediation guidance

> Advisory only: the report does not change a model schema, prove that
> trusted application state exists, or deploy a runtime integration.

| Tool | Argument | Status | Preferred remediation | Fallback remediation | Review reason |
|---|---|---|---|---|---|
| create_entities | entities | review_required | — | — | authority_inference_requires_review |
| add_observations | observations | review_required | — | — | authority_inference_requires_review |
| delete_entities | entityNames | review_required | — | — | authority_inference_requires_review |
| search_nodes | query | review_required | — | — | authority_inference_requires_review |
| open_nodes | names | review_required | — | — | authority_inference_requires_review |
| read_text_file | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| read_text_file | tail | review_required | — | — | authority_inference_requires_review |
| read_text_file | head | review_required | — | — | authority_inference_requires_review |
| write_file | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| edit_file | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| edit_file | edits | review_required | — | — | authority_inference_requires_review |
| edit_file | dryRun | review_required | — | — | authority_inference_requires_review |
| get_file_info | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |

## Findings

| Tool | Risk | Argument | Type | Required | Constraints | Policy | Review | Reason |
|---|---|---|---|---|---|---|---|---|
| create_entities | unknown | entities | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_observations | unknown | observations | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_entities | unknown | entityNames | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| read_graph | unknown | — | — | — | — | — | — | no arguments |
| search_nodes | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| open_nodes | unknown | names | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| read_text_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| read_text_file | unknown | tail | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| read_text_file | unknown | head | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| write_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| write_file | unknown | content | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| edit_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| edit_file | unknown | edits | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| edit_file | unknown | dryRun | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_info | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |

## Interpretation boundary

This report describes Verb Authority's declared controls and review heuristics.
A tool name is caller-mutable metadata and is never treated as proof of behavior.
Without an explicit risk declaration, the effective tier remains `unknown` and
requires review and runtime confirmation. This report is not a
vulnerability verdict, does not inspect tool implementations, and does not prove
that the surrounding application supplies correct provenance or authorization.
Remediation guidance is advisory and never rewrites a model-visible schema,
discovers a trusted value source, or changes runtime registration. A protected
argument whose authority is uncertain must be reviewed before choosing a fix.
References and composed/conditional schemas are not resolved; when present,
the report marks the tool for schema review instead of claiming complete coverage.
Review every flagged argument against the real tool semantics before deployment.
