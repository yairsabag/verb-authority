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
| Protected (`trusted_fixed`) | 10 |
| Data-fillable | 4 |
| Parameters requiring review | 6 |
| Schemas requiring review | 5 |
| Tools requiring confirmation | 10 |
| Tool risks requiring review | 10 |
| Tool risk conflicts | 0 |
| Annotation conflicts | 8 |

Schema fingerprint: `cd706cd542612e359452daccbcf49af52274fea8ee6b59501c2e0fb2a321128f`
Names redacted: `no`

## Sources

| Source | Pinned URL |
|---|---|
| official-mcp-filesystem-reference | https://github.com/modelcontextprotocol/servers/blob/599dafc1054550a6eeb87a6545c1e1b03b3ca827/src/filesystem/index.ts |
| official-mcp-memory-reference | https://github.com/modelcontextprotocol/servers/blob/599dafc1054550a6eeb87a6545c1e1b03b3ca827/src/memory/index.ts |

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

## Findings

| Tool | Risk | Argument | Type | Required | Constraints | Policy | Review | Reason |
|---|---|---|---|---|---|---|---|---|
| create_entities | unknown | entities | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_observations | unknown | observations | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_entities | unknown | entityNames | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_entities | unknown | — | — | — | — | — | — | yes | destructiveHint=true conflicts with effective risk |
| read_graph | unknown | — | — | — | — | — | — | no arguments |
| read_graph | unknown | — | — | — | — | — | — | yes | readOnlyHint=true conflicts with effective risk |
| search_nodes | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_nodes | unknown | — | — | — | — | — | — | yes | readOnlyHint=true conflicts with effective risk |
| open_nodes | unknown | names | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| open_nodes | unknown | — | — | — | — | — | — | yes | readOnlyHint=true conflicts with effective risk |
| read_text_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| read_text_file | unknown | tail | number | no | — | typed_bounded | no | typed or bounded value |
| read_text_file | unknown | head | number | no | — | typed_bounded | no | typed or bounded value |
| read_text_file | unknown | — | — | — | — | — | — | yes | readOnlyHint=true conflicts with effective risk |
| write_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| write_file | unknown | content | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| write_file | unknown | — | — | — | — | — | — | yes | destructiveHint=true conflicts with effective risk |
| edit_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| edit_file | unknown | edits | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| edit_file | unknown | dryRun | boolean | no | — | typed_bounded | no | typed or bounded value |
| edit_file | unknown | — | — | — | — | — | — | yes | destructiveHint=true conflicts with effective risk |
| get_file_info | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| get_file_info | unknown | — | — | — | — | — | — | yes | readOnlyHint=true conflicts with effective risk |

## Interpretation boundary

This report describes Verb Authority's declared controls and review heuristics.
A tool name is caller-mutable metadata and is never treated as proof of behavior.
Without an explicit risk declaration, the effective tier remains `unknown` and
requires review and runtime confirmation. This report is not a
vulnerability verdict, does not inspect tool implementations, and does not prove
that the surrounding application supplies correct provenance or authorization.
References and composed/conditional schemas are not resolved; when present,
the report marks the tool for schema review instead of claiming complete coverage.
Review every flagged argument against the real tool semantics before deployment.
