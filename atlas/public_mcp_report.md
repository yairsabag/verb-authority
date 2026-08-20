# Verb Authority schema report

> Local static analysis only: no server was executed and no network was used.
> Descriptions, examples, defaults, and runtime values are not included.

## Summary

| Measure | Count |
|---|---:|
| Tools | 10 |
| Parameters | 14 |
| Protected (`trusted_fixed`) | 9 |
| Data-fillable | 5 |
| Parameters requiring review | 5 |
| Tools requiring confirmation | 1 |
| Annotation conflicts | 3 |

Schema fingerprint: `1f0540357dd957e75ccff824560ddf0fb2de0107ee4a4bcff34ebbd1d3d2f3fb`
Names redacted: `no`

## Sources

| Source | Pinned URL |
|---|---|
| official-mcp-filesystem-reference | https://github.com/modelcontextprotocol/servers/blob/599dafc1054550a6eeb87a6545c1e1b03b3ca827/src/filesystem/index.ts |
| official-mcp-memory-reference | https://github.com/modelcontextprotocol/servers/blob/599dafc1054550a6eeb87a6545c1e1b03b3ca827/src/memory/index.ts |

## Findings

| Tool | Risk | Argument | Type | Required | Policy | Review | Reason |
|---|---|---|---|---|---|---|---|
| create_entities | write | entities | array | yes | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_observations | write | observations | array | yes | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_entities | destructive | entityNames | array | yes | trusted_fixed | yes | ambiguous consequential argument; review required |
| read_graph | read_only | — | — | — | — | — | no arguments |
| search_nodes | read_only | query | string | yes | typed_bounded | no | ambiguous argument auto-relaxed for read-only tool |
| open_nodes | write | names | array | yes | trusted_fixed | yes | ambiguous consequential argument; review required |
| open_nodes | write | — | — | — | — | yes | readOnlyHint=true conflicts with inferred verb risk |
| read_text_file | read_only | path | string | yes | trusted_fixed | no | authority-bearing name |
| read_text_file | read_only | tail | number | no | typed_bounded | no | typed or bounded value |
| read_text_file | read_only | head | number | no | typed_bounded | no | typed or bounded value |
| write_file | write | path | string | yes | trusted_fixed | no | authority-bearing name |
| write_file | write | content | string | yes | outbound_payload | no | outbound payload name or bounded free text |
| write_file | write | — | — | — | — | yes | destructiveHint=true conflicts with inferred verb risk |
| edit_file | write | path | string | yes | trusted_fixed | no | authority-bearing name |
| edit_file | write | edits | array | yes | trusted_fixed | yes | ambiguous consequential argument; review required |
| edit_file | write | dryRun | boolean | no | typed_bounded | no | typed or bounded value |
| edit_file | write | — | — | — | — | yes | destructiveHint=true conflicts with inferred verb risk |
| get_file_info | read_only | path | string | yes | trusted_fixed | no | authority-bearing name |

## Interpretation boundary

This report describes Verb Authority's name/type-based inference. It is not a
vulnerability verdict, does not inspect tool implementations, and does not prove
that the surrounding application supplies correct provenance or authorization.
Review every flagged argument against the real tool semantics before deployment.
