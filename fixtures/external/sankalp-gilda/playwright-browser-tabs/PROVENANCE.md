# Provenance and third-party attribution

## Contribution

Sankalp Gilda contributed the external fixture in GitHub pull request #21.
The original contribution commit, frozen JSON artifacts, manifest, and
reported rerun commands remain unchanged. The repository's tests and derived
oracle may evolve separately from those originals.

## Upstream schema source

The contributor identifies `frozen/tools-list.json` as the verbatim MCP
`tools/list` response captured on 2026-08-26 from:

- package: `@playwright/mcp@0.0.76`;
- invocation: `npx -y @playwright/mcp@0.0.76 --headless --isolated`;
- upstream project: Microsoft `playwright-mcp`;
- immutable upstream tag commit:
  `b301c372ec741289eff1cf6aab9d3bec553f31e2`;
- upstream license: Apache License 2.0.

Immutable upstream reference:
<https://github.com/microsoft/playwright-mcp/tree/b301c372ec741289eff1cf6aab9d3bec553f31e2>

The upstream npm package includes its Apache-2.0 `LICENSE` and no `NOTICE`
file. Copyright in the upstream schema descriptions remains with Microsoft
Corporation and the respective upstream contributors. No affiliation or
endorsement is implied.

## What is independently verifiable here

The captured schema has SHA-256
`1e615213d0fcc71246febecd281ce85fb11fc8cce3e8f636d9fbc255021a2c44`.
The completed `frozen/MANIFEST.sha256` freezes the schema, sidecar, and four
generated reports. On 2026-08-30, the Verb Authority maintainer independently
ran the beta.10 and beta.11 scanner sources from their immutable repository
tags against the contributed schema and sidecar. All four generated reports
matched the contributed reports byte-for-byte.

## Evidentiary limit

The contribution does not preserve the exact JSON-RPC capture transcript or
the Node.js and npm environment used to obtain `tools-list.json`. The upstream
origin, capture date, invocation, and claim that the semantic expectation was
fixed before the rerun are contributor attestations. The repository verifies
the preserved bytes and scanner reproducibility; it does not present the
completed manifest as independent proof of pre-registration chronology or of
the original capture process.
