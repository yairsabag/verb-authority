# Public regression fixtures

## `avp9_nexus_financial_*`

This fixture is adapted, with attribution permission, from the deployment case
shared by [`avp9-nexus` in issue #7](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5360058740).
The original tool name and deployment identifiers were not disclosed, so the
fixture uses the local name `purchase_bid`.

In a later [deployment-status correction](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5378944333),
`avp9-nexus` clarified that the server per-call ceiling and platform per-cycle
budget are enforced today, while the two contract-level bounds are specified
in an undeployed contract revision. The fixture keeps the full ordered chain
and records that distinction per bound.

- `avp9_nexus_financial_tool.json` is the caller-visible tool schema.
- `avp9_nexus_financial_controls.json` records out-of-schema control evidence.
- `avp9_nexus_expected.json` is the regression oracle.

`bidWei` is intentionally a positive control: it must remain `constrained`, not
be collapsed into either `locked` or `free`. `destination` is deliberately
absent from the caller-visible schema and its evidence must remain `declared`.
The first two `bidWei` bounds must remain `enforced`; the last two must remain
`specified`, including the only immutable bound.

The sidecar also attests that the tool signs and broadcasts an on-chain
transaction which commits funds. That risk declaration, rather than the local
`purchase_bid` label, establishes the effective `financial` tier. The expected
report separately pins the name heuristic, declaration evidence, conflict
status, and confirmation requirement.

The sidecar records supplied evidence. It does not claim that Verb Authority
independently observed or verified the deployed controls.

## External fixture layout

External contributions keep frozen evidence separate from the smaller inputs
used by CI:

```text
fixtures/external/<contributor>/<case>/
├── README.md                  # narrow claim and reproduction summary
├── PROVENANCE.md              # source, license, attribution, evidence limits
├── EXPECTED.json              # derived regression oracle
├── probe-controls.json        # optional derived probes
└── frozen/                    # contributor-supplied, never rewritten
    ├── tools-list.json
    ├── controls.json          # when used
    ├── reports-*.json         # when contributed
    ├── COMMANDS.md
    └── MANIFEST.sha256
```

The manifest freezes the files it names. It does not by itself prove when an
expectation was registered, how an upstream capture was produced, or that a
control declaration matches a live deployment. Record those as attestations
and preserve the distinction in `PROVENANCE.md`.

See the
[`playwright-browser-tabs`](external/sankalp-gilda/playwright-browser-tabs/README.md)
case for the current two-arm, multi-version example. Contribution and redaction
requirements are documented in [`CONTRIBUTING.md`](../CONTRIBUTING.md).
