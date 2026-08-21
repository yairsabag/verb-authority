# Public regression fixtures

## `avp9_nexus_financial_*`

This fixture is adapted, with attribution permission, from the deployment case
shared by [`avp9-nexus` in issue #7](https://github.com/yairsabag/verb-authority/issues/7#issuecomment-5360058740).
The original tool name and deployment identifiers were not disclosed, so the
fixture uses the local name `purchase_bid`.

- `avp9_nexus_financial_tool.json` is the caller-visible tool schema.
- `avp9_nexus_financial_controls.json` records out-of-schema control evidence.
- `avp9_nexus_expected.json` is the regression oracle.

`bidWei` is intentionally a positive control: it must remain `constrained`, not
be collapsed into either `locked` or `free`. `destination` is deliberately
absent from the caller-visible schema and its evidence must remain `declared`.

The sidecar records supplied evidence. It does not claim that Verb Authority
independently observed or verified the deployed controls.
