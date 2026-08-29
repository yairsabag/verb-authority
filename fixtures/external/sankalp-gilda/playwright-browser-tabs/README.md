# playwright-browser-tabs

An external two-arm regression case, contributed by Sankalp Gilda.

It pins the two behaviours that changed in `0.10.0b11` so a later release
cannot widen the claim back over them without CI noticing.

## What it holds

`frozen/` is the evidence, byte-for-byte, and nothing in it is derived or
reduced. It carries the verbatim `tools/list` from `@playwright/mcp@0.0.76`,
the control sidecar, all four run reports across two releases, a SHA-256
manifest over every one of those files, and the exact commands. Reruns go
through `COMMANDS.md`; nothing there is a reconstruction.

Everything outside `frozen/` is for CI and may be rewritten freely.
`EXPECTED.json` is the oracle, `probe-controls-destructive.json` is a third
input used by one probe, and the assertions live in
`test_schema_scan.py::test_playwright_browser_tabs_external_regression`.
Keeping those apart is Larry Peseckis's rule from the payment fixture, and it
is worth keeping: a frozen artifact that a CI convenience edit can touch is no
longer frozen.

## The subject

`browser_tabs` takes `action`, an enum of `list`, `new`, `close` and `select`;
`index`, an unbounded number; and `url`, a string.

`url` is read only on the `new` branch. Untrusted data supplying
`action=close` with an `index` closes a tab. So the argument that selects the
operation carries the consequence, and the one carrying a URL does not.

## What each arm establishes

Arm 1 declares nothing. Every argument sits behind an unknown risk tier and
confirmation is required for all 23 tools, which is fail-safe and hides the
question. Arm 2 declares `browser_tabs` a write with observed evidence, which
drops confirmation and exposes what the scanner concluded about each argument
on its own.

Two arms are the point. Either one alone is consistent with a scanner that is
correct and with one that is fail-safe by accident, and only the pair separates
them.

## What `0.10.0b11` changed, measured on these bytes

At `0.10.0b10`, arm 2 returned `action` and `index` as `typed_bounded` at high
confidence with no review required, because membership of an enum or a numeric
type established safe data authorship before any authority reasoning ran. At
`0.10.0b11` both are `trusted_fixed`, confidence `uncertain`, review required,
with the reason `ambiguous consequential argument; review required`. `url` is
unchanged in both.

Annotation conflicts went from 23 of 23 tools to 0 of 23 in arm 1 and 1 of 23
in arm 2, and the surviving one is the interesting part rather than a leftover.
`browser_tabs` carries `destructiveHint=true` while this fixture's sidecar
declares the tier `write`. Those genuinely disagree. Declaring `destructive`
instead clears it and moves both hints to `consistent`, which is the
`probe-controls-destructive.json` run.

So the check now fires on a hint that actually disagrees, and the one case it
raises is this fixture's own under-declaration rather than the scanner's.

## One thing the reports do not say plainly

In arm 2 on `0.10.0b11`, `schema_review_required` on the tool is `false` while
two of its three arguments require review. A consumer reading only the
tool-level flag would not see the finding. `--fail-on-review` does exit `2`, so
the intended CI path is unaffected, and the oracle pins the exit status rather
than the flag for that reason.

## Scope

The evidence covers per-argument authority on one tool from one MCP server at
one version, under two declarations. It says nothing about cross-argument,
sequence, or action-instance authorization, which the payment fixture already
covers and which the project states as outside its conformance claim.

The sidecar records supplied evidence. It does not claim that Verb Authority
independently observed the deployed behaviour of the tool.
