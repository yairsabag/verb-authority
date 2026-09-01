# `@verb-authority/node` — experimental source prototype

This directory contains an **unpublished, server-side TypeScript prototype**
for testing one narrow runtime boundary without Python:

> Explicit trusted application registration plus per-call argument-authority
> enforcement immediately before a privately captured tool handler.

It is not part of Beta 14, is not available from npm, and is not described as
production-ready or as full parity with Python's `GuardedToolRunner`.

## Try it

Requires Node.js 22 or newer. From this directory:

```bash
npm ci --ignore-scripts --no-audit --no-fund
npm run check
npm run quickstart
```

The quickstart has no model, network, or email integration. It proves that an
untrusted recipient and an overlong body reach zero local handler invocations,
while the application-supplied exact recipient reaches one.

Generated `node_modules/` and `dist/` are intentionally local-only. Run Python
release verification in a separate clean checkout; the Python release contract
rejects untracked build material even when it is ignored by Git.

`npm run check` performs more than a dry run: it cleans and rebuilds `dist/`,
checks an exact package-file allowlist, verifies the package copy of the Apache
license, validates both source and packed manifests against an exact private,
dependency-free contract with no lifecycle hooks, creates a temporary tarball,
installs it offline with lifecycle scripts disabled into a fresh ESM consumer,
imports it, proves block `0` / allow `1`, and type-checks a separate TypeScript
consumer. Source maps and the unexported quickstart are not included in that
tarball. The tarball is deleted after the check and nothing is published.

To test the same source in another local server project, first run
`npm run check`, then create an explicitly local tarball:

```bash
npm run build
npm pack --ignore-scripts
```

Install the resulting `verb-authority-node-0.0.0-experimental.tgz` by local
path in the test project. The import below assumes that local package is
installed; it is not a registry dependency.

## Minimal server-side use

```ts
import { createGuardedToolRunner } from "@verb-authority/node";

const runner = createGuardedToolRunner([
  {
    name: "send_email",
    risk: "write",
    params: [
      { name: "to", authority: "trusted_fixed", type: "string" },
      {
        name: "body",
        authority: "outbound_payload",
        type: "string",
        maxLength: 2000,
      },
    ],
    handler: async ({ to, body }) => {
      return await applicationEmailService.send({ to, body });
    },
  },
]);

const result = await runner.run(
  {
    name: "send_email",
    input: modelProposedArguments,
  },
  {
    // Read independently from authenticated application state.
    trustedArgs: { to: sessionRecipient },
  },
);

if (!result.decision.allow) {
  // Authority, constraints, or confirmation blocked the call before dispatch.
}
if (result.invoked && !result.handlerCompleted) {
  // The handler threw or its accepted native Promise rejected. Do not retry:
  // the handler may already have produced side effects.
}
if (result.handlerCompleted && !result.resultValidated) {
  // The handler returned, but its result violated the finite plain-JSON
  // contract. The original authorization remains visible; do not retry.
}
```

Every model-triggered execution route must call `runner.run`. The adapter
cannot stop application code from calling a raw handler reference directly.
`trustedArgs` must be populated independently from authenticated application
state, not copied from model, retrieval, webpage, or prior tool output.

A confirmation broker must correlate exactly one pending decision by the
unique `confirmationId`. `actionDigest` is a deterministic commitment for
display, comparison, or deduplication within one runner; it is not an approval
token and must never be used to approve multiple attempts.

## Enforced in this prototype

- explicit `risk`, authority, type, enum, and bounds in trusted server code;
- `typed_bounded` requires an enum, a boolean type, or an applicable declared
  bound; an unconstrained number, string, object, array, or JSON value is
  rejected at registration;
- every registered argument is required; unknown tools and arguments fail;
- `trusted_fixed` requires deep, type-exact equality with `trustedArgs`;
  object key order and signed zero are intentionally significant;
- finite plain-JSON snapshots with depth, node, and material budgets;
- no getters, Node-detected built-in exotic objects, cycles, aliases, sparse
  arrays, unsafe integers, or lone surrogates at the runtime boundary; accepted
  object containers are normalized to frozen null-prototype JSON;
- financial, destructive, code-execution, unknown, or explicitly elevated
  tools require a callback that returns the exact boolean `true`;
- confirmation receives a frozen, ASCII-escaped exact argument snapshot, a
  unique per-attempt `confirmationId`, and a deterministic keyed
  `actionDigest`; execution uses the same private snapshot and handler;
- blocked and unconfirmed calls invoke nothing; successful calls invoke once;
- `decision` records the pre-execution authorization, while `invoked`,
  `handlerCompleted`, and `resultValidated` separately record what happened
  after dispatch; handler failure or an unsupported result remains marked
  already invoked and must not be retried automatically;
- prototype-sensitive keys (`__proto__`, `constructor`, and `prototype`) are
  rejected recursively before handler code can merge model-authored objects;
- public decisions and execution results are frozen null-prototype records, so
  ambient `Object.prototype.allow` or `Object.prototype.then` pollution cannot
  alter internal discrimination or assimilate the returned result; and
- async Promise handlers and confirmations are supported. Streaming is not.

Registered handlers and confirmation callbacks are trusted application code.
The runner observes genuine Promises through a module-initialized intrinsic
`then`, so an own or prototype-level `then` override is not consulted and
rejections are consumed. It temporarily shadows a configurable Promise
`constructor` while attaching the observer, which avoids ordinary subclass and
species hooks. An unshadowable constructor/species remains inside the trusted
callback boundary because JavaScript exposes no side-effect-free alternative.
Do not return a rejecting Promise with an unshadowable constructor hook or a
rejecting Proxy-wrapped Promise: its rejection may remain outside the runner's
observation. Generic thenables and Proxy-wrapped Promises are not assimilated;
only the settled handler value crosses the finite plain-JSON result boundary.

The adapter intentionally does not validate email or URI syntax. Declare those
as strings and enforce application-specific syntax or catalog policy separately.

## Not included

- policy inference from an exported schema;
- the Python result-provenance ledger or protection against laundering prior
  tool output through `trustedArgs`;
- mixed-script/NFKC and URI/email extraction parity;
- selector branches, trusted catalog resolvers, or framework adapters;
- reusable approvals, replay/freshness controls, or external-state atomicity;
- built-in timeouts or cancellation. Confirmation callbacks and handlers must
  settle. A service-level timeout after handler invocation does not prove
  rollback; treat that call as already invoked and never retry automatically;
- an aggregate in-flight request cap. The hosting service must bound body size,
  concurrency, queue depth, and confirmation/handler deadlines before calling
  the runner;
- dynamic registration, hot reload, streaming, browser-side enforcement, or
  distributed coordination;
- prevention of direct calls to a raw handler retained elsewhere in the app;
- business, tenant, cross-field, sequence, or purpose authorization; or
- complete prompt-injection protection, confidentiality, or output filtering.

For schema inference and authority drift today, export the exact MCP, OpenAI,
or Anthropic tool JSON and use the Python scanner or the repository's GitHub
Action. Scanner output is review evidence; it must not silently become trusted
runtime configuration.
