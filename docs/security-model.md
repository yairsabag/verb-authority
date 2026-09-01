# Security model

Verb Authority enforces an argument-authorship policy immediately before a
registered tool implementation runs. It does not classify prompts. This page
defines the exact claim, the trusted application boundary, and the relationship
between argument authority and tool risk.

> **Exact guarantee:** under the gate's provenance model, untrusted data cannot
> author tool-call arguments whose policy is `trusted_fixed`. The decision is
> enforced before the tool runs; the gate does not try to decide whether a
> prompt is malicious.

> **Control-flow boundary:** Verb Authority constrains who may author a
> sensitive argument's value. It does not prevent untrusted content from
> influencing whether a tool is called or which member of an already approved
> set is selected. If an untrusted email says “send this to Dana” and Dana is
> in the application's trusted contact directory, the current value-level gate
> can allow the directory-supplied address. Preventing that control-flow
> influence requires planner- or session-level information-flow control.

> **Compositional-authority boundary:** conformance is per argument. Trusted
> application code may additionally register one exhaustive, exact selector
> map so the gate can say, for example, that `action="close"` is destructive
> and uses `index`, while `action="list"` is read-only. That narrow branch map
> is an applicability and risk declaration, not authorization of the action
> instance. A recipient, account, amount, and purpose can each have valid
> provenance while their particular combination is still forbidden. The
> surrounding application must enforce general cross-argument, transaction,
> sequence, and business-policy rules before execution; Verb Authority does
> not infer those relationships.

The per-argument boundary is the intended utility tradeoff: an application can
lock `to` while still allowing untrusted text to fill `body`, instead of
disabling the entire `send_email` tool after untrusted content enters context.

This is a research-grade boundary, not a claim that prompt injection is
impossible. The optional ledger catches exact reuse, emails and URLs extracted
from returned text, nested JSON values, every exact object key, exact
containers (including empty ones), and several lexical disguises. It does
**not** follow a value through semantic
reconstruction—for example,
turning “attacker at evil dot com” into an address. A developer can also defeat
the guarantee by marking untrusted input as trusted without using the ledger.
Systems such as CaMeL and FIDES use interpreter- or framework-level
information-flow tracking to cover that deeper boundary.

## What the gate does

The dependency-free core remains one importable module with six cooperating
pieces. The optional Pydantic adapter is a separate module and extra:

- **Per-parameter policies.** Sensitive sinks such as recipients, URLs,
  accounts, paths, and commands default to `trusted_fixed`; bounded values are
  type-checked; free-text bodies are treated as outbound payloads.
- **Conservative, review-first inference.** Policies are proposed from the
  existing tool schema. Ambiguous parameters on consequential tools stay
  locked and appear in a one-time review queue. Authority-bearing names are
  evaluated before broad numeric or payload rules: an integer `account_id` and
  a string `reply_to`
  remain locked, while an ambiguous `message_id` remains locked for review.
  A raw `maxLength`, enum membership, numeric type, or boolean type constrains
  representation but does not by itself grant the model authority to author an
  ambiguous consequential argument.
  Payload names are token-bound rather than matched as arbitrary substrings.
  Flattened names such as `destinationurlvalue` and
  `destinationurloverride` conservatively retain the underlying URL boundary,
  with bounded parsing and `sink=False` as the explicit release valve. This is
  still a finite label heuristic, not semantic proof: unusual author-chosen
  names must declare their sink role explicitly.
- **Declared capabilities.** `Param(..., sink=True|False)` lets a tool schema
  registered by trusted application code resolve overloaded names such as
  `path` without relying on the heuristic. The scanner does not treat a raw
  schema's `x-verb-authority-sink` extension as verified authority evidence;
  that author-controlled field remains committed by the schema fingerprints
  but cannot unlock an argument.
- **Declared verb-risk tiers.** Applications declare tools as read-only, write,
  financial, destructive, or code execution. Undeclared tools remain `unknown`
  and require review plus confirmation. A complete-token name heuristic is
  reported only as caller-mutable evidence; it never establishes authority.
- **Exact selector branches.** A trusted registration may enumerate every
  value of one scalar enum selector and bind each value to its effective risk
  plus complete active-argument set. Missing, unknown, duplicated, or
  non-exhaustive cases fail closed; inactive arguments are rejected. The
  selected branch is committed into policy fingerprints, action IDs, and any
  human-confirmation request. This is a deliberately narrow exception for
  local risk/applicability, not a general relational-policy language.
- **Optional provenance ledger.** Values returned by tools are recorded as
  untrusted. Exact, type-tagged JSON scalar leaves (`null`, booleans, integers,
  finite floats, and strings), every exact object key, and exact list/object
  containers (including empty or container-only values) are forced back to
  data provenance even if `trusted_args` was wired incorrectly. `True`, `1`,
  and `1.0` do not share a ledger identity.
  Containment recognizes email addresses and anchored HTTP, HTTPS, FTP, WS,
  WSS, protocol-relative, and `www.` URI forms extracted verbatim from returned
  text. NFKC normalization and recursive script detection reject a locked JSON
  string or key containing more than one of the tracked Latin, Greek, and
  Cyrillic scripts.
  Every NFKC call has a pre-normalization work ceiling. A longer non-ASCII tool
  result is still retained for exact and raw-substring taint. A bounded,
  per-code-point compatibility skeleton also preserves ASCII email and URI
  disguises without normalizing the hostile whole string, so unrelated ASCII
  destinations are not blocked merely because long Unicode appeared earlier.
  Non-ASCII destinations remain fail-closed while that full canonical index is
  incomplete; if even the bounded ASCII skeleton cannot be completed, ASCII
  destination promotion fails closed too.
  The ledger is bounded and fail-closed: capacity exhaustion saturates the
  session instead of evicting old evidence, so callers must create a fresh
  session and must not retry the tool call that already produced the result.

The gate rejects unknown tools, unknown arguments, and every omitted active
registered parameter. A non-branched tool treats every registered parameter as
active. `Param.required` remains schema metadata, not an implicit-default
execution path. URI containment is not a general URI/IDN validator, and the
mixed-script check is not a complete Unicode-confusables implementation. The
gate also does not replace complete JSON Schema validation or the tool
implementation's own authorization checks, including general cross-argument
and action-instance authorization.

## Related work and positioning

Verb Authority is one small implementation in a broader family of structural
agent controls. It is not the only pre-execution gate, argument-level system,
schema-to-policy proposal, or provenance mechanism. Its current product
hypothesis is narrower: a deterministic local scan that exposes evidence and
uncertainty, followed by a small portable runtime boundary.

Important overlaps and differences include:

- **Amazon Bedrock AgentCore Policy** is a GA policy platform whose Gateway can
  enforce declared tool and argument conditions. **Dogwood** temporal policies
  can bind an argument exactly to a prior tool output and enforce sequencing,
  approval, and freshness. AWS does not document automatic inference that an
  argument such as `to` is a protected sink. Once the policy is correctly
  declared, however, its structured temporal binding is stronger than this
  project's lexical ledger for that workflow.
- **PACT**, **CXI**, and **ROPE** are among the closest research neighbors.
  PACT synthesizes draft argument roles from tool metadata, tracks cross-step
  provenance, and checks role-specific contracts. CXI binds field authority,
  exact-effect authorization, and invocation authority to the same action
  manifest. ROPE performs deterministic origin checks over audited sensitive
  parameters. Verb Authority does not establish
  research novelty over them or reproduce their evaluations.
- **CaMeL** tracks information flow through a custom interpreter. **FIDES** is
  an experimental Microsoft Agent Framework feature that propagates
  content-level integrity and confidentiality labels to sensitive tools.
  Both require deeper runtime integration than this boundary gate and cover
  transformations or confidentiality that it does not.
- **AgentLock** is an active pre-action authorization implementation with
  caller-recorded session provenance and opt-in parameter lineage. It requires
  trusted policy registration rather than inferring the same authority map
  from a raw schema.
- **AgentWard** scans MCP and Python tools, generates reviewable policy, and
  enforces tool and per-argument constraints through a proxy. Its public
  documentation does not describe the same value-origin lineage contract, but
  its scanning and enforcement surfaces overlap substantially.
- **Progent** enforces policies over tool calls and arguments. **NeuroTaint**
  performs semantic taint analysis offline rather than blocking calls at
  runtime. Detector-based guardrails classify content or intent and can be
  layered with structural controls.

[`LANDSCAPE.md`](../LANDSCAPE.md) contains the dated comparison, primary
sources, real-incident coverage matrix, and places where this project does less
than adjacent systems. If you need sound transformation tracking,
confidentiality enforcement, general temporal authorization, or managed
gateway policy, choose a system that provides that stronger boundary.

## Continue reading

- [Runtime gate](runtime-gate.md)
- [Schema scanner and Authority Diff](schema-scanner.md)
- [Limits and boundaries](limits-and-boundaries.md)
