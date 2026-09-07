# Landscape: structural defenses and argument-authority systems

Last verified: **2026-09-01**.

This is a non-exhaustive map of systems that constrain how AI agents turn
context into actions. It is not a novelty claim, product ranking, or assertion
that differently scoped guarantees are interchangeable. Public maturity means
only how a project describes its release status; it is not a security score.

OpenAI and Anthropic both describe prompt-injection defense as layered rather
than classifier-only. [OpenAI argues that input filtering is insufficient and
that systems should constrain the impact of manipulation with deterministic
controls](https://openai.com/index/designing-agents-to-resist-prompt-injection/).
[Anthropic says model-layer defenses cannot stand alone and recommends
containment boundaries and limited tool
permissions](https://www.anthropic.com/engineering/how-we-contain-claude).
The implementations below differ substantially in policy source, granularity,
provenance model, deployment boundary, and maturity.

## Comparison map

| System | Public maturity | Policy source | Enforcement point and granularity | Provenance or temporal support | Deployment requirement and documented boundary |
|---|---|---|---|---|---|
| **Amazon Bedrock AgentCore Policy + Dogwood** | AWS Policy became GA on 2026-03-03; temporal policies were announced on 2026-08-06 | Administrators declare requirements directly or use natural-language generation against a Gateway schema | AgentCore Gateway evaluates MCP tool calls and argument conditions before execution; default deny when no permit applies | Dogwood session history can bind a current argument exactly to a prior tool output, require sequencing, approval, and freshness | The agent may run elsewhere, but protected MCP traffic must traverse an attached AgentCore Gateway; temporal evaluation also requires a stable caller-supplied policy session ID. The schema helps validate or generate a stated rule; AWS does not document automatic inference that an argument such as `to` is a protected sink |
| **CaMeL** | Research artifact, explicitly not a supported Google product | Engine-defined Python policy functions over tool names and arguments; per-value capability tags carry source and allowed-reader metadata | Interpreter-level information-flow control around the agent | Tracks per-value capabilities and recursively maintained variable-dependency graphs within its restricted Python interpreter | Requires adopting the interpreter and its programming model; the repository warns that the artifact may contain bugs and may not be fully secure |
| **PACT** | Research preprint | Draft per-argument contracts are synthesized from tool and argument metadata; provenance is supplied or inferred | Runtime monitor before tools, per argument | Cross-step value provenance and role-specific trust contracts | The paper identifies provenance inference and contract synthesis as the remaining deployment bottleneck; reported inference is imperfect and includes an LLM classifier for ambiguous provenance |
| **CXI** | Research preprint | Policies mark protected sink fields and define narrow releases | Execution boundary; protected fields, exact effects, and invocation authority | Binds field authority, exact-effect authorization, and invocation authority to the same action manifest | Requires complete mediation, a trusted host/runtime and tools, correct total field policy, conservative provenance, validators/adapters, and a capability ledger; task quality and validator completeness remain outside the core admission claim |
| **ROPE** | Research preprint submitted 2026-08-27, with public code and logs | Audited sensitive parameters plus origin policy | Deterministic origin check before state-changing tools | Origin-guarded sensitive-parameter values must trace to the user, a user-named authenticated source, or an authoritative user record | Requires truthful and propagated origin metadata, integrity of authoritative-record fields, and complete enumeration of state-changing tools and harm-carrying parameters; it does not control model text or arbitrary content sent to a legitimate destination |
| **FIDES** | Experimental feature in Microsoft Agent Framework; currently Python-only | Applications label sources and configure integrity/confidentiality policy | Agent Framework middleware before sensitive tool calls | Propagates integrity and confidentiality labels | Requires the framework's security-aware components and correct source labeling; current documentation notes conservative propagation and coarse approvals |
| **Progent** | Research system | A policy DSL over tool calls and arguments, written or generated | Module between the agent and tools | Constrains calls; it does not make the same per-value origin claim as a lineage tracker | Requires a policy; generated policy quality remains part of the trusted deployment process |
| **NeuroTaint** | Research system | A default source/sink policy plus user annotations for application-specific tools | Runtime callbacks collect tool, source, sink, memory, and reasoning events; NeuroTaint then performs an offline, sink-time provenance audit rather than blocking calls | Reconstructs explicit semantic propagation, implicit control influence through counterfactual probes, and cross-session provenance reuse | Audits completed trajectories rather than enforcing a pre-execution gate; findings attribute source-to-sink propagation and do not decide whether an action is harmful |
| **AgentLock** | Active OSS Python package and reference implementation | Trusted tool registration plus caller-recorded context provenance | Pre-action authorization with optional per-tool parameter lineage | Session provenance, parameter lineage, deferred commit, and documented cross-hop carriage | Parameter lineage is opt-in and can only observe provenance the caller records; current releases use AGPL-3.0-or-later with a commercial-license path |
| **AgentWard** | Public source-available project, self-described as early-stage | Scanner-generated smart-default YAML that developers can inspect or edit | Proxy enforcement at tool and argument-constraint level | Public documentation emphasizes policy and call inspection rather than the same value-lineage contract | Discovers MCP/Python tools and generates policy, but deployment requires routing calls through its proxy and accepting or editing the generated constraints; its documentation notes that several integration paths are not yet end-to-end verified |
| **Verb Authority** | OSS research-grade prerelease | Conservative schema heuristics, optional author-supplied evidence, and trusted runtime registration | Local schema review plus a pre-execution gate, per argument | Optional bounded lexical ledger for exact, contained, and selected normalized forms | Every execution route must pass through the gate. It does not track semantic rewrites, confidentiality, general control flow, or business authorization; a scan is a review proposal, not deployed policy |

Primary references:

- AWS: [GA announcement](https://aws.amazon.com/about-aws/whats-new/2026/03/policy-amazon-bedrock-agentcore-generally-available/),
  [natural-language policy authoring](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-natural-language.html),
  [Gateway enforcement](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/use-gateway-with-policy.html), and
  [Dogwood temporal authoring](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/policy-temporal-authoring.html).
- Research: [CaMeL](https://github.com/google-research/camel-prompt-injection),
  [PACT](https://arxiv.org/html/2605.11039v1),
  [CXI](https://arxiv.org/abs/2607.06000),
  [ROPE](https://arxiv.org/abs/2608.27496),
  [FIDES paper](https://arxiv.org/abs/2505.23643),
  [Progent](https://arxiv.org/abs/2504.11703), and
  [NeuroTaint](https://arxiv.org/abs/2604.23374).
- Implementations: [FIDES in Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/agents/security),
  [AgentLock](https://github.com/webpro255/agentlock), and
  [AgentWard](https://github.com/agentward-ai/agentward).

## Where Verb Authority overlaps, and where it differs

Verb Authority is **not** the only deterministic pre-execution gate, the only
argument-level system, or the only project that uses provenance. PACT, CXI,
ROPE, AgentLock, FIDES, and AgentCore temporal policies overlap with one or more
of those primitives. PACT also synthesizes draft argument roles from schema
metadata, and AgentWard combines schema/code scanning, generated policy, and
argument constraints.

The project's narrower product hypothesis is the combination of:

1. a deterministic, dependency-free local scan of exported MCP, OpenAI, and
   Anthropic tool-schema shapes;
2. an explicit reason, uncertainty, review obligation, and either a remediation
   recommendation or an explicit remediation-review reason for each proposed
   protected boundary rather than presenting heuristic output as verified
   policy;
3. frozen external evidence kept separate from derived regression fixtures;
   and
4. a small portable gate for teams that want to test the boundary without
   first adopting a gateway or custom interpreter.

That combination is a deployment and review workflow, not an established
research novelty or durable market moat.

### Compared with AgentCore Policy and Dogwood

AgentCore is a production policy platform. Once an administrator has supplied
the correct policy, its Gateway can enforce tool and argument conditions. Its
temporal policies can perform exact prior-output-to-current-input binding,
sequencing, and freshness checks that are stronger than Verb Authority's
lexical ledger for the declared workflow.

Verb Authority asks an earlier, weaker question: what protected-argument rules
does this schema appear to need, and what evidence supports that proposal? It
does not know AWS principals, Gateway ARNs, business rules, intended sequences,
or the authoritative source of a value. Any future AgentCore export must
therefore be a review-required draft, not a deployment-ready policy.

### Compared with PACT, CXI, and ROPE

These are among the closest published research neighbors. PACT gives argument
roles, contract synthesis, and cross-step provenance a deeper evaluation. The
paper reports 87.1% role accuracy and 77.4% provenance accuracy on its 20-tool
real-MCP evaluation, underscoring that inference remains fallible. CXI binds
field authority, exact-effect authorization, and invocation authority to the
same action manifest. ROPE checks whether sensitive parameters trace to an
allowed origin. Verb Authority does not
establish research novelty over them and does not reproduce their evaluations.
Its current distinction is a smaller executable package centered on a fully
local deterministic scan, evidence grading, external regression fixtures, and
a bounded local gate.

### Compared with CaMeL and FIDES

CaMeL and FIDES provide deeper information-flow models. FIDES tracks both
integrity and confidentiality; Verb Authority tracks only a bounded integrity
signal. CaMeL's interpreter can preserve information-flow structure through
transformations that a boundary-level lexical ledger misses. Those stronger
models require deeper runtime integration and trusted labeling or interpreter
semantics.

### Compared with AgentLock and AgentWard

AgentLock directly overlaps at the runtime/provenance boundary. It records
session sources and can apply parameter lineage to registered tools. Verb
Authority instead begins with a conservative schema-based authority proposal;
its ledger is narrower and its inference can be wrong.

AgentWard overlaps in discovery, policy generation, proxy enforcement, and
per-argument constraints. Its public documentation describes a broader tool and
supply-chain scanner. Verb Authority's narrower focus is authorship provenance
for protected arguments and the evidence supporting each proposed boundary.
Neither description proves that one system subsumes the other.

## Real incidents and control coverage

An incident in the same threat family is not evidence that Verb Authority
would have stopped it. No incident below currently has a frozen end-to-end
replay in this repository, so none is labeled “directly covered.” Where a row
is marked potentially relevant, that means only that a protected argument may
appear somewhere in the attack chain and that a correctly integrated gate
could constrain that argument.

| Incident | Publicly documented mechanism | Relationship to Verb Authority | Current claim |
|---|---|---|---|
| **Comment and Control** (2026 public research report) | Untrusted PR or issue content influenced Claude Code Security Review, Gemini CLI Action, or GitHub Copilot Agent; the agents then used powerful execution and GitHub channels to expose credentials | A gate could constrain a specifically registered protected argument, but Verb Authority does not sandbox shell access, isolate secrets, restrict GitHub tokens, classify the intent of intentionally model-authored shell commands, or control every output/egress channel | Same broad threat family; no end-to-end prevention claim |
| **EchoLeak / CVE-2025-32711** | Crafted email content crossed Microsoft 365 Copilot trust boundaries and used rendered/fetched content to exfiltrate data | The present gate does not provide confidentiality tracking, rendering isolation, CSP enforcement, or general egress control | Outside the current guarantee |
| **Kong Konnect MCP / CVE-2026-13341** | Stored analytics metadata could become prompt injection; a related identifier/path issue could cause unintended authenticated API requests | Only the related identifier/path sub-path is potentially relevant, and only if those identifiers are model-visible tool arguments, registered as protected, and every call is routed through the gate. The primary stored-output/render/fetch chain remains outside the guarantee | Potentially relevant to one sub-path; unproven and not complete coverage |
| **ios-simulator-mcp / CVE-2025-52573** | Model-visible arguments such as `duration` and `udid` were concatenated into a shell command using `exec` | This is the clearest argument-boundary fit in this table, but an argument explicitly released as model-authorable (`sink=False`) would still need implementation-level validation and safe process invocation. The correct fix includes removing unsafe shell construction | Potential mitigation only after exact fixture, policy, and runtime tests; not a current prevention claim |
| **Cursor / CVE-2026-22708** | In non-default Auto-Run + Allowlist mode, shell built-ins could poison environment variables that later changed the behavior of trusted commands | The current ledger does not parse shell semantics, model persistent shell environment state, or track this form of control-flow influence | Outside the current guarantee |

Incident references: [Comment and Control](https://oddguan.com/blog/comment-and-control-prompt-injection-credential-theft-claude-code-gemini-cli-github-copilot/),
[EchoLeak](https://arxiv.org/abs/2509.10540),
[Kong advisory](https://github.com/Kong/mcp-konnect/security/advisories/GHSA-7767-3m3w-2p44),
[ios-simulator-mcp advisory](https://github.com/joshuayoes/ios-simulator-mcp/security/advisories/GHSA-6f6r-m9pv-67jw), and
[Cursor advisory](https://github.com/cursor/cursor/security/advisories/GHSA-82wg-qcm4-fp2w).

Before associating the project with a real incident more strongly, preserve the
exact vulnerable schema and implementation assumptions, pre-register the
expected decision, run the historical vulnerable path and a control, and state
which other controls remain necessary.

## Evaluation discipline

*The Attacker Moves Second* (Nasr, Carlini, Hayes, Shumailov, Tramèr et al.;
[USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/nasr))
argues that static attack sets and computationally weak, non-adaptive
optimization are insufficient for robustness claims; defenses should be tested
against attackers that adapt specifically to the defense. Consistent with that
principle, Verb Authority includes an adaptive probe harness that documents
where its bounded lexical defense fails. Separately, it keeps scanner
expectations apart from the implementation under test and stores frozen
external evidence separately from derived CI fixtures.

The repository's corpus remains a small, curated baseline. It is not an
AgentDojo score, a representative sample of deployed agents, or proof of market
adoption. External fixtures establish only the narrow claims in their frozen
oracles.

## Status

Verb Authority is early, research-grade work. The comparison above will change
as adjacent systems evolve. If a characterization is inaccurate, please open an
issue with a primary source and the exact statement that should change.
