# Limits and boundaries

Read this before treating a clean report or an allowed call as a security
verdict. Verb Authority is a focused per-argument provenance control, not a
general prompt-injection defense or a business-authorization engine.

## Security boundary and known limitations

This project deliberately publishes its failure modes:

- **Provenance must be real.** Without a ledger, `trusted_args` is only as
  trustworthy as the application code that supplies it. Data mislabeled as
  trusted can reach a locked sink.
- **Semantic rewrites are not tracked.** The ledger matches exact values,
  contained risk-shaped strings, and canonicalized lexical variants. It cannot
  track a value the model interprets and reconstructs.
- **Approved-choice control flow is not tracked.** Untrusted content can still
  influence whether a tool runs or which already approved catalog entry is
  selected. The gate constrains the resulting value; it does not establish
  that the user's intent selected that key.
- **Integrity, not confidentiality.** The gate controls whether untrusted data
  can author sensitive arguments. It does not track secrets or stop private
  data from leaving through an otherwise authorized channel.
- **Tool calls, not model output.** Text returned to a human is not audited, so
  untrusted content can still social-engineer the user through the agent's
  reply.
- **Heuristics need review.** Undeclared parameter policies are inferred from
  names and types. Tool-name risk is only a caller-mutable review signal;
  undeclared tools stay `unknown`. Review both `PolicySet.review` and
  `PolicySet.risk_review`, declare tool risk and overloaded sink capabilities,
  and keep the registry accurate.
- **Application controls still apply.** Required arguments, authentication,
  authorization, rate limits, sandboxing, and human confirmation must still be
  enforced by the surrounding system.

Run `python adversarial.py` to see the known gaps exercised rather than hidden.
Please report new bypasses with the repository's focused issue template; keep
sensitive deployment details out of public issues and follow
[`SECURITY.md`](../SECURITY.md).

## Operational boundaries at a glance

- The gate protects only calls routed through it.
- A schema describes a calling shape; it does not prove implementation behavior.
- Trusted application code must supply protected values independently of
  untrusted model, webpage, retrieval, or tool-result content.
- General cross-argument, transaction, sequence, tenant, and business rules
  remain the application's responsibility.
- The ledger recognizes exact, contained, and selected lexical forms; it does
  not provide sound semantic taint tracking.
- Argument integrity does not provide confidentiality or output filtering.
- An allowed member of a trusted catalog can still have been selected because
  untrusted content influenced control flow.
- This remains early, research-grade work and is not described as
  production-ready.

For the detailed runtime and scanner resource contracts, see
[Runtime gate](runtime-gate.md) and
[Schema scanner and Authority Diff](schema-scanner.md).
