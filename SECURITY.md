# Security policy

Verb Authority is research-grade software. Security reports, provenance
bypasses, false negatives, and real-world tool schemas are welcome, but there
is no production-support or response-time commitment.

## Supported versions

Security fixes target the latest published beta and the current `main` branch.
Critical fixes may be backported to the latest stable `0.9.x` release when
practical. Earlier experiments and withheld release candidates are not
maintained as supported versions.

## Reporting

- For a self-contained bypass that does not expose secrets or a live system,
  use the **Bypass report or tool schema** issue template. Include the smallest
  runnable tool schema, provenance setup, proposed call, observed decision, and
  expected decision.
- If a report contains credentials, private data, or details that could affect
  a deployed system, do **not** open a detailed public issue. Use GitHub's
  **Report a vulnerability** option when it is available. Otherwise open a
  minimal issue asking the maintainer to establish a private channel, without
  including exploit details.

Never include live secrets, customer data, or third-party targets. Reports are
evaluated against the documented boundary: semantic rewrites, confidentiality
tracking, approved-choice control-flow influence, compositional/action-instance
authorization, and output-side manipulation are currently known limitations,
though new reductions or practical examples are still useful.
