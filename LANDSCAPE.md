# Where this sits: a map of structural prompt-injection defenses

I read the main papers on structural (non-classifier) prompt-injection defense
so you don't have to. This document is an honest map of the field and where
`verb-authority` fits in it — including everything it does *worse* than the
research systems.

If you take one thing from this page: **the serious defenses have converged on a
single idea — stop classifying content, and instead control how information is
allowed to flow into actions.** The systems below are different points on that
one idea. `verb-authority` is the small, drop-in point.

---

## The one idea everyone converged on

An agent that reads an email, a web page, or a document is reading *untrusted
data*. The injection problem is that this data can end up *authoring an action*
— becoming the recipient of an email, the URL of a request, the argument to a
shell command. Classifier defenses try to detect the bad content. That is an
arms race with false positives baked in.

The structural answer: **untrusted data may select among allowed actions; it may
never author a sensitive one.** Enforce that deterministically, at a layer the
model can't talk its way past. Every system below is a version of this.

---

## The map

| System | Where it runs | What it tracks | Adoption cost | Soundness |
|---|---|---|---|---|
| **CaMeL** (DeepMind) | Custom Python interpreter around the agent | Full data-flow taint through arbitrary control flow | Rewrite the agent loop into the interpreter | High — tracks transforms |
| **FIDES** (Microsoft) | A planner that runs the agent | Confidentiality **and** integrity labels through execution | Adopt the planner | High — formal IFC |
| **Progent** (UC Berkeley) | A module between agent and tools | A policy (DSL) over tool names + arguments | Minimal — wraps the loop; you write/generate policies | Deterministic on the *call*, not the value's origin |
| **NeuroTaint** | Offline audit of execution traces | Semantic taint incl. transformation + causal influence | Runs offline, post-hoc | High — semantic, but not a runtime gate |
| **verb-authority** (this) | A gate before each tool call | Per-call provenance (trusted vs data) + verbatim/contained tool-result taint | Minimal — ~5 lines, policy auto-inferred | Partial — verbatim + extraction; **not** transforms |

Reference links: CaMeL arXiv:2503.18813 · FIDES arXiv:2505.23643 ·
Progent arXiv:2504.11703 · NeuroTaint arXiv:2604.23374 ·
Operationalizing CaMeL (Tallam & Miller) arXiv:2505.22852.

---

## How `verb-authority` differs — precisely, and where it loses

**vs. CaMeL.** CaMeL is the gold standard for soundness: its interpreter tracks
taint through transformations, so an address the agent *rewrites* is still
caught. The cost is that you run your agent inside its interpreter. This project
does not: it enforces at the tool-call boundary in ~5 lines. The price is real —
we catch verbatim reuse and values *extracted* from returned text, but a value
the agent *rewrites or obfuscates* slips (documented in Known Limitations).

**vs. FIDES.** FIDES tracks two labels — integrity (where did this come from)
*and* confidentiality (is this secret). `verb-authority` tracks only integrity.
That means it can block an injection from authoring an action, but it does **not**
prevent exfiltration of genuinely private data through a legitimate channel. If
you need confidentiality tracking, you need FIDES (or CaMeL), not this. (This gap
was pointed out by a reviewer and is now explicit in Known Limitations.)

**vs. Progent.** The closest neighbor, and the most important distinction to get
right. Progent enforces a *policy over the call* — is `send_email` with these
arguments permitted by the rules? It is deterministic, drop-in, and resilient to
adaptive attacks; it is a strong, mature system from Dawn Song's group.
`verb-authority` asks a *different* question: *where did this argument value come
from* — was it authored by untrusted data? Progent checks the call; this checks
the value's provenance. They are **complementary layers, not competitors** — a
policy engine and a provenance tracker aimed at the same boundary. Progent also
asks you to write (or LLM-generate) policies; `verb-authority` auto-infers a
safe-by-default policy from your existing tool schema.

**vs. NeuroTaint.** NeuroTaint is the most complete taint tracker, including
semantic transformations — but it runs *offline*, auditing traces after the fact.
`verb-authority` is an online gate that blocks before the call executes. Different
job: forensics/audit vs. runtime prevention.

---

## So what is this actually *for*

Not to beat CaMeL, FIDES, or Progent. They are deeper, and in most dimensions
better. This exists because all of them ask you to adopt something — an
interpreter, a planner, a policy language, an offline pipeline — and a developer
with an existing OpenAI/Anthropic tool-use loop often can't, or won't, do that
today.

`verb-authority` is the **five-line, zero-dependency-on-your-architecture entry
point** to the same paradigm: auto-inferred safe-by-default policy, verb-risk
tiers, a provenance ledger, and an adversarial suite that reports its own
failures — so you can get a large fraction of the value now, with a clear-eyed
list of exactly what you're not getting.

It is a bridge from the research to a running agent. Read this page, decide how
much soundness your use case needs, and pick the right tool — which may not be
this one. That honesty is the point.

---

## Status

Research-grade, built in public. If any characterization of another system above
is inaccurate, that is my error and I want to fix it — open an issue.
