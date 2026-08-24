"""
verb-authority -- a drop-in action-layer guard for AI agents.

PRINCIPLE: data selects, never authors.
We do not classify whether content is "malicious". We constrain which ACTIONS
run and which PARAMETERS untrusted data may fill. Under the gate's provenance
model, data cannot author parameters whose policy is trusted_fixed; semantic
rewrites and influence over which already-approved value is selected remain
outside this drop-in gate's tracking boundary.

Built on the security model behind Google DeepMind's CaMeL
("Defeating Prompt Injections by Design", arXiv:2503.18813, Apache-2.0).
Made drop-in via a policy that is auto-inferred, safe-by-default, asks when
unsure, and scales scrutiny to each verb's risk.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Iterable
import re
import sys


# === roles a parameter value may play =====================================
class Policy(str, Enum):
    TRUSTED_FIXED    = "trusted_fixed"     # sink: data may NOT fill it
    TYPED_BOUNDED    = "typed_bounded"     # data may fill, must pass type + bounds
    OUTBOUND_PAYLOAD = "outbound_payload"  # free text, flows outward only


class Confidence(str, Enum):
    HIGH = "high"
    UNCERTAIN = "uncertain"


# === trusted choice resolution ============================================
class ResolutionStatus(str, Enum):
    """Outcome of an exact lookup in an application-owned trusted catalog."""

    RESOLVED = "resolved"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class TrustedChoice:
    """One application-owned key/value pair and its evidence label.

    The application, not the model, must construct these entries from a
    trusted source such as an authenticated contact directory. `evidence` is
    retained for logging and review; Verb Authority does not verify the claim.
    """

    key: str
    value: Any
    evidence: str


@dataclass(frozen=True)
class TrustedResolution:
    """A fail-closed result returned by :class:`TrustedResolver`."""

    requested_key: str
    status: ResolutionStatus
    value: Any = None
    evidence: str | None = None
    matches: int = 0

    @property
    def resolved(self) -> bool:
        return self.status is ResolutionStatus.RESOLVED


def _normalize_choice_key(key: str) -> str:
    """Conservative matching for human labels: trim and case-fold only."""

    return key.strip().casefold()


class TrustedResolver:
    """Resolve a key to a canonical value from a closed trusted catalog.

    This primitive deliberately does not perform fuzzy matching, path/prefix
    policy, endpoint validation, or authorization. It only implements
    ``key -> (value, evidence)``. Unknown and ambiguous keys fail closed.

    The selected *value* comes from the trusted catalog, never from the lookup
    key. The key may still have been influenced by untrusted content; that is
    control-flow influence and remains outside this value-level boundary.
    """

    def __init__(
        self,
        choices: Iterable[TrustedChoice],
        *,
        normalize_key: Callable[[str], str] | None = None,
    ) -> None:
        self._normalize_key = normalize_key or _normalize_choice_key
        self._choices: dict[str, list[TrustedChoice]] = {}
        for choice in choices:
            if not isinstance(choice, TrustedChoice):
                raise TypeError("choices must contain TrustedChoice instances")
            if not isinstance(choice.key, str) or not choice.key.strip():
                raise ValueError("trusted choice keys must be non-empty strings")
            if not isinstance(choice.evidence, str) or not choice.evidence.strip():
                raise ValueError("trusted choice evidence must be non-empty text")
            if choice.value is None:
                raise ValueError("trusted choice values must not be None")
            normalized = self._normalize_key(choice.key)
            if not isinstance(normalized, str) or not normalized:
                raise ValueError(
                    "normalized trusted choice keys must be non-empty strings"
                )
            self._choices.setdefault(normalized, []).append(choice)

    def resolve(self, key: str) -> TrustedResolution:
        """Return one trusted catalog value, or an explicit closed failure."""

        if not isinstance(key, str) or not key.strip():
            return TrustedResolution(str(key), ResolutionStatus.NOT_FOUND)
        normalized = self._normalize_key(key)
        if not isinstance(normalized, str) or not normalized:
            return TrustedResolution(key, ResolutionStatus.NOT_FOUND)
        matches = self._choices.get(normalized, [])
        if not matches:
            return TrustedResolution(key, ResolutionStatus.NOT_FOUND)
        if len(matches) != 1:
            return TrustedResolution(
                key,
                ResolutionStatus.AMBIGUOUS,
                matches=len(matches),
            )
        choice = matches[0]
        return TrustedResolution(
            key,
            ResolutionStatus.RESOLVED,
            value=choice.value,
            evidence=choice.evidence,
            matches=1,
        )


# The risk tiers below are inspired by the tiered-risk access model proposed in
# Tallam & Miller, "Operationalizing CaMeL" (arXiv:2505.22852, 2025).
# This implementation is more granular (five declared tiers plus an unknown
# fail-safe vs. their three). A tool-name heuristic is reported for review, but
# only an explicit application declaration establishes the effective tier.
class Risk(str, Enum):
    UNKNOWN = "unknown"
    READ_ONLY = "read_only"
    WRITE = "write"
    FINANCIAL = "financial"
    DESTRUCTIVE = "destructive"
    CODE_EXEC = "code_exec"


class RiskConfidence(str, Enum):
    HEURISTIC = "heuristic"
    UNCERTAIN = "uncertain"


@dataclass(frozen=True)
class RiskAssessment:
    """The lexical evidence behind a tool-name risk guess.

    A tool name is author-controlled metadata, never proof of runtime behavior.
    `HEURISTIC` therefore means only that a complete name token matched a rule;
    it deliberately does not mean independently verified or high confidence.
    """

    risk: Risk
    source: str
    confidence: RiskConfidence
    mutability: str
    matched_tokens: tuple[str, ...]
    review_required: bool


# === tool schema ==========================================================
@dataclass
class Param:
    name: str
    type: str = "string"      # string|number|integer|email|uri|enum|boolean
    enum: list[str] | None = None
    max_len: int | None = None
    cap: float | None = None
    sink: bool | None = None  # declared capability (DylanWang's point):
                              #   True  -> this param IS a sink (data may not author it)
                              #   False -> explicitly NOT a sink (safe to let data fill)
                              #   None  -> not declared; fall back to name-based inference
                              # A declaration always overrides the name-based guess, so
                              # overloaded names (path, query, template) stop being
                              # guessed from the verb and are stated by the tool instead.


@dataclass
class Tool:
    name: str
    params: list[Param]
    fn: Callable[..., Any] | None = None
    risk: Risk | str | None = None  # explicit application declaration; overrides name inference


@dataclass
class Registry:
    tools: dict[str, Tool] = field(default_factory=dict)

    def add(self, t: Tool) -> None:
        self.tools[t.name] = t


# === verb risk (a reviewable heuristic over complete name tokens) =========
# Tool names are mutable labels supplied by a tool author. They can seed a
# review, but cannot establish what the implementation really does. Matching
# complete snake/kebab/camel-case tokens avoids false positives such as
# "revaluate" -> "eval". Even a match remains advisory: build_policy keeps an
# undeclared tool at UNKNOWN until the application supplies a risk declaration.
_RISK_TOKENS: list[tuple[Risk, frozenset[str]]] = [
    (
        Risk.CODE_EXEC,
        frozenset({"eval", "exec", "execute", "shell", "sql", "spawn"}),
    ),
    (Risk.DESTRUCTIVE, frozenset({
        "delete", "remove", "drop", "wipe", "revoke", "destroy", "purge", "truncate",
    })),
    (Risk.FINANCIAL, frozenset({
        "pay", "payment", "payments", "transfer", "charge", "refund", "purchase",
        "withdraw", "invoice", "billing", "bid", "buy",
    })),
    (Risk.WRITE, frozenset({
        "create", "update", "send", "post", "write", "add", "set", "book", "insert",
        "modify", "upload", "submit", "place",
    })),
    (Risk.READ_ONLY, frozenset({
        "get", "search", "list", "read", "fetch", "lookup", "find", "view", "describe",
        "scan",
    })),
]
NEEDS_CONFIRM = {Risk.UNKNOWN, Risk.FINANCIAL, Risk.DESTRUCTIVE, Risk.CODE_EXEC}


def _tool_name_tokens(tool_name: str) -> tuple[str, ...]:
    separated = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", tool_name)
    return tuple(token.lower() for token in re.findall(r"[A-Za-z0-9]+", separated))


def infer_risk(tool_name: str) -> RiskAssessment:
    tokens = _tool_name_tokens(tool_name)
    for risk, candidates in _RISK_TOKENS:
        matched = tuple(token for token in tokens if token in candidates)
        if matched:
            return RiskAssessment(
                risk=risk,
                source="tool_name",
                confidence=RiskConfidence.HEURISTIC,
                mutability="caller",
                matched_tokens=matched,
                review_required=True,
            )
    return RiskAssessment(
        risk=Risk.UNKNOWN,
        source="tool_name",
        confidence=RiskConfidence.UNCERTAIN,
        mutability="caller",
        matched_tokens=(),
        review_required=True,
    )


def verb_risk(tool_name: str) -> Risk:
    """Return the lexical risk guess; use `infer_risk` for its evidence."""

    return infer_risk(tool_name).risk


# === per-parameter inference (safe-by-default, with confidence) ===========
_SINK = re.compile(
    r"(^to$|recipient|account|iban|^url$|_url$|endpoint|host|webhook|^path$|_path$|"
    r"^file$|_file$|cmd|command|token|password|secret|credential|api[_-]?key)", re.I)
_PAYLOAD = re.compile(r"(body|message|content|^text$|summary|reply|note|description)", re.I)


def infer_policy(p: Param):
    # A declared capability always wins over name-based guessing (DylanWang):
    # the tool manifest is authoritative, so we don't infer sink-ness from the
    # param name when the developer has stated it outright.
    if p.sink is True:
        return Policy.TRUSTED_FIXED, Confidence.HIGH
    if p.sink is False:
        # explicitly not a sink: still type-check, but data may fill it
        if p.type in ("number", "integer", "enum", "boolean"):
            return Policy.TYPED_BOUNDED, Confidence.HIGH
        if _PAYLOAD.search(p.name) or (p.type == "string" and (p.max_len or 0) > 200):
            return Policy.OUTBOUND_PAYLOAD, Confidence.HIGH
        return Policy.TYPED_BOUNDED, Confidence.HIGH
    # --- no declaration: fall back to name-based inference (unchanged) ---
    if p.type in ("number", "integer", "enum", "boolean"):
        return Policy.TYPED_BOUNDED, Confidence.HIGH
    if p.type in ("email", "uri") or _SINK.search(p.name):
        return Policy.TRUSTED_FIXED, Confidence.HIGH
    if _PAYLOAD.search(p.name) or (p.type == "string" and (p.max_len or 0) > 200):
        return Policy.OUTBOUND_PAYLOAD, Confidence.HIGH
    return Policy.TRUSTED_FIXED, Confidence.UNCERTAIN   # locked-safe until you confirm


# === build a policy set for a whole registry =============================
@dataclass
class PolicySet:
    policy: dict
    risk: dict
    review: list      # (tool, param) -- uncertain, unlock if a legit input
    confirm: list     # tools requiring a runtime human confirmation
    risk_inference: dict
    risk_review: list
    risk_conflicts: list


def build_policy(reg: Registry) -> PolicySet:
    policy, risk, review, confirm = {}, {}, [], []
    risk_inference, risk_review, risk_conflicts = {}, [], []
    for name, tool in reg.tools.items():
        inferred = infer_risk(name)
        declared = tool.risk
        if isinstance(declared, str):
            declared = Risk(declared)
        conflict = declared is not None and inferred.risk is not Risk.UNKNOWN and declared is not inferred.risk
        # A caller-mutable name cannot establish runtime behavior. Keep the
        # effective tier unknown until the application makes a declaration.
        # A declaration that conflicts with the lexical evidence is not yet a
        # resolved tier either: preserve both claims for review and keep the
        # effective result at the same fail-safe UNKNOWN boundary.
        r = Risk.UNKNOWN if declared is None or conflict else declared

        risk_inference[name] = inferred
        risk[name] = r
        if declared is None or conflict:
            risk_review.append(name)
        if conflict:
            risk_conflicts.append(name)
        # A non-conflicting declaration controls the effective tier. A visible
        # conflict keeps both the effective tier and confirmation fail-safe
        # until a human resolves it.
        if r in NEEDS_CONFIRM or (conflict and inferred.risk in NEEDS_CONFIRM):
            confirm.append(name)
        policy[name] = {}
        for p in tool.params:
            pol, conf = infer_policy(p)
            if conf is Confidence.UNCERTAIN:
                if r is Risk.READ_ONLY:
                    pol = Policy.TYPED_BOUNDED        # safe to auto-relax: no side effects
                else:
                    review.append((name, p.name))    # keep locked + surface for review
            policy[name][p.name] = pol
    return PolicySet(
        policy,
        risk,
        review,
        confirm,
        risk_inference,
        risk_review,
        risk_conflicts,
    )


# === the gate (call before every tool execution) =========================
@dataclass
class Decision:
    allow: bool
    reason: str
    needs_confirm: bool = False


def _type_ok(p: Param, v) -> bool:
    if p.type in ("number", "integer"):
        return isinstance(v, (int, float)) and (p.cap is None or v <= p.cap)
    if p.type == "enum":
        return p.enum is not None and v in p.enum
    if p.type == "boolean":
        return isinstance(v, bool)
    if p.max_len is not None and isinstance(v, str) and len(v) > p.max_len:
        return False
    return True


# Homograph / mixed-script detection.
# A value that mixes Latin letters with visually-confusable letters from
# another script (Cyrillic, Greek) is almost always an impersonation attempt:
# "аpple.com" with a Cyrillic 'а' renders identically to "apple.com" but is a
# different string. This is a STRUCTURAL property of the value, independent of
# where it came from -- so we check it in the gate, before provenance even
# matters. Found by the adaptive attacker in adaptive.py: a homograph slipped
# past both the sink rule (dev mis-declared it trusted) and the ledger (no
# verbatim match), because neither normalizes characters.
_LATIN = re.compile(r"[a-zA-Z]")
_CONFUSABLE = re.compile(
    r"[\u0400-\u04FF\u0370-\u03FF]"   # Cyrillic + Greek blocks
)


def _has_mixed_script(v) -> bool:
    if not isinstance(v, str):
        return False
    return bool(_LATIN.search(v) and _CONFUSABLE.search(v))


def gate(reg: Registry, ps: PolicySet, tool: str, args: dict, provenance: dict) -> Decision:
    if tool not in reg.tools:
        return Decision(False, f"verb '{tool}' is not in the registry")
    by_name = {p.name: p for p in reg.tools[tool].params}
    pol = ps.policy[tool]
    for name, val in args.items():
        if name not in pol:
            return Decision(False, f"unknown param '{name}'")
        # Structural check first: a mixed-script value in a locked sink is a
        # homograph impersonation regardless of declared provenance.
        if pol[name] is Policy.TRUSTED_FIXED and _has_mixed_script(val):
            return Decision(False, f"param '{name}' mixes scripts (homograph); rejected as impersonation")
        prov = provenance.get(name, "data")
        if pol[name] is Policy.TRUSTED_FIXED and prov == "data":
            return Decision(False, f"param '{name}' is a locked sink; data may not author it")
        if pol[name] is Policy.TYPED_BOUNDED and not _type_ok(by_name[name], val):
            return Decision(False, f"param '{name}' failed its type/bounds check")
    if tool in ps.confirm:
        return Decision(True, f"risk policy ({ps.risk[tool].value}); needs human confirmation",
                        needs_confirm=True)
    return Decision(True, "within authority")


# === provenance ledger (partial taint propagation across a call chain) ====
#
# THE GAP THIS CLOSES (and the part it does not):
#
# The plain `dispatch` below decides provenance from a `trusted_args` map the
# developer supplies. That has a laundering hole: if a value came OUT of an
# earlier tool call (so it is really untrusted data the agent just read) and a
# naive developer threads it into `trusted_args` for the next call, the gate
# would trust it. That is Family 3 in adversarial.py.
#
# The ledger adds an INDEPENDENT, dev-proof source of truth. Every value a tool
# *returns* is data the agent read, so it is tainted at origin. We record those
# values. On a later call, if an argument's value matches something the ledger
# saw come out of a previous tool, the gate forces its provenance to "data" --
# EVEN IF the developer declared it trusted. The dev can no longer launder a
# tool result into a sink by mis-wiring trusted_args.
#
# What this is NOT: it is not CaMeL's sound interpreter taint. It tracks values
# by exact match, so a value the agent paraphrases or reformats (e.g. strips a
# name out of a sentence) no longer matches and escapes the ledger. It catches
# verbatim propagation -- the common, naive case -- not arbitrary control flow.
# Honest verdict: closes the laundering path it can SEE; the transform path
# still needs the dev to be careful (or a real interpreter).
@dataclass
class ProvenanceLedger:
    """Remembers values that originated from tool results within one session.

    Thread one ledger through an agent's tool-use loop. Call `record_result`
    after each tool returns; pass the ledger to `dispatch` on each call.

    Two layers of matching:
      1. exact   -- a value equal to something a tool returned verbatim.
      2. contained -- a RISK-SHAPED value (an email or URL) that appears as a
         substring inside a larger free-text blob a tool returned. This closes
         the extraction-from-prose path: read_doc returns a sentence containing
         attacker@evil.com, the agent lifts the bare address out, and we still
         recognise it because it lived inside a tainted blob.

    Why containment is limited to risk-shaped values: checking "is this string
    a substring of anything a tool returned" for ALL arguments would flag
    innocuous values that happen to co-occur in returned text (a real first
    name, a common word), producing false positives. Restricting containment
    to emails/URLs -- the things that actually author exfiltration -- keeps the
    check cheap and the false-positive surface small.

    Still NOT closed (the honest next boundary): a value the agent *rewrites*
    -- attacker [at] evil [dot] com, a base64 blob, a translated string -- has
    no verbatim substring in the tainted text, so it escapes. That needs real
    dataflow tracking through transforms (CaMeL's interpreter), not matching.
    """
    _tainted: set[str] = field(default_factory=set)
    _blobs: list[str] = field(default_factory=list)
    _canon_blobs: list[str] = field(default_factory=list)

    def record_result(self, result: Any) -> None:
        """Register every string a tool returned: exact values + full blobs,
        plus a canonicalized copy of each blob for disguise-resistant matching."""
        for s in _iter_strings(result):
            stripped = s.strip()
            if stripped:
                self._tainted.add(stripped)
                self._blobs.append(s)
                self._canon_blobs.append(_canonical(s))

    def is_tainted(self, value: Any) -> bool:
        """True if value is a tool-result value (exact), a risk-shaped value
        extracted from a blob (contained), or a CANONICAL match -- the same
        risk-shaped value in disguise (homograph, uppercase, spaced)."""
        if not isinstance(value, str):
            return False
        v = value.strip()
        if not v:
            return False
        if v in self._tainted:                         # layer 1: exact
            return True
        if _is_risk_shaped(v):                          # layer 2: contained
            if any(v in blob for blob in self._blobs):
                return True
        # layer 3: canonical. Fold the value to a disguise-free form and look
        # for it in the canonicalized blobs. This catches the family the
        # adaptive attacker found -- homograph / uppercase / spaced variants
        # of a tainted address -- without a separate rule per trick.
        cv = _canonical(v)
        if _is_risk_shaped(cv) and any(cv in cb for cb in self._canon_blobs):
            return True
        return False


# Canonicalization: fold a value to a single disguise-free form so that
# variants meant to look different to a string comparison but identical to a
# human (or to the destination system) collapse together. This is the
# principled answer to the adaptive attacker: rather than a rule per trick
# (homograph, uppercase, spacing), normalize once and compare.
#   - NFKC unicode normalization folds many compatibility/confusable forms
#   - casefold() handles case variation
#   - stripping spaces and common obfuscation separators handles "a t t a c k"
#     and "attacker [at] evil [dot] com" style spacing
# HONEST BOUNDARY (unchanged): this folds *lexical* disguises. It does NOT
# undo a SEMANTIC rewrite the model must interpret -- "attacker at evil dot
# com" written as words the agent reads and reconstructs is no longer the same
# string in disguise, it is content the model understood. That still needs
# interpreter-level dataflow tracking (CaMeL/FIDES), not normalization.
import unicodedata

_DISGUISE = re.compile(r"[\s\[\](){}<>]+")


def _canonical(s: str) -> str:
    if not isinstance(s, str):
        return ""
    n = unicodedata.normalize("NFKC", s)
    n = n.casefold()
    n = _DISGUISE.sub("", n)
    # common textual separators used to break up an address
    n = n.replace("[at]", "@").replace("(at)", "@").replace("[dot]", ".").replace("(dot)", ".")
    return n


_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_URL_RE = re.compile(r"https?://|www\.", re.IGNORECASE)


def _is_risk_shaped(v: str) -> bool:
    """A value that can author exfiltration: an email address or a URL.
    Containment matching is restricted to these to bound false positives."""
    return bool(_EMAIL_RE.fullmatch(v) or _URL_RE.search(v))


def _iter_strings(obj: Any):
    """Yield all string leaves from a nested dict/list/str result."""
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


# === drop-in dispatcher (the 5-line integration point) ===================
def dispatch(reg: Registry, ps: PolicySet, tool_use: dict,
             trusted_args: dict | None = None,
             ledger: ProvenanceLedger | None = None) -> Decision:
    """Drop-in wrapper for an LLM-proposed tool call.

    Pass the tool_use block your agent produced (OpenAI / Anthropic format:
    a dict with `name` and `input` keys). `trusted_args` is a small map of
    param -> known-trusted value (e.g. {"to": user.confirmed_email}); any arg
    matching gets provenance='trusted', everything else 'data'.

    Optionally pass a `ProvenanceLedger`. Any argument whose value the ledger
    saw come out of a previous tool result is forced to provenance='data',
    overriding `trusted_args` -- this is what stops a laundered tool result
    from reaching a locked sink. Returns a Decision.
    """
    trusted_args = trusted_args or {}
    tool, args = tool_use["name"], tool_use["input"]
    provenance = {}
    for n in args:
        if ledger is not None and ledger.is_tainted(args.get(n)):
            provenance[n] = "data"            # ledger overrides any dev declaration
        elif n in trusted_args and args.get(n) == trusted_args[n]:
            provenance[n] = "trusted"
        else:
            provenance[n] = "data"
    return gate(reg, ps, tool, args, provenance)


@dataclass
class ExecutionResult:
    """The policy decision and whether the underlying tool actually ran."""

    decision: Decision
    executed: bool
    result: Any = None


class GuardedToolRunner:
    """Execute registered callables only after Verb Authority allows the call.

    The runner is intentionally synchronous and provider-neutral. Applications
    normalize a provider tool call to ``{"name": ..., "input": ...}``, then
    call :meth:`run`. A confirmation callback is required for any decision with
    ``needs_confirm=True``; without one, the runner does not execute the tool.
    Successful tool results are recorded in the session ledger automatically.
    """

    def __init__(
        self,
        registry: Registry,
        policy_set: PolicySet | None = None,
        *,
        ledger: ProvenanceLedger | None = None,
    ) -> None:
        self.registry = registry
        self.policy_set = policy_set or build_policy(registry)
        self.ledger = ledger if ledger is not None else ProvenanceLedger()

    def run(
        self,
        tool_use: dict,
        *,
        trusted_args: dict | None = None,
        confirm: Callable[[Decision], bool] | None = None,
    ) -> ExecutionResult:
        decision = dispatch(
            self.registry,
            self.policy_set,
            tool_use,
            trusted_args=trusted_args,
            ledger=self.ledger,
        )
        if not decision.allow:
            return ExecutionResult(decision, executed=False)
        if decision.needs_confirm and (
            confirm is None or not confirm(decision)
        ):
            return ExecutionResult(decision, executed=False)

        tool_name = tool_use["name"]
        implementation = self.registry.tools[tool_name].fn
        if implementation is None:
            raise RuntimeError(f"verb '{tool_name}' has no registered implementation")
        result = implementation(**tool_use["input"])
        self.ledger.record_result(result)
        return ExecutionResult(decision, executed=True, result=result)


# === demo =================================================================
def demo() -> None:
    reg = Registry()
    reg.add(Tool("send_email", [
        Param("to", "email"), Param("subject", "string"), Param("body", "string")
    ], risk=Risk.WRITE))
    reg.add(Tool("search_web", [
        Param("query", "string"), Param("num_results", "integer")
    ], risk=Risk.READ_ONLY))
    reg.add(Tool("delete_record", [
        Param("table", "string"), Param("record_id", "string")
    ], risk=Risk.DESTRUCTIVE))
    ps = build_policy(reg)

    print("risk tiers:    ", {t: r.value for t, r in ps.risk.items()})
    print("needs confirm: ", ps.confirm)
    print("review queue:  ", ps.review)
    print()

    d = gate(reg, ps, "send_email", {"to": "attacker@evil.com", "body": "x"},
             {"to": "data", "body": "data"})
    print("attack send_email(to=attacker):", "BLOCKED" if not d.allow else "ALLOW", "-", d.reason)

    d = gate(reg, ps, "send_email", {"to": "alice@company.com", "body": "summary"},
             {"to": "trusted", "body": "data"})
    print("legit  send_email(to=alice):   ", "ALLOW" if d.allow else "BLOCKED", "-", d.reason)

    d = gate(reg, ps, "delete_record", {"table": "users", "record_id": "42"},
             {"table": "trusted", "record_id": "trusted"})
    print("delete_record:                 ",
          "NEEDS CONFIRM" if d.needs_confirm else ("ALLOW" if d.allow else "BLOCKED"), "-", d.reason)


def main(argv: list[str] | None = None) -> int:
    """Run the demo, local schema scanner, or authority-diff command."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "scan":
        from verb_authority_scan import main as scan_main

        return scan_main(argv[1:])
    if argv and argv[0] == "diff":
        from verb_authority_diff import main as diff_main

        return diff_main(argv[1:])
    if argv:
        print("usage: python -m verb_authority [scan|diff ...]", file=sys.stderr)
        return 2
    demo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
