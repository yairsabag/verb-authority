"""
verb-authority -- a drop-in action-layer guard for AI agents.

PRINCIPLE: data selects, never authors.
We never classify whether content is "malicious" (impossible -- and the source
of every false positive). We constrain which ACTIONS run and which PARAMETERS
untrusted data may fill.

Built on the security model behind Google DeepMind's CaMeL
("Defeating Prompt Injections by Design", arXiv:2503.18813, Apache-2.0).
Made drop-in via a policy that is auto-inferred, safe-by-default, asks when
unsure, and scales scrutiny to each verb's risk.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable
import re


# === roles a parameter value may play =====================================
class Policy(str, Enum):
    TRUSTED_FIXED    = "trusted_fixed"     # sink: data may NOT fill it
    TYPED_BOUNDED    = "typed_bounded"     # data may fill, must pass type + bounds
    OUTBOUND_PAYLOAD = "outbound_payload"  # free text, flows outward only


class Confidence(str, Enum):
    HIGH = "high"
    UNCERTAIN = "uncertain"


# The risk tiers below are inspired by the tiered-risk access model proposed in
# Tallam & Miller, "Operationalizing CaMeL" (arXiv:2505.22852, 2025).
# This implementation is more granular (5 tiers vs. their 3) and infers the tier
# from the tool name; the underlying idea -- adjusting enforcement strictness to
# the action's risk class -- is theirs.
class Risk(str, Enum):
    READ_ONLY = "read_only"
    WRITE = "write"
    FINANCIAL = "financial"
    DESTRUCTIVE = "destructive"
    CODE_EXEC = "code_exec"


# === tool schema ==========================================================
@dataclass
class Param:
    name: str
    type: str = "string"      # string|number|integer|email|uri|enum|boolean
    enum: list[str] | None = None
    max_len: int | None = None
    cap: float | None = None


@dataclass
class Tool:
    name: str
    params: list[Param]
    fn: Callable[..., Any] | None = None


@dataclass
class Registry:
    tools: dict[str, Tool] = field(default_factory=dict)

    def add(self, t: Tool) -> None:
        self.tools[t.name] = t


# === verb risk (inferred from the tool name) ==============================
_RISK_RULES = [
    (Risk.CODE_EXEC,   re.compile(r"(exec|eval|run_|shell|sql|interpret|spawn)", re.I)),
    (Risk.DESTRUCTIVE, re.compile(r"(delete|remove|drop|wipe|revoke|destroy|purge|truncate)", re.I)),
    (Risk.FINANCIAL,   re.compile(r"(pay|transfer|charge|refund|purchase|withdraw|invoice|billing)", re.I)),
    (Risk.WRITE,       re.compile(r"(create|update|send|post|write|add|set|book|insert|modify|upload)", re.I)),
    (Risk.READ_ONLY,   re.compile(r"(get|search|list|read|fetch|lookup|find|view|describe)", re.I)),
]
NEEDS_CONFIRM = {Risk.FINANCIAL, Risk.DESTRUCTIVE, Risk.CODE_EXEC}


def verb_risk(tool_name: str) -> Risk:
    for risk, rx in _RISK_RULES:
        if rx.search(tool_name):
            return risk
    return Risk.WRITE  # conservative default for unknown verbs


# === per-parameter inference (safe-by-default, with confidence) ===========
_SINK = re.compile(
    r"(^to$|recipient|account|iban|^url$|_url$|endpoint|host|webhook|^path$|_path$|"
    r"^file$|_file$|cmd|command|token|password|secret|credential|api[_-]?key)", re.I)
_PAYLOAD = re.compile(r"(body|message|content|^text$|summary|reply|note|description)", re.I)


def infer_policy(p: Param):
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


def build_policy(reg: Registry) -> PolicySet:
    policy, risk, review, confirm = {}, {}, [], []
    for name, tool in reg.tools.items():
        r = verb_risk(name)
        risk[name] = r
        if r in NEEDS_CONFIRM:
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
    return PolicySet(policy, risk, review, confirm)


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


def gate(reg: Registry, ps: PolicySet, tool: str, args: dict, provenance: dict) -> Decision:
    if tool not in reg.tools:
        return Decision(False, f"verb '{tool}' is not in the registry")
    by_name = {p.name: p for p in reg.tools[tool].params}
    pol = ps.policy[tool]
    for name, val in args.items():
        if name not in pol:
            return Decision(False, f"unknown param '{name}'")
        prov = provenance.get(name, "data")
        if pol[name] is Policy.TRUSTED_FIXED and prov == "data":
            return Decision(False, f"param '{name}' is a locked sink; data may not author it")
        if pol[name] is Policy.TYPED_BOUNDED and not _type_ok(by_name[name], val):
            return Decision(False, f"param '{name}' failed its type/bounds check")
    if tool in ps.confirm:
        return Decision(True, f"high-risk verb ({ps.risk[tool].value}); needs human confirmation",
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

    def record_result(self, result: Any) -> None:
        """Register every string a tool returned: exact values + full blobs."""
        for s in _iter_strings(result):
            stripped = s.strip()
            if stripped:
                self._tainted.add(stripped)
                self._blobs.append(s)

    def is_tainted(self, value: Any) -> bool:
        """True if value is a tool-result value (exact), or a risk-shaped
        value extracted from inside one (contained)."""
        if not isinstance(value, str):
            return False
        v = value.strip()
        if not v:
            return False
        if v in self._tainted:                         # layer 1: exact
            return True
        if _is_risk_shaped(v):                          # layer 2: contained
            return any(v in blob for blob in self._blobs)
        return False


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
        elif args.get(n) == trusted_args.get(n):
            provenance[n] = "trusted"
        else:
            provenance[n] = "data"
    return gate(reg, ps, tool, args, provenance)


# === demo =================================================================
def demo() -> None:
    reg = Registry()
    reg.add(Tool("send_email",    [Param("to", "email"), Param("subject", "string"), Param("body", "string")]))
    reg.add(Tool("search_web",    [Param("query", "string"), Param("num_results", "integer")]))
    reg.add(Tool("delete_record", [Param("table", "string"), Param("record_id", "string")]))
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


if __name__ == "__main__":
    demo()
