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