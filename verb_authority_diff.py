"""Compare two Verb Authority scans and surface authority drift.

Inputs may be existing JSON reports or raw MCP/OpenAI/Anthropic schema exports.
Raw schemas are scanned locally before comparison; no server is started and no
networking code is used.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import math
import sys
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from verb_authority import infer_risk
from verb_authority_scan import (
    CONTROL_VERIFICATION_NOTICE,
    MAX_SCAN_ARGUMENTS,
    MAX_SCAN_CONTROL_COLLECTION_MEMBERS,
    MAX_SCAN_ENUM_MEMBERS,
    MAX_SCAN_TOOL_DEFINITIONS,
    REPORT_VERSION,
    SchemaError,
    _summary_requires_review,
    _tool_review_required,
    _tool_review_sources,
    canonical_decimal_text,
    is_branch_selector_name,
    is_report_shaped_document,
    load_json_path,
    scan_documents,
    validate_plain_json,
)


DIFF_VERSION = 2
_SUPPORTED_REPORT_VERSION = 5
_COMPATIBLE_REPORT_VERSIONS = frozenset({4, 5})
if REPORT_VERSION != _SUPPORTED_REPORT_VERSION:
    raise RuntimeError(
        "scanner and Authority Diff current report versions are out of sync"
    )

_CLASSIFICATION_ORDER = {
    "authority_increase": 0,
    "review": 1,
    "protection_increase": 2,
}
_POLICY_RANK = {
    "trusted_fixed": 0,
    "typed_bounded": 1,
    "outbound_payload": 2,
}
_DECLARED_AUTHORITY_RANK = {
    "locked": 0,
    "constrained": 1,
    "free": 2,
}
_RISK_RANK = {
    "read_only": 0,
    "write": 1,
    "financial": 2,
    "destructive": 2,
    "code_exec": 2,
}
_POLICIES = frozenset(_POLICY_RANK)
_DECLARED_AUTHORITIES = frozenset(_DECLARED_AUTHORITY_RANK)
_RISKS = frozenset({"unknown", *_RISK_RANK})
_RISK_SOURCES = frozenset(
    {
        "safe_default",
        "control_declaration",
        "branch_control_declaration",
        "conflict_safe_default",
    }
)
_RISK_INFERENCE_SOURCES = frozenset({"tool_name", "inference_limit"})
_RISK_CONFIDENCES = frozenset({"heuristic", "uncertain"})
_ARGUMENT_CONFIDENCES = frozenset({"high", "uncertain"})
_CONFIRMATION_RISKS = frozenset(
    {"unknown", "financial", "destructive", "code_exec"}
)
_BRANCH_RISK_PRIORITY = {
    "read_only": 0,
    "write": 1,
    "financial": 2,
    "code_exec": 3,
    "destructive": 4,
}
_EVIDENCE = frozenset({"observed", "declared", "attested"})
_BOUND_MUTABILITY = frozenset({"immutable", "trusted_party", "caller"})
_BOUND_STATUS = frozenset({"enforced", "specified", "not_stated"})
_MCP_ANNOTATION_ORDER = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)
_MCP_ANNOTATIONS = frozenset(_MCP_ANNOTATION_ORDER)
_ANNOTATION_STATES = frozenset(
    {"consistent", "conflict", "unresolved", "inapplicable"}
)
_ANNOTATION_COMPARISON_SOURCES = frozenset(
    {"effective_risk", "readOnlyHint", "none"}
)
_ANNOTATION_ASSESSMENT_FIELDS = frozenset(
    {
        "annotation",
        "value",
        "state",
        "evidence_source",
        "trust",
        "comparison_source",
        "comparison_value",
    }
)
_HEX = frozenset("0123456789abcdef")


class DiffError(ValueError):
    """Raised when reports cannot be correlated safely."""


def _is_report_shaped(document: Any) -> bool:
    """Recognize report sentinels in every supported raw-schema envelope."""
    return is_report_shaped_document(document)


def _require_object(value: Any, *, field: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise DiffError(f"{field} must be an object")
    return value


def _require_array(value: Any, *, field: str) -> list[Any]:
    if type(value) is not list:
        raise DiffError(f"{field} must be an array")
    return value


def _require_text(value: Any, *, field: str) -> str:
    if type(value) is not str or not value:
        raise DiffError(f"{field} must be non-empty text")
    return value


def _require_scanner_normalized_text(value: Any, *, field: str) -> str:
    text = _require_text(value, field=field)
    if not text.strip() or text != text.strip():
        raise DiffError(f"{field} must be trimmed, non-empty text")
    return text


def _require_bool(value: Any, *, field: str) -> bool:
    if type(value) is not bool:
        raise DiffError(f"{field} must be a boolean")
    return value


def _reject_unknown_fields(
    value: dict[str, Any], *, allowed: set[str] | frozenset[str], field: str
) -> None:
    unknown = sorted(set(value) - set(allowed))
    if unknown:
        raise DiffError(
            f"{field} contains unsupported fields: " + ", ".join(unknown)
        )


def _is_sha256(value: Any) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _HEX for character in value)
    )


def _require_sha256(value: Any, *, field: str) -> str:
    if not _is_sha256(value):
        raise DiffError(f"{field} must be a lowercase SHA-256 fingerprint")
    return value


def _require_string_array(value: Any, *, field: str) -> list[str]:
    items = _require_array(value, field=field)
    if any(type(item) is not str for item in items):
        raise DiffError(f"{field} must contain only text")
    return items


def _validate_declared_risk(value: Any, *, field: str) -> None:
    if value is None:
        return
    risk = _require_object(value, field=field)
    _reject_unknown_fields(
        risk,
        allowed={"tier", "evidence", "effects", "note"},
        field=field,
    )
    if risk.get("tier") not in _RISKS - {"unknown"}:
        raise DiffError(f"{field}.tier is invalid")
    if risk.get("evidence") not in _EVIDENCE:
        raise DiffError(f"{field}.evidence is invalid")
    effects = _require_string_array(risk.get("effects"), field=f"{field}.effects")
    if not effects or len(effects) != len(set(effects)):
        raise DiffError(
            f"{field}.effects must contain trimmed, non-empty, unique text"
        )
    for index, effect in enumerate(effects, start=1):
        try:
            _require_scanner_normalized_text(
                effect,
                field=f"{field}.effects[{index}]",
            )
        except DiffError as exc:
            raise DiffError(
                f"{field}.effects must contain trimmed, non-empty, unique text"
            ) from exc
    if "note" in risk:
        _require_scanner_normalized_text(risk["note"], field=f"{field}.note")


def _validate_risk_inference_coherence(
    tool: dict[str, Any],
    *,
    name: str,
    matched_tokens_included: bool,
) -> None:
    """Reject inferred-risk evidence tuples the scanner could never emit."""

    inference = tool["risk_inference"]
    inference_source = inference["source"]
    inference_confidence = inference["confidence"]
    inferred_risk = tool["inferred_risk"]
    if inference_source not in _RISK_INFERENCE_SOURCES:
        raise DiffError(f"tool '{name}' has invalid risk inference source")
    if inference_confidence not in _RISK_CONFIDENCES:
        raise DiffError(f"tool '{name}' has invalid risk inference confidence")
    if inference["mutability"] != "caller":
        raise DiffError(f"tool '{name}' has invalid risk inference mutability")

    matched_tokens = inference.get("matched_tokens")
    if matched_tokens_included:
        if (
            any(not token for token in matched_tokens)
            or len(matched_tokens) != len(set(matched_tokens))
        ):
            raise DiffError(f"tool '{name}' has invalid risk inference tokens")
        if inference_source == "inference_limit":
            inference_coherent = (
                inferred_risk == "unknown"
                and inference_confidence == "uncertain"
                and matched_tokens == []
            )
        elif inferred_risk == "unknown":
            inference_coherent = (
                inference_confidence == "uncertain" and matched_tokens == []
            )
        else:
            inference_coherent = (
                inference_confidence == "heuristic" and bool(matched_tokens)
            )
        if not inference_coherent:
            raise DiffError(f"tool '{name}' has inconsistent risk inference")
        if inference_source == "tool_name":
            expected = infer_risk(name)
            if (
                inferred_risk != expected.risk.value
                or inference_confidence != expected.confidence.value
                or matched_tokens != list(expected.matched_tokens)
            ):
                raise DiffError(f"tool '{name}' has inconsistent risk inference")
    elif inference_source == "inference_limit" and (
        inferred_risk != "unknown" or inference_confidence != "uncertain"
    ):
        raise DiffError(f"tool '{name}' has inconsistent risk inference")
    elif inference_source == "tool_name" and (
        (inferred_risk == "unknown" and inference_confidence != "uncertain")
        or (inferred_risk != "unknown" and inference_confidence != "heuristic")
    ):
        raise DiffError(f"tool '{name}' has inconsistent risk inference")


def _validate_report_risk_coherence(
    tool: dict[str, Any],
    *,
    name: str,
    matched_tokens_included: bool,
) -> None:
    """Reject complete non-branch risk tuples the scanner could never emit."""

    _validate_risk_inference_coherence(
        tool,
        name=name,
        matched_tokens_included=matched_tokens_included,
    )

    inference = tool["risk_inference"]
    inference_source = inference["source"]
    inferred_risk = tool["inferred_risk"]
    declared = tool["declared_risk"]
    declared_tier = declared["tier"] if declared is not None else None
    inference_incomplete = inference_source == "inference_limit"
    expected_conflict = (
        declared_tier is not None
        and inferred_risk != "unknown"
        and declared_tier != inferred_risk
    )
    unresolved = (
        declared_tier is None or expected_conflict or inference_incomplete
    )
    expected_risk = "unknown" if unresolved else declared_tier
    if expected_conflict:
        expected_source = "conflict_safe_default"
    elif declared_tier is not None and not inference_incomplete:
        expected_source = "control_declaration"
    else:
        expected_source = "safe_default"
    expected_evidence = (
        declared["evidence"]
        if declared is not None and not expected_conflict and not inference_incomplete
        else None
    )
    expected_confirmation = expected_risk in _CONFIRMATION_RISKS

    expected = {
        "risk": expected_risk,
        "risk_source": expected_source,
        "risk_evidence": expected_evidence,
        "risk_conflict": expected_conflict,
        "risk_review_required": unresolved,
        "needs_confirmation": expected_confirmation,
    }
    for field, expected_value in expected.items():
        if tool[field] != expected_value:
            raise DiffError(
                f"tool '{name}' has inconsistent {field}; "
                "rescan the original schema"
            )


def _validate_report_argument(
    value: Any,
    *,
    tool: str,
    seen: set[str],
    require_fingerprints: bool,
    effective_risk: str,
) -> None:
    argument = _require_object(value, field=f"tool '{tool}' argument")
    _reject_unknown_fields(
        argument,
        allowed={
            "name",
            "type",
            "required",
            "policy",
            "confidence",
            "review_required",
            "reason",
            "constraints",
            "schema_material_fingerprint_sha256",
            "unmodeled_schema_fingerprint_sha256",
        },
        field=f"tool '{tool}' argument",
    )
    name = _require_text(argument.get("name"), field=f"tool '{tool}' argument name")
    if name in seen:
        raise DiffError(f"report contains duplicate argument name: {tool}.{name}")
    seen.add(name)
    _require_text(argument.get("type"), field=f"argument {tool}.{name}.type")
    _require_bool(argument.get("required"), field=f"argument {tool}.{name}.required")
    policy = argument.get("policy")
    if policy not in _POLICIES:
        raise DiffError(f"argument {tool}.{name}.policy is invalid")
    confidence = _require_text(
        argument.get("confidence"), field=f"argument {tool}.{name}.confidence"
    )
    if confidence not in _ARGUMENT_CONFIDENCES:
        raise DiffError(f"argument {tool}.{name}.confidence is invalid")
    review_required = _require_bool(
        argument.get("review_required"),
        field=f"argument {tool}.{name}.review_required",
    )
    if confidence == "high":
        inference_coherent = review_required is False
    elif policy == "trusted_fixed":
        inference_coherent = review_required is True
    else:
        inference_coherent = (
            policy == "typed_bounded"
            and effective_risk == "read_only"
            and review_required is False
        )
    if not inference_coherent:
        raise DiffError(
            f"argument {tool}.{name} has inconsistent policy inference"
        )
    _require_text(argument.get("reason"), field=f"argument {tool}.{name}.reason")
    _validated_constraints(argument.get("constraints"), tool=tool, argument=name)
    for fingerprint_field in (
        "schema_material_fingerprint_sha256",
        "unmodeled_schema_fingerprint_sha256",
    ):
        if require_fingerprints:
            _require_sha256(
                argument.get(fingerprint_field),
                field=f"argument {tool}.{name}.{fingerprint_field}",
            )
        elif fingerprint_field in argument:
            raise DiffError(
                f"redacted argument {tool}.{name} exposes an exact schema fingerprint"
            )


def _same_exact_scalar(left: Any, right: Any) -> bool:
    if type(left) is not type(right):
        return False
    if type(left) is float and left == 0.0 and right == 0.0:
        return math.copysign(1.0, left) == math.copysign(1.0, right)
    if type(left) is Decimal and left.is_zero() and right.is_zero():
        return left.is_signed() is right.is_signed()
    return left == right


def _validate_annotation_assessments(
    tool: dict[str, Any], *, name: str
) -> None:
    raw_assessments = _require_array(
        tool.get("annotation_assessments"),
        field=f"tool '{name}' annotation assessments",
    )
    assessments: list[dict[str, Any]] = []
    seen: set[str] = set()
    order: list[int] = []

    for index, raw_assessment in enumerate(raw_assessments, start=1):
        field = f"tool '{name}' annotation assessment[{index}]"
        assessment = _require_object(raw_assessment, field=field)
        _reject_unknown_fields(
            assessment,
            allowed=_ANNOTATION_ASSESSMENT_FIELDS,
            field=field,
        )
        missing = sorted(_ANNOTATION_ASSESSMENT_FIELDS - set(assessment))
        if missing:
            raise DiffError(
                f"{field} is missing required fields: " + ", ".join(missing)
            )

        annotation = _require_text(
            assessment["annotation"], field=f"{field}.annotation"
        )
        if annotation not in _MCP_ANNOTATIONS:
            raise DiffError(f"{field}.annotation is unsupported")
        if annotation in seen:
            raise DiffError(
                f"tool '{name}' contains duplicate annotation assessment: "
                f"{annotation}"
            )
        seen.add(annotation)
        order.append(_MCP_ANNOTATION_ORDER.index(annotation))

        _require_bool(assessment["value"], field=f"{field}.value")
        state = _require_text(assessment["state"], field=f"{field}.state")
        if state not in _ANNOTATION_STATES:
            raise DiffError(f"{field}.state is unsupported")
        if assessment["evidence_source"] != "mcp_tool_annotation":
            raise DiffError(f"{field}.evidence_source is unsupported")
        if assessment["trust"] != "unverified_hint":
            raise DiffError(f"{field}.trust is unsupported")
        comparison_source = _require_text(
            assessment["comparison_source"],
            field=f"{field}.comparison_source",
        )
        if comparison_source not in _ANNOTATION_COMPARISON_SOURCES:
            raise DiffError(f"{field}.comparison_source is unsupported")
        assessments.append(assessment)

    if order != sorted(order):
        raise DiffError(
            f"tool '{name}' annotation assessments are not in canonical order"
        )

    by_annotation = {
        assessment["annotation"]: assessment for assessment in assessments
    }
    read_only = by_annotation.get("readOnlyHint")
    read_only_value = read_only["value"] if read_only is not None else None
    risk = tool["risk"]

    for assessment in assessments:
        annotation = assessment["annotation"]
        value = assessment["value"]
        if annotation == "readOnlyHint":
            expected_read_only = risk == "read_only"
            expected_state = (
                "unresolved"
                if risk == "unknown"
                else "consistent" if value is expected_read_only else "conflict"
            )
            expected_source = "effective_risk"
            expected_value: Any = risk
        elif annotation == "destructiveHint":
            if read_only_value is True:
                expected_state = "inapplicable"
                expected_source = "readOnlyHint"
                expected_value = True
            else:
                expected_destructive = risk == "destructive"
                expected_state = (
                    "unresolved"
                    if risk == "unknown"
                    else (
                        "consistent"
                        if value is expected_destructive
                        else "conflict"
                    )
                )
                expected_source = "effective_risk"
                expected_value = risk
        elif annotation == "idempotentHint":
            if read_only_value is True:
                expected_state = "inapplicable"
                expected_source = "readOnlyHint"
                expected_value = True
            else:
                expected_state = "unresolved"
                expected_source = "none"
                expected_value = None
        else:
            expected_state = "unresolved"
            expected_source = "none"
            expected_value = None

        if (
            assessment["state"] != expected_state
            or assessment["comparison_source"] != expected_source
            or not _same_exact_scalar(
                assessment["comparison_value"], expected_value
            )
        ):
            raise DiffError(
                f"tool '{name}' annotation assessment for {annotation} "
                "is inconsistent"
            )

    expected_conflicts = [
        f"{assessment['annotation']}={str(assessment['value']).lower()} "
        "conflicts with effective risk"
        for assessment in assessments
        if assessment["state"] == "conflict"
    ]
    conflicts = _require_string_array(
        tool.get("annotation_conflicts"),
        field=f"tool '{name}' annotation conflicts",
    )
    if conflicts != expected_conflicts:
        raise DiffError(
            f"tool '{name}' annotation conflicts do not match its assessments"
        )


def _validate_branch_risk(
    tool: dict[str, Any],
    *,
    name: str,
    argument_names: set[str],
    names_redacted: bool,
) -> None:
    branch_review = _require_bool(
        tool.get("branch_risk_review_required"),
        field=f"tool '{name}' branch_risk_review_required",
    )
    raw_branch = tool.get("branch_risk")
    if raw_branch is None:
        expected_review = (
            any(
                argument.get("type") == "enum"
                and argument.get("policy") == "trusted_fixed"
                and argument.get("confidence") == "uncertain"
                and is_branch_selector_name(argument["name"])
                for argument in tool["arguments"]
            )
            and tool["risk"] != "read_only"
        )
        if not names_redacted and branch_review is not expected_review:
            raise DiffError(
                f"tool '{name}' has inconsistent branch risk review state"
            )
        return

    if branch_review is not False:
        raise DiffError(
            f"tool '{name}' cannot require branch review with declared branches"
        )
    branch = _require_object(raw_branch, field=f"tool '{name}' branch risk")
    _reject_unknown_fields(
        branch,
        allowed={"source", "selector", "value_disclosure", "cases"},
        field=f"tool '{name}' branch risk",
    )
    if branch.get("source") != "control_declaration":
        raise DiffError(f"tool '{name}' has invalid branch risk source")
    selector = _require_text(
        branch.get("selector"), field=f"tool '{name}' branch selector"
    )
    if selector not in argument_names:
        raise DiffError(f"tool '{name}' branch selector is not an argument")
    selector_argument = next(
        argument for argument in tool["arguments"] if argument["name"] == selector
    )
    if selector_argument["type"] != "enum":
        raise DiffError(f"tool '{name}' branch selector is not an enum")
    if branch.get("value_disclosure") != "sha256_fingerprint_only":
        raise DiffError(f"tool '{name}' has invalid branch value disclosure")

    cases = _require_array(
        branch.get("cases"), field=f"tool '{name}' branch cases"
    )
    if not cases:
        raise DiffError(f"tool '{name}' branch cases must not be empty")
    normalized_cases: list[dict[str, Any]] = []
    seen_fingerprints: set[str] = set()
    for index, raw_case in enumerate(cases, start=1):
        field = f"tool '{name}' branch case[{index}]"
        case = _require_object(raw_case, field=field)
        allowed = {
            "value_fingerprint_sha256",
            "risk",
            "evidence",
            "effects",
            "active_arguments",
            "needs_confirmation",
            "note",
        }
        _reject_unknown_fields(case, allowed=allowed, field=field)
        required = allowed - {"note"}
        missing = sorted(required - set(case))
        if missing:
            raise DiffError(
                f"{field} is missing required fields: " + ", ".join(missing)
            )
        fingerprint = _require_sha256(
            case["value_fingerprint_sha256"],
            field=f"{field}.value_fingerprint_sha256",
        )
        if fingerprint in seen_fingerprints:
            raise DiffError(f"tool '{name}' has duplicate branch fingerprints")
        seen_fingerprints.add(fingerprint)
        risk = case["risk"]
        if risk not in _RISKS - {"unknown"}:
            raise DiffError(f"{field}.risk is invalid")
        if case["evidence"] not in _EVIDENCE:
            raise DiffError(f"{field}.evidence is invalid")
        effects = _require_string_array(case["effects"], field=f"{field}.effects")
        if not effects or len(effects) != len(set(effects)):
            raise DiffError(
                f"{field}.effects must contain unique, non-empty text"
            )
        for effect_index, effect in enumerate(effects, start=1):
            _require_scanner_normalized_text(
                effect, field=f"{field}.effects[{effect_index}]"
            )
        active_arguments = _require_string_array(
            case["active_arguments"], field=f"{field}.active_arguments"
        )
        if (
            not active_arguments
            or len(active_arguments) != len(set(active_arguments))
            or any(argument not in argument_names for argument in active_arguments)
            or selector not in active_arguments
        ):
            raise DiffError(f"{field}.active_arguments is inconsistent")
        expected_active_order = [
            argument["name"]
            for argument in tool["arguments"]
            if argument["name"] in set(active_arguments)
        ]
        if active_arguments != expected_active_order:
            raise DiffError(
                f"{field}.active_arguments is not in canonical argument order"
            )
        expected_confirmation = risk in _CONFIRMATION_RISKS
        if (
            _require_bool(
                case["needs_confirmation"],
                field=f"{field}.needs_confirmation",
            )
            is not expected_confirmation
        ):
            raise DiffError(f"{field}.needs_confirmation is inconsistent")
        if "note" in case:
            _require_scanner_normalized_text(case["note"], field=f"{field}.note")
        normalized_cases.append(case)

    fingerprints = [case["value_fingerprint_sha256"] for case in normalized_cases]
    if fingerprints != sorted(fingerprints):
        raise DiffError(f"tool '{name}' branch cases are not in canonical order")
    selector_constraints = selector_argument.get("constraints")
    selector_enum = (
        selector_constraints.get("enum")
        if isinstance(selector_constraints, dict)
        else None
    )
    if not isinstance(selector_enum, dict):
        raise DiffError(f"tool '{name}' branch selector has no enum evidence")
    if names_redacted:
        if selector_enum.get("count") != len(fingerprints):
            raise DiffError(
                f"tool '{name}' branch cases do not exhaust the selector enum"
            )
    elif selector_enum.get("value_fingerprints_sha256") != fingerprints:
        raise DiffError(
            f"tool '{name}' branch cases do not exhaust the selector enum"
        )
    worst = max(
        (case["risk"] for case in normalized_cases),
        key=lambda risk: _BRANCH_RISK_PRIORITY[risk],
    )
    expected = {
        "risk": worst,
        "risk_source": "branch_control_declaration",
        "risk_evidence": None,
        "declared_risk": None,
        "risk_conflict": False,
        "risk_review_required": False,
        "needs_confirmation": any(
            case["needs_confirmation"] is True for case in normalized_cases
        ),
    }
    for field, expected_value in expected.items():
        if tool[field] != expected_value:
            raise DiffError(
                f"tool '{name}' has inconsistent branch-derived {field}"
            )


def _validate_or_derive_tool_review(
    tool: dict[str, Any], *, name: str, report_version: int
) -> None:
    expected_review_sources = _tool_review_sources(
        arguments=tool["arguments"],
        schema_review_required=tool["schema_review_required"],
        risk_review_required=tool["risk_review_required"],
        risk_conflict=tool["risk_conflict"],
        annotation_assessments=tool["annotation_assessments"],
        branch_risk_review_required=tool["branch_risk_review_required"],
    )
    expected_review_required = _tool_review_required(expected_review_sources)
    if report_version == 4:
        # Report v4 did not expose the aggregate. Keep the caller-owned report
        # unchanged; _index_report derives the same fields in its internal
        # normalized representation when observational comparison needs them.
        return

    if "review_required" not in tool:
        raise DiffError(f"tool '{name}' is missing review_required")
    if "review_sources" not in tool:
        raise DiffError(f"tool '{name}' is missing review_sources")
    review_required = _require_bool(
        tool["review_required"], field=f"tool '{name}' review_required"
    )
    review_sources = _require_object(
        tool["review_sources"], field=f"tool '{name}' review sources"
    )
    source_fields = {
        "arguments",
        "schema",
        "risk",
        "risk_conflict",
        "annotation_conflicts",
        "branch_risk",
    }
    _reject_unknown_fields(
        review_sources,
        allowed=source_fields,
        field=f"tool '{name}' review sources",
    )
    if not source_fields.issubset(review_sources):
        missing = sorted(source_fields - set(review_sources))
        raise DiffError(
            f"tool '{name}' review sources are missing required fields: "
            + ", ".join(missing)
        )
    _require_string_array(
        review_sources["arguments"],
        field=f"tool '{name}' review source arguments",
    )
    _require_string_array(
        review_sources["annotation_conflicts"],
        field=f"tool '{name}' review source annotation conflicts",
    )
    for boolean_source in (
        "schema",
        "risk",
        "risk_conflict",
        "branch_risk",
    ):
        _require_bool(
            review_sources[boolean_source],
            field=f"tool '{name}' review source {boolean_source}",
        )
    if review_sources != expected_review_sources:
        raise DiffError(f"tool '{name}' review_sources are inconsistent")
    if review_required is not expected_review_required:
        raise DiffError(f"tool '{name}' review_required is inconsistent")


def _validate_report_tool(
    value: Any,
    *,
    seen: set[str],
    require_fingerprints: bool,
    report_version: int,
) -> tuple[str, set[str]]:
    tool = _require_object(value, field="report tool")
    allowed_fields = {
        "name",
        "risk",
        "risk_source",
        "risk_evidence",
        "inferred_risk",
        "risk_inference",
        "declared_risk",
        "risk_conflict",
        "risk_review_required",
        "needs_confirmation",
        "schema_closes_unknown_arguments",
        "schema_review_required",
        "annotation_assessments",
        "annotation_conflicts",
        "branch_risk",
        "branch_risk_review_required",
        "arguments",
        "schema_material_fingerprint_sha256",
        "unmodeled_schema_fingerprint_sha256",
        "source_id",
        "source_url",
    }
    if report_version >= 5:
        allowed_fields.update({"review_required", "review_sources"})
    _reject_unknown_fields(
        tool,
        allowed=allowed_fields,
        field="report tool",
    )
    name = _require_text(tool.get("name"), field="report tool name")
    if name in seen:
        raise DiffError(f"report contains duplicate tool name: {name}")
    seen.add(name)
    if tool.get("risk") not in _RISKS:
        raise DiffError(f"tool '{name}' has invalid risk")
    if tool.get("risk_source") not in _RISK_SOURCES:
        raise DiffError(f"tool '{name}' has invalid risk source")
    risk_evidence = tool.get("risk_evidence")
    if risk_evidence is not None and risk_evidence not in _EVIDENCE:
        raise DiffError(f"tool '{name}' has invalid risk evidence")
    if tool.get("inferred_risk") not in _RISKS:
        raise DiffError(f"tool '{name}' has invalid inferred risk")
    risk_inference = _require_object(
        tool.get("risk_inference"), field=f"tool '{name}' risk inference"
    )
    _reject_unknown_fields(
        risk_inference,
        allowed={
            "source",
            "confidence",
            "mutability",
            "matched_tokens",
            "signal_redacted",
        },
        field=f"tool '{name}' risk inference",
    )
    _require_text(
        risk_inference.get("source"), field=f"tool '{name}' risk inference source"
    )
    _require_text(
        risk_inference.get("confidence"),
        field=f"tool '{name}' risk inference confidence",
    )
    _require_text(
        risk_inference.get("mutability"),
        field=f"tool '{name}' risk inference mutability",
    )
    if require_fingerprints:
        _require_string_array(
            risk_inference.get("matched_tokens"),
            field=f"tool '{name}' risk inference matched_tokens",
        )
        if "signal_redacted" in risk_inference:
            raise DiffError(
                f"named tool '{name}' has redacted risk-inference metadata"
            )
    else:
        if risk_inference.get("signal_redacted") is not True:
            raise DiffError(
                f"redacted tool '{name}' has invalid risk-inference metadata"
            )
        if "matched_tokens" in risk_inference:
            raise DiffError(
                f"redacted tool '{name}' exposes risk-inference tokens"
            )
    if "risk_evidence" not in tool:
        raise DiffError(f"tool '{name}' is missing risk_evidence")
    if "declared_risk" not in tool:
        raise DiffError(f"tool '{name}' is missing declared_risk")
    if "branch_risk" not in tool:
        raise DiffError(f"tool '{name}' is missing branch_risk")
    if "branch_risk_review_required" not in tool:
        raise DiffError(
            f"tool '{name}' is missing branch_risk_review_required"
        )
    _validate_declared_risk(tool["declared_risk"], field=f"tool '{name}' risk")
    for boolean_field in (
        "risk_conflict",
        "risk_review_required",
        "needs_confirmation",
        "schema_closes_unknown_arguments",
    ):
        _require_bool(tool.get(boolean_field), field=f"tool '{name}' {boolean_field}")
    if "schema_review_required" not in tool:
        raise DiffError(
            f"tool '{name}' is missing schema_review_required; rescan the "
            "original schema with the current scanner"
        )
    _require_bool(
        tool["schema_review_required"],
        field=f"tool '{name}' schema_review_required",
    )
    for optional_text_field in ("source_id", "source_url"):
        if optional_text_field in tool:
            _require_text(
                tool[optional_text_field],
                field=f"tool '{name}' {optional_text_field}",
            )
    for fingerprint_field in (
        "schema_material_fingerprint_sha256",
        "unmodeled_schema_fingerprint_sha256",
    ):
        if require_fingerprints:
            _require_sha256(
                tool.get(fingerprint_field),
                field=f"tool '{name}' {fingerprint_field}",
            )
        elif fingerprint_field in tool:
            raise DiffError(
                f"redacted tool '{name}' exposes an exact schema fingerprint"
            )

    argument_names: set[str] = set()
    # Branch declarations establish operation-specific risk and applicability,
    # not argument authorship. Validate the argument rows against the same
    # fail-closed UNKNOWN inference context used by the scanner before the
    # displayed worst-branch risk is applied to the tool summary.
    argument_inference_risk = (
        "unknown" if tool["branch_risk"] is not None else tool["risk"]
    )
    for argument in _require_array(
        tool.get("arguments"), field=f"tool '{name}' arguments"
    ):
        _validate_report_argument(
            argument,
            tool=name,
            seen=argument_names,
            require_fingerprints=require_fingerprints,
            effective_risk=argument_inference_risk,
        )
    _validate_branch_risk(
        tool,
        name=name,
        argument_names=argument_names,
        names_redacted=not require_fingerprints,
    )
    _validate_annotation_assessments(tool, name=name)
    if tool["branch_risk"] is None:
        _validate_report_risk_coherence(
            tool,
            name=name,
            matched_tokens_included=require_fingerprints,
        )
    else:
        _validate_risk_inference_coherence(
            tool,
            name=name,
            matched_tokens_included=require_fingerprints,
        )
    return name, argument_names


def _validate_bound(value: Any, *, field: str) -> None:
    bound = _require_object(value, field=field)
    _reject_unknown_fields(
        bound,
        allowed={
            "source",
            "bounds_mutability",
            "operational_status",
            "enforcement",
        },
        field=field,
    )
    _require_scanner_normalized_text(
        bound.get("source"), field=f"{field}.source"
    )
    if bound.get("bounds_mutability") not in _BOUND_MUTABILITY:
        raise DiffError(f"{field}.bounds_mutability is invalid")
    if bound.get("operational_status") not in _BOUND_STATUS:
        raise DiffError(f"{field}.operational_status is invalid")
    if "enforcement" in bound:
        _require_scanner_normalized_text(
            bound["enforcement"], field=f"{field}.enforcement"
        )


def _validate_declared_controls(
    value: Any,
    *,
    report_tools: dict[str, dict[str, Any]],
    report_arguments: dict[str, dict[str, dict[str, Any]]],
    names_redacted: bool,
) -> None:
    declared = _require_object(value, field="declared_controls")
    _reject_unknown_fields(
        declared,
        allowed={"version", "verification_notice", "tools", "attribution"},
        field="declared_controls",
    )
    if type(declared.get("version")) is not int or declared.get("version") != 1:
        raise DiffError("declared_controls.version is invalid")
    verification_notice = _require_text(
        declared.get("verification_notice"),
        field="declared_controls.verification_notice",
    )
    if verification_notice != CONTROL_VERIFICATION_NOTICE:
        raise DiffError("declared_controls.verification_notice is invalid")
    if "attribution" in declared:
        attribution = _require_object(
            declared["attribution"], field="declared_controls.attribution"
        )
        _reject_unknown_fields(
            attribution,
            allowed={"name", "source"},
            field="declared_controls.attribution",
        )
        if not attribution:
            raise DiffError("declared_controls.attribution must not be empty")
        for attribution_field, attribution_value in attribution.items():
            _require_scanner_normalized_text(
                attribution_value,
                field=f"declared_controls.attribution.{attribution_field}",
            )
    tools_seen: set[str] = set()
    declared_tool_order: list[str] = []
    for raw_tool in _require_array(
        declared.get("tools"), field="declared_controls.tools"
    ):
        tool = _require_object(raw_tool, field="declared control tool")
        _reject_unknown_fields(
            tool,
            allowed={
                "name",
                "schema_closes_unknown_arguments",
                "arguments",
                "unexposed_arguments",
                "risk",
                "branches",
            },
            field="declared control tool",
        )
        name = _require_text(tool.get("name"), field="declared control tool name")
        if name in tools_seen:
            raise DiffError(f"declared controls contain duplicate tool name: {name}")
        tools_seen.add(name)
        declared_tool_order.append(name)
        if name not in report_tools:
            raise DiffError(f"declared controls reference unknown report tool: {name}")
        report_tool = report_tools[name]
        _require_bool(
            tool.get("schema_closes_unknown_arguments"),
            field=f"declared control tool '{name}' schema closure",
        )
        if (
            tool["schema_closes_unknown_arguments"]
            is not report_tool["schema_closes_unknown_arguments"]
        ):
            raise DiffError(
                f"declared control tool '{name}' schema closure conflicts with "
                "the report tool"
            )
        if "risk" in tool:
            _validate_declared_risk(tool["risk"], field=f"declared tool '{name}' risk")
        if tool.get("risk") != report_tool.get("declared_risk"):
            raise DiffError(
                f"declared control tool '{name}' risk conflicts with the report tool"
            )
        if "risk" in tool and "branches" in tool:
            raise DiffError(
                f"declared control tool '{name}' combines tool and branch risk"
            )
        if "branches" in tool:
            _require_object(
                tool["branches"], field=f"declared tool '{name}' branches"
            )
        if tool.get("branches") != report_tool.get("branch_risk"):
            raise DiffError(
                f"declared control tool '{name}' branches conflict with the "
                "report tool"
            )

        argument_names: set[str] = set()
        declared_argument_order: list[str] = []
        for raw_argument in _require_array(
            tool.get("arguments"), field=f"declared tool '{name}' arguments"
        ):
            argument = _require_object(
                raw_argument, field=f"declared argument for '{name}'"
            )
            _reject_unknown_fields(
                argument,
                allowed={
                    "name",
                    "schema_exposure",
                    "inferred_policy",
                    "review_required",
                    "authority",
                    "evidence",
                    "bounds",
                    "note",
                },
                field=f"declared argument for '{name}'",
            )
            argument_name = _require_text(
                argument.get("name"), field=f"declared argument name for '{name}'"
            )
            if argument_name in argument_names:
                raise DiffError(
                    f"declared controls contain duplicate argument name: "
                    f"{name}.{argument_name}"
                )
            argument_names.add(argument_name)
            declared_argument_order.append(argument_name)
            if argument_name not in report_arguments[name]:
                raise DiffError(
                    f"declared controls reference unknown argument: "
                    f"{name}.{argument_name}"
                )
            report_argument = report_arguments[name][argument_name]
            if argument.get("schema_exposure") != "exposed":
                raise DiffError(
                    f"declared argument schema exposure is invalid: "
                    f"{name}.{argument_name}"
                )
            if argument.get("inferred_policy") not in _POLICIES:
                raise DiffError(
                    f"declared argument inferred policy is invalid: "
                    f"{name}.{argument_name}"
                )
            if argument["inferred_policy"] != report_argument["policy"]:
                raise DiffError(
                    f"declared argument inferred policy conflicts with the report: "
                    f"{name}.{argument_name}"
                )
            _require_bool(
                argument.get("review_required"),
                field=f"declared argument review requirement for "
                f"{name}.{argument_name}",
            )
            if argument["review_required"] is not report_argument["review_required"]:
                raise DiffError(
                    f"declared argument review requirement conflicts with the report: "
                    f"{name}.{argument_name}"
                )
            if argument.get("authority") not in _DECLARED_AUTHORITIES:
                raise DiffError(f"declared authority is invalid: {name}.{argument_name}")
            if argument.get("evidence") not in _EVIDENCE:
                raise DiffError(f"declared evidence is invalid: {name}.{argument_name}")
            bounds = _require_array(
                argument.get("bounds", []),
                field=f"declared bounds for {name}.{argument_name}",
            )
            if argument["authority"] == "constrained" and not bounds:
                raise DiffError(
                    f"constrained declared argument has no bounds: "
                    f"{name}.{argument_name}"
                )
            if argument["authority"] != "constrained" and bounds:
                raise DiffError(
                    f"non-constrained declared argument has bounds: "
                    f"{name}.{argument_name}"
                )
            bound_keys: set[tuple[str, str, str, str | None]] = set()
            for index, bound in enumerate(
                bounds,
                start=1,
            ):
                _validate_bound(
                    bound,
                    field=f"declared bound {index} for {name}.{argument_name}",
                )
                bound_key = (
                    bound["source"],
                    bound["bounds_mutability"],
                    bound["operational_status"],
                    bound.get("enforcement"),
                )
                if bound_key in bound_keys:
                    raise DiffError(
                        f"duplicate declared bound for {name}.{argument_name}"
                    )
                bound_keys.add(bound_key)
            if "note" in argument:
                _require_scanner_normalized_text(
                    argument["note"],
                    field=f"declared argument note for {name}.{argument_name}",
                )

        expected_argument_order = [
            argument_name
            for argument_name in report_arguments[name]
            if argument_name in argument_names
        ]
        if declared_argument_order != expected_argument_order:
            raise DiffError(
                f"declared argument order does not match report order for '{name}'"
            )

        unexposed_arguments = _require_array(
            tool.get("unexposed_arguments"),
            field=f"declared tool '{name}' unexposed arguments",
        )
        unexposed_argument_order: list[str] = []
        for raw_argument in unexposed_arguments:
            argument = _require_object(
                raw_argument, field=f"unexposed control for '{name}'"
            )
            _reject_unknown_fields(
                argument,
                allowed={
                    "name",
                    "schema_exposure",
                    "exposure",
                    "enforced_by",
                    "evidence",
                    "note",
                },
                field=f"unexposed control for '{name}'",
            )
            argument_name = _require_text(
                argument.get("name"), field=f"unexposed control name for '{name}'"
            )
            if argument_name in argument_names:
                raise DiffError(
                    f"declared controls contain duplicate argument name: "
                    f"{name}.{argument_name}"
                )
            argument_names.add(argument_name)
            unexposed_argument_order.append(argument_name)
            if argument_name in report_arguments[name]:
                raise DiffError(
                    f"argument is both exposed and unexposed: {name}.{argument_name}"
                )
            if argument.get("schema_exposure") != "unexposed":
                raise DiffError(
                    f"unexposed control schema exposure is invalid: "
                    f"{name}.{argument_name}"
                )
            if argument.get("exposure") != "server_fixed":
                raise DiffError(f"unexposed control is invalid: {name}.{argument_name}")
            if argument.get("evidence") not in _EVIDENCE:
                raise DiffError(f"unexposed evidence is invalid: {name}.{argument_name}")
            _require_scanner_normalized_text(
                argument.get("enforced_by"),
                field=f"unexposed control enforcement for {name}.{argument_name}",
            )
            if "note" in argument:
                _require_scanner_normalized_text(
                    argument["note"],
                    field=f"unexposed control note for {name}.{argument_name}",
                )
        if names_redacted:
            expected_unexposed_order = [
                f"param_{index:03d}"
                for index in range(
                    len(report_arguments[name]) + 1,
                    len(report_arguments[name]) + len(unexposed_argument_order) + 1,
                )
            ]
        else:
            expected_unexposed_order = sorted(unexposed_argument_order)
        if unexposed_argument_order != expected_unexposed_order:
            raise DiffError(
                f"unexposed control order is not canonical for '{name}'"
            )
        if (
            unexposed_arguments
            and report_tool["schema_closes_unknown_arguments"] is False
            and report_tool.get("schema_review_required") is not True
        ):
            raise DiffError(
                f"tool '{name}' has unexposed controls on an open schema but "
                "does not require schema review"
            )

    expected_tool_order = [name for name in report_tools if name in tools_seen]
    if declared_tool_order != expected_tool_order:
        raise DiffError("declared control tool order does not match report order")

    for name, report_tool in report_tools.items():
        if (
            report_tool.get("declared_risk") is not None
            or report_tool.get("branch_risk") is not None
        ) and name not in tools_seen:
            raise DiffError(
                f"report tool '{name}' exposes declared risk without the matching "
                "declared control tool"
            )


def _validate_report_cardinalities(
    tools: list[dict[str, Any]],
    declared_controls: dict[str, Any] | None,
    *,
    label: str,
) -> None:
    """Require imported reports to stay within scanner-emittable ceilings."""

    arguments = sum(len(tool["arguments"]) for tool in tools)
    enum_members = 0
    for tool in tools:
        for argument in tool["arguments"]:
            constraints = argument.get("constraints")
            if type(constraints) is not dict:
                continue
            enum = constraints.get("enum")
            if type(enum) is dict and type(enum.get("count")) is int:
                enum_members += enum["count"]

    control_collection_members = 0
    if declared_controls is not None:
        for tool in declared_controls["tools"]:
            arguments += len(tool["unexposed_arguments"])
            risk = tool.get("risk")
            if risk is not None:
                control_collection_members += len(risk["effects"])
            branches = tool.get("branches")
            if branches is not None:
                control_collection_members += len(branches["cases"])
                for case in branches["cases"]:
                    control_collection_members += len(case["effects"])
                    control_collection_members += len(case["active_arguments"])
            for argument in tool["arguments"]:
                control_collection_members += len(argument.get("bounds", []))

    counts = (
        ("tool-definition", len(tools), MAX_SCAN_TOOL_DEFINITIONS),
        ("argument", arguments, MAX_SCAN_ARGUMENTS),
        ("enum-member", enum_members, MAX_SCAN_ENUM_MEMBERS),
        (
            "control collection-member",
            control_collection_members,
            MAX_SCAN_CONTROL_COLLECTION_MEMBERS,
        ),
    )
    for kind, count, limit in counts:
        if count > limit:
            raise DiffError(
                f"{label} exceeds the scanner {kind} limit of {limit}; rescan "
                "the original schema with the current scanner"
            )


def _control_declaration_fingerprint(value: dict[str, Any]) -> str:
    """Recompute the scanner's stable fingerprint for declared controls."""

    normalized = {
        "version": value["version"],
        "tools": value["tools"],
    }
    try:
        encoded = json.dumps(
            normalized,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise DiffError("declared controls are not canonical JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _validate_report(report: Any, *, label: str) -> dict[str, Any]:
    try:
        validate_plain_json(report, field=label)
    except SchemaError as exc:
        raise DiffError(str(exc)) from exc
    if type(report) is not dict:
        raise DiffError(f"{label} is not a Verb Authority JSON report")
    report_version = report.get("report_version")
    if type(report_version) is int and report_version in {2, 3}:
        raise DiffError(
            f"{label} uses legacy report version {report_version}; rescan the "
            "original schema with report version "
            f"{_SUPPORTED_REPORT_VERSION} before diffing"
        )
    if report.get("generator") != "verb-authority":
        raise DiffError(
            f"{label} is report-shaped but has a missing or invalid generator"
        )
    if (
        type(report_version) is not int
        or report_version not in _COMPATIBLE_REPORT_VERSIONS
    ):
        raise DiffError(
            f"{label} uses unsupported report version "
            f"{report_version!r}; expected one of "
            + ", ".join(str(version) for version in sorted(_COMPATIBLE_REPORT_VERSIONS))
        )
    _reject_unknown_fields(
        report,
        allowed={
            "report_version",
            "generator",
            "privacy",
            "schema_fingerprint_sha256",
            "summary",
            "tools",
            "declared_controls",
            "control_declaration_fingerprint_sha256",
        },
        field=label,
    )
    _require_sha256(
        report.get("schema_fingerprint_sha256"),
        field=f"{label} schema_fingerprint_sha256",
    )
    privacy = _require_object(
        report.get("privacy"), field=f"{label} privacy metadata"
    )
    _reject_unknown_fields(
        privacy,
        allowed={
            "network_used",
            "server_executed",
            "descriptions_included",
            "examples_included",
            "defaults_included",
            "runtime_values_included",
            "schema_constraint_values_included",
            "enum_values_included",
            "enum_value_fingerprints_included",
            "enum_value_fingerprints_dictionary_guessable",
            "branch_value_fingerprints_included",
            "branch_value_fingerprints_dictionary_guessable",
            "schema_material_fingerprints_included",
            "schema_material_fingerprints_dictionary_guessable",
            "unmodeled_schema_fingerprints_included",
            "schema_fingerprint_material_scope",
            "names_redacted",
            "control_declarations_included",
        },
        field=f"{label} privacy metadata",
    )
    names_redacted = privacy.get("names_redacted")
    if type(names_redacted) is not bool:
        raise DiffError(f"{label} has invalid report privacy metadata")
    exact_constraints_included = not names_redacted
    expected_fingerprint_scope = (
        "modeled_presence_and_enum_count_only"
        if names_redacted
        else "full_validation_material_excluding_annotations"
    )
    if (
        privacy.get("network_used") is not False
        or privacy.get("server_executed") is not False
        or privacy.get("descriptions_included") is not False
        or privacy.get("examples_included") is not False
        or privacy.get("defaults_included") is not False
        or privacy.get("runtime_values_included") is not False
        or privacy.get("enum_values_included") is not False
        or privacy.get("schema_constraint_values_included")
        is not exact_constraints_included
        or privacy.get("enum_value_fingerprints_included")
        is not exact_constraints_included
        or privacy.get("enum_value_fingerprints_dictionary_guessable")
        is not exact_constraints_included
        or privacy.get("branch_value_fingerprints_included") is not True
        or privacy.get("branch_value_fingerprints_dictionary_guessable") is not True
        or privacy.get("schema_material_fingerprints_included")
        is not exact_constraints_included
        or privacy.get("schema_material_fingerprints_dictionary_guessable")
        is not exact_constraints_included
        or privacy.get("unmodeled_schema_fingerprints_included")
        is not exact_constraints_included
        or privacy.get("schema_fingerprint_material_scope")
        != expected_fingerprint_scope
        or type(privacy.get("control_declarations_included")) is not bool
    ):
        raise DiffError(f"{label} has invalid constraint privacy metadata")

    summary = _require_object(report.get("summary"), field=f"{label} summary")
    required_summary_fields = {
        "tools",
        "parameters",
        "protected_parameters",
        "data_fillable_parameters",
        "review_required",
        "confirmation_required_tools",
        "risk_review_required_tools",
        "risk_conflicts",
        "annotation_conflicts",
        "schema_review_required_tools",
        "branch_risk_review_required_tools",
    }
    if report_version >= 5:
        required_summary_fields.add("review_required_tools")
    _reject_unknown_fields(
        summary,
        allowed=required_summary_fields,
        field=f"{label} summary",
    )
    if "schema_review_required_tools" not in summary:
        raise DiffError(
            f"{label} is missing summary.schema_review_required_tools; rescan "
            "the original schema with the current scanner"
        )
    if not required_summary_fields.issubset(summary) or any(
        type(value) is not int or value < 0 for value in summary.values()
    ):
        raise DiffError(f"{label} has invalid report summary")

    tools = _require_array(report.get("tools"), field=f"{label} tools")
    if not tools:
        raise DiffError(
            f"{label} contains no tool definitions; rescan the original schema "
            "with the current scanner"
        )
    tool_names: set[str] = set()
    report_tools: dict[str, dict[str, Any]] = {}
    report_arguments: dict[str, dict[str, dict[str, Any]]] = {}
    for raw_tool in tools:
        tool_name, argument_names = _validate_report_tool(
            raw_tool,
            seen=tool_names,
            require_fingerprints=not names_redacted,
            report_version=report_version,
        )
        report_tools[tool_name] = raw_tool
        report_arguments[tool_name] = {
            argument["name"]: argument for argument in raw_tool["arguments"]
        }
        if set(report_arguments[tool_name]) != argument_names:
            raise DiffError(f"tool '{tool_name}' argument index is inconsistent")

    expected_summary = {
        "tools": len(tools),
        "parameters": sum(len(tool["arguments"]) for tool in tools),
        "protected_parameters": sum(
            argument["policy"] == "trusted_fixed"
            for tool in tools
            for argument in tool["arguments"]
        ),
        "data_fillable_parameters": sum(
            argument["policy"] != "trusted_fixed"
            for tool in tools
            for argument in tool["arguments"]
        ),
        "review_required": sum(
            argument["review_required"] is True
            for tool in tools
            for argument in tool["arguments"]
        ),
        "confirmation_required_tools": sum(
            tool["needs_confirmation"] is True for tool in tools
        ),
        "risk_review_required_tools": sum(
            tool["risk_review_required"] is True for tool in tools
        ),
        "risk_conflicts": sum(tool["risk_conflict"] is True for tool in tools),
        "annotation_conflicts": sum(
            len(tool["annotation_conflicts"]) for tool in tools
        ),
        "branch_risk_review_required_tools": sum(
            tool["branch_risk_review_required"] is True for tool in tools
        ),
    }
    for field, expected_value in expected_summary.items():
        if summary[field] != expected_value:
            raise DiffError(f"{label} summary.{field} does not match its tools")

    if summary["schema_review_required_tools"] != sum(
        tool["schema_review_required"] is True for tool in tools
    ):
        raise DiffError(
            f"{label} summary.schema_review_required_tools does not match its tools"
        )

    controls_included = privacy["control_declarations_included"]
    validated_declared_controls: dict[str, Any] | None = None
    if controls_included:
        if "declared_controls" not in report:
            raise DiffError(f"{label} is missing declared_controls")
        declared_fingerprint = _require_sha256(
            report.get("control_declaration_fingerprint_sha256"),
            field=f"{label} control declaration fingerprint",
        )
        _validate_declared_controls(
            report["declared_controls"],
            report_tools=report_tools,
            report_arguments=report_arguments,
            names_redacted=names_redacted,
        )
        validated_declared_controls = report["declared_controls"]
        if declared_fingerprint != _control_declaration_fingerprint(
            report["declared_controls"]
        ):
            raise DiffError(
                f"{label} control declaration fingerprint does not match its controls"
            )
    elif "declared_controls" in report or "control_declaration_fingerprint_sha256" in report:
        raise DiffError(f"{label} has inconsistent declared control metadata")
    elif any(
        tool["declared_risk"] is not None or tool["branch_risk"] is not None
        for tool in tools
    ):
        raise DiffError(
            f"{label} exposes declared risk without declared control metadata"
        )

    for tool in tools:
        _validate_or_derive_tool_review(
            tool,
            name=tool["name"],
            report_version=report_version,
        )
    if report_version >= 5:
        expected_review_required_tools = sum(
            tool["review_required"] is True for tool in tools
        )
        if summary["review_required_tools"] != expected_review_required_tools:
            raise DiffError(
                f"{label} summary.review_required_tools does not match its tools"
            )

    _validate_report_cardinalities(
        tools,
        validated_declared_controls,
        label=label,
    )

    if names_redacted is True:
        raise DiffError(
            f"{label} has redacted names; diff requires stable tool and argument "
            "names. Compare non-redacted local reports instead."
        )
    return report


def _validated_constraints(
    value: Any, *, tool: str, argument: str
) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise DiffError(f"argument constraints must be an object: {tool}.{argument}")
    unknown = sorted(set(value) - {"maximum", "max_length", "enum"})
    if unknown:
        raise DiffError(
            f"argument constraints contain unsupported fields: {tool}.{argument}"
        )

    normalized: dict[str, Any] = {}
    if "maximum" in value:
        maximum = value["maximum"]
        if type(maximum) is int:
            normalized_maximum: int | str = maximum
        elif type(maximum) is str:
            try:
                parsed = Decimal(maximum)
            except InvalidOperation as exc:
                raise DiffError(
                    f"argument maximum is invalid: {tool}.{argument}"
                ) from exc
            if not parsed.is_finite() or canonical_decimal_text(parsed) != maximum:
                raise DiffError(f"argument maximum is invalid: {tool}.{argument}")
            normalized_maximum = maximum
        else:
            raise DiffError(f"argument maximum is invalid: {tool}.{argument}")
        normalized["maximum"] = normalized_maximum

    if "max_length" in value:
        max_length = value["max_length"]
        if type(max_length) is not int or max_length < 0:
            raise DiffError(f"argument max_length is invalid: {tool}.{argument}")
        normalized["max_length"] = max_length

    if "enum" in value:
        enum = value["enum"]
        if not isinstance(enum, dict) or set(enum) != {
            "count",
            "value_fingerprints_sha256",
        }:
            raise DiffError(f"argument enum constraint is invalid: {tool}.{argument}")
        count = enum["count"]
        fingerprints = enum["value_fingerprints_sha256"]
        if type(count) is not int or count < 0 or not isinstance(fingerprints, list):
            raise DiffError(f"argument enum constraint is invalid: {tool}.{argument}")
        if (
            len(fingerprints) != count
            or fingerprints != sorted(set(fingerprints))
            or any(
                not isinstance(item, str)
                or len(item) != 64
                or any(character not in "0123456789abcdef" for character in item)
                for item in fingerprints
            )
        ):
            raise DiffError(f"argument enum constraint is invalid: {tool}.{argument}")
        normalized["enum"] = {
            "count": count,
            "value_fingerprints_sha256": list(fingerprints),
        }
    return normalized


def load_report_or_schema(
    path: str,
    *,
    controls_path: str | None = None,
    label: str = "input",
) -> dict[str, Any]:
    """Load a report, or scan a raw schema export before diffing it."""

    document = load_json_path(path)
    if _is_report_shaped(document):
        if controls_path is not None:
            raise DiffError(
                f"{label} is already a report; do not also pass a controls file"
            )
        if type(document) is not dict:
            raise DiffError(
                f"{label} is report-shaped but is not a complete "
                "Verb Authority JSON report"
            )
        return _validate_report(document, label=label)

    controls = load_json_path(controls_path) if controls_path is not None else None
    report = scan_documents([document], control_declarations=controls)
    return _validate_report(report, label=label)


def load_raw_schema(
    path: str,
    *,
    controls_path: str | None = None,
    label: str = "input",
) -> dict[str, Any]:
    """Load and locally scan one raw schema for an enforcement decision."""

    document = load_json_path(path)
    if _is_report_shaped(document):
        raise DiffError(
            f"{label} is report-shaped; failure thresholds require raw "
            "schema inputs that Authority Diff rescans locally"
        )
    controls = load_json_path(controls_path) if controls_path is not None else None
    report = scan_documents([document], control_declarations=controls)
    return _validate_report(report, label=label)


def _index_report(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for raw_tool in report["tools"]:
        name = raw_tool.get("name")
        if not isinstance(name, str) or not name:
            raise DiffError("report contains a tool without a stable name")
        if name in indexed:
            raise DiffError(f"report contains duplicate tool name: {name}")
        arguments: dict[str, dict[str, Any]] = {}
        for raw_argument in raw_tool.get("arguments", []):
            argument_name = raw_argument.get("name")
            if not isinstance(argument_name, str) or not argument_name:
                raise DiffError(f"tool '{name}' contains an unnamed argument")
            arguments[argument_name] = {
                "schema_exposure": "exposed",
                "inferred_policy": raw_argument.get("policy"),
                "review_required": raw_argument.get("review_required"),
                "type": raw_argument.get("type"),
                "required": raw_argument.get("required"),
                "constraints": _validated_constraints(
                    raw_argument.get("constraints"),
                    tool=name,
                    argument=argument_name,
                ),
                "schema_material_fingerprint_sha256": raw_argument[
                    "schema_material_fingerprint_sha256"
                ],
                "unmodeled_schema_fingerprint_sha256": raw_argument[
                    "unmodeled_schema_fingerprint_sha256"
                ],
            }
        review_sources = raw_tool.get("review_sources")
        if review_sources is None:
            review_sources = _tool_review_sources(
                arguments=raw_tool["arguments"],
                schema_review_required=raw_tool["schema_review_required"],
                risk_review_required=raw_tool["risk_review_required"],
                risk_conflict=raw_tool["risk_conflict"],
                annotation_assessments=raw_tool["annotation_assessments"],
                branch_risk_review_required=raw_tool[
                    "branch_risk_review_required"
                ],
            )
        review_required = raw_tool.get("review_required")
        if review_required is None:
            review_required = _tool_review_required(review_sources)
        indexed[name] = {
            "risk": raw_tool.get("risk"),
            "risk_source": raw_tool.get("risk_source"),
            "risk_evidence": raw_tool.get("risk_evidence"),
            "inferred_risk": raw_tool.get("inferred_risk"),
            "risk_inference": raw_tool.get("risk_inference"),
            "declared_risk": raw_tool.get("declared_risk"),
            "risk_conflict": raw_tool.get("risk_conflict"),
            "risk_review_required": raw_tool.get("risk_review_required"),
            "review_required": review_required,
            "review_sources": review_sources,
            "needs_confirmation": raw_tool.get("needs_confirmation"),
            "annotation_assessments": raw_tool["annotation_assessments"],
            "annotation_conflicts": raw_tool["annotation_conflicts"],
            "branch_risk": raw_tool["branch_risk"],
            "branch_risk_review_required": raw_tool[
                "branch_risk_review_required"
            ],
            "schema_closes_unknown_arguments": raw_tool.get(
                "schema_closes_unknown_arguments"
            ),
            "schema_review_required": raw_tool["schema_review_required"],
            "schema_material_fingerprint_sha256": raw_tool[
                "schema_material_fingerprint_sha256"
            ],
            "unmodeled_schema_fingerprint_sha256": raw_tool[
                "unmodeled_schema_fingerprint_sha256"
            ],
            "arguments": arguments,
        }

    declared = report.get("declared_controls")
    if declared is None:
        return indexed
    for raw_tool in declared.get("tools", []):
        name = raw_tool.get("name")
        if name not in indexed:
            raise DiffError(f"declared controls reference unknown report tool: {name}")
        indexed_tool = indexed[name]
        indexed_tool["schema_closes_unknown_arguments"] = raw_tool.get(
            "schema_closes_unknown_arguments"
        )
        for raw_argument in raw_tool.get("arguments", []):
            argument_name = raw_argument.get("name")
            if argument_name not in indexed_tool["arguments"]:
                raise DiffError(
                    f"declared controls reference unknown argument: "
                    f"{name}.{argument_name}"
                )
            indexed_argument = indexed_tool["arguments"][argument_name]
            indexed_argument.update(
                {
                    "declared_authority": raw_argument.get("authority"),
                    "evidence": raw_argument.get("evidence"),
                    "bounds": raw_argument.get("bounds", []),
                }
            )
        for raw_argument in raw_tool.get("unexposed_arguments", []):
            argument_name = raw_argument.get("name")
            if not isinstance(argument_name, str) or not argument_name:
                raise DiffError(f"tool '{name}' contains an unnamed control")
            if argument_name in indexed_tool["arguments"]:
                raise DiffError(
                    f"argument is both exposed and unexposed: "
                    f"{name}.{argument_name}"
                )
            indexed_tool["arguments"][argument_name] = {
                "schema_exposure": "unexposed",
                "exposure": raw_argument.get("exposure"),
                "evidence": raw_argument.get("evidence"),
                "enforced_by": raw_argument.get("enforced_by"),
            }
    return indexed


def _change(
    classification: str,
    kind: str,
    tool: str,
    *,
    message: str,
    argument: str | None = None,
    field: str | None = None,
    before: Any = None,
    after: Any = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "classification": classification,
        "kind": kind,
        "tool": tool,
        "message": message,
    }
    if argument is not None:
        item["argument"] = argument
    if field is not None:
        item["field"] = field
        item["before"] = before
        item["after"] = after
    return item


def _classify_branch_risk_change(
    before: dict[str, Any] | None,
    after: dict[str, Any] | None,
) -> tuple[str, str]:
    """Classify pure active-argument set changes; keep all others advisory."""

    if before is None or after is None:
        return "review", "Selector branch declarations were added or removed."
    if (
        before.get("source") != after.get("source")
        or before.get("selector") != after.get("selector")
        or before.get("value_disclosure") != after.get("value_disclosure")
    ):
        return "review", "Selector branch identity or evidence changed."
    before_cases = {
        case["value_fingerprint_sha256"]: case for case in before["cases"]
    }
    after_cases = {
        case["value_fingerprint_sha256"]: case for case in after["cases"]
    }
    expanded = False
    reduced = False
    other_changed = False
    for fingerprint in set(before_cases) & set(after_cases):
        before_case = before_cases[fingerprint]
        after_case = after_cases[fingerprint]
        before_other = {
            key: value
            for key, value in before_case.items()
            if key != "active_arguments"
        }
        after_other = {
            key: value
            for key, value in after_case.items()
            if key != "active_arguments"
        }
        if before_other != after_other:
            other_changed = True
        before_active = set(before_case["active_arguments"])
        after_active = set(after_case["active_arguments"])
        # Any newly admitted argument is an authority increase, even when the
        # same edit also removes another argument (set-incomparable
        # replacement) or changes branch risk/evidence. Removals cannot cancel
        # the larger caller-visible surface introduced by the addition.
        if after_active - before_active:
            expanded = True
        if before_active - after_active:
            reduced = True

    # A simultaneous risk/evidence edit or reduction must never mask a known
    # expansion. Any existing exact case that accepts another argument has a
    # concrete larger caller-controlled surface and must trip the increase
    # threshold.
    if expanded:
        return (
            "authority_increase",
            "One or more branches now admit additional caller-visible arguments.",
        )
    if set(before_cases) != set(after_cases):
        return "review", "The set of selector branch cases changed."
    if other_changed:
        return "review", "Branch risk or supporting evidence changed."
    if reduced:
        return (
            "protection_increase",
            "One or more branches now admit fewer caller-visible arguments.",
        )
    return "review", "Branch active-argument applicability changed ambiguously."


def _ranked_change(
    changes: list[dict[str, Any]],
    *,
    kind: str,
    tool: str,
    argument: str | None,
    field: str,
    before: str,
    after: str,
    ranks: dict[str, int],
    increase_message: str,
    reduction_message: str,
    review_message: str,
) -> None:
    before_rank = ranks.get(before)
    after_rank = ranks.get(after)
    if before_rank is not None and after_rank is not None and after_rank > before_rank:
        classification = "authority_increase"
        message = increase_message
    elif before_rank is not None and after_rank is not None and after_rank < before_rank:
        classification = "protection_increase"
        message = reduction_message
    else:
        classification = "review"
        message = review_message
    changes.append(
        _change(
            classification,
            kind,
            tool,
            argument=argument,
            field=field,
            before=before,
            after=after,
            message=message,
        )
    )


def _bounds_classification(
    before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> str:
    before_status = [
        bound.get("operational_status", "not_stated") for bound in before
    ]
    after_status = [
        bound.get("operational_status", "not_stated") for bound in after
    ]
    if "not_stated" in before_status or "not_stated" in after_status:
        return "review"

    mutability_rank = {"caller": 0, "trusted_party": 1, "immutable": 2}

    def structured_strengths(
        bounds: list[dict[str, Any]], statuses: list[str]
    ) -> dict[str, list[int]]:
        groups: dict[str, list[int]] = {}
        for bound, status in zip(bounds, statuses):
            identity = dict(bound)
            identity.pop("bounds_mutability", None)
            identity.pop("operational_status", None)
            key = json.dumps(
                identity,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            strength = (
                mutability_rank.get(bound.get("bounds_mutability"), -1)
                if status == "enforced"
                else -1
            )
            groups.setdefault(key, []).append(strength)
        for values in groups.values():
            values.sort()
        return groups

    before_strengths = structured_strengths(before, before_status)
    after_strengths = structured_strengths(after, after_status)

    def dominates_protective_baseline(
        candidate: list[int], baseline: list[int]
    ) -> bool:
        required = [strength for strength in baseline if strength >= 1]
        available = list(candidate)
        candidate_index = 0
        for required_strength in required:
            while (
                candidate_index < len(available)
                and available[candidate_index] < required_strength
            ):
                candidate_index += 1
            if candidate_index == len(available):
                return False
            candidate_index += 1
        return True

    # A different new bound cannot erase a known weakening of the same
    # source/enforcement identity. Opaque replacement identities remain review.
    for identity in before_strengths.keys() & after_strengths.keys():
        if not dominates_protective_baseline(
            after_strengths[identity], before_strengths[identity]
        ):
            return "authority_increase"

    def canonical_protective(
        bounds: list[dict[str, Any]], statuses: list[str]
    ) -> Counter[str]:
        return Counter(
            json.dumps(
                bound,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for bound, status in zip(bounds, statuses)
            if status == "enforced"
            and bound.get("bounds_mutability") in {"trusted_party", "immutable"}
        )

    before_protective = canonical_protective(before, before_status)
    after_protective = canonical_protective(after, after_status)

    def canonical_nonprotective(
        bounds: list[dict[str, Any]], statuses: list[str]
    ) -> Counter[str]:
        return Counter(
            json.dumps(
                bound,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for bound, status in zip(bounds, statuses)
            if not (
                status == "enforced"
                and bound.get("bounds_mutability")
                in {"trusted_party", "immutable"}
            )
        )

    before_nonprotective = canonical_nonprotective(before, before_status)
    after_nonprotective = canonical_nonprotective(after, after_status)

    def canonical_bound(bound: dict[str, Any]) -> str:
        return json.dumps(
            bound,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    def structured_entries(
        bounds: list[dict[str, Any]], statuses: list[str]
    ) -> dict[str, list[tuple[int, int, str]]]:
        groups: dict[str, list[tuple[int, int, str]]] = {}
        for bound, status in zip(bounds, statuses):
            identity = dict(bound)
            identity.pop("bounds_mutability", None)
            identity.pop("operational_status", None)
            identity_key = canonical_bound(identity)
            declared_strength = mutability_rank.get(
                bound.get("bounds_mutability"),
                -1,
            )
            effective_strength = (
                declared_strength
                if status == "enforced"
                else -1
            )
            groups.setdefault(identity_key, []).append(
                (effective_strength, declared_strength, canonical_bound(bound))
            )
        return groups

    before_entries = structured_entries(before, before_status)
    after_entries = structured_entries(after, after_status)
    unexplained_before_nonprotective = before_nonprotective.copy()
    unexplained_after_nonprotective = after_nonprotective.copy()
    for identity in before_entries.keys() & after_entries.keys():
        before_identity = before_entries[identity]
        after_identity = after_entries[identity]
        if len(before_identity) != 1 or len(after_identity) != 1:
            continue
        (
            before_strength,
            before_declared_strength,
            before_canonical,
        ) = before_identity[0]
        (
            after_strength,
            after_declared_strength,
            after_canonical,
        ) = after_identity[0]
        if (
            after_strength >= 1
            and after_strength > before_strength
            and after_declared_strength >= before_declared_strength
        ):
            unexplained_before_nonprotective.subtract([before_canonical])
            unexplained_after_nonprotective.subtract([after_canonical])
    unexplained_before_nonprotective += Counter()
    unexplained_after_nonprotective += Counter()

    def canonical_non_enforced(
        bounds: list[dict[str, Any]], statuses: list[str]
    ) -> Counter[str]:
        return Counter(
            json.dumps(
                bound,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            for bound, status in zip(bounds, statuses)
            if status != "enforced"
        )

    before_non_enforced = canonical_non_enforced(before, before_status)
    after_non_enforced = canonical_non_enforced(after, after_status)
    before_retained = before_protective <= after_protective
    after_retained = after_protective <= before_protective
    if after_retained and not before_retained:
        return "authority_increase"
    if before_retained and not after_retained:
        if (
            unexplained_before_nonprotective
            == unexplained_after_nonprotective
        ):
            return "protection_increase"
        return "review"

    # Mutability is structured evidence, unlike an author-written source or
    # enforcement description. If the exact same enforced bounds remain and
    # only that field changes, order the change explicitly. New/replaced
    # opaque claims still fall through to review and cannot mask a weakening.
    def identity_groups(
        bounds: list[dict[str, Any]], statuses: list[str]
    ) -> dict[str, list[int]]:
        groups: dict[str, list[int]] = {}
        for bound, status in zip(bounds, statuses):
            if status != "enforced":
                continue
            mutability = bound.get("bounds_mutability")
            if mutability not in mutability_rank:
                continue
            identity = dict(bound)
            identity.pop("bounds_mutability", None)
            key = json.dumps(
                identity,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            groups.setdefault(key, []).append(mutability_rank[mutability])
        for values in groups.values():
            values.sort()
        return groups

    before_groups = identity_groups(before, before_status)
    after_groups = identity_groups(after, after_status)
    if before_groups.keys() == after_groups.keys() and all(
        len(before_groups[key]) == len(after_groups[key])
        for key in before_groups
    ):
        comparisons = [
            after_rank - before_rank
            for key in before_groups
            for before_rank, after_rank in zip(
                before_groups[key], after_groups[key]
            )
        ]
        if comparisons and all(delta <= 0 for delta in comparisons) and any(
            delta < 0 for delta in comparisons
        ):
            return "authority_increase"
        if comparisons and all(delta >= 0 for delta in comparisons) and any(
            delta > 0 for delta in comparisons
        ):
            if before_non_enforced == after_non_enforced:
                return "protection_increase"
            return "review"
    # Replacing one declared control with another is not ordered merely by its
    # mutability label or by the number of bounds. Only exact retained enforced
    # controls establish addition/removal; replacements and caller/specification
    # drift remain explicit review debt.
    return "review"


def _compare_upper_constraint(
    changes: list[dict[str, Any]],
    *,
    tool: str,
    argument: str,
    field: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    before_present = field in before
    after_present = field in after
    if field == "maximum":
        before_comparable = (
            Decimal(before[field]) if before_present else None
        )
        after_comparable = Decimal(after[field]) if after_present else None
    else:
        before_comparable = before.get(field)
        after_comparable = after.get(field)
    if before_present == after_present and (
        not before_present or before_comparable == after_comparable
    ):
        return

    before_value = before.get(field)
    after_value = after.get(field)
    if before_present and not after_present:
        classification = "authority_increase"
        message = f"The schema {field.replace('_', ' ')} was removed."
    elif not before_present and after_present:
        classification = "protection_increase"
        message = f"The schema gained a {field.replace('_', ' ')}."
    elif after_comparable > before_comparable:
        classification = "authority_increase"
        message = f"The schema {field.replace('_', ' ')} was widened."
    else:
        classification = "protection_increase"
        message = f"The schema {field.replace('_', ' ')} was tightened."
    changes.append(
        _change(
            classification,
            f"{field}_changed",
            tool,
            argument=argument,
            field=f"constraints.{field}",
            before=before_value,
            after=after_value,
            message=message,
        )
    )


def _compare_enum_constraint(
    changes: list[dict[str, Any]],
    *,
    tool: str,
    argument: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    before_enum = before.get("enum")
    after_enum = after.get("enum")
    if before_enum == after_enum:
        return

    if before_enum is None:
        classification = "protection_increase"
        message = "The schema gained an enum constraint."
    elif after_enum is None:
        classification = "authority_increase"
        message = "The schema enum constraint was removed."
    else:
        before_values = set(before_enum["value_fingerprints_sha256"])
        after_values = set(after_enum["value_fingerprints_sha256"])
        if before_values < after_values:
            classification = "authority_increase"
            message = "The schema enum added caller-selectable values."
        elif after_values < before_values:
            classification = "protection_increase"
            message = "The schema enum removed caller-selectable values."
        else:
            classification = "review"
            message = "The schema enum changed without a strict set relationship."
    changes.append(
        _change(
            classification,
            "enum_changed",
            tool,
            argument=argument,
            field="constraints.enum",
            before=before_enum,
            after=after_enum,
            message=message,
        )
    )


def _compare_schema_constraints(
    changes: list[dict[str, Any]],
    *,
    tool: str,
    argument: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    for field in ("maximum", "max_length"):
        _compare_upper_constraint(
            changes,
            tool=tool,
            argument=argument,
            field=field,
            before=before,
            after=after,
        )
    _compare_enum_constraint(
        changes,
        tool=tool,
        argument=argument,
        before=before,
        after=after,
    )


def _compare_unmodeled_schema(
    changes: list[dict[str, Any]],
    *,
    tool: str,
    before: dict[str, Any],
    after: dict[str, Any],
    argument: str | None = None,
) -> None:
    field = "unmodeled_schema_fingerprint_sha256"
    if before[field] == after[field]:
        return
    changes.append(
        _change(
            "review",
            "unmodeled_schema_changed",
            tool,
            argument=argument,
            field=field,
            before=before[field],
            after=after[field],
            message=(
                "Schema validation material outside the explicitly modeled "
                "constraint vocabulary changed; inspect the original schemas."
            ),
        )
    )


def _compare_exposed_argument(
    changes: list[dict[str, Any]],
    tool: str,
    argument: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    before_policy = before.get("inferred_policy")
    after_policy = after.get("inferred_policy")
    if before_policy != after_policy:
        _ranked_change(
            changes,
            kind="inferred_policy_changed",
            tool=tool,
            argument=argument,
            field="inferred_policy",
            before=before_policy,
            after=after_policy,
            ranks=_POLICY_RANK,
            increase_message="Inferred caller authority increased.",
            reduction_message="Inferred caller authority decreased.",
            review_message="Inferred policy changed and needs review.",
        )

    before_declared = before.get("declared_authority")
    after_declared = after.get("declared_authority")
    if before_declared is None and after_declared is not None:
        changes.append(
            _change(
                "review",
                "declared_control_added",
                tool,
                argument=argument,
                field="declared_authority",
                before=None,
                after=after_declared,
                message="Author-supplied control evidence was added.",
            )
        )
    elif before_declared is not None and after_declared is None:
        changes.append(
            _change(
                "review",
                "declared_control_removed",
                tool,
                argument=argument,
                field="declared_authority",
                before=before_declared,
                after=None,
                message="Author-supplied control evidence was removed.",
            )
        )
    elif before_declared != after_declared:
        _ranked_change(
            changes,
            kind="declared_authority_changed",
            tool=tool,
            argument=argument,
            field="declared_authority",
            before=before_declared,
            after=after_declared,
            ranks=_DECLARED_AUTHORITY_RANK,
            increase_message="Declared caller authority increased.",
            reduction_message="Declared caller authority decreased.",
            review_message="Declared authority changed and needs review.",
        )

    if before.get("evidence") != after.get("evidence") and (
        before.get("evidence") is not None or after.get("evidence") is not None
    ):
        changes.append(
            _change(
                "review",
                "evidence_changed",
                tool,
                argument=argument,
                field="evidence",
                before=before.get("evidence"),
                after=after.get("evidence"),
                message="Control evidence status changed.",
            )
        )

    before_bounds = before.get("bounds", [])
    after_bounds = after.get("bounds", [])
    if before_bounds != after_bounds:
        classification = _bounds_classification(before_bounds, after_bounds)
        messages = {
            "authority_increase": (
                "The declared bound chain lost or weakened a currently "
                "enforced control."
            ),
            "protection_increase": (
                "The declared bound chain gained or strengthened a currently "
                "enforced control."
            ),
            "review": (
                "The declared bound chain changed without a proven change to "
                "currently enforced controls."
            ),
        }
        changes.append(
            _change(
                classification,
                "bounds_changed",
                tool,
                argument=argument,
                field="bounds",
                before=before_bounds,
                after=after_bounds,
                message=messages[classification],
            )
        )

    _compare_schema_constraints(
        changes,
        tool=tool,
        argument=argument,
        before=before.get("constraints", {}),
        after=after.get("constraints", {}),
    )
    _compare_unmodeled_schema(
        changes,
        tool=tool,
        argument=argument,
        before=before,
        after=after,
    )

    for field in ("type", "required", "review_required"):
        if before.get(field) != after.get(field):
            changes.append(
                _change(
                    "review",
                    f"{field}_changed",
                    tool,
                    argument=argument,
                    field=field,
                    before=before.get(field),
                    after=after.get(field),
                    message=f"Argument {field.replace('_', ' ')} changed.",
                )
            )


def _compare_unexposed_argument(
    changes: list[dict[str, Any]],
    tool: str,
    argument: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    for field in ("exposure", "evidence", "enforced_by"):
        if before.get(field) != after.get(field):
            changes.append(
                _change(
                    "review",
                    f"unexposed_{field}_changed",
                    tool,
                    argument=argument,
                    field=field,
                    before=before.get(field),
                    after=after.get(field),
                    message=f"Unexposed control {field.replace('_', ' ')} changed.",
                )
            )


def diff_reports(
    before_report: dict[str, Any], after_report: dict[str, Any]
) -> dict[str, Any]:
    """Return a deterministic, machine-readable advisory authority diff.

    Callers that enforce the result must derive reports from trusted raw inputs
    or authenticate them independently. Structural coherence is not provenance.
    """

    before_report = _validate_report(before_report, label="before report")
    after_report = _validate_report(after_report, label="after report")
    before_tools = _index_report(before_report)
    after_tools = _index_report(after_report)
    changes: list[dict[str, Any]] = []

    for tool in sorted(set(before_tools) | set(after_tools)):
        before_tool = before_tools.get(tool)
        after_tool = after_tools.get(tool)
        if before_tool is None:
            changes.append(
                _change(
                    "authority_increase",
                    "tool_added",
                    tool,
                    message="A new caller-visible tool was added.",
                )
            )
            continue
        if after_tool is None:
            changes.append(
                _change(
                    "protection_increase",
                    "tool_removed",
                    tool,
                    message="A caller-visible tool was removed.",
                )
            )
            continue

        if before_tool["risk"] != after_tool["risk"]:
            changes.append(
                _change(
                    "review",
                    "tool_risk_changed",
                    tool,
                    field="risk",
                    before=before_tool["risk"],
                    after=after_tool["risk"],
                    message="Tool risk class changed and needs review.",
                )
            )

        for field, kind, message in (
            (
                "risk_source",
                "risk_source_changed",
                "The source of the effective risk tier changed.",
            ),
            (
                "risk_evidence",
                "risk_evidence_changed",
                "The evidence status for the effective risk tier changed.",
            ),
            (
                "inferred_risk",
                "inferred_risk_changed",
                "The advisory tool-name risk heuristic changed.",
            ),
            (
                "risk_inference",
                "risk_inference_changed",
                "The signal or evidence behind the risk heuristic changed.",
            ),
            (
                "declared_risk",
                "declared_risk_changed",
                "The author-supplied risk tier or effects changed.",
            ),
            (
                "risk_conflict",
                "risk_conflict_changed",
                "The conflict between declared and heuristic risk changed.",
            ),
            (
                "risk_review_required",
                "risk_review_required_changed",
                "The tool-risk review requirement changed.",
            ),
        ):
            if before_tool[field] != after_tool[field]:
                changes.append(
                    _change(
                        "review",
                        kind,
                        tool,
                        field=field,
                        before=before_tool[field],
                        after=after_tool[field],
                        message=message,
                    )
                )

        before_confirmation = before_tool["needs_confirmation"]
        after_confirmation = after_tool["needs_confirmation"]
        if before_confirmation != after_confirmation:
            if before_confirmation is True and after_confirmation is False:
                classification = "authority_increase"
                message = "Required human confirmation was removed."
            elif before_confirmation is False and after_confirmation is True:
                classification = "protection_increase"
                message = "Required human confirmation was added."
            else:
                classification = "review"
                message = "Human-confirmation behavior changed."
            changes.append(
                _change(
                    classification,
                    "confirmation_changed",
                    tool,
                    field="needs_confirmation",
                    before=before_confirmation,
                    after=after_confirmation,
                    message=message,
                )
            )

        before_closed = before_tool["schema_closes_unknown_arguments"]
        after_closed = after_tool["schema_closes_unknown_arguments"]
        if before_closed != after_closed and (
            before_closed is not None and after_closed is not None
        ):
            if before_closed is True and after_closed is False:
                classification = "authority_increase"
                message = "The schema no longer rejects unknown arguments."
            elif after_tool["schema_review_required"] is True:
                classification = "review"
                message = (
                    "The schema appears to reject unknown arguments but still "
                    "requires unresolved authority review."
                )
            else:
                classification = "protection_increase"
                message = "The schema now rejects unknown arguments."
            changes.append(
                _change(
                    classification,
                    "unknown_arguments_changed",
                    tool,
                    field="schema_closes_unknown_arguments",
                    before=before_closed,
                    after=after_closed,
                    message=message,
                )
            )

        before_schema_review = before_tool["schema_review_required"]
        after_schema_review = after_tool["schema_review_required"]
        if before_schema_review is not after_schema_review:
            classification = "review"
            if after_schema_review is True:
                message = (
                    "The schema now uses unresolved composition or references and "
                    "requires manual authority review."
                )
            else:
                message = (
                    "The unresolved schema-composition review requirement was "
                    "cleared and that resolution requires manual review."
                )
            changes.append(
                _change(
                    classification,
                    "schema_review_requirement_changed",
                    tool,
                    field="schema_review_required",
                    before=before_schema_review,
                    after=after_schema_review,
                    message=message,
                )
            )

        before_assessments = before_tool["annotation_assessments"]
        after_assessments = after_tool["annotation_assessments"]
        if before_assessments != after_assessments:
            changes.append(
                _change(
                    "review",
                    "annotation_assessments_changed",
                    tool,
                    field="annotation_assessments",
                    before=before_assessments,
                    after=after_assessments,
                    message="MCP annotation evidence or its assessment changed.",
                )
            )

        if before_tool["branch_risk"] != after_tool["branch_risk"]:
            classification, message = _classify_branch_risk_change(
                before_tool["branch_risk"], after_tool["branch_risk"]
            )
            changes.append(
                _change(
                    classification,
                    "branch_risk_changed",
                    tool,
                    field="branch_risk",
                    before=before_tool["branch_risk"],
                    after=after_tool["branch_risk"],
                    message=message,
                )
            )

        if (
            before_tool["branch_risk_review_required"]
            is not after_tool["branch_risk_review_required"]
        ):
            changes.append(
                _change(
                    "review",
                    "branch_risk_review_requirement_changed",
                    tool,
                    field="branch_risk_review_required",
                    before=before_tool["branch_risk_review_required"],
                    after=after_tool["branch_risk_review_required"],
                    message="The unresolved branch-risk review requirement changed.",
                )
            )

        _compare_unmodeled_schema(
            changes,
            tool=tool,
            before=before_tool,
            after=after_tool,
        )

        before_arguments = before_tool["arguments"]
        after_arguments = after_tool["arguments"]
        for argument in sorted(set(before_arguments) | set(after_arguments)):
            before_argument = before_arguments.get(argument)
            after_argument = after_arguments.get(argument)
            if before_argument is None:
                if after_argument["schema_exposure"] == "exposed":
                    changes.append(
                        _change(
                            "authority_increase",
                            "argument_added",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before=None,
                            after="exposed",
                            message="A new caller-visible argument was added.",
                        )
                    )
                else:
                    changes.append(
                        _change(
                            "review",
                            "unexposed_control_added",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before=None,
                            after="unexposed",
                            message="An author-supplied unexposed control was added.",
                        )
                    )
                continue
            if after_argument is None:
                if before_argument["schema_exposure"] == "exposed":
                    if after_tool["schema_closes_unknown_arguments"] is False:
                        classification = "authority_increase"
                        message = (
                            "A modeled argument disappeared, but its name remains "
                            "caller-visible through the open or dynamic schema."
                        )
                    elif after_tool["schema_review_required"] is True:
                        classification = "review"
                        message = (
                            "A modeled argument disappeared into a schema that "
                            "still requires unresolved authority review."
                        )
                    elif after_tool["schema_closes_unknown_arguments"] is True:
                        classification = "protection_increase"
                        message = "A caller-visible argument was removed."
                    else:
                        classification = "authority_increase"
                        message = (
                            "A modeled argument was removed while unknown arguments "
                            "remain caller-visible, so its authority policy no longer "
                            "protects that input name."
                        )
                    changes.append(
                        _change(
                            classification,
                            "argument_removed",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before="exposed",
                            after=None,
                            message=message,
                        )
                    )
                else:
                    changes.append(
                        _change(
                            "review",
                            "unexposed_control_removed",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before="unexposed",
                            after=None,
                            message="An author-supplied unexposed control was removed.",
                        )
                    )
                continue

            before_exposure = before_argument["schema_exposure"]
            after_exposure = after_argument["schema_exposure"]
            if before_exposure != after_exposure:
                if before_exposure == "unexposed" and after_exposure == "exposed":
                    classification = "authority_increase"
                    message = "A previously unexposed argument became caller-visible."
                else:
                    if after_tool["schema_closes_unknown_arguments"] is False:
                        classification = "authority_increase"
                        message = (
                            "The declaration calls this argument unexposed, but "
                            "the open or dynamic schema still admits its name."
                        )
                    elif after_tool["schema_review_required"] is True:
                        classification = "review"
                        message = (
                            "The argument became declared-unexposed inside a "
                            "schema with unresolved authority review."
                        )
                    elif after_tool["schema_closes_unknown_arguments"] is True:
                        classification = "protection_increase"
                        message = "A caller-visible argument became unexposed."
                    else:
                        classification = "authority_increase"
                        message = (
                            "The argument's modeled policy disappeared without "
                            "proof that its name is no longer caller-visible."
                        )
                changes.append(
                    _change(
                        classification,
                        "argument_exposure_changed",
                        tool,
                        argument=argument,
                        field="schema_exposure",
                        before=before_exposure,
                        after=after_exposure,
                        message=message,
                    )
                )
                continue

            if before_exposure == "exposed":
                _compare_exposed_argument(
                    changes, tool, argument, before_argument, after_argument
                )
            else:
                _compare_unexposed_argument(
                    changes, tool, argument, before_argument, after_argument
                )

    changes.sort(
        key=lambda item: (
            _CLASSIFICATION_ORDER[item["classification"]],
            item["tool"],
            item.get("argument", ""),
            item["kind"],
        )
    )
    counts = {
        classification: sum(
            change["classification"] == classification for change in changes
        )
        for classification in _CLASSIFICATION_ORDER
    }
    changed_tools = len({change["tool"] for change in changes})
    return {
        "diff_version": DIFF_VERSION,
        "generator": "verb-authority",
        "before": {
            "schema_fingerprint_sha256": before_report.get(
                "schema_fingerprint_sha256"
            ),
            "control_declaration_fingerprint_sha256": before_report.get(
                "control_declaration_fingerprint_sha256"
            ),
        },
        "after": {
            "schema_fingerprint_sha256": after_report.get(
                "schema_fingerprint_sha256"
            ),
            "control_declaration_fingerprint_sha256": after_report.get(
                "control_declaration_fingerprint_sha256"
            ),
        },
        "summary": {
            "changes": len(changes),
            "changed_tools": changed_tools,
            "authority_increases": counts["authority_increase"],
            "reviews": counts["review"],
            "protection_increases": counts["protection_increase"],
        },
        "changes": changes,
    }


def _terminal_text(value: str) -> str:
    """Escape terminal controls and directional formatting in text output."""

    escaped: list[str] = []
    for character in value:
        codepoint = ord(character)
        category = unicodedata.category(character)
        if character == "\\":
            escaped.append("\\\\")
        elif character == "\n":
            escaped.append("\\n")
        elif character == "\r":
            escaped.append("\\r")
        elif character == "\t":
            escaped.append("\\t")
        elif category.startswith("C") or category in {"Zl", "Zp"}:
            escape = "\\u" if codepoint <= 0xFFFF else "\\U"
            width = 4 if codepoint <= 0xFFFF else 8
            escaped.append(f"{escape}{codepoint:0{width}x}")
        else:
            escaped.append(character)
    return "".join(escaped)


def _short(value: Any) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return rendered if len(rendered) <= 180 else rendered[:177] + "..."
    if type(value) is str:
        return _terminal_text(value)
    return str(value)


def _candidate_review_debt_diagnostic(summary: dict[str, Any]) -> str:
    """Describe nonzero candidate review counters without exposing names."""

    counter_labels = (
        ("review_required", "parameters requiring review"),
        ("schema_review_required_tools", "schemas requiring review"),
        ("risk_review_required_tools", "tool risks requiring review"),
        ("risk_conflicts", "risk conflicts"),
        ("annotation_conflicts", "annotation conflicts"),
        ("branch_risk_review_required_tools", "branch risks requiring review"),
    )
    counters = "; ".join(
        f"{label}: {summary[field]}"
        for field, label in counter_labels
        if summary[field]
    )
    return (
        "Review threshold failed: candidate scan has existing review debt "
        f"({counters})."
    )


def render_text(diff: dict[str, Any]) -> str:
    """Render a compact diff intended for terminals and pull-request logs."""

    summary = diff["summary"]
    lines = [
        "Verb Authority diff",
        "",
        f"Changes: {summary['changes']} across {summary['changed_tools']} tool(s)",
        f"Authority increases: {summary['authority_increases']}",
        f"Review-classified changes: {summary['reviews']}",
        f"Protection increases: {summary['protection_increases']}",
    ]
    if not diff["changes"]:
        lines.extend(["", "No authority-relevant changes detected."])
        return "\n".join(lines) + "\n"

    labels = {
        "authority_increase": "AUTHORITY INCREASE",
        "review": "REVIEW",
        "protection_increase": "PROTECTION INCREASE",
    }
    for change in diff["changes"]:
        subject = _terminal_text(change["tool"])
        if change.get("argument"):
            subject += "." + _terminal_text(change["argument"])
        lines.extend(
            [
                "",
                f"[{labels[change['classification']]}] {subject}",
                f"  {change['message']}",
            ]
        )
        if "field" in change:
            lines.append(
                f"  {change['field']}: {_short(change['before'])} -> "
                f"{_short(change['after'])}"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two tool-schema exports or Verb Authority JSON reports "
            "and surface authority drift."
        )
    )
    parser.add_argument(
        "before",
        help="baseline raw schema, or JSON report without a failure threshold",
    )
    parser.add_argument(
        "after",
        help="candidate raw schema, or JSON report without a failure threshold",
    )
    parser.add_argument(
        "--before-controls", help="control declarations for a raw baseline schema"
    )
    parser.add_argument(
        "--after-controls", help="control declarations for a raw candidate schema"
    )
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="diff format"
    )
    parser.add_argument("--output", help="write the diff to this file instead of stdout")
    parser.add_argument(
        "--fail-on-increase",
        action="store_true",
        help=(
            "exit with status 2 when caller authority increases; both inputs "
            "must be raw schemas"
        ),
    )
    parser.add_argument(
        "--fail-on-review",
        action="store_true",
        help=(
            "exit with status 2 when a change requires review or the candidate "
            "has existing review debt; both inputs must be raw schemas"
        ),
    )
    args = parser.parse_args(argv)
    enforcement_requested = args.fail_on_increase or args.fail_on_review
    input_loader = load_raw_schema if enforcement_requested else load_report_or_schema

    try:
        before = input_loader(
            args.before,
            controls_path=args.before_controls,
            label="before input",
        )
        after = input_loader(
            args.after,
            controls_path=args.after_controls,
            label="after input",
        )
        diff = diff_reports(before, after)
    except (OSError, json.JSONDecodeError, SchemaError, DiffError) as exc:
        parser.error(str(exc))

    if args.format == "json":
        rendered = json.dumps(diff, indent=2, sort_keys=True) + "\n"
    else:
        rendered = render_text(diff)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    if args.fail_on_increase and diff["summary"]["authority_increases"]:
        return 2
    if args.fail_on_review:
        candidate_has_review_debt = _summary_requires_review(after["summary"])
        if diff["summary"]["reviews"] or candidate_has_review_debt:
            if candidate_has_review_debt:
                print(
                    _candidate_review_debt_diagnostic(after["summary"]),
                    file=sys.stderr,
                )
            return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
