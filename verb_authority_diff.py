"""Compare two Verb Authority scans and surface authority drift.

Inputs may be existing JSON reports or raw MCP/OpenAI/Anthropic schema exports.
Raw schemas are scanned locally before comparison; no server is started and no
networking code is used.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import unicodedata
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from verb_authority_scan import (
    REPORT_VERSION,
    SchemaError,
    canonical_decimal_text,
    load_json_path,
    scan_documents,
    validate_plain_json,
)


DIFF_VERSION = 2

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
    {"safe_default", "control_declaration", "conflict_safe_default"}
)
_EVIDENCE = frozenset({"observed", "declared", "attested"})
_BOUND_MUTABILITY = frozenset({"immutable", "trusted_party", "caller"})
_BOUND_STATUS = frozenset({"enforced", "specified", "not_stated"})
_HEX = frozenset("0123456789abcdef")
_REPORT_SENTINEL_KEYS = frozenset(
    {
        "report_version",
        "privacy",
        "schema_fingerprint_sha256",
        "summary",
        "declared_controls",
        "control_declaration_fingerprint_sha256",
    }
)
_REPORT_TOOL_SENTINEL_KEYS = frozenset(
    {
        "arguments",
        "risk_source",
        "risk_evidence",
        "inferred_risk",
        "risk_inference",
        "risk_conflict",
        "risk_review_required",
        "needs_confirmation",
        "schema_review_required",
        "annotation_conflicts",
        "schema_material_fingerprint_sha256",
        "unmodeled_schema_fingerprint_sha256",
    }
)


class DiffError(ValueError):
    """Raised when reports cannot be correlated safely."""


def _is_report_shaped(document: Any) -> bool:
    """Recognize report sentinels in every supported raw-schema envelope."""

    if type(document) is dict and (
        "generator" in document or _REPORT_SENTINEL_KEYS.intersection(document)
    ):
        return True

    def entry_is_report_shaped(entry: Any) -> bool:
        if type(entry) is not dict:
            return False
        if _REPORT_TOOL_SENTINEL_KEYS.intersection(entry):
            return True
        function = entry.get("function")
        return (
            entry.get("type") == "function"
            and type(function) is dict
            and bool(_REPORT_TOOL_SENTINEL_KEYS.intersection(function))
        )

    candidate_entries: list[Any] = []
    if type(document) is list:
        candidate_entries.extend(document)
    elif type(document) is dict:
        if "name" in document:
            candidate_entries.append(document)

        tools = document.get("tools")
        if type(tools) is list:
            candidate_entries.extend(tools)

        functions = document.get("functions")
        if type(functions) is list:
            candidate_entries.extend(functions)

        result = document.get("result")
        if type(result) is dict and type(result.get("tools")) is list:
            candidate_entries.extend(result["tools"])

        sources = document.get("sources")
        if type(sources) is list:
            for source in sources:
                if type(source) is dict and type(source.get("tools")) is list:
                    candidate_entries.extend(source["tools"])

    return any(entry_is_report_shaped(entry) for entry in candidate_entries)


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
        raise DiffError(f"{field}.effects must be non-empty and unique")
    if "note" in risk:
        _require_text(risk["note"], field=f"{field}.note")


def _validate_report_argument(
    value: Any,
    *,
    tool: str,
    seen: set[str],
    require_fingerprints: bool,
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
    if argument.get("policy") not in _POLICIES:
        raise DiffError(f"argument {tool}.{name}.policy is invalid")
    _require_text(
        argument.get("confidence"), field=f"argument {tool}.{name}.confidence"
    )
    _require_bool(
        argument.get("review_required"),
        field=f"argument {tool}.{name}.review_required",
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


def _validate_report_tool(
    value: Any,
    *,
    seen: set[str],
    require_fingerprints: bool,
) -> tuple[str, set[str]]:
    tool = _require_object(value, field="report tool")
    _reject_unknown_fields(
        tool,
        allowed={
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
            "annotation_conflicts",
            "arguments",
            "schema_material_fingerprint_sha256",
            "unmodeled_schema_fingerprint_sha256",
            "source_id",
            "source_url",
        },
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
    _validate_declared_risk(tool.get("declared_risk"), field=f"tool '{name}' risk")
    for boolean_field in (
        "risk_conflict",
        "risk_review_required",
        "needs_confirmation",
        "schema_closes_unknown_arguments",
    ):
        _require_bool(tool.get(boolean_field), field=f"tool '{name}' {boolean_field}")
    if "schema_review_required" in tool:
        _require_bool(
            tool["schema_review_required"],
            field=f"tool '{name}' schema_review_required",
        )
    _require_string_array(
        tool.get("annotation_conflicts"),
        field=f"tool '{name}' annotation conflicts",
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
    for argument in _require_array(
        tool.get("arguments"), field=f"tool '{name}' arguments"
    ):
        _validate_report_argument(
            argument,
            tool=name,
            seen=argument_names,
            require_fingerprints=require_fingerprints,
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
    _require_text(bound.get("source"), field=f"{field}.source")
    if bound.get("bounds_mutability") not in _BOUND_MUTABILITY:
        raise DiffError(f"{field}.bounds_mutability is invalid")
    if bound.get("operational_status") not in _BOUND_STATUS:
        raise DiffError(f"{field}.operational_status is invalid")
    if "enforcement" in bound:
        _require_text(bound["enforcement"], field=f"{field}.enforcement")


def _validate_declared_controls(
    value: Any,
    *,
    report_tools: dict[str, dict[str, Any]],
    report_arguments: dict[str, dict[str, dict[str, Any]]],
) -> None:
    declared = _require_object(value, field="declared_controls")
    _reject_unknown_fields(
        declared,
        allowed={"version", "verification_notice", "tools", "attribution"},
        field="declared_controls",
    )
    if type(declared.get("version")) is not int or declared.get("version") != 1:
        raise DiffError("declared_controls.version is invalid")
    _require_text(
        declared.get("verification_notice"),
        field="declared_controls.verification_notice",
    )
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
            _require_text(
                attribution_value,
                field=f"declared_controls.attribution.{attribution_field}",
            )
    tools_seen: set[str] = set()
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
            },
            field="declared control tool",
        )
        name = _require_text(tool.get("name"), field="declared control tool name")
        if name in tools_seen:
            raise DiffError(f"declared controls contain duplicate tool name: {name}")
        tools_seen.add(name)
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

        argument_names: set[str] = set()
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
            for index, bound in enumerate(
                bounds,
                start=1,
            ):
                _validate_bound(
                    bound,
                    field=f"declared bound {index} for {name}.{argument_name}",
                )
            if "note" in argument:
                _require_text(
                    argument["note"],
                    field=f"declared argument note for {name}.{argument_name}",
                )

        for raw_argument in _require_array(
            tool.get("unexposed_arguments"),
            field=f"declared tool '{name}' unexposed arguments",
        ):
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
            _require_text(
                argument.get("enforced_by"),
                field=f"unexposed control enforcement for {name}.{argument_name}",
            )
            if "note" in argument:
                _require_text(
                    argument["note"],
                    field=f"unexposed control note for {name}.{argument_name}",
                )

    for name, report_tool in report_tools.items():
        if report_tool.get("declared_risk") is not None and name not in tools_seen:
            raise DiffError(
                f"report tool '{name}' exposes declared risk without the matching "
                "declared control tool"
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
    if report_version == 2:
        raise DiffError(
            f"{label} uses legacy report version 2, which omitted schema "
            "constraint values; rescan the original schema with report "
            f"version {REPORT_VERSION} before diffing"
        )
    if report.get("generator") != "verb-authority":
        raise DiffError(
            f"{label} is report-shaped but has a missing or invalid generator"
        )
    if type(report_version) is not int or report_version != REPORT_VERSION:
        raise DiffError(
            f"{label} uses unsupported report version "
            f"{report_version!r}; expected {REPORT_VERSION}"
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
    }
    optional_summary_fields = {"schema_review_required_tools"}
    _reject_unknown_fields(
        summary,
        allowed=required_summary_fields | optional_summary_fields,
        field=f"{label} summary",
    )
    if not required_summary_fields.issubset(summary) or any(
        type(value) is not int or value < 0 for value in summary.values()
    ):
        raise DiffError(f"{label} has invalid report summary")

    tools = _require_array(report.get("tools"), field=f"{label} tools")
    tool_names: set[str] = set()
    report_tools: dict[str, dict[str, Any]] = {}
    report_arguments: dict[str, dict[str, dict[str, Any]]] = {}
    for raw_tool in tools:
        tool_name, argument_names = _validate_report_tool(
            raw_tool,
            seen=tool_names,
            require_fingerprints=not names_redacted,
        )
        report_tools[tool_name] = raw_tool
        report_arguments[tool_name] = {
            argument["name"]: argument for argument in raw_tool["arguments"]
        }
        if set(report_arguments[tool_name]) != argument_names:
            raise DiffError(f"tool '{tool_name}' argument index is inconsistent")

    if summary.get("schema_review_required_tools") != sum(
        tool.get("schema_review_required", False) is True for tool in tools
    ) and "schema_review_required_tools" in summary:
        raise DiffError(
            f"{label} schema_review_required_tools does not match its tools"
        )

    controls_included = privacy["control_declarations_included"]
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
        )
        if declared_fingerprint != _control_declaration_fingerprint(
            report["declared_controls"]
        ):
            raise DiffError(
                f"{label} control declaration fingerprint does not match its controls"
            )
    elif "declared_controls" in report or "control_declaration_fingerprint_sha256" in report:
        raise DiffError(f"{label} has inconsistent declared control metadata")

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
        indexed[name] = {
            "risk": raw_tool.get("risk"),
            "risk_source": raw_tool.get("risk_source"),
            "risk_evidence": raw_tool.get("risk_evidence"),
            "inferred_risk": raw_tool.get("inferred_risk"),
            "risk_inference": raw_tool.get("risk_inference"),
            "declared_risk": raw_tool.get("declared_risk"),
            "risk_conflict": raw_tool.get("risk_conflict"),
            "risk_review_required": raw_tool.get("risk_review_required"),
            "needs_confirmation": raw_tool.get("needs_confirmation"),
            "annotation_conflicts": raw_tool.get("annotation_conflicts", []),
            "schema_closes_unknown_arguments": raw_tool.get(
                "schema_closes_unknown_arguments"
            ),
            "schema_review_required": raw_tool.get(
                "schema_review_required", False
            ),
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

    before_enforced = [
        bound
        for bound, status in zip(before, before_status)
        if status == "enforced"
    ]
    after_enforced = [
        bound
        for bound, status in zip(after, after_status)
        if status == "enforced"
    ]
    strength = {"trusted_party": 1, "immutable": 2}
    before_protective = sorted(
        strength[bound["bounds_mutability"]]
        for bound in before_enforced
        if bound.get("bounds_mutability") in strength
    )
    after_protective = sorted(
        strength[bound["bounds_mutability"]]
        for bound in after_enforced
        if bound.get("bounds_mutability") in strength
    )

    def dominates(candidate: list[int], baseline: list[int]) -> bool:
        """Whether candidate can match every fixed baseline bound in strength."""

        if len(candidate) < len(baseline):
            return False
        candidate_index = 0
        for required_strength in baseline:
            while (
                candidate_index < len(candidate)
                and candidate[candidate_index] < required_strength
            ):
                candidate_index += 1
            if candidate_index == len(candidate):
                return False
            candidate_index += 1
        return True

    after_dominates = dominates(after_protective, before_protective)
    before_dominates = dominates(before_protective, after_protective)
    if before_dominates and not after_dominates:
        return "authority_increase"
    if after_dominates and not before_dominates:
        return "protection_increase"
    # Caller-controlled bounds are not fixed authority controls. Adding or
    # removing only those bounds is visible drift, but cannot establish either
    # a protection increase or a weakening without semantic evidence.
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
    """Return a deterministic, machine-readable authority diff."""

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
            _ranked_change(
                changes,
                kind="tool_risk_changed",
                tool=tool,
                argument=None,
                field="risk",
                before=before_tool["risk"],
                after=after_tool["risk"],
                ranks=_RISK_RANK,
                increase_message="Tool risk increased.",
                reduction_message="Tool risk decreased.",
                review_message="Tool risk class changed and needs review.",
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
            if after_schema_review is True:
                classification = "review"
                message = (
                    "The schema now uses unresolved composition or references and "
                    "requires manual authority review."
                )
            else:
                classification = "protection_increase"
                message = (
                    "The unresolved schema-composition review requirement was removed."
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

        before_conflicts = before_tool["annotation_conflicts"]
        after_conflicts = after_tool["annotation_conflicts"]
        if before_conflicts != after_conflicts:
            changes.append(
                _change(
                    "review",
                    "annotation_conflicts_changed",
                    tool,
                    field="annotation_conflicts",
                    before=before_conflicts,
                    after=after_conflicts,
                    message="MCP annotation conflicts changed.",
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
                    if after_tool["schema_closes_unknown_arguments"] is True:
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
                    classification = "protection_increase"
                    message = "A caller-visible argument became unexposed."
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


def render_text(diff: dict[str, Any]) -> str:
    """Render a compact diff intended for terminals and pull-request logs."""

    summary = diff["summary"]
    lines = [
        "Verb Authority diff",
        "",
        f"Changes: {summary['changes']} across {summary['changed_tools']} tool(s)",
        f"Authority increases: {summary['authority_increases']}",
        f"Needs review: {summary['reviews']}",
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
    parser.add_argument("before", help="baseline schema export or JSON report")
    parser.add_argument("after", help="candidate schema export or JSON report")
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
        help="exit with status 2 when caller authority increases",
    )
    parser.add_argument(
        "--fail-on-review",
        action="store_true",
        help="exit with status 2 when a change requires review",
    )
    args = parser.parse_args(argv)

    try:
        before = load_report_or_schema(
            args.before,
            controls_path=args.before_controls,
            label="before input",
        )
        after = load_report_or_schema(
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
    if args.fail_on_review and diff["summary"]["reviews"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
