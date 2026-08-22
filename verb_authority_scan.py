"""Local tool-schema scanner for Verb Authority.

The scanner accepts exported MCP, OpenAI, or Anthropic tool definitions. It
never starts a tool server and contains no networking code. Reports omit tool
descriptions, examples, defaults, and runtime values so they can be reviewed or
shared with substantially less disclosure than the original schema.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from verb_authority import (
    Confidence,
    Param,
    Policy,
    Registry,
    Risk,
    Tool,
    build_policy,
    infer_policy,
)


REPORT_VERSION = 2
CONTROL_DECLARATION_VERSION = 1
CONTROL_AUTHORITIES = frozenset({"constrained", "free", "locked"})
CONTROL_EVIDENCE = frozenset({"observed", "declared", "attested"})
BOUND_MUTABILITY = frozenset({"immutable", "trusted_party", "caller"})
BOUND_OPERATIONAL_STATUS = frozenset({"enforced", "specified"})
CONTROL_EXPOSURES = frozenset({"server_fixed"})
DECLARABLE_RISKS = frozenset(
    risk.value for risk in Risk if risk is not Risk.UNKNOWN
)
CONTROL_VERIFICATION_NOTICE = (
    "Control declarations are supplied by the report author. Their evidence "
    "labels and operational statuses are preserved but are not independently "
    "verified by this scanner."
)


class SchemaError(ValueError):
    """Raised when an input does not contain recognizable tool definitions."""


@dataclass
class ToolDefinition:
    name: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    source_id: str | None = None
    source_url: str | None = None


def _tool_from_mapping(
    raw: dict[str, Any],
    *,
    source_id: str | None = None,
    source_url: str | None = None,
) -> ToolDefinition:
    source_id = raw.get("source_id", source_id)
    source_url = raw.get("source_url", source_url)

    if raw.get("type") == "function" and isinstance(raw.get("function"), dict):
        function = raw["function"]
        name = function.get("name")
        schema = function.get("parameters", {})
        annotations = raw.get("annotations", {})
    else:
        name = raw.get("name")
        schema = raw.get("inputSchema")
        if schema is None:
            schema = raw.get("input_schema")
        if schema is None:
            schema = raw.get("parameters")
        annotations = raw.get("annotations", {})

    if not isinstance(name, str) or not name.strip():
        raise SchemaError("tool definition is missing a non-empty name")
    if schema is None:
        schema = {}
    if not isinstance(schema, dict):
        raise SchemaError(f"tool '{name}' has a non-object input schema")
    if not isinstance(annotations, dict):
        annotations = {}
    return ToolDefinition(
        name=name,
        input_schema=schema,
        annotations=annotations,
        source_id=source_id,
        source_url=source_url,
    )


def parse_tool_definitions(document: Any) -> list[ToolDefinition]:
    """Normalize common exported tool-schema envelopes.

    Supported shapes include MCP ``tools/list`` results, OpenAI function tools,
    Anthropic tools, and the attributed ``sources`` envelope used by the public
    Atlas fixture.
    """

    if isinstance(document, list):
        if not document:
            return []
        return [_tool_from_mapping(item) for item in document if isinstance(item, dict)]

    if not isinstance(document, dict):
        raise SchemaError("schema document must be a JSON object or array")

    if isinstance(document.get("sources"), list):
        tools: list[ToolDefinition] = []
        for source in document["sources"]:
            if not isinstance(source, dict) or not isinstance(source.get("tools"), list):
                raise SchemaError("each Atlas source must contain a tools array")
            source_id = source.get("id")
            source_url = source.get("url")
            for raw in source["tools"]:
                if not isinstance(raw, dict):
                    raise SchemaError("tool definitions must be JSON objects")
                tools.append(
                    _tool_from_mapping(
                        raw,
                        source_id=source_id if isinstance(source_id, str) else None,
                        source_url=source_url if isinstance(source_url, str) else None,
                    )
                )
        return tools

    result = document.get("result")
    if isinstance(result, dict) and isinstance(result.get("tools"), list):
        return parse_tool_definitions(result["tools"])
    if isinstance(document.get("tools"), list):
        return parse_tool_definitions(document["tools"])
    if isinstance(document.get("functions"), list):
        return [
            _tool_from_mapping({"type": "function", "function": function})
            for function in document["functions"]
            if isinstance(function, dict)
        ]
    if "name" in document:
        return [_tool_from_mapping(document)]

    raise SchemaError("no recognizable tool definitions found")


def _property_type(schema: dict[str, Any]) -> str:
    if isinstance(schema.get("enum"), list):
        return "enum"
    schema_type = schema.get("type", "string")
    if isinstance(schema_type, list):
        schema_type = next((item for item in schema_type if item != "null"), "string")
    if not isinstance(schema_type, str):
        schema_type = "string"
    value_format = schema.get("format")
    if value_format == "email":
        return "email"
    if value_format in {"uri", "uri-reference", "url"}:
        return "uri"
    return schema_type


def _param(name: str, schema: Any) -> Param:
    if not isinstance(schema, dict):
        schema = {}
    param_type = _property_type(schema)
    enum = schema.get("enum") if param_type == "enum" else None
    maximum = schema.get("maximum")
    cap = maximum if isinstance(maximum, (int, float)) else None
    max_length = schema.get("maxLength")
    max_len = max_length if isinstance(max_length, int) else None
    sink = schema.get("x-verb-authority-sink")
    if not isinstance(sink, bool):
        sink = None
    return Param(
        name=name,
        type=param_type,
        enum=enum if isinstance(enum, list) else None,
        max_len=max_len,
        cap=cap,
        sink=sink,
    )


def _properties(definition: ToolDefinition) -> tuple[dict[str, Any], set[str]]:
    schema = definition.input_schema
    properties = schema.get("properties")
    if properties is None:
        # Some SDK exports expose the input shape directly rather than wrapping
        # it in a JSON Schema object.
        properties = {
            key: value
            for key, value in schema.items()
            if key not in {"type", "required", "$schema", "additionalProperties"}
        }
    if not isinstance(properties, dict):
        raise SchemaError(f"tool '{definition.name}' has non-object properties")
    required = schema.get("required", [])
    if not isinstance(required, list):
        required = []
    return properties, {item for item in required if isinstance(item, str)}


def _optional_text(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"control declaration field '{field}' must be non-empty text")
    return value.strip()


def _reject_unknown_fields(
    value: dict[str, Any], *, allowed: set[str], field: str
) -> None:
    unknown = sorted(str(item) for item in value if item not in allowed)
    if unknown:
        raise SchemaError(
            f"unknown field in {field}: " + ", ".join(str(item) for item in unknown)
        )


def _validate_control_declarations(
    definitions: list[ToolDefinition], document: Any
) -> dict[str, Any]:
    if not isinstance(document, dict):
        raise SchemaError("control declarations must be a JSON object")
    _reject_unknown_fields(
        document,
        allowed={"version", "attribution", "tools"},
        field="control declarations",
    )
    if document.get("version") != CONTROL_DECLARATION_VERSION:
        raise SchemaError(
            f"control declaration version must be {CONTROL_DECLARATION_VERSION}"
        )

    definitions_by_name = {definition.name: definition for definition in definitions}
    raw_tools = document.get("tools")
    if not isinstance(raw_tools, dict):
        raise SchemaError("control declarations must contain a tools object")

    attribution = document.get("attribution")
    normalized_attribution: dict[str, str] | None = None
    if attribution is not None:
        if not isinstance(attribution, dict):
            raise SchemaError("control declaration attribution must be an object")
        _reject_unknown_fields(
            attribution,
            allowed={"name", "source"},
            field="control declaration attribution",
        )
        normalized_attribution = {}
        for field in ("name", "source"):
            value = _optional_text(attribution.get(field), field=f"attribution.{field}")
            if value is not None:
                normalized_attribution[field] = value
        if not normalized_attribution:
            normalized_attribution = None

    normalized_tools: dict[str, Any] = {}
    for tool_name, raw_tool in raw_tools.items():
        if not isinstance(tool_name, str) or tool_name not in definitions_by_name:
            raise SchemaError(f"control declaration references unknown tool: {tool_name}")
        if not isinstance(raw_tool, dict):
            raise SchemaError(f"control declaration for '{tool_name}' must be an object")
        _reject_unknown_fields(
            raw_tool,
            allowed={"risk", "arguments", "unexposed_arguments"},
            field=f"control declaration for '{tool_name}'",
        )

        raw_risk = raw_tool.get("risk")
        risk_declaration: dict[str, Any] | None = None
        if raw_risk is not None:
            if not isinstance(raw_risk, dict):
                raise SchemaError(
                    f"risk declaration for '{tool_name}' must be an object"
                )
            _reject_unknown_fields(
                raw_risk,
                allowed={"tier", "evidence", "effects", "note"},
                field=f"risk declaration for '{tool_name}'",
            )
            tier = raw_risk.get("tier")
            evidence = raw_risk.get("evidence")
            if tier not in DECLARABLE_RISKS:
                raise SchemaError(
                    f"risk tier for '{tool_name}' must be one of: "
                    + ", ".join(sorted(DECLARABLE_RISKS))
                )
            if evidence not in CONTROL_EVIDENCE:
                raise SchemaError(
                    f"risk evidence for '{tool_name}' must be one of: "
                    + ", ".join(sorted(CONTROL_EVIDENCE))
                )
            raw_effects = raw_risk.get("effects")
            if not isinstance(raw_effects, list) or not raw_effects:
                raise SchemaError(
                    f"risk effects for '{tool_name}' must be a non-empty array"
                )
            effects: list[str] = []
            for effect_index, raw_effect in enumerate(raw_effects, start=1):
                effect = _optional_text(
                    raw_effect,
                    field=f"{tool_name}.risk.effects[{effect_index}]",
                )
                if effect is None:
                    raise SchemaError(
                        f"risk effect {effect_index} for '{tool_name}' "
                        "must be non-empty text"
                    )
                if effect in effects:
                    raise SchemaError(
                        f"duplicate risk effect for '{tool_name}': {effect}"
                    )
                effects.append(effect)
            risk_declaration = {
                "tier": tier,
                "evidence": evidence,
                "effects": effects,
            }
            risk_note = _optional_text(
                raw_risk.get("note"), field=f"{tool_name}.risk.note"
            )
            if risk_note is not None:
                risk_declaration["note"] = risk_note

        properties, _ = _properties(definitions_by_name[tool_name])
        raw_arguments = raw_tool.get("arguments", {})
        if not isinstance(raw_arguments, dict):
            raise SchemaError(f"control arguments for '{tool_name}' must be an object")
        arguments: dict[str, Any] = {}
        for argument_name, raw_argument in raw_arguments.items():
            if argument_name not in properties:
                raise SchemaError(
                    f"control declaration references unknown argument: "
                    f"{tool_name}.{argument_name}"
                )
            if not isinstance(raw_argument, dict):
                raise SchemaError(
                    f"control declaration for '{tool_name}.{argument_name}' "
                    "must be an object"
                )
            _reject_unknown_fields(
                raw_argument,
                allowed={"authority", "evidence", "bounds", "note"},
                field=f"control declaration for '{tool_name}.{argument_name}'",
            )
            authority = raw_argument.get("authority")
            evidence = raw_argument.get("evidence")
            if authority not in CONTROL_AUTHORITIES:
                raise SchemaError(
                    f"authority for '{tool_name}.{argument_name}' must be one of: "
                    + ", ".join(sorted(CONTROL_AUTHORITIES))
                )
            if evidence not in CONTROL_EVIDENCE:
                raise SchemaError(
                    f"evidence for '{tool_name}.{argument_name}' must be one of: "
                    + ", ".join(sorted(CONTROL_EVIDENCE))
                )

            raw_bounds = raw_argument.get("bounds", [])
            if not isinstance(raw_bounds, list):
                raise SchemaError(
                    f"bounds for '{tool_name}.{argument_name}' must be an array"
                )
            if authority == "constrained" and not raw_bounds:
                raise SchemaError(
                    f"constrained argument '{tool_name}.{argument_name}' "
                    "must declare at least one bound"
                )
            if authority != "constrained" and raw_bounds:
                raise SchemaError(
                    f"only constrained arguments may declare bounds: "
                    f"{tool_name}.{argument_name}"
                )
            bounds = []
            for bound_index, raw_bound in enumerate(raw_bounds, start=1):
                if not isinstance(raw_bound, dict):
                    raise SchemaError(
                        f"bound {bound_index} for '{tool_name}.{argument_name}' "
                        "must be an object"
                    )
                _reject_unknown_fields(
                    raw_bound,
                    allowed={
                        "source",
                        "bounds_mutability",
                        "enforcement",
                        "operational_status",
                    },
                    field=(
                        f"bound {bound_index} for "
                        f"'{tool_name}.{argument_name}'"
                    ),
                )
                source = _optional_text(
                    raw_bound.get("source"),
                    field=f"{tool_name}.{argument_name}.bounds[{bound_index}].source",
                )
                mutability = raw_bound.get("bounds_mutability")
                if source is None:
                    raise SchemaError(
                        f"bound {bound_index} for '{tool_name}.{argument_name}' "
                        "must name its source"
                    )
                if mutability not in BOUND_MUTABILITY:
                    raise SchemaError(
                        f"bounds_mutability for '{tool_name}.{argument_name}' must be "
                        "one of: " + ", ".join(sorted(BOUND_MUTABILITY))
                    )
                operational_status = raw_bound.get("operational_status")
                if (
                    operational_status is not None
                    and operational_status not in BOUND_OPERATIONAL_STATUS
                ):
                    raise SchemaError(
                        f"operational_status for "
                        f"'{tool_name}.{argument_name}' must be one of: "
                        + ", ".join(sorted(BOUND_OPERATIONAL_STATUS))
                    )
                bound = {
                    "source": source,
                    "bounds_mutability": mutability,
                    "operational_status": operational_status or "not_stated",
                }
                enforcement = _optional_text(
                    raw_bound.get("enforcement"),
                    field=(
                        f"{tool_name}.{argument_name}.bounds[{bound_index}].enforcement"
                    ),
                )
                if enforcement is not None:
                    bound["enforcement"] = enforcement
                bounds.append(bound)

            argument = {"authority": authority, "evidence": evidence}
            if bounds:
                argument["bounds"] = bounds
            note = _optional_text(
                raw_argument.get("note"), field=f"{tool_name}.{argument_name}.note"
            )
            if note is not None:
                argument["note"] = note
            arguments[argument_name] = argument

        raw_unexposed = raw_tool.get("unexposed_arguments", {})
        if not isinstance(raw_unexposed, dict):
            raise SchemaError(
                f"unexposed arguments for '{tool_name}' must be an object"
            )
        unexposed_arguments: dict[str, Any] = {}
        for argument_name, raw_argument in raw_unexposed.items():
            if argument_name in properties:
                raise SchemaError(
                    f"unexposed argument collides with schema argument: "
                    f"{tool_name}.{argument_name}"
                )
            if not isinstance(argument_name, str) or not argument_name.strip():
                raise SchemaError("unexposed argument names must be non-empty text")
            if not isinstance(raw_argument, dict):
                raise SchemaError(
                    f"unexposed declaration for '{tool_name}.{argument_name}' "
                    "must be an object"
                )
            _reject_unknown_fields(
                raw_argument,
                allowed={"exposure", "enforced_by", "evidence", "note"},
                field=f"unexposed declaration for '{tool_name}.{argument_name}'",
            )
            exposure = raw_argument.get("exposure")
            evidence = raw_argument.get("evidence")
            if exposure not in CONTROL_EXPOSURES:
                raise SchemaError(
                    f"exposure for '{tool_name}.{argument_name}' must be one of: "
                    + ", ".join(sorted(CONTROL_EXPOSURES))
                )
            if evidence not in CONTROL_EVIDENCE:
                raise SchemaError(
                    f"evidence for '{tool_name}.{argument_name}' must be one of: "
                    + ", ".join(sorted(CONTROL_EVIDENCE))
                )
            enforced_by = _optional_text(
                raw_argument.get("enforced_by"),
                field=f"{tool_name}.{argument_name}.enforced_by",
            )
            if enforced_by is None:
                raise SchemaError(
                    f"unexposed argument '{tool_name}.{argument_name}' "
                    "must declare enforced_by"
                )
            argument = {
                "exposure": exposure,
                "enforced_by": enforced_by,
                "evidence": evidence,
            }
            note = _optional_text(
                raw_argument.get("note"), field=f"{tool_name}.{argument_name}.note"
            )
            if note is not None:
                argument["note"] = note
            unexposed_arguments[argument_name] = argument

        normalized_tool = {
            "arguments": arguments,
            "unexposed_arguments": unexposed_arguments,
        }
        if risk_declaration is not None:
            normalized_tool["risk"] = risk_declaration
        normalized_tools[tool_name] = normalized_tool

    return {
        "version": CONTROL_DECLARATION_VERSION,
        "attribution": normalized_attribution,
        "tools": normalized_tools,
    }


def _reason(param: Param, policy: Policy, confidence: Confidence, risk: Risk) -> str:
    if param.sink is True:
        return "declared authority sink"
    if param.sink is False:
        return "declared data-fillable"
    if param.type in {"email", "uri"}:
        return f"{param.type} destination"
    if confidence is Confidence.UNCERTAIN and risk is Risk.READ_ONLY:
        return "ambiguous argument auto-relaxed for read-only tool"
    if confidence is Confidence.UNCERTAIN:
        return "ambiguous consequential argument; review required"
    if policy is Policy.TRUSTED_FIXED:
        return "authority-bearing name"
    if policy is Policy.OUTBOUND_PAYLOAD:
        return "outbound payload name or bounded free text"
    return "typed or bounded value"


def _annotation_conflicts(risk: Risk, annotations: dict[str, Any]) -> list[str]:
    conflicts: list[str] = []
    read_only = annotations.get("readOnlyHint")
    destructive = annotations.get("destructiveHint")
    if read_only is True and risk is not Risk.READ_ONLY:
        conflicts.append("readOnlyHint=true conflicts with effective risk")
    elif read_only is False and risk is Risk.READ_ONLY:
        conflicts.append("readOnlyHint=false conflicts with effective risk")
    if destructive is True and risk is not Risk.DESTRUCTIVE:
        conflicts.append("destructiveHint=true conflicts with effective risk")
    return conflicts


def _fingerprint(
    definitions: Iterable[ToolDefinition], *, redact_names: bool = False
) -> str:
    normalized = []
    for tool_index, definition in enumerate(definitions, start=1):
        properties, required = _properties(definition)
        normalized_properties = {}
        for param_index, (name, raw) in enumerate(sorted(properties.items()), start=1):
            display_name = f"param_{param_index:03d}" if redact_names else name
            normalized_properties[display_name] = {
                "type": _property_type(raw if isinstance(raw, dict) else {}),
                "required": name in required,
            }
        normalized.append(
            {
                "name": f"tool_{tool_index:03d}" if redact_names else definition.name,
                "properties": normalized_properties,
            }
        )
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _control_declaration_fingerprint(declared_controls: dict[str, Any]) -> str:
    normalized = {
        "version": declared_controls["version"],
        "tools": declared_controls["tools"],
    }
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _declared_controls_report(
    definitions: list[ToolDefinition],
    report_tools: list[dict[str, Any]],
    declarations: dict[str, Any],
    *,
    redact_names: bool,
) -> dict[str, Any]:
    declared_tools = declarations["tools"]
    tools: list[dict[str, Any]] = []

    for definition, report_tool in zip(definitions, report_tools):
        declared_tool = declared_tools.get(definition.name)
        if declared_tool is None:
            continue

        properties, _ = _properties(definition)
        report_arguments = {
            original_name: report_argument
            for original_name, report_argument in zip(
                properties, report_tool["arguments"]
            )
        }
        exposed_arguments: list[dict[str, Any]] = []
        for argument_name in properties:
            if argument_name not in declared_tool["arguments"]:
                continue
            declared_argument = declared_tool["arguments"][argument_name]
            report_argument = report_arguments[argument_name]
            item = {
                "name": report_argument["name"],
                "schema_exposure": "exposed",
                "inferred_policy": report_argument["policy"],
                "review_required": report_argument["review_required"],
                "authority": declared_argument["authority"],
                "evidence": declared_argument["evidence"],
            }
            if "bounds" in declared_argument:
                item["bounds"] = declared_argument["bounds"]
            if "note" in declared_argument:
                item["note"] = declared_argument["note"]
            exposed_arguments.append(item)

        unexposed_arguments: list[dict[str, Any]] = []
        for index, argument_name in enumerate(
            sorted(declared_tool["unexposed_arguments"]), start=len(properties) + 1
        ):
            declared_argument = declared_tool["unexposed_arguments"][argument_name]
            item = {
                "name": f"param_{index:03d}" if redact_names else argument_name,
                "schema_exposure": "unexposed",
                "exposure": declared_argument["exposure"],
                "enforced_by": declared_argument["enforced_by"],
                "evidence": declared_argument["evidence"],
            }
            if "note" in declared_argument:
                item["note"] = declared_argument["note"]
            unexposed_arguments.append(item)

        tool_item = {
            "name": report_tool["name"],
            "schema_closes_unknown_arguments": (
                definition.input_schema.get("additionalProperties") is False
            ),
            "arguments": exposed_arguments,
            "unexposed_arguments": unexposed_arguments,
        }
        if "risk" in declared_tool:
            tool_item["risk"] = declared_tool["risk"]
        tools.append(tool_item)

    report = {
        "version": CONTROL_DECLARATION_VERSION,
        "verification_notice": CONTROL_VERIFICATION_NOTICE,
        "tools": tools,
    }
    if not redact_names and declarations.get("attribution"):
        report["attribution"] = declarations["attribution"]
    return report


def scan_definitions(
    definitions: list[ToolDefinition],
    *,
    redact_names: bool = False,
    control_declarations: Any | None = None,
) -> dict[str, Any]:
    if not definitions:
        raise SchemaError("no tool definitions found")

    declarations = None
    if control_declarations is not None:
        declarations = _validate_control_declarations(
            definitions, control_declarations
        )

    registry = Registry()
    params_by_tool: dict[str, list[Param]] = {}
    required_by_tool: dict[str, set[str]] = {}
    for definition in definitions:
        if definition.name in registry.tools:
            raise SchemaError(f"duplicate tool name: {definition.name}")
        properties, required = _properties(definition)
        params = [_param(name, raw) for name, raw in properties.items()]
        declared_tool = (
            declarations["tools"].get(definition.name) if declarations else None
        )
        declared_risk = (
            Risk(declared_tool["risk"]["tier"])
            if declared_tool is not None and "risk" in declared_tool
            else None
        )
        registry.add(Tool(definition.name, params, risk=declared_risk))
        params_by_tool[definition.name] = params
        required_by_tool[definition.name] = required

    policy_set = build_policy(registry)
    review_pairs = set(policy_set.review)
    report_tools = []
    counts = {
        "tools": len(definitions),
        "parameters": 0,
        "protected_parameters": 0,
        "data_fillable_parameters": 0,
        "review_required": 0,
        "confirmation_required_tools": len(policy_set.confirm),
        "risk_review_required_tools": len(policy_set.risk_review),
        "risk_conflicts": len(policy_set.risk_conflicts),
        "annotation_conflicts": 0,
    }

    for tool_index, definition in enumerate(definitions, start=1):
        tool_name = definition.name
        display_tool = f"tool_{tool_index:03d}" if redact_names else tool_name
        risk = policy_set.risk[tool_name]
        inferred_risk = policy_set.risk_inference[tool_name]
        declared_tool = (
            declarations["tools"].get(tool_name) if declarations else None
        )
        declared_risk = (
            declared_tool.get("risk") if declared_tool is not None else None
        )
        conflicts = _annotation_conflicts(risk, definition.annotations)
        counts["annotation_conflicts"] += len(conflicts)
        arguments = []
        for param_index, param in enumerate(params_by_tool[tool_name], start=1):
            initial_policy, confidence = infer_policy(param)
            final_policy = policy_set.policy[tool_name][param.name]
            needs_review = (tool_name, param.name) in review_pairs
            counts["parameters"] += 1
            if final_policy is Policy.TRUSTED_FIXED:
                counts["protected_parameters"] += 1
            else:
                counts["data_fillable_parameters"] += 1
            if needs_review:
                counts["review_required"] += 1
            display_param = f"param_{param_index:03d}" if redact_names else param.name
            arguments.append(
                {
                    "name": display_param,
                    "type": param.type,
                    "required": param.name in required_by_tool[tool_name],
                    "policy": final_policy.value,
                    "confidence": confidence.value,
                    "review_required": needs_review,
                    "reason": _reason(param, initial_policy, confidence, risk),
                }
            )
        risk_inference: dict[str, Any] = {
            "source": inferred_risk.source,
            "confidence": inferred_risk.confidence.value,
            "mutability": inferred_risk.mutability,
        }
        if redact_names:
            risk_inference["signal_redacted"] = True
        else:
            risk_inference["matched_tokens"] = list(inferred_risk.matched_tokens)

        risk_conflict = tool_name in policy_set.risk_conflicts
        if risk_conflict:
            risk_source = "conflict_safe_default"
        elif declared_risk is not None:
            risk_source = "control_declaration"
        else:
            risk_source = "safe_default"

        tool_report: dict[str, Any] = {
            "name": display_tool,
            "risk": risk.value,
            "risk_source": risk_source,
            "risk_evidence": (
                declared_risk["evidence"]
                if declared_risk is not None and not risk_conflict
                else None
            ),
            "inferred_risk": inferred_risk.risk.value,
            "risk_inference": risk_inference,
            "declared_risk": declared_risk,
            "risk_conflict": risk_conflict,
            "risk_review_required": tool_name in policy_set.risk_review,
            "needs_confirmation": tool_name in policy_set.confirm,
            "schema_closes_unknown_arguments": (
                definition.input_schema.get("additionalProperties") is False
            ),
            "annotation_conflicts": conflicts,
            "arguments": arguments,
        }
        if definition.source_id and not redact_names:
            tool_report["source_id"] = definition.source_id
        if definition.source_url and not redact_names:
            tool_report["source_url"] = definition.source_url
        report_tools.append(tool_report)

    report = {
        "report_version": REPORT_VERSION,
        "generator": "verb-authority",
        "privacy": {
            "network_used": False,
            "server_executed": False,
            "descriptions_included": False,
            "examples_or_values_included": False,
            "names_redacted": redact_names,
            "control_declarations_included": control_declarations is not None,
        },
        "schema_fingerprint_sha256": _fingerprint(
            definitions, redact_names=redact_names
        ),
        "summary": counts,
        "tools": report_tools,
    }
    if declarations is not None:
        declared_controls = _declared_controls_report(
            definitions,
            report_tools,
            declarations,
            redact_names=redact_names,
        )
        report["declared_controls"] = declared_controls
        report["control_declaration_fingerprint_sha256"] = (
            _control_declaration_fingerprint(declared_controls)
        )
    return report


def scan_documents(
    documents: Iterable[Any],
    *,
    redact_names: bool = False,
    control_declarations: Any | None = None,
) -> dict[str, Any]:
    definitions: list[ToolDefinition] = []
    for document in documents:
        definitions.extend(parse_tool_definitions(document))
    return scan_definitions(
        definitions,
        redact_names=redact_names,
        control_declarations=control_declarations,
    )


def _markdown_cell(value: Any) -> str:
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\n", " ")


def _control_details(argument: dict[str, Any]) -> str:
    if argument["schema_exposure"] == "unexposed":
        details = f"enforced by {argument['enforced_by']}"
    else:
        bounds = []
        for bound in argument.get("bounds", []):
            detail = (
                f"{bound['source']} [{bound['bounds_mutability']}; "
                f"{bound.get('operational_status', 'not_stated')}]"
            )
            if bound.get("enforcement"):
                detail += f"; {bound['enforcement']}"
            bounds.append(detail)
        details = "; ".join(bounds) if bounds else "—"
    if argument.get("note"):
        details += f"; note: {argument['note']}"
    return details


def render_markdown(report: dict[str, Any]) -> str:
    summary = report["summary"]
    privacy = report["privacy"]
    lines = [
        "# Verb Authority schema report",
        "",
        "> Local static analysis only: no server was executed and no network was used.",
        "> Descriptions, examples, defaults, and runtime values are not included.",
        "",
        "## Summary",
        "",
        "| Measure | Count |",
        "|---|---:|",
        f"| Tools | {summary['tools']} |",
        f"| Parameters | {summary['parameters']} |",
        f"| Protected (`trusted_fixed`) | {summary['protected_parameters']} |",
        f"| Data-fillable | {summary['data_fillable_parameters']} |",
        f"| Parameters requiring review | {summary['review_required']} |",
        f"| Tools requiring confirmation | {summary['confirmation_required_tools']} |",
        f"| Tool risks requiring review | {summary['risk_review_required_tools']} |",
        f"| Tool risk conflicts | {summary['risk_conflicts']} |",
        f"| Annotation conflicts | {summary['annotation_conflicts']} |",
        "",
        f"Schema fingerprint: `{report['schema_fingerprint_sha256']}`",
        f"Names redacted: `{'yes' if privacy['names_redacted'] else 'no'}`",
    ]
    sources = sorted(
        {
            (tool.get("source_id", "public source"), tool["source_url"])
            for tool in report["tools"]
            if tool.get("source_url")
        }
    )
    if sources:
        lines.extend(["", "## Sources", "", "| Source | Pinned URL |", "|---|---|"])
        for source_id, source_url in sources:
            lines.append(
                f"| {_markdown_cell(source_id)} | {_markdown_cell(source_url)} |"
            )
    lines.extend(
        [
            "",
            "## Tool risk evidence",
            "",
            "| Tool | Effective risk | Source | Name heuristic | Mutability | "
            "Declared effects | Conflict | Review | Confirmation |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for tool in report["tools"]:
        risk_inference = tool["risk_inference"]
        if risk_inference.get("signal_redacted"):
            name_signal = "redacted"
        else:
            matched = risk_inference.get("matched_tokens", [])
            name_signal = (
                f"{tool['inferred_risk']} via {', '.join(matched)}"
                if matched
                else f"{tool['inferred_risk']} (no complete-token match)"
            )
        declared_risk = tool.get("declared_risk")
        declared_effects = (
            ", ".join(declared_risk["effects"]) if declared_risk else "—"
        )
        lines.append(
            "| {tool} | {risk} | {source} | {signal} ({confidence}) | "
            "{mutability} | {effects} | {conflict} | {review} | {confirmation} |".format(
                tool=_markdown_cell(tool["name"]),
                risk=_markdown_cell(tool["risk"]),
                source=_markdown_cell(tool["risk_source"]),
                signal=_markdown_cell(name_signal),
                confidence=_markdown_cell(risk_inference["confidence"]),
                mutability=_markdown_cell(risk_inference["mutability"]),
                effects=_markdown_cell(declared_effects),
                conflict="yes" if tool["risk_conflict"] else "no",
                review="yes" if tool["risk_review_required"] else "no",
                confirmation="yes" if tool["needs_confirmation"] else "no",
            )
        )
    declared_controls = report.get("declared_controls")
    if declared_controls is not None:
        lines.extend(
            [
                "",
                "## Declared controls (author-supplied)",
                "",
                f"> {_markdown_cell(declared_controls['verification_notice'])}",
                "",
                "Control declaration fingerprint: "
                f"`{report['control_declaration_fingerprint_sha256']}`",
            ]
        )
        attribution = declared_controls.get("attribution")
        if attribution:
            attribution_parts = [
                attribution[field] for field in ("name", "source") if field in attribution
            ]
            lines.append(
                "Attribution: " + _markdown_cell(" — ".join(attribution_parts))
            )
        lines.extend(
            [
                "",
                "| Tool | Argument | Schema exposure | Inferred policy | "
                "Declared control | Evidence | Details |",
                "|---|---|---|---|---|---|---|",
            ]
        )
        for tool in declared_controls["tools"]:
            for argument in tool["arguments"]:
                lines.append(
                    "| {tool} | {argument} | exposed | {policy} | {authority} | "
                    "{evidence} | {details} |".format(
                        tool=_markdown_cell(tool["name"]),
                        argument=_markdown_cell(argument["name"]),
                        policy=_markdown_cell(argument["inferred_policy"]),
                        authority=_markdown_cell(argument["authority"]),
                        evidence=_markdown_cell(argument["evidence"]),
                        details=_markdown_cell(_control_details(argument)),
                    )
                )
            for argument in tool["unexposed_arguments"]:
                lines.append(
                    "| {tool} | {argument} | unexposed | — | {exposure} | "
                    "{evidence} | {details} |".format(
                        tool=_markdown_cell(tool["name"]),
                        argument=_markdown_cell(argument["name"]),
                        exposure=_markdown_cell(argument["exposure"]),
                        evidence=_markdown_cell(argument["evidence"]),
                        details=_markdown_cell(_control_details(argument)),
                    )
                )
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Tool | Risk | Argument | Type | Required | Policy | Review | Reason |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for tool in report["tools"]:
        for argument in tool["arguments"]:
            lines.append(
                "| {tool} | {risk} | {argument} | {type} | {required} | "
                "{policy} | {review} | {reason} |".format(
                    tool=_markdown_cell(tool["name"]),
                    risk=_markdown_cell(tool["risk"]),
                    argument=_markdown_cell(argument["name"]),
                    type=_markdown_cell(argument["type"]),
                    required="yes" if argument["required"] else "no",
                    policy=_markdown_cell(argument["policy"]),
                    review="yes" if argument["review_required"] else "no",
                    reason=_markdown_cell(argument["reason"]),
                )
            )
        if not tool["arguments"]:
            lines.append(
                f"| {_markdown_cell(tool['name'])} | {_markdown_cell(tool['risk'])} | "
                "— | — | — | — | — | no arguments |"
            )
        for conflict in tool["annotation_conflicts"]:
            lines.append(
                f"| {_markdown_cell(tool['name'])} | {_markdown_cell(tool['risk'])} | "
                f"— | — | — | — | yes | {_markdown_cell(conflict)} |"
            )
    lines.extend(
        [
            "",
            "## Interpretation boundary",
            "",
            "This report describes Verb Authority's declared controls and review heuristics.",
            "A tool name is caller-mutable metadata and is never treated as proof of behavior.",
            "Without an explicit risk declaration, the effective tier remains `unknown` and",
            "requires review and runtime confirmation. This report is not a",
            "vulnerability verdict, does not inspect tool implementations, and does not prove",
            "that the surrounding application supplies correct provenance or authorization.",
            "Review every flagged argument against the real tool semantics before deployment.",
            "",
        ]
    )
    return "\n".join(lines)


def _load_json(path: str) -> Any:
    if path == "-":
        return json.load(sys.stdin)
    with Path(path).open(encoding="utf-8") as schema_file:
        return json.load(schema_file)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan exported MCP/OpenAI/Anthropic tool schemas locally."
    )
    parser.add_argument("schemas", nargs="+", help="JSON schema export(s), or - for stdin")
    parser.add_argument(
        "--format", choices=("markdown", "json"), default="markdown", help="report format"
    )
    parser.add_argument("--output", help="write the report to this file instead of stdout")
    parser.add_argument(
        "--controls",
        help="JSON declarations for author-supplied argument controls, or - for stdin",
    )
    parser.add_argument(
        "--redact-names",
        action="store_true",
        help="replace tool and parameter names with stable report-local identifiers",
    )
    parser.add_argument(
        "--fail-on-review",
        action="store_true",
        help="exit with status 2 when arguments, risks, or annotations require review",
    )
    args = parser.parse_args(argv)

    try:
        if args.controls == "-" and "-" in args.schemas:
            raise SchemaError("schemas and control declarations cannot both use stdin")
        controls = _load_json(args.controls) if args.controls else None
        report = scan_documents(
            [_load_json(path) for path in args.schemas],
            redact_names=args.redact_names,
            control_declarations=controls,
        )
    except (OSError, json.JSONDecodeError, SchemaError) as exc:
        parser.error(str(exc))

    if args.format == "json":
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    else:
        rendered = render_markdown(report)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="" if rendered.endswith("\n") else "\n")

    summary = report["summary"]
    if args.fail_on_review and (
        summary["review_required"]
        or summary["risk_review_required_tools"]
        or summary["risk_conflicts"]
        or summary["annotation_conflicts"]
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
