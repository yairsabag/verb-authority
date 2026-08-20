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


REPORT_VERSION = 1


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
        conflicts.append("readOnlyHint=true conflicts with inferred verb risk")
    elif read_only is False and risk is Risk.READ_ONLY:
        conflicts.append("readOnlyHint=false conflicts with inferred verb risk")
    if destructive is True and risk is not Risk.DESTRUCTIVE:
        conflicts.append("destructiveHint=true conflicts with inferred verb risk")
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


def scan_definitions(
    definitions: list[ToolDefinition], *, redact_names: bool = False
) -> dict[str, Any]:
    if not definitions:
        raise SchemaError("no tool definitions found")

    registry = Registry()
    params_by_tool: dict[str, list[Param]] = {}
    required_by_tool: dict[str, set[str]] = {}
    for definition in definitions:
        if definition.name in registry.tools:
            raise SchemaError(f"duplicate tool name: {definition.name}")
        properties, required = _properties(definition)
        params = [_param(name, raw) for name, raw in properties.items()]
        registry.add(Tool(definition.name, params))
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
        "annotation_conflicts": 0,
    }

    for tool_index, definition in enumerate(definitions, start=1):
        tool_name = definition.name
        display_tool = f"tool_{tool_index:03d}" if redact_names else tool_name
        risk = policy_set.risk[tool_name]
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
        tool_report: dict[str, Any] = {
            "name": display_tool,
            "risk": risk.value,
            "needs_confirmation": tool_name in policy_set.confirm,
            "annotation_conflicts": conflicts,
            "arguments": arguments,
        }
        if definition.source_id and not redact_names:
            tool_report["source_id"] = definition.source_id
        if definition.source_url and not redact_names:
            tool_report["source_url"] = definition.source_url
        report_tools.append(tool_report)

    return {
        "report_version": REPORT_VERSION,
        "generator": "verb-authority",
        "privacy": {
            "network_used": False,
            "server_executed": False,
            "descriptions_included": False,
            "examples_or_values_included": False,
            "names_redacted": redact_names,
        },
        "schema_fingerprint_sha256": _fingerprint(
            definitions, redact_names=redact_names
        ),
        "summary": counts,
        "tools": report_tools,
    }


def scan_documents(documents: Iterable[Any], *, redact_names: bool = False) -> dict[str, Any]:
    definitions: list[ToolDefinition] = []
    for document in documents:
        definitions.extend(parse_tool_definitions(document))
    return scan_definitions(definitions, redact_names=redact_names)


def _markdown_cell(value: Any) -> str:
    return html.escape(str(value), quote=False).replace("|", "\\|").replace("\n", " ")


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
            "This report describes Verb Authority's name/type-based inference. It is not a",
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
        "--redact-names",
        action="store_true",
        help="replace tool and parameter names with stable report-local identifiers",
    )
    parser.add_argument(
        "--fail-on-review",
        action="store_true",
        help="exit with status 2 when arguments or annotation conflicts require review",
    )
    args = parser.parse_args(argv)

    try:
        report = scan_documents(
            [_load_json(path) for path in args.schemas], redact_names=args.redact_names
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
        summary["review_required"] or summary["annotation_conflicts"]
    ):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
