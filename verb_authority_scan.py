"""Local tool-schema scanner for Verb Authority.

The scanner accepts exported MCP, OpenAI, or Anthropic tool definitions. It
never starts a tool server and contains no networking code. Reports omit tool
descriptions, examples, defaults, and runtime values so they can be reviewed or
shared with substantially less disclosure than the original schema.
"""

from __future__ import annotations

import argparse
import codecs
import copy
import hashlib
import html
import json
import math
import re
import sys
import unicodedata
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterable

from verb_authority import (
    Confidence,
    MAX_JSON_INTEGER_DIGITS,
    Param,
    Policy,
    Registry,
    Risk,
    SelectorCase,
    Tool,
    _PolicyInferenceContext,
    _compact_identifier_segments,
    _identifier_tokens,
    build_policy,
    infer_policy,
)


REPORT_VERSION = 6
CONTROL_DECLARATION_VERSION = 1
CONTROL_AUTHORITIES = frozenset({"constrained", "free", "locked"})
CONTROL_EVIDENCE = frozenset({"observed", "declared", "attested"})
BOUND_MUTABILITY = frozenset({"immutable", "trusted_party", "caller"})
BOUND_OPERATIONAL_STATUS = frozenset({"enforced", "specified"})
CONTROL_EXPOSURES = frozenset({"server_fixed"})
DECLARABLE_RISKS = frozenset(
    risk.value for risk in Risk if risk is not Risk.UNKNOWN
)
_CONFIRMATION_RISKS = frozenset(
    {Risk.UNKNOWN, Risk.FINANCIAL, Risk.DESTRUCTIVE, Risk.CODE_EXEC}
)
_BRANCH_RISK_PRIORITY = {
    Risk.READ_ONLY: 0,
    Risk.WRITE: 1,
    Risk.FINANCIAL: 2,
    Risk.CODE_EXEC: 3,
    Risk.DESTRUCTIVE: 4,
}
_BRANCH_SELECTOR_TOKENS = frozenset({"action", "operation", "method", "command"})
_MAX_RUNTIME_SELECTOR_INTEGER_ABS = 10 ** MAX_JSON_INTEGER_DIGITS
CONTROL_VERIFICATION_NOTICE = (
    "Control declarations are supplied by the report author. Their evidence "
    "labels and operational statuses are preserved but are not independently "
    "verified by this scanner."
)

REMEDIATION_STATUS_RECOMMENDED = "recommended"
REMEDIATION_STATUS_REVIEW_REQUIRED = "review_required"
REMEDIATION_REVIEW_REASON_SELECTOR = "selector_semantics_require_review"
REMEDIATION_REVIEW_REASON_AUTHORITY = "authority_inference_requires_review"
PREFERRED_TRUSTED_FIXED_REMEDIATION = (
    "remove_from_model_schema_and_inject_from_application"
)
FALLBACK_TRUSTED_FIXED_REMEDIATION = "bind_trusted_value_at_runtime"

_MCP_BOOLEAN_TOOL_ANNOTATIONS = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
)

_SCHEMA_ANNOTATION_KEYS = frozenset(
    {
        "$comment",
        "default",
        "deprecated",
        "description",
        "examples",
        "title",
    }
)
_SCHEMA_MAP_KEYWORDS = frozenset(
    {
        "$defs",
        "definitions",
        "dependencies",
        "dependentSchemas",
        "patternProperties",
        "properties",
    }
)
_SCHEMA_SINGLE_SUBSCHEMA_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
_SCHEMA_ARRAY_SUBSCHEMA_KEYWORDS = frozenset(
    {"allOf", "anyOf", "oneOf", "prefixItems"}
)
_SCHEMA_AUTHORITY_REVIEW_KEYWORDS = frozenset(
    {
        "$dynamicRef",
        "$recursiveRef",
        "$ref",
        "allOf",
        "anyOf",
        "dependencies",
        "dependentRequired",
        "dependentSchemas",
        "else",
        "if",
        "oneOf",
        "then",
    }
)
_SCHEMA_UNMODELED_AUTHORITY_KEYWORDS = frozenset(
    {
        "contains",
        "contentSchema",
        "items",
        "not",
        "prefixItems",
        "propertyNames",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
_SCHEMA_WRAPPER_KEYWORDS = frozenset(
    {
        "$defs",
        "$schema",
        "additionalProperties",
        "const",
        "enum",
        "maxProperties",
        "minProperties",
        "required",
        "type",
        "unevaluatedProperties",
        *_SCHEMA_MAP_KEYWORDS,
        *_SCHEMA_SINGLE_SUBSCHEMA_KEYWORDS,
        *_SCHEMA_ARRAY_SUBSCHEMA_KEYWORDS,
        *_SCHEMA_AUTHORITY_REVIEW_KEYWORDS,
    }
)
_MODELED_ARGUMENT_CONSTRAINTS = frozenset({"enum", "maxLength", "maximum"})
_SHA256_HEX_LENGTH = 64
MAX_JSON_DEPTH = 128
MAX_SCAN_INPUT_BYTES = 8 * 1024 * 1024
MAX_SCAN_TOTAL_INPUT_BYTES = 16 * 1024 * 1024
MAX_SCAN_SCHEMA_DOCUMENTS = 500
MAX_SCAN_JSON_NODES = 100_000
MAX_SCAN_JSON_MATERIAL_BYTES = 2 * 1024 * 1024
MAX_SCAN_TOOL_DEFINITIONS = 500
MAX_SCAN_ARGUMENTS = 2_000
MAX_SCAN_ENUM_MEMBERS = 10_000
MAX_SCAN_CONTROL_COLLECTION_MEMBERS = 2_000

_TOOL_SCHEMA_ALIASES = ("inputSchema", "input_schema", "parameters")
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
        "review_required",
        "review_sources",
        "needs_confirmation",
        "schema_review_required",
        "annotation_assessments",
        "annotation_conflicts",
        "branch_risk",
        "branch_risk_review_required",
        "schema_material_fingerprint_sha256",
        "unmodeled_schema_fingerprint_sha256",
    }
)


class SchemaError(ValueError):
    """Raised when an input does not contain recognizable tool definitions."""


class _CLIInputBudget:
    """Lazy raw-input budget shared by every document in one CLI scan."""

    __slots__ = ("remaining_bytes", "remaining_documents")

    def __init__(self) -> None:
        limits = (MAX_SCAN_TOTAL_INPUT_BYTES, MAX_SCAN_SCHEMA_DOCUMENTS)
        if any(type(limit) is not int or limit < 1 for limit in limits):
            raise SchemaError("scanner aggregate input limits are invalid")
        self.remaining_bytes = MAX_SCAN_TOTAL_INPUT_BYTES
        self.remaining_documents = MAX_SCAN_SCHEMA_DOCUMENTS

    def consume_document(self) -> None:
        self.remaining_documents -= 1
        if self.remaining_documents < 0:
            raise SchemaError(
                "scanner CLI input exceeds the aggregate document limit of "
                f"{MAX_SCAN_SCHEMA_DOCUMENTS}"
            )

    def consume_bytes(self, amount: int) -> None:
        self.remaining_bytes -= amount
        if self.remaining_bytes < 0:
            raise SchemaError(
                "scanner CLI input exceeds the aggregate UTF-8 input limit of "
                f"{MAX_SCAN_TOTAL_INPUT_BYTES} bytes"
            )


class _ScannerBudget:
    """Incremental resource budget for one logical scanner operation."""

    __slots__ = (
        "remaining_nodes",
        "remaining_material_bytes",
        "remaining_tools",
        "remaining_arguments",
        "remaining_enum_members",
        "remaining_control_collection_members",
    )

    def __init__(self) -> None:
        limits = (
            ("total node", MAX_SCAN_JSON_NODES),
            ("material byte", MAX_SCAN_JSON_MATERIAL_BYTES),
            ("tool-definition", MAX_SCAN_TOOL_DEFINITIONS),
            ("argument", MAX_SCAN_ARGUMENTS),
            ("enum-member", MAX_SCAN_ENUM_MEMBERS),
            ("control collection-member", MAX_SCAN_CONTROL_COLLECTION_MEMBERS),
        )
        if any(type(limit) is not int or limit < 1 for _, limit in limits):
            raise SchemaError("scanner resource limits are invalid")
        self.remaining_nodes = MAX_SCAN_JSON_NODES
        self.remaining_material_bytes = MAX_SCAN_JSON_MATERIAL_BYTES
        self.remaining_tools = MAX_SCAN_TOOL_DEFINITIONS
        self.remaining_arguments = MAX_SCAN_ARGUMENTS
        self.remaining_enum_members = MAX_SCAN_ENUM_MEMBERS
        self.remaining_control_collection_members = (
            MAX_SCAN_CONTROL_COLLECTION_MEMBERS
        )

    def consume_material(self, amount: int) -> None:
        self.remaining_material_bytes -= amount
        if self.remaining_material_bytes < 0:
            raise SchemaError(
                "scanner JSON exceeds the conservative material limit of "
                f"{MAX_SCAN_JSON_MATERIAL_BYTES} bytes"
            )

    def consume_node(self) -> None:
        self.remaining_nodes -= 1
        if self.remaining_nodes < 0:
            raise SchemaError(
                "scanner JSON exceeds the total node limit of "
                f"{MAX_SCAN_JSON_NODES}"
            )
        # Conservatively charge a scalar position or adjacent comma/colon.
        self.consume_material(1)

    def consume_text(self, value: str) -> None:
        # Quotes plus the ASCII-safe representation used by JSON reports.
        self.consume_material(2)
        for character in value:
            codepoint = ord(character)
            if 0xD800 <= codepoint <= 0xDFFF:
                raise SchemaError("scanner JSON contains invalid Unicode")
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

    def _consume_count(self, field: str, amount: int) -> None:
        attribute = f"remaining_{field}"
        remaining = getattr(self, attribute) - amount
        setattr(self, attribute, remaining)
        if remaining < 0:
            limits = {
                "tools": MAX_SCAN_TOOL_DEFINITIONS,
                "arguments": MAX_SCAN_ARGUMENTS,
                "enum_members": MAX_SCAN_ENUM_MEMBERS,
                "control_collection_members": MAX_SCAN_CONTROL_COLLECTION_MEMBERS,
            }
            labels = {
                "tools": "tool-definition",
                "arguments": "argument",
                "enum_members": "enum-member",
                "control_collection_members": "control collection-member",
            }
            raise SchemaError(
                f"scanner input exceeds the {labels[field]} limit of "
                f"{limits[field]}"
            )

    def consume_tools(self, amount: int) -> None:
        self._consume_count("tools", amount)

    def consume_arguments(self, amount: int) -> None:
        self._consume_count("arguments", amount)

    def consume_enum_members(self, amount: int) -> None:
        self._consume_count("enum_members", amount)

    def consume_control_collection_members(self, amount: int) -> None:
        self._consume_count("control_collection_members", amount)


def _validate_plain_json(
    value: Any,
    *,
    field: str = "JSON input",
    active: set[int] | None = None,
    seen: set[int] | None = None,
    depth: int = 0,
    budget: _ScannerBudget | None = None,
) -> None:
    """Require a finite, alias-free tree of exact JSON-compatible types."""

    budget = _ScannerBudget() if budget is None else budget
    budget.consume_node()
    value_type = type(value)
    if value_type in (str, int, bool) or value is None:
        if value_type is str:
            budget.consume_text(value)
        elif value is None:
            budget.consume_material(4)
        elif value_type is bool:
            budget.consume_material(4 if value else 5)
        else:
            try:
                budget.consume_material(len(str(value)))
            except ValueError as exc:
                raise SchemaError(f"{field} contains an oversized integer") from exc
        return
    if value_type is float:
        if not math.isfinite(value):
            raise SchemaError(f"{field} contains a non-finite number")
        budget.consume_material(32)
        return
    if value_type is Decimal:
        if not value.is_finite():
            raise SchemaError(f"{field} contains a non-finite number")
        try:
            budget.consume_material(len(str(value)))
        except (MemoryError, ValueError) as exc:
            raise SchemaError(f"{field} contains an oversized decimal") from exc
        return
    if value_type not in (dict, list):
        raise SchemaError(f"{field} must contain only plain JSON values")
    if depth >= MAX_JSON_DEPTH:
        raise SchemaError(
            f"{field} exceeds the maximum nesting depth of {MAX_JSON_DEPTH}"
        )
    budget.consume_material(1)  # closing list/object bracket

    active = set() if active is None else active
    seen = set() if seen is None else seen
    identity = id(value)
    if identity in active:
        raise SchemaError(f"{field} contains a cycle")
    if identity in seen:
        raise SchemaError(
            f"{field} contains a repeated container alias; plain JSON must be a tree"
        )
    seen.add(identity)
    active.add(identity)
    try:
        if value_type is dict:
            for key, child in value.items():
                if type(key) is not str:
                    raise SchemaError(f"{field} contains a non-string object key")
                try:
                    budget.consume_node()
                    budget.consume_text(key)
                except SchemaError as exc:
                    raise SchemaError(f"{field}: {exc}") from exc
                _validate_plain_json(
                    child,
                    field=field,
                    active=active,
                    seen=seen,
                    depth=depth + 1,
                    budget=budget,
                )
        else:
            for child in value:
                _validate_plain_json(
                    child,
                    field=field,
                    active=active,
                    seen=seen,
                    depth=depth + 1,
                    budget=budget,
                )
    finally:
        active.remove(identity)


def validate_plain_json(
    value: Any,
    *,
    field: str = "JSON input",
    _budget: _ScannerBudget | None = None,
) -> None:
    """Validate a public API value against the scanner's strict JSON boundary."""

    try:
        _validate_plain_json(value, field=field, budget=_budget)
    except RecursionError as exc:
        raise SchemaError(f"{field} exceeds the maximum nesting depth") from exc
    except MemoryError as exc:
        raise SchemaError(f"{field} exceeds available scanner resources") from exc


def _reject_json_constant(value: str) -> Any:
    raise SchemaError(f"JSON input contains non-standard numeric constant {value}")


def _json_object_without_duplicates(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise SchemaError(f"JSON input contains duplicate object key: {key}")
        value[key] = item
    return value


def _scanner_input_limit() -> int:
    if type(MAX_SCAN_INPUT_BYTES) is not int or MAX_SCAN_INPUT_BYTES < 1:
        raise SchemaError("scanner input-byte limit is invalid")
    return MAX_SCAN_INPUT_BYTES


def _read_bounded_json_text(
    stream: Any, *, _input_budget: _CLIInputBudget | None = None
) -> str:
    limit = _scanner_input_limit()
    chunks: list[str] = []
    total_bytes = 0
    stream_kind: str | None = None
    decoder: Any = None
    while True:
        chunk = stream.read(64 * 1024)
        if chunk == "" or chunk == b"":
            break
        if type(chunk) is str:
            if stream_kind == "bytes":
                raise SchemaError("JSON input stream changed data type")
            stream_kind = "text"
            try:
                chunk_bytes = len(chunk.encode("utf-8"))
            except UnicodeEncodeError as exc:
                raise SchemaError("JSON input contains invalid Unicode") from exc
            decoded_chunk = chunk
        elif type(chunk) is bytes:
            if stream_kind == "text":
                raise SchemaError("JSON input stream changed data type")
            stream_kind = "bytes"
            if decoder is None:
                decoder = codecs.getincrementaldecoder("utf-8")("strict")
            chunk_bytes = len(chunk)
            try:
                decoded_chunk = decoder.decode(chunk)
            except UnicodeDecodeError as exc:
                raise SchemaError("JSON input contains invalid Unicode") from exc
        else:
            raise SchemaError("JSON input stream must provide text or bytes")
        total_bytes += chunk_bytes
        if _input_budget is not None:
            _input_budget.consume_bytes(chunk_bytes)
        if total_bytes > limit:
            raise SchemaError(
                f"JSON input exceeds the UTF-8 input limit of {limit} bytes"
            )
        chunks.append(decoded_chunk)
    if stream_kind == "bytes":
        try:
            final_chunk = decoder.decode(b"", final=True)
        except UnicodeDecodeError as exc:
            raise SchemaError("JSON input contains invalid Unicode") from exc
        if final_chunk:
            chunks.append(final_chunk)
    return "".join(chunks)


def _load_json_stream(
    stream: Any, *, _input_budget: _CLIInputBudget | None = None
) -> Any:
    try:
        value = json.loads(
            _read_bounded_json_text(stream, _input_budget=_input_budget),
            object_pairs_hook=_json_object_without_duplicates,
            parse_constant=_reject_json_constant,
            parse_float=Decimal,
        )
        _validate_plain_json(value)
    except SchemaError:
        raise
    except MemoryError as exc:
        raise SchemaError("JSON input exceeds available scanner resources") from exc
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise SchemaError(f"invalid JSON input: {exc}") from exc
    return value


def load_json_path(
    path: str,
    *,
    allow_stdin: bool = False,
    _input_budget: _CLIInputBudget | None = None,
) -> Any:
    """Load strict JSON while rejecting duplicate keys and non-finite numbers."""

    if _input_budget is not None:
        _input_budget.consume_document()
    if path == "-":
        if not allow_stdin:
            raise SchemaError("stdin is not supported for this input")
        stdin_stream = getattr(sys.stdin, "buffer", sys.stdin)
        return _load_json_stream(stdin_stream, _input_budget=_input_budget)
    input_path = Path(path)
    limit = _scanner_input_limit()
    if input_path.stat().st_size > limit:
        raise SchemaError(
            f"JSON input exceeds the UTF-8 input limit of {limit} bytes"
        )
    with input_path.open("rb") as source:
        return _load_json_stream(source, _input_budget=_input_budget)


@dataclass
class ToolDefinition:
    name: str
    input_schema: dict[str, Any]
    annotations: dict[str, Any]
    source_id: str | None = None
    source_url: str | None = None


def _entry_is_report_shaped(entry: Any) -> bool:
    if type(entry) is not dict:
        return False
    if (
        "generator" in entry
        or _REPORT_SENTINEL_KEYS.intersection(entry)
        or _REPORT_TOOL_SENTINEL_KEYS.intersection(entry)
    ):
        return True
    function = entry.get("function")
    return (
        entry.get("type") == "function"
        and type(function) is dict
        and (
            "generator" in function
            or bool(_REPORT_SENTINEL_KEYS.intersection(function))
            or bool(_REPORT_TOOL_SENTINEL_KEYS.intersection(function))
        )
    )


def _container_has_report_tool(container: Any) -> bool:
    if type(container) is list:
        return any(_entry_is_report_shaped(entry) for entry in container)
    if type(container) is dict:
        if _entry_is_report_shaped(container):
            return True
        return any(_entry_is_report_shaped(entry) for entry in container.values())
    return False


def is_report_shaped_document(document: Any) -> bool:
    """Recognize scanner reports, including malformed supported envelopes.

    The diff accepts either raw schemas or existing reports.  A damaged report
    must never become a seemingly valid raw-schema scan merely because its
    envelope changed from an array to an object or was combined with a second
    dialect.  Inspection is deliberately limited to supported envelope paths;
    arbitrary JSON Schema subschemas are not searched for report vocabulary.
    """

    if type(document) is list:
        return _container_has_report_tool(document)
    if type(document) is not dict:
        return False
    if "generator" in document or _REPORT_SENTINEL_KEYS.intersection(document):
        return True
    if "name" in document and _entry_is_report_shaped(document):
        return True
    if _container_has_report_tool(document.get("tools")):
        return True
    if _container_has_report_tool(document.get("functions")):
        return True

    result = document.get("result")
    if type(result) is dict:
        if "generator" in result or _REPORT_SENTINEL_KEYS.intersection(result):
            return True
        if _container_has_report_tool(result.get("tools")):
            return True

    sources = document.get("sources")
    source_entries: Iterable[Any]
    if type(sources) is list:
        source_entries = sources
    elif type(sources) is dict:
        source_entries = sources.values()
    else:
        source_entries = ()
    for source in source_entries:
        if type(source) is not dict:
            continue
        if "generator" in source or _REPORT_SENTINEL_KEYS.intersection(source):
            return True
        if _container_has_report_tool(source.get("tools")):
            return True
    return False


def _select_schema_alias(
    raw: dict[str, Any],
    *,
    field: str,
    required_alias: str | None = None,
    allow_missing: bool = False,
) -> dict[str, Any]:
    aliases = [alias for alias in _TOOL_SCHEMA_ALIASES if alias in raw]
    if len(aliases) > 1:
        raise SchemaError(
            f"{field} contains competing input schema aliases: "
            + ", ".join(aliases)
        )
    if not aliases:
        if allow_missing:
            return {}
        raise SchemaError(
            f"{field} must contain exactly one input schema alias "
            f"({', '.join(_TOOL_SCHEMA_ALIASES)})"
        )
    alias = aliases[0]
    if required_alias is not None and alias != required_alias:
        raise SchemaError(
            f"{field} uses schema alias '{alias}' from a competing tool dialect; "
            f"expected '{required_alias}'"
        )
    schema = raw[alias]
    if type(schema) is not dict:
        raise SchemaError(f"{field} has a non-object input schema")
    return schema


def _validate_tool_annotations(name: str, annotations: Any) -> None:
    if type(annotations) is not dict:
        raise SchemaError(f"tool '{name}' has non-object annotations")
    for annotation in _MCP_BOOLEAN_TOOL_ANNOTATIONS:
        if annotation in annotations and type(annotations[annotation]) is not bool:
            raise SchemaError(
                f"tool '{name}' annotation '{annotation}' must be boolean"
            )


def _tool_from_mapping(
    raw: dict[str, Any],
    *,
    source_id: str | None = None,
    source_url: str | None = None,
) -> ToolDefinition:
    source_id = raw.get("source_id", source_id)
    source_url = raw.get("source_url", source_url)

    # Chat Completions wraps a function under ``function``. Responses uses the
    # equally valid direct shape ``{type: function, name, parameters}``; the
    # type discriminator alone must therefore not force the nested dialect.
    nested_marker = "function" in raw
    direct_marker = "name" in raw or any(
        alias in raw for alias in _TOOL_SCHEMA_ALIASES
    )
    if nested_marker:
        if raw.get("type") != "function" or type(raw.get("function")) is not dict:
            raise SchemaError("malformed nested OpenAI function tool definition")
        if direct_marker:
            raise SchemaError(
                "tool definition combines direct and nested OpenAI/MCP dialects"
            )
        function = raw["function"]
        name = function.get("name")
        schema = _select_schema_alias(
            function,
            field=f"nested function tool {name!r}",
            required_alias="parameters",
            allow_missing=True,
        )
        annotations = raw.get("annotations", {})
    else:
        name = raw.get("name")
        if (
            "parameters" in raw
            and "type" in raw
            and raw["type"] != "function"
        ):
            raise SchemaError(
                "direct OpenAI function tool definition with 'parameters' "
                "must use type 'function'"
            )
        responses_function = raw.get("type") == "function"
        schema = _select_schema_alias(
            raw,
            field=f"tool {name!r}",
            required_alias="parameters" if responses_function else None,
            allow_missing=responses_function,
        )
        annotations = raw.get("annotations", {})

    if not isinstance(name, str) or not name.strip():
        raise SchemaError("tool definition is missing a non-empty name")
    _validate_tool_annotations(name, annotations)
    return ToolDefinition(
        name=name,
        input_schema=schema,
        annotations=annotations,
        source_id=source_id,
        source_url=source_url,
    )


def _parse_tool_definitions_unchecked(document: Any) -> list[ToolDefinition]:
    """Normalize one already validated tool-schema envelope.

    Supported shapes include MCP ``tools/list`` results, OpenAI function tools,
    Anthropic tools, and the attributed ``sources`` envelope used by the public
    Atlas fixture.
    """

    if is_report_shaped_document(document):
        raise SchemaError(
            "schema document is report-shaped; expected raw tool definitions"
        )

    if type(document) is list:
        if not document:
            return []
        if any(type(item) is not dict for item in document):
            raise SchemaError("tool definitions must be JSON objects")
        return [_tool_from_mapping(item) for item in document]

    if type(document) is not dict:
        raise SchemaError("schema document must be a JSON object or array")

    envelopes: list[str] = []
    if "sources" in document:
        if type(document["sources"]) is not list:
            raise SchemaError("Atlas sources envelope must contain a sources array")
        envelopes.append("sources")
    result = document.get("result")
    if type(result) is dict and "tools" in result:
        if type(result["tools"]) is not list:
            raise SchemaError("MCP result.tools envelope must contain a tools array")
        envelopes.append("result.tools")
    if "tools" in document:
        if type(document["tools"]) is not list:
            raise SchemaError("tools envelope must contain a tools array")
        envelopes.append("tools")
    if "functions" in document:
        if type(document["functions"]) is not list:
            raise SchemaError("functions envelope must contain a functions array")
        envelopes.append("functions")
    direct_schema = any(alias in document for alias in _TOOL_SCHEMA_ALIASES)
    direct_openai_function = document.get("type") == "function"
    if "name" in document and (direct_schema or direct_openai_function):
        envelopes.append("direct tool")

    if len(envelopes) > 1:
        raise SchemaError(
            "schema document contains competing tool-definition envelopes: "
            + ", ".join(envelopes)
        )
    if not envelopes:
        raise SchemaError("no recognizable tool definitions found")

    envelope = envelopes[0]
    if envelope == "sources":
        tools: list[ToolDefinition] = []
        for source in document["sources"]:
            if type(source) is not dict or type(source.get("tools")) is not list:
                raise SchemaError("each Atlas source must contain a tools array")
            source_id = source.get("id")
            source_url = source.get("url")
            for raw in source["tools"]:
                if type(raw) is not dict:
                    raise SchemaError("tool definitions must be JSON objects")
                tools.append(
                    _tool_from_mapping(
                        raw,
                        source_id=source_id if isinstance(source_id, str) else None,
                        source_url=source_url if isinstance(source_url, str) else None,
                    )
                )
        return tools

    if envelope == "result.tools":
        return _parse_tool_definitions_unchecked(result["tools"])
    if envelope == "tools":
        return _parse_tool_definitions_unchecked(document["tools"])
    if envelope == "functions":
        if any(type(function) is not dict for function in document["functions"]):
            raise SchemaError("function definitions must be JSON objects")
        return [
            _tool_from_mapping({"type": "function", "function": function})
            for function in document["functions"]
        ]
    if envelope == "direct tool":
        return [_tool_from_mapping(document)]

    raise AssertionError("unreachable tool-definition envelope")


def parse_tool_definitions(document: Any) -> list[ToolDefinition]:
    """Validate and normalize one exported tool-schema document."""

    try:
        budget = _ScannerBudget()
        _validate_plain_json(document, field="schema document", budget=budget)
        definitions = _parse_tool_definitions_unchecked(document)
        _consume_definition_limits(definitions, budget)
        return definitions
    except MemoryError as exc:
        raise SchemaError("schema document exceeds available scanner resources") from exc


def _property_type(schema: dict[str, Any]) -> str:
    if isinstance(schema.get("enum"), list):
        return "enum"
    schema_type = schema.get("type", "string")
    if isinstance(schema_type, list):
        non_null_types = {
            item for item in schema_type if type(item) is str and item != "null"
        }
        schema_type = (
            next(iter(non_null_types)) if len(non_null_types) == 1 else "json"
        )
    if not isinstance(schema_type, str):
        schema_type = "string"
    value_format = schema.get("format")
    if value_format == "email":
        return "email"
    if value_format in {"uri", "uri-reference", "url"}:
        return "uri"
    return schema_type


def _enum_value_fingerprint(value: Any) -> str:
    """Return a stable, type-preserving digest without reporting enum values."""

    try:
        return _canonical_sha256(value)
    except SchemaError as exc:
        raise SchemaError("enum members must be JSON-compatible values") from exc


def _canonical_decimal_text(value: Decimal) -> str:
    """Return a finite Decimal's exact value in bounded canonical notation."""

    if not value.is_finite():
        raise SchemaError("JSON numbers must be finite")
    sign, raw_digits, exponent = value.as_tuple()
    prefix = "-" if sign else ""
    digits = list(raw_digits)
    while len(digits) > 1 and digits[-1] == 0:
        digits.pop()
        exponent += 1
    if not any(digits):
        return prefix + "0"

    digit_text = "".join(str(digit) for digit in digits)
    point = len(digit_text) + exponent
    if 0 < point <= 128:
        if point >= len(digit_text):
            return prefix + digit_text + ("0" * (point - len(digit_text)))
        return prefix + digit_text[:point] + "." + digit_text[point:]
    if -128 < point <= 0:
        return prefix + "0." + ("0" * -point) + digit_text

    adjusted_exponent = point - 1
    coefficient = digit_text[:1]
    if len(digit_text) > 1:
        coefficient += "." + digit_text[1:]
    exponent_sign = "+" if adjusted_exponent >= 0 else ""
    return f"{prefix}{coefficient}e{exponent_sign}{adjusted_exponent}"


def canonical_decimal_text(value: Decimal | float) -> str:
    """Canonical report representation for a non-integer JSON number.

    JSON text is loaded as :class:`Decimal`, so no decimal digits are first
    rounded through a binary float. Direct Python ``float`` inputs necessarily
    describe an already-rounded value; their shortest round-tripping decimal
    representation is canonicalized here.
    """

    if type(value) is float:
        if not math.isfinite(value):
            raise SchemaError("JSON numbers must be finite")
        value = Decimal(repr(value))
    if type(value) is not Decimal:
        raise SchemaError("value must be a decimal JSON number")
    return _canonical_decimal_text(value)


def _contains_exact_noninteger(value: Any) -> bool:
    if type(value) in (float, Decimal):
        return True
    if type(value) is dict:
        return any(_contains_exact_noninteger(item) for item in value.values())
    if type(value) is list:
        return any(_contains_exact_noninteger(item) for item in value)
    return False


def _typed_canonical_bytes(value: Any) -> bytes:
    """Encode a plain JSON value without collisions between JSON types."""

    value_type = type(value)
    if value is None:
        return b"n"
    if value_type is bool:
        return b"b1" if value else b"b0"
    if value_type is int:
        encoded = str(value).encode("ascii")
        return b"i" + str(len(encoded)).encode("ascii") + b":" + encoded
    if value_type is float:
        if not math.isfinite(value):
            raise SchemaError("schema material contains a non-finite number")
        encoded = canonical_decimal_text(value).encode("ascii")
        return b"d" + str(len(encoded)).encode("ascii") + b":" + encoded
    if value_type is Decimal:
        encoded = _canonical_decimal_text(value).encode("ascii")
        return b"d" + str(len(encoded)).encode("ascii") + b":" + encoded
    if value_type is str:
        encoded = value.encode("utf-8")
        return b"s" + str(len(encoded)).encode("ascii") + b":" + encoded
    if value_type is list:
        return (
            b"l"
            + str(len(value)).encode("ascii")
            + b":"
            + b"".join(_typed_canonical_bytes(item) for item in value)
        )
    if value_type is dict:
        encoded_items = []
        for key in sorted(value):
            if type(key) is not str:
                raise SchemaError("schema material contains a non-string key")
            encoded_items.append(_typed_canonical_bytes(key))
            encoded_items.append(_typed_canonical_bytes(value[key]))
        return (
            b"o"
            + str(len(value)).encode("ascii")
            + b":"
            + b"".join(encoded_items)
        )
    raise SchemaError("schema material must contain only plain JSON values")


def _schema_material(value: Any) -> Any:
    """Return canonical validation material with annotations removed.

    Property and definition names are data inside their containing maps, so
    they are retained even when they happen to equal an annotation keyword.
    Enum and const members are instance values rather than subschemas and are
    likewise copied without interpreting their object keys as annotations.
    """

    if type(value) is not dict:
        return value

    material: dict[str, Any] = {}
    for key, item in value.items():
        if key in _SCHEMA_ANNOTATION_KEYS:
            continue
        if key in _SCHEMA_MAP_KEYWORDS and type(item) is dict:
            material[key] = {
                name: (
                    _schema_material(subschema)
                    if type(subschema) in (dict, bool)
                    else subschema
                )
                for name, subschema in item.items()
            }
        elif key in _SCHEMA_SINGLE_SUBSCHEMA_KEYWORDS:
            if type(item) is dict or type(item) is bool:
                material[key] = _schema_material(item)
            elif key == "items" and type(item) is list:
                material[key] = [
                    _schema_material(subschema)
                    if type(subschema) in (dict, bool)
                    else subschema
                    for subschema in item
                ]
            else:
                material[key] = item
        elif key in _SCHEMA_ARRAY_SUBSCHEMA_KEYWORDS and type(item) is list:
            material[key] = [
                _schema_material(subschema)
                if type(subschema) in (dict, bool)
                else subschema
                for subschema in item
            ]
        else:
            # Unknown and raw-value keyword payloads are data, not schemas.
            # Preserve annotation-named members nested inside them. For
            # example, discriminator.mapping.default changes validation
            # behavior and must remain in the fingerprint material.
            material[key] = item
    return material


def _canonical_sha256(value: Any) -> str:
    try:
        if _contains_exact_noninteger(value):
            encoded = b"verb-authority-decimal-canonical-v1\0" + (
                _typed_canonical_bytes(value)
            )
        else:
            encoded = json.dumps(
                value,
                allow_nan=False,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError) as exc:
        raise SchemaError("schema material must be canonical plain JSON") from exc
    return hashlib.sha256(encoded).hexdigest()


def _definition_schema_material(definition: ToolDefinition) -> Any:
    """Preserve both wrapped JSON Schema and supported direct-shape exports."""

    if "properties" in definition.input_schema:
        return _schema_material(definition.input_schema)

    properties, _ = _properties(definition)
    reserved = {
        key: value
        for key, value in definition.input_schema.items()
        if key not in properties
    }
    material = _schema_material(reserved)
    if type(material) is not dict:
        material = {}
    material["properties"] = {
        name: _schema_material(property_schema)
        for name, property_schema in properties.items()
    }
    return material


def _argument_schema_material(schema: Any) -> tuple[str, str]:
    full_material = _schema_material(schema)
    residual_material = _schema_material(schema)
    if type(residual_material) is dict:
        for field in _MODELED_ARGUMENT_CONSTRAINTS:
            residual_material.pop(field, None)
    return (
        _canonical_sha256(full_material),
        _canonical_sha256(residual_material),
    )


def _tool_schema_material(
    definition: ToolDefinition,
) -> tuple[str, str]:
    properties, _ = _properties(definition)
    full_material = _definition_schema_material(definition)
    residual_material = _definition_schema_material(definition)
    if type(residual_material) is dict:
        residual_material.pop("properties", None)

        raw_required = definition.input_schema.get("required")
        if type(raw_required) is list:
            unmodeled_required = sorted(set(raw_required) - set(properties))
            if unmodeled_required:
                residual_material["required"] = unmodeled_required
            else:
                residual_material.pop("required", None)

        additional_properties = definition.input_schema.get("additionalProperties")
        if type(additional_properties) is bool:
            residual_material.pop("additionalProperties", None)
    return (
        _canonical_sha256(full_material),
        _canonical_sha256(residual_material),
    )


def _normalized_constraints(
    schema: Any, *, redact_values: bool = False
) -> dict[str, Any]:
    """Preserve the small constraint vocabulary the runtime already parses.

    Enum members are represented only by stable fingerprints. This is enough
    for set comparison while keeping the original schema values out of both
    named and redacted reports.
    """

    if not isinstance(schema, dict):
        return {}

    constraints: dict[str, Any] = {}
    if "maximum" in schema:
        maximum = schema["maximum"]
        if not (
            type(maximum) is int
            or (type(maximum) is float and math.isfinite(maximum))
            or (type(maximum) is Decimal and maximum.is_finite())
        ):
            raise SchemaError("schema maximum must be a finite number")
        if redact_values:
            constraints["maximum_present"] = True
        elif type(maximum) in (float, Decimal):
            constraints["maximum"] = canonical_decimal_text(maximum)
        else:
            constraints["maximum"] = maximum

    if "maxLength" in schema:
        max_length = schema["maxLength"]
        if type(max_length) is not int or max_length < 0:
            raise SchemaError("schema maxLength must be a non-negative integer")
        if redact_values:
            constraints["max_length_present"] = True
        else:
            constraints["max_length"] = max_length

    if "enum" in schema:
        enum = schema["enum"]
        if type(enum) is not list:
            raise SchemaError("schema enum must be an array")
        fingerprints = sorted({_enum_value_fingerprint(value) for value in enum})
        if len(fingerprints) != len(enum):
            raise SchemaError("schema enum members must be unique")
        if redact_values:
            constraints["enum"] = {
                "count": len(fingerprints),
                "values_redacted": True,
            }
        else:
            constraints["enum"] = {
                "count": len(fingerprints),
                "value_fingerprints_sha256": fingerprints,
            }
    return constraints


def _policy_json_value(value: Any) -> Any:
    """Make exact parsed decimals safe for the scanner-only policy model."""

    if type(value) is Decimal:
        return canonical_decimal_text(value)
    if type(value) is list:
        return [_policy_json_value(item) for item in value]
    if type(value) is dict:
        return {key: _policy_json_value(item) for key, item in value.items()}
    return value


def _param(name: str, schema: Any) -> Param:
    if not isinstance(schema, dict):
        schema = {}
    param_type = _property_type(schema)
    enum = schema.get("enum") if param_type == "enum" else None
    constraints = _normalized_constraints(schema)
    # ``Param.cap`` is used here only to establish that a numeric argument is
    # bounded; report and diff semantics use the exact normalized constraint.
    # The runtime Param API intentionally accepts only built-in numbers.
    cap = 0.0 if "maximum" in constraints else None
    max_len = constraints.get("max_length")
    return Param(
        name=name,
        type=param_type,
        enum=_policy_json_value(enum) if isinstance(enum, list) else None,
        max_len=max_len,
        cap=cap,
    )


def _is_direct_shape_schema(schema: Any) -> bool:
    """Recognize SDK exports whose root maps argument names to schemas."""

    return (
        type(schema) is dict
        and "properties" not in schema
        and bool(schema)
        and all(type(value) in (dict, bool) for value in schema.values())
    )


def _properties(definition: ToolDefinition) -> tuple[dict[str, Any], set[str]]:
    schema = definition.input_schema
    properties_present = "properties" in schema
    properties = schema.get("properties")
    direct_shape = not properties_present and _is_direct_shape_schema(schema)
    if not properties_present:
        # Some SDK exports expose the input shape directly rather than wrapping
        # it in a JSON Schema object. A document containing recognized schema
        # structure is still a wrapped schema, even when its caller-visible
        # properties are supplied only through an unresolved reference or
        # combinator.
        if direct_shape:
            properties = dict(schema)
        elif _SCHEMA_WRAPPER_KEYWORDS.intersection(schema):
            properties = {}
        else:
            properties = dict(schema)
    if not isinstance(properties, dict):
        raise SchemaError(f"tool '{definition.name}' has non-object properties")
    for name, property_schema in properties.items():
        if type(name) is not str or not name:
            raise SchemaError(
                f"tool '{definition.name}' has an invalid property name"
            )
        if type(property_schema) not in (dict, bool):
            raise SchemaError(
                f"tool '{definition.name}' property '{name}' must be a schema object "
                "or boolean"
            )
    required = [] if direct_shape else schema.get("required", [])
    if type(required) is not list or any(type(item) is not str for item in required):
        raise SchemaError(f"tool '{definition.name}' required must be an array of names")
    if len(required) != len(set(required)):
        raise SchemaError(f"tool '{definition.name}' required names must be unique")
    return properties, set(required)


def _schema_closes_unknown_arguments(definition: ToolDefinition) -> bool:
    schema = definition.input_schema
    pattern_properties = schema.get("patternProperties")
    pattern_properties_are_empty = (
        "patternProperties" not in schema
        or (type(pattern_properties) is dict and not pattern_properties)
    )
    return (
        not _is_direct_shape_schema(schema)
        and schema.get("additionalProperties") is False
        and pattern_properties_are_empty
    )


def _schema_requires_authority_review(schema: Any) -> bool:
    """Flag composition the scanner deliberately does not resolve.

    The scanner models only the caller-visible ``properties`` at the exported
    input-schema root. References, combinators, and conditional/dependent
    schemas can add or alter those properties, so their presence must remain a
    visible review obligation rather than silently producing a complete-looking
    per-argument report. Traversal follows schema-bearing keyword positions and
    intentionally does not interpret instance values such as ``enum`` members.
    """

    if type(schema) is bool:
        # Boolean property schemas are valid JSON Schema, but the scanner's
        # Param model does not represent "accept everything"/"accept nothing".
        return True
    if type(schema) is not dict:
        return False
    if _is_direct_shape_schema(schema):
        # A direct-shape argument may legitimately be named ``type``, ``enum``,
        # or another JSON Schema keyword. Preserve every argument, but surface
        # the unavoidable direct-vs-wrapper ambiguity for explicit review.
        return bool(_SCHEMA_WRAPPER_KEYWORDS.intersection(schema)) or any(
            _schema_requires_authority_review(subschema)
            for subschema in schema.values()
        )
    if "properties" in schema and schema.get("type") != "object":
        # A root mapping named ``properties`` is indistinguishable from a
        # direct-shape argument with that literal name unless the document
        # unambiguously declares an object schema. Preserve any modeled inner
        # arguments, but never present the ambiguous shape as a clean audit.
        return True
    schema_type = schema.get("type")
    if type(schema_type) is list and (
        len(schema_type) != 1
        or any(type(item) is not str for item in schema_type)
    ):
        # The runtime policy model represents one exact JSON type. A union can
        # make constraints type-conditional (for example, maximum does not
        # constrain a string), so selecting one member would overstate safety.
        return True
    if "properties" in schema and any(
        key not in _SCHEMA_WRAPPER_KEYWORDS
        and key not in _SCHEMA_ANNOTATION_KEYS
        and type(value) in (dict, bool)
        for key, value in schema.items()
    ):
        # ``properties`` is the one direct-shape argument name that is
        # structurally indistinguishable from a wrapped schema. If schema-like
        # siblings would otherwise disappear, retain a visible review debt.
        return True
    if (
        _SCHEMA_AUTHORITY_REVIEW_KEYWORDS.intersection(schema)
        or _SCHEMA_UNMODELED_AUTHORITY_KEYWORDS.intersection(schema)
    ):
        return True

    if "patternProperties" in schema:
        pattern_properties = schema["patternProperties"]
        if type(pattern_properties) is not dict or pattern_properties:
            return True
    if type(schema.get("additionalProperties")) is dict:
        return True

    properties = schema.get("properties")
    required = schema.get("required")
    if type(required) is list:
        modeled_properties = (
            set(properties) if type(properties) is dict else set()
        )
        if any(
            type(name) is not str or name not in modeled_properties
            for name in required
        ):
            # A required name that is absent from the properties map is still
            # caller-visible when unknown arguments remain open. The scanner
            # cannot infer its type or authority policy, so an empty argument
            # list must not look like a complete analysis.
            return True

    # Root ``properties`` and nested object properties are the only schema map
    # this scanner actually enumerates. Follow those paths so a ref/combinator
    # inside an argument is still surfaced. Deliberately do not walk `$defs`
    # or legacy `definitions`: an unused helper definition is inert, while any
    # reference to it is already caught at the reference site.
    return type(properties) is dict and any(
        _schema_requires_authority_review(subschema)
        for subschema in properties.values()
    )


def _consume_definition_limits(
    definitions: list[ToolDefinition], budget: _ScannerBudget
) -> None:
    """Charge schema cardinalities once, before report expansion begins."""

    budget.consume_tools(len(definitions))
    for definition in definitions:
        _consume_definition_detail_limits(definition, budget)


def _consume_definition_detail_limits(
    definition: ToolDefinition, budget: _ScannerBudget
) -> None:
    properties, _ = _properties(definition)
    budget.consume_arguments(len(properties))
    for property_schema in properties.values():
        if type(property_schema) is dict:
            enum = property_schema.get("enum")
            if type(enum) is list:
                budget.consume_enum_members(len(enum))


def _consume_control_declaration_limits(
    document: Any, budget: _ScannerBudget
) -> None:
    """Bound declaration-driven report expansion before normalization/copying."""

    if type(document) is not dict:
        return
    raw_tools = document.get("tools")
    if type(raw_tools) is not dict:
        return
    for raw_tool in raw_tools.values():
        if type(raw_tool) is not dict:
            continue

        raw_unexposed = raw_tool.get("unexposed_arguments")
        if type(raw_unexposed) is dict:
            # Unexposed controls become argument rows in the report and must
            # share the same aggregate argument ceiling as schema arguments.
            budget.consume_arguments(len(raw_unexposed))

        raw_risk = raw_tool.get("risk")
        if type(raw_risk) is dict and type(raw_risk.get("effects")) is list:
            budget.consume_control_collection_members(len(raw_risk["effects"]))

        raw_branches = raw_tool.get("branches")
        if type(raw_branches) is dict and type(raw_branches.get("cases")) is list:
            raw_cases = raw_branches["cases"]
            budget.consume_control_collection_members(len(raw_cases))
            for raw_case in raw_cases:
                if type(raw_case) is not dict:
                    continue
                raw_case_risk = raw_case.get("risk")
                if (
                    type(raw_case_risk) is dict
                    and type(raw_case_risk.get("effects")) is list
                ):
                    budget.consume_control_collection_members(
                        len(raw_case_risk["effects"])
                    )
                if type(raw_case.get("arguments")) is list:
                    budget.consume_control_collection_members(
                        len(raw_case["arguments"])
                    )

        raw_arguments = raw_tool.get("arguments")
        if type(raw_arguments) is not dict:
            continue
        for raw_argument in raw_arguments.values():
            if type(raw_argument) is not dict:
                continue
            raw_bounds = raw_argument.get("bounds")
            if type(raw_bounds) is list:
                budget.consume_control_collection_members(len(raw_bounds))


def _optional_text(value: Any, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"control declaration field '{field}' must be non-empty text")
    return value.strip()


def _same_exact_scalar(left: Any, right: Any) -> bool:
    """Compare JSON scalars without Python's ``True == 1`` aliasing."""

    if type(left) is not type(right):
        return False
    if type(left) is float and left == 0.0 and right == 0.0:
        return math.copysign(1.0, left) == math.copysign(1.0, right)
    if type(left) is Decimal and left.is_zero() and right.is_zero():
        return left.is_signed() is right.is_signed()
    return left == right


def _require_exact_json_scalar(value: Any, *, field: str) -> Any:
    if value is None or type(value) in {str, bool, int, float, Decimal}:
        return value
    raise SchemaError(f"{field} must be an exact JSON scalar")


def _runtime_selector_scalar(value: Any, *, field: str) -> Any:
    """Normalize an exact parsed JSON scalar for the runtime selector API.

    The strict JSON loader retains non-integer numbers as ``Decimal`` so
    fingerprints never depend on accidental binary-float rounding. The
    runtime selector deliberately accepts only ordinary JSON scalar types,
    however, so a decimal selector is portable only when converting it to a
    float preserves its canonical JSON spelling exactly.
    """

    value = _require_exact_json_scalar(value, field=field)
    if type(value) is int and not (
        -_MAX_RUNTIME_SELECTOR_INTEGER_ABS
        < value
        < _MAX_RUNTIME_SELECTOR_INTEGER_ABS
    ):
        raise SchemaError(f"{field} exceeds the portable runtime integer limit")
    if type(value) is not Decimal:
        return value
    converted = float(value)
    if (
        not math.isfinite(converted)
        or canonical_decimal_text(converted) != canonical_decimal_text(value)
    ):
        raise SchemaError(
            f"{field} cannot be represented as an exact portable runtime "
            "selector value"
        )
    return converted


def _validated_risk_declaration(raw_risk: Any, *, field: str) -> dict[str, Any]:
    if not isinstance(raw_risk, dict):
        raise SchemaError(f"{field} must be an object")
    _reject_unknown_fields(
        raw_risk,
        allowed={"tier", "evidence", "effects", "note"},
        field=field,
    )
    tier = raw_risk.get("tier")
    evidence = raw_risk.get("evidence")
    if tier not in DECLARABLE_RISKS:
        raise SchemaError(
            f"risk tier in {field} must be one of: "
            + ", ".join(sorted(DECLARABLE_RISKS))
        )
    if evidence not in CONTROL_EVIDENCE:
        raise SchemaError(
            f"{field} evidence must be one of: "
            + ", ".join(sorted(CONTROL_EVIDENCE))
        )
    raw_effects = raw_risk.get("effects")
    if not isinstance(raw_effects, list) or not raw_effects:
        raise SchemaError(f"{field} effects must be a non-empty array")
    effects: list[str] = []
    for effect_index, raw_effect in enumerate(raw_effects, start=1):
        effect = _optional_text(
            raw_effect,
            field=f"{field}.effects[{effect_index}]",
        )
        if effect is None:
            raise SchemaError(
                f"{field} effect {effect_index} must be non-empty text"
            )
        if effect in effects:
            raise SchemaError(f"duplicate effect in {field}: {effect}")
        effects.append(effect)
    normalized = {"tier": tier, "evidence": evidence, "effects": effects}
    note = _optional_text(raw_risk.get("note"), field=f"{field}.note")
    if note is not None:
        normalized["note"] = note
    return normalized


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
            allowed={"risk", "branches", "arguments", "unexposed_arguments"},
            field=f"control declaration for '{tool_name}'",
        )

        raw_risk = raw_tool.get("risk")
        risk_declaration: dict[str, Any] | None = None
        if raw_risk is not None:
            risk_declaration = _validated_risk_declaration(
                raw_risk,
                field=f"risk declaration for '{tool_name}'",
            )

        properties, _ = _properties(definitions_by_name[tool_name])
        raw_branches = raw_tool.get("branches")
        branch_declaration: dict[str, Any] | None = None
        if raw_branches is not None:
            if risk_declaration is not None:
                raise SchemaError(
                    f"control declaration for '{tool_name}' cannot combine "
                    "tool risk with branch risk"
                )
            if not isinstance(raw_branches, dict):
                raise SchemaError(
                    f"branch declaration for '{tool_name}' must be an object"
                )
            _reject_unknown_fields(
                raw_branches,
                allowed={"selector", "cases"},
                field=f"branch declaration for '{tool_name}'",
            )
            selector = _optional_text(
                raw_branches.get("selector"),
                field=f"{tool_name}.branches.selector",
            )
            if selector is None or selector not in properties:
                raise SchemaError(
                    f"branch selector for '{tool_name}' must name an exposed "
                    "schema argument"
                )
            selector_schema = properties[selector]
            selector_enum = (
                selector_schema.get("enum")
                if type(selector_schema) is dict
                else None
            )
            if not isinstance(selector_enum, list) or not selector_enum:
                raise SchemaError(
                    f"branch selector '{tool_name}.{selector}' must have a "
                    "non-empty enum"
                )
            runtime_selector_enum = []
            for enum_index, enum_value in enumerate(selector_enum, start=1):
                runtime_selector_enum.append(
                    _runtime_selector_scalar(
                        enum_value,
                        field=(
                            f"branch selector '{tool_name}.{selector}' enum"
                            f"[{enum_index}]"
                        ),
                    )
                )

            raw_cases = raw_branches.get("cases")
            if not isinstance(raw_cases, list) or not raw_cases:
                raise SchemaError(
                    f"branch cases for '{tool_name}' must be a non-empty array"
                )
            normalized_by_enum_index: dict[int, dict[str, Any]] = {}
            for case_index, raw_case in enumerate(raw_cases, start=1):
                case_field = f"{tool_name}.branches.cases[{case_index}]"
                if not isinstance(raw_case, dict):
                    raise SchemaError(f"{case_field} must be an object")
                _reject_unknown_fields(
                    raw_case,
                    allowed={"value", "risk", "arguments"},
                    field=case_field,
                )
                if "value" not in raw_case:
                    raise SchemaError(f"{case_field} is missing value")
                value = _runtime_selector_scalar(
                    raw_case["value"], field=f"{case_field}.value"
                )
                matching_enum_indexes = [
                    enum_index
                    for enum_index, enum_value in enumerate(runtime_selector_enum)
                    if _same_exact_scalar(value, enum_value)
                ]
                if len(matching_enum_indexes) != 1:
                    raise SchemaError(
                        f"{case_field}.value must match exactly one selector "
                        "enum member"
                    )
                enum_index = matching_enum_indexes[0]
                if enum_index in normalized_by_enum_index:
                    raise SchemaError(
                        f"duplicate exact branch case for '{tool_name}.{selector}'"
                    )
                case_risk = _validated_risk_declaration(
                    raw_case.get("risk"), field=f"{case_field}.risk"
                )
                raw_active = raw_case.get("arguments")
                if not isinstance(raw_active, list) or not raw_active:
                    raise SchemaError(
                        f"{case_field}.arguments must be a non-empty array"
                    )
                active_seen: set[str] = set()
                for active_index, active_name in enumerate(raw_active, start=1):
                    if (
                        not isinstance(active_name, str)
                        or not active_name.strip()
                        or active_name not in properties
                    ):
                        raise SchemaError(
                            f"{case_field}.arguments[{active_index}] must name "
                            "an exposed schema argument"
                        )
                    if active_name in active_seen:
                        raise SchemaError(
                            f"duplicate active argument in {case_field}: "
                            f"{active_name}"
                        )
                    active_seen.add(active_name)
                if selector not in active_seen:
                    raise SchemaError(
                        f"{case_field}.arguments must include selector '{selector}'"
                    )
                normalized_by_enum_index[enum_index] = {
                    "value": value,
                    "risk": case_risk,
                    "arguments": [
                        argument_name
                        for argument_name in properties
                        if argument_name in active_seen
                    ],
                }
            if set(normalized_by_enum_index) != set(range(len(selector_enum))):
                raise SchemaError(
                    f"branch cases for '{tool_name}' must exhaust the selector enum"
                )
            branch_declaration = {
                "selector": selector,
                "cases": [
                    normalized_by_enum_index[index]
                    for index in range(len(selector_enum))
                ],
            }

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
            bound_keys: set[tuple[str, str, str, str | None]] = set()
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
                bound_key = (
                    source,
                    mutability,
                    bound["operational_status"],
                    enforcement,
                )
                if bound_key in bound_keys:
                    raise SchemaError(
                        f"duplicate bound for '{tool_name}.{argument_name}'"
                    )
                bound_keys.add(bound_key)
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
        if branch_declaration is not None:
            normalized_tool["branches"] = branch_declaration
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
    if (
        confidence is Confidence.UNCERTAIN
        and risk is Risk.READ_ONLY
        and policy is Policy.TYPED_BOUNDED
    ):
        return "ambiguous argument auto-relaxed for read-only tool"
    if (
        confidence is Confidence.UNCERTAIN
        and risk is Risk.READ_ONLY
        and policy is Policy.TRUSTED_FIXED
    ):
        return "identifier inference incomplete; kept locked for review"
    if confidence is Confidence.UNCERTAIN:
        return "ambiguous consequential argument; review required"
    if policy is Policy.TRUSTED_FIXED:
        return "authority-bearing name"
    if policy is Policy.OUTBOUND_PAYLOAD:
        return "outbound payload name or bounded free text"
    return "typed or bounded value"


def _annotation_assessment(
    annotation: str,
    value: bool,
    state: str,
    *,
    comparison_source: str,
    comparison_value: Any,
) -> dict[str, Any]:
    return {
        "annotation": annotation,
        "value": value,
        "state": state,
        "evidence_source": "mcp_tool_annotation",
        "trust": "unverified_hint",
        "comparison_source": comparison_source,
        "comparison_value": comparison_value,
    }


def _annotation_assessments(
    risk: Risk, annotations: dict[str, Any]
) -> list[dict[str, Any]]:
    """Keep MCP hints as evidence without turning uncertainty into conflict."""

    assessments: list[dict[str, Any]] = []
    read_only = annotations.get("readOnlyHint")

    if read_only is not None:
        if risk is Risk.UNKNOWN:
            state = "unresolved"
        else:
            expected_read_only = risk is Risk.READ_ONLY
            state = "consistent" if read_only is expected_read_only else "conflict"
        assessments.append(
            _annotation_assessment(
                "readOnlyHint",
                read_only,
                state,
                comparison_source="effective_risk",
                comparison_value=risk.value,
            )
        )

    if "destructiveHint" in annotations:
        destructive = annotations["destructiveHint"]
        if read_only is True:
            assessments.append(
                _annotation_assessment(
                    "destructiveHint",
                    destructive,
                    "inapplicable",
                    comparison_source="readOnlyHint",
                    comparison_value=True,
                )
            )
        else:
            if risk is Risk.UNKNOWN:
                state = "unresolved"
            else:
                expected_destructive = risk is Risk.DESTRUCTIVE
                state = (
                    "consistent"
                    if destructive is expected_destructive
                    else "conflict"
                )
            assessments.append(
                _annotation_assessment(
                    "destructiveHint",
                    destructive,
                    state,
                    comparison_source="effective_risk",
                    comparison_value=risk.value,
                )
            )

    if "idempotentHint" in annotations:
        idempotent = annotations["idempotentHint"]
        if read_only is True:
            state = "inapplicable"
            comparison_source = "readOnlyHint"
            comparison_value: Any = True
        else:
            state = "unresolved"
            comparison_source = "none"
            comparison_value = None
        assessments.append(
            _annotation_assessment(
                "idempotentHint",
                idempotent,
                state,
                comparison_source=comparison_source,
                comparison_value=comparison_value,
            )
        )

    if "openWorldHint" in annotations:
        assessments.append(
            _annotation_assessment(
                "openWorldHint",
                annotations["openWorldHint"],
                "unresolved",
                comparison_source="none",
                comparison_value=None,
            )
        )

    return assessments


def _annotation_conflicts(
    assessments: list[dict[str, Any]],
) -> list[str]:
    return [
        f"{assessment['annotation']}={str(assessment['value']).lower()} "
        "conflicts with effective risk"
        for assessment in assessments
        if assessment["state"] == "conflict"
    ]


def _tool_review_sources(
    *,
    arguments: list[dict[str, Any]],
    schema_review_required: bool,
    risk_review_required: bool,
    risk_conflict: bool,
    annotation_assessments: list[dict[str, Any]],
    branch_risk_review_required: bool,
) -> dict[str, Any]:
    """Index every existing static-review obligation for one tool.

    This is deliberately derived from evidence already present in the report.
    Runtime confirmation is a separate execution requirement and is not review
    debt merely because a well-classified consequential action needs approval.
    """

    return {
        "arguments": [
            argument["name"]
            for argument in arguments
            if argument["review_required"] is True
        ],
        "schema": schema_review_required,
        "risk": risk_review_required,
        "risk_conflict": risk_conflict,
        "annotation_conflicts": [
            assessment["annotation"]
            for assessment in annotation_assessments
            if assessment["state"] == "conflict"
        ],
        "branch_risk": branch_risk_review_required,
    }


def _tool_review_required(review_sources: dict[str, Any]) -> bool:
    return any(
        (
            review_sources["arguments"],
            review_sources["schema"],
            review_sources["risk"],
            review_sources["risk_conflict"],
            review_sources["annotation_conflicts"],
            review_sources["branch_risk"],
        )
    )


def _trusted_fixed_remediation(
    policy: Policy,
    *,
    review_required: bool,
    param: Param,
    inference_context: _PolicyInferenceContext,
) -> dict[str, Any]:
    """Return deterministic advisory remediation for a protected argument.

    A high-confidence ``trusted_fixed`` inference can explain the two standard
    integration paths.  An uncertain argument must be reviewed first: in
    particular, a selector the model legitimately needs to choose must not be
    projected away merely because the scanner kept it locked by default.
    """

    if policy is not Policy.TRUSTED_FIXED:
        return {}
    if review_required:
        review_reason = (
            REMEDIATION_REVIEW_REASON_SELECTOR
            if (
                param.type == "enum"
                and is_branch_selector_name(param.name, inference_context)
            )
            else REMEDIATION_REVIEW_REASON_AUTHORITY
        )
        return {
            "remediation_status": REMEDIATION_STATUS_REVIEW_REQUIRED,
            "preferred_remediation": None,
            "fallback_remediation": None,
            "remediation_review_reason": review_reason,
        }
    return {
        "remediation_status": REMEDIATION_STATUS_RECOMMENDED,
        "preferred_remediation": PREFERRED_TRUSTED_FIXED_REMEDIATION,
        "fallback_remediation": FALLBACK_TRUSTED_FIXED_REMEDIATION,
        "remediation_review_reason": None,
    }


def _worst_branch_risk(branches: dict[str, Any]) -> Risk:
    return max(
        (Risk(case["risk"]["tier"]) for case in branches["cases"]),
        key=lambda risk: _BRANCH_RISK_PRIORITY[risk],
    )


def _branch_selector_candidate(
    definition: ToolDefinition,
    params: list[Param],
    risk: Risk,
    inference_context: _PolicyInferenceContext,
) -> bool:
    """Flag unresolved enum selectors without inventing branch semantics.

    A raw schema can prove only membership in an enum, not what each member
    does.  Consequential or unresolved tools therefore keep any ambiguous enum
    argument locked and expose the missing branch declaration as review debt.
    """

    if risk is Risk.READ_ONLY:
        return False
    for param in params:
        if param.type != "enum":
            continue
        if not is_branch_selector_name(param.name, inference_context):
            continue
        policy, confidence = infer_policy(param, inference_context)
        if policy is Policy.TRUSTED_FIXED and confidence is Confidence.UNCERTAIN:
            return True
    return False


def is_branch_selector_name(
    name: str,
    inference_context: _PolicyInferenceContext | None = None,
) -> bool:
    """Recognize complete-token, camel-case, and flat selector suffixes."""

    semantic_tokens = tuple(
        token
        for token in _identifier_tokens(name, inference_context)
        if not token.isdigit()
    )
    compact_segments = _compact_identifier_segments(name, inference_context)
    return bool(_BRANCH_SELECTOR_TOKENS.intersection(semantic_tokens)) or any(
        token.endswith(suffix) and token != suffix
        for token in semantic_tokens
        for suffix in _BRANCH_SELECTOR_TOKENS
    ) or any(
        segment == suffix or segment.endswith(suffix)
        for segment in compact_segments
        for suffix in _BRANCH_SELECTOR_TOKENS
    )


def _branch_risk_report(
    branches: dict[str, Any],
    *,
    properties: dict[str, Any],
    redact_names: bool,
) -> dict[str, Any]:
    display_names = {
        name: f"param_{index:03d}" if redact_names else name
        for index, name in enumerate(properties, start=1)
    }
    cases = []
    for case in branches["cases"]:
        risk = case["risk"]
        item: dict[str, Any] = {
            "value_fingerprint_sha256": _enum_value_fingerprint(case["value"]),
            "risk": risk["tier"],
            "evidence": risk["evidence"],
            "effects": list(risk["effects"]),
            "active_arguments": [
                display_names[name] for name in case["arguments"]
            ],
            "needs_confirmation": Risk(risk["tier"]) in _CONFIRMATION_RISKS,
        }
        if "note" in risk:
            item["note"] = risk["note"]
        cases.append(item)
    cases.sort(key=lambda item: item["value_fingerprint_sha256"])
    return {
        "source": "control_declaration",
        "selector": display_names[branches["selector"]],
        "value_disclosure": "sha256_fingerprint_only",
        "cases": cases,
    }


def _fingerprint(
    definitions: Iterable[ToolDefinition], *, redact_names: bool = False
) -> str:
    if not redact_names:
        material = [
            {
                "name": definition.name,
                "input_schema": _definition_schema_material(definition),
            }
            for definition in definitions
        ]
        return _canonical_sha256(material)

    normalized = []
    for tool_index, definition in enumerate(definitions, start=1):
        properties, required = _properties(definition)
        normalized_properties = {}
        for param_index, (name, raw) in enumerate(sorted(properties.items()), start=1):
            display_name = f"param_{param_index:03d}" if redact_names else name
            normalized_property = {
                "type": _property_type(raw if isinstance(raw, dict) else {}),
                "required": name in required,
            }
            constraints = _normalized_constraints(raw, redact_values=redact_names)
            if constraints:
                normalized_property["constraints"] = constraints
            normalized_properties[display_name] = normalized_property
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
            "schema_closes_unknown_arguments": _schema_closes_unknown_arguments(
                definition
            ),
            "arguments": exposed_arguments,
            "unexposed_arguments": unexposed_arguments,
        }
        if "risk" in declared_tool:
            # The same declaration is also exposed on the inferred tool
            # report. Keep the public report an actual JSON tree rather than
            # sharing a compact Python object graph between those locations.
            tool_item["risk"] = copy.deepcopy(declared_tool["risk"])
        if "branches" in declared_tool:
            tool_item["branches"] = _branch_risk_report(
                declared_tool["branches"],
                properties=properties,
                redact_names=redact_names,
            )
        tools.append(tool_item)

    report = {
        "version": CONTROL_DECLARATION_VERSION,
        "verification_notice": CONTROL_VERIFICATION_NOTICE,
        "tools": tools,
    }
    if not redact_names and declarations.get("attribution"):
        report["attribution"] = declarations["attribution"]
    return report


def _scan_definitions_bounded(
    definitions: list[ToolDefinition],
    *,
    redact_names: bool = False,
    control_declarations: Any | None = None,
    budget: _ScannerBudget,
    definitions_validated: bool,
    controls_validated: bool,
    limits_counted: bool,
) -> dict[str, Any]:
    if not definitions:
        raise SchemaError("no tool definitions found")

    if not limits_counted:
        budget.consume_tools(len(definitions))
    for definition in definitions:
        if type(definition) is not ToolDefinition:
            raise SchemaError("tool definitions must use ToolDefinition values")
        if type(definition.name) is not str or not definition.name.strip():
            raise SchemaError("tool definition is missing a non-empty name")
        _validate_tool_annotations(definition.name, definition.annotations)
        for source_field, source_value in (
            ("source_id", definition.source_id),
            ("source_url", definition.source_url),
        ):
            if source_value is not None and type(source_value) is not str:
                raise SchemaError(
                    f"tool '{definition.name}' {source_field} must be text"
                )
        if not definitions_validated:
            _validate_plain_json(
                definition.name,
                field="tool definition name",
                budget=budget,
            )
            for source_field, source_value in (
                ("source_id", definition.source_id),
                ("source_url", definition.source_url),
            ):
                if source_value is not None:
                    _validate_plain_json(
                        source_value,
                        field=f"tool '{definition.name}' {source_field}",
                        budget=budget,
                    )
            _validate_plain_json(
                definition.input_schema,
                field=f"tool '{definition.name}' input schema",
                budget=budget,
            )
            _validate_plain_json(
                definition.annotations,
                field=f"tool '{definition.name}' annotations",
                budget=budget,
            )
        _properties(definition)
        if not limits_counted:
            _consume_definition_detail_limits(definition, budget)

    if control_declarations is not None and not controls_validated:
        _validate_plain_json(
            control_declarations,
            field="control declarations",
            budget=budget,
        )

    declarations = None
    if control_declarations is not None:
        _consume_control_declaration_limits(control_declarations, budget)
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
        declared_tool = (
            declarations["tools"].get(definition.name) if declarations else None
        )
        declared_risk = (
            Risk(declared_tool["risk"]["tier"])
            if declared_tool is not None and "risk" in declared_tool
            else None
        )
        declared_branches = (
            declared_tool.get("branches") if declared_tool is not None else None
        )
        params = []
        for name, raw in properties.items():
            if (
                declared_branches is not None
                and name == declared_branches["selector"]
            ):
                # Branch validation has already converted exact Decimal input
                # only when it has a lossless portable float representation.
                # Feed those same runtime scalars to Param so the enum and the
                # SelectorCase values cannot disagree after JSON loading.
                selector_schema = (
                    copy.deepcopy(raw) if isinstance(raw, dict) else {}
                )
                selector_schema["enum"] = [
                    case["value"] for case in declared_branches["cases"]
                ]
                params.append(_param(name, selector_schema))
            else:
                params.append(_param(name, raw))
        selector_cases = (
            [
                SelectorCase(
                    value=case["value"],
                    risk=case["risk"]["tier"],
                    active_args=list(case["arguments"]),
                )
                for case in declared_branches["cases"]
            ]
            if declared_branches is not None
            else None
        )
        registry.add(
            Tool(
                definition.name,
                params,
                # Branch evidence says what each operation does; it says
                # nothing about who may author an argument. Keep the coarse
                # risk input identical to a scan without branch declarations
                # so branch metadata can never relax provenance inference.
                risk=declared_risk,
                selector=(
                    declared_branches["selector"]
                    if declared_branches is not None
                    else None
                ),
                selector_cases=selector_cases,
            )
        )
        params_by_tool[definition.name] = params
        required_by_tool[definition.name] = required

    inference_context = _PolicyInferenceContext()
    policy_set = build_policy(
        registry,
        _inference_context=inference_context,
    )
    review_pairs = set(policy_set.review)
    report_tools = []
    counts = {
        "tools": len(definitions),
        "parameters": 0,
        "protected_parameters": 0,
        "data_fillable_parameters": 0,
        "review_required": 0,
        "review_required_tools": 0,
        "schema_review_required_tools": 0,
        "confirmation_required_tools": 0,
        "risk_review_required_tools": 0,
        "risk_conflicts": 0,
        "annotation_conflicts": 0,
        "branch_risk_review_required_tools": 0,
    }

    for tool_index, definition in enumerate(definitions, start=1):
        tool_name = definition.name
        display_tool = f"tool_{tool_index:03d}" if redact_names else tool_name
        properties, _ = _properties(definition)
        inference_risk = policy_set.risk[tool_name]
        risk = inference_risk
        inferred_risk = policy_set.risk_inference[tool_name]
        declared_tool = (
            declarations["tools"].get(tool_name) if declarations else None
        )
        declared_risk = (
            declared_tool.get("risk") if declared_tool is not None else None
        )
        declared_branches = (
            declared_tool.get("branches") if declared_tool is not None else None
        )
        branch_report = (
            _branch_risk_report(
                declared_branches,
                properties=properties,
                redact_names=redact_names,
            )
            if declared_branches is not None
            else None
        )
        if declared_branches is not None:
            risk = _worst_branch_risk(declared_branches)
        branch_review_required = (
            declared_branches is None
            and _branch_selector_candidate(
                definition,
                params_by_tool[tool_name],
                risk,
                inference_context,
            )
        )
        if branch_review_required:
            counts["branch_risk_review_required_tools"] += 1
        annotation_assessments = _annotation_assessments(
            risk, definition.annotations
        )
        conflicts = _annotation_conflicts(annotation_assessments)
        counts["annotation_conflicts"] += len(conflicts)
        schema_closes_unknown_arguments = _schema_closes_unknown_arguments(
            definition
        )
        unexposed_without_schema_closure = bool(
            declared_tool is not None
            and declared_tool["unexposed_arguments"]
            and not schema_closes_unknown_arguments
        )
        schema_review_required = (
            _schema_requires_authority_review(definition.input_schema)
            or unexposed_without_schema_closure
        )
        if schema_review_required:
            counts["schema_review_required_tools"] += 1
        arguments = []
        for param_index, param in enumerate(params_by_tool[tool_name], start=1):
            initial_policy, confidence = infer_policy(
                param,
                inference_context,
            )
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
            argument = {
                "name": display_param,
                "type": param.type,
                "required": param.name in required_by_tool[tool_name],
                "policy": final_policy.value,
                "confidence": confidence.value,
                "review_required": needs_review,
                "reason": _reason(
                    param, final_policy, confidence, inference_risk
                ),
            }
            argument.update(
                _trusted_fixed_remediation(
                    final_policy,
                    review_required=needs_review,
                    param=param,
                    inference_context=inference_context,
                )
            )
            constraints = _normalized_constraints(
                properties.get(param.name), redact_values=redact_names
            )
            if constraints:
                argument["constraints"] = constraints
            if not redact_names:
                (
                    argument["schema_material_fingerprint_sha256"],
                    argument["unmodeled_schema_fingerprint_sha256"],
                ) = _argument_schema_material(properties.get(param.name))
            arguments.append(argument)
        risk_inference: dict[str, Any] = {
            "source": inferred_risk.source,
            "confidence": inferred_risk.confidence.value,
            "mutability": inferred_risk.mutability,
        }
        if redact_names:
            risk_inference["signal_redacted"] = True
        else:
            risk_inference["matched_tokens"] = list(inferred_risk.matched_tokens)

        risk_conflict = (
            False
            if declared_branches is not None
            else tool_name in policy_set.risk_conflicts
        )
        inference_incomplete = inferred_risk.source == "inference_limit"
        if declared_branches is not None:
            risk_source = "branch_control_declaration"
        elif risk_conflict:
            risk_source = "conflict_safe_default"
        elif declared_risk is not None and not inference_incomplete:
            risk_source = "control_declaration"
        else:
            risk_source = "safe_default"

        risk_review_required = (
            False
            if declared_branches is not None
            else tool_name in policy_set.risk_review
        )
        needs_confirmation = (
            any(
                Risk(case["risk"]["tier"]) in _CONFIRMATION_RISKS
                for case in declared_branches["cases"]
            )
            if declared_branches is not None
            else tool_name in policy_set.confirm
        )
        counts["risk_conflicts"] += int(risk_conflict)
        counts["risk_review_required_tools"] += int(risk_review_required)
        counts["confirmation_required_tools"] += int(needs_confirmation)

        review_sources = _tool_review_sources(
            arguments=arguments,
            schema_review_required=schema_review_required,
            risk_review_required=risk_review_required,
            risk_conflict=risk_conflict,
            annotation_assessments=annotation_assessments,
            branch_risk_review_required=branch_review_required,
        )
        tool_review_required = _tool_review_required(review_sources)
        counts["review_required_tools"] += int(tool_review_required)

        tool_report: dict[str, Any] = {
            "name": display_tool,
            "risk": risk.value,
            "risk_source": risk_source,
            "risk_evidence": (
                declared_risk["evidence"]
                if (
                    declared_risk is not None
                    and not risk_conflict
                    and not inference_incomplete
                )
                else None
            ),
            "inferred_risk": inferred_risk.risk.value,
            "risk_inference": risk_inference,
            "declared_risk": declared_risk,
            "risk_conflict": risk_conflict,
            "risk_review_required": risk_review_required,
            "review_required": tool_review_required,
            "review_sources": review_sources,
            "needs_confirmation": needs_confirmation,
            "branch_risk": branch_report,
            "branch_risk_review_required": branch_review_required,
            "schema_closes_unknown_arguments": schema_closes_unknown_arguments,
            "schema_review_required": schema_review_required,
            "annotation_assessments": annotation_assessments,
            "annotation_conflicts": conflicts,
            "arguments": arguments,
        }
        if not redact_names:
            (
                tool_report["schema_material_fingerprint_sha256"],
                tool_report["unmodeled_schema_fingerprint_sha256"],
            ) = _tool_schema_material(definition)
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
            "examples_included": False,
            "defaults_included": False,
            "runtime_values_included": False,
            "schema_constraint_values_included": not redact_names,
            "enum_values_included": False,
            "enum_value_fingerprints_included": not redact_names,
            "enum_value_fingerprints_dictionary_guessable": not redact_names,
            "branch_value_fingerprints_included": True,
            "branch_value_fingerprints_dictionary_guessable": True,
            "schema_material_fingerprints_included": not redact_names,
            "schema_material_fingerprints_dictionary_guessable": not redact_names,
            "unmodeled_schema_fingerprints_included": not redact_names,
            "schema_fingerprint_material_scope": (
                "modeled_presence_and_enum_count_only"
                if redact_names
                else "full_validation_material_excluding_annotations"
            ),
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
    validate_plain_json(report, field="generated scanner report")
    return report


def scan_definitions(
    definitions: list[ToolDefinition],
    *,
    redact_names: bool = False,
    control_declarations: Any | None = None,
) -> dict[str, Any]:
    """Scan normalized definitions under one aggregate resource budget."""

    try:
        return _scan_definitions_bounded(
            definitions,
            redact_names=redact_names,
            control_declarations=control_declarations,
            budget=_ScannerBudget(),
            definitions_validated=False,
            controls_validated=False,
            limits_counted=False,
        )
    except MemoryError as exc:
        raise SchemaError("tool definitions exceed available scanner resources") from exc


def scan_documents(
    documents: Iterable[Any],
    *,
    redact_names: bool = False,
    control_declarations: Any | None = None,
) -> dict[str, Any]:
    try:
        budget = _ScannerBudget()
        definitions: list[ToolDefinition] = []
        for document in documents:
            _validate_plain_json(
                document,
                field="schema document",
                budget=budget,
            )
            parsed = _parse_tool_definitions_unchecked(document)
            _consume_definition_limits(parsed, budget)
            definitions.extend(parsed)
        controls_validated = control_declarations is not None
        if controls_validated:
            _validate_plain_json(
                control_declarations,
                field="control declarations",
                budget=budget,
            )
        return _scan_definitions_bounded(
            definitions,
            redact_names=redact_names,
            control_declarations=control_declarations,
            budget=budget,
            definitions_validated=True,
            controls_validated=controls_validated,
            limits_counted=True,
        )
    except MemoryError as exc:
        raise SchemaError("schema documents exceed available scanner resources") from exc


def _markdown_cell(value: Any) -> str:
    safe: list[str] = []
    for character in str(value):
        codepoint = ord(character)
        category = unicodedata.category(character)
        if character == "\n":
            safe.append(" ")
        elif character == "\r":
            safe.append("\\r")
        elif character == "\t":
            safe.append("\\t")
        elif category.startswith("C") or category in {"Zl", "Zp"}:
            escape = "\\u" if codepoint <= 0xFFFF else "\\U"
            width = 4 if codepoint <= 0xFFFF else 8
            safe.append(f"{escape}{codepoint:0{width}x}")
        else:
            safe.append(character)
    escaped = html.escape("".join(safe), quote=False)
    zwnj_insertions: set[int] = set()
    for match in re.finditer(r"(?<![A-Za-z0-9_])(?i:gh)-(?:[0-9]+)\b", escaped):
        hyphen_index = escaped.find("-", match.start(), match.end())
        zwnj_insertions.add(hyphen_index)
    for match in re.finditer(
        r"(?<![A-Za-z0-9_])[0-9A-Fa-f]{7,40}(?![A-Za-z0-9_])", escaped
    ):
        zwnj_insertions.add(match.start() + (match.end() - match.start()) // 2)
    markdown_safe: list[str] = []
    for index, character in enumerate(escaped):
        # Link syntax is escaped below. Neutralize the remaining bare-autolink
        # signals while preserving how cells render: scheme separators, email
        # or mention markers, issue-reference markers, and a leading www-dot.
        if index in zwnj_insertions:
            markdown_safe.append("&#8204;")
        if character == ":" and escaped[index + 1 : index + 3] == "//":
            markdown_safe.append("&#58;")
            continue
        if character == "@":
            markdown_safe.append("@&#8204;")
            continue
        if character == "#":
            markdown_safe.append("#&#8204;")
            continue
        if (
            character == "."
            and escaped[max(0, index - 3) : index].casefold() == "www"
        ):
            markdown_safe.append("&#46;")
            continue
        if character in {"\\", "`", "!", "[", "]", "|"}:
            markdown_safe.append("\\")
        markdown_safe.append(character)
    return "".join(markdown_safe)


def _constraint_details(argument: dict[str, Any]) -> str:
    constraints = argument.get("constraints", {})
    details = []
    if "maximum" in constraints:
        details.append(f"maximum: {constraints['maximum']}")
    elif constraints.get("maximum_present") is True:
        details.append("maximum: redacted")
    if "max_length" in constraints:
        details.append(f"max length: {constraints['max_length']}")
    elif constraints.get("max_length_present") is True:
        details.append("max length: redacted")
    enum = constraints.get("enum")
    if isinstance(enum, dict):
        representation = (
            "redacted" if enum.get("values_redacted") is True else "fingerprinted"
        )
        details.append(f"enum: {enum['count']} {representation} member(s)")
    return "; ".join(details) if details else "—"


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
        "> Enum members are always omitted. Non-redacted reports use stable SHA-256",
        "> fingerprints for comparison; these are guessable for low-entropy values.",
        "> Non-redacted reports also fingerprint full schema validation material,",
        "> excluding annotations; those hashes are correlatable and may be guessable.",
        "> Redacted reports omit exact constraint values and all exact schema hashes.",
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
        f"| Tools requiring review | {summary['review_required_tools']} |",
        f"| Schemas requiring review | {summary.get('schema_review_required_tools', 0)} |",
        f"| Tools requiring confirmation | {summary['confirmation_required_tools']} |",
        f"| Tool risks requiring review | {summary['risk_review_required_tools']} |",
        f"| Branch risks requiring review | {summary['branch_risk_review_required_tools']} |",
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
            "## Tool review summary",
            "",
            "> Static review debt is separate from runtime confirmation.",
            "",
            "| Tool | Review required | Arguments | Schema | Risk | Risk conflict | "
            "Annotation conflicts | Branch risk |",
            "|---|---|---|---|---|---|---|---|",
        ]
    )
    for tool in report["tools"]:
        review_sources = tool["review_sources"]
        lines.append(
            "| {tool} | {required} | {arguments} | {schema} | {risk} | "
            "{risk_conflict} | {annotations} | {branch_risk} |".format(
                tool=_markdown_cell(tool["name"]),
                required="yes" if tool["review_required"] else "no",
                arguments=_markdown_cell(
                    ", ".join(review_sources["arguments"]) or "—"
                ),
                schema="yes" if review_sources["schema"] else "no",
                risk="yes" if review_sources["risk"] else "no",
                risk_conflict=(
                    "yes" if review_sources["risk_conflict"] else "no"
                ),
                annotations=_markdown_cell(
                    ", ".join(review_sources["annotation_conflicts"]) or "—"
                ),
                branch_risk="yes" if review_sources["branch_risk"] else "no",
            )
        )
    lines.extend(
        [
            "",
            "## Tool risk evidence",
            "",
            "| Tool | Effective risk | Source | Name heuristic | Mutability | "
            "Declared effects | Conflict | Risk review | Schema review | Confirmation |",
            "|---|---|---|---|---|---|---|---|---|---|",
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
            "{mutability} | {effects} | {conflict} | {review} | {schema_review} | "
            "{confirmation} |".format(
                tool=_markdown_cell(tool["name"]),
                risk=_markdown_cell(tool["risk"]),
                source=_markdown_cell(tool["risk_source"]),
                signal=_markdown_cell(name_signal),
                confidence=_markdown_cell(risk_inference["confidence"]),
                mutability=_markdown_cell(risk_inference["mutability"]),
                effects=_markdown_cell(declared_effects),
                conflict="yes" if tool["risk_conflict"] else "no",
                review="yes" if tool["risk_review_required"] else "no",
                schema_review=(
                    "yes" if tool.get("schema_review_required") is True else "no"
                ),
                confirmation="yes" if tool["needs_confirmation"] else "no",
            )
        )
    branch_rows = [
        (tool, case)
        for tool in report["tools"]
        if tool["branch_risk"] is not None
        for case in tool["branch_risk"]["cases"]
    ]
    if branch_rows:
        lines.extend(
            [
                "",
                "## Declared branch risk",
                "",
                "> Selector values are omitted; stable SHA-256 fingerprints are "
                "shown instead.",
                "",
                "| Tool | Selector | Value fingerprint | Risk | Evidence | "
                "Active arguments | Confirmation | Effects |",
                "|---|---|---|---|---|---|---|---|",
            ]
        )
        for tool, case in branch_rows:
            branch = tool["branch_risk"]
            lines.append(
                "| {tool} | {selector} | `{fingerprint}` | {risk} | "
                "{evidence} | {arguments} | {confirmation} | {effects} |".format(
                    tool=_markdown_cell(tool["name"]),
                    selector=_markdown_cell(branch["selector"]),
                    fingerprint=case["value_fingerprint_sha256"],
                    risk=_markdown_cell(case["risk"]),
                    evidence=_markdown_cell(case["evidence"]),
                    arguments=_markdown_cell(", ".join(case["active_arguments"])),
                    confirmation="yes" if case["needs_confirmation"] else "no",
                    effects=_markdown_cell(", ".join(case["effects"])),
                )
            )
    annotation_rows = [
        (tool, assessment)
        for tool in report["tools"]
        for assessment in tool["annotation_assessments"]
    ]
    if annotation_rows:
        lines.extend(
            [
                "",
                "## MCP annotation evidence",
                "",
                "> Tool annotations are unverified server hints, not enforcement "
                "evidence.",
                "",
                "| Tool | Annotation | Value | State | Comparison source | "
                "Comparison value |",
                "|---|---|---|---|---|---|",
            ]
        )
        for tool, assessment in annotation_rows:
            comparison_value = assessment["comparison_value"]
            if comparison_value is None:
                comparison_display = "—"
            elif type(comparison_value) is bool:
                comparison_display = str(comparison_value).lower()
            else:
                comparison_display = str(comparison_value)
            lines.append(
                "| {tool} | {annotation} | {value} | {state} | {source} | "
                "{comparison} |".format(
                    tool=_markdown_cell(tool["name"]),
                    annotation=_markdown_cell(assessment["annotation"]),
                    value="true" if assessment["value"] else "false",
                    state=_markdown_cell(assessment["state"]),
                    source=_markdown_cell(assessment["comparison_source"]),
                    comparison=_markdown_cell(comparison_display),
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
    protected_arguments = [
        (tool, argument)
        for tool in report["tools"]
        for argument in tool["arguments"]
        if argument["policy"] == "trusted_fixed"
    ]
    if protected_arguments:
        lines.extend(
            [
                "",
                "## Remediation guidance",
                "",
                "> Advisory only: the report does not change a model schema, prove that",
                "> trusted application state exists, or deploy a runtime integration.",
                "",
                "| Tool | Argument | Status | Preferred remediation | Fallback remediation | Review reason |",
                "|---|---|---|---|---|---|",
            ]
        )
        for tool, argument in protected_arguments:
            preferred = argument["preferred_remediation"] or "—"
            fallback = argument["fallback_remediation"] or "—"
            review_reason = argument["remediation_review_reason"] or "—"
            lines.append(
                "| {tool} | {argument} | {status} | {preferred} | {fallback} | {review_reason} |".format(
                    tool=_markdown_cell(tool["name"]),
                    argument=_markdown_cell(argument["name"]),
                    status=_markdown_cell(argument["remediation_status"]),
                    preferred=_markdown_cell(preferred),
                    fallback=_markdown_cell(fallback),
                    review_reason=_markdown_cell(review_reason),
                )
            )
    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| Tool | Risk | Argument | Type | Required | Constraints | Policy | Review | Reason |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for tool in report["tools"]:
        for argument in tool["arguments"]:
            lines.append(
                "| {tool} | {risk} | {argument} | {type} | {required} | "
                "{constraints} | {policy} | {review} | {reason} |".format(
                    tool=_markdown_cell(tool["name"]),
                    risk=_markdown_cell(tool["risk"]),
                    argument=_markdown_cell(argument["name"]),
                    type=_markdown_cell(argument["type"]),
                    required="yes" if argument["required"] else "no",
                    constraints=_markdown_cell(_constraint_details(argument)),
                    policy=_markdown_cell(argument["policy"]),
                    review="yes" if argument["review_required"] else "no",
                    reason=_markdown_cell(argument["reason"]),
                )
            )
        if not tool["arguments"]:
            lines.append(
                f"| {_markdown_cell(tool['name'])} | {_markdown_cell(tool['risk'])} | "
                "— | — | — | — | — | — | no arguments |"
            )
        for conflict in tool["annotation_conflicts"]:
            lines.append(
                f"| {_markdown_cell(tool['name'])} | {_markdown_cell(tool['risk'])} | "
                f"— | — | — | — | — | — | yes | {_markdown_cell(conflict)} |"
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
            "Remediation guidance is advisory and never rewrites a model-visible schema,",
            "discovers a trusted value source, or changes runtime registration. A protected",
            "argument whose authority is uncertain must be reviewed before choosing a fix.",
            "References and composed/conditional schemas are not resolved; when present,",
            "the report marks the tool for schema review instead of claiming complete coverage.",
            "Review every flagged argument against the real tool semantics before deployment.",
            "",
        ]
    )
    return "\n".join(lines)


def _summary_requires_review(summary: dict[str, Any]) -> bool:
    """Return whether a scanner summary carries any advertised review debt."""

    return any(
        summary.get(field, 0)
        for field in (
            "review_required",
            "review_required_tools",
            "schema_review_required_tools",
            "risk_review_required_tools",
            "risk_conflicts",
            "annotation_conflicts",
            "branch_risk_review_required_tools",
        )
    )


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
        input_budget = _CLIInputBudget()
        if args.controls == "-" and "-" in args.schemas:
            raise SchemaError("schemas and control declarations cannot both use stdin")
        controls = (
            load_json_path(
                args.controls,
                allow_stdin=True,
                _input_budget=input_budget,
            )
            if args.controls
            else None
        )
        report = scan_documents(
            (
                load_json_path(
                    path,
                    allow_stdin=True,
                    _input_budget=input_budget,
                )
                for path in args.schemas
            ),
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

    if args.fail_on_review and _summary_requires_review(report["summary"]):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
