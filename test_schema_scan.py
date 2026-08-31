import copy
import hashlib
import io
import json
import os
from decimal import Decimal
from pathlib import Path, PurePosixPath

import pytest

import verb_authority
import verb_authority_scan as scanner
from verb_authority_scan import (
    REPORT_VERSION,
    SchemaError,
    ToolDefinition,
    load_json_path,
    main,
    parse_tool_definitions,
    render_markdown,
    scan_definitions,
    scan_documents,
    validate_plain_json,
)


def _constraint_schema(maximum, max_length, enum):
    return {
        "tools": [
            {
                "name": "set_policy",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "amount": {"type": "number", "maximum": maximum},
                        "message": {
                            "type": "string",
                            "maxLength": max_length,
                        },
                        "mode": {"type": "string", "enum": enum},
                    },
                },
            }
        ]
    }


def test_report_v5_preserves_constraints_without_disclosing_enum_members():
    document = _constraint_schema(100, 40, ["safe", "reviewed"])

    report = scan_documents([document])
    arguments = {
        argument["name"]: argument for argument in report["tools"][0]["arguments"]
    }

    assert REPORT_VERSION == 5
    assert report["report_version"] == 5
    assert arguments["amount"]["constraints"] == {"maximum": 100}
    assert arguments["message"]["constraints"] == {"max_length": 40}
    enum = arguments["mode"]["constraints"]["enum"]
    assert enum["count"] == 2
    assert len(enum["value_fingerprints_sha256"]) == 2
    assert all(len(value) == 64 for value in enum["value_fingerprints_sha256"])
    assert report["privacy"]["schema_constraint_values_included"] is True
    assert report["privacy"]["enum_values_included"] is False
    assert report["privacy"]["enum_value_fingerprints_dictionary_guessable"] is True
    assert report["privacy"]["schema_material_fingerprints_included"] is True
    assert "examples_or_values_included" not in report["privacy"]
    assert report["privacy"]["examples_included"] is False
    assert report["privacy"]["defaults_included"] is False
    assert report["privacy"]["runtime_values_included"] is False
    assert report["privacy"]["schema_fingerprint_material_scope"] == (
        "full_validation_material_excluding_annotations"
    )
    assert len(report["tools"][0]["schema_material_fingerprint_sha256"]) == 64
    assert len(report["tools"][0]["unmodeled_schema_fingerprint_sha256"]) == 64
    assert all(
        len(argument["schema_material_fingerprint_sha256"]) == 64
        and len(argument["unmodeled_schema_fingerprint_sha256"]) == 64
        for argument in arguments.values()
    )
    assert '"safe"' not in json.dumps(report, sort_keys=True)

    markdown = render_markdown(report)
    assert "maximum: 100" in markdown
    assert "max length: 40" in markdown
    assert "enum: 2 fingerprinted member(s)" in markdown


def test_direct_float_and_equivalent_json_decimal_share_fingerprints(tmp_path):
    direct = _constraint_schema(1.5, 40, [1.5])
    schema_path = tmp_path / "decimal.json"
    schema_path.write_text(
        '{"tools":[{"name":"set_policy","inputSchema":{"type":"object",'
        '"properties":{"amount":{"type":"number","maximum":1.5},'
        '"message":{"type":"string","maxLength":40},'
        '"mode":{"type":"string","enum":[1.5]}}}}]}',
        encoding="utf-8",
    )

    direct_report = scan_documents([direct])
    loaded_report = scan_documents([load_json_path(str(schema_path))])

    assert direct_report == loaded_report


def test_redacted_constraint_report_uses_only_presence_and_count_sentinels():
    before = _constraint_schema(100, 40, ["safe", "reviewed"])
    changed_values = _constraint_schema(10**12, 10**9, ["open", "unrestricted"])

    before_report = scan_documents([before], redact_names=True)
    changed_report = scan_documents([changed_values], redact_names=True)
    arguments = before_report["tools"][0]["arguments"]

    assert arguments[0]["constraints"] == {"maximum_present": True}
    assert arguments[1]["constraints"] == {"max_length_present": True}
    assert arguments[2]["constraints"] == {
        "enum": {"count": 2, "values_redacted": True}
    }
    assert before_report["privacy"]["schema_constraint_values_included"] is False
    assert before_report["privacy"]["enum_value_fingerprints_included"] is False
    assert (
        before_report["privacy"]["enum_value_fingerprints_dictionary_guessable"]
        is False
    )
    assert before_report["privacy"]["schema_material_fingerprints_included"] is False
    assert before_report["privacy"]["unmodeled_schema_fingerprints_included"] is False
    assert before_report["privacy"]["schema_fingerprint_material_scope"] == (
        "modeled_presence_and_enum_count_only"
    )
    assert "schema_material_fingerprint_sha256" not in before_report["tools"][0]
    assert "unmodeled_schema_fingerprint_sha256" not in before_report["tools"][0]
    assert all(
        "schema_material_fingerprint_sha256" not in argument
        and "unmodeled_schema_fingerprint_sha256" not in argument
        for argument in arguments
    )
    assert before_report["schema_fingerprint_sha256"] == changed_report[
        "schema_fingerprint_sha256"
    ]
    assert scan_documents([before])["schema_fingerprint_sha256"] != scan_documents(
        [changed_values]
    )["schema_fingerprint_sha256"]

    markdown = render_markdown(before_report)
    assert "maximum: redacted" in markdown
    assert "max length: redacted" in markdown
    assert "enum: 2 redacted member(s)" in markdown
    assert "Redacted reports omit exact constraint values" in markdown
    assert "all exact schema hashes" in markdown


@pytest.mark.parametrize(
    "property_schema, message",
    [
        ({"type": "number", "maximum": float("inf")}, "finite number"),
        ({"type": "string", "maxLength": -1}, "non-negative integer"),
        ({"type": "string", "enum": "safe"}, "enum must be an array"),
        ({"type": "string", "enum": ["safe", "safe"]}, "must be unique"),
    ],
)
def test_invalid_modeled_constraints_are_rejected(property_schema, message):
    document = {
        "tools": [
            {
                "name": "set_value",
                "inputSchema": {"properties": {"value": property_schema}},
            }
        ]
    }

    with pytest.raises(SchemaError, match=message):
        scan_documents([document])


@pytest.mark.parametrize(
    "document",
    [
        {"tools": ["not-an-object"]},
        {
            "tools": [
                {
                    "name": "set_value",
                    "inputSchema": {"properties": {"value": ("tuple",)}},
                }
            ]
        },
        {
            "tools": [
                {
                    "name": "set_value",
                    "inputSchema": {
                        "type": "object",
                        "properties": None,
                        "additionalProperties": False,
                    },
                }
            ]
        },
        {"tools": [], "non_finite": float("nan")},
    ],
)
def test_scanner_rejects_non_plain_or_malformed_json_shapes(document):
    with pytest.raises(SchemaError):
        scan_documents([document])


def _collision_mcp_tool(name="send_message"):
    return {
        "name": name,
        "inputSchema": {
            "type": "object",
            "properties": {"recipient": {"type": "string"}},
        },
    }


def _collision_openai_function(name="send_message"):
    return {
        "name": name,
        "parameters": {
            "type": "object",
            "properties": {"recipient": {"type": "string"}},
        },
    }


def _collision_envelope(name):
    if name == "sources":
        return [{"id": "source", "tools": [_collision_mcp_tool()]}]
    if name == "result":
        return {"tools": [_collision_mcp_tool()]}
    if name == "tools":
        return [_collision_mcp_tool()]
    if name == "functions":
        return [_collision_openai_function()]
    raise AssertionError(f"unknown test envelope: {name}")


@pytest.mark.parametrize(
    ("first", "second"),
    (
        ("sources", "tools"),
        ("tools", "sources"),
        ("result", "tools"),
        ("tools", "result"),
        ("tools", "functions"),
        ("functions", "tools"),
    ),
)
def test_competing_schema_envelopes_are_rejected_in_both_key_orders(
    first, second
):
    document = {
        first: _collision_envelope(first),
        second: _collision_envelope(second),
    }

    with pytest.raises(SchemaError, match="competing tool-definition envelopes"):
        parse_tool_definitions(document)
    with pytest.raises(SchemaError, match="competing tool-definition envelopes"):
        scan_documents([document])


@pytest.mark.parametrize("reverse", (False, True), ids=("direct-first", "nested-first"))
def test_direct_and_nested_tool_dialects_are_rejected_in_both_key_orders(reverse):
    direct = [("name", "direct"), ("inputSchema", {"type": "object"})]
    nested = [
        ("type", "function"),
        ("function", _collision_openai_function("nested")),
    ]
    raw = dict((nested + direct) if reverse else (direct + nested))

    with pytest.raises(SchemaError, match="direct and nested OpenAI/MCP dialects"):
        parse_tool_definitions({"tools": [raw]})


@pytest.mark.parametrize(
    ("first", "second"),
    tuple(
        direction
        for pair in (
            ("inputSchema", "input_schema"),
            ("inputSchema", "parameters"),
            ("input_schema", "parameters"),
        )
        for direction in (pair, pair[::-1])
    ),
)
def test_competing_schema_aliases_are_rejected_in_both_key_orders(first, second):
    raw = dict(
        [
            ("name", "send_message"),
            (first, {"type": "object"}),
            (second, {"type": "object"}),
        ]
    )

    with pytest.raises(SchemaError, match="competing input schema aliases"):
        parse_tool_definitions({"tools": [raw]})


def test_tool_definition_requires_one_explicit_schema_alias():
    with pytest.raises(SchemaError, match="exactly one input schema alias"):
        parse_tool_definitions({"tools": [{"name": "schema_less"}]})


@pytest.mark.parametrize(
    "document",
    (
        {
            "tools": [
                {
                    "type": "function",
                    "name": "responses_ping",
                }
            ]
        },
        {
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "chat_ping"},
                }
            ]
        },
        {"functions": [{"name": "legacy_chat_ping"}]},
    ),
    ids=("responses-direct", "chat-wrapper", "functions-envelope"),
)
def test_unambiguous_openai_zero_argument_functions_allow_missing_parameters(
    document,
):
    definitions = parse_tool_definitions(document)

    assert len(definitions) == 1
    assert definitions[0].input_schema == {}


def test_openai_responses_direct_function_uses_parameters_schema():
    definitions = parse_tool_definitions(
        {
            "tools": [
                {
                    "type": "function",
                    "name": "send_message",
                    "parameters": {
                        "type": "object",
                        "properties": {"recipient": {"type": "string"}},
                    },
                }
            ]
        }
    )

    assert definitions[0].name == "send_message"
    assert definitions[0].input_schema["properties"] == {
        "recipient": {"type": "string"}
    }


def test_type_less_legacy_direct_function_with_parameters_remains_valid():
    definitions = parse_tool_definitions(
        {
            "name": "legacy_send_message",
            "parameters": {
                "type": "object",
                "properties": {"recipient": {"type": "string"}},
            },
        }
    )

    assert definitions[0].name == "legacy_send_message"
    assert definitions[0].input_schema["properties"] == {
        "recipient": {"type": "string"}
    }


@pytest.mark.parametrize(
    "invalid_type",
    ("functoin", 7),
    ids=("misspelled-string", "non-string"),
)
def test_openai_responses_direct_parameters_reject_explicit_non_function_type(
    invalid_type,
):
    document = {
        "tools": [
            {
                "type": invalid_type,
                "name": "send_message",
                "parameters": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}},
                },
            }
        ]
    }

    with pytest.raises(SchemaError, match="must use type 'function'"):
        parse_tool_definitions(document)


def test_top_level_name_metadata_does_not_compete_with_tools_envelope():
    definitions = parse_tool_definitions(
        {
            "name": "example MCP server",
            "tools": [_collision_mcp_tool("read_status")],
        }
    )

    assert [definition.name for definition in definitions] == ["read_status"]


def test_complete_direct_tool_still_competes_with_tools_envelope():
    document = {
        "name": "direct_tool",
        "inputSchema": {"type": "object", "properties": {}},
        "tools": [_collision_mcp_tool("enveloped_tool")],
    }

    with pytest.raises(SchemaError, match="competing tool-definition envelopes"):
        parse_tool_definitions(document)


@pytest.mark.parametrize(
    "raw",
    (
        {
            "type": "function",
            "name": "responses_direct",
            "inputSchema": {"type": "object"},
        },
        {
            "type": "function",
            "name": "responses_direct",
            "parameters": {"type": "object"},
            "function": {
                "name": "chat_nested",
                "parameters": {"type": "object"},
            },
        },
    ),
    ids=("responses-with-mcp-alias", "responses-and-chat-wrapper"),
)
def test_openai_responses_mixed_dialects_remain_ambiguous(raw):
    with pytest.raises(SchemaError, match="competing|direct and nested"):
        parse_tool_definitions({"tools": [raw]})


@pytest.mark.parametrize(
    "document",
    (
        {"tools": [_collision_mcp_tool("mcp")]},
        {"result": {"tools": [_collision_mcp_tool("mcp_result")]}},
        {
            "sources": [
                {"id": "source", "tools": [_collision_mcp_tool("atlas")]}
            ]
        },
        {"functions": [_collision_openai_function("functions")]},
        {
            "tools": [
                {
                    "type": "function",
                    "function": _collision_openai_function("openai"),
                }
            ]
        },
        {
            "tools": [
                {
                    "type": "function",
                    **_collision_openai_function("responses"),
                }
            ]
        },
        {
            "name": "anthropic",
            "input_schema": {"type": "object", "properties": {}},
        },
    ),
)
def test_each_supported_single_schema_dialect_remains_valid(document):
    definitions = parse_tool_definitions(document)

    assert len(definitions) == 1
    assert definitions[0].input_schema["type"] == "object"


@pytest.mark.parametrize("failure_flag", (None, "--fail-on-review"))
def test_scanner_cli_rejects_envelope_collision_before_thresholds(
    tmp_path, capsys, failure_flag
):
    document = {
        "tools": [_collision_mcp_tool()],
        "functions": [_collision_openai_function()],
    }
    path = tmp_path / "mixed-dialects.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    argv = [str(path), "--format", "json"]
    if failure_flag is not None:
        argv.append(failure_flag)

    with pytest.raises(SystemExit) as exc_info:
        main(argv)

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "competing tool-definition envelopes" in error
    assert "Traceback" not in error


def test_malformed_report_container_cannot_fall_through_to_direct_tool_scan():
    report = scan_documents([{"tools": [_collision_mcp_tool("reported")]}])
    malformed = {
        "name": "fallback",
        "inputSchema": {"type": "object", "properties": {}},
        "tools": {"reported": report["tools"][0]},
    }

    with pytest.raises(SchemaError, match="report-shaped"):
        parse_tool_definitions(malformed)


def test_annotation_assessments_mark_report_tool_instead_of_raw_schema():
    report_shaped = {
        "tools": [
            {
                "name": "operate",
                "annotation_assessments": [],
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            }
        ]
    }

    with pytest.raises(SchemaError, match="report-shaped"):
        scan_documents([report_shaped])


def _wrap_collection_entry(envelope, tool):
    if envelope == "direct-list":
        return [tool]
    if envelope == "tools":
        return {"tools": [tool]}
    if envelope == "result.tools":
        return {"result": {"tools": [tool]}}
    if envelope == "sources.tools":
        return {"sources": [{"id": "source", "tools": [tool]}]}
    raise AssertionError(f"unknown collection envelope: {envelope}")


@pytest.mark.parametrize(
    ("header", "value"),
    (
        ("generator", "verb-authority"),
        ("report_version", 3),
        ("privacy", {}),
        ("schema_fingerprint_sha256", "0" * 64),
        ("summary", {}),
        ("declared_controls", {}),
        ("control_declaration_fingerprint_sha256", "0" * 64),
    ),
)
@pytest.mark.parametrize(
    "envelope",
    ("direct-list", "tools", "result.tools", "sources.tools"),
)
def test_report_header_sentinel_on_collection_entry_never_becomes_raw_schema(
    envelope, header, value
):
    hybrid = _collision_mcp_tool("operate")
    hybrid[header] = value
    document = _wrap_collection_entry(envelope, hybrid)

    with pytest.raises(SchemaError, match="report-shaped"):
        parse_tool_definitions(document)


@pytest.mark.parametrize(
    ("sentinel", "value"),
    (("review_required", True), ("review_sources", {})),
)
@pytest.mark.parametrize(
    "envelope",
    ("direct-list", "tools", "result.tools", "sources.tools"),
)
def test_v5_tool_review_sentinels_never_become_raw_schema(
    envelope, sentinel, value
):
    hybrid = _collision_mcp_tool("operate")
    hybrid[sentinel] = value

    with pytest.raises(SchemaError, match="report-shaped"):
        parse_tool_definitions(_wrap_collection_entry(envelope, hybrid))


def test_v5_review_names_inside_input_schema_remain_ordinary_arguments():
    document = {
        "tools": [
            {
                "name": "record_review",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "review_required": {"type": "boolean"},
                        "review_sources": {"type": "object"},
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }

    definitions = parse_tool_definitions(document)

    assert [definition.name for definition in definitions] == ["record_review"]
    assert set(definitions[0].input_schema["properties"]) == {
        "review_required",
        "review_sources",
    }


@pytest.mark.parametrize(
    "envelope",
    ("direct-list", "tools", "result.tools", "sources.tools"),
)
def test_ordinary_raw_tool_in_each_collection_envelope_remains_accepted(envelope):
    document = _wrap_collection_entry(envelope, _collision_mcp_tool("operate"))

    definitions = parse_tool_definitions(document)

    assert [definition.name for definition in definitions] == ["operate"]


def test_scanner_shares_and_caches_identifier_nfkc_work(monkeypatch):
    original_normalize = verb_authority.unicodedata.normalize
    normalization_calls = []
    monkeypatch.setattr(verb_authority, "MAX_NFKC_OPERATION_CHARS", 8)

    def counted_normalize(form, value):
        normalization_calls.append((form, value))
        return original_normalize(form, value)

    monkeypatch.setattr(
        verb_authority,
        "unicodedata",
        type(
            "UnicodeProxy",
            (),
            {
                "normalize": staticmethod(counted_normalize),
                "name": staticmethod(verb_authority.unicodedata.name),
            },
        ),
    )
    document = {
        "tools": [
            {
                "name": "write_values",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "éaaa": {"type": "integer"},
                        "öbbb": {"type": "integer"},
                        "üccc": {"type": "integer"},
                    },
                },
            }
        ]
    }

    report = scan_documents([document])

    assert len(normalization_calls) == 2
    assert all(
        argument["policy"] == "trusted_fixed"
        for argument in report["tools"][0]["arguments"]
    )


def _scanner_identifier_budget_burners(total_chars, *, start):
    names = []
    remaining = total_chars
    index = 0
    while remaining:
        length = min(
            verb_authority.MAX_IDENTIFIER_INFERENCE_CHARS,
            remaining,
        )
        names.append(chr(start + index) + ("é" * (length - 1)))
        remaining -= length
        index += 1
    return names


def test_scanner_nfkc_max_plus_one_surfaces_incomplete_risk_fail_closed():
    target = "ｄｅｌｅｔｅ_records"
    burner_names = _scanner_identifier_budget_burners(
        verb_authority.MAX_NFKC_OPERATION_CHARS - len(target) + 1,
        start=0xA00,
    )
    tools = [
        {
            "name": name,
            "inputSchema": {"type": "object", "properties": {}},
        }
        for name in burner_names
    ]
    tools.append(
        {
            "name": target,
            "inputSchema": {"type": "object", "properties": {}},
        }
    )
    controls = {
        "version": 1,
        "tools": {
            target: {
                "risk": {
                    "tier": "read_only",
                    "evidence": "attested",
                    "effects": ["reads records"],
                }
            }
        },
    }

    report = scan_documents(
        [{"tools": tools}],
        control_declarations=controls,
    )
    scanned = report["tools"][-1]

    assert scanned["risk"] == "unknown"
    assert scanned["risk_source"] == "safe_default"
    assert scanned["risk_evidence"] is None
    assert scanned["inferred_risk"] == "unknown"
    assert scanned["risk_inference"]["source"] == "inference_limit"
    assert scanned["risk_review_required"] is True
    assert scanned["needs_confirmation"] is True


def test_scanner_nfkc_max_plus_one_keeps_read_only_sink_locked():
    target = "ｒｅｃｉｐｉｅｎｔ"
    burner_names = _scanner_identifier_budget_burners(
        verb_authority.MAX_NFKC_OPERATION_CHARS - len(target) + 1,
        start=0xB00,
    )
    tools = [
        {
            "name": name,
            "inputSchema": {"type": "object", "properties": {}},
        }
        for name in burner_names
    ]
    tools.append(
        {
            "name": "catalog",
            "inputSchema": {
                "type": "object",
                "properties": {target: {"type": "string"}},
                "additionalProperties": False,
            },
        }
    )
    controls = {
        "version": 1,
        "tools": {
            "catalog": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "attested",
                    "effects": ["reads catalog"],
                }
            }
        },
    }

    report = scan_documents(
        [{"tools": tools}],
        control_declarations=controls,
    )
    argument = report["tools"][-1]["arguments"][0]

    assert argument["policy"] == "trusted_fixed"
    assert argument["confidence"] == "uncertain"
    assert argument["review_required"] is True
    assert argument["reason"] == (
        "identifier inference incomplete; kept locked for review"
    )
    assert report["summary"]["data_fillable_parameters"] == 0


def test_scanner_read_only_reason_uses_the_effective_relaxed_policy():
    document = {
        "tools": [
            {
                "name": "catalog",
                "inputSchema": {
                    "type": "object",
                    "properties": {"foo": {"type": "string"}},
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "catalog": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "attested",
                    "effects": ["reads catalog"],
                }
            }
        },
    }

    report = scan_documents(
        [document],
        control_declarations=controls,
    )
    argument = report["tools"][0]["arguments"][0]

    assert argument["policy"] == "typed_bounded"
    assert argument["review_required"] is False
    assert argument["reason"] == (
        "ambiguous argument auto-relaxed for read-only tool"
    )


def test_scanner_rejects_compact_programmatic_schema_dag():
    shared = {"type": "string", "allOf": [{"maxLength": 20}]}
    document = {
        "tools": [
            {
                "name": "set_values",
                "inputSchema": {
                    "properties": {
                        "first": shared,
                        "second": shared,
                    }
                },
            }
        ]
    }

    with pytest.raises(SchemaError, match="repeated container alias"):
        scan_documents([document])


def test_scanner_accepts_equal_but_distinct_schema_subtrees():
    document = {
        "tools": [
            {
                "name": "set_values",
                "inputSchema": {
                    "properties": {
                        "first": {"type": "string", "maxLength": 20},
                        "second": {"type": "string", "maxLength": 20},
                    }
                },
            }
        ]
    }

    report = scan_documents([document])

    assert report["summary"]["parameters"] == 2
    fingerprints = [
        argument["schema_material_fingerprint_sha256"]
        for argument in report["tools"][0]["arguments"]
    ]
    assert fingerprints[0] == fingerprints[1]


def test_scanner_json_node_and_material_limits_are_exact(monkeypatch):
    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_NODES", 3)
    validate_plain_json([0, 1])
    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_NODES", 2)
    with pytest.raises(SchemaError, match="total node limit"):
        validate_plain_json([0, 1])

    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_NODES", 100)
    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_MATERIAL_BYTES", 6)
    validate_plain_json("abc")
    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_MATERIAL_BYTES", 5)
    with pytest.raises(SchemaError, match="material limit"):
        validate_plain_json("abc")


def test_scanner_file_limit_is_checked_before_json_parsing(tmp_path, monkeypatch):
    path = tmp_path / "input.json"
    path.write_text('{"x":0}', encoding="utf-8")
    monkeypatch.setattr(scanner, "MAX_SCAN_INPUT_BYTES", 7)
    assert load_json_path(str(path)) == {"x": 0}

    monkeypatch.setattr(scanner, "MAX_SCAN_INPUT_BYTES", 6)
    with pytest.raises(SchemaError, match="UTF-8 input limit"):
        load_json_path(str(path))


def _definition(name, properties):
    return ToolDefinition(
        name=name,
        input_schema={"properties": properties},
        annotations={},
    )


def test_all_scanner_entry_points_enforce_tool_and_argument_limits(monkeypatch):
    first = _definition("first", {"one": {"type": "string"}})
    second = _definition("second", {"two": {"type": "string"}})
    document = {
        "tools": [
            {
                "name": definition.name,
                "inputSchema": definition.input_schema,
            }
            for definition in (first, second)
        ]
    }
    monkeypatch.setattr(scanner, "MAX_SCAN_TOOL_DEFINITIONS", 1)
    with pytest.raises(SchemaError, match="tool-definition limit"):
        parse_tool_definitions(document)
    with pytest.raises(SchemaError, match="tool-definition limit"):
        scan_definitions([first, second])
    with pytest.raises(SchemaError, match="tool-definition limit"):
        scan_documents(
            [
                {"tools": [document["tools"][0]]},
                {"tools": [document["tools"][1]]},
            ]
        )

    monkeypatch.setattr(scanner, "MAX_SCAN_TOOL_DEFINITIONS", 10)
    two_arguments = {"one": {"type": "string"}, "two": {"type": "string"}}
    definition = _definition("one_tool", two_arguments)
    document = {
        "tools": [
            {
                "name": definition.name,
                "inputSchema": definition.input_schema,
            }
        ]
    }
    monkeypatch.setattr(scanner, "MAX_SCAN_ARGUMENTS", 1)
    with pytest.raises(SchemaError, match="argument limit"):
        parse_tool_definitions(document)
    with pytest.raises(SchemaError, match="argument limit"):
        scan_definitions([definition])
    with pytest.raises(SchemaError, match="argument limit"):
        scan_documents([document])


def test_enum_budget_is_aggregate_but_not_double_counted(monkeypatch):
    document = {
        "tools": [
            {
                "name": "choose",
                "inputSchema": {
                    "properties": {
                        "mode": {"type": "string", "enum": ["a", "b"]}
                    }
                },
            }
        ]
    }
    monkeypatch.setattr(scanner, "MAX_SCAN_ENUM_MEMBERS", 2)
    assert scan_documents([document])["summary"]["parameters"] == 1
    definitions = parse_tool_definitions(document)
    assert scan_definitions(definitions)["summary"]["parameters"] == 1

    monkeypatch.setattr(scanner, "MAX_SCAN_ENUM_MEMBERS", 1)
    with pytest.raises(SchemaError, match="enum-member limit"):
        parse_tool_definitions(document)
    definition = _definition(
        "choose",
        {"mode": {"type": "string", "enum": ["a", "b"]}},
    )
    with pytest.raises(SchemaError, match="enum-member limit"):
        scan_definitions([definition])
    with pytest.raises(SchemaError, match="enum-member limit"):
        scan_documents([document])


def test_control_declaration_expansion_is_bounded_before_report_build(monkeypatch):
    document = {
        "tools": [
            {
                "name": "send",
                "inputSchema": {
                    "properties": {"recipient": {"type": "string"}}
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "send": {
                "risk": {
                    "tier": "write",
                    "evidence": "declared",
                    "effects": ["sends_message"],
                },
                "arguments": {
                    "recipient": {
                        "authority": "constrained",
                        "evidence": "declared",
                        "bounds": [
                            {
                                "source": "approved contacts",
                                "bounds_mutability": "trusted_party",
                            }
                        ],
                    }
                },
                "unexposed_arguments": {
                    "tenant": {
                        "exposure": "server_fixed",
                        "enforced_by": "authenticated session",
                        "evidence": "declared",
                    }
                },
            }
        },
    }

    # The exposed declaration refers to the one already-counted schema argument;
    # only the additional unexposed argument consumes the remaining argument slot.
    monkeypatch.setattr(scanner, "MAX_SCAN_ARGUMENTS", 2)
    monkeypatch.setattr(scanner, "MAX_SCAN_CONTROL_COLLECTION_MEMBERS", 2)
    assert scan_documents(
        [document], control_declarations=controls
    )["summary"]["parameters"] == 1

    monkeypatch.setattr(scanner, "MAX_SCAN_ARGUMENTS", 1)
    with pytest.raises(SchemaError, match="argument limit"):
        scan_documents([document], control_declarations=controls)

    monkeypatch.setattr(scanner, "MAX_SCAN_ARGUMENTS", 2)
    monkeypatch.setattr(scanner, "MAX_SCAN_CONTROL_COLLECTION_MEMBERS", 1)
    with pytest.raises(SchemaError, match="control collection-member limit"):
        scan_documents([document], control_declarations=controls)


def test_generated_report_is_checked_against_output_budget(monkeypatch):
    document = {"tools": [{"name": "read", "inputSchema": {}}]}
    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_NODES", 25)

    with pytest.raises(SchemaError, match="generated scanner report.*total node"):
        scan_documents([document])


@pytest.mark.parametrize("output_format", ("markdown", "json"))
def test_scanner_cli_rejects_over_budget_schema_without_traceback(
    tmp_path, capsys, monkeypatch, output_format
):
    schema_path = tmp_path / "too-many-arguments.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "send",
                        "inputSchema": {
                            "properties": {
                                "recipient": {"type": "string"},
                                "body": {"type": "string"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(scanner, "MAX_SCAN_ARGUMENTS", 1)

    with pytest.raises(SystemExit) as exc_info:
        main([str(schema_path), "--format", output_format])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "argument limit" in error
    assert "Traceback" not in error


def test_cli_rejects_duplicate_json_object_keys_cleanly(tmp_path, capsys):
    schema_path = tmp_path / "duplicate.json"
    schema_path.write_text(
        '{"tools":[{"name":"one","name":"two","inputSchema":{}}]}',
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        main([str(schema_path), "--format", "json"])

    assert exc_info.value.code == 2
    assert "duplicate object key: name" in capsys.readouterr().err


def test_cli_rejects_parseable_overdeep_schema_without_traceback(tmp_path, capsys):
    nested = {"type": "string"}
    for _ in range(140):
        nested = {"allOf": [nested]}
    schema_path = tmp_path / "deep.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "set_value",
                        "inputSchema": {"properties": {"value": nested}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        main([str(schema_path), "--format", "json"])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "maximum nesting depth" in error
    assert "Traceback" not in error


def test_markdown_report_escapes_terminal_and_bidi_controls_everywhere():
    hostile = "hostile\r\x1b[31m\u202e\u2028\u2029"
    tool_name = f"send_{hostile}"
    argument_name = f"recipient_{hostile}"
    document = {
        "sources": [
            {
                "id": hostile,
                "url": hostile,
                "tools": [
                    {
                        "name": tool_name,
                        "inputSchema": {
                            "properties": {
                                argument_name: {
                                    "type": "string",
                                    "format": "email",
                                }
                            }
                        },
                    }
                ],
            }
        ]
    }
    controls = {
        "version": 1,
        "attribution": {"name": hostile, "source": hostile},
        "tools": {
            tool_name: {
                "risk": {
                    "tier": "write",
                    "evidence": "declared",
                    "effects": [hostile],
                    "note": hostile,
                },
                "arguments": {
                    argument_name: {
                        "authority": "locked",
                        "evidence": "declared",
                        "note": hostile,
                    }
                },
                "unexposed_arguments": {
                    hostile: {
                        "exposure": "server_fixed",
                        "enforced_by": hostile,
                        "evidence": "declared",
                        "note": hostile,
                    }
                },
            }
        },
    }

    markdown = render_markdown(
        scan_documents([document], control_declarations=controls)
    )

    assert "\r" not in markdown
    assert "\x1b" not in markdown
    assert "\u202e" not in markdown
    assert "\u2028" not in markdown
    assert "\u2029" not in markdown
    assert "\\r" in markdown
    assert "\\u001b" in markdown
    assert "\\u202e" in markdown
    assert "\\u2028" in markdown
    assert "\\u2029" in markdown


def test_scans_mcp_tools_list_result():
    document = {
        "jsonrpc": "2.0",
        "result": {
            "tools": [
                {
                    "name": "send_email",
                    "description": "A private description that must not be reported",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string", "format": "email"},
                            "body": {"type": "string", "maxLength": 1000},
                        },
                        "required": ["to", "body"],
                    },
                }
            ]
        },
    }

    report = scan_documents([document])

    assert report["summary"] == {
        "tools": 1,
        "parameters": 2,
        "protected_parameters": 1,
        "data_fillable_parameters": 1,
        "review_required": 0,
        "review_required_tools": 1,
        "schema_review_required_tools": 0,
        "confirmation_required_tools": 1,
        "risk_review_required_tools": 1,
        "risk_conflicts": 0,
        "annotation_conflicts": 0,
        "branch_risk_review_required_tools": 0,
    }
    assert report["tools"][0]["risk"] == "unknown"
    assert report["tools"][0]["inferred_risk"] == "write"
    assert report["tools"][0]["risk_source"] == "safe_default"
    assert report["tools"][0]["risk_review_required"] is True
    assert report["tools"][0]["arguments"][0]["policy"] == "trusted_fixed"
    assert report["tools"][0]["schema_closes_unknown_arguments"] is False
    assert "private description" not in json.dumps(report).lower()


def test_scans_openai_and_anthropic_exports_together():
    openai = [
        {
            "type": "function",
            "function": {
                "name": "search_web",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        }
    ]
    anthropic = [
        {
            "name": "delete_file",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]

    report = scan_documents([openai, anthropic])

    assert report["summary"]["tools"] == 2
    assert [tool["risk"] for tool in report["tools"]] == [
        "unknown",
        "unknown",
    ]
    assert [tool["inferred_risk"] for tool in report["tools"]] == [
        "read_only",
        "destructive",
    ]


@pytest.mark.parametrize(
    "name",
    ["place_bid", "purchase_bid", "buy_bid", "submit_bid", "transfer_funds", "bid"],
)
def test_avp9_bid_name_mutations_are_only_advisory_until_declared(name):
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": name,
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ]
    )
    tool = report["tools"][0]

    assert tool["inferred_risk"] == "financial"
    assert tool["risk_inference"]["source"] == "tool_name"
    assert tool["risk_inference"]["mutability"] == "caller"
    assert tool["risk"] == "unknown"
    assert tool["risk_review_required"] is True
    assert tool["needs_confirmation"] is True


@pytest.mark.parametrize("name", ["evaluate", "evaluation", "revaluate"])
def test_avp9_evaluation_names_do_not_trigger_code_exec_substrings(name):
    report = scan_documents(
        [{"tools": [{"name": name, "inputSchema": {"properties": {}}}]}]
    )
    tool = report["tools"][0]

    assert tool["inferred_risk"] == "unknown"
    assert tool["risk_inference"]["matched_tokens"] == []
    assert tool["risk"] == "unknown"
    assert tool["needs_confirmation"] is True


def test_avp9_eval_complete_token_is_advisory_code_exec_evidence():
    tool = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "eval",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ]
    )["tools"][0]

    assert tool["inferred_risk"] == "code_exec"
    assert tool["risk_inference"]["matched_tokens"] == ["eval"]
    assert tool["risk"] == "unknown"
    assert tool["risk_source"] == "safe_default"
    assert tool["risk_review_required"] is True
    assert tool["needs_confirmation"] is True
    assert tool["review_required"] is True
    assert tool["review_sources"] == {
        "arguments": [],
        "schema": False,
        "risk": True,
        "risk_conflict": False,
        "annotation_conflicts": [],
        "branch_risk": False,
    }


def test_descriptions_and_parameter_names_do_not_author_risk():
    document = {
        "tools": [
            {
                "name": "neutral_action",
                "description": (
                    "Transfers funds. Spends money. Payment. Purchase. Buy. "
                    "Sends ETH from the wallet."
                ),
                "inputSchema": {
                    "properties": {
                        "amountWei": {"type": "string"},
                        "payment": {"type": "string"},
                    }
                },
            }
        ]
    }

    tool = scan_documents([document])["tools"][0]

    assert tool["inferred_risk"] == "unknown"
    assert tool["risk"] == "unknown"


def test_declared_effects_resolve_bid_evaluation_and_read_only_scanner():
    document = {
        "tools": [
            {
                "name": name,
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
            for name in ("place_bid", "evaluate", "chain_index")
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "place_bid": {
                "risk": {
                    "tier": "financial",
                    "evidence": "attested",
                    "effects": ["signs_transaction", "commits_funds"],
                }
            },
            "evaluate": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "attested",
                    "effects": ["reads_metadata", "calls_model"],
                }
            },
            "chain_index": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "observed",
                    "effects": ["reads_chain_state"],
                }
            },
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tools = {tool["name"]: tool for tool in report["tools"]}

    assert tools["place_bid"]["risk"] == "financial"
    assert tools["place_bid"]["needs_confirmation"] is True
    assert tools["evaluate"]["risk"] == "read_only"
    assert tools["evaluate"]["needs_confirmation"] is False
    assert tools["chain_index"]["risk"] == "read_only"
    assert tools["chain_index"]["needs_confirmation"] is False
    assert all(not tool["risk_review_required"] for tool in tools.values())
    assert all(not tool["review_required"] for tool in tools.values())
    assert all(
        tool["review_sources"]
        == {
            "arguments": [],
            "schema": False,
            "risk": False,
            "risk_conflict": False,
            "annotation_conflicts": [],
            "branch_risk": False,
        }
        for tool in tools.values()
    )
    # Runtime confirmation is an execution control, not static review debt.
    assert tools["place_bid"]["needs_confirmation"] is True
    assert tools["place_bid"]["review_required"] is False
    assert report["summary"]["risk_review_required_tools"] == 0
    assert report["summary"]["review_required_tools"] == 0


def test_synthetic_browser_tabs_locks_operation_selector_and_unbounded_index():
    document = {
        "tools": [
            {
                "name": "browser_tabs",
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": False,
                    "idempotentHint": True,
                    "openWorldHint": True,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "new", "close", "select"],
                            "description": "Operation to perform",
                        },
                        "index": {"type": "number"},
                        "url": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "browser_tabs": {
                "risk": {
                    "tier": "write",
                    "evidence": "observed",
                    "effects": ["changes browser tab state"],
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]
    arguments = {argument["name"]: argument for argument in tool["arguments"]}
    assessment_states = {
        assessment["annotation"]: assessment["state"]
        for assessment in tool["annotation_assessments"]
    }

    assert report["report_version"] == 5
    assert tool["review_required"] is True
    assert tool["review_sources"] == {
        "arguments": ["action", "index"],
        "schema": False,
        "risk": False,
        "risk_conflict": False,
        "annotation_conflicts": [],
        "branch_risk": True,
    }
    assert report["summary"]["review_required_tools"] == 1
    for name in ("action", "index"):
        assert arguments[name]["policy"] == "trusted_fixed"
        assert arguments[name]["confidence"] == "uncertain"
        assert arguments[name]["review_required"] is True
    assert arguments["url"]["policy"] == "trusted_fixed"
    assert arguments["url"]["confidence"] == "high"
    assert arguments["url"]["review_required"] is False
    assert tool["risk"] == "write"
    assert tool["needs_confirmation"] is False
    assert tool["branch_risk"] is None
    assert tool["branch_risk_review_required"] is True
    assert report["summary"]["branch_risk_review_required_tools"] == 1
    assert assessment_states == {
        "readOnlyHint": "consistent",
        "destructiveHint": "consistent",
        "idempotentHint": "unresolved",
        "openWorldHint": "unresolved",
    }
    assert tool["annotation_conflicts"] == []


def _browser_tabs_branch_controls():
    return {
        "version": 1,
        "tools": {
            "browser_tabs": {
                "branches": {
                    "selector": "action",
                    "cases": [
                        {
                            "value": "list",
                            "risk": {
                                "tier": "read_only",
                                "evidence": "observed",
                                "effects": ["reads_tabs"],
                            },
                            "arguments": ["action"],
                        },
                        {
                            "value": "new",
                            "risk": {
                                "tier": "write",
                                "evidence": "observed",
                                "effects": ["opens_tab"],
                            },
                            "arguments": ["url", "action"],
                        },
                        {
                            "value": "close",
                            "risk": {
                                "tier": "destructive",
                                "evidence": "observed",
                                "effects": ["destroys_tab"],
                            },
                            "arguments": ["index", "action"],
                        },
                        {
                            "value": "select",
                            "risk": {
                                "tier": "write",
                                "evidence": "observed",
                                "effects": ["selects_tab"],
                            },
                            "arguments": ["action", "index"],
                        },
                    ],
                }
            }
        },
    }


def _browser_tabs_branch_document():
    return {
        "tools": [
            {
                "name": "browser_tabs",
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": False,
                },
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "new", "close", "select"],
                            "description": "Operation to perform",
                        },
                        "index": {"type": "number"},
                        "url": {"type": "string"},
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }


def test_declared_browser_tab_branches_report_exact_risk_without_values():
    report = scan_documents(
        [_browser_tabs_branch_document()],
        control_declarations=_browser_tabs_branch_controls(),
    )
    tool = report["tools"][0]
    branch = tool["branch_risk"]
    action = next(
        argument for argument in tool["arguments"] if argument["name"] == "action"
    )

    assert tool["risk"] == "destructive"
    assert tool["risk_source"] == "branch_control_declaration"
    assert tool["risk_evidence"] is None
    assert tool["risk_review_required"] is False
    assert tool["needs_confirmation"] is True
    assert tool["branch_risk_review_required"] is False
    assert branch["selector"] == "action"
    assert branch["value_disclosure"] == "sha256_fingerprint_only"
    assert len(branch["cases"]) == 4
    assert [
        case["value_fingerprint_sha256"] for case in branch["cases"]
    ] == sorted(case["value_fingerprint_sha256"] for case in branch["cases"])
    assert sum(case["risk"] == "destructive" for case in branch["cases"]) == 1
    assert sum(case["needs_confirmation"] for case in branch["cases"]) == 1
    assert all(
        case["evidence"] == "observed" and case["active_arguments"]
        for case in branch["cases"]
    )
    # Branch evidence does not silently authorize data to select the branch.
    assert action["policy"] == "trusted_fixed"
    assert action["confidence"] == "uncertain"
    assert action["review_required"] is True
    assert report["summary"]["branch_risk_review_required_tools"] == 0
    assert report["summary"]["confirmation_required_tools"] == 1
    assert tool["annotation_conflicts"] == [
        "destructiveHint=false conflicts with effective risk"
    ]
    serialized = json.dumps(report, sort_keys=True)
    for raw_value in ('"list"', '"new"', '"close"', '"select"'):
        assert raw_value not in serialized
    assert "## Declared branch risk" in render_markdown(report)


def test_all_read_only_branches_do_not_relax_argument_provenance():
    controls = _browser_tabs_branch_controls()
    for case in controls["tools"]["browser_tabs"]["branches"]["cases"]:
        case["risk"]["tier"] = "read_only"
    report = scan_documents(
        [_browser_tabs_branch_document()],
        control_declarations=controls,
    )
    tool = report["tools"][0]
    arguments = {
        argument["name"]: argument for argument in tool["arguments"]
    }

    assert tool["risk"] == "read_only"
    assert tool["needs_confirmation"] is False
    for name in ("action", "index"):
        assert arguments[name]["policy"] == "trusted_fixed"
        assert arguments[name]["confidence"] == "uncertain"
        assert arguments[name]["review_required"] is True
        assert arguments[name]["reason"] == (
            "ambiguous consequential argument; review required"
        )


def test_redacted_branch_report_redacts_selector_and_active_argument_names():
    report = scan_documents(
        [_browser_tabs_branch_document()],
        control_declarations=_browser_tabs_branch_controls(),
        redact_names=True,
    )
    tool = report["tools"][0]
    branch = tool["branch_risk"]

    assert tool["name"] == "tool_001"
    assert tool["review_sources"]["arguments"] == [
        "param_001",
        "param_002",
    ]
    assert branch["selector"] == "param_001"
    assert all(
        set(case["active_arguments"]) <= {"param_001", "param_002", "param_003"}
        for case in branch["cases"]
    )
    assert report["privacy"]["branch_value_fingerprints_included"] is True
    assert (
        report["privacy"]["branch_value_fingerprints_dictionary_guessable"]
        is True
    )
    serialized = json.dumps(report, sort_keys=True)
    for secret in ("browser_tabs", "action", "index", "url"):
        assert secret not in serialized


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda controls: controls["tools"]["browser_tabs"].update(
                {
                    "risk": {
                        "tier": "write",
                        "evidence": "observed",
                        "effects": ["writes_state"],
                    }
                }
            ),
            "cannot combine tool risk with branch risk",
        ),
        (
            lambda controls: controls["tools"]["browser_tabs"]["branches"].update(
                {"selector": "missing"}
            ),
            "must name an exposed schema argument",
        ),
        (
            lambda controls: controls["tools"]["browser_tabs"]["branches"][
                "cases"
            ].pop(),
            "must exhaust the selector enum",
        ),
        (
            lambda controls: controls["tools"]["browser_tabs"]["branches"][
                "cases"
            ].__setitem__(
                1,
                copy.deepcopy(
                    controls["tools"]["browser_tabs"]["branches"]["cases"][0]
                ),
            ),
            "duplicate exact branch case",
        ),
        (
            lambda controls: controls["tools"]["browser_tabs"]["branches"][
                "cases"
            ][0].update({"arguments": ["index"]}),
            "must include selector",
        ),
        (
            lambda controls: controls["tools"]["browser_tabs"]["branches"][
                "cases"
            ][0].update({"arguments": ["action", "action"]}),
            "duplicate active argument",
        ),
        (
            lambda controls: controls["tools"]["browser_tabs"]["branches"][
                "cases"
            ][0].update({"arguments": ["action", "missing"]}),
            "must name an exposed schema argument",
        ),
        (
            lambda controls: controls["tools"]["browser_tabs"]["branches"][
                "cases"
            ][0].update({"unexpected": True}),
            "unknown field",
        ),
    ],
)
def test_branch_control_declarations_fail_closed(mutate, message):
    controls = _browser_tabs_branch_controls()
    mutate(controls)

    with pytest.raises(SchemaError, match=message):
        scan_documents(
            [_browser_tabs_branch_document()], control_declarations=controls
        )


def test_branch_selector_requires_scalar_enum_members():
    document = _browser_tabs_branch_document()
    document["tools"][0]["inputSchema"]["properties"]["action"]["enum"][0] = {
        "operation": "list"
    }
    controls = _browser_tabs_branch_controls()
    controls["tools"]["browser_tabs"]["branches"]["cases"][0]["value"] = {
        "operation": "list"
    }

    with pytest.raises(SchemaError, match="must be an exact JSON scalar"):
        scan_documents([document], control_declarations=controls)


def test_branch_selector_distinguishes_positive_and_negative_zero():
    document = {
        "tools": [
            {
                "name": "choose_mode",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "number", "enum": [0.0]}
                    },
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "choose_mode": {
                "branches": {
                    "selector": "action",
                    "cases": [
                        {
                            "value": -0.0,
                            "risk": {
                                "tier": "read_only",
                                "evidence": "observed",
                                "effects": ["reads_state"],
                            },
                            "arguments": ["action"],
                        }
                    ],
                }
            }
        },
    }

    with pytest.raises(SchemaError, match="match exactly one selector enum"):
        scan_documents([document], control_declarations=controls)


def test_branch_selector_losslessly_normalizes_exact_decimal_members():
    document = {
        "tools": [
            {
                "name": "choose_mode",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "number",
                            "enum": [Decimal("0.1"), Decimal("1.5")],
                        }
                    },
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "choose_mode": {
                "branches": {
                    "selector": "action",
                    "cases": [
                        {
                            "value": Decimal("0.1"),
                            "risk": {
                                "tier": "read_only",
                                "evidence": "observed",
                                "effects": ["reads_state"],
                            },
                            "arguments": ["action"],
                        },
                        {
                            "value": Decimal("1.5"),
                            "risk": {
                                "tier": "destructive",
                                "evidence": "observed",
                                "effects": ["destroys_state"],
                            },
                            "arguments": ["action"],
                        },
                    ],
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)

    assert report["tools"][0]["risk"] == "destructive"
    assert len(report["tools"][0]["branch_risk"]["cases"]) == 2


def test_branch_selector_rejects_decimal_that_float_cannot_preserve():
    value = Decimal("0.1000000000000000000001")
    document = {
        "tools": [
            {
                "name": "choose_mode",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "number", "enum": [value]}
                    },
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "choose_mode": {
                "branches": {
                    "selector": "action",
                    "cases": [
                        {
                            "value": value,
                            "risk": {
                                "tier": "read_only",
                                "evidence": "observed",
                                "effects": ["reads_state"],
                            },
                            "arguments": ["action"],
                        }
                    ],
                }
            }
        },
    }

    with pytest.raises(SchemaError, match="exact portable runtime selector"):
        scan_documents([document], control_declarations=controls)


def test_branch_selector_rejects_integer_beyond_runtime_portable_bound():
    value = 10 ** verb_authority.MAX_JSON_INTEGER_DIGITS
    document = {
        "tools": [
            {
                "name": "choose_mode",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "integer", "enum": [value]}
                    },
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "choose_mode": {
                "branches": {
                    "selector": "action",
                    "cases": [
                        {
                            "value": value,
                            "risk": {
                                "tier": "read_only",
                                "evidence": "observed",
                                "effects": ["reads_state"],
                            },
                            "arguments": ["action"],
                        }
                    ],
                }
            }
        },
    }

    with pytest.raises(SchemaError, match="portable runtime integer limit"):
        scan_documents([document], control_declarations=controls)


@pytest.mark.parametrize("selector", ("tabAction", "tab_action", "tabaction"))
def test_branch_review_recognizes_camel_and_flat_selector_names(selector):
    document = {
        "tools": [
            {
                "name": "operate_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        selector: {
                            "type": "string",
                            "enum": ["list", "close"],
                        }
                    },
                },
            }
        ]
    }

    report = scan_documents([document])

    assert report["tools"][0]["branch_risk_review_required"] is True
    assert report["summary"]["branch_risk_review_required_tools"] == 1


@pytest.mark.parametrize("raw_sink_hint", (False, True))
def test_raw_schema_sink_hint_cannot_act_as_verified_authority_control(
    raw_sink_hint,
):
    def browser_tabs_document(include_hint):
        action = {
            "type": "string",
            "enum": ["list", "new", "close", "select"],
        }
        index = {"type": "number"}
        if include_hint:
            action["x-verb-authority-sink"] = raw_sink_hint
            index["x-verb-authority-sink"] = raw_sink_hint
        return {
            "tools": [
                {
                    "name": "browser_tabs",
                    "inputSchema": {
                        "type": "object",
                        "properties": {"action": action, "index": index},
                        "additionalProperties": False,
                    },
                }
            ]
        }

    controls = {
        "version": 1,
        "tools": {
            "browser_tabs": {
                "risk": {
                    "tier": "write",
                    "evidence": "observed",
                    "effects": ["changes browser tab state"],
                }
            }
        },
    }
    report = scan_documents(
        [browser_tabs_document(True)], control_declarations=controls
    )
    baseline = scan_documents(
        [browser_tabs_document(False)], control_declarations=controls
    )
    arguments = {
        argument["name"]: argument for argument in report["tools"][0]["arguments"]
    }
    baseline_arguments = {
        argument["name"]: argument
        for argument in baseline["tools"][0]["arguments"]
    }

    for name in ("action", "index"):
        assert arguments[name]["policy"] == "trusted_fixed"
        assert arguments[name]["confidence"] == "uncertain"
        assert arguments[name]["review_required"] is True
        assert arguments[name]["reason"] == (
            "ambiguous consequential argument; review required"
        )
        assert arguments[name]["schema_material_fingerprint_sha256"] != (
            baseline_arguments[name]["schema_material_fingerprint_sha256"]
        )
        assert arguments[name]["unmodeled_schema_fingerprint_sha256"] != (
            baseline_arguments[name]["unmodeled_schema_fingerprint_sha256"]
        )


def test_raw_max_length_cannot_unlock_ambiguous_authority_string():
    document = {
        "tools": [
            {
                "name": "browser_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "maxLength": 201}
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "browser_tabs": {
                "risk": {
                    "tier": "write",
                    "evidence": "observed",
                    "effects": ["changes browser tab state"],
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]
    action = tool["arguments"][0]

    assert action["policy"] == "trusted_fixed"
    assert action["confidence"] == "uncertain"
    assert action["review_required"] is True
    assert action["constraints"] == {"max_length": 201}
    assert tool["needs_confirmation"] is False
    assert report["summary"]["review_required"] == 1


def test_unknown_risk_keeps_mcp_annotations_unresolved_not_conflicting():
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "operate",
                        "annotations": {
                            "readOnlyHint": False,
                            "destructiveHint": True,
                            "idempotentHint": True,
                            "openWorldHint": False,
                        },
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        ]
    )
    tool = report["tools"][0]
    assessments = {
        assessment["annotation"]: assessment
        for assessment in tool["annotation_assessments"]
    }

    assert tool["risk"] == "unknown"
    assert tool["annotation_conflicts"] == []
    assert report["summary"]["annotation_conflicts"] == 0
    assert tool["review_sources"]["annotation_conflicts"] == []
    assert {name: assessment["state"] for name, assessment in assessments.items()} == {
        "readOnlyHint": "unresolved",
        "destructiveHint": "unresolved",
        "idempotentHint": "unresolved",
        "openWorldHint": "unresolved",
    }
    assert assessments["readOnlyHint"]["comparison_source"] == "effective_risk"
    assert assessments["readOnlyHint"]["comparison_value"] == "unknown"
    assert assessments["destructiveHint"]["comparison_source"] == "effective_risk"
    assert assessments["destructiveHint"]["comparison_value"] == "unknown"
    assert assessments["idempotentHint"]["comparison_source"] == "none"
    assert assessments["idempotentHint"]["comparison_value"] is None
    assert all(
        assessment["evidence_source"] == "mcp_tool_annotation"
        and assessment["trust"] == "unverified_hint"
        for assessment in assessments.values()
    )

    markdown = render_markdown(report)
    assert "## MCP annotation evidence" in markdown
    assert (
        "| operate | destructiveHint | true | unresolved | effective_risk | "
        "unknown |"
    ) in markdown


def test_read_only_hint_makes_effect_hints_inapplicable_even_when_risk_unknown():
    tool = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "operate",
                        "annotations": {
                            "readOnlyHint": True,
                            "destructiveHint": True,
                            "idempotentHint": True,
                        },
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        ]
    )["tools"][0]

    assessments = {
        assessment["annotation"]: assessment
        for assessment in tool["annotation_assessments"]
    }
    assert assessments["readOnlyHint"]["state"] == "unresolved"
    assert assessments["destructiveHint"]["state"] == "inapplicable"
    assert assessments["destructiveHint"]["comparison_source"] == "readOnlyHint"
    assert assessments["idempotentHint"]["state"] == "inapplicable"
    assert tool["annotation_conflicts"] == []


@pytest.mark.parametrize(
    ("name", "tier", "annotations", "expected_states", "expected_conflicts"),
    [
        (
            "read_record",
            "read_only",
            {"readOnlyHint": True},
            {"readOnlyHint": "consistent"},
            [],
        ),
        (
            "read_record",
            "read_only",
            {"readOnlyHint": False},
            {"readOnlyHint": "conflict"},
            ["readOnlyHint=false conflicts with effective risk"],
        ),
        (
            "write_record",
            "write",
            {"readOnlyHint": False, "destructiveHint": False},
            {"readOnlyHint": "consistent", "destructiveHint": "consistent"},
            [],
        ),
        (
            "write_record",
            "write",
            {
                "readOnlyHint": True,
                "destructiveHint": True,
                "idempotentHint": False,
            },
            {
                "readOnlyHint": "conflict",
                "destructiveHint": "inapplicable",
                "idempotentHint": "inapplicable",
            },
            ["readOnlyHint=true conflicts with effective risk"],
        ),
        (
            "delete_record",
            "destructive",
            {"readOnlyHint": False, "destructiveHint": True},
            {"readOnlyHint": "consistent", "destructiveHint": "consistent"},
            [],
        ),
        (
            "delete_record",
            "destructive",
            {"destructiveHint": True},
            {"destructiveHint": "consistent"},
            [],
        ),
        (
            "delete_record",
            "destructive",
            {"readOnlyHint": False, "destructiveHint": False},
            {"readOnlyHint": "consistent", "destructiveHint": "conflict"},
            ["destructiveHint=false conflicts with effective risk"],
        ),
    ],
)
def test_mcp_annotation_assessment_states(
    name, tier, annotations, expected_states, expected_conflicts
):
    document = {
        "tools": [
            {
                "name": name,
                "annotations": annotations,
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            name: {
                "risk": {
                    "tier": tier,
                    "evidence": "observed",
                    "effects": [f"observed_{tier}_effect"],
                }
            }
        },
    }

    tool = scan_documents([document], control_declarations=controls)["tools"][0]

    assert {
        assessment["annotation"]: assessment["state"]
        for assessment in tool["annotation_assessments"]
    } == expected_states
    assert tool["annotation_conflicts"] == expected_conflicts


@pytest.mark.parametrize(
    "annotation",
    ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"),
)
def test_non_boolean_known_mcp_annotation_is_rejected(annotation):
    document = {
        "tools": [
            {
                "name": "operate",
                "annotations": {annotation: "true"},
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
    }

    with pytest.raises(
        SchemaError, match=rf"annotation '{annotation}' must be boolean"
    ):
        scan_documents([document])


def test_direct_tool_definition_revalidates_known_mcp_annotation_types():
    definition = ToolDefinition(
        name="operate",
        input_schema={"type": "object", "properties": {}},
        annotations={"readOnlyHint": 1},
    )

    with pytest.raises(
        SchemaError, match="annotation 'readOnlyHint' must be boolean"
    ):
        scan_definitions([definition])


def test_destructive_hint_false_conflicts_with_declared_destructive_risk():
    document = {
        "tools": [
            {
                "name": "erase_store",
                "annotations": {
                    "readOnlyHint": False,
                    "destructiveHint": False,
                },
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "erase_store": {
                "risk": {
                    "tier": "destructive",
                    "evidence": "attested",
                    "effects": ["deletes_store"],
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]

    assert tool["annotation_conflicts"] == [
        "destructiveHint=false conflicts with effective risk"
    ]
    assert {
        assessment["annotation"]: assessment["state"]
        for assessment in tool["annotation_assessments"]
    } == {
        "readOnlyHint": "consistent",
        "destructiveHint": "conflict",
    }
    assert report["summary"]["annotation_conflicts"] == 1
    assert tool["review_required"] is True
    assert tool["review_sources"]["annotation_conflicts"] == [
        "destructiveHint"
    ]
    assert tool["needs_confirmation"] is True


def test_declared_lower_risk_conflict_keeps_confirmation_fail_safe():
    document = {
        "tools": [
            {"name": "purchase_bid", "inputSchema": {"properties": {}}}
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "purchase_bid": {
                "risk": {
                    "tier": "write",
                    "evidence": "declared",
                    "effects": ["writes_state"],
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]

    assert tool["risk"] == "unknown"
    assert tool["risk_source"] == "conflict_safe_default"
    assert tool["risk_evidence"] is None
    assert tool["inferred_risk"] == "financial"
    assert tool["declared_risk"]["tier"] == "write"
    assert tool["declared_risk"]["evidence"] == "declared"
    assert tool["risk_conflict"] is True
    assert tool["risk_review_required"] is True
    assert tool["review_required"] is True
    assert tool["review_sources"]["risk"] is True
    assert tool["review_sources"]["risk_conflict"] is True
    assert tool["needs_confirmation"] is True
    assert "| purchase_bid | unknown | conflict_safe_default |" in render_markdown(
        report
    )


def test_redacted_report_omits_names_sources_and_name_derived_fingerprint():
    document = {
        "sources": [
            {
                "id": "private-customer-name",
                "url": "https://internal.example/private",
                "tools": [
                    {
                        "name": "send_confidential_invoice",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "customer_secret_account": {"type": "string"}
                            },
                        },
                    }
                ],
            }
        ]
    }

    named = scan_documents([document])
    redacted = scan_documents([document], redact_names=True)
    serialized = json.dumps(redacted)

    assert redacted["tools"][0]["name"] == "tool_001"
    assert redacted["tools"][0]["arguments"][0]["name"] == "param_001"
    assert "private" not in serialized
    assert "confidential" not in serialized
    assert "customer" not in serialized
    assert redacted["schema_fingerprint_sha256"] != named["schema_fingerprint_sha256"]


def test_public_atlas_baseline_is_reproducible():
    atlas_directory = Path(__file__).with_name("atlas")
    schema_path = atlas_directory / "public_mcp_schemas.json"
    report_path = atlas_directory / "public_mcp_report.md"
    document = json.loads(schema_path.read_text(encoding="utf-8"))

    report = scan_documents([document])

    assert report["summary"] == {
        "tools": 10,
        "parameters": 14,
        "protected_parameters": 13,
        "data_fillable_parameters": 1,
        "review_required": 9,
        "review_required_tools": 10,
        "schema_review_required_tools": 5,
        "confirmation_required_tools": 10,
        "risk_review_required_tools": 10,
        "risk_conflicts": 0,
        "annotation_conflicts": 0,
        "branch_risk_review_required_tools": 0,
    }
    assert report["schema_fingerprint_sha256"] == (
        "cd706cd542612e359452daccbcf49af52274fea8ee6b59501c2e0fb2a321128f"
    )
    assert report_path.read_text(encoding="utf-8") == render_markdown(report)


def test_markdown_states_privacy_and_interpretation_boundary():
    report = scan_documents(
        [{"tools": [{"name": "read_graph", "inputSchema": {"type": "object"}}]}]
    )

    markdown = render_markdown(report)

    assert "no server was executed and no network was used" in markdown
    assert "vulnerability verdict" in markdown


def test_markdown_escapes_schema_controlled_names():
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "read_<script>|tool",
                        "inputSchema": {
                            "properties": {"line\nbreak|arg": {"type": "string"}}
                        },
                    }
                ]
            }
        ]
    )

    markdown = render_markdown(report)

    assert "&lt;script&gt;\\|tool" in markdown
    assert "line break\\|arg" in markdown


def test_markdown_neutralizes_active_link_and_image_syntax():
    hostile = "![audit](https://example.invalid/pixel)`label`"
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": hostile,
                        "inputSchema": {"properties": {hostile: {"type": "string"}}},
                    }
                ]
            }
        ]
    )

    markdown = render_markdown(report)

    assert hostile not in markdown
    assert "![audit](" not in markdown
    assert "https://example.invalid/pixel" not in markdown
    assert (
        "\\!\\[audit\\](https&#58;//example.invalid/pixel)\\`label\\`"
        in markdown
    )


def test_markdown_neutralizes_github_shorthand_and_raw_commit_references():
    commit = "0123456789abcdef0123456789abcdef01234567"
    hostile = f"GH-26 #7 @yairsabag {commit}"
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": hostile,
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        ]
    )

    markdown = render_markdown(report)

    assert "GH-26" not in markdown
    assert "#7" not in markdown
    assert "@yairsabag" not in markdown
    assert commit not in markdown
    assert "GH&#8204;-26" in markdown
    assert "#&#8204;7" in markdown
    assert "@&#8204;yairsabag" in markdown
    assert "0123456789abcdef0123&#8204;456789abcdef01234567" in markdown


@pytest.mark.parametrize("length", [7, 8, 12, 20, 39])
def test_markdown_neutralizes_standalone_commit_prefixes(length):
    token = "0123456789abcdef0123456789abcdef01234567"[:length]
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": token,
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        ]
    )

    markdown = render_markdown(report)
    midpoint = length // 2

    assert token not in markdown
    assert token[:midpoint] + "&#8204;" + token[midpoint:] in markdown


def test_reports_declared_controls_without_overriding_inferred_policy():
    document = {
        "tools": [
            {
                "name": "create_export",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "destination_path": {"type": "string"},
                        "format": {"type": "string", "enum": ["csv", "json"]},
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "attribution": {"name": "Example reviewer", "source": "implementation review"},
        "tools": {
            "create_export": {
                "arguments": {
                    "destination_path": {
                        "authority": "constrained",
                        "evidence": "attested",
                        "bounds": [
                            {
                                "source": "approved export root",
                                "bounds_mutability": "trusted_party",
                                "enforcement": "runtime path containment",
                            }
                        ],
                    },
                    "format": {"authority": "free", "evidence": "observed"},
                },
                "unexposed_arguments": {
                    "tenant_id": {
                        "exposure": "server_fixed",
                        "enforced_by": "authenticated session",
                        "evidence": "declared",
                    }
                },
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    declared = report["declared_controls"]

    assert report["tools"][0]["arguments"][0]["policy"] == "trusted_fixed"
    assert declared["tools"][0]["arguments"][0]["authority"] == "constrained"
    assert declared["tools"][0]["arguments"][0]["bounds"][0][
        "operational_status"
    ] == "not_stated"
    assert declared["tools"][0]["arguments"][0]["inferred_policy"] == (
        "trusted_fixed"
    )
    assert declared["tools"][0]["unexposed_arguments"][0]["exposure"] == (
        "server_fixed"
    )
    assert declared["tools"][0]["schema_closes_unknown_arguments"] is True
    assert "not independently verified" in declared["verification_notice"]
    assert len(report["control_declaration_fingerprint_sha256"]) == 64

    markdown = render_markdown(report)
    assert "Declared controls (author-supplied)" in markdown
    assert "destination_path" in markdown
    assert "runtime path containment" in markdown
    assert "not_stated" in markdown


def test_unexposed_control_on_open_schema_requires_schema_review():
    document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": True,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "send_message": {
                "unexposed_arguments": {
                    "recipient": {
                        "exposure": "server_fixed",
                        "enforced_by": "authenticated session",
                        "evidence": "declared",
                    }
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)

    assert report["tools"][0]["schema_closes_unknown_arguments"] is False
    assert report["tools"][0]["schema_review_required"] is True
    assert report["tools"][0]["review_required"] is True
    assert report["tools"][0]["review_sources"]["schema"] is True
    assert report["summary"]["schema_review_required_tools"] == 1


def test_redacts_declared_control_names_attribution_and_fingerprint_inputs():
    document = {
        "tools": [
            {
                "name": "create_private_export",
                "inputSchema": {
                    "properties": {"secret_destination": {"type": "string"}}
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "attribution": {"name": "Private reviewer"},
        "tools": {
            "create_private_export": {
                "arguments": {
                    "secret_destination": {
                        "authority": "locked",
                        "evidence": "declared",
                    }
                },
                "unexposed_arguments": {
                    "private_tenant": {
                        "exposure": "server_fixed",
                        "enforced_by": "session context",
                        "evidence": "observed",
                    }
                },
            }
        },
    }

    named = scan_documents([document], control_declarations=controls)
    redacted = scan_documents(
        [document], redact_names=True, control_declarations=controls
    )
    serialized = json.dumps(redacted)

    assert "create_private_export" not in serialized
    assert "secret_destination" not in serialized
    assert "private_tenant" not in serialized
    assert "Private reviewer" not in serialized
    assert redacted["declared_controls"]["tools"][0]["name"] == "tool_001"
    assert redacted["declared_controls"]["tools"][0]["arguments"][0]["name"] == (
        "param_001"
    )
    assert redacted["control_declaration_fingerprint_sha256"] != named[
        "control_declaration_fingerprint_sha256"
    ]


def test_avp9_nexus_financial_fixture_regression():
    fixtures = Path(__file__).parent / "fixtures"
    schema = json.loads(
        (fixtures / "avp9_nexus_financial_tool.json").read_text(encoding="utf-8")
    )
    controls = json.loads(
        (fixtures / "avp9_nexus_financial_controls.json").read_text(
            encoding="utf-8"
        )
    )
    expected = json.loads(
        (fixtures / "avp9_nexus_expected.json").read_text(encoding="utf-8")
    )

    report = scan_documents([schema], control_declarations=controls)
    tool = report["tools"][0]
    declared = report["declared_controls"]
    declared_tool = declared["tools"][0]
    arguments = {
        argument["name"]: argument for argument in declared_tool["arguments"]
    }
    unexposed = {
        argument["name"]: argument
        for argument in declared_tool["unexposed_arguments"]
    }

    assert tool["name"] == expected["tool"]
    assert tool["risk"] == expected["risk"]
    assert tool["risk_source"] == expected["risk_source"]
    assert tool["risk_evidence"] == expected["risk_evidence"]
    assert tool["inferred_risk"] == expected["inferred_risk"]
    assert tool["risk_conflict"] is expected["risk_conflict"]
    assert tool["risk_review_required"] is expected["risk_review_required"]
    assert tool["declared_risk"]["effects"] == expected["effects"]
    assert tool["needs_confirmation"] is expected["needs_confirmation"]
    assert (
        declared_tool["schema_closes_unknown_arguments"]
        is expected["schema_closes_unknown_arguments"]
    )
    assert declared["attribution"] == expected["attribution"]
    assert declared_tool["risk"]["tier"] == expected["risk"]
    assert declared_tool["risk"]["effects"] == expected["effects"]

    for name, expected_argument in expected["arguments"].items():
        assert arguments[name]["authority"] == expected_argument["authority"]
        assert arguments[name]["evidence"] == expected_argument["evidence"]
        if "bounds_mutability" in expected_argument:
            assert [
                bound["bounds_mutability"] for bound in arguments[name]["bounds"]
            ] == expected_argument["bounds_mutability"]
        if "operational_status" in expected_argument:
            assert [
                bound["operational_status"] for bound in arguments[name]["bounds"]
            ] == expected_argument["operational_status"]

    # Positive-control guard: do not collapse this deployment into either extreme.
    assert arguments["bidWei"]["authority"] == "constrained"
    assert arguments["bidWei"]["authority"] not in {"locked", "free"}

    for name, expected_argument in expected["unexposed_arguments"].items():
        assert unexposed[name]["exposure"] == expected_argument["exposure"]
        assert unexposed[name]["enforced_by"] == expected_argument["enforced_by"]
        assert unexposed[name]["evidence"] == expected_argument["evidence"]

    redacted = json.dumps(
        scan_documents(
            [schema], redact_names=True, control_declarations=controls
        ),
        sort_keys=True,
    )
    assert "avp9-nexus" not in redacted
    assert expected["attribution"]["source"] not in redacted


def test_control_fingerprint_ignores_json_object_member_order():
    document = {
        "tools": [
            {
                "name": "search_records",
                "inputSchema": {
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer"},
                    }
                },
            }
        ]
    }
    query = {"authority": "free", "evidence": "observed"}
    limit = {"authority": "locked", "evidence": "declared"}
    first = {
        "version": 1,
        "tools": {
            "search_records": {"arguments": {"query": query, "limit": limit}}
        },
    }
    reordered = {
        "tools": {
            "search_records": {"arguments": {"limit": limit, "query": query}}
        },
        "version": 1,
    }

    first_report = scan_documents([document], control_declarations=first)
    reordered_report = scan_documents([document], control_declarations=reordered)

    assert first_report["control_declaration_fingerprint_sha256"] == (
        reordered_report["control_declaration_fingerprint_sha256"]
    )


@pytest.mark.parametrize(
    ("controls", "message"),
    [
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "risk": {
                            "tier": "write",
                            "evidence": "declared",
                            "effects": [],
                        }
                    }
                },
            },
            "non-empty array",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "risk": {
                            "tier": "unknown",
                            "evidence": "declared",
                            "effects": ["writes_state"],
                        }
                    }
                },
            },
            "risk tier",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "arguments": {
                            "opaque": {
                                "authority": "constrained",
                                "evidence": "declared",
                            }
                        }
                    }
                },
            },
            "must declare at least one bound",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "arguments": {
                            "opaque": {
                                "authority": "locked",
                                "evidence": "declared",
                                "typo": True,
                            }
                        }
                    }
                },
            },
            "unknown field",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "arguments": {
                            "opaque": {
                                "authority": "constrained",
                                "evidence": "declared",
                                "bounds": [
                                    {
                                        "source": "future limit",
                                        "bounds_mutability": "trusted_party",
                                        "operational_status": "planned",
                                    }
                                ],
                            }
                        }
                    }
                },
            },
            "operational_status",
        ),
    ],
)
def test_rejects_invalid_control_declarations(controls, message):
    document = {
        "tools": [
            {
                "name": "create_record",
                "inputSchema": {"properties": {"opaque": {"type": "object"}}},
            }
        ]
    }

    with pytest.raises(SchemaError, match=message):
        scan_documents([document], control_declarations=controls)


def test_cli_accepts_a_separate_control_declaration_file(tmp_path):
    schema_path = tmp_path / "tools.json"
    controls_path = tmp_path / "controls.json"
    report_path = tmp_path / "report.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "search_records",
                        "inputSchema": {
                            "properties": {"query": {"type": "string"}}
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    controls_path.write_text(
        json.dumps(
            {
                "version": 1,
                "tools": {
                    "search_records": {
                        "arguments": {
                            "query": {"authority": "free", "evidence": "observed"}
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                str(schema_path),
                "--controls",
                str(controls_path),
                "--format",
                "json",
                "--output",
                str(report_path),
            ]
        )
        == 0
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["declared_controls"]["tools"][0]["arguments"][0][
        "authority"
    ] == "free"


def test_cli_writes_report_and_can_fail_on_review(tmp_path):
    schema_path = tmp_path / "tools.json"
    report_path = tmp_path / "report.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "create_record",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"opaque": {"type": "object"}},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            str(schema_path),
            "--format",
            "json",
            "--output",
            str(report_path),
            "--fail-on-review",
        ]
    )

    assert exit_code == 2
    assert json.loads(report_path.read_text(encoding="utf-8"))["summary"][
        "review_required"
    ] == 1


def test_cli_fail_on_review_checks_branch_debt_directly(tmp_path, monkeypatch):
    schema_path = tmp_path / "tools.json"
    report_path = tmp_path / "report.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "read_record",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    real_scan_documents = scanner.scan_documents

    def branch_debt_only(*args, **kwargs):
        report = real_scan_documents(*args, **kwargs)
        for field in (
            "review_required",
            "review_required_tools",
            "schema_review_required_tools",
            "risk_review_required_tools",
            "risk_conflicts",
            "annotation_conflicts",
        ):
            report["summary"][field] = 0
        report["summary"]["branch_risk_review_required_tools"] = 1
        return report

    monkeypatch.setattr(scanner, "scan_documents", branch_debt_only)

    assert (
        main(
            [
                str(schema_path),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--fail-on-review",
            ]
        )
        == 2
    )


@pytest.mark.parametrize(
    "input_schema",
    (
        {
            "$defs": {
                "input": {
                    "properties": {
                        "recipient": {"type": "string", "format": "email"}
                    }
                }
            },
            "$ref": "#/$defs/input",
        },
        {
            "properties": {},
            "allOf": [
                {
                    "properties": {
                        "recipient": {"type": "string", "format": "email"}
                    }
                }
            ],
        },
        {"properties": {}, "anyOf": [{"properties": {"recipient": {}}}]},
        {"properties": {}, "oneOf": [{"properties": {"recipient": {}}}]},
        {
            "properties": {"mode": {"type": "string"}},
            "if": {"properties": {"mode": {"const": "send"}}},
            "then": {"properties": {"recipient": {"format": "email"}}},
        },
        {
            "properties": {"mode": {"type": "string"}},
            "dependentSchemas": {
                "mode": {"properties": {"recipient": {"format": "email"}}}
            },
        },
        {
            "properties": {"mode": {"type": "string"}},
            "dependencies": {
                "mode": {"properties": {"recipient": {"format": "email"}}}
            },
        },
        {
            "properties": {"mode": {"type": "string"}},
            "dependentRequired": {"mode": ["recipient"]},
        },
        {"properties": {}, "required": ["recipient"]},
        {"properties": {}, "$dynamicRef": "#input"},
        {"properties": {}, "$recursiveRef": "#"},
        {
            "properties": {},
            "patternProperties": {
                "^recipient$": {"type": "string", "format": "email"}
            },
        },
        {"properties": {}, "additionalProperties": {"format": "email"}},
        {"properties": {}, "unevaluatedProperties": False},
        {"properties": {}, "propertyNames": {"pattern": "recipient"}},
        {
            "properties": {
                "recipients": {"type": "array", "items": {"format": "email"}}
            }
        },
        {
            "properties": {
                "recipients": {
                    "type": "array",
                    "contains": {"format": "email"},
                }
            }
        },
        {"properties": {}, "not": {"properties": {"recipient": {}}}},
        {
            "properties": {
                "payload": {
                    "type": "string",
                    "contentSchema": {"properties": {"recipient": {}}},
                }
            }
        },
        {
            "properties": {
                "tuple": {
                    "type": "array",
                    "prefixItems": [{"format": "email"}],
                }
            }
        },
        {"properties": {"recipient": True}},
        {"properties": {"recipient": False}},
    ),
    ids=(
        "local-ref",
        "all-of",
        "any-of",
        "one-of",
        "conditional",
        "dependent-schemas",
        "legacy-dependencies",
        "dependent-required",
        "required-property-not-modeled",
        "dynamic-ref",
        "recursive-ref",
        "pattern-properties",
        "additional-properties-schema",
        "unevaluated-properties",
        "property-names",
        "array-items",
        "array-contains",
        "not",
        "content-schema",
        "prefix-items",
        "boolean-true-property",
        "boolean-false-property",
    ),
)
def test_composed_or_unresolved_schemas_require_explicit_review(input_schema):
    report = scan_documents(
        [{"tools": [{"name": "send_message", "inputSchema": input_schema}]}]
    )

    assert report["tools"][0]["schema_review_required"] is True
    assert report["summary"]["schema_review_required_tools"] == 1


def test_simple_schema_and_enum_instance_values_do_not_require_schema_review():
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "set_mode",
                        "inputSchema": {
                            "type": "object",
                            "$defs": {
                                "unused": {
                                    "allOf": [{"properties": {"recipient": {}}}]
                                }
                            },
                            "properties": {
                                "mode": {
                                    "type": "object",
                                    "enum": [{"$ref": "instance-data-only"}],
                                }
                            },
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ]
    )

    assert report["tools"][0]["schema_review_required"] is False
    assert report["summary"]["schema_review_required_tools"] == 0


def test_multi_type_union_fails_closed_and_requires_schema_review(tmp_path):
    document = {
        "tools": [
            {
                "name": "pay_invoice",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "amount": {
                            "type": ["integer", "string"],
                            "maximum": 100,
                        }
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "pay_invoice": {
                "risk": {
                    "tier": "financial",
                    "evidence": "attested",
                    "effects": ["commits_funds"],
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]
    amount = tool["arguments"][0]
    assert tool["schema_review_required"] is True
    assert report["summary"]["schema_review_required_tools"] == 1
    assert amount["type"] == "json"
    assert amount["policy"] == "trusted_fixed"
    assert amount["review_required"] is True

    schema_path = tmp_path / "schema.json"
    controls_path = tmp_path / "controls.json"
    output_path = tmp_path / "report.json"
    schema_path.write_text(json.dumps(document), encoding="utf-8")
    controls_path.write_text(json.dumps(controls), encoding="utf-8")
    assert (
        main(
            [
                str(schema_path),
                "--controls",
                str(controls_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-review",
            ]
        )
        == 2
    )


@pytest.mark.parametrize(
    ("collision", "collision_schema"),
    (
        ("type", {"type": "string", "enum": ["notice"]}),
        ("enum", {"type": "string", "enum": ["notice"]}),
        ("required", {"type": "string"}),
        ("additionalProperties", False),
    ),
)
def test_direct_shape_keyword_collision_preserves_all_arguments_and_reviews(
    tmp_path, collision, collision_schema
):
    document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    collision: collision_schema,
                    "recipient": {"type": "string", "format": "email"},
                    "body": {"type": "string"},
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "send_message": {
                "risk": {
                    "tier": "write",
                    "evidence": "attested",
                    "effects": ["sends_message"],
                }
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]
    arguments = {argument["name"]: argument for argument in tool["arguments"]}
    assert set(arguments) == {collision, "recipient", "body"}
    assert arguments["recipient"]["policy"] == "trusted_fixed"
    assert tool["schema_review_required"] is True
    assert tool["schema_closes_unknown_arguments"] is False
    assert report["summary"]["schema_review_required_tools"] == 1
    assert report["summary"]["risk_review_required_tools"] == 0

    schema_path = tmp_path / "schema.json"
    controls_path = tmp_path / "controls.json"
    output_path = tmp_path / "report.json"
    schema_path.write_text(json.dumps(document), encoding="utf-8")
    controls_path.write_text(json.dumps(controls), encoding="utf-8")
    assert (
        main(
            [
                str(schema_path),
                "--controls",
                str(controls_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-review",
            ]
        )
        == 2
    )


@pytest.mark.parametrize(
    "recipient_schema",
    ({"type": "string", "format": "email"}, True, False),
)
def test_properties_keyword_collision_cannot_produce_a_clean_empty_audit(
    recipient_schema,
):
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "send_message",
                        "inputSchema": {
                            "properties": {},
                            "recipient": recipient_schema,
                            "body": {"type": "string"},
                        },
                    }
                ]
            }
        ]
    )

    assert report["tools"][0]["arguments"] == []
    assert report["tools"][0]["schema_review_required"] is True
    assert report["summary"]["schema_review_required_tools"] == 1


def test_boolean_additional_properties_are_handled_by_schema_closure():
    reports = [
        scan_documents(
            [
                {
                    "tools": [
                        {
                            "name": f"tool_{str(value).lower()}",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                                "additionalProperties": value,
                            },
                        }
                    ]
                }
            ]
        )
        for value in (False, True)
    ]

    assert [
        report["tools"][0]["schema_review_required"] for report in reports
    ] == [False, False]
    assert [
        report["tools"][0]["schema_closes_unknown_arguments"]
        for report in reports
    ] == [True, False]


@pytest.mark.parametrize(
    "ambiguous_schema",
    (
        {"properties": {}},
        {"properties": {}, "type": {}},
        {"properties": {}, "enum": []},
        {"properties": {}, "const": None},
        {"properties": {}, "additionalProperties": False},
        {"properties": {}, "patternProperties": {}},
        {"properties": {}, "description": "looks like a wrapper"},
        {
            "properties": {},
            "type": {},
            "additionalProperties": False,
            "description": "combined ambiguity",
        },
    ),
)
def test_properties_without_unambiguous_object_type_always_require_review(
    ambiguous_schema,
):
    report = scan_documents(
        [{"tools": [{"name": "send_message", "inputSchema": ambiguous_schema}]}]
    )

    assert report["tools"][0]["schema_review_required"] is True
    assert report["summary"]["schema_review_required_tools"] == 1


def test_ambiguous_properties_root_preserves_inner_arguments_and_fails_cli_review(
    tmp_path,
):
    document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "properties": {"recipient": {"type": "string"}}
                },
            }
        ]
    }
    report = scan_documents([document])
    assert [argument["name"] for argument in report["tools"][0]["arguments"]] == [
        "recipient"
    ]
    assert report["tools"][0]["schema_review_required"] is True

    schema_path = tmp_path / "ambiguous.json"
    output_path = tmp_path / "report.json"
    schema_path.write_text(json.dumps(document), encoding="utf-8")
    assert main(
        [
            str(schema_path),
            "--format",
            "json",
            "--output",
            str(output_path),
            "--fail-on-review",
        ]
    ) == 2


def test_cli_fail_on_review_rejects_hidden_authority_in_local_ref(tmp_path):
    schema_path = tmp_path / "tools.json"
    report_path = tmp_path / "report.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "send_message",
                        "inputSchema": {
                            "$defs": {
                                "input": {
                                    "properties": {
                                        "recipient": {
                                            "type": "string",
                                            "format": "email",
                                        }
                                    }
                                }
                            },
                            "$ref": "#/$defs/input",
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                str(schema_path),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--fail-on-review",
            ]
        )
        == 2
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["schema_review_required_tools"] == 1
    assert report["tools"][0]["arguments"] == []


def test_cli_fail_on_review_rejects_required_name_missing_from_properties(tmp_path):
    schema_path = tmp_path / "tools.json"
    report_path = tmp_path / "report.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "send_message",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "required": ["recipient"],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                str(schema_path),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--fail-on-review",
            ]
        )
        == 2
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["summary"]["schema_review_required_tools"] == 1
    assert report["tools"][0]["arguments"] == []


def test_cli_loads_schema_paths_lazily_under_the_aggregate_budget(
    tmp_path, monkeypatch
):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "read_record",
                        "description": "x" * 3_500,
                        "inputSchema": {"properties": {}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    original_loader = scanner.load_json_path
    load_count = 0

    def counted_loader(path, *, allow_stdin=False, _input_budget=None):
        nonlocal load_count
        load_count += 1
        return original_loader(
            path,
            allow_stdin=allow_stdin,
            _input_budget=_input_budget,
        )

    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_MATERIAL_BYTES", 4_096)
    monkeypatch.setattr(scanner, "load_json_path", counted_loader)

    with pytest.raises(SystemExit) as exc_info:
        main([str(schema_path)] * 80 + ["--format", "json"])

    assert exc_info.value.code == 2
    assert 1 <= load_count <= 2


def test_cli_caps_actual_aggregate_utf8_bytes_across_whitespace_documents(
    tmp_path, monkeypatch
):
    schema_path = tmp_path / "schema.json"
    schema_path.write_text(
        " " * 80
        + json.dumps(
            {
                "tools": [
                    {
                        "name": "read_record",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(scanner, "MAX_SCAN_TOTAL_INPUT_BYTES", 250)

    with pytest.raises(SystemExit) as exc_info:
        main([str(schema_path), str(schema_path), "--format", "json"])

    assert exc_info.value.code == 2


def test_cli_aggregate_budget_counts_raw_crlf_bytes(tmp_path, monkeypatch):
    schema_path = tmp_path / "schema.json"
    document = json.dumps(
        {
            "tools": [
                {
                    "name": "read_record",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        }
    ).encode("utf-8")
    raw_document = (b"\r\n" * 64) + document
    normalized_size = len(raw_document.replace(b"\r\n", b"\n"))
    schema_path.write_bytes(raw_document)
    monkeypatch.setattr(
        scanner, "MAX_SCAN_TOTAL_INPUT_BYTES", normalized_size * 2
    )

    with pytest.raises(SystemExit) as exc_info:
        main([str(schema_path), str(schema_path), "--format", "json"])

    assert exc_info.value.code == 2


def test_cli_document_limit_is_shared_by_controls_and_lazy_schema_loads(
    tmp_path, monkeypatch
):
    schema_path = tmp_path / "schema.json"
    controls_path = tmp_path / "controls.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "read_record",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    controls_path.write_text("{}", encoding="utf-8")
    monkeypatch.setattr(scanner, "MAX_SCAN_SCHEMA_DOCUMENTS", 2)

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(schema_path),
                str(schema_path),
                "--controls",
                str(controls_path),
            ]
        )

    assert exc_info.value.code == 2


def test_cli_aggregate_byte_limit_includes_stdin(monkeypatch):
    document = json.dumps(
        {
            "tools": [
                {
                    "name": "read_record",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        }
    )
    monkeypatch.setattr(scanner, "MAX_SCAN_TOTAL_INPUT_BYTES", len(document) - 1)
    monkeypatch.setattr(scanner.sys, "stdin", io.StringIO(document))

    with pytest.raises(SystemExit) as exc_info:
        main(["-", "--format", "json"])

    assert exc_info.value.code == 2


def test_cli_prefers_raw_binary_stdin_for_aggregate_budget(monkeypatch):
    document = json.dumps(
        {
            "tools": [
                {
                    "name": "read_record",
                    "inputSchema": {"type": "object", "properties": {}},
                }
            ]
        }
    ).encode("utf-8")
    raw_document = (b"\r\n" * 32) + document

    class BinaryBackedStdin:
        buffer = io.BytesIO(raw_document)

        def read(self, _size=-1):
            raise AssertionError("text stdin must not be used when .buffer exists")

    monkeypatch.setattr(scanner, "MAX_SCAN_TOTAL_INPUT_BYTES", len(raw_document) - 1)
    monkeypatch.setattr(scanner.sys, "stdin", BinaryBackedStdin())

    with pytest.raises(SystemExit) as exc_info:
        main(["-", "--format", "json"])

    assert exc_info.value.code == 2


def test_rejects_duplicate_exact_control_bounds():
    document = {
        "tools": [
            {
                "name": "send",
                "inputSchema": {
                    "properties": {"recipient": {"type": "string"}}
                },
            }
        ]
    }
    bound = {
        "source": "approved contacts",
        "bounds_mutability": "trusted_party",
        "operational_status": "enforced",
        "enforcement": "resolver lookup",
    }
    controls = {
        "version": 1,
        "tools": {
            "send": {
                "arguments": {
                    "recipient": {
                        "authority": "constrained",
                        "evidence": "declared",
                        "bounds": [bound, dict(bound)],
                    }
                }
            }
        },
    }

    with pytest.raises(SchemaError, match="duplicate bound"):
        scan_documents([document], control_declarations=controls)


def test_demo_remains_default_and_unknown_arguments_are_rejected(capsys):
    assert verb_authority.main([]) == 0
    assert "attack send_email" in capsys.readouterr().out

    assert verb_authority.main(["unknown"]) == 2
    assert "usage:" in capsys.readouterr().err


def test_quickstart_demo_connects_schema_report_to_gate(capsys):
    assert verb_authority.main(["quickstart"]) == 0

    output = capsys.readouterr().out
    assert "SCHEMA -> AUTHORITY -> GATE" in output
    assert "send_email.to    -> trusted_fixed" in output
    assert "send_email.body  -> outbound_payload" in output
    assert "BLOCKED - param 'to' is a locked sink" in output
    assert "ALLOWED - within authority" in output
    assert output.count("local tool invocations=0") == 2
    assert output.count("local tool invocations=1") == 1
    assert "body length=2001; registered maxLength=2000" in output
    assert "BLOCKED - param 'body' failed its type/bounds check" in output
    assert "CONTROL: APPLICATION-SUPPLIED TRUSTED RECIPIENT" in output
    assert "APPROVED DESTINATION" not in output
    assert "never sends email" in output

    assert verb_authority.main(["quickstart", "extra"]) == 2
    assert "verb_authority quickstart" in capsys.readouterr().err


def test_rejects_documents_without_tools():
    with pytest.raises(SchemaError, match="no recognizable"):
        parse_tool_definitions({"not_tools": []})


def _playwright_browser_tabs_fixture():
    root = (
        Path(__file__).parent
        / "fixtures"
        / "external"
        / "sankalp-gilda"
        / "playwright-browser-tabs"
    )
    frozen = root / "frozen"
    if not frozen.is_dir():
        pytest.skip("external frozen evidence is repository-only")
    return root, frozen


def _verify_playwright_browser_tabs_frozen_inputs(frozen, expected):
    integrity = expected["frozen_integrity"]
    manifest = frozen / "MANIFEST.sha256"
    assert manifest.is_file() and not manifest.is_symlink()
    assert hashlib.sha256(manifest.read_bytes()).hexdigest() == integrity[
        "manifest_sha256"
    ]
    commands = frozen / "COMMANDS.md"
    assert commands.is_file() and not commands.is_symlink()
    assert hashlib.sha256(commands.read_bytes()).hexdigest() == integrity[
        "commands_sha256"
    ]

    recorded = {}
    for line in manifest.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        digest, name = line.split(maxsplit=1)
        name = name.strip()
        path = PurePosixPath(name)
        assert not path.is_absolute() and len(path.parts) == 1
        assert name not in {".", ".."} and "\\" not in name
        assert name not in recorded, f"duplicate frozen manifest member: {name}"
        assert len(digest) == 64 and all(
            character in "0123456789abcdef" for character in digest
        )
        recorded[name] = digest

    assert list(recorded) == integrity["manifest_members"]
    for name, digest in recorded.items():
        member = frozen / name
        assert member.is_file() and not member.is_symlink()
        actual = hashlib.sha256(member.read_bytes()).hexdigest()
        assert actual == digest, f"{name} no longer matches the frozen manifest"

    assert (
        recorded["tools-list.json"]
        == "1e615213d0fcc71246febecd281ce85fb11fc8cce3e8f636d9fbc255021a2c44"
    )


def test_playwright_browser_tabs_frozen_inputs_are_unmodified():
    """The manifest is the fixture's own tripwire, so check it before using it.

    A regression case whose inputs drifted proves nothing about the release it
    names, and a drifted input fails in exactly the same way as a real
    regression. Reading the manifest first tells those two apart.
    """
    root, frozen = _playwright_browser_tabs_fixture()
    expected = json.loads((root / "EXPECTED.json").read_text(encoding="utf-8"))
    _verify_playwright_browser_tabs_frozen_inputs(frozen, expected)


@pytest.mark.parametrize(
    "member",
    ("../escape.json", "/absolute.json", "nested/file.json", "nested\\file.json"),
)
def test_playwright_frozen_manifest_rejects_unsafe_member_paths(tmp_path, member):
    frozen = tmp_path / "frozen"
    frozen.mkdir()
    commands = frozen / "COMMANDS.md"
    commands.write_bytes(b"")
    manifest = frozen / "MANIFEST.sha256"
    manifest.write_text(f"{'0' * 64}  {member}\n", encoding="utf-8")
    expected = {
        "frozen_integrity": {
            "manifest_sha256": hashlib.sha256(manifest.read_bytes()).hexdigest(),
            "commands_sha256": hashlib.sha256(commands.read_bytes()).hexdigest(),
            "manifest_members": [member],
        }
    }

    with pytest.raises(AssertionError):
        _verify_playwright_browser_tabs_frozen_inputs(frozen, expected)


def test_playwright_browser_tabs_external_regression():
    """Pin the two behaviours 0.10.0b11 established, on externally frozen bytes.

    Two arms, because one is ambiguous. With nothing declared every tool sits
    behind an unknown tier and requires confirmation, which is fail-safe and
    hides what the scanner concluded per argument. Declaring the tool a write
    removes that cover. A scanner that is correct and one that is merely
    fail-safe agree on arm 1 and differ on arm 2.
    """
    root, frozen = _playwright_browser_tabs_fixture()
    expected = json.loads((root / "EXPECTED.json").read_text(encoding="utf-8"))
    _verify_playwright_browser_tabs_frozen_inputs(frozen, expected)
    schema = json.loads((frozen / "tools-list.json").read_text(encoding="utf-8"))
    controls = json.loads((frozen / "controls.json").read_text(encoding="utf-8"))

    def subject(report):
        for tool in report["tools"]:
            if tool["name"] == expected["tool"]:
                return tool
        raise AssertionError(f"{expected['tool']} absent from the report")

    def arguments(tool):
        return {argument["name"]: argument for argument in tool["arguments"]}

    superseded = expected["superseded"]
    beta10_undeclared = json.loads(
        (frozen / "report-0.10.0b10-undeclared.json").read_text(encoding="utf-8")
    )
    beta10_declared = json.loads(
        (frozen / "report-0.10.0b10-declared-write.json").read_text(
            encoding="utf-8"
        )
    )
    assert beta10_undeclared["summary"]["annotation_conflicts"] == superseded[
        "undeclared_annotation_conflicts_total"
    ]
    assert beta10_declared["summary"]["annotation_conflicts"] == superseded[
        "declared_write_annotation_conflicts_total"
    ]
    beta10_arguments = arguments(subject(beta10_declared))
    for name, want in superseded["declared_write_arguments"].items():
        argument = beta10_arguments[name]
        assert argument["policy"] == want["policy"], name
        assert argument["review_required"] is want["review_required"], name
        assert argument["confidence"] == want["confidence"], name

    undeclared = scan_documents([schema])
    declared = scan_documents([schema], control_declarations=controls)

    # Arm 1. The count is the assertion: 23 of 23 tools reporting a conflict is
    # indistinguishable from none of them doing so, because a correct hint and a
    # wrong one produced the same string.
    assert (
        undeclared["summary"]["annotation_conflicts"]
        == expected["undeclared"]["annotation_conflicts_total"]
    )
    undeclared_arguments = arguments(subject(undeclared))
    for name, want in expected["undeclared"]["arguments"].items():
        assert undeclared_arguments[name]["policy"] == want["policy"]
        assert undeclared_arguments[name]["review_required"] is want["review_required"]

    # Arm 2. An argument whose value selects the operation must stay
    # consequential, whatever its type says.
    arm2 = expected["declared_write"]
    tool = subject(declared)
    assert declared["summary"]["annotation_conflicts"] == arm2["annotation_conflicts_total"]
    assert tool["annotation_conflicts"] == arm2["annotation_conflicts_on_subject"]
    assert tool["risk"] == arm2["risk"]
    assert tool["needs_confirmation"] is arm2["needs_confirmation"]

    states = {
        assessment["annotation"]: assessment["state"]
        for assessment in tool["annotation_assessments"]
    }
    assert states == arm2["annotation_states"]

    declared_arguments = arguments(tool)
    for name, want in arm2["arguments"].items():
        argument = declared_arguments[name]
        assert argument["policy"] == want["policy"], name
        assert argument["review_required"] is want["review_required"], name
        assert argument["confidence"] == want["confidence"], name

    # schema_review_required remains the narrow schema-structure source. Report
    # v5 also exposes one tool-wide aggregate and its complete source index.
    current = expected["current_report_v5"]
    assert declared["report_version"] == current["report_version"]
    assert declared["summary"]["review_required_tools"] == current[
        "summary_review_required_tools"
    ]
    assert tool["schema_review_required"] is current["schema_review_required"]
    assert tool["review_required"] is current["review_required"]
    assert tool["review_sources"] == current["review_sources"]

    # The process exit remains the CI enforcement path for any review source.
    assert scanner.main(
        [
            "--format",
            "json",
            "--controls",
            str(frozen / "controls.json"),
            "--fail-on-review",
            "--output",
            os.devnull,
            str(frozen / "tools-list.json"),
        ]
    ) == arm2["fail_on_review_exit_status"]

    # The one surviving conflict is this fixture's own under-declaration, not a
    # scanner defect. Declaring the tier the hint asserts clears it.
    probe_controls = json.loads(
        (root / "probe-controls-destructive.json").read_text(encoding="utf-8")
    )
    probe = scan_documents([schema], control_declarations=probe_controls)
    probe_expected = expected["declared_destructive_probe"]
    assert (
        probe["summary"]["annotation_conflicts"]
        == probe_expected["annotation_conflicts_total"]
    )
    assert {
        assessment["annotation"]: assessment["state"]
        for assessment in subject(probe)["annotation_assessments"]
    } == probe_expected["annotation_states"]
