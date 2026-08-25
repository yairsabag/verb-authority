import copy
import json
from pathlib import Path

import pytest

import verb_authority
import verb_authority_scan as scanner
from verb_authority_diff import (
    DIFF_VERSION,
    DiffError,
    diff_reports,
    load_report_or_schema,
    main,
    render_text,
)
from verb_authority_scan import load_json_path, scan_documents


FIXTURES = Path(__file__).parent / "fixtures"


def _avp9_report():
    schema = json.loads(
        (FIXTURES / "avp9_nexus_financial_tool.json").read_text(encoding="utf-8")
    )
    controls = json.loads(
        (FIXTURES / "avp9_nexus_financial_controls.json").read_text(
            encoding="utf-8"
        )
    )
    return scan_documents([schema], control_declarations=controls)


def _refresh_control_fingerprint(report):
    report["control_declaration_fingerprint_sha256"] = (
        scanner._control_declaration_fingerprint(report["declared_controls"])
    )


def _constraint_document(maximum, max_length, enum):
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


def _constraint_report(maximum, max_length, enum):
    return scan_documents([_constraint_document(maximum, max_length, enum)])


def _single_argument_report(property_schema):
    return scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "set_value",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"value": property_schema},
                        },
                    }
                ]
            }
        ]
    )


def test_identical_reports_have_no_authority_changes():
    report = _avp9_report()

    diff = diff_reports(report, copy.deepcopy(report))

    assert diff["summary"] == {
        "changes": 0,
        "changed_tools": 0,
        "authority_increases": 0,
        "reviews": 0,
        "protection_increases": 0,
    }
    assert "No authority-relevant changes detected" in render_text(diff)


def test_daybreak_constraint_widening_is_an_authority_increase():
    before = _constraint_report(100, 40, ["safe"])
    after = _constraint_report(10**12, 10**9, ["safe", "unrestricted"])

    diff = diff_reports(before, after)

    assert before["schema_fingerprint_sha256"] != after[
        "schema_fingerprint_sha256"
    ]
    assert DIFF_VERSION == 2
    assert diff["diff_version"] == 2
    assert diff["summary"] == {
        "changes": 3,
        "changed_tools": 1,
        "authority_increases": 3,
        "reviews": 0,
        "protection_increases": 0,
    }
    assert {change["kind"] for change in diff["changes"]} == {
        "maximum_changed",
        "max_length_changed",
        "enum_changed",
    }
    assert all(
        change["classification"] == "authority_increase"
        for change in diff["changes"]
    )


def test_cli_fails_on_simultaneous_constraint_widening(tmp_path):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(
        json.dumps(_constraint_document(100, 40, ["safe"])), encoding="utf-8"
    )
    after_path.write_text(
        json.dumps(
            _constraint_document(
                10**12,
                10**9,
                ["safe", "unrestricted"],
            )
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            str(before_path),
            str(after_path),
            "--format",
            "json",
            "--output",
            str(output_path),
            "--fail-on-increase",
        ]
    )

    assert exit_code == 2
    diff = json.loads(output_path.read_text(encoding="utf-8"))
    assert diff["summary"]["authority_increases"] == 3


def test_decimal_constraints_above_float_precision_are_lossless(tmp_path):
    before_path = tmp_path / "before-decimal.json"
    after_path = tmp_path / "after-decimal.json"
    output_path = tmp_path / "decimal-diff.json"
    before_path.write_text(
        '{"tools":[{"name":"set_policy","inputSchema":{"properties":'
        '{"amount":{"type":"number","maximum":9007199254740992.0},'
        '"mode":{"type":"number","enum":[9007199254740992.0]}}}}]}',
        encoding="utf-8",
    )
    after_path.write_text(
        '{"tools":[{"name":"set_policy","inputSchema":{"properties":'
        '{"amount":{"type":"number","maximum":9007199254740993.0},'
        '"mode":{"type":"number","enum":[9007199254740993.0]}}}}]}',
        encoding="utf-8",
    )

    before_report = scan_documents([load_json_path(str(before_path))])
    after_report = scan_documents([load_json_path(str(after_path))])
    before_arguments = {
        item["name"]: item for item in before_report["tools"][0]["arguments"]
    }
    after_arguments = {
        item["name"]: item for item in after_report["tools"][0]["arguments"]
    }

    assert before_arguments["amount"]["constraints"]["maximum"] == (
        "9007199254740992"
    )
    assert after_arguments["amount"]["constraints"]["maximum"] == (
        "9007199254740993"
    )
    assert before_arguments["mode"]["constraints"]["enum"] != (
        after_arguments["mode"]["constraints"]["enum"]
    )
    assert before_report["schema_fingerprint_sha256"] != (
        after_report["schema_fingerprint_sha256"]
    )

    assert (
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-increase",
            ]
        )
        == 2
    )
    assert (
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-review",
            ]
        )
        == 2
    )
    diff = json.loads(output_path.read_text(encoding="utf-8"))
    assert diff["summary"]["authority_increases"] == 1
    assert diff["summary"]["reviews"] == 1
    assert {change["kind"] for change in diff["changes"]} == {
        "maximum_changed",
        "enum_changed",
    }


def test_cli_can_fail_closed_on_unmodeled_schema_review(tmp_path):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "set_value",
                        "inputSchema": {
                            "properties": {
                                "value": {"type": "number", "minimum": 0}
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "set_value",
                        "inputSchema": {
                            "properties": {
                                "value": {
                                    "type": "number",
                                    "minimum": -(10**12),
                                }
                            }
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
                str(before_path),
                str(after_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-increase",
            ]
        )
        == 0
    )
    assert (
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-review",
            ]
        )
        == 2
    )
    diff = json.loads(output_path.read_text(encoding="utf-8"))
    assert diff["summary"]["authority_increases"] == 0
    assert diff["summary"]["reviews"] == 1
    assert diff["changes"][0]["kind"] == "unmodeled_schema_changed"


def test_constraint_tightening_is_a_protection_increase():
    before = _constraint_report(10**12, 10**9, ["safe", "unrestricted"])
    after = _constraint_report(100, 40, ["safe"])

    diff = diff_reports(before, after)

    assert diff["summary"]["protection_increases"] == 3
    assert diff["summary"]["authority_increases"] == 0
    assert all(
        change["classification"] == "protection_increase"
        for change in diff["changes"]
    )


def test_removing_schema_constraints_is_an_authority_increase():
    before_document = _constraint_document(100, 40, ["safe"])
    after_document = copy.deepcopy(before_document)
    properties = after_document["tools"][0]["inputSchema"]["properties"]
    properties["amount"].pop("maximum")
    properties["message"].pop("maxLength")
    properties["mode"].pop("enum")

    diff = diff_reports(
        scan_documents([before_document]), scan_documents([after_document])
    )

    assert diff["summary"]["authority_increases"] == 3
    assert diff["summary"]["reviews"] == 2
    assert any(
        change["kind"] == "type_changed"
        and change["classification"] == "review"
        for change in diff["changes"]
    )


def test_enum_replacement_without_set_relationship_requires_review():
    before = _constraint_report(100, 40, ["safe", "legacy"])
    after = _constraint_report(100, 40, ["safe", "reviewed"])

    diff = diff_reports(before, after)

    assert diff["summary"]["reviews"] == 1
    assert diff["summary"]["authority_increases"] == 0
    assert diff["changes"][0]["kind"] == "enum_changed"
    assert diff["changes"][0]["classification"] == "review"


def test_legacy_v2_reports_require_rescanning_instead_of_lossy_migration():
    legacy = _constraint_report(100, 40, ["safe"])
    legacy["report_version"] = 2
    for argument in legacy["tools"][0]["arguments"]:
        argument.pop("constraints", None)

    with pytest.raises(DiffError, match="legacy report version 2.*rescan"):
        diff_reports(legacy, copy.deepcopy(legacy))


def test_malformed_v3_constraint_metadata_is_rejected():
    report = _constraint_report(100, 40, ["safe"])
    mode = next(
        argument
        for argument in report["tools"][0]["arguments"]
        if argument["name"] == "mode"
    )
    mode["constraints"]["enum"]["count"] = 2

    with pytest.raises(DiffError, match="enum constraint is invalid"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    "before_schema, after_schema",
    [
        (False, True),
        (
            {"allOf": [{"type": "number", "maximum": 100}]},
            {"allOf": [{"type": "number", "maximum": 10**12}]},
        ),
        (
            {"type": "number", "minimum": 0},
            {"type": "number", "minimum": -(10**12)},
        ),
        (
            {
                "type": "object",
                "properties": {
                    "recipient": {"type": "string", "enum": ["approved"]}
                },
                "additionalProperties": False,
            },
            {
                "type": "object",
                "properties": {
                    "recipient": {
                        "type": "string",
                        "enum": ["approved", "attacker"],
                    }
                },
                "additionalProperties": True,
            },
        ),
    ],
    ids=("boolean-schema", "all-of", "minimum", "nested-object"),
)
def test_unmodeled_schema_widening_requires_exactly_one_review(
    before_schema, after_schema
):
    before = _single_argument_report(before_schema)
    after = _single_argument_report(after_schema)

    diff = diff_reports(before, after)

    assert before["schema_fingerprint_sha256"] != after[
        "schema_fingerprint_sha256"
    ]
    assert diff["summary"] == {
        "changes": 1,
        "changed_tools": 1,
        "authority_increases": 0,
        "reviews": 1,
        "protection_increases": 0,
    }
    assert diff["changes"][0]["kind"] == "unmodeled_schema_changed"
    assert diff["changes"][0]["argument"] == "value"
    assert diff["changes"][0]["classification"] == "review"


def test_modeled_and_unmodeled_changes_each_emit_one_classification():
    before = _single_argument_report(
        {"type": "number", "maximum": 100, "minimum": 0}
    )
    after = _single_argument_report(
        {"type": "number", "maximum": 10**12, "minimum": -(10**12)}
    )

    diff = diff_reports(before, after)

    assert diff["summary"]["authority_increases"] == 1
    assert diff["summary"]["reviews"] == 1
    assert [change["kind"] for change in diff["changes"]].count(
        "unmodeled_schema_changed"
    ) == 1
    assert [change["kind"] for change in diff["changes"]].count(
        "maximum_changed"
    ) == 1


def test_annotation_only_changes_do_not_create_schema_drift_noise():
    before = _single_argument_report(
        {"type": "number", "maximum": 100, "description": "old text"}
    )
    after = _single_argument_report(
        {"type": "number", "maximum": 100, "description": "new text"}
    )

    diff = diff_reports(before, after)

    assert before["schema_fingerprint_sha256"] == after[
        "schema_fingerprint_sha256"
    ]
    assert diff["summary"]["changes"] == 0


def test_annotation_named_data_inside_unknown_keyword_is_fingerprinted():
    before = _single_argument_report(
        {
            "type": "object",
            "discriminator": {"mapping": {"default": "#/A"}},
        }
    )
    after = _single_argument_report(
        {
            "type": "object",
            "discriminator": {"mapping": {"default": "#/B"}},
        }
    )

    diff = diff_reports(before, after)

    assert before["schema_fingerprint_sha256"] != after[
        "schema_fingerprint_sha256"
    ]
    assert diff["summary"]["reviews"] == 1
    assert diff["changes"][0]["kind"] == "unmodeled_schema_changed"


def test_duplicate_argument_names_are_rejected_before_indexing():
    before = _single_argument_report({"type": "number", "maximum": 100})
    after = copy.deepcopy(before)
    widened = copy.deepcopy(after["tools"][0]["arguments"][0])
    widened["constraints"]["maximum"] = 10**12
    after["tools"][0]["arguments"].insert(0, widened)

    with pytest.raises(DiffError, match="duplicate argument name"):
        diff_reports(before, after)


@pytest.mark.parametrize("malformation", ("tool", "arguments", "argument"))
def test_malformed_report_containers_raise_clean_diff_errors(malformation):
    before = _single_argument_report({"type": "number", "maximum": 100})
    after = copy.deepcopy(before)
    if malformation == "tool":
        after["tools"] = ["not-an-object"]
    elif malformation == "arguments":
        after["tools"][0]["arguments"] = {"value": {}}
    else:
        after["tools"][0]["arguments"] = ["not-an-object"]

    with pytest.raises(DiffError):
        diff_reports(before, after)


def test_diff_reports_rejects_over_budget_report_before_indexing(monkeypatch):
    report = _single_argument_report({"type": "number", "maximum": 100})
    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_NODES", 10)

    with pytest.raises(DiffError, match="total node limit"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize("output_format", ("text", "json"))
def test_diff_cli_rejects_over_budget_report_without_traceback(
    tmp_path, capsys, monkeypatch, output_format
):
    report = _single_argument_report({"type": "number", "maximum": 100})
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(report), encoding="utf-8")
    after_path.write_text(json.dumps(report), encoding="utf-8")
    monkeypatch.setattr(scanner, "MAX_SCAN_JSON_NODES", 10)

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                output_format,
            ]
        )

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "total node limit" in error
    assert "Traceback" not in error


def test_invalid_schema_fingerprint_is_rejected():
    report = _single_argument_report({"type": "number", "maximum": 100})
    report["tools"][0]["unmodeled_schema_fingerprint_sha256"] = "not-a-hash"

    with pytest.raises(DiffError, match="lowercase SHA-256"):
        diff_reports(report, copy.deepcopy(report))


def test_duplicate_declared_control_tools_are_rejected():
    report = _avp9_report()
    report["declared_controls"]["tools"].append(
        copy.deepcopy(report["declared_controls"]["tools"][0])
    )

    with pytest.raises(DiffError, match="duplicate tool name"):
        diff_reports(report, copy.deepcopy(report))


def test_duplicate_declared_control_arguments_are_rejected():
    report = _avp9_report()
    arguments = report["declared_controls"]["tools"][0]["arguments"]
    arguments.append(copy.deepcopy(arguments[0]))

    with pytest.raises(DiffError, match="duplicate argument name"):
        diff_reports(report, copy.deepcopy(report))


def test_duplicate_unexposed_control_arguments_are_rejected():
    report = _avp9_report()
    arguments = report["declared_controls"]["tools"][0]["unexposed_arguments"]
    arguments.append(copy.deepcopy(arguments[0]))

    with pytest.raises(DiffError, match="duplicate argument name"):
        diff_reports(report, copy.deepcopy(report))


def test_control_declaration_fingerprint_is_recomputed_before_diffing():
    report = _avp9_report()
    report["control_declaration_fingerprint_sha256"] = "0" * 64

    with pytest.raises(DiffError, match="fingerprint does not match"):
        diff_reports(report, copy.deepcopy(report))


def test_duplicated_declared_risk_must_match_the_report_tool():
    report = _avp9_report()
    report["declared_controls"]["tools"][0]["risk"]["effects"].append(
        "different_effect"
    )
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="risk conflicts with the report tool"):
        diff_reports(report, copy.deepcopy(report))


def test_declared_risk_cannot_outlive_its_declared_control_tool():
    report = _avp9_report()
    report["declared_controls"]["tools"] = []
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="declared risk without the matching"):
        diff_reports(report, copy.deepcopy(report))


def test_duplicated_schema_closure_must_match_the_report_tool():
    report = _avp9_report()
    declared_tool = report["declared_controls"]["tools"][0]
    declared_tool["schema_closes_unknown_arguments"] = not declared_tool[
        "schema_closes_unknown_arguments"
    ]
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="schema closure conflicts"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    "field,value,message",
    (
        ("inferred_policy", "typed_bounded", "inferred policy conflicts"),
        ("review_required", None, "review requirement conflicts"),
    ),
)
def test_duplicated_declared_argument_analysis_must_match_report(
    field, value, message
):
    report = _avp9_report()
    argument = next(
        item
        for item in report["declared_controls"]["tools"][0]["arguments"]
        if item["name"] == "bidWei"
    )
    if field == "review_required":
        value = not argument[field]
    argument[field] = value
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match=message):
        diff_reports(report, copy.deepcopy(report))


def test_cli_rejects_malformed_report_with_exit_two(tmp_path, capsys):
    before = _single_argument_report({"type": "number", "maximum": 100})
    after = copy.deepcopy(before)
    after["tools"][0]["arguments"].append(
        copy.deepcopy(after["tools"][0]["arguments"][0])
    )
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main([str(before_path), str(after_path)])

    assert exc_info.value.code == 2
    stderr = capsys.readouterr().err
    assert "duplicate argument name" in stderr
    assert "Traceback" not in stderr


def _replace_with_invalid_generator_raw_shape(report):
    report.clear()
    report.update(
        {
            "generator": "not-verb-authority",
            "tools": [{"name": "set_value", "inputSchema": {}}],
        }
    )


def _strip_report_header_but_keep_report_tool_markers(report):
    tools = report["tools"]
    report.clear()
    report.update({"tools": tools, "inputSchema": {}})


@pytest.mark.parametrize(
    "mutation, message",
    [
        (lambda report: report.pop("generator"), "report-shaped"),
        (
            lambda report: (
                report.pop("report_version"),
                report.update({"inputSchema": {}}),
            ),
            "unsupported report version",
        ),
        (lambda report: report.update({"report_version": 2}), "legacy report"),
        (_replace_with_invalid_generator_raw_shape, "report-shaped"),
        (_strip_report_header_but_keep_report_tool_markers, "report-shaped"),
    ],
    ids=(
        "missing-generator",
        "missing-version-hybrid",
        "legacy-v2",
        "invalid-generator-only",
        "nested-report-tool-markers",
    ),
)
def test_report_shaped_inputs_never_fall_through_to_raw_scanning(
    tmp_path, mutation, message
):
    report = _single_argument_report({"type": "number", "maximum": 100})
    mutation(report)
    path = tmp_path / "report-shaped.json"
    path.write_text(json.dumps(report), encoding="utf-8")

    with pytest.raises(DiffError, match=message):
        load_report_or_schema(str(path), label="candidate")


def _wrap_report_tool(wrapper, tool):
    wrappers = {
        "direct-tool": tool,
        "top-level-list": [tool],
        "tools-envelope": {"tools": [tool]},
        "mcp-result": {"result": {"tools": [tool]}},
        "atlas-sources": {"sources": [{"id": "source", "tools": [tool]}]},
        "functions-envelope": {"functions": [tool]},
        "openai-function": {
            "tools": [{"type": "function", "function": tool}]
        },
    }
    return wrappers[wrapper]


@pytest.mark.parametrize(
    "wrapper",
    (
        "direct-tool",
        "top-level-list",
        "tools-envelope",
        "mcp-result",
        "atlas-sources",
        "functions-envelope",
        "openai-function",
    ),
)
@pytest.mark.parametrize("failure_flag", ("--fail-on-increase", "--fail-on-review"))
def test_report_tool_sentinels_are_rejected_in_every_supported_envelope(
    tmp_path, capsys, wrapper, failure_flag
):
    before_document = {
        "tools": [
            {
                "name": "set_value",
                "inputSchema": {
                    "properties": {
                        "recipient": {"type": "string", "format": "email"}
                    }
                },
            }
        ]
    }
    report = scan_documents([before_document])
    candidate = _wrap_report_tool(wrapper, copy.deepcopy(report["tools"][0]))
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before_document), encoding="utf-8")
    after_path.write_text(json.dumps(candidate), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main([str(before_path), str(after_path), failure_flag])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "report-shaped" in error
    assert "Traceback" not in error


@pytest.mark.parametrize("output_format", ("text", "json"))
def test_cli_rejects_unknown_nested_report_number_without_traceback(
    tmp_path, capsys, output_format
):
    before = _single_argument_report({"type": "number", "maximum": 100})
    after = copy.deepcopy(before)
    after["tools"][0]["risk_inference"]["extra_score"] = 1.5
    before_path = tmp_path / "before-report.json"
    after_path = tmp_path / "after-report.json"
    output_path = tmp_path / "diff-output"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                output_format,
                "--output",
                str(output_path),
            ]
        )

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "unsupported fields: extra_score" in error
    assert "Traceback" not in error


@pytest.mark.parametrize(
    "mutation",
    (
        lambda report: report["tools"][0]["declared_risk"].update(
            {"extra_score": 1.5}
        ),
        lambda report: next(
            argument
            for argument in report["declared_controls"]["tools"][0]["arguments"]
            if argument["name"] == "bidWei"
        )["bounds"][0].update({"extra_score": 1.5}),
        lambda report: report["declared_controls"]["tools"][0].update(
            {"extra_score": 1.5}
        ),
    ),
    ids=("declared-risk", "declared-bound", "declared-tool"),
)
def test_unknown_declared_control_fields_are_rejected(mutation):
    report = _avp9_report()
    mutation(report)

    with pytest.raises(DiffError, match="unsupported fields: extra_score"):
        diff_reports(report, copy.deepcopy(report))


def test_diff_cli_rejects_overdeep_raw_schema_without_traceback(tmp_path, capsys):
    nested = {"type": "string"}
    for _ in range(140):
        nested = {"allOf": [nested]}
    document = {
        "tools": [
            {
                "name": "set_value",
                "inputSchema": {"properties": {"value": nested}},
            }
        ]
    }
    before_path = tmp_path / "deep-before.json"
    after_path = tmp_path / "deep-after.json"
    before_path.write_text(json.dumps(document), encoding="utf-8")
    after_path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main([str(before_path), str(after_path)])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "maximum nesting depth" in error
    assert "Traceback" not in error


def test_text_diff_escapes_terminal_and_bidi_controls():
    before = _constraint_report(100, 40, ["safe"])
    after = _constraint_report(200, 40, ["safe"])
    hostile = "tool\r\x1b[31m\u202e\u2028\u2029"
    hostile_argument = "amount\r\x1b\u202e\u2028\u2029"
    hostile_type = "number\r\x1b\u202e\u2028\u2029"
    for report in (before, after):
        report["tools"][0]["name"] = hostile
        amount = next(
            argument
            for argument in report["tools"][0]["arguments"]
            if argument["name"] == "amount"
        )
        amount["name"] = hostile_argument
    next(
        argument
        for argument in after["tools"][0]["arguments"]
        if argument["name"] == hostile_argument
    )["type"] = hostile_type

    rendered = render_text(diff_reports(before, after))

    assert "\r" not in rendered
    assert "\x1b" not in rendered
    assert "\u202e" not in rendered
    assert "\u2028" not in rendered
    assert "\u2029" not in rendered
    assert "\\r" in rendered
    assert "\\u001b" in rendered
    assert "\\u202e" in rendered
    assert "\\u2028" in rendered
    assert "\\u2029" in rendered


def test_declared_risk_effect_change_requires_review():
    before = _avp9_report()
    after = copy.deepcopy(before)
    after["tools"][0]["declared_risk"]["effects"].append("pays_gas")
    after["declared_controls"]["tools"][0]["risk"]["effects"].append("pays_gas")
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    change = next(
        item for item in diff["changes"] if item["kind"] == "declared_risk_changed"
    )
    assert change["classification"] == "review"
    assert change["field"] == "declared_risk"


def test_new_risk_conflict_requires_review():
    before = _avp9_report()
    after = copy.deepcopy(before)
    after["tools"][0]["risk_conflict"] = True
    after["tools"][0]["risk_review_required"] = True

    diff = diff_reports(before, after)

    kinds = {item["kind"] for item in diff["changes"]}
    assert "risk_conflict_changed" in kinds
    assert "risk_review_required_changed" in kinds
    assert diff["summary"]["reviews"] == 2


def test_avp9_constrained_amount_becoming_free_is_an_authority_increase():
    before = _avp9_report()
    after = copy.deepcopy(before)
    arguments = after["declared_controls"]["tools"][0]["arguments"]
    bid = next(argument for argument in arguments if argument["name"] == "bidWei")
    bid["authority"] = "free"
    bid.pop("bounds")
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    changes = [
        change
        for change in diff["changes"]
        if change.get("argument") == "bidWei"
    ]
    assert diff["summary"]["authority_increases"] == 2
    assert {change["kind"] for change in changes} == {
        "declared_authority_changed",
        "bounds_changed",
    }
    assert all(change["classification"] == "authority_increase" for change in changes)


def test_server_fixed_argument_becoming_exposed_is_an_authority_increase():
    before = _avp9_report()
    after = copy.deepcopy(before)
    tool = after["tools"][0]
    destination_report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "replacement",
                        "inputSchema": {
                            "properties": {"destination": {"type": "string"}},
                            "required": ["destination"],
                        },
                    }
                ]
            }
        ]
    )
    destination_argument = destination_report["tools"][0]["arguments"][0]
    tool["arguments"].append(destination_argument)
    declared_tool = after["declared_controls"]["tools"][0]
    declared_tool["unexposed_arguments"] = []
    declared_tool["arguments"].append(
        {
            "name": "destination",
            "schema_exposure": "exposed",
            "inferred_policy": destination_argument["policy"],
            "review_required": destination_argument["review_required"],
            "authority": "locked",
            "evidence": "declared",
        }
    )
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    exposure = next(
        change
        for change in diff["changes"]
        if change.get("argument") == "destination"
    )
    assert exposure["kind"] == "argument_exposure_changed"
    assert exposure["classification"] == "authority_increase"
    assert exposure["before"] == "unexposed"
    assert exposure["after"] == "exposed"


@pytest.mark.parametrize(
    ("after_schema_extra", "classification"),
    [
        ({"additionalProperties": True}, "authority_increase"),
        ({"additionalProperties": False}, "protection_increase"),
        (
            {
                "additionalProperties": False,
                "$ref": "#/$defs/unresolved",
            },
            "review",
        ),
    ],
)
def test_exposed_to_declared_unexposed_respects_candidate_schema_closure(
    after_schema_extra,
    classification,
):
    before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}},
                    "additionalProperties": True,
                },
            }
        ]
    }
    before_controls = {
        "version": 1,
        "tools": {
            "send_message": {
                "arguments": {
                    "recipient": {
                        "authority": "locked",
                        "evidence": "declared",
                    }
                }
            }
        },
    }
    after_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    **after_schema_extra,
                },
            }
        ]
    }
    after_controls = {
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

    before = scan_documents(
        [before_document], control_declarations=before_controls
    )
    after = scan_documents([after_document], control_declarations=after_controls)
    diff = diff_reports(before, after)
    exposure = next(
        change
        for change in diff["changes"]
        if change["kind"] == "argument_exposure_changed"
    )

    assert exposure["classification"] == classification


def test_enforced_bound_becoming_caller_controlled_is_flagged():
    before = _avp9_report()
    after = copy.deepcopy(before)
    arguments = after["declared_controls"]["tools"][0]["arguments"]
    bid = next(argument for argument in arguments if argument["name"] == "bidWei")
    bid["bounds"][0]["bounds_mutability"] = "caller"
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "authority_increase"
    assert "currently enforced" in bound_change["message"]


def test_enforced_bound_becoming_specified_is_an_authority_increase():
    before = _avp9_report()
    after = copy.deepcopy(before)
    arguments = after["declared_controls"]["tools"][0]["arguments"]
    bid = next(argument for argument in arguments if argument["name"] == "bidWei")
    bid["bounds"][0]["operational_status"] = "specified"
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "authority_increase"


def test_specified_bound_becoming_enforced_is_a_protection_increase():
    before = _avp9_report()
    after = copy.deepcopy(before)
    arguments = after["declared_controls"]["tools"][0]["arguments"]
    bid = next(argument for argument in arguments if argument["name"] == "bidWei")
    bid["bounds"][-1]["operational_status"] = "enforced"
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "protection_increase"


def test_specified_bound_mutability_change_requires_review_but_does_not_fail():
    before = _avp9_report()
    after = copy.deepcopy(before)
    arguments = after["declared_controls"]["tools"][0]["arguments"]
    bid = next(argument for argument in arguments if argument["name"] == "bidWei")
    bid["bounds"][-1]["bounds_mutability"] = "caller"
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "review"
    assert diff["summary"]["authority_increases"] == 0


def test_more_caller_controlled_bounds_cannot_replace_one_immutable_bound(
    tmp_path,
):
    before = _avp9_report()
    before_bid = next(
        argument
        for argument in before["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    before_bid["bounds"] = [
        {
            "source": "immutable ceiling",
            "bounds_mutability": "immutable",
            "operational_status": "enforced",
            "enforcement": "constant check",
        }
    ]
    _refresh_control_fingerprint(before)

    after = copy.deepcopy(before)
    after_bid = next(
        argument
        for argument in after["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    after_bid["bounds"] = [
        {
            "source": "caller ceiling one",
            "bounds_mutability": "caller",
            "operational_status": "enforced",
            "enforcement": "request check",
        },
        {
            "source": "caller ceiling two",
            "bounds_mutability": "caller",
            "operational_status": "enforced",
            "enforcement": "request check",
        },
    ]
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "authority_increase"
    assert diff["summary"]["authority_increases"] == 1
    assert diff["summary"]["protection_increases"] == 0

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")
    assert (
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-increase",
                "--fail-on-review",
            ]
        )
        == 2
    )


@pytest.mark.parametrize("duplicate_side", ["before", "after"])
def test_legacy_duplicate_exact_bounds_require_review(duplicate_side):
    before = _avp9_report()
    after = copy.deepcopy(before)
    report = before if duplicate_side == "before" else after
    bid = next(
        argument
        for argument in report["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    bid["bounds"].append(copy.deepcopy(bid["bounds"][0]))
    _refresh_control_fingerprint(report)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "review"
    assert diff["summary"]["reviews"] == 1
    assert diff["summary"]["protection_increases"] == 0
    assert diff["summary"]["authority_increases"] == 0


def test_protective_addition_with_nonprotective_drift_requires_review():
    before = _avp9_report()
    before_bid = next(
        argument
        for argument in before["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    before_bid["bounds"] = [
        {
            "source": "absolute ceiling",
            "bounds_mutability": "immutable",
            "operational_status": "enforced",
            "enforcement": "constant check",
        }
    ]
    _refresh_control_fingerprint(before)

    after = copy.deepcopy(before)
    after_bid = next(
        argument
        for argument in after["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    after_bid["bounds"].extend(
        [
            {
                "source": "server budget",
                "bounds_mutability": "trusted_party",
                "operational_status": "enforced",
                "enforcement": "server check",
            },
            {
                "source": "request budget",
                "bounds_mutability": "caller",
                "operational_status": "enforced",
                "enforcement": "request check",
            },
        ]
    )
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "review"
    assert diff["summary"]["protection_increases"] == 0


def test_protective_addition_with_unchanged_nonprotective_bounds_is_protection():
    before = _avp9_report()
    before_bid = next(
        argument
        for argument in before["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    before_bid["bounds"] = [
        {
            "source": "absolute ceiling",
            "bounds_mutability": "immutable",
            "operational_status": "enforced",
            "enforcement": "constant check",
        },
        {
            "source": "request budget",
            "bounds_mutability": "caller",
            "operational_status": "enforced",
            "enforcement": "request check",
        },
    ]
    _refresh_control_fingerprint(before)

    after = copy.deepcopy(before)
    after_bid = next(
        argument
        for argument in after["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    after_bid["bounds"].append(
        {
            "source": "server budget",
            "bounds_mutability": "trusted_party",
            "operational_status": "enforced",
            "enforcement": "server check",
        }
    )
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "protection_increase"


def test_structured_mutability_upgrade_cannot_mask_specified_bound_drift():
    before = _avp9_report()
    before_bid = next(
        argument
        for argument in before["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    before_bid["bounds"] = [
        {
            "source": "server ceiling",
            "bounds_mutability": "trusted_party",
            "operational_status": "enforced",
            "enforcement": "server check",
        },
        {
            "source": "future contract ceiling",
            "bounds_mutability": "caller",
            "operational_status": "specified",
            "enforcement": "contract revision",
        },
    ]
    _refresh_control_fingerprint(before)

    after = copy.deepcopy(before)
    after_bid = next(
        argument
        for argument in after["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    after_bid["bounds"][0]["bounds_mutability"] = "immutable"
    after_bid["bounds"][1]["source"] = "different future ceiling"
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "review"
    assert diff["summary"]["protection_increases"] == 0


def test_specified_activation_with_mutability_downgrade_requires_review():
    before = _avp9_report()
    before_bid = next(
        argument
        for argument in before["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    before_bid["bounds"] = [
        {
            "source": "contract ceiling",
            "bounds_mutability": "immutable",
            "operational_status": "specified",
            "enforcement": "contract check",
        }
    ]
    _refresh_control_fingerprint(before)

    after = copy.deepcopy(before)
    after_bid = next(
        argument
        for argument in after["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    after_bid["bounds"][0]["operational_status"] = "enforced"
    after_bid["bounds"][0]["bounds_mutability"] = "trusted_party"
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "review"
    assert diff["summary"]["protection_increases"] == 0


@pytest.mark.parametrize("downgrade", ["mutability", "operational_status"])
def test_unrelated_protective_addition_cannot_mask_known_bound_downgrade(
    downgrade,
):
    before = _avp9_report()
    before_bid = next(
        argument
        for argument in before["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    before_bid["bounds"] = [
        {
            "source": "absolute ceiling",
            "bounds_mutability": "immutable",
            "operational_status": "enforced",
            "enforcement": "constant check",
        }
    ]
    _refresh_control_fingerprint(before)

    after = copy.deepcopy(before)
    after_bid = next(
        argument
        for argument in after["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    if downgrade == "mutability":
        after_bid["bounds"][0]["bounds_mutability"] = "trusted_party"
    else:
        after_bid["bounds"][0]["operational_status"] = "specified"
    after_bid["bounds"].append(
        {
            "source": "different immutable budget",
            "bounds_mutability": "immutable",
            "operational_status": "enforced",
            "enforcement": "separate constant check",
        }
    )
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "authority_increase"
    assert diff["summary"]["authority_increases"] == 1


def test_enforced_protective_bound_replacement_requires_review_and_fails_ci(
    tmp_path,
):
    before = _avp9_report()
    after = copy.deepcopy(before)
    bid = next(
        argument
        for argument in after["declared_controls"]["tools"][0]["arguments"]
        if argument["name"] == "bidWei"
    )
    bid["bounds"][0]["source"] = "replacement ceiling 1000000000"
    bid["bounds"][0]["enforcement"] = "replacement maximum check"
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "review"
    assert diff["summary"]["protection_increases"] == 0

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")
    assert main(
        [
            str(before_path),
            str(after_path),
            "--format",
            "json",
            "--output",
            str(output_path),
            "--fail-on-increase",
            "--fail-on-review",
        ]
    ) == 2


@pytest.mark.parametrize(
    ("before_mutability", "after_mutability", "classification"),
    [
        ("immutable", "trusted_party", "authority_increase"),
        ("trusted_party", "immutable", "protection_increase"),
    ],
)
def test_same_enforced_bound_orders_structured_mutability_changes(
    before_mutability,
    after_mutability,
    classification,
):
    before = _avp9_report()
    after = copy.deepcopy(before)
    for report, mutability in (
        (before, before_mutability),
        (after, after_mutability),
    ):
        bid = next(
            argument
            for argument in report["declared_controls"]["tools"][0]["arguments"]
            if argument["name"] == "bidWei"
        )
        bid["bounds"][0]["bounds_mutability"] = mutability
        _refresh_control_fingerprint(report)

    diff = diff_reports(before, after)
    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == classification


def test_new_tool_and_removed_confirmation_fail_the_ci_threshold():
    pay_tool = {
        "name": "pay_invoice",
        "inputSchema": {"properties": {"amount": {"type": "integer"}}},
    }
    before = scan_documents([{"tools": [pay_tool]}])
    after = scan_documents(
        [
            {
                "tools": [
                    pay_tool,
                    {
                        "name": "send_message",
                        "inputSchema": {"properties": {}},
                    },
                ]
            }
        ]
    )
    after["tools"][0]["needs_confirmation"] = False

    diff = diff_reports(before, after)

    assert diff["summary"]["authority_increases"] == 2
    assert {change["kind"] for change in diff["changes"]} == {
        "confirmation_changed",
        "tool_added",
    }


def test_opening_additional_properties_is_an_authority_increase():
    closed = {
        "tools": [
            {
                "name": "purchase_bid",
                "inputSchema": {
                    "properties": {"bidWei": {"type": "string"}},
                    "additionalProperties": False,
                },
            }
        ]
    }
    open_schema = copy.deepcopy(closed)
    open_schema["tools"][0]["inputSchema"]["additionalProperties"] = True

    diff = diff_reports(scan_documents([closed]), scan_documents([open_schema]))

    change = next(
        item
        for item in diff["changes"]
        if item["kind"] == "unknown_arguments_changed"
    )
    assert change["classification"] == "authority_increase"
    assert change["before"] is True
    assert change["after"] is False


def test_removing_modeled_argument_from_open_schema_is_authority_increase(
    tmp_path,
):
    before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string", "format": "email"}
                    },
                    "additionalProperties": True,
                },
            }
        ]
    }
    after_document = copy.deepcopy(before_document)
    after_document["tools"][0]["inputSchema"]["properties"] = {}

    diff = diff_reports(
        scan_documents([before_document]), scan_documents([after_document])
    )

    change = next(
        item for item in diff["changes"] if item["kind"] == "argument_removed"
    )
    assert change["classification"] == "authority_increase"
    assert diff["summary"]["authority_increases"] == 1
    assert diff["summary"]["protection_increases"] == 0

    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(json.dumps(before_document), encoding="utf-8")
    after_path.write_text(json.dumps(after_document), encoding="utf-8")

    assert (
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--fail-on-increase",
                "--fail-on-review",
            ]
        )
        == 2
    )


def test_removing_modeled_argument_from_closed_schema_is_protection_increase():
    before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string", "format": "email"}
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    after_document = copy.deepcopy(before_document)
    after_document["tools"][0]["inputSchema"]["properties"] = {}

    diff = diff_reports(
        scan_documents([before_document]), scan_documents([after_document])
    )

    change = next(
        item for item in diff["changes"] if item["kind"] == "argument_removed"
    )
    assert change["classification"] == "protection_increase"


def test_new_unresolved_schema_composition_requires_diff_review():
    before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"body": {"type": "string"}},
                },
            }
        ]
    }
    after_document = copy.deepcopy(before_document)
    after_document["tools"][0]["inputSchema"]["allOf"] = [
        {
            "properties": {
                "recipient": {"type": "string", "format": "email"}
            }
        }
    ]

    diff = diff_reports(
        scan_documents([before_document]), scan_documents([after_document])
    )

    change = next(
        item
        for item in diff["changes"]
        if item["kind"] == "schema_review_requirement_changed"
    )
    assert change["classification"] == "review"
    assert change["before"] is False
    assert change["after"] is True


def test_pattern_property_replacement_cannot_look_like_argument_protection(
    tmp_path,
):
    before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}},
                    "additionalProperties": False,
                },
            }
        ]
    }
    after_document = copy.deepcopy(before_document)
    after_schema = after_document["tools"][0]["inputSchema"]
    after_schema["properties"] = {}
    after_schema["patternProperties"] = {"^recipient$": True}

    before = scan_documents([before_document])
    after = scan_documents([after_document])
    assert after["tools"][0]["schema_closes_unknown_arguments"] is False
    assert after["tools"][0]["schema_review_required"] is True

    diff = diff_reports(before, after)
    removed = next(
        change for change in diff["changes"] if change["kind"] == "argument_removed"
    )
    assert removed["classification"] == "authority_increase"
    assert removed["classification"] != "protection_increase"

    before_path = tmp_path / "before-schema.json"
    after_path = tmp_path / "after-schema.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(json.dumps(before_document), encoding="utf-8")
    after_path.write_text(json.dumps(after_document), encoding="utf-8")
    assert main(
        [
            str(before_path),
            str(after_path),
            "--format",
            "json",
            "--output",
            str(output_path),
            "--fail-on-increase",
        ]
    ) == 2


def test_open_schema_argument_removed_into_pattern_is_authority_increase():
    before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}},
                },
            }
        ]
    }
    after_document = copy.deepcopy(before_document)
    after_schema = after_document["tools"][0]["inputSchema"]
    after_schema["properties"] = {}
    after_schema["patternProperties"] = {"^recipient$": True}

    diff = diff_reports(
        scan_documents([before_document]), scan_documents([after_document])
    )

    removed = next(
        change for change in diff["changes"] if change["kind"] == "argument_removed"
    )
    assert removed["classification"] == "authority_increase"


def test_optional_schema_review_fields_preserve_legacy_v3_compatibility():
    report = _single_argument_report({"type": "string"})
    report["summary"].pop("schema_review_required_tools")
    report["tools"][0].pop("schema_review_required")

    diff = diff_reports(report, copy.deepcopy(report))

    assert diff["summary"]["changes"] == 0


def test_schema_review_summary_must_match_tool_flags():
    report = _single_argument_report({"type": "string"})
    report["summary"]["schema_review_required_tools"] = 1

    with pytest.raises(DiffError, match="does not match its tools"):
        diff_reports(report, copy.deepcopy(report))


def test_redacted_reports_are_rejected_because_names_are_not_stable():
    report = scan_documents(
        [{"tools": [{"name": "read_item", "inputSchema": {}}]}],
        redact_names=True,
    )

    with pytest.raises(DiffError, match="redacted names"):
        diff_reports(report, report)


def test_cli_accepts_raw_schemas_and_returns_two_on_authority_increase(tmp_path):
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "send_email",
                        "inputSchema": {
                            "properties": {"body": {"type": "string"}}
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "send_email",
                        "inputSchema": {
                            "properties": {
                                "body": {"type": "string"},
                                "to": {"type": "string", "format": "email"},
                            }
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            str(before_path),
            str(after_path),
            "--format",
            "json",
            "--output",
            str(output_path),
            "--fail-on-increase",
        ]
    )

    assert exit_code == 2
    diff = json.loads(output_path.read_text(encoding="utf-8"))
    assert diff["summary"]["authority_increases"] == 1
    assert diff["changes"][0]["argument"] == "to"


def test_primary_module_routes_to_diff_command(tmp_path):
    report = _avp9_report()
    before_path = tmp_path / "before-report.json"
    after_path = tmp_path / "after-report.json"
    before_path.write_text(json.dumps(report), encoding="utf-8")
    after_path.write_text(json.dumps(report), encoding="utf-8")

    assert verb_authority.main(["diff", str(before_path), str(after_path)]) == 0
