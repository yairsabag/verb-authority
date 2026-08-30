import copy
import json
from pathlib import Path

import pytest

import verb_authority
import verb_authority_diff as differ
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


def _refresh_report_summary(report):
    tools = report["tools"]
    arguments = [argument for tool in tools for argument in tool["arguments"]]
    for tool in tools:
        tool["review_sources"] = scanner._tool_review_sources(
            arguments=tool["arguments"],
            schema_review_required=tool["schema_review_required"],
            risk_review_required=tool["risk_review_required"],
            risk_conflict=tool["risk_conflict"],
            annotation_assessments=tool["annotation_assessments"],
            branch_risk_review_required=tool[
                "branch_risk_review_required"
            ],
        )
        tool["review_required"] = scanner._tool_review_required(
            tool["review_sources"]
        )
    summary = report["summary"]
    summary.update(
        {
            "tools": len(tools),
            "parameters": len(arguments),
            "protected_parameters": sum(
                argument["policy"] == "trusted_fixed" for argument in arguments
            ),
            "data_fillable_parameters": sum(
                argument["policy"] != "trusted_fixed" for argument in arguments
            ),
            "review_required": sum(
                argument["review_required"] is True for argument in arguments
            ),
            "review_required_tools": sum(
                tool["review_required"] is True for tool in tools
            ),
            "confirmation_required_tools": sum(
                tool["needs_confirmation"] is True for tool in tools
            ),
            "risk_review_required_tools": sum(
                tool["risk_review_required"] is True for tool in tools
            ),
            "risk_conflicts": sum(
                tool["risk_conflict"] is True for tool in tools
            ),
            "annotation_conflicts": sum(
                len(tool["annotation_conflicts"]) for tool in tools
            ),
            "branch_risk_review_required_tools": sum(
                tool["branch_risk_review_required"] is True for tool in tools
            ),
        }
    )
    if "schema_review_required_tools" in summary:
        summary["schema_review_required_tools"] = sum(
            tool.get("schema_review_required", False) is True for tool in tools
        )


def _as_v4_report(report):
    legacy = copy.deepcopy(report)
    legacy["report_version"] = 4
    legacy["summary"].pop("review_required_tools")
    for tool in legacy["tools"]:
        tool.pop("review_required")
        tool.pop("review_sources")
    return legacy


def _two_review_argument_report():
    document = {
        "tools": [
            {
                "name": "browser_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "close"],
                        },
                        "index": {"type": "number"},
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
                    "effects": ["changes_tab_state"],
                }
            }
        },
    }
    return scan_documents([document], control_declarations=controls)


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


def _annotation_report(annotations, *, name="operate", tier=None):
    document = {
        "tools": [
            {
                "name": name,
                "annotations": annotations,
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = None
    if tier is not None:
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
    return scan_documents([document], control_declarations=controls)


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


def _declared_risk_report(tier, *, name="florp"):
    schema = {
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
    controls = {
        "version": 1,
        "tools": {
            name: {
                "risk": {
                    "tier": tier,
                    "evidence": "declared",
                    "effects": ["test effect"],
                },
                "arguments": {},
            }
        },
    }
    return scan_documents([schema], control_declarations=controls)


def _branch_risk_report(*, all_read_only=False):
    document = {
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
                            "arguments": ["action", "url"],
                        },
                        {
                            "value": "close",
                            "risk": {
                                "tier": "destructive",
                                "evidence": "observed",
                                "effects": ["destroys_tab"],
                            },
                            "arguments": ["action", "index"],
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
    if all_read_only:
        for case in controls["tools"]["browser_tabs"]["branches"]["cases"]:
            case["risk"]["tier"] = "read_only"
    return scan_documents([document], control_declarations=controls)


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
    assert diff["summary"]["reviews"] == 1
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


def test_legacy_v3_reports_require_rescanning_without_fallback():
    legacy = _constraint_report(100, 40, ["safe"])
    legacy["report_version"] = 3

    with pytest.raises(DiffError, match="legacy report version 3.*rescan"):
        diff_reports(legacy, copy.deepcopy(legacy))


def test_malformed_v4_constraint_metadata_is_rejected():
    report = _constraint_report(100, 40, ["safe"])
    mode = next(
        argument
        for argument in report["tools"][0]["arguments"]
        if argument["name"] == "mode"
    )
    mode["constraints"]["enum"]["count"] = 2

    with pytest.raises(DiffError, match="enum constraint is invalid"):
        diff_reports(report, copy.deepcopy(report))


def test_v5_annotation_assessments_are_accepted_when_scanner_coherent():
    report = _annotation_report(
        {
            "readOnlyHint": False,
            "destructiveHint": True,
            "idempotentHint": True,
            "openWorldHint": False,
        }
    )

    diff = diff_reports(report, copy.deepcopy(report))

    assert report["report_version"] == 5
    assert diff["changes"] == []


def test_v4_report_compares_with_v5_without_mutating_legacy_input():
    current = _avp9_report()
    legacy = _as_v4_report(current)
    frozen_legacy = copy.deepcopy(legacy)

    first = diff_reports(legacy, current)
    second = diff_reports(legacy, current)

    assert first["changes"] == []
    assert second["changes"] == []
    assert legacy == frozen_legacy
    assert legacy["report_version"] == 4
    assert "review_required_tools" not in legacy["summary"]
    assert "review_required" not in legacy["tools"][0]


@pytest.mark.parametrize("field", ("review_required", "review_sources"))
def test_v5_tool_review_aggregate_fields_are_mandatory(field):
    report = _avp9_report()
    report["tools"][0].pop(field)

    with pytest.raises(DiffError, match=rf"missing {field}"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    "mutate",
    (
        lambda tool: tool.__setitem__("review_required", False),
        lambda tool: tool["review_sources"].__setitem__("arguments", []),
        lambda tool: tool["review_sources"].pop("schema"),
        lambda tool: tool["review_sources"].__setitem__("unexpected", False),
    ),
)
def test_v5_tool_review_aggregate_cannot_be_forged(mutate):
    report = _avp9_report()
    mutate(report["tools"][0])

    with pytest.raises(DiffError, match="review"):
        diff_reports(report, copy.deepcopy(report))


def test_v5_review_required_tools_summary_is_mandatory_and_coherent():
    missing = _avp9_report()
    missing["summary"].pop("review_required_tools")
    with pytest.raises(DiffError, match="invalid report summary"):
        diff_reports(missing, copy.deepcopy(missing))

    forged = _avp9_report()
    forged["summary"]["review_required_tools"] = 0
    with pytest.raises(DiffError, match="review_required_tools does not match"):
        diff_reports(forged, copy.deepcopy(forged))


@pytest.mark.parametrize(
    "argument_sources",
    (
        [],
        ["index", "action"],
        ["action", "missing"],
        ["action", "action"],
    ),
)
def test_v5_review_argument_sources_must_match_canonical_review_rows(
    argument_sources,
):
    report = _two_review_argument_report()
    assert report["tools"][0]["review_sources"]["arguments"] == [
        "action",
        "index",
    ]
    report["tools"][0]["review_sources"]["arguments"] = argument_sources

    with pytest.raises(DiffError, match="review_sources are inconsistent"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    "source",
    ("schema", "risk", "risk_conflict", "branch_risk"),
)
def test_v5_review_boolean_sources_cannot_be_flipped(source):
    report = _avp9_report()
    current = report["tools"][0]["review_sources"][source]
    report["tools"][0]["review_sources"][source] = not current

    with pytest.raises(DiffError, match="review_sources are inconsistent"):
        diff_reports(report, copy.deepcopy(report))


def test_v5_review_annotation_sources_must_match_conflict_assessments():
    report = _avp9_report()
    report["tools"][0]["review_sources"]["annotation_conflicts"] = [
        "readOnlyHint"
    ]

    with pytest.raises(DiffError, match="review_sources are inconsistent"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    ("path", "value", "error"),
    (
        ("review_required", 1, "review_required must be a boolean"),
        ("arguments", "bidWei", "review source arguments must be an array"),
        ("schema", 0, "review source schema must be a boolean"),
        (
            "annotation_conflicts",
            "readOnlyHint",
            "review source annotation conflicts must be an array",
        ),
    ),
)
def test_v5_review_aggregate_rejects_wrong_types(path, value, error):
    report = _avp9_report()
    if path == "review_required":
        report["tools"][0][path] = value
    else:
        report["tools"][0]["review_sources"][path] = value

    with pytest.raises(DiffError, match=error):
        diff_reports(report, copy.deepcopy(report))


def test_v4_report_cannot_smuggle_v5_aggregate_fields():
    report = _avp9_report()
    report["report_version"] = 4
    report["summary"].pop("review_required_tools")

    with pytest.raises(DiffError, match="unsupported fields"):
        diff_reports(report, copy.deepcopy(report))


def test_annotation_evidence_change_is_a_semantic_review_even_without_conflict():
    before = _annotation_report({"readOnlyHint": False})
    after = _annotation_report({"readOnlyHint": True})

    diff = diff_reports(before, after)

    assert before["schema_fingerprint_sha256"] == after[
        "schema_fingerprint_sha256"
    ]
    assert before["tools"][0]["annotation_conflicts"] == []
    assert after["tools"][0]["annotation_conflicts"] == []
    assert diff["summary"] == {
        "changes": 1,
        "changed_tools": 1,
        "authority_increases": 0,
        "reviews": 1,
        "protection_increases": 0,
    }
    assert diff["changes"][0]["kind"] == "annotation_assessments_changed"
    assert diff["changes"][0]["field"] == "annotation_assessments"


@pytest.mark.parametrize(
    "invalid_assessments",
    (None, {}, "readOnlyHint", True),
)
def test_annotation_assessments_must_be_an_array(invalid_assessments):
    report = _annotation_report({"readOnlyHint": False})
    report["tools"][0]["annotation_assessments"] = invalid_assessments

    with pytest.raises(DiffError, match="annotation assessments must be an array"):
        diff_reports(report, copy.deepcopy(report))


def test_each_annotation_assessment_must_be_an_object():
    report = _annotation_report({"readOnlyHint": False})
    report["tools"][0]["annotation_assessments"][0] = "unresolved"

    with pytest.raises(
        DiffError, match=r"annotation assessment\[1\] must be an object"
    ):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    "field",
    (
        "annotation",
        "value",
        "state",
        "evidence_source",
        "trust",
        "comparison_source",
        "comparison_value",
    ),
)
def test_annotation_assessment_requires_every_v4_field(field):
    report = _annotation_report({"readOnlyHint": False})
    report["tools"][0]["annotation_assessments"][0].pop(field)

    with pytest.raises(DiffError, match=rf"missing required fields:.*{field}"):
        diff_reports(report, copy.deepcopy(report))


def test_annotation_assessment_rejects_unknown_fields():
    report = _annotation_report({"readOnlyHint": False})
    report["tools"][0]["annotation_assessments"][0]["future"] = "trusted"

    with pytest.raises(DiffError, match="unsupported fields: future"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    ("field", "invalid_value", "message"),
    (
        ("annotation", "futureHint", "annotation is unsupported"),
        ("annotation", 1, "annotation must be non-empty text"),
        ("value", 1, "value must be a boolean"),
        ("state", "trusted", "state is unsupported"),
        ("state", 1, "state must be non-empty text"),
        ("evidence_source", "control_declaration", "evidence_source is unsupported"),
        ("evidence_source", 1, "evidence_source is unsupported"),
        ("trust", "verified", "trust is unsupported"),
        ("trust", 1, "trust is unsupported"),
        ("comparison_source", "declared_risk", "comparison_source is unsupported"),
        ("comparison_source", 1, "comparison_source must be non-empty text"),
        ("comparison_value", [], "is inconsistent"),
    ),
)
def test_annotation_assessment_vocabulary_and_types_are_closed(
    field, invalid_value, message
):
    report = _annotation_report({"readOnlyHint": False})
    report["tools"][0]["annotation_assessments"][0][field] = invalid_value

    with pytest.raises(DiffError, match=message):
        diff_reports(report, copy.deepcopy(report))


def test_annotation_assessments_are_unique_and_canonically_ordered():
    duplicate = _annotation_report(
        {"readOnlyHint": False, "destructiveHint": True}
    )
    duplicate["tools"][0]["annotation_assessments"].append(
        copy.deepcopy(duplicate["tools"][0]["annotation_assessments"][0])
    )
    reordered = _annotation_report(
        {"readOnlyHint": False, "destructiveHint": True}
    )
    reordered["tools"][0]["annotation_assessments"].reverse()

    with pytest.raises(DiffError, match="duplicate annotation assessment"):
        diff_reports(duplicate, copy.deepcopy(duplicate))
    with pytest.raises(DiffError, match="not in canonical order"):
        diff_reports(reordered, copy.deepcopy(reordered))


@pytest.mark.parametrize(
    ("annotations", "field", "forged_value"),
    (
        ({"readOnlyHint": False}, "state", "conflict"),
        ({"readOnlyHint": False}, "comparison_source", "none"),
        ({"readOnlyHint": False}, "comparison_value", None),
        (
            {"readOnlyHint": True, "destructiveHint": True},
            "state",
            "unresolved",
        ),
    ),
)
def test_annotation_assessment_semantic_forgery_is_rejected(
    annotations, field, forged_value
):
    report = _annotation_report(annotations)
    report["tools"][0]["annotation_assessments"][-1][field] = forged_value

    with pytest.raises(DiffError, match="annotation assessment.*is inconsistent"):
        diff_reports(report, copy.deepcopy(report))


def test_annotation_conflict_summary_must_match_structured_assessments():
    report = _annotation_report(
        {"readOnlyHint": False}, name="read_record", tier="read_only"
    )
    assert report["tools"][0]["annotation_assessments"][0]["state"] == "conflict"
    report["tools"][0]["annotation_conflicts"] = []
    _refresh_report_summary(report)

    with pytest.raises(DiffError, match="conflicts do not match its assessments"):
        diff_reports(report, copy.deepcopy(report))


def test_branch_report_is_accepted_and_branch_changes_are_surfaced():
    before = _branch_risk_report()
    after = copy.deepcopy(before)
    case = next(
        case
        for case in after["tools"][0]["branch_risk"]["cases"]
        if case["risk"] == "write"
    )
    case["effects"] = ["changed_write_effect"]
    after["declared_controls"]["tools"][0]["branches"] = copy.deepcopy(
        after["tools"][0]["branch_risk"]
    )
    _refresh_control_fingerprint(after)

    diff = diff_reports(before, after)

    change = next(
        change for change in diff["changes"] if change["kind"] == "branch_risk_changed"
    )
    assert change["classification"] == "review"
    assert change["field"] == "branch_risk"


def _set_branch_active_arguments(report, risk, arguments):
    case = next(
        case
        for case in report["tools"][0]["branch_risk"]["cases"]
        if case["risk"] == risk
    )
    case["active_arguments"] = arguments
    report["declared_controls"]["tools"][0]["branches"] = copy.deepcopy(
        report["tools"][0]["branch_risk"]
    )
    _refresh_control_fingerprint(report)


def test_expanding_branch_active_arguments_is_an_authority_increase():
    before = _branch_risk_report()
    after = copy.deepcopy(before)
    _set_branch_active_arguments(after, "read_only", ["action", "index"])

    result = diff_reports(before, after)

    change = next(
        change
        for change in result["changes"]
        if change["kind"] == "branch_risk_changed"
    )
    assert change["classification"] == "authority_increase"
    assert result["summary"]["authority_increases"] == 1


def test_reducing_branch_active_arguments_is_a_protection_increase():
    after = _branch_risk_report()
    before = copy.deepcopy(after)
    _set_branch_active_arguments(before, "read_only", ["action", "index"])

    result = diff_reports(before, after)

    change = next(
        change
        for change in result["changes"]
        if change["kind"] == "branch_risk_changed"
    )
    assert change["classification"] == "protection_increase"
    assert result["summary"]["protection_increases"] == 1


def test_mixed_branch_active_argument_changes_cannot_mask_an_increase():
    before = _branch_risk_report()
    after = copy.deepcopy(before)
    _set_branch_active_arguments(after, "read_only", ["action", "index"])
    _set_branch_active_arguments(after, "destructive", ["action"])

    result = diff_reports(before, after)

    change = next(
        change
        for change in result["changes"]
        if change["kind"] == "branch_risk_changed"
    )
    assert change["classification"] == "authority_increase"
    assert result["summary"]["authority_increases"] == 1


def test_branch_risk_edit_cannot_mask_active_argument_expansion():
    before = _branch_risk_report()
    after = copy.deepcopy(before)
    _set_branch_active_arguments(after, "read_only", ["action", "index"])
    case = next(
        case
        for case in after["tools"][0]["branch_risk"]["cases"]
        if case["risk"] == "read_only"
    )
    case["effects"] = ["changed_read_effect"]
    after["declared_controls"]["tools"][0]["branches"] = copy.deepcopy(
        after["tools"][0]["branch_risk"]
    )
    _refresh_control_fingerprint(after)

    result = diff_reports(before, after)

    change = next(
        change
        for change in result["changes"]
        if change["kind"] == "branch_risk_changed"
    )
    assert change["classification"] == "authority_increase"
    assert result["summary"]["authority_increases"] == 1


def test_set_incomparable_branch_replacement_is_an_authority_increase():
    before = _branch_risk_report()
    _set_branch_active_arguments(before, "read_only", ["action", "index"])
    after = copy.deepcopy(before)
    _set_branch_active_arguments(after, "read_only", ["action", "url"])
    case = next(
        case
        for case in after["tools"][0]["branch_risk"]["cases"]
        if case["risk"] == "read_only"
    )
    case["evidence"] = "declared"
    after["declared_controls"]["tools"][0]["branches"] = copy.deepcopy(
        after["tools"][0]["branch_risk"]
    )
    _refresh_control_fingerprint(after)

    result = diff_reports(before, after)

    change = next(
        change
        for change in result["changes"]
        if change["kind"] == "branch_risk_changed"
    )
    assert change["classification"] == "authority_increase"
    assert result["summary"]["authority_increases"] == 1


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda report: report["tools"][0]["branch_risk"]["cases"][0].update(
                {"value": "close"}
            ),
            "unsupported fields",
        ),
        (
            lambda report: report["tools"][0]["branch_risk"]["cases"][0].update(
                {"needs_confirmation": True}
            ),
            "needs_confirmation is inconsistent",
        ),
        (
            lambda report: report["tools"][0].update({"risk": "write"}),
            "branch-derived risk",
        ),
        (
            lambda report: report["tools"][0]["branch_risk"]["cases"][0].update(
                {"active_arguments": ["action", "missing"]}
            ),
            "active_arguments is inconsistent",
        ),
        (
            lambda report: report["tools"][0]["branch_risk"]["cases"].append(
                copy.deepcopy(
                    report["tools"][0]["branch_risk"]["cases"][0]
                )
            ),
            "duplicate branch fingerprints",
        ),
        (
            lambda report: report["tools"][0]["branch_risk"]["cases"].reverse(),
            "not in canonical order",
        ),
    ],
)
def test_branch_report_forgery_is_rejected(mutate, message):
    report = _branch_risk_report()
    mutate(report)

    with pytest.raises(DiffError, match=message):
        diff_reports(report, copy.deepcopy(report))


def test_branch_case_fingerprints_must_exhaust_selector_enum():
    report = _branch_risk_report()
    cases = report["tools"][0]["branch_risk"]["cases"]
    replacement = "f" * 64
    assert replacement not in {
        case["value_fingerprint_sha256"] for case in cases
    }
    cases[0]["value_fingerprint_sha256"] = replacement
    cases.sort(key=lambda case: case["value_fingerprint_sha256"])
    report["declared_controls"]["tools"][0]["branches"] = copy.deepcopy(
        report["tools"][0]["branch_risk"]
    )
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="do not exhaust the selector enum"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("source", "branch_declaration", "invalid risk inference source"),
        ("confidence", "heuristic", "inconsistent risk inference"),
        ("mutability", "trusted_party", "invalid risk inference mutability"),
        ("matched_tokens", ["delete"], "inconsistent risk inference"),
    ],
)
def test_branch_report_rejects_forged_risk_inference(field, value, message):
    report = _branch_risk_report()
    report["tools"][0]["risk_inference"][field] = value

    with pytest.raises(DiffError, match=message):
        diff_reports(report, copy.deepcopy(report))


def test_raw_signed_zero_selector_change_is_detected(tmp_path):
    def schema(value):
        return {
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

    def controls(value):
        return {
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

    before_schema = tmp_path / "before-schema.json"
    after_schema = tmp_path / "after-schema.json"
    before_controls = tmp_path / "before-controls.json"
    after_controls = tmp_path / "after-controls.json"
    before_schema.write_text(json.dumps(schema(0.0)), encoding="utf-8")
    after_schema.write_text(json.dumps(schema(-0.0)), encoding="utf-8")
    before_controls.write_text(json.dumps(controls(0.0)), encoding="utf-8")
    after_controls.write_text(json.dumps(controls(-0.0)), encoding="utf-8")

    before = load_report_or_schema(
        str(before_schema), controls_path=str(before_controls), label="before"
    )
    after = load_report_or_schema(
        str(after_schema), controls_path=str(after_controls), label="after"
    )
    result = diff_reports(before, after)

    assert before["schema_fingerprint_sha256"] != after[
        "schema_fingerprint_sha256"
    ]
    assert before["control_declaration_fingerprint_sha256"] != after[
        "control_declaration_fingerprint_sha256"
    ]
    assert {change["kind"] for change in result["changes"]} >= {
        "enum_changed",
        "branch_risk_changed",
    }


def test_fail_on_increase_trips_on_branch_active_argument_expansion(tmp_path):
    schema = {
        "tools": [
            {
                "name": "browser_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["list"]},
                        "index": {"type": "integer"},
                    },
                },
            }
        ]
    }

    def controls(arguments):
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
                                "arguments": arguments,
                            }
                        ],
                    }
                }
            },
        }

    before_schema = tmp_path / "before.json"
    after_schema = tmp_path / "after.json"
    before_controls = tmp_path / "before-controls.json"
    after_controls = tmp_path / "after-controls.json"
    before_schema.write_text(json.dumps(schema), encoding="utf-8")
    after_schema.write_text(json.dumps(schema), encoding="utf-8")
    before_controls.write_text(
        json.dumps(controls(["action"])), encoding="utf-8"
    )
    after_controls.write_text(
        json.dumps(controls(["action", "index"])), encoding="utf-8"
    )

    assert (
        main(
            [
                str(before_schema),
                str(after_schema),
                "--before-controls",
                str(before_controls),
                "--after-controls",
                str(after_controls),
                "--fail-on-increase",
            ]
        )
        == 2
    )


def test_fail_on_increase_trips_on_incomparable_branch_replacement(tmp_path):
    schema = {
        "tools": [
            {
                "name": "browser_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {"type": "string", "enum": ["list"]},
                        "index": {"type": "integer"},
                        "url": {"type": "string"},
                    },
                },
            }
        ]
    }

    def controls(arguments, evidence):
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
                                    "evidence": evidence,
                                    "effects": ["reads_tabs"],
                                },
                                "arguments": arguments,
                            }
                        ],
                    }
                }
            },
        }

    before_schema = tmp_path / "before.json"
    after_schema = tmp_path / "after.json"
    before_controls = tmp_path / "before-controls.json"
    after_controls = tmp_path / "after-controls.json"
    before_schema.write_text(json.dumps(schema), encoding="utf-8")
    after_schema.write_text(json.dumps(schema), encoding="utf-8")
    before_controls.write_text(
        json.dumps(controls(["action", "index"], "observed")),
        encoding="utf-8",
    )
    after_controls.write_text(
        json.dumps(controls(["action", "url"], "declared")),
        encoding="utf-8",
    )

    assert (
        main(
            [
                str(before_schema),
                str(after_schema),
                "--before-controls",
                str(before_controls),
                "--after-controls",
                str(after_controls),
                "--fail-on-increase",
            ]
        )
        == 2
    )


def test_fail_on_review_includes_unresolved_branch_risk_directly(tmp_path):
    schema = {
        "tools": [
            {
                "name": "operate_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tabAction": {
                            "type": "string",
                            "enum": ["list", "close"],
                        }
                    },
                },
            }
        ]
    }
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps(schema), encoding="utf-8")
    after.write_text(json.dumps(schema), encoding="utf-8")

    assert main([str(before), str(after), "--fail-on-review"]) == 2


def _write_identical_risk_review_inputs(tmp_path):
    document = {
        "tools": [
            {
                "name": "mystery",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ]
    }
    report = scan_documents([document])
    assert report["summary"]["risk_review_required_tools"] == 1
    assert all(
        report["summary"][field] == 0
        for field in (
            "review_required",
            "schema_review_required_tools",
            "risk_conflicts",
            "annotation_conflicts",
            "branch_risk_review_required_tools",
        )
    )

    before = tmp_path / "before-review-debt.json"
    after = tmp_path / "after-review-debt.json"
    before.write_text(json.dumps(document), encoding="utf-8")
    after.write_text(json.dumps(document), encoding="utf-8")
    return before, after


def test_unchanged_candidate_review_debt_is_explained_in_text_output(
    tmp_path, capsys
):
    before, after = _write_identical_risk_review_inputs(tmp_path)

    assert main([str(before), str(after), "--fail-on-review"]) == 2

    captured = capsys.readouterr()
    assert "Review-classified changes: 0" in captured.out
    assert "No authority-relevant changes detected." in captured.out
    assert captured.err == (
        "Review threshold failed: candidate scan has existing review debt "
        "(tool risks requiring review: 1).\n"
    )


def test_unchanged_candidate_review_debt_keeps_json_stdout_valid(tmp_path, capsys):
    before, after = _write_identical_risk_review_inputs(tmp_path)

    assert (
        main(
            [
                str(before),
                str(after),
                "--format",
                "json",
                "--fail-on-review",
            ]
        )
        == 2
    )

    captured = capsys.readouterr()
    rendered = json.loads(captured.out)
    assert rendered["summary"] == {
        "changes": 0,
        "changed_tools": 0,
        "authority_increases": 0,
        "reviews": 0,
        "protection_increases": 0,
    }
    assert "Review threshold failed" not in captured.out
    assert captured.err == (
        "Review threshold failed: candidate scan has existing review debt "
        "(tool risks requiring review: 1).\n"
    )


def _assert_unchanged_raw_review_threshold(
    tmp_path,
    document,
    *,
    expected_summary_field,
    controls=None,
):
    report = scan_documents([document], control_declarations=controls)
    assert report["summary"][expected_summary_field] > 0
    assert diff_reports(report, copy.deepcopy(report))["summary"] == {
        "changes": 0,
        "changed_tools": 0,
        "authority_increases": 0,
        "reviews": 0,
        "protection_increases": 0,
    }

    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    before.write_text(json.dumps(document), encoding="utf-8")
    after.write_text(json.dumps(document), encoding="utf-8")
    argv = [str(before), str(after)]
    if controls is not None:
        before_controls = tmp_path / "before-controls.json"
        after_controls = tmp_path / "after-controls.json"
        before_controls.write_text(json.dumps(controls), encoding="utf-8")
        after_controls.write_text(json.dumps(controls), encoding="utf-8")
        argv.extend(
            [
                "--before-controls",
                str(before_controls),
                "--after-controls",
                str(after_controls),
            ]
        )

    assert main([*argv, "--fail-on-review"]) == 2


def test_fail_on_review_trips_on_unchanged_argument_review_debt(tmp_path):
    document = {
        "tools": [
            {
                "name": "write_record",
                "inputSchema": {
                    "type": "object",
                    "properties": {"value": {"type": "string"}},
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "write_record": {
                "risk": {
                    "tier": "write",
                    "evidence": "observed",
                    "effects": ["writes_record"],
                }
            }
        },
    }
    _assert_unchanged_raw_review_threshold(
        tmp_path,
        document,
        controls=controls,
        expected_summary_field="review_required",
    )


def test_fail_on_review_trips_on_unchanged_risk_review_debt(tmp_path):
    document = {
        "tools": [
            {
                "name": "mystery",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ]
    }
    _assert_unchanged_raw_review_threshold(
        tmp_path,
        document,
        expected_summary_field="risk_review_required_tools",
    )


def test_fail_on_review_trips_on_unchanged_risk_conflict(tmp_path):
    document = {
        "tools": [
            {
                "name": "delete_record",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "delete_record": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "observed",
                    "effects": ["reads_record"],
                }
            }
        },
    }
    _assert_unchanged_raw_review_threshold(
        tmp_path,
        document,
        controls=controls,
        expected_summary_field="risk_conflicts",
    )


def test_fail_on_review_trips_on_unchanged_schema_review_debt(tmp_path):
    document = {
        "tools": [
            {
                "name": "read_record",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "allOf": [
                        {"properties": {"recipient": {"type": "string"}}}
                    ],
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "read_record": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "observed",
                    "effects": ["reads_record"],
                }
            }
        },
    }
    _assert_unchanged_raw_review_threshold(
        tmp_path,
        document,
        controls=controls,
        expected_summary_field="schema_review_required_tools",
    )


def test_fail_on_review_trips_on_unchanged_annotation_conflict(tmp_path):
    document = {
        "tools": [
            {
                "name": "read_record",
                "annotations": {"readOnlyHint": False},
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "read_record": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "observed",
                    "effects": ["reads_record"],
                }
            }
        },
    }
    _assert_unchanged_raw_review_threshold(
        tmp_path,
        document,
        controls=controls,
        expected_summary_field="annotation_conflicts",
    )


def test_fail_on_review_trips_on_unchanged_branch_review_debt(tmp_path):
    document = {
        "tools": [
            {
                "name": "operate_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "tabAction": {
                            "type": "string",
                            "enum": ["list", "close"],
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
            "operate_tabs": {
                "risk": {
                    "tier": "write",
                    "evidence": "observed",
                    "effects": ["changes_tabs"],
                }
            }
        },
    }
    _assert_unchanged_raw_review_threshold(
        tmp_path,
        document,
        controls=controls,
        expected_summary_field="branch_risk_review_required_tools",
    )


def test_branch_declaration_copy_must_match_report_branch():
    report = _branch_risk_report()
    report["declared_controls"]["tools"][0]["branches"]["cases"][0][
        "effects"
    ] = ["forged_effect"]
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="branches conflict with the report tool"):
        diff_reports(report, copy.deepcopy(report))


def test_branch_review_summary_and_state_are_recomputed():
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "operate",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "enum": ["read", "delete"],
                                }
                            },
                        },
                    }
                ]
            }
        ]
    )
    assert report["tools"][0]["branch_risk_review_required"] is True
    assert report["summary"]["branch_risk_review_required_tools"] == 1

    report["tools"][0]["branch_risk_review_required"] = False
    report["summary"]["branch_risk_review_required_tools"] = 0
    with pytest.raises(DiffError, match="inconsistent branch risk review state"):
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


def test_control_verification_notice_must_remain_the_scanner_warning():
    report = _avp9_report()
    report["declared_controls"]["verification_notice"] = (
        "All declarations were independently verified."
    )

    with pytest.raises(DiffError, match="verification_notice is invalid"):
        diff_reports(report, copy.deepcopy(report))


def test_duplicated_declared_risk_must_match_the_report_tool():
    report = _avp9_report()
    report["declared_controls"]["tools"][0]["risk"]["effects"].append(
        "different_effect"
    )
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="risk conflicts with the report tool"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize("effect", ("", "   ", " padded "))
def test_imported_declared_risk_effects_must_match_scanner_output(effect):
    report = _avp9_report()
    report["tools"][0]["declared_risk"]["effects"] = [effect]
    report["declared_controls"]["tools"][0]["risk"]["effects"] = [effect]
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="trimmed, non-empty, unique"):
        diff_reports(report, copy.deepcopy(report))


def test_imported_v3_report_must_contain_at_least_one_tool():
    report = _single_argument_report({"type": "string"})
    report["tools"] = []
    report["summary"] = {field: 0 for field in report["summary"]}

    with pytest.raises(DiffError, match="no tool definitions.*rescan"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    "field",
    (
        "risk_note",
        "attribution_name",
        "bound_source",
        "bound_enforcement",
        "argument_note",
        "unexposed_enforced_by",
        "unexposed_note",
    ),
)
def test_imported_control_text_must_match_scanner_normalization(field):
    report = _avp9_report()
    controls = report["declared_controls"]
    tool = controls["tools"][0]
    if field == "risk_note":
        tool["risk"]["note"] = " padded "
        report["tools"][0]["declared_risk"]["note"] = " padded "
    elif field == "attribution_name":
        controls["attribution"]["name"] = " padded "
    elif field == "bound_source":
        tool["arguments"][1]["bounds"][0]["source"] = " padded "
    elif field == "bound_enforcement":
        tool["arguments"][1]["bounds"][0]["enforcement"] = " padded "
    elif field == "argument_note":
        tool["arguments"][0]["note"] = " padded "
    elif field == "unexposed_enforced_by":
        tool["unexposed_arguments"][0]["enforced_by"] = " padded "
    else:
        tool["unexposed_arguments"][0]["note"] = " padded "
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="trimmed, non-empty text"):
        diff_reports(report, copy.deepcopy(report))


def test_imported_declared_control_order_must_match_scanner_output():
    schema = {
        "tools": [
            {
                "name": name,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "first": {"type": "string"},
                        "second": {"type": "string"},
                    },
                },
            }
            for name in ("write_alpha", "write_beta")
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            name: {
                "arguments": {
                    "first": {"authority": "free", "evidence": "declared"},
                    "second": {"authority": "free", "evidence": "declared"},
                }
            }
            for name in ("write_alpha", "write_beta")
        },
    }
    report = scan_documents([schema], control_declarations=controls)

    reversed_tools = copy.deepcopy(report)
    reversed_tools["declared_controls"]["tools"].reverse()
    _refresh_control_fingerprint(reversed_tools)
    with pytest.raises(DiffError, match="tool order"):
        diff_reports(reversed_tools, copy.deepcopy(reversed_tools))

    reversed_arguments = copy.deepcopy(report)
    reversed_arguments["declared_controls"]["tools"][0]["arguments"].reverse()
    _refresh_control_fingerprint(reversed_arguments)
    with pytest.raises(DiffError, match="argument order"):
        diff_reports(reversed_arguments, copy.deepcopy(reversed_arguments))


def test_imported_unexposed_control_order_must_be_canonical():
    schema = {
        "tools": [
            {
                "name": "write_record",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "write_record": {
                "unexposed_arguments": {
                    name: {
                        "exposure": "server_fixed",
                        "enforced_by": "server",
                        "evidence": "declared",
                    }
                    for name in ("zeta", "alpha")
                }
            }
        },
    }
    report = scan_documents([schema], control_declarations=controls)
    report["declared_controls"]["tools"][0]["unexposed_arguments"].reverse()
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="order is not canonical"):
        diff_reports(report, copy.deepcopy(report))


def test_redacted_unexposed_control_order_uses_scanner_numeric_sequence():
    schema = {
        "tools": [
            {
                "name": "write_record",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "write_record": {
                "unexposed_arguments": {
                    f"hidden_{index:04d}": {
                        "exposure": "server_fixed",
                        "enforced_by": "server",
                        "evidence": "declared",
                    }
                    for index in range(1_000)
                }
            }
        },
    }
    report = scan_documents(
        [schema],
        redact_names=True,
        control_declarations=controls,
    )

    with pytest.raises(DiffError, match="redacted names"):
        diff_reports(report, copy.deepcopy(report))


def test_imported_report_enforces_tool_cardinality(monkeypatch):
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "read_alpha",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                    {
                        "name": "read_beta",
                        "inputSchema": {"type": "object", "properties": {}},
                    },
                ]
            }
        ]
    )
    monkeypatch.setattr(differ, "MAX_SCAN_TOOL_DEFINITIONS", 1)

    with pytest.raises(DiffError, match="tool-definition limit of 1.*rescan"):
        diff_reports(report, copy.deepcopy(report))


def test_imported_report_enforces_argument_cardinality_including_unexposed(
    monkeypatch,
):
    report = _avp9_report()
    exposed = sum(len(tool["arguments"]) for tool in report["tools"])
    monkeypatch.setattr(differ, "MAX_SCAN_ARGUMENTS", exposed)

    with pytest.raises(DiffError, match="argument limit.*rescan"):
        diff_reports(report, copy.deepcopy(report))


def test_imported_report_enforces_enum_member_cardinality(monkeypatch):
    report = _single_argument_report({"type": "string", "enum": ["safe"]})
    enum = report["tools"][0]["arguments"][0]["constraints"]["enum"]
    enum["count"] = 2
    enum["value_fingerprints_sha256"] = ["0" * 64, "1" * 64]
    monkeypatch.setattr(differ, "MAX_SCAN_ENUM_MEMBERS", 1)

    with pytest.raises(DiffError, match="enum-member limit of 1.*rescan"):
        diff_reports(report, copy.deepcopy(report))


def test_imported_report_enforces_control_collection_cardinality(monkeypatch):
    report = _avp9_report()
    controls = report["declared_controls"]["tools"][0]
    members = len(controls["risk"]["effects"]) + sum(
        len(argument.get("bounds", [])) for argument in controls["arguments"]
    )
    monkeypatch.setattr(
        differ,
        "MAX_SCAN_CONTROL_COLLECTION_MEMBERS",
        members - 1,
    )

    with pytest.raises(DiffError, match="control collection-member limit.*rescan"):
        diff_reports(report, copy.deepcopy(report))


def test_declared_risk_cannot_outlive_its_declared_control_tool():
    report = _avp9_report()
    report["declared_controls"]["tools"] = []
    _refresh_control_fingerprint(report)

    with pytest.raises(DiffError, match="declared risk without the matching"):
        diff_reports(report, copy.deepcopy(report))


def test_declared_risk_cannot_outlive_all_declared_control_metadata():
    report = _avp9_report()
    report["privacy"]["control_declarations_included"] = False
    report.pop("declared_controls")
    report.pop("control_declaration_fingerprint_sha256")

    with pytest.raises(DiffError, match="declared risk without declared control"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize("field", ("risk_evidence", "declared_risk"))
def test_required_nullable_risk_fields_cannot_be_omitted(field):
    report = _avp9_report()
    report["tools"][0].pop(field)

    with pytest.raises(DiffError, match=f"missing {field}"):
        diff_reports(report, copy.deepcopy(report))


def test_missing_declared_risk_is_a_clean_cli_input_error(tmp_path, capsys):
    before = _avp9_report()
    after = copy.deepcopy(before)
    after["tools"][0].pop("declared_risk")
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main([str(before_path), str(after_path)])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "missing declared_risk" in error
    assert "Traceback" not in error


@pytest.mark.parametrize("omit_fields", (False, True))
def test_open_schema_with_unexposed_controls_cannot_hide_schema_review(
    omit_fields
):
    schema = {
        "tools": [
            {
                "name": "florp",
                "inputSchema": {"type": "object", "properties": {}},
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "florp": {
                "unexposed_arguments": {
                    "destination": {
                        "exposure": "server_fixed",
                        "enforced_by": "server",
                        "evidence": "declared",
                    }
                }
            }
        },
    }
    report = scan_documents([schema], control_declarations=controls)
    assert report["tools"][0]["schema_closes_unknown_arguments"] is False
    assert report["tools"][0]["schema_review_required"] is True

    forged = copy.deepcopy(report)
    if omit_fields:
        forged["tools"][0].pop("schema_review_required")
        forged["summary"].pop("schema_review_required_tools")
    else:
        forged["tools"][0]["schema_review_required"] = False
        forged["summary"]["schema_review_required_tools"] = 0

    expected = (
        "rescan" if omit_fields else "unexposed controls on an open schema"
    )
    with pytest.raises(DiffError, match=expected):
        diff_reports(report, forged)


def test_argument_confidence_policy_and_review_must_be_coherent():
    report = _single_argument_report({"type": "string"})
    argument = report["tools"][0]["arguments"][0]
    assert argument["confidence"] == "uncertain"
    assert argument["policy"] == "trusted_fixed"
    assert argument["review_required"] is True
    argument["review_required"] = False
    _refresh_report_summary(report)

    with pytest.raises(DiffError, match="inconsistent policy inference"):
        diff_reports(report, copy.deepcopy(report))


def test_all_read_only_branch_report_uses_fail_closed_argument_coherence():
    report = _branch_risk_report(all_read_only=True)
    tool = report["tools"][0]
    arguments = {argument["name"]: argument for argument in tool["arguments"]}

    assert tool["risk"] == "read_only"
    assert diff_reports(report, copy.deepcopy(report))["summary"]["changes"] == 0
    assert (
        arguments["action"]["policy"],
        arguments["action"]["confidence"],
        arguments["action"]["review_required"],
    ) == ("trusted_fixed", "uncertain", True)

    forged = copy.deepcopy(report)
    forged_action = next(
        argument
        for argument in forged["tools"][0]["arguments"]
        if argument["name"] == "action"
    )
    forged_action["policy"] = "typed_bounded"
    forged_action["review_required"] = False
    _refresh_report_summary(forged)

    with pytest.raises(DiffError, match="inconsistent policy inference"):
        diff_reports(report, forged)


@pytest.mark.parametrize(
    ("argument_name", "argument_type", "declared_read_only", "expected"),
    (
        ("recipient", "string", False, ("trusted_fixed", "high", False)),
        ("value", "string", False, ("trusted_fixed", "uncertain", True)),
        ("value", "integer", False, ("trusted_fixed", "uncertain", True)),
        ("value", "string", True, ("typed_bounded", "uncertain", False)),
        ("message", "string", False, ("outbound_payload", "high", False)),
    ),
)
def test_all_scanner_emitted_argument_inference_rows_validate(
    argument_name, argument_type, declared_read_only, expected
):
    tool_name = "read_item"
    schema = {
        "tools": [
            {
                "name": tool_name,
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        argument_name: {"type": argument_type},
                    },
                },
            }
        ]
    }
    controls = None
    if declared_read_only:
        controls = {
            "version": 1,
            "tools": {
                tool_name: {
                    "risk": {
                        "tier": "read_only",
                        "evidence": "declared",
                        "effects": ["reads data"],
                    }
                }
            },
        }
    report = scan_documents([schema], control_declarations=controls)
    argument = report["tools"][0]["arguments"][0]

    assert (
        argument["policy"],
        argument["confidence"],
        argument["review_required"],
    ) == expected
    assert diff_reports(report, copy.deepcopy(report))["summary"]["changes"] == 0


def test_all_scanner_emitted_risk_state_rows_validate(monkeypatch):
    undeclared = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "read_item",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        ]
    )
    declared_clean = _declared_risk_report("read_only")
    conflict = _declared_risk_report("read_only", name="delete_item")

    target = "ｄｅｌｅｔｅ_records"
    monkeypatch.setattr(
        verb_authority,
        "MAX_NFKC_OPERATION_CHARS",
        len(target) - 1,
    )
    inference_limit = _declared_risk_report("read_only", name=target)

    assert undeclared["tools"][0]["risk_source"] == "safe_default"
    assert declared_clean["tools"][0]["risk_source"] == "control_declaration"
    assert conflict["tools"][0]["risk_source"] == "conflict_safe_default"
    assert (
        inference_limit["tools"][0]["risk_inference"]["source"]
        == "inference_limit"
    )
    for report in (undeclared, declared_clean, conflict, inference_limit):
        assert diff_reports(report, copy.deepcopy(report))["summary"]["changes"] == 0


@pytest.mark.parametrize(
    ("field", "forged_value"),
    (
        ("risk", "read_only"),
        ("risk_source", "safe_default"),
        ("risk_evidence", "declared"),
        ("risk_conflict", True),
        ("risk_review_required", True),
        ("needs_confirmation", False),
    ),
)
def test_one_field_risk_tuple_forgery_is_rejected(field, forged_value):
    report = _avp9_report()
    report["tools"][0][field] = forged_value

    with pytest.raises(DiffError, match=f"inconsistent {field}"):
        diff_reports(report, copy.deepcopy(report))


def test_one_field_inferred_risk_forgery_is_rejected():
    report = _avp9_report()
    report["tools"][0]["inferred_risk"] = "write"

    with pytest.raises(DiffError, match="inconsistent risk"):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    ("field", "forged_value", "message"),
    (
        ("source", "inference_limit", "inconsistent risk inference"),
        ("confidence", "uncertain", "inconsistent risk inference"),
        ("mutability", "trusted_party", "invalid risk inference mutability"),
        ("matched_tokens", [], "inconsistent risk inference"),
    ),
)
def test_one_field_risk_inference_forgery_is_rejected(
    field, forged_value, message
):
    report = _avp9_report()
    report["tools"][0]["risk_inference"][field] = forged_value

    with pytest.raises(DiffError, match=message):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    ("field", "message"),
    (
        ("source", "invalid risk inference source"),
        ("confidence", "invalid risk inference confidence"),
    ),
)
def test_risk_inference_vocabulary_is_closed(field, message):
    report = _avp9_report()
    report["tools"][0]["risk_inference"][field] = "arbitrary"

    with pytest.raises(DiffError, match=message):
        diff_reports(report, copy.deepcopy(report))


@pytest.mark.parametrize(
    "summary_field",
    (
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
    ),
)
def test_every_report_summary_counter_is_recomputed(summary_field):
    report = _avp9_report()
    report["summary"][summary_field] += 1

    with pytest.raises(DiffError, match=f"summary.{summary_field}"):
        diff_reports(report, copy.deepcopy(report))


def test_avp9_risk_only_forgery_is_rejected_in_observation_mode(
    tmp_path, capsys
):
    before = _avp9_report()
    after = copy.deepcopy(before)
    after["tools"][0]["risk"] = "read_only"
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(before_path),
                str(after_path),
            ]
        )

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "inconsistent risk" in error
    assert "Traceback" not in error


def test_coherent_effective_risk_changes_always_require_review():
    before = _declared_risk_report("read_only")
    after = _declared_risk_report("write")

    diff = diff_reports(before, after)
    risk_change = next(
        change for change in diff["changes"] if change["kind"] == "tool_risk_changed"
    )

    assert risk_change["classification"] == "review"
    assert diff["summary"]["reviews"] >= 1
    assert diff["summary"]["protection_increases"] == 0


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
        (lambda report: report.update({"report_version": 3}), "legacy report"),
        (_replace_with_invalid_generator_raw_shape, "report-shaped"),
        (_strip_report_header_but_keep_report_tool_markers, "report-shaped"),
    ],
    ids=(
        "missing-generator",
        "missing-version-hybrid",
        "legacy-v2",
        "legacy-v3",
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


def _diff_collision_mcp_tool(name="send_message"):
    return {
        "name": name,
        "inputSchema": {
            "type": "object",
            "properties": {"recipient": {"type": "string"}},
        },
    }


def _diff_collision_openai_function(name="send_message"):
    return {
        "name": name,
        "parameters": {
            "type": "object",
            "properties": {"recipient": {"type": "string"}},
        },
    }


def _diff_collision_envelope(name):
    if name == "sources":
        return [{"id": "source", "tools": [_diff_collision_mcp_tool()]}]
    if name == "result":
        return {"tools": [_diff_collision_mcp_tool()]}
    if name == "tools":
        return [_diff_collision_mcp_tool()]
    if name == "functions":
        return [_diff_collision_openai_function()]
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
def test_diff_loader_rejects_raw_envelope_collisions_in_both_key_orders(
    tmp_path, first, second
):
    document = {
        first: _diff_collision_envelope(first),
        second: _diff_collision_envelope(second),
    }
    path = tmp_path / f"{first}-{second}.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(
        scanner.SchemaError, match="competing tool-definition envelopes"
    ):
        load_report_or_schema(str(path), label="candidate")


def test_diff_loader_accepts_openai_responses_direct_schema(tmp_path):
    document = {
        "tools": [
            {
                "type": "function",
                "name": "set_limit",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "amount": {"type": "number", "maximum": 10}
                    },
                    "required": ["amount"],
                },
            }
        ]
    }
    path = tmp_path / "responses-tools.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    report = load_report_or_schema(str(path), label="candidate")

    assert report["summary"]["tools"] == 1
    assert report["tools"][0]["name"] == "set_limit"
    assert report["tools"][0]["arguments"][0]["name"] == "amount"


@pytest.mark.parametrize(
    "invalid_type",
    ("functoin", 7),
    ids=("misspelled-string", "non-string"),
)
def test_raw_diff_rejects_direct_openai_parameters_with_non_function_type(
    tmp_path, capsys, invalid_type
):
    before = {
        "tools": [
            {
                "type": "function",
                "name": "set_limit",
                "parameters": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}},
                },
            }
        ]
    }
    after = copy.deepcopy(before)
    after["tools"][0]["type"] = invalid_type
    before_path = tmp_path / "before-valid-responses.json"
    after_path = tmp_path / "after-invalid-responses.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main([str(before_path), str(after_path), "--fail-on-review"])

    assert exc_info.value.code == 2
    assert "must use type 'function'" in capsys.readouterr().err


def test_diff_loader_accepts_openai_zero_argument_function(tmp_path):
    document = {
        "tools": [{"type": "function", "name": "read_status"}]
    }
    path = tmp_path / "responses-zero-argument.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    report = load_report_or_schema(str(path), label="candidate")

    assert report["summary"]["tools"] == 1
    assert report["summary"]["parameters"] == 0


def test_diff_loader_rejects_mixed_responses_and_nested_openai_dialects(
    tmp_path,
):
    document = {
        "tools": [
            {
                "type": "function",
                "name": "responses_direct",
                "parameters": {"type": "object"},
                "function": {
                    "name": "chat_nested",
                    "parameters": {"type": "object"},
                },
            }
        ]
    }
    path = tmp_path / "mixed-openai-dialects.json"
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(scanner.SchemaError, match="direct and nested"):
        load_report_or_schema(str(path), label="candidate")


@pytest.mark.parametrize("failure_flag", ("--fail-on-increase", "--fail-on-review"))
def test_diff_cli_rejects_envelope_collision_before_failure_thresholds(
    tmp_path, capsys, failure_flag
):
    before = {"tools": [_diff_collision_mcp_tool()]}
    after = {
        "tools": [_diff_collision_mcp_tool()],
        "functions": [_diff_collision_openai_function()],
    }
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    before_path.write_text(json.dumps(before), encoding="utf-8")
    after_path.write_text(json.dumps(after), encoding="utf-8")

    with pytest.raises(SystemExit) as exc_info:
        main([str(before_path), str(after_path), failure_flag])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "competing tool-definition envelopes" in error
    assert "Traceback" not in error


@pytest.mark.parametrize(
    "malformed_envelope",
    ("tools", "functions", "result.tools", "sources.tools"),
)
def test_malformed_report_containers_never_fall_through_to_raw_diff_scan(
    tmp_path, malformed_envelope
):
    report_tool = copy.deepcopy(
        _single_argument_report({"type": "number", "maximum": 100})["tools"][0]
    )
    valid_tool = _diff_collision_mcp_tool("fallback")
    if malformed_envelope == "tools":
        candidate = {
            "name": valid_tool["name"],
            "inputSchema": valid_tool["inputSchema"],
            "tools": {"reported": report_tool},
        }
    elif malformed_envelope == "functions":
        candidate = {
            "tools": [valid_tool],
            "functions": {"reported": report_tool},
        }
    elif malformed_envelope == "result.tools":
        candidate = {
            "tools": [valid_tool],
            "result": {"tools": {"reported": report_tool}},
        }
    else:
        candidate = {
            "tools": [valid_tool],
            "sources": {
                "source": {"tools": {"reported": report_tool}}
            },
        }
    path = tmp_path / "malformed-report-envelope.json"
    path.write_text(json.dumps(candidate), encoding="utf-8")

    with pytest.raises(DiffError, match="report-shaped"):
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
    ("top-level-list", "tools-envelope", "mcp-result", "atlas-sources"),
)
def test_raw_diff_loader_rejects_report_header_on_collection_entry(
    tmp_path, wrapper
):
    hybrid = _diff_collision_mcp_tool("operate")
    hybrid.update({"generator": "verb-authority", "report_version": 3})
    candidate = _wrap_report_tool(wrapper, hybrid)
    path = tmp_path / f"{wrapper}-report-header-hybrid.json"
    path.write_text(json.dumps(candidate), encoding="utf-8")

    with pytest.raises(DiffError, match="report-shaped"):
        differ.load_raw_schema(str(path), label="candidate")


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
        tool = report["tools"][0]
        tool["name"] = hostile
        inference = verb_authority.infer_risk(hostile)
        tool["inferred_risk"] = inference.risk.value
        tool["risk_inference"] = {
            "source": inference.source,
            "confidence": inference.confidence.value,
            "mutability": inference.mutability,
            "matched_tokens": list(inference.matched_tokens),
        }
        amount = next(
            argument
            for argument in tool["arguments"]
            if argument["name"] == "amount"
        )
        amount["name"] = hostile_argument
    next(
        argument
        for argument in after["tools"][0]["arguments"]
        if argument["name"] == hostile_argument
    )["type"] = hostile_type
    _refresh_report_summary(before)
    _refresh_report_summary(after)

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
    schema = json.loads(
        (FIXTURES / "avp9_nexus_financial_tool.json").read_text(encoding="utf-8")
    )
    controls = json.loads(
        (FIXTURES / "avp9_nexus_financial_controls.json").read_text(
            encoding="utf-8"
        )
    )
    controls["tools"]["purchase_bid"]["risk"]["tier"] = "write"
    after = scan_documents([schema], control_declarations=controls)

    diff = diff_reports(before, after)

    kinds = {item["kind"] for item in diff["changes"]}
    assert "risk_conflict_changed" in kinds
    assert "risk_review_required_changed" in kinds
    assert "tool_risk_changed" in kinds
    assert diff["summary"]["reviews"] >= 3


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
    _refresh_report_summary(after)

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


def test_more_caller_controlled_bounds_cannot_replace_one_immutable_bound():
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


@pytest.mark.parametrize(
    "thresholds",
    (
        ("--fail-on-increase",),
        ("--fail-on-review",),
        ("--fail-on-increase", "--fail-on-review"),
    ),
)
@pytest.mark.parametrize("report_side", ("before", "after"))
def test_failure_thresholds_require_locally_rescanned_raw_schemas(
    tmp_path, capsys, thresholds, report_side
):
    raw = _constraint_document(100, 40, ["safe"])
    report = scan_documents([raw])
    before_path = tmp_path / "before.json"
    after_path = tmp_path / "after.json"
    output_path = tmp_path / "diff.json"
    before_path.write_text(
        json.dumps(report if report_side == "before" else raw),
        encoding="utf-8",
    )
    after_path.write_text(
        json.dumps(report if report_side == "after" else raw),
        encoding="utf-8",
    )

    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(before_path),
                str(after_path),
                "--format",
                "json",
                "--output",
                str(output_path),
                *thresholds,
            ]
        )

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "report-shaped" in error
    assert "failure thresholds require raw schema inputs" in error
    assert "Traceback" not in error
    assert not output_path.exists()


@pytest.mark.parametrize("duplicate_side", ["before", "after"])
def test_imported_v3_rejects_duplicate_exact_bounds(duplicate_side):
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

    with pytest.raises(DiffError, match="duplicate declared bound"):
        diff_reports(before, after)


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


def test_enforced_protective_bound_replacement_requires_review():
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


def test_impossible_confirmation_removal_is_rejected_before_ci_thresholds():
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

    with pytest.raises(DiffError, match="inconsistent needs_confirmation"):
        diff_reports(before, after)


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


def test_clearing_schema_review_requirement_still_requires_review(tmp_path):
    document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "$ref": "#/$defs/missing",
                },
            }
        ]
    }
    before = scan_documents([document])
    after = copy.deepcopy(before)
    assert before["tools"][0]["schema_review_required"] is True
    after["tools"][0]["schema_review_required"] = False
    after["summary"]["schema_review_required_tools"] = 0
    _refresh_report_summary(after)

    diff = diff_reports(before, after)
    change = next(
        item
        for item in diff["changes"]
        if item["kind"] == "schema_review_requirement_changed"
    )
    assert change["classification"] == "review"
    assert diff["summary"]["reviews"] == 1
    assert diff["summary"]["protection_increases"] == 0

    before_path = tmp_path / "before-report.json"
    after_path = tmp_path / "after-report.json"
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
        ]
    ) == 0
    rendered = json.loads(output_path.read_text(encoding="utf-8"))
    assert rendered["summary"]["reviews"] == 1
    assert rendered["summary"]["protection_increases"] == 0


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


@pytest.mark.parametrize("tool_count", (1, 2))
def test_v3_schema_review_fields_are_mandatory_and_require_rescan(
    tmp_path, capsys, tool_count
):
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": f"set_value_{index}",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "$ref": "#/$defs/missing",
                        },
                    }
                    for index in range(tool_count)
                ]
            }
        ]
    )
    forged = copy.deepcopy(report)
    forged["summary"].pop("schema_review_required_tools")
    for tool in forged["tools"]:
        tool.pop("schema_review_required")

    with pytest.raises(DiffError, match="missing .*schema_review_required.*rescan"):
        diff_reports(report, forged)

    before_path = tmp_path / "before-report.json"
    after_path = tmp_path / "after-report.json"
    before_path.write_text(json.dumps(report), encoding="utf-8")
    after_path.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        main(
            [
                str(before_path),
                str(after_path),
            ]
        )

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "schema_review_required" in error
    assert "rescan" in error
    assert "Traceback" not in error


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
