import copy
import json
from pathlib import Path

import pytest

import verb_authority
from verb_authority_diff import DiffError, diff_reports, main, render_text
from verb_authority_scan import scan_documents


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


def test_avp9_constrained_amount_becoming_free_is_an_authority_increase():
    before = _avp9_report()
    after = copy.deepcopy(before)
    arguments = after["declared_controls"]["tools"][0]["arguments"]
    bid = next(argument for argument in arguments if argument["name"] == "bidWei")
    bid["authority"] = "free"
    bid.pop("bounds")

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
    tool["arguments"].append(
        {
            "name": "destination",
            "type": "string",
            "required": True,
            "policy": "trusted_fixed",
            "confidence": "high",
            "review_required": False,
            "reason": "authority-bearing name",
        }
    )
    declared_tool = after["declared_controls"]["tools"][0]
    declared_tool["unexposed_arguments"] = []
    declared_tool["arguments"].append(
        {
            "name": "destination",
            "schema_exposure": "exposed",
            "inferred_policy": "trusted_fixed",
            "review_required": False,
            "authority": "locked",
            "evidence": "declared",
        }
    )

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


def test_immutable_bound_becoming_caller_controlled_is_flagged():
    before = _avp9_report()
    after = copy.deepcopy(before)
    arguments = after["declared_controls"]["tools"][0]["arguments"]
    bid = next(argument for argument in arguments if argument["name"] == "bidWei")
    bid["bounds"][-1]["bounds_mutability"] = "caller"

    diff = diff_reports(before, after)

    bound_change = next(
        change for change in diff["changes"] if change["kind"] == "bounds_changed"
    )
    assert bound_change["classification"] == "authority_increase"
    assert "caller-controlled" in bound_change["message"]


def test_new_tool_and_removed_confirmation_fail_the_ci_threshold():
    before = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "pay_invoice",
                        "inputSchema": {"properties": {"amount": {"type": "integer"}}},
                    }
                ]
            }
        ]
    )
    after = copy.deepcopy(before)
    after["tools"][0]["needs_confirmation"] = False
    after["tools"].append(
        {
            "name": "send_message",
            "risk": "write",
            "needs_confirmation": False,
            "annotation_conflicts": [],
            "arguments": [],
        }
    )

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
