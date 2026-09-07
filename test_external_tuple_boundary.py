"""Maintainer-derived regression; never execute or rewrite the frozen runner.

The oracle below is test-only business policy, deliberately outside the scanner.
It is not a runtime authorization implementation or a real payment integration.
"""

import copy
import hashlib
import json
import shutil
from pathlib import Path

import pytest

import verb_authority_scan as scanner


ROOT = Path(__file__).resolve().parent
FROZEN = ROOT / "fixtures/external/larry-peseckis/tuple-boundary/frozen"
# Maintainer pin of the complete contribution at beb5ad0e01f6, not a claim
# that the contributor preregistered this manifest before the historical runs.
FROZEN_HASHES = dict(
    line.split(maxsplit=1)[::-1]
    for line in """
3d5753784c702b7ca28457368aa16102f511785bd1e9956c23be2c9f4b12a316 LICENSE-NOTE.txt
ec3b0c1fbb548b30985dc0918ead5f9d43aed4ab308d9f72eb297955163b7a59 SHA256SUMS-fixture.txt
960e9f4a05b7c61b673ebf3dcf82de722dec36b04ab9f89ba8453c21995bf4ec fixture/EXPECTED.md
b5a27e47146d7316151bfb8f52a2e10152fa1817f81299e6ebdf30e48690945f fixture/cases.json
eba92873b401590d9ae97aa2c26bdf7db6b0717dbfd72431cf658a862d253f20 fixture/controls.json
ca897b3f8ce9dd6f44bdec3d7a6d7be2ba0a56c989b0828e9a3099f418f86189 fixture/policy.json
b11f1e927c3b83f6462b67034b1f9fd582367043c60dc98d648ebc51e6499427 fixture/tools.json
9c8c28dc92792dffdbf6ecd6e226420831ea024246cb1253d0456291ac2edd8e runner.py
bd5e2963b404ebbe0afd3e62a6a9624ee08c455325cee505e6a09f5d6502e506 runs/beta.10/BOUNDARY-ASSESSMENT.md
4744dc6830c4c5a3962de66485dbf24404c6520d02ef9796b929cfb043cf6666 runs/beta.10/COMMANDS.txt
32799f8b62b8c951873038477bab0a27bbda9352c16b7fea9786e1a0c19cd854 runs/beta.10/authority-report.json
e0ce39571d9de35e9f18c56fc013eb5a4de08cde49fc04e409e4049a2f67bf7d runs/beta.10/boundary-results.json
2e2e91ce3bac57af7d046608dba890869ea4e622102b92599bb330135f390ddb runs/beta.10/fixture-input-hashes.txt
bc3cfd3138c3dfd44fde3f0098575181a8fdee01586ff883c7aa9cfff6103c8c runs/beta.10/installed-version.txt
bd5e2963b404ebbe0afd3e62a6a9624ee08c455325cee505e6a09f5d6502e506 runs/beta.6/BOUNDARY-ASSESSMENT.md
ad66696efaa9edc095a7567d2c482ad17fcdb31590cc091d8462b76dc467433a runs/beta.6/authority-report.json
5216f8983920cd75fc27a091b8f3419c51dadb3aad87f5a3d378bab4c86e3d07 runs/beta.6/boundary-results.json
902bbb4b3eec17e35bf25ef79d30c93e1efa88cf9110e47072837c75869252df runs/beta.6/checksums.sha256
""".strip().splitlines()
)
EXPECTED_CASES = {
    "A": ("ALLOW", "R1"),
    "B": ("DENY", None),
    "C": ("DENY", None),
    "D": ("ALLOW", "R2"),
}
NOTICE = (
    "Control declarations are supplied by the report author. Their evidence "
    "labels and operational statuses are preserved but are not independently "
    "verified by this scanner."
)


def _verify_frozen(directory):
    assert directory.is_dir() and not directory.is_symlink()
    for entry in directory.rglob("*"):
        assert not entry.is_symlink(), str(entry)
    assert {
        path.relative_to(directory).as_posix()
        for path in directory.rglob("*") if path.is_file()
    } == set(FROZEN_HASHES)
    for name, expected in FROZEN_HASHES.items():
        actual = hashlib.sha256((directory / name).read_bytes()).hexdigest()
        assert actual == expected, f"frozen bytes changed: {name}"


@pytest.fixture(scope="module")
def frozen():
    if not FROZEN.exists():
        assert not (ROOT / ".git").exists(), "frozen evidence missing from repository"
        pytest.skip("external frozen evidence is repository-only")
    _verify_frozen(FROZEN)
    return FROZEN


def _read(frozen, name):
    return json.loads((frozen / name).read_text(encoding="utf-8-sig"))


def test_frozen_bundle_is_intact(frozen):
    _verify_frozen(frozen)


@pytest.mark.parametrize("name", [
    "fixture/tools.json", "runner.py", "runs/beta.10/boundary-results.json",
])
def test_frozen_pin_rejects_mutation(frozen, tmp_path, name):
    duplicate = tmp_path / "frozen"
    shutil.copytree(frozen, duplicate)
    path = duplicate / name
    path.write_bytes(path.read_bytes() + b"\n")
    with pytest.raises(AssertionError, match="frozen bytes changed"):
        _verify_frozen(duplicate)


@pytest.mark.parametrize("case_id", EXPECTED_CASES)
def test_individually_valid_fields_do_not_authorize_a_tuple(frozen, case_id):
    # Validate only the fixed, hashed schema's vocabulary, not arbitrary JSON Schema.
    tool, = _read(frozen, "fixture/tools.json")["tools"]
    schema = tool["inputSchema"]
    cases = _read(frozen, "fixture/cases.json")["cases"]
    assert [case["id"] for case in cases] == list(EXPECTED_CASES)
    case = next(case for case in cases if case["id"] == case_id)
    values = case["input"]
    assert schema["additionalProperties"] is False
    assert set(values) == set(schema["required"]) == set(schema["properties"])
    for name, value in values.items():
        field = schema["properties"][name]
        if field["type"] == "number":
            assert type(value) in (int, float)
            assert field["minimum"] <= value <= field["maximum"]
        else:
            assert field["type"] == "string" and type(value) is str
            assert value in field["enum"]

    # This separate fixture oracle never enters scan_documents or a tool handler.
    policy = _read(frozen, "fixture/policy.json")
    matches = [rule["id"] for rule in policy["rules"] if
               all(values[key] == rule[key] for key in ("account", "recipient", "purpose"))
               and values["amount"] <= rule["max_amount"]]
    assert len(matches) <= 1
    actual = ("ALLOW", matches[0]) if matches else ("DENY", None)
    assert actual == EXPECTED_CASES[case_id]
    assert (case["expected_action_instance_authorization"], case["expected_rule"]) == actual


@pytest.mark.parametrize("version, report_version", [("beta.6", 2), ("beta.10", 3)])
def test_historical_summaries_match_preserved_reports(frozen, version, report_version):
    report = _read(frozen, f"runs/{version}/authority-report.json")
    recorded = _read(frozen, f"runs/{version}/boundary-results.json")
    summary = recorded["scanner"]["summary"]
    tool, = report["tools"]
    assert report["report_version"] == summary["report_version"] == report_version
    assert tool["name"] == "submit_payment" and summary["tool_found"] is True
    assert tool["risk"] == summary["effective_risk"] == "financial"
    assert tool["needs_confirmation"] is summary["needs_confirmation"] is True
    expected = dict.fromkeys(("account", "recipient", "amount", "purpose"), "typed_bounded")
    if version == "beta.10":
        expected.update(account="trusted_fixed", recipient="trusted_fixed")
    assert {arg["name"]: arg["policy"] for arg in tool["arguments"]} == expected
    assert summary["inferred_argument_policy"] == expected
    assert report["declared_controls"]["verification_notice"] == NOTICE
    assert {case["id"]: (case["oracle_result"], case["oracle_rule"])
            for case in recorded["cases"]} == EXPECTED_CASES
    assert all(case["schema_valid"] is True for case in recorded["cases"])


def _assert_current_report(report):
    assert report["report_version"] == scanner.REPORT_VERSION == 6
    assert report["generator"] == "verb-authority"
    tool, = report["tools"]
    assert tool["name"] == "submit_payment"
    assert tool["risk"] == "financial"
    assert tool["risk_source"] == "control_declaration"
    assert tool["needs_confirmation"] is True
    assert tool["review_required"] is True
    assert tool["review_sources"]["arguments"] == ["amount", "purpose"]
    assert {arg["name"]: (arg["policy"], arg["confidence"], arg["review_required"])
            for arg in tool["arguments"]} == {
        "account": ("trusted_fixed", "high", False),
        "recipient": ("trusted_fixed", "high", False),
        "amount": ("trusted_fixed", "uncertain", True),
        "purpose": ("trusted_fixed", "uncertain", True),
    }
    assert report["summary"]["protected_parameters"] == 4
    assert report["summary"]["data_fillable_parameters"] == 0
    assert report["summary"]["review_required"] == 2
    assert report["declared_controls"]["verification_notice"] == NOTICE
    assert report["privacy"]["runtime_values_included"] is False
    assert report["privacy"]["server_executed"] is False


def test_current_scanner_preserves_review_and_interpretation_boundary(frozen):
    report = scanner.scan_documents(
        [_read(frozen, "fixture/tools.json")],
        control_declarations=_read(frozen, "fixture/controls.json"),
    )
    _assert_current_report(report)
    markdown = scanner.render_markdown(report)
    assert "## Interpretation boundary" in markdown
    assert "does not prove\nthat the surrounding application supplies correct provenance or authorization" in markdown
    assert "not independently verified" in markdown


@pytest.mark.parametrize("mutation", ["empty", "missing_tool", "relaxed_amount"])
def test_current_report_assertions_reject_false_passes(frozen, mutation):
    report = scanner.scan_documents(
        [_read(frozen, "fixture/tools.json")],
        control_declarations=_read(frozen, "fixture/controls.json"),
    )
    broken = copy.deepcopy(report)
    if mutation == "empty":
        broken = {}
    elif mutation == "missing_tool":
        broken["tools"] = []
    else:
        amount = next(arg for arg in broken["tools"][0]["arguments"] if arg["name"] == "amount")
        amount["policy"] = "typed_bounded"
    with pytest.raises((AssertionError, KeyError, ValueError)):
        _assert_current_report(broken)


@pytest.mark.parametrize("output_format", ["json", "markdown"])
def test_cli_review_threshold_is_not_an_authorization_verdict(frozen, tmp_path, output_format):
    output = tmp_path / "current-report"
    args = [str(frozen / "fixture/tools.json"), "--controls",
            str(frozen / "fixture/controls.json"), "--format", output_format,
            "--output", str(output)]
    assert scanner.main(args) == 0  # Successful report generation, not permission.
    ordinary = output.read_bytes()
    output.unlink()
    assert scanner.main([*args, "--fail-on-review"]) == 2
    assert output.read_bytes() == ordinary
    if output_format == "json":
        _assert_current_report(json.loads(ordinary))
