"""Pure SQLite example checks; no application, database, or runtime execution."""

import ast
from copy import deepcopy
import importlib.util
import json
from pathlib import Path

import pytest


EXAMPLE = Path(__file__).resolve().parent / "examples" / "sqlite-change-trial"


@pytest.fixture(scope="module")
def comparison():
    path = EXAMPLE / "integration-change-check" / "comparison.py"
    spec = importlib.util.spec_from_file_location("sqlite_example_comparison", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def render_summary():
    # Load only display definitions: importing the runner would also alter sys.path.
    path = EXAMPLE / "sqlite-change-check" / "check_sqlite.py"
    source = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    names = {"_summary_text", "_summary_rows", "_summary_details", "summary"}
    functions = [node for node in source.body
                 if isinstance(node, ast.FunctionDef) and node.name in names]
    assert {node.name for node in functions} == names
    workflow = next(node.value for node in source.body
                    if isinstance(node, ast.Assign)
                    and any(isinstance(target, ast.Name) and target.id == "WORKFLOW"
                            for target in node.targets))
    namespace = {"json": json, "WORKFLOW": ast.literal_eval(workflow)}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec"), namespace)
    return namespace["summary"]


@pytest.fixture
def report():
    before = {"tables": [["tickets", "table"]], "rows": [
        {"tenant": "oak", "ticket_id": "17", "text": "Original request"},
        {"tenant": "pine", "ticket_id": "17", "text": "Other request"},
    ]}
    expected = deepcopy(before)
    expected["rows"][0]["text"] = "Requested update"
    observed = deepcopy(expected)
    observed["rows"][1]["text"] = "Unexpected overwrite"
    return {
        "status": "incomplete", "root": "example-evidence", "errors": ["comparison interrupted"],
        "runs": {"candidate": {
            "status": "incomplete", "source": "candidate_app.py", "config_path": "candidate.json",
            "errors": ["worker exited early"], "rows": [{
                "id": "edit", "database": "candidate/case.sqlite",
                "app_result": None, "expected_result": "ok",
                "before": before, "expected_after": expected, "after": observed,
                "error": "RuntimeError: stopped after commit",
                "verdict": {"status": "incomplete", "failures": ["unexpected_database_effect"],
                            "gaps": ["application_exception"]},
            }],
        }},
    }


@pytest.mark.parametrize("baseline,candidate,expected", [
    ("pass", "pass", "pass"),
    ("pass", "fail", "regression"),
    ("pass", "incomplete", "incomplete"),
    ("fail", "pass", "incomplete"),
    ("fail", "fail", "incomplete"),
])
def test_classifier_verdicts_and_failed_baseline(comparison, baseline, candidate, expected):
    assert comparison.classify_comparison(baseline, candidate) == expected
    assert comparison.EXIT_CODES == {"pass": 0, "regression": 1, "incomplete": 2}


@pytest.mark.parametrize("invalid", ["unknown", None, ["pass"]])
def test_unknown_and_malformed_statuses_are_incomplete(comparison, invalid):
    assert comparison.classify_comparison(invalid, "pass") == "incomplete"
    assert comparison.classify_comparison("pass", invalid) == "incomplete"


def test_uncertainty_and_malformed_flags_are_incomplete(comparison):
    for flags in ({"comparable": False}, {"incomplete": True},
                  {"comparable": 1}, {"incomplete": "false"}):
        assert comparison.classify_comparison("pass", "pass", **flags) == "incomplete"


def test_incomplete_summary_retains_committed_changes_and_errors(render_summary, report):
    original = deepcopy(report)
    output = render_summary(report)
    assert output.startswith("INCOMPLETE: tenant-ticket-update/v1\ncandidate: incomplete\n")
    assert 'Row {"tenant": "oak", "ticket_id": "17"}' in output
    assert ('before text "Original request"; expected text "Requested update"; '
            'observed text "Requested update"') in output
    assert 'Row {"tenant": "pine", "ticket_id": "17"}' in output
    assert ('before text "Other request"; expected text "Other request"; '
            'observed text "Unexpected overwrite"') in output
    for evidence in ("unexpected_database_effect", "application_exception",
                     "RuntimeError: stopped after commit", "worker exited early",
                     "comparison interrupted", "candidate/case.sqlite"):
        assert evidence in output
    assert report == original


@pytest.mark.parametrize("snapshot", [
    None,
    {"tables": [["tickets", "table"]], "rows": [{"tenant": "oak"}]},
])
def test_missing_or_malformed_observation_is_unavailable(render_summary, report, snapshot):
    row = report["runs"]["candidate"]["rows"][0]
    row["after"] = snapshot
    row["observation_error"] = "observation unavailable"
    output = render_summary(report)
    assert "Row details unavailable: missing or malformed expected/observed snapshot." in output
    assert "observation unavailable" in output
    assert 'Row {"tenant"' not in output


def test_summary_escapes_terminal_controls_without_mutation(render_summary, report):
    hostile = "visible\n\r\t\x1b[31m\x00\u202e"
    run = report["runs"].pop("candidate")
    report["runs"]["candidate" + hostile] = run
    report["root"] = run["source"] = run["config_path"] = hostile
    row = run["rows"][0]
    row["id"] = row["database"] = row["error"] = hostile
    row["after"]["rows"][1]["tenant"] = hostile
    row["after"]["rows"][1]["text"] = hostile
    original = deepcopy(report)
    output = render_summary(report)
    escaped = json.dumps(hostile, ensure_ascii=True)
    assert "candidate" + escaped[1:-1] + ": incomplete" in output
    for prefix in ("Evidence directory: ", "source: ", "config: ", '"case": ',
                   "Database evidence: ", '"tenant": ', "observed text ", '"error": '):
        assert prefix + escaped in output
    assert hostile not in output
    assert all(character == "\n" or 32 <= ord(character) < 127 for character in output)
    assert report == original
