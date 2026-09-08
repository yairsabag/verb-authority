"""Regression checks for the executable, inert authority comparison."""

from copy import deepcopy
import json
from pathlib import Path
import subprocess
import sys

import pytest

import authority_assurance_demo as demo
from verb_authority import Decision, ExecutionResult


SCRIPT = Path(demo.__file__).resolve()


def test_json_cli_is_deterministic_and_contains_observed_evidence():
    command = [sys.executable, str(SCRIPT), "--json"]
    first = subprocess.run(command, check=True, text=True, capture_output=True)
    second = subprocess.run(command, check=True, text=True, capture_output=True)
    assert first.stdout == second.stdout
    report = json.loads(first.stdout)
    assert report["checks_passed"] is True
    assert "legitimate input therefore differs" in report["interface_comparison"]
    assert "not a live-model attack success rate" in report["scope"]
    assert len(report["records"]) == 96
    assert {record["workflow"] for record in report["records"]} == {
        "send_email", "update_service_ticket", "update_deployment",
    }
    assert all({"submitted_input", "trusted_args", "decision",
                "handler_entry_count", "observed_arguments"} <= record.keys()
               for record in report["records"])


def test_readable_cli_and_optimized_cli_execute_real_checks():
    readable = subprocess.run([sys.executable, str(SCRIPT)], check=True,
                              text=True, capture_output=True)
    optimized = subprocess.run([sys.executable, "-O", str(SCRIPT), "--json"],
                               check=True, text=True, capture_output=True)
    assert "All 96 arm checks passed" in readable.stdout
    assert "server_injection: BLOCK; 0; []" in readable.stdout
    assert json.loads(optimized.stdout)["checks_passed"] is True


@pytest.mark.parametrize("workflow", demo.WORKFLOWS, ids=lambda workflow: workflow.name)
def test_independent_protected_values_and_projected_legitimate_controls(workflow):
    cases = {case.name: case for case in demo.cases_for(workflow)}
    for field, changed in workflow.changed:
        case = cases[f"changed_{field}"]
        naive = demo.run_case(workflow, case, "no_gate")
        assert naive["observed_arguments"][0][field] == changed
        assert naive["observed_arguments"][0][field] != dict(workflow.protected)[field]
        for arm in ("verb_authority", "server_injection"):
            record = demo.run_case(workflow, case, arm)
            assert record["handler_entry_count"] == 0
            assert record["observed_arguments"] == []
    for name in ("legitimate", "benign_payload_change", "attacklike_payload_only"):
        for arm in demo.ARMS:
            record = demo.run_case(workflow, cases[name], arm)
            assert record["handler_entry_count"] == 1
            for field, expected in workflow.protected:
                assert record["observed_arguments"][0][field] == expected
            expected_fields = ({workflow.payload} if arm == "server_injection"
                               else set(cases[name].arguments))
            assert set(record["submitted_input"]["input"]) == expected_fields


@pytest.mark.parametrize("workflow", demo.WORKFLOWS, ids=lambda workflow: workflow.name)
def test_stale_call_has_real_previous_entry_and_new_independent_host_binding(workflow):
    case = next(case for case in demo.cases_for(workflow)
                if case.name == "stale_previous_target")
    for arm in demo.ARMS:
        record = demo.run_case(workflow, case, arm)
        assert record["previous_call"]["handler_entry_count"] == 1
        assert record["previous_call"]["trusted_args"] == dict(workflow.protected)
        assert record["trusted_args"] == dict(workflow.next_protected)
        assert record["handler_entry_count"] == (1 if arm == "no_gate" else 0)


@pytest.mark.parametrize("mutation", ["bypass_gate", "block_everything", "fake_execution"])
def test_cli_returns_failure_for_broken_runtime(monkeypatch, capsys, mutation):
    def broken_run(self, call, **kwargs):
        if mutation == "block_everything":
            return ExecutionResult(Decision(False, "broken blanket denial"), executed=False)
        if mutation == "bypass_gate":
            self.registry.tools[call["name"]].fn(**call["input"])
        return ExecutionResult(Decision(True, "broken success claim"),
                               executed=True, invoked=True)

    monkeypatch.setattr(demo.GuardedToolRunner, "run", broken_run)
    assert demo.main(["--json"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "FAILED:" in captured.err


def test_observed_arguments_oracle_rejects_a_wrong_destination():
    workflow = demo.WORKFLOWS[0]
    case = demo.cases_for(workflow)[0]
    record = demo.run_case(workflow, case, "verb_authority")
    corrupted = deepcopy(record)
    corrupted["observed_arguments"][0]["to"] = "outsider@external.test"
    with pytest.raises(AssertionError, match="actual handler arguments"):
        demo.verify_record(workflow, "verb_authority", case.name, corrupted,
                           True, case.arguments)


def test_noop_injection_cannot_claim_success(monkeypatch):
    monkeypatch.setattr(demo, "dispatch_injection", lambda *args: (True, "no-op"))
    with pytest.raises(AssertionError, match="handler entries"):
        demo.run_demo()


def test_optimized_process_exits_nonzero_for_fake_execution():
    code = """
import authority_assurance_demo as demo
from verb_authority import Decision, ExecutionResult
demo.GuardedToolRunner.run = lambda *args, **kwargs: ExecutionResult(
    Decision(True, "fake success"), executed=True, invoked=True
)
raise SystemExit(demo.main(["--json"]))
"""
    result = subprocess.run([sys.executable, "-O", "-c", code], cwd=SCRIPT.parent,
                            text=True, capture_output=True)
    assert result.returncode == 1
    assert result.stdout == ""
    assert "FAILED: send_email/legitimate/verb_authority: handler entries" in result.stderr


def test_structural_alternative_never_constructs_or_calls_a_va_runner(monkeypatch):
    def unexpected_runner(*args, **kwargs):
        raise AssertionError("VA runner must not be used by no-VA arms")

    monkeypatch.setattr(demo, "GuardedToolRunner", unexpected_runner)
    for workflow in demo.WORKFLOWS:
        for case in demo.cases_for(workflow):
            for arm in ("no_gate", "server_injection"):
                demo.run_case(workflow, case, arm)
