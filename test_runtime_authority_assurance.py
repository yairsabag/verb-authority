"""Internal inert probes for the guarded runtime authority boundary."""

import pytest

from verb_authority import (
    GuardedToolRunner,
    Param,
    Registry,
    Risk,
    Tool,
    build_policy,
)


def _runner(param, calls, *, risk=Risk.READ_ONLY):
    registry = Registry()

    def handler(value):
        calls.append(value)
        return {"received": value}

    registry.add(Tool("apply_value", [param], fn=handler, risk=risk))
    return GuardedToolRunner(registry, build_policy(registry))


def test_nested_protected_mismatch_never_enters_handler():
    calls = []
    runner = _runner(Param("value", "json", sink=True), calls)

    result = runner.run(
        {
            "name": "apply_value",
            "input": {"value": {"route": ["safe", {"tenant": "changed"}]}},
        },
        trusted_args={
            "value": {"route": ["safe", {"tenant": "approved"}]}
        },
    )

    assert not result.invoked and not result.executed
    assert "locked sink" in result.decision.reason
    assert calls == []


def test_nested_protected_exact_match_reaches_handler_once():
    calls = []
    runner = _runner(Param("value", "json", sink=True), calls)
    approved = {"route": ["safe", {"tenant": "approved"}]}

    result = runner.run(
        {"name": "apply_value", "input": {"value": approved}},
        trusted_args={"value": approved},
    )

    assert result.invoked and result.executed
    assert calls == [approved]


@pytest.mark.parametrize(
    "malformed",
    [
        {"route": float("nan")},
        {1: "non-string-key"},
    ],
)
def test_malformed_protected_json_fails_before_handler(malformed):
    calls = []
    runner = _runner(Param("value", "json", sink=True), calls)

    result = runner.run(
        {"name": "apply_value", "input": {"value": malformed}},
        trusted_args={"value": malformed},
    )

    assert not result.invoked and not result.executed
    assert calls == []


def test_aliased_plain_python_graph_fails_before_handler():
    calls = []
    runner = _runner(Param("value", "json", sink=True), calls)
    shared = {"tenant": "approved"}
    aliased = [shared, shared]

    result = runner.run(
        {"name": "apply_value", "input": {"value": aliased}},
        trusted_args={"value": [{"tenant": "approved"}, {"tenant": "approved"}]},
    )

    assert not result.invoked and not result.executed
    assert calls == []


def test_trusted_provenance_does_not_waive_numeric_cap():
    calls = []
    runner = _runner(Param("value", "integer", cap=10, sink=True), calls)

    result = runner.run(
        {"name": "apply_value", "input": {"value": 11}},
        trusted_args={"value": 11},
    )

    assert not result.invoked and not result.executed
    assert "type/bounds" in result.decision.reason
    assert calls == []


def test_confirmation_cannot_swap_snapshotted_protected_value():
    calls = []
    runner = _runner(
        Param("value", "json", sink=True), calls, risk=Risk.FINANCIAL
    )
    tool_call = {
        "name": "apply_value",
        "input": {"value": {"tenant": "approved"}},
    }
    trusted = {"value": {"tenant": "approved"}}

    def confirm(_request):
        tool_call["input"]["value"]["tenant"] = "changed"
        trusted["value"]["tenant"] = "changed"
        return True

    result = runner.run(tool_call, trusted_args=trusted, confirm=confirm)

    assert result.invoked and result.executed
    assert calls == [{"tenant": "approved"}]


def test_truthy_non_boolean_confirmation_does_not_invoke():
    calls = []
    runner = _runner(
        Param("value", "string", sink=True), calls, risk=Risk.FINANCIAL
    )

    result = runner.run(
        {"name": "apply_value", "input": {"value": "approved"}},
        trusted_args={"value": "approved"},
        confirm=lambda _request: 1,
    )

    assert not result.invoked and not result.executed
    assert calls == []
