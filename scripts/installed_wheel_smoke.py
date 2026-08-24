"""Installed-wheel audit smoke for the beta.8 release boundary.

Run this copy from outside the source checkout after installing the wheel. The
checks intentionally repeat all audited blocker families, then exercise the
report-format migration and the diff CLI's release threshold.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import importlib.metadata
import inspect
import io
import json
import os
import subprocess
import sys
import threading
import types
from dataclasses import FrozenInstanceError
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any

import verb_authority
import verb_authority_diff
import verb_authority_scan
from verb_authority import (
    Confidence,
    GuardedToolRunner,
    Param,
    Policy,
    Registry,
    Risk,
    Tool,
    build_policy,
    dispatch,
    infer_policy,
)
from verb_authority_diff import DIFF_VERSION, DiffError, diff_reports
from verb_authority_scan import REPORT_VERSION, render_markdown, scan_documents


def _check(condition: Any, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _constraint_document(
    maximum: int, max_length: int, enum: list[str]
) -> dict[str, Any]:
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
                    "required": ["amount", "message", "mode"],
                },
            }
        ]
    }


def _installed_identity(
    expected_version: str, forbidden_roots: tuple[Path, ...]
) -> None:
    distribution = importlib.metadata.distribution("verb-authority")
    installed_version = distribution.version
    _check(
        installed_version == expected_version,
        f"installed version {installed_version!r} != {expected_version!r}",
    )
    distribution_root = Path(distribution.locate_file("")).resolve()
    for module in (verb_authority, verb_authority_scan, verb_authority_diff):
        location = Path(module.__file__).resolve()
        _check(
            location.is_relative_to(distribution_root),
            f"{module.__name__} is outside installed distribution root: {location}",
        )
        for forbidden_root in forbidden_roots:
            _check(
                not location.is_relative_to(forbidden_root),
                f"{module.__name__} imported from forbidden source root: {location}",
            )
    _check(REPORT_VERSION == 3, "installed scanner is not report v3")
    _check(DIFF_VERSION == 2, "installed Authority Diff is not diff v2")


def _plain_dict_boundary() -> None:
    class HiddenItems(dict):
        def items(self):
            return {}.items()

    registry = Registry()
    registry.add(
        Tool(
            "set_limit",
            [Param("amount", "number", cap=100)],
            risk=Risk.WRITE,
        )
    )
    hidden_input = HiddenItems(amount=10**9, unknown_argument="attacker-authored")
    call = {"name": "set_limit", "input": hidden_input}
    decision = dispatch(
        registry,
        build_policy(registry),
        call,
    )
    _check(
        not decision.allow,
        "dict-subclass input hid an invalid bound and unknown argument",
    )


def _trusted_fixed_validation() -> None:
    cases = (
        (Param("value", "string", sink=True), {"hidden": "route"}, "type"),
        (Param("value", "integer", cap=10, sink=True), 11, "cap"),
        (Param("value", "enum", enum=["safe"], sink=True), "unsafe", "enum"),
    )
    for param, value, boundary in cases:
        registry = Registry()
        registry.add(Tool("set_value", [param], risk=Risk.WRITE))
        decision = dispatch(
            registry,
            build_policy(registry),
            {"name": "set_value", "input": {"value": value}},
            trusted_args={"value": value},
        )
        _check(
            not decision.allow and "type/bounds" in decision.reason,
            f"trusted_fixed value bypassed its declared {boundary} boundary",
        )


def _serialized_policy_runtime_boundary() -> None:
    def operate(amount):
        return {"amount": amount}

    registry = Registry()
    registry.add(
        Tool(
            "operate",
            [Param("amount", "integer", cap=10, sink=False)],
            fn=operate,
            risk=Risk.FINANCIAL,
        )
    )
    policy = build_policy(registry)
    policy.policy["operate"]["amount"] = Policy.TYPED_BOUNDED.value
    policy.risk["operate"] = Risk.FINANCIAL.value
    call = {"name": "operate", "input": {"amount": 7}}
    gated = verb_authority.gate(
        registry,
        policy,
        "operate",
        {"amount": 7},
        {"amount": "data"},
    )
    dispatched = dispatch(registry, policy, call)
    stopped = GuardedToolRunner(registry, policy).run(
        call,
        confirm=lambda request: False,
    )
    _check(
        gated.allow
        and gated.needs_confirm
        and dispatched.allow
        and dispatched.needs_confirm
        and not stopped.invoked
        and stopped.decision.needs_confirm,
        "valid serialized policy/risk values diverged across runtime APIs",
    )

    for field in ("policy", "risk"):
        malformed = build_policy(registry)
        if field == "policy":
            malformed.policy["operate"]["amount"] = "not-a-policy"
        else:
            malformed.risk["operate"] = "not-a-risk"
        direct_decisions = (
            verb_authority.gate(
                registry,
                malformed,
                "operate",
                {"amount": 7},
                {"amount": "data"},
            ),
            dispatch(registry, malformed, call),
        )
        _check(
            all(
                not decision.allow and "policy is malformed" in decision.reason
                for decision in direct_decisions
            ),
            f"malformed serialized {field} escaped a direct API",
        )
        try:
            GuardedToolRunner(registry, malformed)
        except (TypeError, ValueError):
            pass
        else:
            raise AssertionError(
                f"guarded runner accepted malformed serialized {field}"
            )


def _authority_name_precedence() -> None:
    cases = (
        (Param("account_id", "integer"), 17, Confidence.HIGH, False),
        (Param("reply_to", "string"), "approved-thread", Confidence.HIGH, False),
        (
            Param("message_id", "string"),
            "approved-message",
            Confidence.UNCERTAIN,
            True,
        ),
    )
    for param, value, expected_confidence, expected_review in cases:
        inferred, confidence = infer_policy(param)
        _check(
            inferred is Policy.TRUSTED_FIXED
            and confidence is expected_confidence,
            f"authority selector {param.name!r} was relaxed by a broad rule",
        )
        registry = Registry()
        registry.add(Tool("write_selection", [param], risk=Risk.WRITE))
        policy = build_policy(registry)
        in_review = ("write_selection", param.name) in policy.review
        decision = dispatch(
            registry,
            policy,
            {"name": "write_selection", "input": {param.name: value}},
        )
        _check(
            in_review is expected_review
            and not decision.allow
            and "locked sink" in decision.reason,
            f"authority selector {param.name!r} silently accepted data",
        )


def _exact_authority_and_action_identity() -> None:
    registry = Registry()
    registry.add(
        Tool(
            "set_value",
            [Param("value", "json", sink=True)],
            risk=Risk.WRITE,
        )
    )
    for proposed, trusted in (
        (0.0, -0.0),
        ({"first": 1, "second": 2}, {"second": 2, "first": 1}),
    ):
        decision = dispatch(
            registry,
            build_policy(registry),
            {"name": "set_value", "input": {"value": proposed}},
            trusted_args={"value": trusted},
        )
        _check(
            not decision.allow and "locked sink" in decision.reason,
            "observable JSON differences shared trusted authority",
        )

    registry = Registry()
    registry.add(
        Tool(
            "commit_value",
            [Param("value", "json", sink=False)],
            fn=lambda value: value,
            risk=Risk.FINANCIAL,
        )
    )
    runner = GuardedToolRunner(registry)

    def capture(value):
        requests = []
        result = runner.run(
            {"name": "commit_value", "input": {"value": value}},
            confirm=lambda request: requests.append(request) or False,
        )
        _check(
            not result.invoked and len(requests) == 1,
            "exact action did not stop at confirmation",
        )
        return requests[0]

    positive_zero = capture(0.0)
    negative_zero = capture(-0.0)
    first_order = capture({"first": 1, "second": 2})
    second_order = capture({"second": 2, "first": 1})
    _check(
        positive_zero.arguments_json != negative_zero.arguments_json
        and positive_zero.action_id != negative_zero.action_id
        and first_order.arguments_json != second_order.arguments_json
        and first_order.action_id != second_order.action_id,
        "confirmation identity collapsed signed zero or object order",
    )


def _registry_replacement_drift() -> None:
    calls: list[tuple[str, str]] = []

    def safe(destination: str) -> None:
        calls.append(("safe", destination))

    def destructive(destination: str) -> None:
        calls.append(("destructive", destination))

    registry = Registry()
    registry.add(
        Tool(
            "lookup_record",
            [Param("destination", sink=False)],
            fn=safe,
            risk=Risk.READ_ONLY,
        )
    )
    runner = GuardedToolRunner(registry)
    registry.add(
        Tool(
            "lookup_record",
            [Param("destination", sink=True)],
            fn=destructive,
            risk=Risk.DESTRUCTIVE,
        )
    )
    result = runner.run(
        {"name": "lookup_record", "input": {"destination": "attacker"}}
    )
    _check(not result.executed and not calls, "stale registration executed")
    _check(
        "registry changed" in result.decision.reason,
        "registry replacement did not produce drift denial",
    )


def _forged_callable_metadata_denial() -> None:
    def implementation(hidden_destination="acct-attacker", **kwargs):
        return {"hidden_destination": hidden_destination, **kwargs}

    implementation.__signature__ = inspect.Signature(
        [
            inspect.Parameter(
                "value",
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
    )
    registry = Registry()
    registry.add(
        Tool(
            "set_value",
            [Param("value", sink=False)],
            fn=implementation,
            risk=Risk.WRITE,
        )
    )
    try:
        GuardedToolRunner(registry)
    except TypeError as exc:
        _check(
            "cannot define __signature__" in str(exc),
            "forged __signature__ was rejected for an unexpected reason",
        )
    else:
        raise AssertionError("forged __signature__ hid callable authority")

    def advertised(value):
        return value

    def wrapped_implementation(hidden_destination="acct-attacker", **kwargs):
        return {"hidden_destination": hidden_destination, **kwargs}

    wrapped_implementation.__wrapped__ = advertised
    registry = Registry()
    registry.add(
        Tool(
            "set_value",
            [Param("value", sink=False)],
            fn=wrapped_implementation,
            risk=Risk.WRITE,
        )
    )
    try:
        GuardedToolRunner(registry)
    except ValueError as exc:
        _check(
            "undeclared params: hidden_destination" in str(exc),
            "__wrapped__ metadata was rejected for an unexpected reason",
        )
    else:
        raise AssertionError("__wrapped__ hid the raw callable signature")


def _callable_binding_and_code_drift() -> None:
    calls: list[tuple[str, str]] = []

    def approved(destination: str) -> str:
        calls.append(("approved", destination))
        return destination

    registry = Registry()
    tool = Tool(
        "transfer_funds",
        [Param("destination", sink=True)],
        fn=approved,
        risk=Risk.FINANCIAL,
    )
    registry.add(tool)
    runner = GuardedToolRunner(registry)

    def replace_with_same_code(request) -> bool:
        tool.fn = types.FunctionType(
            approved.__code__,
            approved.__globals__,
            name=approved.__name__,
            argdefs=approved.__defaults__,
            closure=approved.__closure__,
        )
        return True

    result = runner.run(
        {
            "name": "transfer_funds",
            "input": {"destination": "acct-approved"},
        },
        trusted_args={"destination": "acct-approved"},
        confirm=replace_with_same_code,
    )
    _check(
        not result.invoked
        and not result.executed
        and "registry changed" in result.decision.reason
        and not calls,
        "same-code replacement escaped the private callable binding",
    )

    def replacement(destination: str) -> str:
        calls.append(("replacement", destination))
        return destination

    registry = Registry()
    registry.add(
        Tool(
            "transfer_funds",
            [Param("destination", sink=True)],
            fn=approved,
            risk=Risk.FINANCIAL,
        )
    )
    runner = GuardedToolRunner(registry)

    def replace_code(request) -> bool:
        approved.__code__ = replacement.__code__
        return True

    result = runner.run(
        {
            "name": "transfer_funds",
            "input": {"destination": "acct-approved"},
        },
        trusted_args={"destination": "acct-approved"},
        confirm=replace_code,
    )
    _check(
        not result.invoked
        and not result.executed
        and "registry changed" in result.decision.reason
        and not calls,
        "callable __code__ drift reached invocation",
    )


def _confirmation_action_snapshot() -> None:
    executed: list[tuple[str, int, str]] = []
    observed = []
    call = {
        "name": "transfer_funds",
        "input": {
            "destination": "acct-approved",
            "amount": 1_000_000,
            "memo": "שלום",
        },
    }

    def transfer(destination: str, amount: int, memo: str) -> None:
        executed.append((destination, amount, memo))

    registry = Registry()
    registry.add(
        Tool(
            "transfer_funds",
            [
                Param("destination", sink=True),
                Param("amount", "number"),
                Param("memo", "string", sink=False),
            ],
            fn=transfer,
            risk=Risk.FINANCIAL,
        )
    )
    runner = GuardedToolRunner(registry)

    def confirm(request) -> bool:
        call["input"]["amount"] = 1
        observed.append(request)
        return True

    result = runner.run(
        call,
        trusted_args={"destination": "acct-approved"},
        confirm=confirm,
    )
    _check(result.executed, "approved private action did not execute")
    _check(
        executed == [("acct-approved", 1_000_000, "שלום")],
        "callback mutation changed the executed action",
    )
    _check(len(observed) == 1, "confirmation request was not delivered exactly once")
    request = observed[0]
    _check(
        json.loads(request.arguments_json)
        == {
            "amount": 1_000_000,
            "destination": "acct-approved",
            "memo": "שלום",
        },
        "confirmation did not expose the approved argument snapshot",
    )
    _check(
        "שלום" not in request.arguments_json and "\\u05e9" in request.arguments_json,
        "confirmation arguments_json is not ASCII-escaped JSON",
    )
    _check(
        request.risk is Risk.FINANCIAL
        and request.risk_assessment.risk is Risk.FINANCIAL,
        "confirmation omitted effective risk evidence",
    )
    _check(
        all(
            (
                request.registration_id,
                request.executable_id,
                request.action_id,
            )
        ),
        "confirmation omitted action identity commitments",
    )
    try:
        request.arguments_json = "{}"
    except (FrozenInstanceError, AttributeError):
        pass
    else:
        raise AssertionError("confirmation request is mutable")


def _bidi_confirmation_snapshot() -> None:
    registry = Registry()
    registry.add(
        Tool(
            "transfer_funds",
            [Param("destination", sink=True)],
            fn=lambda destination: destination,
            risk=Risk.FINANCIAL,
        )
    )
    runner = GuardedToolRunner(registry)
    destination = "acct-\u202e\u00e9"
    requests = []
    result = runner.run(
        {
            "name": "transfer_funds",
            "input": {"destination": destination},
        },
        trusted_args={"destination": destination},
        confirm=lambda request: requests.append(request) or False,
    )
    _check(
        not result.invoked and not result.executed and len(requests) == 1,
        "BiDi-bearing action did not stop at confirmation",
    )
    arguments_json = requests[0].arguments_json
    _check(
        arguments_json.isascii()
        and "\\u202e" in arguments_json
        and "\\u00e9" in arguments_json
        and json.loads(arguments_json) == {"destination": destination},
        "confirmation snapshot exposed raw BiDi or non-ASCII display text",
    )


def _implicit_default_denial() -> None:
    calls: list[dict[str, str]] = []
    application_default = {"account": "approved"}

    def transfer(destination: dict[str, str] = application_default) -> None:
        calls.append(destination)

    registry = Registry()
    registry.add(
        Tool(
            "transfer_funds",
            [Param("destination", sink=True, required=False)],
            fn=transfer,
            risk=Risk.FINANCIAL,
        )
    )
    confirmations = []
    result = GuardedToolRunner(registry).run(
        {"name": "transfer_funds", "input": {}},
        confirm=lambda request: confirmations.append(request) or True,
    )
    _check(
        not result.invoked and not result.executed,
        "implicit protected default reached the callable",
    )
    _check(not calls and not confirmations, "default denial happened after approval")
    _check(
        "optional default" in result.decision.reason,
        "implicit default was not rejected by the explicit-value contract",
    )


def _numeric_result_taint() -> None:
    writes: list[int] = []

    def read_account() -> dict[str, dict[str, int]]:
        return {"nested": {"account_id": 31337}}

    def set_account(account_id: int) -> None:
        writes.append(account_id)

    registry = Registry()
    registry.add(
        Tool("read_account", [], fn=read_account, risk=Risk.READ_ONLY)
    )
    registry.add(
        Tool(
            "set_account",
            [Param("account_id", "integer", sink=True)],
            fn=set_account,
            risk=Risk.WRITE,
        )
    )
    runner = GuardedToolRunner(registry)
    read = runner.run({"name": "read_account", "input": {}})
    _check(read.executed and read.invoked, "plain JSON read did not complete")
    value = read.result["nested"]["account_id"]
    _check(runner.ledger.is_tainted(value), "numeric result leaf was not tainted")
    write = runner.run(
        {"name": "set_account", "input": {"account_id": value}},
        trusted_args={"account_id": value},
    )
    _check(not write.executed and not writes, "numeric tool result reached locked sink")


def _object_key_and_container_taint() -> None:
    writes = []

    def read_accounts():
        return {"acct-attacker": {"balance": 100}}

    def set_account(account_id):
        writes.append(account_id)

    registry = Registry()
    registry.add(
        Tool("read_accounts", [], fn=read_accounts, risk=Risk.READ_ONLY)
    )
    registry.add(
        Tool(
            "set_account",
            [Param("account_id", sink=True)],
            fn=set_account,
            risk=Risk.WRITE,
        )
    )
    runner = GuardedToolRunner(registry)
    read = runner.run({"name": "read_accounts", "input": {}})
    account_id = next(iter(read.result))
    _check(
        runner.ledger.is_tainted(account_id),
        "plain object key was not tracked as an exact result value",
    )
    write = runner.run(
        {"name": "set_account", "input": {"account_id": account_id}},
        trusted_args={"account_id": account_id},
    )
    _check(
        not write.invoked and not write.executed and not writes,
        "plain object key reached a locked sink",
    )

    for returned in ({}, [], {"route": []}, {"route": {}}):
        ledger = verb_authority.ProvenanceLedger()
        ledger.record_result({"result": returned})
        _check(
            ledger.is_tainted(returned),
            "empty or container-only exact result was not tracked",
        )


def _json_depth_integer_and_result_boundaries() -> None:
    def nested_lists(count, leaf="value"):
        value = leaf
        for _ in range(count):
            value = [value]
        return value

    calls = []

    def consume(payload):
        calls.append(payload)
        return None

    registry = Registry()
    registry.add(
        Tool(
            "consume",
            [Param("payload", "json", sink=False)],
            fn=consume,
            risk=Risk.READ_ONLY,
        )
    )
    runner = GuardedToolRunner(registry)
    overdeep = nested_lists(verb_authority.MAX_JSON_DEPTH + 500)
    result = runner.run(
        {"name": "consume", "input": {"payload": overdeep}}
    )
    _check(
        not result.invoked and not result.executed and not calls,
        "overdeep input escaped the bounded JSON snapshot",
    )

    deep_result = nested_lists(verb_authority.MAX_JSON_DEPTH + 500)

    def read_deep():
        return deep_result

    registry = Registry()
    registry.add(
        Tool("read_deep", [], fn=read_deep, risk=Risk.READ_ONLY)
    )
    result = GuardedToolRunner(registry).run(
        {"name": "read_deep", "input": {}}
    )
    _check(
        result.invoked
        and not result.executed
        and result.contract_violation == "unsupported_result",
        "overdeep result escaped instead of becoming unsupported_result",
    )

    confirmations = []
    registry = Registry()
    registry.add(
        Tool(
            "transfer",
            [Param("amount", "integer", sink=False)],
            fn=lambda amount: amount,
            risk=Risk.FINANCIAL,
        )
    )
    result = GuardedToolRunner(registry).run(
        {"name": "transfer", "input": {"amount": 10**5000}},
        confirm=lambda request: confirmations.append(request) or True,
    )
    _check(
        not result.invoked and not result.executed and not confirmations,
        "oversized integer reached confirmation serialization",
    )

    registry = Registry()
    registry.add(
        Tool(
            "choose",
            [Param("mode", "enum", enum=["safe"], sink=False)],
            fn=lambda mode: mode,
            risk=Risk.READ_ONLY,
        )
    )
    result = GuardedToolRunner(registry).run(
        {"name": "choose", "input": {"mode": 10**5000}}
    )
    _check(
        not result.invoked and not result.executed,
        "oversized enum candidate escaped as an encoder exception",
    )


def _graph_and_ledger_resource_boundaries() -> None:
    calls = []

    def shared_dag(count):
        value = {"leaf": "value"}
        for _ in range(count):
            value = [value, value]
        return value

    registry = Registry()
    registry.add(
        Tool(
            "consume",
            [Param("payload", "json", sink=False)],
            fn=lambda payload: calls.append(payload),
            risk=Risk.READ_ONLY,
        )
    )
    result = GuardedToolRunner(registry).run(
        {
            "name": "consume",
            "input": {"payload": shared_dag(30)},
        }
    )
    _check(
        not result.invoked and not result.executed and not calls,
        "compact shared DAG expanded across the plain-JSON boundary",
    )

    original_node_limit = verb_authority.MAX_JSON_NODES
    original_snapshot_byte_limit = verb_authority.MAX_JSON_MATERIAL_BYTES
    try:
        verb_authority.MAX_JSON_NODES = 64
        repeated = [0] * 1_000
        result = GuardedToolRunner(registry).run(
            {"name": "consume", "input": {"payload": repeated}}
        )
        _check(
            not result.invoked and not result.executed and not calls,
            "repeated input scalars evaded the total snapshot-node budget",
        )

        invocations = []
        result_registry = Registry()
        result_registry.add(
            Tool(
                "read_value",
                [],
                fn=lambda: invocations.append("invoked") or repeated,
                risk=Risk.READ_ONLY,
            )
        )
        result = GuardedToolRunner(result_registry).run(
            {"name": "read_value", "input": {}}
        )
        _check(
            result.invoked
            and not result.executed
            and result.contract_violation == "unsupported_result"
            and "do not retry" in result.decision.reason
            and invocations == ["invoked"],
            "oversized result lost snapshot/no-retry telemetry",
        )

        verb_authority.MAX_JSON_NODES = 4
        verb_authority.MAX_JSON_MATERIAL_BYTES = 17
        _check(
            verb_authority._snapshot_json_value([{"a": "é"}])
            == [{"a": "é"}],
            "ordinary JSON failed exactly at the documented snapshot bounds",
        )
        verb_authority.MAX_JSON_MATERIAL_BYTES = 8
        try:
            verb_authority._snapshot_json_value("é" * 100_000)
        except ValueError as exc:
            _check(
                "serialized-material limit" in str(exc),
                "oversized text failed for an unexpected reason",
            )
        else:
            raise AssertionError("one oversized string evaded the snapshot budget")
    finally:
        verb_authority.MAX_JSON_NODES = original_node_limit
        verb_authority.MAX_JSON_MATERIAL_BYTES = original_snapshot_byte_limit

    original_byte_limit = verb_authority.MAX_LEDGER_UTF8_BYTES
    try:
        verb_authority.MAX_LEDGER_UTF8_BYTES = 32
        invocations = []
        registry = Registry()
        registry.add(
            Tool(
                "read_value",
                [],
                fn=lambda: invocations.append("invoked") or "x" * 64,
                risk=Risk.READ_ONLY,
            )
        )
        runner = GuardedToolRunner(registry)
        first = runner.run({"name": "read_value", "input": {}})
        second = runner.run({"name": "read_value", "input": {}})
        _check(
            first.invoked
            and not first.executed
            and first.contract_violation == "ledger_capacity_exceeded"
            and "do not retry" in first.decision.reason,
            "ledger overflow lost invoked/no-retry telemetry",
        )
        _check(
            not second.invoked
            and not second.executed
            and "start a new session" in second.decision.reason
            and invocations == ["invoked"],
            "saturated ledger did not deny every later invocation",
        )
    finally:
        verb_authority.MAX_LEDGER_UTF8_BYTES = original_byte_limit


def _policy_and_ledger_integrity() -> None:
    registry = Registry()
    registry.add(
        Tool(
            "transfer_funds",
            [Param("destination", sink=True)],
            fn=lambda destination: destination,
            risk=Risk.FINANCIAL,
        )
    )
    policy = build_policy(registry)
    policy.confirm.clear()
    try:
        GuardedToolRunner(registry, policy)
    except ValueError:
        pass
    else:
        raise AssertionError("mutated PolicySet removed required confirmation")

    try:
        verb_authority.ProvenanceLedger(_tainted=set())
    except TypeError:
        pass
    else:
        raise AssertionError("ledger accepted caller-injected private storage")

    ledger = verb_authority.ProvenanceLedger()
    runner = GuardedToolRunner(registry, ledger=ledger)
    ledger._tainted = set()
    result = runner.run(
        {
            "name": "transfer_funds",
            "input": {"destination": "acct-approved"},
        },
        trusted_args={"destination": "acct-approved"},
    )
    _check(
        not result.invoked
        and "ledger internals changed" in result.decision.reason,
        "runner did not detect replacement of a ledger private store",
    )


def _ledger_invocation_serialization() -> None:
    entered = threading.Event()
    release = threading.Event()
    record_started = threading.Event()
    record_done = threading.Event()
    executions = []

    def implementation(destination: str) -> dict[str, str]:
        entered.set()
        _check(release.wait(2), "timed out releasing the guarded invocation")
        return {"destination": destination}

    registry = Registry()
    registry.add(
        Tool(
            "set_destination",
            [Param("destination", sink=True)],
            fn=implementation,
            risk=Risk.WRITE,
        )
    )
    runner = GuardedToolRunner(registry)

    def invoke() -> None:
        executions.append(
            runner.run(
                {
                    "name": "set_destination",
                    "input": {"destination": "acct-approved"},
                },
                trusted_args={"destination": "acct-approved"},
            )
        )

    def record_concurrently() -> None:
        record_started.set()
        runner.ledger.record_result("acct-approved")
        record_done.set()

    invocation_thread = threading.Thread(target=invoke)
    writer_thread = threading.Thread(target=record_concurrently)
    invocation_thread.start()
    _check(entered.wait(2), "guarded invocation did not start")
    writer_thread.start()
    _check(record_started.wait(2), "concurrent ledger writer did not start")
    try:
        _check(
            not record_done.wait(0.1),
            "concurrent ledger write slipped through during invocation",
        )
    finally:
        release.set()
    invocation_thread.join(2)
    writer_thread.join(2)
    _check(
        not invocation_thread.is_alive()
        and not writer_thread.is_alive()
        and record_done.is_set(),
        "serialized invocation or ledger writer did not terminate",
    )
    _check(
        len(executions) == 1 and executions[0].executed,
        "serialized guarded invocation did not publish exactly once",
    )


def _async_rejection() -> None:
    async def read_message() -> dict[str, str]:
        return {"reply_to": "attacker@evil.example"}

    registry = Registry()
    registry.add(
        Tool("read_message", [], fn=read_message, risk=Risk.READ_ONLY)
    )
    result = GuardedToolRunner(registry).run(
        {"name": "read_message", "input": {}}
    )
    _check(
        not result.invoked and not result.executed and not result.decision.allow,
        "async implementation crossed the synchronous boundary",
    )
    _check("async" in result.decision.reason, "async rejection reason is absent")

    async def eventual_result() -> dict[str, str]:
        return {"reply_to": "attacker@evil.example"}

    awaitable = eventual_result()

    def returns_awaitable():
        return awaitable

    registry = Registry()
    registry.add(
        Tool("read_message", [], fn=returns_awaitable, risk=Risk.READ_ONLY)
    )
    result = GuardedToolRunner(registry).run(
        {"name": "read_message", "input": {}}
    )
    _check(
        result.invoked and not result.executed,
        "awaitable result did not preserve invoked/executed distinction",
    )
    _check(
        result.contract_violation == "awaitable_result",
        "awaitable result omitted its contract-violation code",
    )
    _check(awaitable.cr_frame is None, "rejected coroutine result was not closed")

    effects = []

    class HostileResult:
        def __await__(self):
            effects.append("await hook ran")
            if False:
                yield None

        @property
        def __class__(self):
            effects.append("class spoof read")
            raise RuntimeError("must not be inspected")

        def close(self):
            effects.append("close hook ran")

        def aclose(self):
            effects.append("aclose hook ran")

    registry = Registry()
    registry.add(
        Tool(
            "read_message",
            [],
            fn=lambda: HostileResult(),
            risk=Risk.READ_ONLY,
        )
    )
    result = GuardedToolRunner(registry).run(
        {"name": "read_message", "input": {}}
    )
    _check(
        result.invoked
        and not result.executed
        and result.contract_violation == "unsupported_result"
        and not effects,
        "rejected result triggered class/close/aclose protocol hooks",
    )

    async def stream_messages():
        yield {"reply_to": "attacker@evil.example"}

    registry = Registry()
    registry.add(
        Tool("read_message", [], fn=stream_messages, risk=Risk.READ_ONLY)
    )
    result = GuardedToolRunner(registry).run(
        {"name": "read_message", "input": {}}
    )
    _check(
        not result.invoked and not result.executed and not result.decision.allow,
        "async-generator implementation crossed the synchronous boundary",
    )

    def raises_private_exception():
        raise RuntimeError("private tool implementation detail")

    registry = Registry()
    registry.add(
        Tool(
            "read_message",
            [],
            fn=raises_private_exception,
            risk=Risk.READ_ONLY,
        )
    )
    result = GuardedToolRunner(registry).run(
        {"name": "read_message", "input": {}}
    )
    _check(
        result.invoked
        and not result.executed
        and result.result is None
        and result.contract_violation == "invocation_exception",
        "ordinary invocation exception did not become a failed ExecutionResult",
    )
    _check(
        "private tool implementation detail" not in result.decision.reason,
        "invocation exception details leaked into the generic denial",
    )


def _unicode_homograph_rejection() -> None:
    registry = Registry()
    registry.add(
        Tool(
            "send_value",
            [Param("destination", sink=True)],
            risk=Risk.WRITE,
        )
    )
    destination = {"route": {"\uff41\u0501min@example.com": True}}
    decision = dispatch(
        registry,
        build_policy(registry),
        {"name": "send_value", "input": {"destination": destination}},
        trusted_args={"destination": destination},
    )
    _check(not decision.allow, "extended/full-width homograph reached locked sink")
    _check("homograph" in decision.reason, "homograph rejection reason is absent")


def _constraint_diff_and_migration() -> None:
    before_document = _constraint_document(100, 40, ["safe"])
    after_document = _constraint_document(
        10**12, 10**9, ["safe", "unrestricted"]
    )
    before = scan_documents([before_document])
    after = scan_documents([after_document])
    _check(before["report_version"] == 3, "scanner did not produce report v3")
    privacy = before["privacy"]
    _check(
        privacy["examples_included"] is False
        and privacy["defaults_included"] is False
        and privacy["runtime_values_included"] is False
        and "examples_or_values_included" not in privacy,
        "report v3 privacy fields do not separately exclude values",
    )
    _check(
        privacy["schema_material_fingerprints_included"] is True
        and privacy["schema_material_fingerprints_dictionary_guessable"] is True
        and privacy["unmodeled_schema_fingerprints_included"] is True
        and privacy["schema_fingerprint_material_scope"]
        == "full_validation_material_excluding_annotations",
        "named report privacy does not describe exact schema commitments",
    )
    _check(
        before["schema_fingerprint_sha256"]
        != after["schema_fingerprint_sha256"],
        "constraint widening did not change the schema fingerprint",
    )
    arguments = {
        argument["name"]: argument
        for argument in before["tools"][0]["arguments"]
    }
    _check(
        "schema_material_fingerprint_sha256" in before["tools"][0]
        and "unmodeled_schema_fingerprint_sha256" in before["tools"][0]
        and all(
            "schema_material_fingerprint_sha256" in argument
            and "unmodeled_schema_fingerprint_sha256" in argument
            for argument in arguments.values()
        ),
        "named report omitted exact tool/argument schema fingerprints",
    )
    _check(
        arguments["amount"]["constraints"] == {"maximum": 100},
        "named report omitted exact maximum",
    )
    _check(
        arguments["message"]["constraints"] == {"max_length": 40},
        "named report omitted exact maxLength",
    )
    enum = arguments["mode"]["constraints"]["enum"]
    _check(
        enum["count"] == 1
        and len(enum["value_fingerprints_sha256"]) == 1,
        "named report omitted enum fingerprints",
    )
    diff = diff_reports(before, after)
    _check(diff["diff_version"] == 2, "constraint comparison is not diff v2")
    _check(
        diff["summary"]["authority_increases"] == 3,
        "three simultaneous constraint widenings were not all reported",
    )
    _check(
        all(change["classification"] == "authority_increase" for change in diff["changes"]),
        "a constraint widening was not classified as an authority increase",
    )

    def residual_document(minimum: int) -> dict[str, Any]:
        return {
            "tools": [
                {
                    "name": "set_value",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "value": {
                                "type": "number",
                                "minimum": minimum,
                            }
                        },
                    },
                }
            ]
        }

    def residual_report(minimum: int) -> dict[str, Any]:
        return scan_documents([residual_document(minimum)])

    residual = diff_reports(residual_report(0), residual_report(-(10**12)))
    _check(
        residual["summary"]["changes"] == 1
        and residual["summary"]["reviews"] == 1
        and residual["changes"][0]["kind"] == "unmodeled_schema_changed"
        and residual["changes"][0]["classification"] == "review",
        "unmodeled validation widening did not require one explicit review",
    )

    redacted_before = scan_documents([before_document], redact_names=True)
    redacted_after = scan_documents([after_document], redact_names=True)
    redacted_privacy = redacted_before["privacy"]
    _check(
        redacted_privacy["schema_material_fingerprints_included"] is False
        and redacted_privacy["schema_material_fingerprints_dictionary_guessable"]
        is False
        and redacted_privacy["unmodeled_schema_fingerprints_included"] is False
        and redacted_privacy["schema_fingerprint_material_scope"]
        == "modeled_presence_and_enum_count_only",
        "redacted report privacy does not declare its shape-only scope",
    )
    _check(
        "schema_material_fingerprint_sha256" not in redacted_before["tools"][0]
        and all(
            "schema_material_fingerprint_sha256" not in argument
            and "unmodeled_schema_fingerprint_sha256" not in argument
            for argument in redacted_before["tools"][0]["arguments"]
        ),
        "redacted report retained exact schema fingerprints",
    )
    redacted_constraints = [
        argument.get("constraints")
        for argument in redacted_before["tools"][0]["arguments"]
    ]
    _check(
        redacted_constraints
        == [
            {"maximum_present": True},
            {"max_length_present": True},
            {"enum": {"count": 1, "values_redacted": True}},
        ],
        "redacted report disclosed more than shape/presence/count",
    )
    _check(
        redacted_before["schema_fingerprint_sha256"]
        != redacted_after["schema_fingerprint_sha256"],
        "redacted enum-count widening was not committed",
    )

    legacy = copy.deepcopy(before)
    legacy["report_version"] = 2
    for argument in legacy["tools"][0]["arguments"]:
        argument.pop("constraints", None)
    try:
        diff_reports(legacy, copy.deepcopy(legacy))
    except DiffError as exc:
        _check("rescan" in str(exc), "legacy report rejection omitted rescan guidance")
    else:
        raise AssertionError("legacy report v2 was compared as if lossless")

    with TemporaryDirectory(prefix="verb-authority-wheel-smoke-") as directory:
        root = Path(directory)
        before_path = root / "before.json"
        after_path = root / "after.json"
        output_path = root / "diff.json"
        before_path.write_text(json.dumps(before_document), encoding="utf-8")
        after_path.write_text(json.dumps(after_document), encoding="utf-8")
        exit_code = verb_authority_diff.main(
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
        _check(exit_code == 2, "diff CLI did not fail on authority increase")
        rendered = json.loads(output_path.read_text(encoding="utf-8"))
        _check(
            rendered["summary"]["authority_increases"] == 3,
            "diff CLI output lost simultaneous constraint widenings",
        )

        residual_before_path = root / "residual-before.json"
        residual_after_path = root / "residual-after.json"
        residual_output_path = root / "residual-diff.json"
        residual_before_path.write_text(
            json.dumps(residual_document(0)), encoding="utf-8"
        )
        residual_after_path.write_text(
            json.dumps(residual_document(-(10**12))), encoding="utf-8"
        )
        increase_only_exit = verb_authority_diff.main(
            [
                str(residual_before_path),
                str(residual_after_path),
                "--format",
                "json",
                "--output",
                str(residual_output_path),
                "--fail-on-increase",
            ]
        )
        _check(
            increase_only_exit == 0,
            "review-only drift incorrectly tripped the authority-increase threshold",
        )
        child_env = os.environ.copy()
        child_env.pop("PYTHONPATH", None)
        child_env.pop("PYTHONHOME", None)
        review_process = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "verb_authority",
                "diff",
                str(residual_before_path),
                str(residual_after_path),
                "--format",
                "json",
                "--output",
                str(residual_output_path),
                "--fail-on-review",
            ],
            check=False,
            capture_output=True,
            env=child_env,
            text=True,
        )
        _check(
            review_process.returncode == 2,
            "installed diff CLI did not fail on unmodeled REVIEW: "
            f"{review_process.stderr.strip()}",
        )
        residual_rendered = json.loads(
            residual_output_path.read_text(encoding="utf-8")
        )
        _check(
            residual_rendered["summary"]["reviews"] == 1
            and residual_rendered["changes"][0]["kind"]
            == "unmodeled_schema_changed",
            "diff CLI review threshold output lost unmodeled schema drift",
        )


def _scanner_resource_boundaries() -> None:
    limit_names = (
        "MAX_SCAN_INPUT_BYTES",
        "MAX_SCAN_JSON_NODES",
        "MAX_SCAN_JSON_MATERIAL_BYTES",
        "MAX_SCAN_TOOL_DEFINITIONS",
        "MAX_SCAN_ARGUMENTS",
        "MAX_SCAN_ENUM_MEMBERS",
        "MAX_SCAN_CONTROL_COLLECTION_MEMBERS",
    )
    original_limits = {
        name: getattr(verb_authority_scan, name) for name in limit_names
    }

    def restore_limits() -> None:
        for name, value in original_limits.items():
            setattr(verb_authority_scan, name, value)

    def expect_schema_error(callback: Any, expected: str) -> None:
        try:
            callback()
        except verb_authority_scan.SchemaError as exc:
            _check(expected in str(exc), f"unexpected scanner error: {exc}")
        else:
            raise AssertionError(f"installed scanner did not enforce {expected}")

    try:
        verb_authority_scan.MAX_SCAN_JSON_NODES = 3
        verb_authority_scan.validate_plain_json([0, 1])
        verb_authority_scan.MAX_SCAN_JSON_NODES = 2
        expect_schema_error(
            lambda: verb_authority_scan.validate_plain_json([0, 1]),
            "total node limit",
        )

        restore_limits()
        verb_authority_scan.MAX_SCAN_JSON_MATERIAL_BYTES = 6
        verb_authority_scan.validate_plain_json("abc")
        verb_authority_scan.MAX_SCAN_JSON_MATERIAL_BYTES = 5
        expect_schema_error(
            lambda: verb_authority_scan.validate_plain_json("abc"),
            "material limit",
        )

        restore_limits()
        two_tools = {
            "tools": [
                {"name": "first", "inputSchema": {}},
                {"name": "second", "inputSchema": {}},
            ]
        }
        definitions = verb_authority_scan.parse_tool_definitions(two_tools)
        verb_authority_scan.MAX_SCAN_TOOL_DEFINITIONS = 1
        expect_schema_error(
            lambda: verb_authority_scan.parse_tool_definitions(two_tools),
            "tool-definition limit",
        )
        expect_schema_error(
            lambda: verb_authority_scan.scan_definitions(definitions),
            "tool-definition limit",
        )
        expect_schema_error(
            lambda: scan_documents(
                [
                    {"tools": [two_tools["tools"][0]]},
                    {"tools": [two_tools["tools"][1]]},
                ]
            ),
            "tool-definition limit",
        )

        restore_limits()
        two_arguments = {
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
        argument_definitions = verb_authority_scan.parse_tool_definitions(
            two_arguments
        )
        verb_authority_scan.MAX_SCAN_ARGUMENTS = 1
        expect_schema_error(
            lambda: verb_authority_scan.parse_tool_definitions(two_arguments),
            "argument limit",
        )
        expect_schema_error(
            lambda: verb_authority_scan.scan_definitions(argument_definitions),
            "argument limit",
        )
        expect_schema_error(
            lambda: scan_documents([two_arguments]), "argument limit"
        )

        restore_limits()
        enum_document = {
            "tools": [
                {
                    "name": "choose",
                    "inputSchema": {
                        "properties": {
                            "mode": {
                                "type": "string",
                                "enum": ["a", "b"],
                            }
                        }
                    },
                }
            ]
        }
        verb_authority_scan.MAX_SCAN_ENUM_MEMBERS = 2
        scan_documents([enum_document])
        verb_authority_scan.MAX_SCAN_ENUM_MEMBERS = 1
        expect_schema_error(
            lambda: scan_documents([enum_document]), "enum-member limit"
        )

        restore_limits()
        controls = {
            "version": 1,
            "tools": {
                "choose": {
                    "risk": {
                        "tier": "write",
                        "evidence": "declared",
                        "effects": ["changes_mode"],
                    },
                    "arguments": {
                        "mode": {
                            "authority": "constrained",
                            "evidence": "declared",
                            "bounds": [
                                {
                                    "source": "approved modes",
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
        verb_authority_scan.MAX_SCAN_ARGUMENTS = 1
        expect_schema_error(
            lambda: scan_documents(
                [enum_document], control_declarations=controls
            ),
            "argument limit",
        )
        restore_limits()
        verb_authority_scan.MAX_SCAN_CONTROL_COLLECTION_MEMBERS = 1
        expect_schema_error(
            lambda: scan_documents(
                [enum_document], control_declarations=controls
            ),
            "control collection-member limit",
        )

        restore_limits()
        report = scan_documents(
            [{"tools": [{"name": "read", "inputSchema": {}}]}]
        )
        verb_authority_scan.MAX_SCAN_JSON_NODES = 10
        try:
            diff_reports(report, copy.deepcopy(report))
        except DiffError as exc:
            _check(
                "total node limit" in str(exc),
                f"unexpected installed diff resource error: {exc}",
            )
        else:
            raise AssertionError("installed diff indexed an over-budget report")

        restore_limits()
        with TemporaryDirectory(prefix="verb-authority-wheel-budget-") as directory:
            root = Path(directory)
            tiny_path = root / "tiny.json"
            tiny_path.write_text('{"x":0}', encoding="utf-8")
            verb_authority_scan.MAX_SCAN_INPUT_BYTES = 7
            verb_authority_scan.load_json_path(str(tiny_path))
            verb_authority_scan.MAX_SCAN_INPUT_BYTES = 6
            expect_schema_error(
                lambda: verb_authority_scan.load_json_path(str(tiny_path)),
                "UTF-8 input limit",
            )

            schema_path = root / "too-many-arguments.json"
            schema_path.write_text(json.dumps(two_arguments), encoding="utf-8")
            restore_limits()
            verb_authority_scan.MAX_SCAN_ARGUMENTS = 1
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    verb_authority_scan.main(
                        [str(schema_path), "--format", "json"]
                    )
            except SystemExit as exc:
                _check(exc.code == 2, "installed scanner CLI did not exit 2")
            else:
                raise AssertionError(
                    "installed scanner CLI accepted an over-budget schema"
                )
            error = stderr.getvalue()
            _check(
                "argument limit" in error and "Traceback" not in error,
                "installed scanner CLI did not fail cleanly on its resource cap",
            )
    finally:
        restore_limits()


def _daybreak_scanner_diff_regressions() -> None:
    with TemporaryDirectory(prefix="verb-authority-wheel-daybreak-") as directory:
        root = Path(directory)
        before_path = root / "decimal-before.json"
        after_path = root / "decimal-after.json"
        output_path = root / "decimal-diff.json"
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
        before = scan_documents(
            [verb_authority_scan.load_json_path(str(before_path))]
        )
        after = scan_documents(
            [verb_authority_scan.load_json_path(str(after_path))]
        )
        before_arguments = {
            argument["name"]: argument
            for argument in before["tools"][0]["arguments"]
        }
        after_arguments = {
            argument["name"]: argument
            for argument in after["tools"][0]["arguments"]
        }
        _check(
            before_arguments["amount"]["constraints"]["maximum"]
            == "9007199254740992"
            and after_arguments["amount"]["constraints"]["maximum"]
            == "9007199254740993"
            and before_arguments["mode"]["constraints"]["enum"]
            != after_arguments["mode"]["constraints"]["enum"],
            "installed scanner collapsed adjacent decimals above 2^53",
        )
        decimal_diff = diff_reports(before, after)
        _check(
            decimal_diff["summary"]["authority_increases"] == 1
            and decimal_diff["summary"]["reviews"] == 1,
            "installed diff lost exact decimal maximum/enum drift",
        )
        for threshold in ("--fail-on-increase", "--fail-on-review"):
            exit_code = verb_authority_diff.main(
                [
                    str(before_path),
                    str(after_path),
                    "--format",
                    "json",
                    "--output",
                    str(output_path),
                    threshold,
                ]
            )
            _check(exit_code == 2, f"installed diff ignored {threshold}")

        base_report = scan_documents([_constraint_document(100, 40, ["safe"])])
        malformed_reports = []
        missing_generator = copy.deepcopy(base_report)
        missing_generator.pop("generator")
        malformed_reports.append(("missing-generator", missing_generator))
        hybrid = copy.deepcopy(base_report)
        hybrid.pop("report_version")
        hybrid["inputSchema"] = {}
        malformed_reports.append(("report-hybrid", hybrid))
        legacy = copy.deepcopy(base_report)
        legacy["report_version"] = 2
        malformed_reports.append(("legacy-v2", legacy))
        report_tool = copy.deepcopy(base_report["tools"][0])
        malformed_reports.extend(
            (
                ("report-tool-direct", copy.deepcopy(report_tool)),
                ("report-tool-list", [copy.deepcopy(report_tool)]),
                ("report-tool-tools", {"tools": [copy.deepcopy(report_tool)]}),
                (
                    "report-tool-result",
                    {"result": {"tools": [copy.deepcopy(report_tool)]}},
                ),
                (
                    "report-tool-sources",
                    {"sources": [{"tools": [copy.deepcopy(report_tool)]}]},
                ),
                (
                    "report-tool-functions",
                    {"functions": [copy.deepcopy(report_tool)]},
                ),
                (
                    "report-tool-openai",
                    {
                        "tools": [
                            {
                                "type": "function",
                                "function": copy.deepcopy(report_tool),
                            }
                        ]
                    },
                ),
            )
        )
        unknown_nested = copy.deepcopy(base_report)
        unknown_nested["tools"][0]["risk_inference"]["extra_score"] = 1.5
        malformed_reports.append(("unknown-nested-number", unknown_nested))
        for label, report in malformed_reports:
            path = root / f"{label}.json"
            path.write_text(json.dumps(report), encoding="utf-8")
            try:
                verb_authority_diff.load_report_or_schema(
                    str(path), label=label
                )
            except DiffError:
                pass
            else:
                raise AssertionError(
                    f"installed diff raw-scanned report-shaped input: {label}"
                )

        def discriminator_document(target: str) -> dict[str, Any]:
            return {
                "tools": [
                    {
                        "name": "set_value",
                        "inputSchema": {
                            "properties": {
                                "value": {
                                    "type": "object",
                                    "discriminator": {
                                        "mapping": {"default": target}
                                    },
                                }
                            }
                        },
                    }
                ]
            }

        discriminator_diff = diff_reports(
            scan_documents([discriminator_document("#/A")]),
            scan_documents([discriminator_document("#/B")]),
        )
        _check(
            discriminator_diff["summary"]["reviews"] == 1
            and discriminator_diff["changes"][0]["kind"]
            == "unmodeled_schema_changed",
            "installed scanner dropped annotation-named discriminator data",
        )

        hostile = "hostile\r\x1b[31m\u202e\u2028\u2029"
        hostile_tool = f"send_{hostile}"
        hostile_argument = f"recipient_{hostile}"
        hostile_report = scan_documents(
            [
                {
                    "tools": [
                        {
                            "name": hostile_tool,
                            "inputSchema": {
                                "properties": {
                                    hostile_argument: {
                                        "type": "string",
                                        "format": "email",
                                    }
                                }
                            },
                        }
                    ]
                }
            ],
            control_declarations={
                "version": 1,
                "attribution": {"name": hostile, "source": hostile},
                "tools": {
                    hostile_tool: {
                        "risk": {
                            "tier": "write",
                            "evidence": "declared",
                            "effects": [hostile],
                        },
                        "arguments": {
                            hostile_argument: {
                                "authority": "locked",
                                "evidence": "declared",
                                "note": hostile,
                            }
                        },
                    }
                },
            },
        )
        markdown = render_markdown(hostile_report)
        _check(
            "\r" not in markdown
            and "\x1b" not in markdown
            and "\u202e" not in markdown
            and "\u2028" not in markdown
            and "\u2029" not in markdown
            and "\\r" in markdown
            and "\\u001b" in markdown
            and "\\u202e" in markdown
            and "\\u2028" in markdown
            and "\\u2029" in markdown,
            "installed scanner emitted live terminal or bidi controls",
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Exercise the installed Verb Authority wheel outside its checkout."
    )
    parser.add_argument("--expected-version", required=True)
    parser.add_argument(
        "--forbid-root",
        required=True,
        action="append",
        type=Path,
        help="source root that installed module imports must not resolve under",
    )
    args = parser.parse_args()

    forbidden_roots = tuple(path.resolve() for path in args.forbid_root)
    _installed_identity(args.expected_version, forbidden_roots)
    checks = (
        _plain_dict_boundary,
        _trusted_fixed_validation,
        _serialized_policy_runtime_boundary,
        _authority_name_precedence,
        _exact_authority_and_action_identity,
        _registry_replacement_drift,
        _forged_callable_metadata_denial,
        _callable_binding_and_code_drift,
        _confirmation_action_snapshot,
        _bidi_confirmation_snapshot,
        _implicit_default_denial,
        _numeric_result_taint,
        _object_key_and_container_taint,
        _json_depth_integer_and_result_boundaries,
        _graph_and_ledger_resource_boundaries,
        _policy_and_ledger_integrity,
        _ledger_invocation_serialization,
        _async_rejection,
        _unicode_homograph_rejection,
        _constraint_diff_and_migration,
        _scanner_resource_boundaries,
        _daybreak_scanner_diff_regressions,
    )
    for check in checks:
        check()
    print(
        "installed-wheel smoke: "
        f"{args.expected_version}; all audited blocker families + v2 migration "
        "+ diff thresholds passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
