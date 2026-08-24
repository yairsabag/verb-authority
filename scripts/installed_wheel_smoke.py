"""Installed-wheel audit smoke for the beta.8 release boundary.

Run this copy from outside the source checkout after installing the wheel. The
checks intentionally repeat all audited blocker families, then exercise the
report-format migration and the diff CLI's release threshold.
"""

from __future__ import annotations

import argparse
import copy
import importlib.metadata
import inspect
import json
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
    GuardedToolRunner,
    Param,
    Registry,
    Risk,
    Tool,
    build_policy,
    dispatch,
)
from verb_authority_diff import DIFF_VERSION, DiffError, diff_reports
from verb_authority_scan import REPORT_VERSION, scan_documents


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
        "confirmation arguments_json is not canonical ASCII-escaped JSON",
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
        "oversized integer reached canonical confirmation serialization",
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
        review_process = subprocess.run(
            [
                sys.executable,
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
        _registry_replacement_drift,
        _forged_callable_metadata_denial,
        _callable_binding_and_code_drift,
        _confirmation_action_snapshot,
        _bidi_confirmation_snapshot,
        _implicit_default_denial,
        _numeric_result_taint,
        _object_key_and_container_taint,
        _json_depth_integer_and_result_boundaries,
        _policy_and_ledger_integrity,
        _ledger_invocation_serialization,
        _async_rejection,
        _unicode_homograph_rejection,
        _constraint_diff_and_migration,
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
