"""Offline adapter audit controls; no live provider or external side effects."""

from __future__ import annotations

import asyncio
import copy
import json

import pytest

pytest.importorskip("pydantic")
pydantic_ai = pytest.importorskip("pydantic_ai")
if pydantic_ai.__version__ != "2.35.0":
    pytest.skip("adapter requires the pinned Pydantic AI release", allow_module_level=True)

from pydantic_ai import DeferredToolRequests, DeferredToolResults
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart
from pydantic_ai.models.function import FunctionModel

from verb_authority import Param, Registry, Risk, Tool, TrustedChoice, TrustedResolver
import verb_authority_pydantic as vap
from verb_authority_pydantic import (
    PydanticAuthorityAgent,
    PydanticAuthorityConfigurationError,
    PydanticAuthoritySession,
    pydantic_schema_tool,
)


def _has_result(messages):
    return any(isinstance(part, ToolReturnPart) for message in messages for part in message.parts)


def _agent(model, schema, *, deferred=False):
    return PydanticAuthorityAgent(
        FunctionModel(model),
        tools=[pydantic_schema_tool(schema, name="deliver")],
        output_type=[str, DeferredToolRequests] if deferred else str,
    )


def _registry(invoked, *, risk=Risk.WRITE, nested=False, handler_raises=False):
    registry = Registry()

    def actual(to, body):
        invoked.append(copy.deepcopy((to, body)))
        if handler_raises:
            raise RuntimeError("mock failed after entry")
        return {"status": "completed"}

    registry.add(Tool(
        "deliver",
        [Param("to", "object" if nested else "email", sink=True),
         Param("body", "string", sink=False)],
        fn=actual,
        risk=risk,
    ))
    return registry


def _fixed_schema(body: str):
    raise AssertionError("schema function must not execute")


def test_adapter_shared_agent_isolates_concurrent_authenticated_sessions():
    invoked = []
    registry = _registry(invoked)
    sessions = [
        PydanticAuthoritySession(registry, trusted_fixed={"deliver": {"to": target}})
        for target in ("alice@example.com", "bob@example.com")
    ]

    async def scenario():
        ready = asyncio.Event()
        model_entries = 0

        async def model(messages, info):
            nonlocal model_entries
            if _has_result(messages):
                return ModelResponse(parts=[TextPart("done")])
            model_entries += 1
            if model_entries == 2:
                ready.set()
            await asyncio.wait_for(ready.wait(), timeout=3)
            prompt = messages[-1].parts[0].content
            return ModelResponse(parts=[ToolCallPart(
                "deliver", {"body": prompt}, tool_call_id="same-id-each-session"
            )])

        agent = _agent(model, _fixed_schema)
        results = await asyncio.gather(
            agent.run("message-a", deps=sessions[0]),
            agent.run("message-b", deps=sessions[1]),
        )
        assert [result.output for result in results] == ["done", "done"]

    asyncio.run(scenario())
    assert sorted(invoked) == [
        ("alice@example.com", "message-a"),
        ("bob@example.com", "message-b"),
    ]
    assert [session.runner.ledger.version for session in sessions] == [1, 1]


def test_adapter_nested_fixed_value_remains_detached_across_runs():
    invoked = []
    source = {"deliver": {"to": {"recipients": ["alice@example.com"]}}}
    session = PydanticAuthoritySession(_registry(invoked, nested=True), trusted_fixed=source)
    prepared, trusted, _ = session.prepare_call("deliver", {"body": "inspection"})
    source["deliver"]["to"]["recipients"][0] = "source-attacker@example.com"
    prepared["to"]["recipients"][0] = "prepared-attacker@example.com"
    trusted["to"]["recipients"][0] = "trusted-attacker@example.com"

    def model(messages, info):
        if _has_result(messages):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart(
            "deliver", {"body": "hello"}, tool_call_id="reused-on-next-turn"
        )])

    agent = _agent(model, _fixed_schema)
    for _ in range(2):
        assert agent.run_sync("send", deps=session).output == "done"
    assert invoked == [({"recipients": ["alice@example.com"]}, "hello")] * 2


@pytest.mark.parametrize("raw", [
    '{"body":"hello","to":"attacker@example.com"}',
    '{"body":"hello","to":"alice@example.com","to":"attacker@example.com"}',
    '{"body":"hello","\\u0074o":"attacker@example.com"}',
    '{"body":"hello","trusted_args":{"to":"attacker@example.com"}}',
    '{"body":"hello","provenance":{"to":"trusted"}}',
])
def test_adapter_raw_json_cannot_supply_hidden_fixed_argument(raw):
    invoked = []
    session = PydanticAuthoritySession(
        _registry(invoked), trusted_fixed={"deliver": {"to": "alice@example.com"}}
    )
    calls = 0

    def model(messages, info):
        nonlocal calls
        calls += 1
        if calls > 1:
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart("deliver", raw, tool_call_id="parser")])

    assert _agent(model, _fixed_schema).run_sync("send", deps=session).output == "done"
    assert invoked == []


@pytest.mark.parametrize(("raw", "expected"), [
    ('{"to":"Alice","body":"hello"}', [("alice@example.com", "hello")]),
    ('{"to":"Mallory","to":"Alice","body":"hello"}', [("alice@example.com", "hello")]),
    ('{"to":"Alice","to":"Mallory","body":"hello"}', []),
    ('{"to":"Alice","\\u0074o":"Mallory","body":"hello"}', []),
])
def test_adapter_nonselector_json_choice_is_canonical_or_blocked(raw, expected):
    invoked = []
    session = PydanticAuthoritySession(_registry(invoked), trusted_choices={
        "deliver": {"to": TrustedResolver([
            TrustedChoice("Alice", "alice@example.com", "host directory: alice")
        ])}
    })

    def schema(to: str, body: str):
        raise AssertionError("schema function must not execute")

    calls = 0

    def model(messages, info):
        nonlocal calls
        calls += 1
        if calls > 1:
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart("deliver", raw, tool_call_id="choice")])

    assert _agent(model, schema).run_sync("send", deps=session).output == "done"
    assert invoked == expected


@pytest.mark.parametrize("handler_raises", [False, True])
def test_adapter_simultaneous_resumes_consume_one_exact_approval(monkeypatch, handler_raises):
    invoked = []
    session = PydanticAuthoritySession(
        _registry(invoked, risk=Risk.FINANCIAL, handler_raises=handler_raises),
        trusted_fixed={"deliver": {"to": "alice@example.com"}},
    )

    def model(messages, info):
        if _has_result(messages):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart(
            "deliver", {"body": "confirmed action"}, tool_call_id="approval-once"
        )])

    agent = _agent(model, _fixed_schema, deferred=True)

    async def scenario():
        first = await agent.run("send", deps=session)
        assert isinstance(first.output, DeferredToolRequests)
        assert invoked == []
        evidence = first.output.metadata["approval-once"]["verb_authority"]
        assert json.loads(evidence["arguments_json"]) == {
            "to": "alice@example.com", "body": "confirmed action"
        }
        both_prepared = asyncio.Event()
        first_executed = asyncio.Event()
        second_returned = asyncio.Event()
        original_run_sync = vap.anyio.to_thread.run_sync
        worker_entries = 0

        async def schedule_workers(func, *args, **kwargs):
            # Instrument only scheduling at the adapter's normal thread handoff.
            # Both resumed calls pass their existing approval checks first.
            # No call arguments, approval state, validation or results are edited.
            nonlocal worker_entries
            if func.__name__ != "execute_guarded":
                return await original_run_sync(func, *args, **kwargs)
            worker_entries += 1
            position = worker_entries
            if worker_entries == 2:
                both_prepared.set()
            await asyncio.wait_for(both_prepared.wait(), timeout=3)
            if position == 1:
                result = await original_run_sync(func, *args, **kwargs)
                first_executed.set()
                await asyncio.wait_for(second_returned.wait(), timeout=3)
                return result
            await asyncio.wait_for(first_executed.wait(), timeout=3)
            try:
                return await original_run_sync(func, *args, **kwargs)
            finally:
                second_returned.set()

        with monkeypatch.context() as scheduling:
            scheduling.setattr(vap.anyio.to_thread, "run_sync", schedule_workers)
            outcomes = await asyncio.gather(*[
                agent.run(
                    deps=session,
                    message_history=copy.deepcopy(first.all_messages()),
                    deferred_tool_results=DeferredToolResults(approvals={"approval-once": True}),
                )
                for _ in range(2)
            ], return_exceptions=True)

        assert invoked == [("alice@example.com", "confirmed action")]
        pending_after_race = bool(session._pending)
        try:
            replay = await agent.run(
                deps=session,
                message_history=copy.deepcopy(first.all_messages()),
                deferred_tool_results=DeferredToolResults(approvals={"approval-once": True}),
            )
        except PydanticAuthorityConfigurationError as exc:
            replay = exc
        observation = repr({
            "race_outcomes": [repr(outcome) for outcome in outcomes],
            "pending_after_race": pending_after_race,
            "replay": repr(replay),
            "actual_invocations": invoked,
        })
        assert invoked == [("alice@example.com", "confirmed action")], observation
        assert not pending_after_race, observation
        assert any(not isinstance(outcome, BaseException) and outcome.output == "done"
                   for outcome in outcomes), observation
        assert isinstance(replay, PydanticAuthorityConfigurationError)
        tool_results = []
        for outcome in outcomes:
            if isinstance(outcome, BaseException):
                assert isinstance(outcome, PydanticAuthorityConfigurationError)
            else:
                assert not isinstance(outcome.output, DeferredToolRequests)
                tool_results.extend(
                    part for message in outcome.all_messages() for part in message.parts
                    if isinstance(part, ToolReturnPart)
                )
        successes = [part for part in tool_results if part.outcome == "success"]
        failures = [part for part in tool_results if part.outcome == "failed"]
        if handler_raises:
            assert successes == []
            assert len(failures) == 2
            assert all("do not retry automatically" in str(part.content) for part in failures)
        else:
            assert len(successes) == 1
            assert successes[0].content == {"status": "completed"}
            assert len(failures) == 1
            assert "do not retry automatically" in str(failures[0].content)

    asyncio.run(scenario())
    assert invoked == [("alice@example.com", "confirmed action")]
    assert not session._pending


def test_adapter_discard_after_precheck_does_not_recreate_approval(monkeypatch):
    invoked = []
    session = PydanticAuthoritySession(
        _registry(invoked, risk=Risk.FINANCIAL),
        trusted_fixed={"deliver": {"to": "alice@example.com"}},
    )

    def model(messages, info):
        if _has_result(messages):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart(
            "deliver", {"body": "cancel me"}, tool_call_id="discarded"
        )])

    agent = _agent(model, _fixed_schema, deferred=True)

    async def scenario():
        first = await agent.run("send", deps=session)
        assert isinstance(first.output, DeferredToolRequests)
        original_run_sync = vap.anyio.to_thread.run_sync
        cancellations = []

        async def discard_before_worker(func, *args, **kwargs):
            if func.__name__ == "execute_guarded":
                cancellations.append(session.discard_pending_approval("discarded"))
            return await original_run_sync(func, *args, **kwargs)

        with monkeypatch.context() as cancellation:
            cancellation.setattr(vap.anyio.to_thread, "run_sync", discard_before_worker)
            resumed = await agent.run(
                deps=session, message_history=copy.deepcopy(first.all_messages()),
                deferred_tool_results=DeferredToolResults(approvals={"discarded": True}),
            )
        assert cancellations == [True]
        assert resumed.output == "done"
        assert not session._pending
        results = [part for message in resumed.all_messages() for part in message.parts
                   if isinstance(part, ToolReturnPart)]
        assert len(results) == 1
        assert results[0].outcome == "failed"
        assert "do not retry automatically" in str(results[0].content)
        with pytest.raises(PydanticAuthorityConfigurationError, match="without matching"):
            await agent.run(
                deps=session, message_history=copy.deepcopy(first.all_messages()),
                deferred_tool_results=DeferredToolResults(approvals={"discarded": True}),
            )

    asyncio.run(scenario())
    assert invoked == []


def test_adapter_same_call_id_other_session_cannot_borrow_approval():
    invoked = []
    registry = _registry(invoked, risk=Risk.FINANCIAL)
    alice, bob = [PydanticAuthoritySession(
        registry, trusted_fixed={"deliver": {"to": recipient}}
    ) for recipient in ("alice@example.com", "bob@example.com")]

    def model(messages, info):
        if _has_result(messages):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(parts=[ToolCallPart(
            "deliver", {"body": "confirm me"}, tool_call_id="same-id"
        )])

    agent = _agent(model, _fixed_schema, deferred=True)
    pending = agent.run_sync("send", deps=alice)
    assert isinstance(pending.output, DeferredToolRequests)
    with pytest.raises(PydanticAuthorityConfigurationError, match="without matching"):
        agent.run_sync(
            deps=bob, message_history=copy.deepcopy(pending.all_messages()),
            deferred_tool_results=DeferredToolResults(approvals={"same-id": True}),
        )
    assert invoked == []
    assert agent.run_sync(
        deps=alice, message_history=pending.all_messages(),
        deferred_tool_results=DeferredToolResults(approvals={"same-id": True}),
    ).output == "done"
    assert invoked == [("alice@example.com", "confirm me")]
    with pytest.raises(PydanticAuthorityConfigurationError, match="without matching"):
        agent.run_sync(
            deps=alice, message_history=copy.deepcopy(pending.all_messages()),
            deferred_tool_results=DeferredToolResults(approvals={"same-id": True}),
        )
    assert invoked == [("alice@example.com", "confirm me")]
