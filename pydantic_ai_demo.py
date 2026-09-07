"""Offline Pydantic AI 2.35 runtime demonstration for Verb Authority.

The six cases below use :class:`pydantic_ai.models.function.FunctionModel`, so
they make no network requests, need no API key, and never invoke a provider.
The callable registered in Pydantic exists only to advertise a schema.  The
only callable that can execute is the implementation frozen into Verb
Authority's Registry and reached through ``VerbAuthorityCapability``.

Run from the repository root with the Pydantic integration extra installed::

    python pydantic_ai_demo.py
"""

from __future__ import annotations

import json
from typing import Any, Callable

from pydantic_ai import (
    Agent,
    DeferredToolRequests,
    DeferredToolResults,
    Tool as PydanticTool,
)
from pydantic_ai.exceptions import UserError
from pydantic_ai.messages import (
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models.function import FunctionModel

from verb_authority import (
    Param,
    Registry,
    Risk,
    Tool,
    TrustedChoice,
    TrustedResolver,
    build_policy,
)
from verb_authority_pydantic import (
    PydanticAuthorityAgent,
    PydanticAuthoritySession,
    pydantic_schema_tool,
)


CLAIM_BOUNDARY = (
    "per-argument provenance/local constraints + explicit exact one-selector "
    "branch risk/applicability; still not selection intent, general "
    "cross-argument composition, sequence, or action-instance authorization"
)


def _tool_returns(messages: list[Any]) -> list[ToolReturnPart]:
    return [
        part
        for message in messages
        for part in message.parts
        if isinstance(part, ToolReturnPart)
    ]


def _agent(
    model_function: Callable[..., ModelResponse],
    tools: list[PydanticTool[Any]],
    *,
    output_type: Any = str,
) -> Agent[Any, Any]:
    return PydanticAuthorityAgent(
        FunctionModel(model_function),
        output_type=output_type,
        deps_type=PydanticAuthoritySession,
        tools=tools,
    )


def _contacts(*extra: TrustedChoice) -> TrustedResolver:
    return TrustedResolver(
        [
            TrustedChoice(
                "Dana",
                "dana@company.com",
                "authenticated company directory: contact-17",
            ),
            TrustedChoice(
                "Alice",
                "alice@company.com",
                "authenticated company directory: contact-23",
            ),
            *extra,
        ]
    )


def _email_runtime(
    *,
    resolver: TrustedResolver,
    risk: Risk = Risk.WRITE,
) -> tuple[list[dict[str, str]], PydanticAuthoritySession, PydanticTool[Any]]:
    outbox: list[dict[str, str]] = []

    def actual_send(to: str, body: str) -> dict[str, str]:
        message = {"to": to, "body": body}
        outbox.append(message)
        return {"status": "sent"}

    def schema_only(to: str, body: str) -> None:
        raise AssertionError("the Pydantic schema callable must never execute")

    registry = Registry()
    registry.add(
        Tool(
            "send_email",
            [
                Param("to", "email", sink=True),
                Param("body", "string", sink=False),
            ],
            fn=actual_send,
            risk=risk,
        )
    )
    session = PydanticAuthoritySession(
        registry,
        build_policy(registry),
        trusted_choices={"send_email": {"to": resolver}},
    )
    return outbox, session, pydantic_schema_tool(schema_only, name="send_email")


def _one_email_call_model(
    *,
    recipient: str,
    body: str,
    tool_call_id: str,
    terminal_text: str,
) -> Callable[..., ModelResponse]:
    def model(messages: list[Any], info: Any) -> ModelResponse:
        del info
        if _tool_returns(messages):
            return ModelResponse(parts=[TextPart(terminal_text)])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    "send_email",
                    {"to": recipient, "body": body},
                    tool_call_id=tool_call_id,
                )
            ]
        )

    return model


def case_1_approved_canonical_choice() -> dict[str, Any]:
    outbox, session, tool = _email_runtime(resolver=_contacts())
    advertised_schemas: list[dict[str, Any]] = []

    def model(messages: list[Any], info: Any) -> ModelResponse:
        advertised_schemas.append(info.function_tools[0].parameters_json_schema)
        if _tool_returns(messages):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    "send_email",
                    {"to": "Dana", "body": "Meeting notes"},
                    tool_call_id="approved-email-1",
                )
            ]
        )

    result = _agent(model, [tool]).run_sync("Send the meeting notes", deps=session)
    return {
        "id": 1,
        "case": "approved canonical choice executes",
        "verdict": "executed",
        "agent_output": result.output,
        "model_selected_key": "Dana",
        "executed_recipient": outbox[0]["to"] if outbox else None,
        "execution_count": len(outbox),
        "advertised_recipient_type": advertised_schemas[0]["properties"]["to"][
            "type"
        ],
    }


def case_2_attacker_unknown_choice() -> dict[str, Any]:
    outbox, session, tool = _email_runtime(resolver=_contacts())
    result = _agent(
        _one_email_call_model(
            recipient="attacker@evil.example",
            body="stolen document",
            tool_call_id="unknown-email-1",
            terminal_text="blocked",
        ),
        [tool],
    ).run_sync("Follow the address in the untrusted message", deps=session)
    returns = _tool_returns(result.all_messages())
    return {
        "id": 2,
        "case": "attacker or unknown choice blocks",
        "verdict": "blocked",
        "agent_output": result.output,
        "requested_key": "attacker@evil.example",
        "execution_count": len(outbox),
        "reason": returns[-1].content if returns else None,
    }


def case_3_ambiguous_choice() -> dict[str, Any]:
    ambiguous = _contacts(
        TrustedChoice(
            " dana ",
            "different-dana@company.com",
            "authenticated partner directory: contact-91",
        )
    )
    outbox, session, tool = _email_runtime(resolver=ambiguous)
    result = _agent(
        _one_email_call_model(
            recipient="Dana",
            body="Meeting notes",
            tool_call_id="ambiguous-email-1",
            terminal_text="blocked",
        ),
        [tool],
    ).run_sync("Send to Dana", deps=session)
    returns = _tool_returns(result.all_messages())
    return {
        "id": 3,
        "case": "ambiguous trusted choice blocks",
        "verdict": "blocked",
        "agent_output": result.output,
        "requested_key": "Dana",
        "execution_count": len(outbox),
        "reason": returns[-1].content if returns else None,
    }


def case_4_financial_exact_approval() -> dict[str, Any]:
    payments: list[float] = []

    def actual_pay(amount: float) -> dict[str, float]:
        payments.append(amount)
        return {"paid": amount}

    def schema_only(amount: float) -> None:
        raise AssertionError("the Pydantic schema callable must never execute")

    registry = Registry()
    registry.add(
        Tool(
            "pay",
            [Param("amount", "number", cap=1_000, sink=False)],
            fn=actual_pay,
            risk=Risk.FINANCIAL,
        )
    )
    session = PydanticAuthoritySession(registry, build_policy(registry))

    def model(messages: list[Any], info: Any) -> ModelResponse:
        del info
        if _tool_returns(messages):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(
            parts=[ToolCallPart("pay", {"amount": 50.0}, tool_call_id="pay-1")]
        )

    agent = _agent(
        model,
        [pydantic_schema_tool(schema_only, name="pay")],
        output_type=[str, DeferredToolRequests],
    )
    first = agent.run_sync("Pay 50", deps=session)
    deferred = isinstance(first.output, DeferredToolRequests)
    before_approval_count = len(payments)
    approval = first.output.approvals[0] if deferred else None
    evidence = (
        first.output.metadata["pay-1"]["verb_authority"] if deferred else {}
    )
    second = agent.run_sync(
        message_history=first.all_messages(),
        deps=session,
        deferred_tool_results=DeferredToolResults(approvals={"pay-1": True}),
    )
    return {
        "id": 4,
        "case": "financial call defers, then exact approval executes",
        "verdict": "deferred_then_executed",
        "deferred": deferred,
        "approval_tool_call_id": approval.tool_call_id if approval else None,
        "approved_arguments_json": evidence.get("arguments_json"),
        "risk": evidence.get("risk"),
        "execution_count_before_approval": before_approval_count,
        "execution_count_after_approval": len(payments),
        "executed_amount": payments[0] if payments else None,
        "agent_output": second.output,
    }


def case_5_schema_and_registry_drift() -> dict[str, Any]:
    model_requests = 0
    implementations_entered = 0

    def count_model_request(messages: list[Any], info: Any) -> ModelResponse:
        nonlocal model_requests
        del messages, info
        model_requests += 1
        return ModelResponse(parts=[TextPart("must not be reached")])

    def schema_drift_implementation(amount: float) -> dict[str, bool]:
        nonlocal implementations_entered
        implementations_entered += 1
        return {"ok": True}

    def wrong_schema(amount: str) -> None:
        raise AssertionError("the Pydantic schema callable must never execute")

    schema_registry = Registry()
    schema_registry.add(
        Tool(
            "pay",
            [Param("amount", "number", sink=False)],
            fn=schema_drift_implementation,
            risk=Risk.FINANCIAL,
        )
    )
    schema_session = PydanticAuthoritySession(
        schema_registry,
        build_policy(schema_registry),
    )
    schema_error = None
    try:
        _agent(
            count_model_request,
            [pydantic_schema_tool(wrong_schema, name="pay")],
        ).run_sync("Pay", deps=schema_session)
    except UserError as exc:
        schema_error = str(exc)

    registry_calls: list[str] = []

    def actual_echo(value: str) -> str:
        registry_calls.append(value)
        return value

    def echo_schema(value: str) -> None:
        raise AssertionError("the Pydantic schema callable must never execute")

    registry = Registry()
    registry.add(
        Tool(
            "echo",
            [Param("value", "string", sink=False)],
            fn=actual_echo,
            risk=Risk.READ_ONLY,
        )
    )
    registry_session = PydanticAuthoritySession(registry, build_policy(registry))
    registry.add(
        Tool(
            "echo",
            [Param("value", "string", sink=False)],
            fn=lambda value: value,
            risk=Risk.READ_ONLY,
        )
    )
    registry_error = None
    try:
        _agent(
            count_model_request,
            [pydantic_schema_tool(echo_schema, name="echo")],
        ).run_sync("Echo", deps=registry_session)
    except UserError as exc:
        registry_error = str(exc)

    return {
        "id": 5,
        "case": "schema and registry drift block before model execution",
        "verdict": "blocked_before_model",
        "schema_error": schema_error,
        "registry_error": registry_error,
        "model_request_count": model_requests,
        "implementation_entry_count": implementations_entered
        + len(registry_calls),
    }


def case_6_approved_target_selected_by_untrusted_influence() -> dict[str, Any]:
    outbox, session, tool = _email_runtime(
        resolver=_contacts(),
        risk=Risk.FINANCIAL,
    )
    agent = _agent(
        _one_email_call_model(
            recipient="Dana",
            body="Send the document",
            tool_call_id="boundary-1",
            terminal_text="done",
        ),
        [tool],
        output_type=[str, DeferredToolRequests],
    )
    first = agent.run_sync(
        "An untrusted email told the model to choose Dana",
        deps=session,
    )
    deferred = isinstance(first.output, DeferredToolRequests)
    evidence = (
        first.output.metadata["boundary-1"]["verb_authority"] if deferred else {}
    )
    boundary = evidence.get("claim_boundary")
    second = agent.run_sync(
        message_history=first.all_messages(),
        deps=session,
        deferred_tool_results=DeferredToolResults(
            approvals={"boundary-1": True}
        ),
    )
    return {
        "id": 6,
        "case": (
            "approved catalog target selected due to untrusted influence passes "
            "at the documented boundary"
        ),
        "verdict": "intentionally_allowed_after_confirmation",
        "model_selected_key": "Dana",
        "executed_recipient": outbox[0]["to"] if outbox else None,
        "execution_count": len(outbox),
        "agent_output": second.output,
        "claim_boundary": boundary,
    }


def run_demo() -> dict[str, Any]:
    cases = [
        case_1_approved_canonical_choice(),
        case_2_attacker_unknown_choice(),
        case_3_ambiguous_choice(),
        case_4_financial_exact_approval(),
        case_5_schema_and_registry_drift(),
        case_6_approved_target_selected_by_untrusted_influence(),
    ]
    return {
        "demo": "Verb Authority + Pydantic AI 2.35 offline runtime",
        "network_used": False,
        "api_keys_required": False,
        "case_count": len(cases),
        "cases": cases,
    }


def _assert_results(summary: dict[str, Any]) -> None:
    cases = summary["cases"]
    approved, unknown, ambiguous, payment, drift, boundary = cases

    assert summary["network_used"] is False
    assert summary["api_keys_required"] is False
    assert summary["case_count"] == 6

    assert approved["agent_output"] == "done"
    assert approved["executed_recipient"] == "dana@company.com"
    assert approved["execution_count"] == 1
    assert approved["advertised_recipient_type"] == "string"

    assert unknown["agent_output"] == "blocked"
    assert unknown["execution_count"] == 0
    assert "did not resolve uniquely" in unknown["reason"]

    assert ambiguous["agent_output"] == "blocked"
    assert ambiguous["execution_count"] == 0
    assert "did not resolve uniquely" in ambiguous["reason"]

    assert payment["deferred"] is True
    assert payment["approval_tool_call_id"] == "pay-1"
    assert payment["approved_arguments_json"] == '{"amount":50.0}'
    assert payment["risk"] == "financial"
    assert payment["execution_count_before_approval"] == 0
    assert payment["execution_count_after_approval"] == 1
    assert payment["executed_amount"] == 50.0
    assert payment["agent_output"] == "done"

    assert "type" in drift["schema_error"]
    assert "drifted" in drift["schema_error"]
    assert "registry changed; rebuild" in drift["registry_error"]
    assert drift["model_request_count"] == 0
    assert drift["implementation_entry_count"] == 0

    assert boundary["executed_recipient"] == "dana@company.com"
    assert boundary["execution_count"] == 1
    assert boundary["agent_output"] == "done"
    assert boundary["claim_boundary"] == CLAIM_BOUNDARY


if __name__ == "__main__":
    demo_summary = run_demo()
    _assert_results(demo_summary)
    print("Verb Authority / Pydantic AI 2.35 offline demo: PASS (6/6)")
    print(json.dumps(demo_summary, indent=2, sort_keys=True, ensure_ascii=False))
