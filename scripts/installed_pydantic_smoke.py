"""Smoke-test the optional Pydantic AI adapter from an installed wheel.

Run this copy outside the source checkout after installing both the wheel and
its ``pydantic`` extra.  The test verifies import provenance and exercises the
application-owned trusted-value boundary through a local ``FunctionModel`` and
one frozen Registry tool. It makes no network request or external model call.
"""

from __future__ import annotations

import argparse
import importlib.metadata
from pathlib import Path
from types import SimpleNamespace
from typing import Literal

import pydantic
import pydantic_ai
import pydantic_core
import verb_authority
import verb_authority_pydantic
from pydantic_ai import DeferredToolRequests, DeferredToolResults
from pydantic_ai.messages import (
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
)
from pydantic_ai.models.function import FunctionModel
from verb_authority import Param, Registry, Risk, SelectorCase, Tool
from verb_authority_pydantic import (
    PydanticAuthorityAgent,
    PydanticAuthoritySession,
    pydantic_schema_tool,
)


def _check(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _installed_identity(
    expected_version: str,
    forbidden_roots: tuple[Path, ...],
) -> None:
    distribution = importlib.metadata.distribution("verb-authority")
    _check(
        distribution.version == expected_version,
        f"installed version {distribution.version!r} != {expected_version!r}",
    )
    _check(
        pydantic_ai.__version__ == "2.35.0",
        f"unsupported Pydantic AI version {pydantic_ai.__version__!r}",
    )
    _check(
        pydantic.__version__ == "2.13.4",
        f"unsupported Pydantic version {pydantic.__version__!r}",
    )
    _check(
        pydantic_core.__version__ == "2.46.4",
        f"unsupported pydantic-core version {pydantic_core.__version__!r}",
    )

    distribution_root = Path(distribution.locate_file("")).resolve()
    for module in (verb_authority, verb_authority_pydantic):
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


def _trusted_session_boundary() -> None:
    outbox: list[dict[str, str]] = []

    def send_email(to: str, body: str) -> dict[str, str]:
        message = {"to": to, "body": body}
        outbox.append(message)
        return message

    def model_visible_send_email(body: str) -> None:
        raise AssertionError("the schema-only Pydantic callable executed")

    registry = Registry()
    registry.add(
        Tool(
            "send_email",
            [
                Param("to", "email", sink=True),
                Param("body", "string", max_len=2_000, sink=False),
            ],
            fn=send_email,
            risk=Risk.WRITE,
        )
    )
    session = PydanticAuthoritySession(
        registry,
        trusted_fixed={
            "send_email": {"to": "approved@example.com"},
        },
    )
    prepared, trusted, evidence = session.prepare_call(
        "send_email",
        {"body": "hello"},
    )
    _check(
        prepared
        == {"body": "hello", "to": "approved@example.com"},
        "adapter did not replace the protected argument from application state",
    )
    _check(
        trusted == {"to": "approved@example.com"},
        "adapter did not bind the protected argument as trusted",
    )
    _check(
        evidence.get("to") == "application-owned authenticated session value",
        "adapter did not retain trusted-value evidence",
    )

    def model(messages, info):
        tool_defs = info.function_tools
        _check(len(tool_defs) == 1, "installed adapter exposed the wrong tools")
        _check(
            set(tool_defs[0].parameters_json_schema["properties"]) == {"body"},
            "fixed recipient remained visible to the model",
        )
        if any(
            isinstance(part, ToolReturnPart)
            for message in messages
            for part in message.parts
        ):
            return ModelResponse(parts=[TextPart("done")])
        return ModelResponse(
            parts=[
                ToolCallPart(
                    "send_email",
                    {"body": "hello"},
                    tool_call_id="installed-smoke-1",
                )
            ]
        )

    agent = PydanticAuthorityAgent(
        FunctionModel(model),
        deps_type=PydanticAuthoritySession,
        tools=[
            pydantic_schema_tool(model_visible_send_email, name="send_email")
        ],
    )
    result = agent.run_sync("send", deps=session)
    _check(result.output == "done", "installed adapter run did not complete")
    _check(
        outbox == [{"to": "approved@example.com", "body": "hello"}],
        "installed adapter did not execute the frozen Registry function exactly once",
    )


def _selector_branch_boundary() -> None:
    invoked: list[tuple[str, int]] = []

    def browser_tabs(action: str, index: int) -> dict[str, object]:
        invoked.append((action, index))
        return {"action": action, "index": index}

    def browser_tabs_schema(
        action: Literal["list", "close"],
        index: int,
    ) -> None:
        raise AssertionError("the schema-only Pydantic callable executed")

    registry = Registry()
    registry.add(
        Tool(
            "browser_tabs",
            [
                Param(
                    "action",
                    "enum",
                    enum=["list", "close"],
                    sink=False,
                ),
                Param("index", "integer", sink=False),
            ],
            fn=browser_tabs,
            risk=Risk.WRITE,
            selector="action",
            selector_cases=[
                SelectorCase(
                    "list",
                    Risk.READ_ONLY,
                    ["action", "index"],
                ),
                SelectorCase(
                    "close",
                    Risk.DESTRUCTIVE,
                    ["action", "index"],
                ),
            ],
        )
    )
    session = PydanticAuthoritySession(registry)

    def branch_model(action: str):
        def model(messages, info):
            _check(
                info.function_tools[0].parameters_json_schema["properties"][
                    "action"
                ]["enum"]
                == ["list", "close"],
                "installed adapter did not preserve the selector enum",
            )
            if any(
                isinstance(part, ToolReturnPart)
                for message in messages
                for part in message.parts
            ):
                return ModelResponse(parts=[TextPart("done")])
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "browser_tabs",
                        {"action": action, "index": 0},
                        tool_call_id=f"installed-{action}-1",
                    )
                ]
            )

        return model

    list_agent = PydanticAuthorityAgent(
        FunctionModel(branch_model("list")),
        deps_type=PydanticAuthoritySession,
        tools=[pydantic_schema_tool(browser_tabs_schema, name="browser_tabs")],
    )
    listed = list_agent.run_sync("list tabs", deps=session)
    _check(listed.output == "done", "read-only selector branch did not complete")
    _check(
        invoked == [("list", 0)],
        "read-only selector branch did not execute exactly once",
    )

    close_agent = PydanticAuthorityAgent(
        FunctionModel(branch_model("close")),
        output_type=[str, DeferredToolRequests],
        deps_type=PydanticAuthoritySession,
        tools=[pydantic_schema_tool(browser_tabs_schema, name="browser_tabs")],
    )
    first = close_agent.run_sync("close tab zero", deps=session)
    _check(
        isinstance(first.output, DeferredToolRequests),
        "destructive selector branch did not require approval",
    )
    _check(
        invoked == [("list", 0)],
        "destructive selector branch ran before approval",
    )
    evidence = first.output.metadata["installed-close-1"]["verb_authority"]
    _check(evidence["risk"] == "destructive", "branch risk was not preserved")
    _check(evidence["selector"] == "action", "selector evidence was not preserved")
    _check(
        evidence["selector_value_json"] == '"close"',
        "selector value evidence was not preserved",
    )
    _check(
        evidence["claim_boundary"]
        == "per-argument provenance/local constraints + explicit exact "
        "one-selector branch risk/applicability; still not selection intent, "
        "general cross-argument composition, sequence, or action-instance "
        "authorization",
        "installed adapter did not preserve the exact claim boundary",
    )
    second = close_agent.run_sync(
        message_history=first.all_messages(),
        deps=session,
        deferred_tool_results=DeferredToolResults(
            approvals={"installed-close-1": True}
        ),
    )
    _check(second.output == "done", "approved selector branch did not complete")
    _check(
        invoked == [("list", 0), ("close", 0)],
        "approved selector branch did not execute exactly once",
    )


def _selector_raw_type_boundary() -> None:
    invoked: list[bool] = []

    def select_one(selector: bool) -> dict[str, bool]:
        invoked.append(selector)
        return {"selector": selector}

    def select_one_schema(selector: Literal[True]) -> None:
        raise AssertionError("the schema-only Pydantic callable executed")

    registry = Registry()
    registry.add(
        Tool(
            "select_one",
            [
                Param(
                    "selector",
                    "enum",
                    enum=[True],
                    sink=False,
                )
            ],
            fn=select_one,
            risk=Risk.READ_ONLY,
            selector="selector",
            selector_cases=[
                SelectorCase(True, Risk.READ_ONLY, ["selector"]),
            ],
        )
    )

    def run_raw(
        raw_arguments: object,
        tool_call_id: str,
        public_policy_mutation: str,
    ) -> None:
        session = PydanticAuthoritySession(registry)
        selector = (
            {"select_one": "bogus"}
            if public_policy_mutation == "assignment-bogus"
            else {}
        )
        replacement = SimpleNamespace(selector=selector)
        if public_policy_mutation in ("assignment-empty", "assignment-bogus"):
            session.runner.policy_set = replacement
        elif public_policy_mutation == "object-setattr-empty":
            object.__setattr__(session.runner, "policy_set", replacement)
        else:  # pragma: no cover - fixed local smoke calls only
            raise AssertionError("unknown public policy mutation")

        def model(messages, info):
            if any(
                isinstance(part, ToolReturnPart)
                for message in messages
                for part in message.parts
            ):
                return ModelResponse(parts=[TextPart("blocked")])
            return ModelResponse(
                parts=[
                    ToolCallPart(
                        "select_one",
                        raw_arguments,
                        tool_call_id=tool_call_id,
                    )
                ]
            )

        agent = PydanticAuthorityAgent(
            FunctionModel(model),
            deps_type=PydanticAuthoritySession,
            tools=[pydantic_schema_tool(select_one_schema, name="select_one")],
        )
        result = agent.run_sync("select", deps=session)
        _check(
            result.output == "blocked",
            "Pydantic-coerced selector was not rejected",
        )
        _check(
            session.runner.ledger.version == 0,
            "Pydantic-coerced selector reached the provenance ledger",
        )

    run_raw(
        {"selector": 1},
        "installed-selector-dict",
        "assignment-empty",
    )
    run_raw(
        '{"selector":1}',
        "installed-selector-json",
        "object-setattr-empty",
    )
    run_raw(
        {"selector": 1},
        "installed-selector-bogus",
        "assignment-bogus",
    )
    _check(
        invoked == [],
        "Pydantic-coerced selector reached the Registry implementation",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--forbid-root", action="append", default=[])
    arguments = parser.parse_args()
    forbidden_roots = tuple(
        Path(item).resolve() for item in arguments.forbid_root
    )
    _installed_identity(arguments.expected_version, forbidden_roots)
    _trusted_session_boundary()
    _selector_branch_boundary()
    _selector_raw_type_boundary()
    print("installed Pydantic AI adapter smoke passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
