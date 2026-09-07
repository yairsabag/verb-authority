"""Installed-wheel audit smoke for the current release boundary.

Run this copy from outside the source checkout after installing the wheel. The
checks intentionally repeat all audited blocker families, then exercise the
report-format migration and the diff CLI's release threshold.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import gc
import importlib.metadata
import inspect
import io
import json
import os
import subprocess
import sys
import threading
import time
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
    SelectorCase,
    Tool,
    TrustedChoice,
    TrustedResolver,
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
    classifiers = distribution.metadata.get_all("Classifier") or []
    _check(
        "Typing :: Typed" not in classifiers,
        "module-only distribution still makes an unsupported PEP 561 claim",
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
    _check(REPORT_VERSION == 6, "installed scanner is not report v6")
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


def _exact_selector_branch_boundary() -> None:
    calls: list[tuple[str, int | None, str | None]] = []

    def browser_tabs(action: str, **kwargs: object) -> dict[str, bool]:
        index = kwargs.get("index")
        url = kwargs.get("url")
        calls.append(
            (
                action,
                index if isinstance(index, int) else None,
                url if isinstance(url, str) else None,
            )
        )
        return {"ok": True}

    registry = Registry()
    registry.add(
        Tool(
            "browser_tabs",
            [
                Param(
                    "action",
                    "enum",
                    enum=["list", "new", "close", "select"],
                    sink=False,
                ),
                Param("index", "integer", sink=False),
                Param("url", "uri"),
            ],
            fn=browser_tabs,
            risk=Risk.WRITE,
            selector="action",
            selector_cases=[
                SelectorCase("list", Risk.READ_ONLY, ["action"]),
                SelectorCase("new", Risk.WRITE, ["action", "url"]),
                SelectorCase(
                    "close",
                    Risk.DESTRUCTIVE,
                    ["action", "index"],
                ),
                SelectorCase("select", Risk.WRITE, ["action", "index"]),
            ],
        )
    )
    runner = GuardedToolRunner(registry)

    listed = runner.run(
        {"name": "browser_tabs", "input": {"action": "list"}},
    )
    pending = runner.run(
        {
            "name": "browser_tabs",
            "input": {"action": "close", "index": 0},
        }
    )
    captured = []
    closed = runner.run(
        {
            "name": "browser_tabs",
            "input": {"action": "close", "index": 0},
        },
        confirm=lambda request: captured.append(request) or True,
    )
    unknown = runner.run(
        {"name": "browser_tabs", "input": {"action": "drop"}},
    )
    inactive = runner.run(
        {
            "name": "browser_tabs",
            "input": {"action": "list", "index": 0},
        }
    )

    _check(
        listed.executed
        and not listed.decision.needs_confirm
        and pending.decision.allow
        and pending.decision.needs_confirm
        and not pending.executed
        and closed.executed
        and closed.decision.needs_confirm
        and not unknown.executed
        and not unknown.decision.allow
        and not inactive.executed
        and not inactive.decision.allow,
        "installed exact selector branch did not fail closed",
    )
    request = captured[0]
    _check(
        request.risk == "destructive"
        and request.selector == "action"
        and request.selector_value_json == '"close"'
        and request.active_args == ("action", "index"),
        "installed confirmation did not bind exact selector evidence",
    )
    _check(
        calls == [("list", None, None), ("close", 0, None)],
        "installed selector branch invoked an unexpected call",
    )


def _daybreak_post_audit_regressions() -> None:
    """Repeat the final pre-release audit findings from the installed wheel."""

    for name in (
        "messageId",
        "message-id",
        "messageID",
        "messageIdentifier",
        "MESSAGEID",
        "messageid",
        "messageId2",
        "messageIDs2",
        "messageUUID",
        "messageGuid",
        "messageuuid",
        "messageguid",
        "userId1",
        "ｍｅｓｓａｇｅｉｄ",
        "message.id",
        "message/id",
        "replyTo",
        "replyTo2",
        "reply-to",
        "userIds",
        "apiKey1",
        "url2",
        "id1",
        "key2",
        "idempotencyKey",
        "customerid",
        "orderid",
        "walletid",
        "paymentid",
        "auctionid",
        "documentid",
        "jobid",
        "orgkey",
    ):
        inferred, _ = infer_policy(Param(name, "integer"))
        _check(
            inferred is verb_authority.Policy.TRUSTED_FIXED,
            f"installed selector tokenizer relaxed {name!r}",
        )
    for name in ("keyboard", "keynote", "guidance", "uuidification", "identity"):
        inferred, confidence = infer_policy(Param(name, "integer"))
        _check(
            inferred is verb_authority.Policy.TRUSTED_FIXED
            and confidence is Confidence.UNCERTAIN,
            f"installed selector tokenizer matched substring-only name {name!r}",
        )
    for name in ("valid", "grid", "monkey", "liquid", "hockey"):
        inferred, confidence = infer_policy(Param(name, "integer"))
        _check(
            inferred is Policy.TRUSTED_FIXED
            and confidence is Confidence.UNCERTAIN,
            f"installed selector suffix did not fail closed for {name!r}",
        )
    inferred, confidence = infer_policy(Param("valid", "boolean", sink=False))
    _check(
        inferred is Policy.TYPED_BOUNDED and confidence is Confidence.HIGH,
        "installed explicit sink=False did not release selector-suffix ambiguity",
    )
    for name in (
        "primaryRecipient",
        "recipient1",
        "backup-account",
        "account2",
        "settlement.IBAN",
        "callbackURL",
        "backup-uri",
        "replyURI",
        "service/endpoint",
        "targetHost",
        "event.webhook",
        "idempotencyPath",
        "source-file",
        "runCmd",
        "execute-command",
        "primary.shell",
        "accessToken",
        "user-password",
        "api.secret",
        "service/credential",
        "api-key",
        "apiKey",
        "message/destination",
        "recipients",
        "accounts",
        "ibans",
        "urls",
        "uris",
        "endpoints",
        "hosts",
        "webhooks",
        "paths",
        "files",
        "cmds",
        "commands",
        "shells",
        "tokens",
        "passwords",
        "secrets",
        "credentials",
        "destinations",
        "apiKeys",
    ):
        inferred, confidence = infer_policy(Param(name, "integer"))
        _check(
            inferred is verb_authority.Policy.TRUSTED_FIXED
            and confidence is Confidence.HIGH,
            f"installed authority tokenizer relaxed {name!r}",
        )
    for name in (
        "profile",
        "compile",
        "commandment",
        "tokenization",
        "hostility",
        "pathway",
        "pathology",
        "accountancy",
        "secretive",
    ):
        inferred, confidence = infer_policy(Param(name, "integer"))
        _check(
            inferred is verb_authority.Policy.TRUSTED_FIXED
            and confidence is Confidence.UNCERTAIN,
            f"installed authority tokenizer matched substring-only name {name!r}",
        )

    max_length_registry = Registry()
    max_length_registry.add(
        Tool(
            "browser_tabs",
            [Param("action", "string", max_len=201)],
            risk=Risk.WRITE,
        )
    )
    max_length_policy = build_policy(max_length_registry)
    max_length_decision = dispatch(
        max_length_registry,
        max_length_policy,
        {"name": "browser_tabs", "input": {"action": "close"}},
    )
    _check(
        max_length_policy.policy["browser_tabs"]["action"]
        is Policy.TRUSTED_FIXED
        and ("browser_tabs", "action") in max_length_policy.review
        and not max_length_decision.allow
        and "locked sink" in max_length_decision.reason,
        "installed maxLength-only string became data-authorable",
    )
    flatcase_name = "destinationurlvalue"
    _check(
        len(flatcase_name) <= verb_authority.MAX_IDENTIFIER_INFERENCE_CHARS
        and verb_authority._identifier_tokens(flatcase_name)
        == (flatcase_name,),
        "installed identifier tokenizer rejected a bounded flatcase name",
    )
    tokenizer_started = time.perf_counter()
    uppercase_tokens = verb_authority._identifier_tokens("A" * 16_000)
    _check(
        uppercase_tokens == ()
        and time.perf_counter() - tokenizer_started < 1.0,
        "installed identifier tokenizer did not reject an overlong name",
    )
    for name in (
        "messageBody",
        "response-content",
        "agent.reply",
        "tool/description",
        "finalSummary",
        "plainText",
    ):
        inferred, confidence = infer_policy(Param(name, "string"))
        _check(
            inferred is verb_authority.Policy.OUTBOUND_PAYLOAD
            and confidence is Confidence.HIGH,
            f"installed payload tokenizer kept {name!r} unnecessarily locked",
        )
    for name in ("replyTo", "contentURL", "messageId"):
        inferred, _ = infer_policy(Param(name, "string"))
        _check(
            inferred is verb_authority.Policy.TRUSTED_FIXED,
            f"installed payload tokenizer overrode authority in {name!r}",
        )
    for name in (
        "somebody",
        "bodyguard",
        "messageboard",
        "contentious",
        "textile",
        "notebook",
        "replying",
        "summaryCount",
        "descriptionHash",
    ):
        inferred, _ = infer_policy(Param(name, "string"))
        _check(
            inferred is verb_authority.Policy.TRUSTED_FIXED,
            f"installed payload tokenizer matched substring/nonfinal {name!r}",
        )
    inferred, confidence = infer_policy(Param("ｂａｃｋｕｐ＿ｐａｔｈ", "integer"))
    _check(
        inferred is verb_authority.Policy.TRUSTED_FIXED
        and confidence is Confidence.HIGH,
        "installed tokenizer did not normalize a fullwidth authority name",
    )
    for name in ("рath", "סכום", "金額", "---", "12345"):
        inferred, confidence = infer_policy(Param(name, "integer"))
        explicit, explicit_confidence = infer_policy(
            Param(name, "integer", sink=False)
        )
        _check(
            inferred is verb_authority.Policy.TRUSTED_FIXED
            and confidence is Confidence.UNCERTAIN,
            f"installed tokenizer trusted unmodelled identifier {name!r}",
        )
        _check(
            explicit is verb_authority.Policy.TYPED_BOUNDED
            and explicit_confidence is Confidence.HIGH,
            f"explicit non-sink did not override identifier review for {name!r}",
        )

    enum_registry = Registry()
    enum_registry.add(
        Tool(
            "choose",
            [Param("mode", "enum", enum=list(range(5_000)), sink=False)],
            risk=Risk.READ_ONLY,
        )
    )
    frozen_enum = verb_authority._freeze_registry(
        enum_registry,
        validate_callable=False,
    ).tools["choose"].params[0]
    candidate = ["not-present" * 100]
    canonical_calls = 0
    original_canonical = verb_authority._canonical_json_value

    def counted_canonical(value: Any) -> str:
        nonlocal canonical_calls
        canonical_calls += 1
        return original_canonical(value)

    verb_authority._canonical_json_value = counted_canonical
    try:
        enum_allowed = verb_authority._type_ok(frozen_enum, candidate)
    finally:
        verb_authority._canonical_json_value = original_canonical
    _check(
        not enum_allowed and canonical_calls == 1,
        "installed enum validation serialized one candidate per enum member",
    )

    ledger = verb_authority.ProvenanceLedger()
    ledger.record_result(
        {"content": "observed https://attacker.invalid/path in tool output"}
    )
    registry = Registry()
    registry.add(
        Tool(
            "send",
            [
                Param("recipient", "uri", sink=True),
                Param("body", "string", sink=False),
            ],
            risk=Risk.WRITE,
        )
    )
    policy = build_policy(registry)
    clean_call = {
        "name": "send",
        "input": {
            "recipient": "https://approved.example/path",
            "body": "hello",
        },
    }
    lookup_calls = 0
    original_lookup = verb_authority.ProvenanceLedger._is_tainted_with_budget

    def counted_lookup(self: Any, value: Any, budget: Any) -> bool:
        nonlocal lookup_calls
        lookup_calls += 1
        return original_lookup(self, value, budget)

    verb_authority.ProvenanceLedger._is_tainted_with_budget = counted_lookup
    try:
        untrusted = dispatch(registry, policy, clean_call, ledger=ledger)
    finally:
        verb_authority.ProvenanceLedger._is_tainted_with_budget = original_lookup
    _check(
        not untrusted.allow and lookup_calls == 0,
        "installed dispatcher scanned ledger history when trust could not promote",
    )

    original_lookup_limit = verb_authority.MAX_LEDGER_LOOKUP_CHARACTERS
    verb_authority.MAX_LEDGER_LOOKUP_CHARACTERS = 1
    try:
        budgeted = dispatch(
            registry,
            policy,
            clean_call,
            trusted_args={"recipient": clean_call["input"]["recipient"]},
            ledger=ledger,
        )
    finally:
        verb_authority.MAX_LEDGER_LOOKUP_CHARACTERS = original_lookup_limit
    _check(
        not budgeted.allow and "locked sink" in budgeted.reason,
        "installed ledger lookup budget did not fail closed",
    )

    composed_document = {
        "tools": [
            {
                "name": "read_record",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "allOf": [
                        {
                            "properties": {
                                "recipient": {
                                    "type": "string",
                                    "format": "email",
                                }
                            },
                            "required": ["recipient"],
                        }
                    ],
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "read_record": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "declared",
                    "effects": ["reads_record"],
                }
            }
        },
    }
    composed_report = scan_documents(
        [composed_document],
        control_declarations=controls,
    )
    _check(
        composed_report["summary"]["schema_review_required_tools"] == 1
        and composed_report["summary"]["risk_review_required_tools"] == 0
        and composed_report["tools"][0]["schema_review_required"] is True
        and composed_report["tools"][0]["arguments"] == [],
        "installed scanner silently omitted composed authority",
    )

    unmodeled_required_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "required": ["recipient"],
                },
            }
        ]
    }
    unmodeled_required_report = scan_documents([unmodeled_required_document])
    _check(
        unmodeled_required_report["summary"]["schema_review_required_tools"] == 1
        and unmodeled_required_report["tools"][0]["schema_review_required"] is True
        and unmodeled_required_report["tools"][0]["arguments"] == [],
        "installed scanner silently omitted an unmodeled required argument",
    )

    union_document = {
        "tools": [
            {
                "name": "pay_invoice",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "amount": {
                            "type": ["integer", "string"],
                            "maximum": 100,
                        }
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    union_controls = {
        "version": 1,
        "tools": {
            "pay_invoice": {
                "risk": {
                    "tier": "financial",
                    "evidence": "attested",
                    "effects": ["commits_funds"],
                }
            }
        },
    }
    union_report = scan_documents(
        [union_document], control_declarations=union_controls
    )
    union_argument = union_report["tools"][0]["arguments"][0]
    _check(
        union_report["tools"][0]["schema_review_required"] is True
        and union_argument["type"] == "json"
        and union_argument["policy"] == "trusted_fixed"
        and union_argument["review_required"] is True,
        "installed scanner treated a multi-type union as a bounded integer",
    )

    direct_shape_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "enum": {"type": "string", "enum": ["notice"]},
                    "recipient": {"type": "string", "format": "email"},
                    "body": {"type": "string"},
                },
            }
        ]
    }
    direct_shape_controls = {
        "version": 1,
        "tools": {
            "send_message": {
                "risk": {
                    "tier": "write",
                    "evidence": "attested",
                    "effects": ["sends_message"],
                }
            }
        },
    }
    direct_shape_report = scan_documents(
        [direct_shape_document], control_declarations=direct_shape_controls
    )
    direct_arguments = {
        argument["name"]: argument
        for argument in direct_shape_report["tools"][0]["arguments"]
    }
    _check(
        set(direct_arguments) == {"enum", "recipient", "body"}
        and direct_arguments["recipient"]["policy"] == "trusted_fixed"
        and direct_shape_report["tools"][0]["schema_review_required"] is True,
        "installed scanner dropped direct-shape arguments after a keyword collision",
    )

    inconsistent = copy.deepcopy(composed_report)
    inconsistent["declared_controls"]["tools"][0]["risk"]["effects"].append(
        "different_effect"
    )
    inconsistent["control_declaration_fingerprint_sha256"] = (
        verb_authority_scan._control_declaration_fingerprint(
            inconsistent["declared_controls"]
        )
    )
    try:
        diff_reports(composed_report, inconsistent)
    except DiffError as exc:
        _check(
            "risk conflicts with the report tool" in str(exc),
            f"installed report validator returned the wrong conflict: {exc}",
        )
    else:
        raise AssertionError(
            "installed Authority Diff accepted inconsistent duplicated risk"
        )

    hostile_name = "![audit](https://example.invalid/pixel)`label`"
    hostile_markdown = render_markdown(
        scan_documents(
            [
                {
                    "tools": [
                        {
                            "name": hostile_name,
                            "inputSchema": {
                                "properties": {
                                    hostile_name: {"type": "string"}
                                }
                            },
                        }
                    ]
                }
            ]
        )
    )
    _check(
        hostile_name not in hostile_markdown
        and "![audit](" not in hostile_markdown
        and "https://example.invalid/pixel" not in hostile_markdown
        and "\\!\\[audit\\](https&#58;//example.invalid/pixel)\\`label\\`"
        in hostile_markdown,
        "installed Markdown renderer emitted an active image or link",
    )

    with TemporaryDirectory(prefix="verb-authority-composed-smoke-") as directory:
        root = Path(directory)
        schema_path = root / "schema.json"
        controls_path = root / "controls.json"
        report_path = root / "report.json"
        schema_path.write_text(json.dumps(composed_document), encoding="utf-8")
        controls_path.write_text(json.dumps(controls), encoding="utf-8")
        exit_code = verb_authority_scan.main(
            [
                str(schema_path),
                "--controls",
                str(controls_path),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--fail-on-review",
            ]
        )
        _check(
            exit_code == 2,
            "installed scan CLI did not fail on unresolved schema composition",
        )
        schema_path.write_text(
            json.dumps(unmodeled_required_document), encoding="utf-8"
        )
        required_exit_code = verb_authority_scan.main(
            [
                str(schema_path),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--fail-on-review",
            ]
        )
        _check(
            required_exit_code == 2,
            "installed scan CLI ignored an unmodeled required argument",
        )
        schema_path.write_text(json.dumps(union_document), encoding="utf-8")
        controls_path.write_text(json.dumps(union_controls), encoding="utf-8")
        union_exit_code = verb_authority_scan.main(
            [
                str(schema_path),
                "--controls",
                str(controls_path),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--fail-on-review",
            ]
        )
        _check(
            union_exit_code == 2,
            "installed scan CLI ignored a multi-type union",
        )
        schema_path.write_text(
            json.dumps(direct_shape_document), encoding="utf-8"
        )
        controls_path.write_text(
            json.dumps(direct_shape_controls), encoding="utf-8"
        )
        direct_exit_code = verb_authority_scan.main(
            [
                str(schema_path),
                "--controls",
                str(controls_path),
                "--format",
                "json",
                "--output",
                str(report_path),
                "--fail-on-review",
            ]
        )
        _check(
            direct_exit_code == 2,
            "installed scan CLI ignored a direct-shape keyword collision",
        )

    open_before = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "recipient": {"type": "string", "format": "email"}
                    },
                    "additionalProperties": True,
                },
            }
        ]
    }
    open_after = copy.deepcopy(open_before)
    open_after["tools"][0]["inputSchema"]["properties"] = {}
    open_diff = diff_reports(
        scan_documents([open_before]), scan_documents([open_after])
    )
    removed = next(
        change
        for change in open_diff["changes"]
        if change["kind"] == "argument_removed"
    )
    _check(
        removed["classification"] == "authority_increase",
        "installed diff treated a modeled argument removed from an open schema "
        "as protection",
    )

    bounds_document = {
        "tools": [
            {
                "name": "purchase_bid",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "bidWei": {"type": "integer", "maximum": 100}
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    bounds_controls = {
        "version": 1,
        "tools": {
            "purchase_bid": {
                "risk": {
                    "tier": "financial",
                    "evidence": "attested",
                    "effects": ["commits_funds"],
                },
                "arguments": {
                    "bidWei": {
                        "authority": "constrained",
                        "evidence": "attested",
                        "bounds": [
                            {
                                "source": "immutable ceiling",
                                "bounds_mutability": "immutable",
                                "operational_status": "enforced",
                                "enforcement": "constant check",
                            }
                        ],
                    }
                },
            }
        },
    }
    bounds_before = scan_documents(
        [bounds_document], control_declarations=bounds_controls
    )
    bounds_after = copy.deepcopy(bounds_before)
    after_bound = bounds_after["declared_controls"]["tools"][0]["arguments"][0]
    after_bound["bounds"] = [
        {
            "source": "caller ceiling one",
            "bounds_mutability": "caller",
            "operational_status": "enforced",
            "enforcement": "request check",
        },
        {
            "source": "caller ceiling two",
            "bounds_mutability": "caller",
            "operational_status": "enforced",
            "enforcement": "request check",
        },
    ]
    bounds_after["control_declaration_fingerprint_sha256"] = (
        verb_authority_scan._control_declaration_fingerprint(
            bounds_after["declared_controls"]
        )
    )
    bounds_diff = diff_reports(bounds_before, bounds_after)
    bounds_change = next(
        change
        for change in bounds_diff["changes"]
        if change["kind"] == "bounds_changed"
    )
    _check(
        bounds_change["classification"] == "authority_increase",
        "installed diff treated caller-controlled bounds as stronger than an "
        "immutable bound",
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
                Param("amount", "number", sink=False),
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
        type(request.risk) is str
        and request.risk == "financial"
        and type(request.risk_assessment.risk) is str
        and request.risk_assessment.risk == "financial"
        and type(request.risk_assessment.confidence) is str,
        "confirmation omitted detached effective risk evidence",
    )
    _check(
        type(request.declared_risk) is str
        and request.declared_risk == "financial",
        "confirmation retained a process-wide declared-risk Enum member",
    )
    try:
        request.declared_risk._value_ = "read_only"
    except AttributeError:
        pass
    else:
        raise AssertionError(
            "installed confirmation declared risk exposes mutable Enum metadata"
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

    calls = []
    version_registry = Registry()
    version_registry.add(
        Tool(
            "evaluate",
            [],
            fn=lambda: calls.append("invoked"),
            risk=Risk.UNKNOWN,
        )
    )
    version_runner = GuardedToolRunner(version_registry)

    def forge_display_version(request) -> bool:
        version_runner.ledger.record_result({"unrelated": "tool result"})
        object.__setattr__(
            request,
            "ledger_version",
            version_runner.ledger.version,
        )
        return True

    forged = version_runner.run(
        {"name": "evaluate", "input": {}},
        confirm=forge_display_version,
    )
    _check(
        not forged.decision.allow
        and not forged.invoked
        and not forged.executed
        and "provenance ledger changed" in forged.decision.reason
        and not calls,
        "confirmation display mutation forged the private ledger commitment",
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


def _mcp_annotation_assessment_contract() -> None:
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "read_record",
                        "annotations": {"readOnlyHint": True},
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                        },
                    },
                    {
                        "name": "write_record",
                        "annotations": {
                            "readOnlyHint": True,
                            "destructiveHint": True,
                            "idempotentHint": False,
                            "openWorldHint": False,
                        },
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                        },
                    },
                ]
            }
        ],
        control_declarations={
            "version": 1,
            "tools": {
                "read_record": {
                    "risk": {
                        "tier": "read_only",
                        "evidence": "observed",
                        "effects": ["reads_record"],
                    }
                },
                "write_record": {
                    "risk": {
                        "tier": "write",
                        "evidence": "observed",
                        "effects": ["writes_record"],
                    }
                },
            },
        },
    )
    _check(
        report["report_version"] == 6,
        "MCP annotation evidence was not emitted in report v6",
    )
    tools = {tool["name"]: tool for tool in report["tools"]}
    read_assessments = {
        assessment["annotation"]: assessment
        for assessment in tools["read_record"]["annotation_assessments"]
    }
    write_assessments = {
        assessment["annotation"]: assessment
        for assessment in tools["write_record"]["annotation_assessments"]
    }
    _check(
        read_assessments["readOnlyHint"]["state"] == "consistent",
        "installed scanner lost a consistent MCP annotation assessment",
    )
    _check(
        {
            name: assessment["state"]
            for name, assessment in write_assessments.items()
        }
        == {
            "readOnlyHint": "conflict",
            "destructiveHint": "inapplicable",
            "idempotentHint": "inapplicable",
            "openWorldHint": "unresolved",
        },
        "installed scanner changed structured MCP annotation states",
    )
    all_assessments = [*read_assessments.values(), *write_assessments.values()]
    expected_fields = {
        "annotation",
        "value",
        "state",
        "evidence_source",
        "trust",
        "comparison_source",
        "comparison_value",
    }
    _check(
        all(
            set(assessment) == expected_fields
            and assessment["evidence_source"] == "mcp_tool_annotation"
            and assessment["trust"] == "unverified_hint"
            for assessment in all_assessments
        ),
        "installed scanner promoted MCP hints or lost assessment provenance",
    )
    _check(
        tools["write_record"]["annotation_conflicts"]
        == ["readOnlyHint=true conflicts with effective risk"]
        and report["summary"]["annotation_conflicts"] == 1,
        "installed scanner lost the derived MCP annotation conflict",
    )


def _tool_review_aggregate_contract() -> None:
    document = {
        "tools": [
            {
                "name": "browser_tabs",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "action": {
                            "type": "string",
                            "enum": ["list", "close"],
                        },
                        "index": {"type": "number"},
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "browser_tabs": {
                "risk": {
                    "tier": "write",
                    "evidence": "observed",
                    "effects": ["changes_tab_state"],
                }
            }
        },
    }
    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]
    _check(
        report["report_version"] == 6
        and tool["review_required"] is True
        and tool["review_sources"]
        == {
            "arguments": ["action", "index"],
            "schema": False,
            "risk": False,
            "risk_conflict": False,
            "annotation_conflicts": [],
            "branch_risk": True,
        }
        and report["summary"]["review_required_tools"] == 1,
        "installed scanner lost the report-v6 tool review aggregate",
    )
    _check(
        "## Tool review summary" in render_markdown(report),
        "installed Markdown report omitted the tool review summary",
    )
    arguments = {argument["name"]: argument for argument in tool["arguments"]}
    _check(
        arguments["action"]["remediation_status"] == "review_required"
        and arguments["action"]["preferred_remediation"] is None
        and arguments["action"]["fallback_remediation"] is None
        and arguments["action"]["remediation_review_reason"]
        == "selector_semantics_require_review"
        and arguments["index"]["remediation_review_reason"]
        == "authority_inference_requires_review",
        "installed scanner lost uncertain remediation review reasons",
    )

    forged = copy.deepcopy(report)
    forged["tools"][0]["review_required"] = False
    try:
        diff_reports(forged, copy.deepcopy(forged))
    except DiffError as exc:
        _check(
            "review_required is inconsistent" in str(exc),
            "installed diff reported the wrong aggregate-forgery boundary",
        )
    else:
        raise AssertionError("installed diff accepted a forged review aggregate")

    remediation_fields = (
        "remediation_status",
        "preferred_remediation",
        "fallback_remediation",
        "remediation_review_reason",
    )
    legacy_v5 = copy.deepcopy(report)
    legacy_v5["report_version"] = 5
    for legacy_tool in legacy_v5["tools"]:
        for argument in legacy_tool["arguments"]:
            for field in remediation_fields:
                argument.pop(field, None)
    frozen_v5 = copy.deepcopy(legacy_v5)
    v5_diff = diff_reports(legacy_v5, report)
    _check(
        v5_diff["changes"] == [] and legacy_v5 == frozen_v5,
        "installed diff did not preserve v5-to-v6 observational compatibility",
    )

    legacy = copy.deepcopy(legacy_v5)
    legacy["report_version"] = 4
    legacy["summary"].pop("review_required_tools")
    for legacy_tool in legacy["tools"]:
        legacy_tool.pop("review_required")
        legacy_tool.pop("review_sources")
    frozen_legacy = copy.deepcopy(legacy)
    legacy_diff = diff_reports(legacy, report)
    _check(
        legacy_diff["changes"] == [] and legacy == frozen_legacy,
        "installed diff did not preserve v4-to-v6 observational compatibility",
    )

    confirmation_only = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "erase_store",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ],
        control_declarations={
            "version": 1,
            "tools": {
                "erase_store": {
                    "risk": {
                        "tier": "destructive",
                        "evidence": "observed",
                        "effects": ["deletes_store"],
                    }
                }
            },
        },
    )["tools"][0]
    _check(
        confirmation_only["needs_confirmation"] is True
        and confirmation_only["review_required"] is False,
        "installed scanner conflated runtime confirmation with static review debt",
    )


def _remediation_guidance_contract() -> None:
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "send_email",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "to": {"type": "string"},
                                "body": {"type": "string"},
                            },
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ]
    )
    arguments = {
        argument["name"]: argument
        for argument in report["tools"][0]["arguments"]
    }
    recipient = arguments["to"]
    _check(
        recipient["policy"] == "trusted_fixed"
        and recipient["review_required"] is False
        and recipient["remediation_status"] == "recommended"
        and recipient["preferred_remediation"]
        == "remove_from_model_schema_and_inject_from_application"
        and recipient["fallback_remediation"]
        == "bind_trusted_value_at_runtime"
        and recipient["remediation_review_reason"] is None,
        "installed scanner lost trusted-fixed remediation guidance",
    )
    _check(
        not {
            "remediation_status",
            "preferred_remediation",
            "fallback_remediation",
            "remediation_review_reason",
        }.intersection(arguments["body"]),
        "installed scanner attached protected remediation to a data-fillable argument",
    )
    markdown = render_markdown(report)
    _check(
        "## Remediation guidance" in markdown
        and "remove_from_model_schema_and_inject_from_application" in markdown
        and "bind_trusted_value_at_runtime" in markdown,
        "installed Markdown report omitted remediation guidance",
    )


def _constraint_diff_and_migration() -> None:
    before_document = _constraint_document(100, 40, ["safe"])
    after_document = _constraint_document(
        10**12, 10**9, ["safe", "unrestricted"]
    )
    before = scan_documents([before_document])
    after = scan_documents([after_document])
    _check(before["report_version"] == 6, "scanner did not produce report v6")
    privacy = before["privacy"]
    _check(
        privacy["examples_included"] is False
        and privacy["defaults_included"] is False
        and privacy["runtime_values_included"] is False
        and "examples_or_values_included" not in privacy,
        "report v6 privacy fields do not separately exclude values",
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
    legacy["report_version"] = 3
    for tool in legacy["tools"]:
        tool.pop("annotation_assessments", None)
    try:
        diff_reports(legacy, copy.deepcopy(legacy))
    except DiffError as exc:
        _check("rescan" in str(exc), "legacy report rejection omitted rescan guidance")
    else:
        raise AssertionError("legacy report v3 was compared as if current")

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
        "MAX_SCAN_TOTAL_INPUT_BYTES",
        "MAX_SCAN_SCHEMA_DOCUMENTS",
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
        for legacy_version in (2, 3):
            legacy = copy.deepcopy(base_report)
            legacy["report_version"] = legacy_version
            if legacy_version == 3:
                for tool in legacy["tools"]:
                    tool.pop("annotation_assessments", None)
            malformed_reports.append((f"legacy-v{legacy_version}", legacy))
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


def _daybreak_followup_regressions() -> None:
    """Repeat the post-adeb1fa audit families from the installed artifact."""

    calls: list[dict[str, Any]] = []

    def write_selection(**arguments: Any) -> dict[str, bool]:
        calls.append(arguments)
        return {"ok": True}

    for selector_name in (
        "recipientiD",
        "messageiD2",
        "walletkeY",
        "customeruuiD",
        "messageI_D",
        "messageI-D",
        "walletK_eY",
    ):
        registry = Registry()
        registry.add(
            Tool(
                "write_selection",
                [Param(selector_name, "integer")],
                fn=write_selection,
                risk=Risk.WRITE,
            )
        )
        policy = build_policy(registry)
        execution = GuardedToolRunner(registry, policy).run(
            {
                "name": "write_selection",
                "input": {selector_name: 7},
            }
        )
        _check(
            policy.policy["write_selection"][selector_name]
            is Policy.TRUSTED_FIXED
            and ("write_selection", selector_name) in policy.review
            and not execution.invoked
            and not execution.executed,
            f"installed mixed-case selector bypassed authority: {selector_name}",
        )
    _check(calls == [], "installed selector regression reached an executor")

    normalization_calls: list[tuple[str, str]] = []
    original_unicode = verb_authority.unicodedata
    original_normalize = original_unicode.normalize

    def counted_normalize(form: str, value: str) -> str:
        normalization_calls.append((form, value))
        return original_normalize(form, value)

    normalization_registry = Registry()
    normalization_registry.add(
        Tool(
            "send_value",
            [Param("destination", "json", sink=True)],
            risk=Risk.WRITE,
        )
    )
    normalization_policy = build_policy(normalization_registry)
    verb_authority.unicodedata = types.SimpleNamespace(
        normalize=counted_normalize,
        name=original_unicode.name,
    )
    try:
        rejected = verb_authority.gate(
            normalization_registry,
            normalization_policy,
            "send_value",
            {
                "destination": [
                    "é" * verb_authority.MAX_NFKC_INPUT_CHARS
                ]
                * 300
            },
            {"destination": "data"},
        )
        _check(
            not rejected.allow and normalization_calls == [],
            "installed gate normalized a data-authored locked sink before denial",
        )

        adversarial = "\u0315\u0300" * (
            verb_authority.MAX_NFKC_INPUT_CHARS // 2
        )
        duplicate_ledger = verb_authority.ProvenanceLedger()
        duplicate_ledger.record_result([adversarial] * 300)
        duplicate_ledger.record_result([adversarial] * 300)
        _check(
            not duplicate_ledger.saturated and len(normalization_calls) == 1,
            "installed ledger repeated NFKC work for duplicate result leaves",
        )
    finally:
        verb_authority.unicodedata = original_unicode

    overlong_unicode = "a" + "\u0315\u0300" * (
        verb_authority.MAX_NFKC_INPUT_CHARS // 2 + 1
    )
    _check(
        verb_authority._identifier_tokens(overlong_unicode) == ()
        and verb_authority._has_mixed_script(overlong_unicode),
        "installed runtime entered unbounded identifier normalization",
    )
    long_hebrew = "א" * (verb_authority.MAX_NFKC_INPUT_CHARS + 1)
    ledger = verb_authority.ProvenanceLedger()
    ledger.record_result({"payload": long_hebrew})
    _check(
        not ledger.saturated
        and ledger._normalization_incomplete is True
        and ledger._ascii_normalization_incomplete is False
        and not ledger.is_tainted("https://approved.example/path")
        and ledger.is_tainted("https://例え.テスト/path")
        and not ledger.is_tainted("ordinary short text"),
        "installed ledger mishandled its bounded partial canonical index",
    )
    skeleton_ledger = verb_authority.ProvenanceLedger()
    skeleton_ledger.record_result(
        {
            "payload": long_hebrew
            + "ｈｔｔｐｓ：／／ｅｖｉｌ．ｅｘａｍｐｌｅ／ｐａｔｈ "
            + "attacker [a t] evil {d\to\tt} com"
        }
    )
    _check(
        skeleton_ledger.is_tainted("https://evil.example/path")
        and skeleton_ledger.is_tainted("attacker@evil.com")
        and not skeleton_ledger.is_tainted("https://approved.example/path"),
        "installed ledger lost an ASCII destination hidden in long Unicode",
    )

    ambiguous_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "properties": {"recipient": {"type": "string"}}
                },
            }
        ]
    }
    ambiguous_report = scan_documents([ambiguous_document])
    _check(
        ambiguous_report["tools"][0]["schema_review_required"] is True
        and [
            argument["name"]
            for argument in ambiguous_report["tools"][0]["arguments"]
        ]
        == ["recipient"],
        "installed scanner produced a clean properties collision",
    )
    empty_collision = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "send_message",
                        "inputSchema": {"properties": {}},
                    }
                ]
            }
        ]
    )
    _check(
        empty_collision["tools"][0]["schema_review_required"] is True,
        "installed scanner produced a clean empty properties collision",
    )

    pattern_before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}},
                    "additionalProperties": False,
                },
            }
        ]
    }
    pattern_after_document = copy.deepcopy(pattern_before_document)
    pattern_after_schema = pattern_after_document["tools"][0]["inputSchema"]
    pattern_after_schema["properties"] = {}
    pattern_after_schema["patternProperties"] = {"^recipient$": True}
    pattern_after = scan_documents([pattern_after_document])
    pattern_diff = diff_reports(
        scan_documents([pattern_before_document]),
        pattern_after,
    )
    removed = next(
        change
        for change in pattern_diff["changes"]
        if change["kind"] == "argument_removed"
    )
    _check(
        pattern_after["tools"][0]["schema_closes_unknown_arguments"] is False
        and pattern_after["tools"][0]["schema_review_required"] is True
        and removed["classification"] == "authority_increase",
        "installed diff presented patternProperties removal as protection",
    )

    exposure_before_document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {"recipient": {"type": "string"}},
                    "additionalProperties": True,
                },
            }
        ]
    }
    exposure_after_document = copy.deepcopy(exposure_before_document)
    exposure_after_document["tools"][0]["inputSchema"]["properties"] = {}
    exposure_before_controls = {
        "version": 1,
        "tools": {
            "send_message": {
                "arguments": {
                    "recipient": {
                        "authority": "locked",
                        "evidence": "declared",
                    }
                }
            }
        },
    }
    exposure_after_controls = {
        "version": 1,
        "tools": {
            "send_message": {
                "unexposed_arguments": {
                    "recipient": {
                        "exposure": "server_fixed",
                        "enforced_by": "authenticated session",
                        "evidence": "declared",
                    }
                }
            }
        },
    }
    exposure_after = scan_documents(
        [exposure_after_document],
        control_declarations=exposure_after_controls,
    )
    exposure_diff = diff_reports(
        scan_documents(
            [exposure_before_document],
            control_declarations=exposure_before_controls,
        ),
        exposure_after,
    )
    exposure_change = next(
        change
        for change in exposure_diff["changes"]
        if change["kind"] == "argument_exposure_changed"
    )
    _check(
        exposure_after["tools"][0]["schema_review_required"] is True
        and exposure_change["classification"] == "authority_increase",
        "installed diff trusted an unexposed declaration on an open schema",
    )

    bound_schema = {
        "tools": [
            {
                "name": "place_order",
                "inputSchema": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}},
                    "additionalProperties": False,
                },
            }
        ]
    }

    def bound(source: str) -> dict[str, Any]:
        return {
            "source": source,
            "bounds_mutability": "immutable",
            "operational_status": "enforced",
            "enforcement": source,
        }

    def controls(bounds: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "version": 1,
            "tools": {
                "place_order": {
                    "risk": {
                        "tier": "write",
                        "evidence": "attested",
                        "effects": ["places_order"],
                    },
                    "arguments": {
                        "amount": {
                            "authority": "constrained",
                            "evidence": "attested",
                            "bounds": bounds,
                        }
                    },
                }
            },
        }

    bound_diff = diff_reports(
        scan_documents(
            [bound_schema],
            control_declarations=controls([bound("amount <= 100")]),
        ),
        scan_documents(
            [bound_schema],
            control_declarations=controls(
                [bound("amount <= 1000000000"), bound("amount >= 0")]
            ),
        ),
    )
    bound_change = next(
        change
        for change in bound_diff["changes"]
        if change["kind"] == "bounds_changed"
    )
    _check(
        bound_change["classification"] == "review"
        and bound_diff["summary"]["protection_increases"] == 0,
        "installed diff ordered replacement bounds by count",
    )

    downgrade_before = controls(
        [
            {
                "source": "absolute ceiling",
                "bounds_mutability": "immutable",
                "operational_status": "enforced",
                "enforcement": "constant check",
            }
        ]
    )
    downgrade_after = controls(
        [
            {
                "source": "absolute ceiling",
                "bounds_mutability": "trusted_party",
                "operational_status": "enforced",
                "enforcement": "constant check",
            },
            {
                "source": "different immutable budget",
                "bounds_mutability": "immutable",
                "operational_status": "enforced",
                "enforcement": "separate constant check",
            },
        ]
    )
    downgrade_diff = diff_reports(
        scan_documents(
            [bound_schema], control_declarations=downgrade_before
        ),
        scan_documents([bound_schema], control_declarations=downgrade_after),
    )
    downgrade_change = next(
        change
        for change in downgrade_diff["changes"]
        if change["kind"] == "bounds_changed"
    )
    _check(
        downgrade_change["classification"] == "authority_increase",
        "installed diff let a new bound mask a known bound downgrade",
    )

    commit = "0123456789abcdef0123456789abcdef01234567"
    short_commit = commit[:7]
    markdown = render_markdown(
        scan_documents(
            [
                {
                    "tools": [
                        {
                            "name": (
                                f"GH-26 #7 @yairsabag {short_commit} {commit}"
                            ),
                            "inputSchema": {"type": "object"},
                        }
                    ]
                }
            ]
        )
    )
    _check(
        "GH-26" not in markdown
        and "#7" not in markdown
        and "@yairsabag" not in markdown
        and commit not in markdown
        and "GH&#8204;-26" in markdown
        and "#&#8204;7" in markdown
        and "@&#8204;yairsabag" in markdown
        and short_commit[:3] + "&#8204;" + short_commit[3:] in markdown,
        "installed Markdown renderer emitted a GitHub reference",
    )

    original_total = verb_authority_scan.MAX_SCAN_TOTAL_INPUT_BYTES
    original_documents = verb_authority_scan.MAX_SCAN_SCHEMA_DOCUMENTS
    try:
        with TemporaryDirectory(prefix="verb-authority-wheel-aggregate-") as directory:
            root = Path(directory)
            schema_path = root / "schema.json"
            output_path = root / "report.json"
            schema_text = " " * 80 + json.dumps(
                {
                    "tools": [
                        {
                            "name": "read_record",
                            "inputSchema": {
                                "type": "object",
                                "properties": {},
                            },
                        }
                    ]
                }
            )
            schema_path.write_text(schema_text, encoding="utf-8")
            verb_authority_scan.MAX_SCAN_TOTAL_INPUT_BYTES = len(schema_text) + 1
            stderr = io.StringIO()
            try:
                with contextlib.redirect_stderr(stderr):
                    verb_authority_scan.main(
                        [
                            str(schema_path),
                            str(schema_path),
                            "--format",
                            "json",
                            "--output",
                            str(output_path),
                        ]
                    )
            except SystemExit as exc:
                _check(exc.code == 2, "aggregate byte cap returned wrong status")
            else:
                raise AssertionError("installed scanner ignored aggregate bytes")

            verb_authority_scan.MAX_SCAN_TOTAL_INPUT_BYTES = original_total
            verb_authority_scan.MAX_SCAN_SCHEMA_DOCUMENTS = 1
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    verb_authority_scan.main(
                        [str(schema_path), str(schema_path), "--format", "json"]
                    )
            except SystemExit as exc:
                _check(exc.code == 2, "document cap returned wrong status")
            else:
                raise AssertionError("installed scanner ignored document count")
    finally:
        verb_authority_scan.MAX_SCAN_TOTAL_INPUT_BYTES = original_total
        verb_authority_scan.MAX_SCAN_SCHEMA_DOCUMENTS = original_documents


def _daybreak_external_audit_regressions() -> None:
    """Pin the P2 families found by the fresh exact-wheel Daybreak audit."""

    flatcase_cases = (
        ("destinationurl", "string", {"max_len": 2048}, "https://evil.example"),
        ("destinationaccount", "integer", {}, 7),
        ("targethost", "string", {"max_len": 255}, "evil.example"),
        ("runcommand", "string", {"max_len": 1024}, "curl evil.example"),
        ("accesscredential", "integer", {}, 7),
        ("destinationurlvalue", "string", {"max_len": 2048}, "https://evil.example"),
        ("targethostnamevalue", "string", {"max_len": 255}, "evil.example"),
        ("runcommandtext", "string", {"max_len": 1024}, "curl evil.example"),
        ("recipientemailaddress", "string", {"max_len": 320}, "evil@example.com"),
        ("tempfile", "string", {"max_len": 1024}, "/tmp/evil"),
        ("bankaccountnumber", "integer", {}, 7),
        ("destinationurloverride", "string", {"max_len": 2048}, "https://evil.example"),
        ("destinationurldefault", "string", {"max_len": 2048}, "https://evil.example"),
        ("destinationurloptional", "string", {"max_len": 2048}, "https://evil.example"),
        ("destinationurljson", "string", {"max_len": 2048}, "https://evil.example"),
        ("destinationurlschema", "string", {"max_len": 2048}, "https://evil.example"),
    )
    for name, param_type, options, value in flatcase_cases:
        registry = Registry()
        registry.add(
            Tool(
                "perform_action",
                [Param(name, param_type, **options)],
                risk=Risk.WRITE,
            )
        )
        policy = build_policy(registry)
        decision = dispatch(
            registry,
            policy,
            {"name": "perform_action", "input": {name: value}},
        )
        _check(
            policy.policy["perform_action"][name] is Policy.TRUSTED_FIXED
            and not decision.allow,
            f"installed flatcase authority name became data-authorable: {name}",
        )

    released_registry = Registry()
    released_registry.add(
        Tool(
            "render_value",
            [
                Param(
                    "destinationurl",
                    "string",
                    max_len=2048,
                    sink=False,
                )
            ],
            risk=Risk.WRITE,
        )
    )
    released_policy = build_policy(released_registry)
    released = dispatch(
        released_registry,
        released_policy,
        {
            "name": "render_value",
            "input": {"destinationurl": "display-only text"},
        },
    )
    _check(
        released_policy.policy["render_value"]["destinationurl"]
        is not Policy.TRUSTED_FIXED
        and released.allow,
        "installed explicit sink=False did not release an overloaded flatcase name",
    )

    for ordinary_name in (
        "profiledefault",
        "ghostraw",
        "accountingconfig",
        "hostageoptional",
        "tokenizercandidate",
    ):
        ordinary_policy, ordinary_confidence = infer_policy(
            Param(ordinary_name, "string", max_len=2048)
        )
        _check(
            ordinary_policy is Policy.TRUSTED_FIXED
            and ordinary_confidence is Confidence.UNCERTAIN,
            f"installed compact inference over-locked an ordinary word: {ordinary_name}",
        )

    overlong_name = "A" * (verb_authority.MAX_IDENTIFIER_INFERENCE_CHARS + 1)
    overlong_policy, overlong_confidence = infer_policy(
        Param(overlong_name, "string", max_len=2048)
    )
    _check(
        overlong_policy is Policy.TRUSTED_FIXED
        and overlong_confidence is Confidence.UNCERTAIN,
        "installed overlong identifier did not fail closed before lexical work",
    )

    original_value = {
        "url": "https://approved.example",
        "routes": ["primary"],
    }
    resolver = TrustedResolver(
        [TrustedChoice("production", original_value, "trusted directory")]
    )
    original_value["url"] = "https://constructor-alias.example"
    first = resolver.resolve("production")
    _check(first.resolved, "installed resolver lost a valid trusted choice")
    first.value["url"] = "https://resolution-alias.example"
    first.value["routes"].append("poisoned")
    second = resolver.resolve("production")
    _check(
        second.resolved
        and second.value
        == {"url": "https://approved.example", "routes": ["primary"]}
        and first.value is not second.value,
        "installed resolver exposed its trusted catalog through a mutable alias",
    )

    class HostileString(str):
        def strip(self, *args, **kwargs):
            raise AssertionError("hostile strip executed")

        def casefold(self):
            raise AssertionError("hostile casefold executed")

        def __hash__(self):
            raise AssertionError("hostile hash executed")

    try:
        TrustedResolver(
            [TrustedChoice(HostileString("production"), 1, "trusted directory")]
        )
    except TypeError:
        pass
    else:
        raise AssertionError("installed resolver accepted a string-subclass key")

    hostile_lookup = resolver.resolve(HostileString("production"))
    _check(
        hostile_lookup.status.value == "not_found"
        and hostile_lookup.requested_key == verb_authority._INVALID_RESOLUTION_KEY,
        "installed resolver did not reject a hostile lookup key before hooks",
    )

    normalize_calls = []

    def counting_normalizer(key):
        normalize_calls.append(key)
        return key.strip().casefold()

    bounded_resolver = TrustedResolver(
        [TrustedChoice("production", 1, "trusted directory")],
        normalize_key=counting_normalizer,
    )
    normalize_calls.clear()
    oversized_lookup = bounded_resolver.resolve(
        "A" * (verb_authority.MAX_NFKC_INPUT_CHARS + 1)
    )
    _check(
        oversized_lookup.status.value == "not_found"
        and oversized_lookup.requested_key
        == verb_authority._INVALID_RESOLUTION_KEY
        and not normalize_calls,
        "installed resolver normalized an oversized untrusted lookup key",
    )

    for bad_choice in (
        TrustedChoice("bad\ud800key", 1, "trusted directory"),
        TrustedChoice("production", 1, "bad\udfff evidence"),
    ):
        try:
            TrustedResolver([bad_choice])
        except ValueError:
            pass
        else:
            raise AssertionError("installed resolver accepted surrogate catalog text")

    mixed_dialect = {
        "tools": [
            {
                "name": "transfer_funds",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "destination_account": {"type": "string"},
                        "amount": {"type": "number"},
                    },
                    "required": ["destination_account", "amount"],
                    "additionalProperties": False,
                },
                "type": "function",
                "function": {
                    "name": "read_status",
                    "parameters": {
                        "type": "object",
                        "properties": {},
                        "additionalProperties": False,
                    },
                },
            }
        ]
    }
    try:
        scan_documents([mixed_dialect])
    except verb_authority_scan.SchemaError:
        pass
    else:
        raise AssertionError(
            "installed scanner accepted competing direct and nested dialects"
        )


def _daybreak_release_candidate_regressions() -> None:
    """Pin the final beta.8 pre-release findings in the installed wheel."""

    invalid_direct_tool = {
        "tools": [
            {
                "type": "functoin",
                "name": "set_limit",
                "parameters": {
                    "type": "object",
                    "properties": {"amount": {"type": "number"}},
                },
            }
        ]
    }
    try:
        scan_documents([invalid_direct_tool])
    except verb_authority_scan.SchemaError:
        pass
    else:
        raise AssertionError(
            "installed scanner accepted a non-function direct discriminator"
        )

    with TemporaryDirectory(prefix="verb-authority-wheel-discriminator-") as directory:
        invalid_path = Path(directory) / "invalid-direct-tool.json"
        invalid_path.write_text(json.dumps(invalid_direct_tool), encoding="utf-8")
        try:
            verb_authority_diff.load_report_or_schema(
                str(invalid_path),
                label="candidate",
            )
        except verb_authority_scan.SchemaError:
            pass
        else:
            raise AssertionError(
                "installed raw Diff loader erased a non-function discriminator"
            )

    for declared_unknown in (Risk.UNKNOWN, "unknown"):
        registry = Registry()
        registry.add(Tool("evaluate", [], risk=declared_unknown))
        policy = build_policy(registry)
        _check(
            policy.risk["evaluate"] is Risk.UNKNOWN
            and policy.risk_review == ["evaluate"]
            and policy.confirm == ["evaluate"]
            and policy.risk_conflicts == [],
            "installed explicit UNKNOWN escaped review or confirmation",
        )

        frozen_registry = Registry()
        frozen_registry.add(
            Tool(
                "evaluate",
                [],
                fn=lambda: None,
                risk=declared_unknown,
            )
        )
        runner = GuardedToolRunner(
            frozen_registry,
            build_policy(frozen_registry),
        )
        _check(
            runner.policy_set.risk["evaluate"] == "unknown"
            and runner.policy_set.risk_review == ("evaluate",)
            and runner.policy_set.confirm == ("evaluate",)
            and runner.policy_set.risk_conflicts == (),
            "installed frozen policy resolved an explicit UNKNOWN declaration",
        )

    class StatefulPolicyName(str):
        __hash__ = str.__hash__

        def __new__(cls, value):
            instance = super().__new__(cls, value)
            instance.comparisons = 0
            return instance

        def __eq__(self, other):
            self.comparisons += 1
            return self.comparisons <= 2 and str.__eq__(self, other)

    registry = Registry()
    registry.add(Tool("evaluate", [], risk=Risk.UNKNOWN))
    forged_policy = build_policy(registry)
    forged_name = StatefulPolicyName("evaluate")
    forged_policy.confirm = [forged_name]
    forged_decision = verb_authority.gate(
        registry,
        forged_policy,
        "evaluate",
        {},
        {},
    )
    _check(
        not forged_decision.allow and forged_name.comparisons == 0,
        "installed gate compared a polymorphic confirmation entry",
    )
    try:
        GuardedToolRunner(registry, forged_policy)
    except TypeError:
        pass
    else:
        raise AssertionError(
            "installed runner accepted a polymorphic confirmation entry"
        )

    events = []
    registry = Registry()
    registry.add(
        Tool(
            "evaluate",
            [],
            fn=lambda: events.append("invoked"),
            risk=Risk.UNKNOWN,
        )
    )
    runner = GuardedToolRunner(registry, build_policy(registry))
    _check(
        not hasattr(runner.policy_set, "__dict__"),
        "installed public frozen policy view exposes a mutable __dict__",
    )
    _check(
        runner.policy_set.risk_inference["evaluate"]
        is not runner._bundle.policy_set.risk_inference["evaluate"],
        "installed public policy view aliases enforced risk evidence",
    )
    object.__setattr__(runner.policy_set, "confirm", ())
    object.__setattr__(
        runner.policy_set.risk_inference["evaluate"],
        "source",
        "forged",
    )
    captured = []
    result = runner.run(
        {"name": "evaluate", "input": {}},
        confirm=lambda request: captured.append(request) or False,
    )
    _check(
        result.decision.allow
        and result.decision.needs_confirm
        and not result.executed
        and not result.invoked
        and not events
        and captured[0].risk_assessment.source == "tool_name",
        "installed public policy view aliases the enforced confirmation state",
    )

    _check(
        type(runner.policy_set.risk["evaluate"]) is str
        and runner.policy_set.risk["evaluate"] == "unknown"
        and type(runner.policy_set.risk_inference["evaluate"].risk) is str
        and runner.policy_set.risk_inference["evaluate"].risk == "unknown"
        and type(runner.policy_set.risk_inference["evaluate"].confidence) is str
        and runner.policy_set.risk_inference["evaluate"].confidence
        == "uncertain"
        and type(captured[0].risk) is str
        and captured[0].risk == "unknown"
        and type(captured[0].risk_assessment.risk) is str
        and captured[0].risk_assessment.risk == "unknown"
        and type(captured[0].risk_assessment.confidence) is str
        and captured[0].risk_assessment.confidence == "uncertain",
        "installed inspection surface retained process-wide Enum leaves",
    )
    for primitive in (
        captured[0].risk,
        captured[0].risk_assessment.risk,
        captured[0].risk_assessment.confidence,
    ):
        try:
            primitive._value_ = "forged"
        except AttributeError:
            pass
        else:
            raise AssertionError(
                "installed confirmation evidence exposes mutable Enum metadata"
            )

    object.__setattr__(captured[0].risk_assessment, "risk", "read_only")
    object.__setattr__(captured[0].risk_assessment, "confidence", "heuristic")
    object.__setattr__(captured[0].risk_assessment, "source", "forged")
    object.__setattr__(
        captured[0].risk_assessment,
        "review_required",
        False,
    )
    later_requests = []
    later = runner.run(
        {"name": "evaluate", "input": {}},
        confirm=lambda request: later_requests.append(request) or False,
    )
    _check(
        not later.executed
        and later_requests[0].risk == "unknown"
        and later_requests[0].risk_assessment.risk == "unknown"
        and later_requests[0].risk_assessment.confidence == "uncertain"
        and later_requests[0].risk_assessment.source == "tool_name"
        and later_requests[0].risk_assessment.review_required is True
        and runner._bundle.policy_set.risk["evaluate"] is Risk.UNKNOWN
        and runner._bundle.policy_set.risk_inference["evaluate"].risk
        is Risk.UNKNOWN
        and runner._bundle.policy_set.risk_inference["evaluate"].confidence
        is verb_authority.RiskConfidence.UNCERTAIN
        and runner._bundle.policy_set.risk_inference["evaluate"].source
        == "tool_name"
        and later_requests[0].action_id == captured[0].action_id,
        "installed confirmation request aliases retained risk evidence",
    )

    inspection_events = []
    inspection_registry = Registry()
    inspection_registry.add(
        Tool(
            "set_destination",
            [Param("destination", sink=True)],
            fn=lambda destination: inspection_events.append(destination),
            risk=Risk.WRITE,
        )
    )
    inspection_runner = GuardedToolRunner(inspection_registry)
    public_outer = next(
        value
        for value in gc.get_referents(inspection_runner.policy_set.policy)
        if type(value) is dict
    )
    enforced_outer = next(
        value
        for value in gc.get_referents(
            inspection_runner._bundle.policy_set.policy
        )
        if type(value) is dict
    )
    public_inner = next(
        value
        for value in gc.get_referents(public_outer["set_destination"])
        if type(value) is dict
    )
    enforced_inner = next(
        value
        for value in gc.get_referents(enforced_outer["set_destination"])
        if type(value) is dict
    )
    inspection_assessment = inspection_runner.policy_set.risk_inference[
        "set_destination"
    ]
    _check(
        type(public_inner["destination"]) is str
        and public_inner["destination"] == "trusted_fixed"
        and type(inspection_runner.policy_set.risk["set_destination"]) is str
        and inspection_runner.policy_set.risk["set_destination"] == "write"
        and type(inspection_assessment.risk) is str
        and inspection_assessment.risk == "write"
        and type(inspection_assessment.confidence) is str
        and inspection_assessment.confidence == "heuristic",
        "installed public inspection view retained process-wide Enum leaves",
    )
    public_inner["destination"] = Policy.TYPED_BOUNDED
    inspection_result = inspection_runner.run(
        {
            "name": "set_destination",
            "input": {"destination": "attacker-authored"},
        }
    )
    _check(
        public_outer is not enforced_outer
        and public_inner is not enforced_inner
        and not inspection_result.decision.allow
        and not inspection_result.executed
        and not inspection_result.invoked
        and not inspection_events,
        "installed public policy mapping aliases enforced policy storage",
    )

    original_limit = verb_authority.MAX_NFKC_OPERATION_CHARS
    original_unicode = verb_authority.unicodedata
    normalization_calls = []

    def counted_normalize(form, value):
        normalization_calls.append(len(value))
        return original_unicode.normalize(form, value)

    try:
        verb_authority.MAX_NFKC_OPERATION_CHARS = 7
        verb_authority.unicodedata = types.SimpleNamespace(
            normalize=counted_normalize,
            name=original_unicode.name,
        )
        tool_name = "é" * 4
        param_name = "ö" * 4
        registry = Registry()
        registry.add(
            Tool(
                tool_name,
                [Param(param_name, "string", max_len=64)],
                risk=Risk.WRITE,
            )
        )
        policy = build_policy(registry)
        _check(
            normalization_calls == [4]
            and policy.policy[tool_name][param_name] is Policy.TRUSTED_FIXED
            and (tool_name, param_name) in policy.review,
            "installed build_policy did not share one Unicode work budget",
        )

        frozen_registry = verb_authority._freeze_registry(
            registry,
            validate_callable=False,
        )
        normalization_calls.clear()
        verb_authority._freeze_policy_set(policy, frozen_registry)
        _check(
            normalization_calls == [4],
            "installed frozen-policy validation reset the tool-name work budget",
        )

        normalization_calls.clear()
        report = scan_documents(
            [
                {
                    "tools": [
                        {
                            "name": tool_name,
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    param_name: {
                                        "type": "string",
                                        "maxLength": 64,
                                    }
                                },
                            },
                        }
                    ]
                }
            ]
        )
        argument = report["tools"][0]["arguments"][0]
        _check(
            normalization_calls == [4]
            and argument["policy"] == Policy.TRUSTED_FIXED.value
            and argument["review_required"] is True,
            "installed scanner did not share the tool/parameter Unicode budget",
        )

        fullwidth_delete = "ｄｅｌｅｔｅ_records"
        risk_registry = Registry()
        risk_events = []
        risk_registry.add(
            Tool(
                fullwidth_delete,
                [],
                fn=lambda: risk_events.append("invoked"),
                risk=Risk.READ_ONLY,
            )
        )
        risk_policy = build_policy(risk_registry)
        risk_runner = GuardedToolRunner(risk_registry, risk_policy)
        risk_result = risk_runner.run(
            {"name": fullwidth_delete, "input": {}}
        )
        _check(
            risk_policy.risk[fullwidth_delete] is Risk.UNKNOWN
            and risk_policy.risk_inference[fullwidth_delete].source
            == "inference_limit"
            and fullwidth_delete in risk_policy.risk_review
            and fullwidth_delete in risk_policy.confirm
            and risk_result.decision.needs_confirm
            and not risk_result.executed
            and not risk_events,
            "installed NFKC exhaustion accepted a lower declared risk tier",
        )

        fullwidth_recipient = "ｒｅｃｉｐｉｅｎｔ"
        sink_registry = Registry()
        sink_events = []
        sink_registry.add(
            Tool(
                "catalog",
                [Param(fullwidth_recipient, "string")],
                fn=lambda **arguments: sink_events.append(arguments),
                risk=Risk.READ_ONLY,
            )
        )
        sink_policy = build_policy(sink_registry)
        sink_runner = GuardedToolRunner(sink_registry, sink_policy)
        sink_result = sink_runner.run(
            {
                "name": "catalog",
                "input": {fullwidth_recipient: "attacker-authored"},
            }
        )
        _check(
            sink_policy.policy["catalog"][fullwidth_recipient]
            is Policy.TRUSTED_FIXED
            and ("catalog", fullwidth_recipient) in sink_policy.review
            and not sink_result.decision.allow
            and not sink_result.executed
            and not sink_events,
            "installed NFKC exhaustion unlocked a read-only authority sink",
        )

        forged_sink_policy = build_policy(sink_registry)
        forged_sink_policy.policy["catalog"][fullwidth_recipient] = (
            Policy.TYPED_BOUNDED
        )
        forged_sink_decision = verb_authority.gate(
            sink_registry,
            forged_sink_policy,
            "catalog",
            {fullwidth_recipient: "attacker-authored"},
            {fullwidth_recipient: "data"},
        )
        _check(
            not forged_sink_decision.allow,
            "installed inference-limit review accepted a policy override",
        )
        try:
            GuardedToolRunner(sink_registry, forged_sink_policy)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "installed runner accepted an inference-limit policy override"
            )

        def reorder_first(registry, target):
            selected = registry.tools.pop(target)
            remaining = list(registry.tools.items())
            registry.tools.clear()
            registry.tools[target] = selected
            registry.tools.update(remaining)

        def replace_derived_state(destination, source):
            for field in (
                "policy",
                "risk",
                "review",
                "confirm",
                "risk_inference",
                "risk_review",
                "risk_conflicts",
            ):
                setattr(destination, field, getattr(source, field))

        reorder_events = []
        reorder_registry = Registry()
        reorder_registry.add(
            Tool("é" * 7, [], fn=lambda: None, risk=Risk.READ_ONLY)
        )
        reorder_param = "ｖａｌｕｅ"
        reorder_registry.add(
            Tool(
                "write_value",
                [Param(reorder_param)],
                fn=lambda **values: reorder_events.append(values),
                risk=Risk.WRITE,
            )
        )
        stale_reorder_policy = build_policy(reorder_registry)
        existing_reorder_runner = GuardedToolRunner(
            reorder_registry,
            stale_reorder_policy,
        )
        _check(
            stale_reorder_policy.policy["write_value"][reorder_param]
            is Policy.TRUSTED_FIXED
            and ("write_value", reorder_param)
            in stale_reorder_policy.review,
            "installed reorder control did not begin resource-limited",
        )
        reorder_first(reorder_registry, "write_value")
        current_reorder_policy = build_policy(reorder_registry)
        _check(
            stale_reorder_policy.registry_version
            == current_reorder_policy.registry_version
            == reorder_registry.version
            and stale_reorder_policy.registry_binding
            != current_reorder_policy.registry_binding,
            "installed registry binding ignored inference iteration order",
        )
        replace_derived_state(stale_reorder_policy, current_reorder_policy)
        stale_reorder_policy.policy["write_value"][reorder_param] = (
            Policy.TYPED_BOUNDED
        )
        reordered_direct = verb_authority.gate(
            reorder_registry,
            stale_reorder_policy,
            "write_value",
            {reorder_param: "attacker-authored"},
            {reorder_param: "data"},
        )
        reordered_dispatch = dispatch(
            reorder_registry,
            stale_reorder_policy,
            {
                "name": "write_value",
                "input": {reorder_param: "attacker-authored"},
            },
        )
        reordered_existing = existing_reorder_runner.run(
            {
                "name": "write_value",
                "input": {reorder_param: "attacker-authored"},
            }
        )
        _check(
            not reordered_direct.allow
            and not reordered_dispatch.allow
            and not reordered_existing.decision.allow
            and not reordered_existing.invoked
            and not reorder_events,
            "installed registry reorder released a resource-limit lock",
        )
        try:
            GuardedToolRunner(reorder_registry, stale_reorder_policy)
        except ValueError:
            pass
        else:
            raise AssertionError(
                "installed runner accepted a policy bound before reordering"
            )

        risk_reorder_events = []
        risk_reorder_registry = Registry()
        risk_reorder_registry.add(
            Tool("ö" * 7, [], fn=lambda: None, risk=Risk.READ_ONLY)
        )
        risk_reorder_target = "ｒｅａｄ"
        risk_reorder_registry.add(
            Tool(
                risk_reorder_target,
                [],
                fn=lambda: risk_reorder_events.append("invoked"),
                risk=Risk.READ_ONLY,
            )
        )
        stale_risk_policy = build_policy(risk_reorder_registry)
        existing_risk_runner = GuardedToolRunner(
            risk_reorder_registry,
            stale_risk_policy,
        )
        _check(
            stale_risk_policy.risk[risk_reorder_target] is Risk.UNKNOWN
            and risk_reorder_target in stale_risk_policy.risk_review
            and risk_reorder_target in stale_risk_policy.confirm,
            "installed risk reorder control did not begin fail-closed",
        )
        reorder_first(risk_reorder_registry, risk_reorder_target)
        current_risk_policy = build_policy(risk_reorder_registry)
        _check(
            current_risk_policy.risk[risk_reorder_target] is Risk.READ_ONLY
            and risk_reorder_target not in current_risk_policy.risk_review
            and risk_reorder_target not in current_risk_policy.confirm
            and stale_risk_policy.registry_binding
            != current_risk_policy.registry_binding,
            "installed risk reorder control did not change inference state",
        )
        replace_derived_state(stale_risk_policy, current_risk_policy)
        risk_reordered_direct = verb_authority.gate(
            risk_reorder_registry,
            stale_risk_policy,
            risk_reorder_target,
            {},
            {},
        )
        risk_reordered_existing = existing_risk_runner.run(
            {"name": risk_reorder_target, "input": {}}
        )
        _check(
            not risk_reordered_direct.allow
            and not risk_reordered_existing.decision.allow
            and not risk_reordered_existing.invoked
            and not risk_reorder_events,
            "installed registry reorder removed required confirmation",
        )
    finally:
        verb_authority.MAX_NFKC_OPERATION_CHARS = original_limit
        verb_authority.unicodedata = original_unicode


def _refresh_tool_review_aggregate(report: dict) -> None:
    for tool in report["tools"]:
        tool["review_sources"] = verb_authority_scan._tool_review_sources(
            arguments=tool["arguments"],
            schema_review_required=tool["schema_review_required"],
            risk_review_required=tool["risk_review_required"],
            risk_conflict=tool["risk_conflict"],
            annotation_assessments=tool["annotation_assessments"],
            branch_risk_review_required=tool[
                "branch_risk_review_required"
            ],
        )
        tool["review_required"] = verb_authority_scan._tool_review_required(
            tool["review_sources"]
        )
    report["summary"]["review_required_tools"] = sum(
        tool["review_required"] is True for tool in report["tools"]
    )


def _schema_review_diff_fail_closed() -> None:
    """Pin report observation, raw-only enforcement, and mandatory fields."""

    document = {
        "tools": [
            {
                "name": "send_message",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "$ref": "#/$defs/missing",
                },
            }
        ]
    }
    before = scan_documents([document])
    explicit_false = copy.deepcopy(before)
    explicit_false["tools"][0]["schema_review_required"] = False
    explicit_false["summary"]["schema_review_required_tools"] = 0
    _refresh_tool_review_aggregate(explicit_false)
    explicit_diff = diff_reports(before, explicit_false)
    explicit_change = next(
        change
        for change in explicit_diff["changes"]
        if change["kind"] == "schema_review_requirement_changed"
    )
    _check(
        explicit_change["classification"] == "review"
        and explicit_diff["summary"]["reviews"] == 1
        and explicit_diff["summary"]["protection_increases"] == 0,
        "installed diff treated cleared schema review as protection",
    )

    omitted = copy.deepcopy(before)
    omitted["tools"][0].pop("schema_review_required")
    omitted["summary"].pop("schema_review_required_tools")

    with TemporaryDirectory(prefix="verb-authority-schema-review-") as directory:
        root = Path(directory)
        before_path = root / "before.json"
        false_path = root / "false.json"
        omitted_path = root / "omitted.json"
        before_path.write_text(json.dumps(before), encoding="utf-8")
        false_path.write_text(json.dumps(explicit_false), encoding="utf-8")
        omitted_path.write_text(json.dumps(omitted), encoding="utf-8")
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.pop("PYTHONHOME", None)

        false_result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "verb_authority",
                "diff",
                str(before_path),
                str(false_path),
            ],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        _check(
            false_result.returncode == 0
            and "[REVIEW]" in false_result.stdout
            and "Traceback" not in false_result.stderr,
            "installed report observation lost cleared schema-review debt",
        )

        threshold_result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "verb_authority",
                "diff",
                str(before_path),
                str(before_path),
                "--fail-on-increase",
                "--fail-on-review",
            ],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        _check(
            threshold_result.returncode == 2
            and "failure thresholds require raw schema inputs"
            in threshold_result.stderr
            and not threshold_result.stdout
            and "Traceback" not in threshold_result.stderr,
            "installed threshold accepted an imported report",
        )

        omitted_result = subprocess.run(
            [
                sys.executable,
                "-I",
                "-m",
                "verb_authority",
                "diff",
                str(before_path),
                str(omitted_path),
            ],
            cwd=root,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )
        _check(
            omitted_result.returncode == 2
            and "schema_review_required" in omitted_result.stderr
            and "rescan" in omitted_result.stderr
            and "Traceback" not in omitted_result.stderr,
            "installed CLI accepted omitted schema-review evidence",
        )


def _daybreak_final_p3_regressions() -> None:
    """Pin the remaining final-audit report and callback boundaries."""

    empty_report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "read_record",
                        "inputSchema": {
                            "type": "object",
                            "properties": {},
                        },
                    }
                ]
            }
        ]
    )
    empty_report["tools"] = []
    empty_report["summary"] = {
        field: 0 for field in empty_report["summary"]
    }
    try:
        diff_reports(empty_report, copy.deepcopy(empty_report))
    except DiffError as exc:
        _check(
            "no tool definitions" in str(exc) and "rescan" in str(exc),
            "installed empty-report rejection omitted rescan guidance",
        )
    else:
        raise AssertionError("installed diff accepted a zero-tool v5 report")

    schema = {
        "tools": [
            {
                "name": "write_record",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "write_record": {
                "risk": {
                    "tier": "write",
                    "evidence": "declared",
                    "effects": ["writes_record"],
                }
            }
        },
    }
    invalid_effect = scan_documents(
        [schema],
        control_declarations=controls,
    )
    invalid_effect["tools"][0]["declared_risk"]["effects"] = [""]
    invalid_effect["declared_controls"]["tools"][0]["risk"]["effects"] = [""]
    invalid_effect["control_declaration_fingerprint_sha256"] = (
        verb_authority_scan._control_declaration_fingerprint(
            invalid_effect["declared_controls"]
        )
    )
    try:
        diff_reports(invalid_effect, copy.deepcopy(invalid_effect))
    except DiffError as exc:
        _check(
            "trimmed, non-empty, unique" in str(exc),
            "installed empty-effect rejection reported the wrong boundary",
        )
    else:
        raise AssertionError("installed diff accepted an empty declared effect")

    parity_schema = {
        "tools": [
            {
                "name": "write_alpha",
                "inputSchema": {
                    "type": "object",
                    "properties": {"target": {"type": "string"}},
                },
            },
            {
                "name": "write_beta",
                "inputSchema": {"type": "object", "properties": {}},
            },
        ]
    }
    parity_controls = {
        "version": 1,
        "tools": {
            "write_alpha": {
                "risk": {
                    "tier": "write",
                    "evidence": "declared",
                    "effects": ["writes_record"],
                    "note": "documented effect",
                },
                "arguments": {
                    "target": {
                        "authority": "constrained",
                        "evidence": "declared",
                        "bounds": [
                            {
                                "source": "allowlist",
                                "bounds_mutability": "trusted_party",
                                "operational_status": "enforced",
                            }
                        ],
                    }
                },
            },
            "write_beta": {},
        },
    }
    parity_report = scan_documents(
        [parity_schema],
        control_declarations=parity_controls,
    )

    padded_note = copy.deepcopy(parity_report)
    padded_note["tools"][0]["declared_risk"]["note"] = " padded "
    padded_note["declared_controls"]["tools"][0]["risk"]["note"] = " padded "
    padded_note["control_declaration_fingerprint_sha256"] = (
        verb_authority_scan._control_declaration_fingerprint(
            padded_note["declared_controls"]
        )
    )
    try:
        diff_reports(padded_note, copy.deepcopy(padded_note))
    except DiffError as exc:
        _check(
            "trimmed, non-empty text" in str(exc),
            "installed diff accepted non-normalized declaration text",
        )
    else:
        raise AssertionError(
            "installed diff accepted non-normalized declaration text"
        )

    reversed_controls = copy.deepcopy(parity_report)
    reversed_controls["declared_controls"]["tools"].reverse()
    reversed_controls["control_declaration_fingerprint_sha256"] = (
        verb_authority_scan._control_declaration_fingerprint(
            reversed_controls["declared_controls"]
        )
    )
    try:
        diff_reports(reversed_controls, copy.deepcopy(reversed_controls))
    except DiffError as exc:
        _check(
            "tool order" in str(exc),
            "installed declaration-order rejection reported the wrong boundary",
        )
    else:
        raise AssertionError("installed diff accepted non-canonical tool order")

    original_tool_limit = verb_authority_diff.MAX_SCAN_TOOL_DEFINITIONS
    verb_authority_diff.MAX_SCAN_TOOL_DEFINITIONS = 1
    try:
        try:
            diff_reports(parity_report, copy.deepcopy(parity_report))
        except DiffError as exc:
            _check(
                "tool-definition limit of 1" in str(exc)
                and "rescan" in str(exc),
                "installed cardinality rejection reported the wrong boundary",
            )
        else:
            raise AssertionError("installed diff ignored scanner cardinality")
    finally:
        verb_authority_diff.MAX_SCAN_TOOL_DEFINITIONS = original_tool_limit

    registry = Registry()
    registry.add(
        Tool(
            "evaluate",
            [],
            fn=lambda: {"ok": True},
            risk=Risk.UNKNOWN,
        )
    )
    runner = GuardedToolRunner(registry)
    captured_decisions = []

    def forge_display_decision_then_deny(request):
        captured_decisions.append(request.decision)
        object.__setattr__(request.decision, "allow", False)
        object.__setattr__(request.decision, "reason", "forged callback reason")
        object.__setattr__(request.decision, "needs_confirm", False)
        object.__setattr__(
            request,
            "decision",
            verb_authority.Decision(False, "forged replacement", False),
        )
        return False

    result = runner.run(
        {"name": "evaluate", "input": {}},
        confirm=forge_display_decision_then_deny,
    )
    _check(
        not result.executed
        and not result.invoked
        and result.decision.allow is True
        and result.decision.needs_confirm is True
        and "risk policy" in result.decision.reason
        and "forged" not in result.decision.reason
        and captured_decisions[0] is not result.decision,
        "installed confirmation display decision aliases returned metadata",
    )


def _nested_argument_schema_review() -> None:
    document = {
        "tools": [{
            "name": "deliver",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "body": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string", "format": "email"},
                            "text": {"type": "string"},
                        },
                        "additionalProperties": False,
                    }
                },
                "additionalProperties": False,
            },
        }]
    }
    controls = {
        "version": 1,
        "tools": {"deliver": {"risk": {
            "tier": "write", "evidence": "declared", "effects": ["send_message"]
        }}},
    }
    report = scan_documents([document], control_declarations=controls)
    tool = report["tools"][0]
    _check(
        tool["schema_review_required"] is True
        and tool["review_required"] is True
        and tool["risk_review_required"] is False
        and tool["arguments"][0]["policy"] == "outbound_payload"
        and tool["arguments"][0]["review_required"] is False,
        "installed scanner lost nested authority review or changed outer policy",
    )
    with TemporaryDirectory(prefix="verb-authority-nested-smoke-") as directory:
        root = Path(directory)
        schema = root / "schema.json"
        sidecar = root / "controls.json"
        schema.write_text(json.dumps(document), encoding="utf-8")
        sidecar.write_text(json.dumps(controls), encoding="utf-8")
        scan_exit = verb_authority_scan.main([
            str(schema), "--controls", str(sidecar), "--fail-on-review",
            "--format", "json", "--output", str(root / "scan.json"),
        ])
        with contextlib.redirect_stdout(io.StringIO()):
            diff_exit = verb_authority_diff.main([
                str(schema), str(schema), "--before-controls", str(sidecar),
                "--after-controls", str(sidecar), "--fail-on-review",
            ])
        _check(scan_exit == 2 and diff_exit == 2,
               "installed scan/diff thresholds ignored unchanged nested review debt")


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
        _exact_selector_branch_boundary,
        _daybreak_post_audit_regressions,
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
        _mcp_annotation_assessment_contract,
        _tool_review_aggregate_contract,
        _remediation_guidance_contract,
        _constraint_diff_and_migration,
        _scanner_resource_boundaries,
        _daybreak_scanner_diff_regressions,
        _daybreak_followup_regressions,
        _daybreak_external_audit_regressions,
        _daybreak_release_candidate_regressions,
        _schema_review_diff_fail_closed,
        _nested_argument_schema_review,
        _daybreak_final_p3_regressions,
    )
    for check in checks:
        check()
    print(
        "installed-wheel smoke: "
        f"{args.expected_version}; all audited blocker families + report v6 "
        "+ v4/v5 compatibility + legacy-v3 rejection + diff thresholds passed"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
