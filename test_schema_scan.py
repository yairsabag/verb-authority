import json
from pathlib import Path

import pytest

import verb_authority
from verb_authority_scan import (
    SchemaError,
    main,
    parse_tool_definitions,
    render_markdown,
    scan_documents,
)


def test_scans_mcp_tools_list_result():
    document = {
        "jsonrpc": "2.0",
        "result": {
            "tools": [
                {
                    "name": "send_email",
                    "description": "A private description that must not be reported",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "to": {"type": "string", "format": "email"},
                            "body": {"type": "string", "maxLength": 1000},
                        },
                        "required": ["to", "body"],
                    },
                }
            ]
        },
    }

    report = scan_documents([document])

    assert report["summary"] == {
        "tools": 1,
        "parameters": 2,
        "protected_parameters": 1,
        "data_fillable_parameters": 1,
        "review_required": 0,
        "confirmation_required_tools": 1,
        "risk_review_required_tools": 1,
        "risk_conflicts": 0,
        "annotation_conflicts": 0,
    }
    assert report["tools"][0]["risk"] == "unknown"
    assert report["tools"][0]["inferred_risk"] == "write"
    assert report["tools"][0]["risk_source"] == "safe_default"
    assert report["tools"][0]["risk_review_required"] is True
    assert report["tools"][0]["arguments"][0]["policy"] == "trusted_fixed"
    assert report["tools"][0]["schema_closes_unknown_arguments"] is False
    assert "private description" not in json.dumps(report).lower()


def test_scans_openai_and_anthropic_exports_together():
    openai = [
        {
            "type": "function",
            "function": {
                "name": "search_web",
                "parameters": {
                    "type": "object",
                    "properties": {"query": {"type": "string"}},
                    "required": ["query"],
                },
            },
        }
    ]
    anthropic = [
        {
            "name": "delete_file",
            "input_schema": {
                "type": "object",
                "properties": {"path": {"type": "string"}},
                "required": ["path"],
            },
        }
    ]

    report = scan_documents([openai, anthropic])

    assert report["summary"]["tools"] == 2
    assert [tool["risk"] for tool in report["tools"]] == [
        "unknown",
        "unknown",
    ]
    assert [tool["inferred_risk"] for tool in report["tools"]] == [
        "read_only",
        "destructive",
    ]


@pytest.mark.parametrize(
    "name",
    ["place_bid", "purchase_bid", "buy_bid", "submit_bid", "transfer_funds", "bid"],
)
def test_avp9_bid_name_mutations_are_only_advisory_until_declared(name):
    report = scan_documents(
        [{"tools": [{"name": name, "inputSchema": {"properties": {}}}]}]
    )
    tool = report["tools"][0]

    assert tool["inferred_risk"] == "financial"
    assert tool["risk_inference"]["source"] == "tool_name"
    assert tool["risk_inference"]["mutability"] == "caller"
    assert tool["risk"] == "unknown"
    assert tool["risk_review_required"] is True
    assert tool["needs_confirmation"] is True


@pytest.mark.parametrize("name", ["evaluate", "eval", "evaluation", "revaluate"])
def test_avp9_evaluation_names_do_not_trigger_code_exec_substrings(name):
    report = scan_documents(
        [{"tools": [{"name": name, "inputSchema": {"properties": {}}}]}]
    )
    tool = report["tools"][0]

    assert tool["inferred_risk"] == "unknown"
    assert tool["risk_inference"]["matched_tokens"] == []
    assert tool["risk"] == "unknown"
    assert tool["needs_confirmation"] is True


def test_descriptions_and_parameter_names_do_not_author_risk():
    document = {
        "tools": [
            {
                "name": "neutral_action",
                "description": (
                    "Transfers funds. Spends money. Payment. Purchase. Buy. "
                    "Sends ETH from the wallet."
                ),
                "inputSchema": {
                    "properties": {
                        "amountWei": {"type": "string"},
                        "payment": {"type": "string"},
                    }
                },
            }
        ]
    }

    tool = scan_documents([document])["tools"][0]

    assert tool["inferred_risk"] == "unknown"
    assert tool["risk"] == "unknown"


def test_declared_effects_resolve_bid_evaluation_and_read_only_scanner():
    document = {
        "tools": [
            {"name": "place_bid", "inputSchema": {"properties": {}}},
            {"name": "evaluate", "inputSchema": {"properties": {}}},
            {"name": "chain_index", "inputSchema": {"properties": {}}},
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "place_bid": {
                "risk": {
                    "tier": "financial",
                    "evidence": "attested",
                    "effects": ["signs_transaction", "commits_funds"],
                }
            },
            "evaluate": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "attested",
                    "effects": ["reads_metadata", "calls_model"],
                }
            },
            "chain_index": {
                "risk": {
                    "tier": "read_only",
                    "evidence": "observed",
                    "effects": ["reads_chain_state"],
                }
            },
        },
    }

    report = scan_documents([document], control_declarations=controls)
    tools = {tool["name"]: tool for tool in report["tools"]}

    assert tools["place_bid"]["risk"] == "financial"
    assert tools["place_bid"]["needs_confirmation"] is True
    assert tools["evaluate"]["risk"] == "read_only"
    assert tools["evaluate"]["needs_confirmation"] is False
    assert tools["chain_index"]["risk"] == "read_only"
    assert tools["chain_index"]["needs_confirmation"] is False
    assert all(not tool["risk_review_required"] for tool in tools.values())
    assert report["summary"]["risk_review_required_tools"] == 0


def test_declared_lower_risk_conflict_keeps_confirmation_fail_safe():
    document = {
        "tools": [
            {"name": "purchase_bid", "inputSchema": {"properties": {}}}
        ]
    }
    controls = {
        "version": 1,
        "tools": {
            "purchase_bid": {
                "risk": {
                    "tier": "write",
                    "evidence": "declared",
                    "effects": ["writes_state"],
                }
            }
        },
    }

    tool = scan_documents([document], control_declarations=controls)["tools"][0]

    assert tool["risk"] == "write"
    assert tool["inferred_risk"] == "financial"
    assert tool["risk_conflict"] is True
    assert tool["risk_review_required"] is True
    assert tool["needs_confirmation"] is True


def test_redacted_report_omits_names_sources_and_name_derived_fingerprint():
    document = {
        "sources": [
            {
                "id": "private-customer-name",
                "url": "https://internal.example/private",
                "tools": [
                    {
                        "name": "send_confidential_invoice",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "customer_secret_account": {"type": "string"}
                            },
                        },
                    }
                ],
            }
        ]
    }

    named = scan_documents([document])
    redacted = scan_documents([document], redact_names=True)
    serialized = json.dumps(redacted)

    assert redacted["tools"][0]["name"] == "tool_001"
    assert redacted["tools"][0]["arguments"][0]["name"] == "param_001"
    assert "private" not in serialized
    assert "confidential" not in serialized
    assert "customer" not in serialized
    assert redacted["schema_fingerprint_sha256"] != named["schema_fingerprint_sha256"]


def test_public_atlas_baseline_is_reproducible():
    atlas_path = Path(__file__).with_name("atlas") / "public_mcp_schemas.json"
    document = json.loads(atlas_path.read_text(encoding="utf-8"))

    report = scan_documents([document])

    assert report["summary"] == {
        "tools": 10,
        "parameters": 14,
        "protected_parameters": 10,
        "data_fillable_parameters": 4,
        "review_required": 6,
        "confirmation_required_tools": 10,
        "risk_review_required_tools": 10,
        "risk_conflicts": 0,
        "annotation_conflicts": 8,
    }
    assert report["schema_fingerprint_sha256"] == (
        "1f0540357dd957e75ccff824560ddf0fb2de0107ee4a4bcff34ebbd1d3d2f3fb"
    )


def test_markdown_states_privacy_and_interpretation_boundary():
    report = scan_documents(
        [{"tools": [{"name": "read_graph", "inputSchema": {"type": "object"}}]}]
    )

    markdown = render_markdown(report)

    assert "no server was executed and no network was used" in markdown
    assert "vulnerability verdict" in markdown


def test_markdown_escapes_schema_controlled_names():
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "read_<script>|tool",
                        "inputSchema": {
                            "properties": {"line\nbreak|arg": {"type": "string"}}
                        },
                    }
                ]
            }
        ]
    )

    markdown = render_markdown(report)

    assert "&lt;script&gt;\\|tool" in markdown
    assert "line break\\|arg" in markdown


def test_reports_declared_controls_without_overriding_inferred_policy():
    document = {
        "tools": [
            {
                "name": "create_export",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "destination_path": {"type": "string"},
                        "format": {"type": "string", "enum": ["csv", "json"]},
                    },
                    "additionalProperties": False,
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "attribution": {"name": "Example reviewer", "source": "implementation review"},
        "tools": {
            "create_export": {
                "arguments": {
                    "destination_path": {
                        "authority": "constrained",
                        "evidence": "attested",
                        "bounds": [
                            {
                                "source": "approved export root",
                                "bounds_mutability": "trusted_party",
                                "enforcement": "runtime path containment",
                            }
                        ],
                    },
                    "format": {"authority": "free", "evidence": "observed"},
                },
                "unexposed_arguments": {
                    "tenant_id": {
                        "exposure": "server_fixed",
                        "enforced_by": "authenticated session",
                        "evidence": "declared",
                    }
                },
            }
        },
    }

    report = scan_documents([document], control_declarations=controls)
    declared = report["declared_controls"]

    assert report["tools"][0]["arguments"][0]["policy"] == "trusted_fixed"
    assert declared["tools"][0]["arguments"][0]["authority"] == "constrained"
    assert declared["tools"][0]["arguments"][0]["bounds"][0][
        "operational_status"
    ] == "not_stated"
    assert declared["tools"][0]["arguments"][0]["inferred_policy"] == (
        "trusted_fixed"
    )
    assert declared["tools"][0]["unexposed_arguments"][0]["exposure"] == (
        "server_fixed"
    )
    assert declared["tools"][0]["schema_closes_unknown_arguments"] is True
    assert "not independently verified" in declared["verification_notice"]
    assert len(report["control_declaration_fingerprint_sha256"]) == 64

    markdown = render_markdown(report)
    assert "Declared controls (author-supplied)" in markdown
    assert "destination_path" in markdown
    assert "runtime path containment" in markdown
    assert "not_stated" in markdown


def test_redacts_declared_control_names_attribution_and_fingerprint_inputs():
    document = {
        "tools": [
            {
                "name": "create_private_export",
                "inputSchema": {
                    "properties": {"secret_destination": {"type": "string"}}
                },
            }
        ]
    }
    controls = {
        "version": 1,
        "attribution": {"name": "Private reviewer"},
        "tools": {
            "create_private_export": {
                "arguments": {
                    "secret_destination": {
                        "authority": "locked",
                        "evidence": "declared",
                    }
                },
                "unexposed_arguments": {
                    "private_tenant": {
                        "exposure": "server_fixed",
                        "enforced_by": "session context",
                        "evidence": "observed",
                    }
                },
            }
        },
    }

    named = scan_documents([document], control_declarations=controls)
    redacted = scan_documents(
        [document], redact_names=True, control_declarations=controls
    )
    serialized = json.dumps(redacted)

    assert "create_private_export" not in serialized
    assert "secret_destination" not in serialized
    assert "private_tenant" not in serialized
    assert "Private reviewer" not in serialized
    assert redacted["declared_controls"]["tools"][0]["name"] == "tool_001"
    assert redacted["declared_controls"]["tools"][0]["arguments"][0]["name"] == (
        "param_001"
    )
    assert redacted["control_declaration_fingerprint_sha256"] != named[
        "control_declaration_fingerprint_sha256"
    ]


def test_avp9_nexus_financial_fixture_regression():
    fixtures = Path(__file__).parent / "fixtures"
    schema = json.loads(
        (fixtures / "avp9_nexus_financial_tool.json").read_text(encoding="utf-8")
    )
    controls = json.loads(
        (fixtures / "avp9_nexus_financial_controls.json").read_text(
            encoding="utf-8"
        )
    )
    expected = json.loads(
        (fixtures / "avp9_nexus_expected.json").read_text(encoding="utf-8")
    )

    report = scan_documents([schema], control_declarations=controls)
    tool = report["tools"][0]
    declared = report["declared_controls"]
    declared_tool = declared["tools"][0]
    arguments = {
        argument["name"]: argument for argument in declared_tool["arguments"]
    }
    unexposed = {
        argument["name"]: argument
        for argument in declared_tool["unexposed_arguments"]
    }

    assert tool["name"] == expected["tool"]
    assert tool["risk"] == expected["risk"]
    assert tool["risk_source"] == expected["risk_source"]
    assert tool["risk_evidence"] == expected["risk_evidence"]
    assert tool["inferred_risk"] == expected["inferred_risk"]
    assert tool["risk_conflict"] is expected["risk_conflict"]
    assert tool["risk_review_required"] is expected["risk_review_required"]
    assert tool["declared_risk"]["effects"] == expected["effects"]
    assert tool["needs_confirmation"] is expected["needs_confirmation"]
    assert (
        declared_tool["schema_closes_unknown_arguments"]
        is expected["schema_closes_unknown_arguments"]
    )
    assert declared["attribution"] == expected["attribution"]
    assert declared_tool["risk"]["tier"] == expected["risk"]
    assert declared_tool["risk"]["effects"] == expected["effects"]

    for name, expected_argument in expected["arguments"].items():
        assert arguments[name]["authority"] == expected_argument["authority"]
        assert arguments[name]["evidence"] == expected_argument["evidence"]
        if "bounds_mutability" in expected_argument:
            assert [
                bound["bounds_mutability"] for bound in arguments[name]["bounds"]
            ] == expected_argument["bounds_mutability"]
        if "operational_status" in expected_argument:
            assert [
                bound["operational_status"] for bound in arguments[name]["bounds"]
            ] == expected_argument["operational_status"]

    # Positive-control guard: do not collapse this deployment into either extreme.
    assert arguments["bidWei"]["authority"] == "constrained"
    assert arguments["bidWei"]["authority"] not in {"locked", "free"}

    for name, expected_argument in expected["unexposed_arguments"].items():
        assert unexposed[name]["exposure"] == expected_argument["exposure"]
        assert unexposed[name]["enforced_by"] == expected_argument["enforced_by"]
        assert unexposed[name]["evidence"] == expected_argument["evidence"]

    redacted = json.dumps(
        scan_documents(
            [schema], redact_names=True, control_declarations=controls
        ),
        sort_keys=True,
    )
    assert "avp9-nexus" not in redacted
    assert expected["attribution"]["source"] not in redacted


def test_control_fingerprint_ignores_json_object_member_order():
    document = {
        "tools": [
            {
                "name": "search_records",
                "inputSchema": {
                    "properties": {
                        "query": {"type": "string"},
                        "limit": {"type": "integer"},
                    }
                },
            }
        ]
    }
    query = {"authority": "free", "evidence": "observed"}
    limit = {"authority": "locked", "evidence": "declared"}
    first = {
        "version": 1,
        "tools": {
            "search_records": {"arguments": {"query": query, "limit": limit}}
        },
    }
    reordered = {
        "tools": {
            "search_records": {"arguments": {"limit": limit, "query": query}}
        },
        "version": 1,
    }

    first_report = scan_documents([document], control_declarations=first)
    reordered_report = scan_documents([document], control_declarations=reordered)

    assert first_report["control_declaration_fingerprint_sha256"] == (
        reordered_report["control_declaration_fingerprint_sha256"]
    )


@pytest.mark.parametrize(
    ("controls", "message"),
    [
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "risk": {
                            "tier": "write",
                            "evidence": "declared",
                            "effects": [],
                        }
                    }
                },
            },
            "non-empty array",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "risk": {
                            "tier": "unknown",
                            "evidence": "declared",
                            "effects": ["writes_state"],
                        }
                    }
                },
            },
            "risk tier",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "arguments": {
                            "opaque": {
                                "authority": "constrained",
                                "evidence": "declared",
                            }
                        }
                    }
                },
            },
            "must declare at least one bound",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "arguments": {
                            "opaque": {
                                "authority": "locked",
                                "evidence": "declared",
                                "typo": True,
                            }
                        }
                    }
                },
            },
            "unknown field",
        ),
        (
            {
                "version": 1,
                "tools": {
                    "create_record": {
                        "arguments": {
                            "opaque": {
                                "authority": "constrained",
                                "evidence": "declared",
                                "bounds": [
                                    {
                                        "source": "future limit",
                                        "bounds_mutability": "trusted_party",
                                        "operational_status": "planned",
                                    }
                                ],
                            }
                        }
                    }
                },
            },
            "operational_status",
        ),
    ],
)
def test_rejects_invalid_control_declarations(controls, message):
    document = {
        "tools": [
            {
                "name": "create_record",
                "inputSchema": {"properties": {"opaque": {"type": "object"}}},
            }
        ]
    }

    with pytest.raises(SchemaError, match=message):
        scan_documents([document], control_declarations=controls)


def test_cli_accepts_a_separate_control_declaration_file(tmp_path):
    schema_path = tmp_path / "tools.json"
    controls_path = tmp_path / "controls.json"
    report_path = tmp_path / "report.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "search_records",
                        "inputSchema": {
                            "properties": {"query": {"type": "string"}}
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    controls_path.write_text(
        json.dumps(
            {
                "version": 1,
                "tools": {
                    "search_records": {
                        "arguments": {
                            "query": {"authority": "free", "evidence": "observed"}
                        }
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                str(schema_path),
                "--controls",
                str(controls_path),
                "--format",
                "json",
                "--output",
                str(report_path),
            ]
        )
        == 0
    )
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["declared_controls"]["tools"][0]["arguments"][0][
        "authority"
    ] == "free"


def test_cli_writes_report_and_can_fail_on_review(tmp_path):
    schema_path = tmp_path / "tools.json"
    report_path = tmp_path / "report.json"
    schema_path.write_text(
        json.dumps(
            {
                "tools": [
                    {
                        "name": "create_record",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"opaque": {"type": "object"}},
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            str(schema_path),
            "--format",
            "json",
            "--output",
            str(report_path),
            "--fail-on-review",
        ]
    )

    assert exit_code == 2
    assert json.loads(report_path.read_text(encoding="utf-8"))["summary"][
        "review_required"
    ] == 1


def test_demo_remains_default_and_unknown_arguments_are_rejected(capsys):
    assert verb_authority.main([]) == 0
    assert "attack send_email" in capsys.readouterr().out

    assert verb_authority.main(["unknown"]) == 2
    assert "usage:" in capsys.readouterr().err


def test_rejects_documents_without_tools():
    with pytest.raises(SchemaError, match="no recognizable"):
        parse_tool_definitions({"not_tools": []})
