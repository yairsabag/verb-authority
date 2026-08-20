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
        "confirmation_required_tools": 0,
        "annotation_conflicts": 0,
    }
    assert report["tools"][0]["arguments"][0]["policy"] == "trusted_fixed"
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
        "read_only",
        "destructive",
    ]


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
        "protected_parameters": 9,
        "data_fillable_parameters": 5,
        "review_required": 5,
        "confirmation_required_tools": 1,
        "annotation_conflicts": 3,
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
