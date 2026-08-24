"""Unit tests for the optional AgentDojo schema exporter."""

import pytest

from benchmarks.export_agentdojo_schemas import _suite_tools


def test_reads_only_names_from_the_public_tools_list(tmp_path):
    task_suite = tmp_path / "task_suite.py"
    task_suite.write_text(
        """
from agentdojo.default_suites.v1.tools.email_client import send_email
from agentdojo.default_suites.v1.tools.web import get_webpage as fetch_page
from unrelated.module import helper

TOOLS = [send_email, fetch_page]
""".strip()
    )

    assert _suite_tools(task_suite) == [
        (
            "send_email",
            "agentdojo.default_suites.v1.tools.email_client",
            "send_email",
        ),
        (
            "fetch_page",
            "agentdojo.default_suites.v1.tools.web",
            "get_webpage",
        ),
    ]


def test_rejects_a_dynamic_tools_list(tmp_path):
    task_suite = tmp_path / "task_suite.py"
    task_suite.write_text("TOOLS = discover_tools()")

    with pytest.raises(ValueError, match="literal list"):
        _suite_tools(task_suite)
