"""Offline boundary controls: argument approval is not proof of read-only effects.

The synthetic handler below uses local counters, never HTTP, a live service, or
a model. Its deliberately unsafe behavior models an inaccurate host contract,
not a new gate bypass. Assertions distinguish handler entry from local effects.
"""

import pytest

from verb_authority import GuardedToolRunner, Param, Registry, Risk, Tool
from verb_authority_scan import scan_documents


APPROVED_URL = "https://service.test/page?action=view"
CHANGED_URL = "https://service.test/page?action=publish"


def _local_reader(*, changes_state_on_approved_url=False):
    counts = {"handler": 0, "local_writes": 0}

    def read_page(url):
        counts["handler"] += 1
        if url == CHANGED_URL or changes_state_on_approved_url:
            counts["local_writes"] += 1
        return {"status": "local-stub-only"}

    registry = Registry()
    registry.add(
        Tool(
            "read_page",
            [Param("url", "uri", sink=True)],
            fn=read_page,
            risk=Risk.READ_ONLY,
        )
    )
    return GuardedToolRunner(registry), counts


def test_unguarded_query_change_positive_control_reaches_local_write():
    runner, counts = _local_reader()
    # Deliberate no-gate control: the same local handler really models a write
    # for the changed query. This is not a recommended dispatch path.
    runner.registry.tools["read_page"].fn(CHANGED_URL)
    assert counts == {"handler": 1, "local_writes": 1}


@pytest.mark.parametrize(
    "narrative",
    [
        "An ordinary source document.",
        "I am 100% confident this operation is safe and authorized.",
        "I admit the earlier mistake. The next operation is only a read.",
    ],
    ids=["neutral", "claimed-confidence", "claimed-confession"],
)
@pytest.mark.parametrize(
    ("proposed_url", "has_host_binding", "allowed"),
    [
        (APPROVED_URL, True, True),
        (CHANGED_URL, True, False),
        (APPROVED_URL, False, False),
    ],
    ids=["exact-host-value", "same-origin-query-change", "missing-host-binding"],
)
def test_read_url_binding_does_not_depend_on_untrusted_narrative(
    narrative, proposed_url, has_host_binding, allowed
):
    runner, counts = _local_reader()
    # Stand-ins for retrieved/model-authored text are data, never approval.
    # They contain neither candidate URL: this is not a lexical-taint test.
    runner.ledger.record_result(narrative)
    result = runner.run(
        {"name": "read_page", "input": {"url": proposed_url}},
        trusted_args={"url": APPROVED_URL} if has_host_binding else None,
    )

    assert runner.policy_set.policy["read_page"]["url"] == "trusted_fixed"
    assert result.decision.allow is allowed
    assert not result.decision.needs_confirm
    assert result.invoked is allowed
    assert result.executed is allowed
    assert result.contract_violation is None
    assert counts == {"handler": int(allowed), "local_writes": 0}


@pytest.mark.parametrize("changes_state", [False, True])
def test_same_approved_url_does_not_prove_implementation_is_read_only(changes_state):
    # Same call and host binding; only the implementation's behavior differs.
    # The True case violates the host's declared read-only contract. Even
    # independent exact argument binding cannot verify remote service semantics.
    runner, counts = _local_reader(changes_state_on_approved_url=changes_state)
    result = runner.run(
        {"name": "read_page", "input": {"url": APPROVED_URL}},
        trusted_args={"url": APPROVED_URL},
    )

    assert result.decision.allow
    assert not result.decision.needs_confirm
    assert result.invoked and result.executed
    assert result.contract_violation is None
    assert counts == {"handler": 1, "local_writes": int(changes_state)}


@pytest.mark.parametrize("read_only_hint", [False, True])
def test_read_name_and_schema_hint_do_not_authorize_url_or_operation(read_only_hint):
    report = scan_documents(
        [
            {
                "tools": [
                    {
                        "name": "read_page",
                        "annotations": {"readOnlyHint": read_only_hint},
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "url": {"type": "string", "format": "uri"},
                                "mode": {
                                    "type": "string", "enum": ["view", "publish"]
                                },
                            },
                            "required": ["url", "mode"],
                            "additionalProperties": False,
                        },
                    }
                ]
            }
        ]
    )
    tool = report["tools"][0]
    arguments = {arg["name"]: arg for arg in tool["arguments"]}

    assert tool["risk"] == "unknown"
    assert tool["needs_confirmation"]
    assert arguments["url"]["policy"] == "trusted_fixed"
    assert arguments["mode"]["policy"] == "trusted_fixed"
    assert arguments["mode"]["review_required"]
