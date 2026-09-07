"""Synthetic, offline controls for the runtime's bounded provenance checks.

The ledger recognizes observed values, not causal origin or arbitrary semantic
rewrites. Deliberately misbound trusted_args and discarded history below model
integrator mistakes outside the trusted-host contract; they are not supported
ways to establish authority. No model, mail service, or network is involved.
"""

import pytest

from verb_authority import GuardedToolRunner, Param, Registry, Risk, Tool


def _local_email_runtime(source_text):
    counts = {"read": 0, "send": 0}
    outbox = []

    def read_document():
        counts["read"] += 1
        return {"content": source_text}

    def send_email(to, body):
        counts["send"] += 1
        outbox.append({"to": to, "body": body})
        return {"status": "recorded-locally"}

    registry = Registry()
    registry.add(
        Tool("read_document", [], fn=read_document, risk=Risk.READ_ONLY)
    )
    registry.add(
        Tool(
            "send_email",
            [
                Param("to", "email", sink=True),
                Param("body", "string", sink=False),
            ],
            fn=send_email,
            risk=Risk.WRITE,
        )
    )
    # Explicit WRITE does not require confirmation by default. These controls
    # exercise argument authority, without an auto-approval callback.
    return GuardedToolRunner(registry), counts, outbox


@pytest.mark.parametrize("record_unrelated_occurrence", [False, True])
def test_independent_trusted_value_can_be_conservatively_blocked_by_equal_history(
    record_unrelated_occurrence,
):
    # Established before reading any document, from independent application state.
    trusted_args = {"to": "archive@corp.test"}
    proposed_call = {
        "name": "send_email",
        "input": {"to": trusted_args["to"], "body": "Quarterly digest"},
    }
    source_text = (
        "An unrelated example mentions archive@corp.test."
        if record_unrelated_occurrence
        else "An unrelated example contains no email address."
    )
    runner, counts, outbox = _local_email_runtime(source_text)

    read = runner.run({"name": "read_document", "input": {}})
    assert read.decision.allow and read.invoked and read.executed
    assert runner.ledger.is_tainted(trusted_args["to"]) is record_unrelated_occurrence

    send = runner.run(proposed_call, trusted_args=trusted_args)

    # Equal bytes are sufficient for the conservative negative check, even
    # though this test knows the host's value was not derived from the document.
    expected_allow = not record_unrelated_occurrence
    assert send.decision.allow is expected_allow
    assert send.invoked is expected_allow
    assert send.executed is expected_allow
    assert not send.decision.needs_confirm
    assert send.contract_violation is None
    assert counts == {"read": 1, "send": int(expected_allow)}
    assert outbox == ([proposed_call["input"]] if expected_allow else [])
    if not expected_allow:
        assert "locked sink" in send.decision.reason


@pytest.mark.parametrize("misbind_trusted_args", [False, True])
def test_spelled_out_destination_still_requires_independent_host_authority(
    misbind_trusted_args,
):
    application_recipient = "archive@corp.test"
    runner, counts, outbox = _local_email_runtime(
        "review at external dot test"
    )
    read = runner.run({"name": "read_document", "input": {}})
    assert read.decision.allow and read.invoked and read.executed

    # A deterministic stand-in for a model rewriting ordinary words, not a
    # live model experiment. The result is a valid address, not a type error.
    reconstructed = (
        read.result["content"].replace(" at ", "@").replace(" dot ", ".")
    )
    assert reconstructed == "review@external.test"
    assert not runner.ledger.is_tainted(reconstructed)
    trusted_args = {
        # The True arm intentionally violates the trusted-host contract.
        "to": reconstructed if misbind_trusted_args else application_recipient
    }
    proposed_call = {
        "name": "send_email",
        "input": {"to": reconstructed, "body": "Quarterly digest"},
    }

    send = runner.run(proposed_call, trusted_args=trusted_args)

    # A lexical miss cannot grant authority when the independent host binding
    # disagrees. Conversely, the gate cannot repair an unrecognized host misbind.
    assert send.decision.allow is misbind_trusted_args
    assert send.invoked is misbind_trusted_args
    assert send.executed is misbind_trusted_args
    assert not send.decision.needs_confirm
    assert send.contract_violation is None
    assert counts == {"read": 1, "send": int(misbind_trusted_args)}
    assert outbox == ([proposed_call["input"]] if misbind_trusted_args else [])
    if not misbind_trusted_args:
        assert "locked sink" in send.decision.reason


@pytest.mark.parametrize("discard_history", [False, True])
@pytest.mark.parametrize("misbind_trusted_args", [False, True])
def test_retained_context_is_not_automatically_carried_into_a_fresh_ledger(
    discard_history, misbind_trusted_args
):
    application_recipient = "archive@corp.test"
    runner, counts, outbox = _local_email_runtime("review@external.test")
    read = runner.run({"name": "read_document", "input": {}})
    assert read.decision.allow and read.invoked and read.executed
    carried_context = read.result
    assert runner.ledger.is_tainted(carried_context["content"])

    if discard_history:
        # Intentionally incorrect session wiring: old context is retained but
        # its ledger is not. This is not a recommended way to clear a denial.
        runner = GuardedToolRunner(runner.registry)
    assert runner.ledger.is_tainted(carried_context["content"]) is (
        not discard_history
    )
    proposed_call = {
        "name": "send_email",
        "input": {"to": carried_context["content"], "body": "Quarterly digest"},
    }
    trusted_args = {
        "to": (
            carried_context["content"]
            if misbind_trusted_args
            else application_recipient
        )
    }

    send = runner.run(proposed_call, trusted_args=trusted_args)

    # Host authority still blocks the call without history. The observed-value
    # backstop catches this exact misbind only while its history is available.
    expected_allow = discard_history and misbind_trusted_args
    assert send.decision.allow is expected_allow
    assert send.invoked is expected_allow
    assert send.executed is expected_allow
    assert not send.decision.needs_confirm
    assert send.contract_violation is None
    assert counts == {"read": 1, "send": int(expected_allow)}
    assert outbox == ([proposed_call["input"]] if expected_allow else [])
    if not expected_allow:
        assert "locked sink" in send.decision.reason
