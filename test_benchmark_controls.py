from benchmarks.provenance_control import run_experiment


def test_identical_content_authority_control():
    result = run_experiment()

    assert result["tool_calls_identical"] is True
    assert result["without_application_binding"] == {
        "allow": False,
        "invoked": False,
        "local_invocations": 0,
        "reason": "param 'to' is a locked sink; data may not author it",
    }
    assert result["with_application_binding"] == {
        "allow": True,
        "invoked": True,
        "local_invocations": 1,
        "reason": "within authority",
    }
    assert result["network_used"] is False
    assert result["model_used"] is False
    assert result["external_effect_used"] is False
