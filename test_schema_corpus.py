from benchmarks.run_schema_corpus import run_corpus


def test_schema_corpus_baseline_is_explicit_and_reproducible():
    result = run_corpus()

    assert result.schemas == 12
    assert result.categories == 10
    assert result.parameters == 34
    assert result.policy_matches == 30
    assert len(result.policy_false_allows) == 2
    assert len(result.policy_false_blocks) == 2
    assert not result.other_policy_mismatches

    assert result.calls == 18
    assert result.call_matches == 15
    assert len(result.call_false_allows) == 2
    assert len(result.call_false_blocks) == 1
    assert not result.other_call_mismatches

    assert {item["case"] for item in result.policy_false_allows} == {
        "charge_card",
        "execute_sql",
    }
    assert {item["call"] for item in result.call_false_allows} == {
        "untrusted_amount",
        "untrusted_query",
    }
