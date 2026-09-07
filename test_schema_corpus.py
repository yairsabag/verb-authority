from benchmarks.run_schema_corpus import run_corpus


def test_schema_corpus_baseline_is_explicit_and_reproducible():
    result = run_corpus()

    assert result.schemas == 12
    assert result.categories == 10
    assert result.parameters == 34
    assert result.policy_matches == 26
    assert len(result.policy_false_allows) == 0
    assert len(result.policy_false_blocks) == 8
    assert not result.other_policy_mismatches

    assert result.calls == 18
    assert result.call_matches == 12
    assert len(result.call_false_allows) == 0
    assert len(result.call_false_blocks) == 6
    assert not result.other_call_mismatches

    assert {
        (item["case"], item["parameter"])
        for item in result.policy_false_allows
    } == set()
    assert {
        (item["case"], item["parameter"])
        for item in result.policy_false_blocks
    } == {
        ("send_email", "subject"),
        ("delete_file", "recursive"),
        ("http_request", "method"),
        ("http_request", "timeout"),
        ("charge_card", "currency"),
        ("create_calendar_event", "title"),
        ("create_github_issue", "title"),
        ("update_crm_contact", "subscribed"),
    }
    assert {
        (item["case"], item["call"])
        for item in result.call_false_allows
    } == set()
    assert {
        (item["case"], item["call"])
        for item in result.call_false_blocks
    } == {
        ("delete_file", "trusted_delete_requires_confirmation"),
        ("http_request", "trusted_destination_data_body"),
        ("charge_card", "trusted_payment_requires_confirmation"),
        ("create_calendar_event", "data_title_on_trusted_event"),
        ("create_github_issue", "data_title_on_trusted_repo"),
        ("update_crm_contact", "trusted_contact_data_note"),
    }
