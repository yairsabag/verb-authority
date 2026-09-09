# Verb Authority schema report

> Local static analysis only: no server was executed and no network was used.
> Descriptions, examples, defaults, and runtime values are not included.
> Enum members are always omitted. Non-redacted reports use stable SHA-256
> fingerprints for comparison; these are guessable for low-entropy values.
> Non-redacted reports also fingerprint full schema validation material,
> excluding annotations; those hashes are correlatable and may be guessable.
> Redacted reports omit exact constraint values and all exact schema hashes.

## Summary

| Measure | Count |
|---|---:|
| Tools | 117 |
| Parameters | 623 |
| Protected (`trusted_fixed`) | 597 |
| Data-fillable | 26 |
| Parameters requiring review | 587 |
| Tools requiring review | 117 |
| Schemas requiring review | 21 |
| Tools requiring confirmation | 117 |
| Tool risks requiring review | 117 |
| Branch risks requiring review | 20 |
| Tool risk conflicts | 0 |
| Annotation conflicts | 0 |

Schema fingerprint: `bee716ad2001250261c759298aff9f3573298d864b03ec5d2f060d8b1190a9cc`
Names redacted: `no`

## Sources

| Source | Pinned URL |
|---|---|
| github-mcp-server-tool-snapshots | https&#58;//github.com/github/github-mcp-server/tree/12d16ed05310876a1e69&#8204;88701b109da63d69dd49/pkg/github/__toolsnaps__ |

## Tool review summary

> Static review debt is separate from runtime confirmation.

| Tool | Review required | Arguments | Schema | Risk | Risk conflict | Annotation conflicts | Branch risk |
|---|---|---|---|---|---|---|---|
| actions_get | yes | method, owner, repo, resource_id | no | yes | no | — | yes |
| actions_list | yes | method, owner, page, per_page, repo, resource_id, workflow_jobs_filter, workflow_runs_filter | no | yes | no | — | yes |
| actions_run_trigger | yes | inputs, method, owner, ref, repo, run_id, workflow_id | no | yes | no | — | yes |
| add_comment_to_pending_review | yes | line, owner, pullNumber, repo, side, startLine, startSide, subjectType | no | yes | no | — | no |
| add_issue_comment | yes | comment_id, issue_number, owner, reaction, repo | no | yes | no | — | yes |
| add_issue_comment_reaction | yes | comment_id, content, owner, repo | no | yes | no | — | no |
| add_issue_reaction | yes | content, issue_number, owner, repo | no | yes | no | — | no |
| add_pull_request_review_comment | yes | line, owner, pullNumber, repo, side, startLine, startSide, subjectType | no | yes | no | — | no |
| add_pull_request_review_comment_reaction | yes | comment_id, content, owner, repo | no | yes | no | — | no |
| add_reply_to_pull_request_comment | yes | commentId, owner, pullNumber, reaction, repo | no | yes | no | — | yes |
| add_sub_issue | yes | issue_number, owner, replace_parent, repo, sub_issue_id | no | yes | no | — | no |
| assign_copilot_to_issue | yes | base_ref, custom_instructions, issue_number, owner, repo | no | yes | no | — | no |
| assign_copilot_to_issue_with_intent | yes | base_ref, confidence, custom_instructions, is_suggestion, issue_number, owner, rationale, repo | no | yes | no | — | no |
| create_branch | yes | branch, from_branch, owner, repo | no | yes | no | — | no |
| create_gist | yes | filename, public | no | yes | no | — | no |
| create_issue | yes | owner, parent_issue_number, parent_owner, parent_repo, repo, title | no | yes | no | — | no |
| create_or_update_file | yes | allow_symlink_write, branch, owner, repo, sha | no | yes | no | — | no |
| create_pull_request | yes | base, draft, head, maintainer_can_modify, owner, repo, reviewers, title | yes | yes | no | — | no |
| create_pull_request_review | yes | commitID, event, owner, pullNumber, repo | no | yes | no | — | no |
| create_repository | yes | autoInit, name, organization, private | no | yes | no | — | no |
| delete_file | yes | branch, owner, repo | no | yes | no | — | no |
| delete_pending_pull_request_review | yes | owner, pullNumber, repo | no | yes | no | — | no |
| delete_repository | yes | owner, repo | no | yes | no | — | no |
| discussion_comment_write | yes | commentNodeID, discussionNumber, method, owner, repo | no | yes | no | — | yes |
| dismiss_notification | yes | state, threadID | no | yes | no | — | no |
| find_duplicate | yes | confidence_threshold, issue_number, owner, page, perPage, repo | no | yes | no | — | no |
| fork_repository | yes | organization, owner, repo | no | yes | no | — | no |
| get_code_quality_finding | yes | findingNumber, owner, repo | no | yes | no | — | no |
| get_code_scanning_alert | yes | alertNumber, owner, repo | no | yes | no | — | no |
| get_commit | yes | detail, owner, page, perPage, repo, sha | no | yes | no | — | no |
| get_dependabot_alert | yes | alertNumber, owner, repo | no | yes | no | — | no |
| get_discussion | yes | discussionNumber, owner, repo | no | yes | no | — | no |
| get_discussion_comments | yes | after, discussionNumber, includeReplies, owner, perPage, repo | no | yes | no | — | no |
| get_file_blame | yes | after, end_line, owner, perPage, ref, repo, start_line | no | yes | no | — | no |
| get_file_contents | yes | fields, owner, ref, repo, sha | yes | yes | no | — | no |
| get_gist | yes | gist_id | no | yes | no | — | no |
| get_global_security_advisory | yes | ghsaId | no | yes | no | — | no |
| get_job_logs | yes | failed_only, job_id, owner, repo, return_content, run_id, tail_lines | no | yes | no | — | no |
| get_label | yes | name, owner, repo | no | yes | no | — | no |
| get_latest_release | yes | owner, repo | no | yes | no | — | no |
| get_me | yes | — | no | yes | no | — | no |
| get_notification_details | yes | notificationID | no | yes | no | — | no |
| get_release_by_tag | yes | owner, repo, tag | no | yes | no | — | no |
| get_repository_tree | yes | owner, recursive, repo, tree_sha | no | yes | no | — | no |
| get_secret_scanning_alert | yes | alertNumber, owner, repo | no | yes | no | — | no |
| get_tag | yes | owner, repo, tag | no | yes | no | — | no |
| get_team_members | yes | org, team_slug | no | yes | no | — | no |
| get_teams | yes | user | no | yes | no | — | no |
| issue_dependency_read | yes | issue_number, method, owner, page, perPage, repo | no | yes | no | — | yes |
| issue_dependency_write | yes | issue_number, method, owner, related_issue_number, related_owner, related_repo, repo, type | no | yes | no | — | yes |
| issue_read | yes | issue_number, method, owner, page, perPage, repo | no | yes | no | — | yes |
| issue_write | yes | assignees, duplicate_of, issue_fields, issue_number, labels, method, milestone, owner, parent_issue_number, parent_owner, parent_repo, repo, state, state_reason, title, type | yes | yes | no | — | yes |
| label_write | yes | color, method, name, new_name, owner, repo | no | yes | no | — | yes |
| list_branches | yes | owner, page, perPage, repo | no | yes | no | — | no |
| list_code_scanning_alerts | yes | owner, page, perPage, ref, repo, severity, state, tool_name | no | yes | no | — | no |
| list_commits | yes | author, fields, owner, page, perPage, repo, sha, since, until | yes | yes | no | — | no |
| list_dependabot_alerts | yes | after, owner, perPage, repo, severity, state | no | yes | no | — | no |
| list_discussion_categories | yes | owner, repo | no | yes | no | — | no |
| list_discussions | yes | after, category, direction, orderBy, owner, perPage, repo | no | yes | no | — | no |
| list_gists | yes | page, perPage, since, username | no | yes | no | — | no |
| list_global_security_advisories | yes | affects, cveId, cwes, ecosystem, ghsaId, isWithdrawn, modified, published, severity, type, updated | yes | yes | no | — | no |
| list_issue_fields | yes | owner, repo | no | yes | no | — | no |
| list_issue_types | yes | owner, repo | no | yes | no | — | no |
| list_issues | yes | after, direction, field_filters, fields, labels, orderBy, owner, perPage, repo, since, state | yes | yes | no | — | no |
| list_label | yes | owner, repo | no | yes | no | — | no |
| list_notifications | yes | before, filter, owner, page, perPage, repo, since | no | yes | no | — | no |
| list_org_repository_security_advisories | yes | direction, org, sort, state | no | yes | no | — | no |
| list_pull_requests | yes | base, direction, fields, head, owner, page, perPage, repo, sort, state | yes | yes | no | — | no |
| list_releases | yes | fields, owner, page, perPage, repo | yes | yes | no | — | no |
| list_repository_collaborators | yes | affiliation, owner, page, perPage, repo | no | yes | no | — | no |
| list_repository_security_advisories | yes | direction, owner, repo, sort, state | no | yes | no | — | no |
| list_secret_scanning_alerts | yes | owner, page, perPage, repo, resolution, state | no | yes | no | — | no |
| list_starred_repositories | yes | direction, page, perPage, sort, username | no | yes | no | — | no |
| list_tags | yes | owner, page, perPage, repo | no | yes | no | — | no |
| manage_notification_subscription | yes | action, notificationID | no | yes | no | — | yes |
| manage_repository_notification_subscription | yes | action, owner, repo | no | yes | no | — | yes |
| mark_all_notifications_read | yes | lastReadAt, owner, repo | no | yes | no | — | no |
| merge_pull_request | yes | commit_title, expectedHeadSha, merge_method, owner, pullNumber, repo | no | yes | no | — | yes |
| projects_get | yes | field_id, field_names, fields, item_id, method, owner, owner_type, project_number, status_update_id, view_id | yes | yes | no | — | yes |
| projects_list | yes | after, before, field_names, fields, method, owner, owner_type, per_page, project_number, query | yes | yes | no | — | yes |
| projects_write | yes | field_name, filter, issue_number, item_id, item_owner, item_repo, item_type, items, iteration_duration, iterations, layout, method, name, owner, owner_type, project_number, pull_request_number, start_date, status, target_date, title, updated_field, view_id, visible_field_names, visible_fields | yes | yes | no | — | yes |
| pull_request_read | yes | after, method, owner, page, perPage, pullNumber, repo | no | yes | no | — | yes |
| pull_request_review_write | yes | commitID, event, method, owner, pullNumber, repo, threadId | no | yes | no | — | yes |
| push_files | yes | branch, owner, repo | yes | yes | no | — | no |
| remove_sub_issue | yes | issue_number, owner, repo, sub_issue_id | no | yes | no | — | no |
| reprioritize_sub_issue | yes | after_id, before_id, issue_number, owner, repo, sub_issue_id | no | yes | no | — | no |
| request_copilot_review | yes | owner, pullNumber, repo | no | yes | no | — | no |
| request_pull_request_reviewers | yes | owner, pullNumber, repo, reviewers | yes | yes | no | — | no |
| resolve_review_thread | yes | threadID | no | yes | no | — | no |
| search_code | yes | fields, order, page, perPage, query, sort | yes | yes | no | — | no |
| search_commits | yes | order, page, perPage, query, sort | no | yes | no | — | no |
| search_issues | yes | fields, order, owner, page, perPage, query, repo, sort | yes | yes | no | — | no |
| search_orgs | yes | order, page, perPage, query, sort | no | yes | no | — | no |
| search_pull_requests | yes | fields, order, owner, page, perPage, query, repo, sort | yes | yes | no | — | no |
| search_repositories | yes | minimal_output, order, page, perPage, query, sort | no | yes | no | — | no |
| search_users | yes | order, page, perPage, query, sort | no | yes | no | — | no |
| set_issue_fields | yes | fields, issue_number, owner, repo | yes | yes | no | — | no |
| star_repository | yes | owner, repo | no | yes | no | — | no |
| sub_issue_write | yes | after_id, before_id, issue_number, method, owner, replace_parent, repo, sub_issue_id | no | yes | no | — | no |
| submit_pending_pull_request_review | yes | event, owner, pullNumber, repo | no | yes | no | — | no |
| ui_get | yes | method, owner, repo | no | yes | no | — | yes |
| unresolve_review_thread | yes | threadID | no | yes | no | — | no |
| unstar_repository | yes | owner, repo | no | yes | no | — | no |
| update_gist | yes | filename, gist_id | no | yes | no | — | no |
| update_issue_assignees | yes | assignees, issue_number, owner, repo | yes | yes | no | — | no |
| update_issue_body | yes | issue_number, owner, repo | no | yes | no | — | no |
| update_issue_labels | yes | issue_number, labels, owner, repo | yes | yes | no | — | no |
| update_issue_milestone | yes | issue_number, milestone, owner, repo | no | yes | no | — | no |
| update_issue_state | yes | confidence, duplicate_of, is_suggestion, issue_number, owner, rationale, repo, state, state_reason | no | yes | no | — | no |
| update_issue_title | yes | issue_number, owner, repo, title | no | yes | no | — | no |
| update_issue_type | yes | confidence, is_suggestion, issue_number, issue_type, owner, rationale, repo | yes | yes | no | — | no |
| update_pull_request | yes | base, draft, maintainer_can_modify, owner, pullNumber, repo, reviewers, state, title | yes | yes | no | — | no |
| update_pull_request_body | yes | owner, pullNumber, repo | no | yes | no | — | no |
| update_pull_request_branch | yes | expectedHeadSha, owner, pullNumber, repo | no | yes | no | — | no |
| update_pull_request_draft_state | yes | draft, owner, pullNumber, repo | no | yes | no | — | no |
| update_pull_request_state | yes | owner, pullNumber, repo, state | no | yes | no | — | no |
| update_pull_request_title | yes | owner, pullNumber, repo, title | no | yes | no | — | no |

## Tool risk evidence

| Tool | Effective risk | Source | Name heuristic | Mutability | Declared effects | Conflict | Risk review | Schema review | Confirmation |
|---|---|---|---|---|---|---|---|---|---|
| actions_get | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| actions_list | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| actions_run_trigger | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| add_comment_to_pending_review | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| add_issue_comment | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| add_issue_comment_reaction | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| add_issue_reaction | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| add_pull_request_review_comment | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| add_pull_request_review_comment_reaction | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| add_reply_to_pull_request_comment | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| add_sub_issue | unknown | safe_default | write via add (heuristic) | caller | — | no | yes | no | yes |
| assign_copilot_to_issue | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| assign_copilot_to_issue_with_intent | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| create_branch | unknown | safe_default | write via create (heuristic) | caller | — | no | yes | no | yes |
| create_gist | unknown | safe_default | write via create (heuristic) | caller | — | no | yes | no | yes |
| create_issue | unknown | safe_default | write via create (heuristic) | caller | — | no | yes | no | yes |
| create_or_update_file | unknown | safe_default | write via create, update (heuristic) | caller | — | no | yes | no | yes |
| create_pull_request | unknown | safe_default | write via create (heuristic) | caller | — | no | yes | yes | yes |
| create_pull_request_review | unknown | safe_default | write via create (heuristic) | caller | — | no | yes | no | yes |
| create_repository | unknown | safe_default | write via create (heuristic) | caller | — | no | yes | no | yes |
| delete_file | unknown | safe_default | destructive via delete (heuristic) | caller | — | no | yes | no | yes |
| delete_pending_pull_request_review | unknown | safe_default | destructive via delete (heuristic) | caller | — | no | yes | no | yes |
| delete_repository | unknown | safe_default | destructive via delete (heuristic) | caller | — | no | yes | no | yes |
| discussion_comment_write | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | no | yes |
| dismiss_notification | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| find_duplicate | unknown | safe_default | read_only via find (heuristic) | caller | — | no | yes | no | yes |
| fork_repository | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| get_code_quality_finding | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_code_scanning_alert | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_commit | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_dependabot_alert | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_discussion | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_discussion_comments | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_file_blame | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_file_contents | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | yes | yes |
| get_gist | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_global_security_advisory | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_job_logs | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_label | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_latest_release | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_me | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_notification_details | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_release_by_tag | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_repository_tree | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_secret_scanning_alert | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_tag | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_team_members | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| get_teams | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| issue_dependency_read | unknown | safe_default | read_only via read (heuristic) | caller | — | no | yes | no | yes |
| issue_dependency_write | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | no | yes |
| issue_read | unknown | safe_default | read_only via read (heuristic) | caller | — | no | yes | no | yes |
| issue_write | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | yes | yes |
| label_write | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | no | yes |
| list_branches | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_code_scanning_alerts | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_commits | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | yes | yes |
| list_dependabot_alerts | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_discussion_categories | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_discussions | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_gists | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_global_security_advisories | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | yes | yes |
| list_issue_fields | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_issue_types | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_issues | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | yes | yes |
| list_label | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_notifications | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_org_repository_security_advisories | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_pull_requests | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | yes | yes |
| list_releases | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | yes | yes |
| list_repository_collaborators | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_repository_security_advisories | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_secret_scanning_alerts | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_starred_repositories | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| list_tags | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | no | yes |
| manage_notification_subscription | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| manage_repository_notification_subscription | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| mark_all_notifications_read | unknown | safe_default | read_only via read (heuristic) | caller | — | no | yes | no | yes |
| merge_pull_request | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| projects_get | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | yes | yes |
| projects_list | unknown | safe_default | read_only via list (heuristic) | caller | — | no | yes | yes | yes |
| projects_write | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | yes | yes |
| pull_request_read | unknown | safe_default | read_only via read (heuristic) | caller | — | no | yes | no | yes |
| pull_request_review_write | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | no | yes |
| push_files | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | yes | yes |
| remove_sub_issue | unknown | safe_default | destructive via remove (heuristic) | caller | — | no | yes | no | yes |
| reprioritize_sub_issue | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| request_copilot_review | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| request_pull_request_reviewers | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | yes | yes |
| resolve_review_thread | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| search_code | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | yes | yes |
| search_commits | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | no | yes |
| search_issues | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | yes | yes |
| search_orgs | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | no | yes |
| search_pull_requests | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | yes | yes |
| search_repositories | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | no | yes |
| search_users | unknown | safe_default | read_only via search (heuristic) | caller | — | no | yes | no | yes |
| set_issue_fields | unknown | safe_default | write via set (heuristic) | caller | — | no | yes | yes | yes |
| star_repository | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| sub_issue_write | unknown | safe_default | write via write (heuristic) | caller | — | no | yes | no | yes |
| submit_pending_pull_request_review | unknown | safe_default | write via submit (heuristic) | caller | — | no | yes | no | yes |
| ui_get | unknown | safe_default | read_only via get (heuristic) | caller | — | no | yes | no | yes |
| unresolve_review_thread | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| unstar_repository | unknown | safe_default | unknown (no complete-token match) (uncertain) | caller | — | no | yes | no | yes |
| update_gist | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_issue_assignees | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | yes | yes |
| update_issue_body | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_issue_labels | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | yes | yes |
| update_issue_milestone | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_issue_state | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_issue_title | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_issue_type | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | yes | yes |
| update_pull_request | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | yes | yes |
| update_pull_request_body | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_pull_request_branch | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_pull_request_draft_state | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_pull_request_state | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |
| update_pull_request_title | unknown | safe_default | write via update (heuristic) | caller | — | no | yes | no | yes |

## MCP annotation evidence

> Tool annotations are unverified server hints, not enforcement evidence.

| Tool | Annotation | Value | State | Comparison source | Comparison value |
|---|---|---|---|---|---|
| actions_get | readOnlyHint | true | unresolved | effective_risk | unknown |
| actions_get | idempotentHint | false | inapplicable | readOnlyHint | true |
| actions_list | readOnlyHint | true | unresolved | effective_risk | unknown |
| actions_list | idempotentHint | false | inapplicable | readOnlyHint | true |
| actions_run_trigger | readOnlyHint | false | unresolved | effective_risk | unknown |
| actions_run_trigger | destructiveHint | true | unresolved | effective_risk | unknown |
| actions_run_trigger | idempotentHint | false | unresolved | none | — |
| add_comment_to_pending_review | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_comment_to_pending_review | idempotentHint | false | unresolved | none | — |
| add_issue_comment | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_issue_comment | idempotentHint | false | unresolved | none | — |
| add_issue_comment_reaction | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_issue_comment_reaction | destructiveHint | false | unresolved | effective_risk | unknown |
| add_issue_comment_reaction | idempotentHint | false | unresolved | none | — |
| add_issue_comment_reaction | openWorldHint | true | unresolved | none | — |
| add_issue_reaction | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_issue_reaction | destructiveHint | false | unresolved | effective_risk | unknown |
| add_issue_reaction | idempotentHint | false | unresolved | none | — |
| add_issue_reaction | openWorldHint | true | unresolved | none | — |
| add_pull_request_review_comment | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_pull_request_review_comment | destructiveHint | false | unresolved | effective_risk | unknown |
| add_pull_request_review_comment | idempotentHint | false | unresolved | none | — |
| add_pull_request_review_comment | openWorldHint | true | unresolved | none | — |
| add_pull_request_review_comment_reaction | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_pull_request_review_comment_reaction | destructiveHint | false | unresolved | effective_risk | unknown |
| add_pull_request_review_comment_reaction | idempotentHint | false | unresolved | none | — |
| add_pull_request_review_comment_reaction | openWorldHint | true | unresolved | none | — |
| add_reply_to_pull_request_comment | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_reply_to_pull_request_comment | idempotentHint | false | unresolved | none | — |
| add_sub_issue | readOnlyHint | false | unresolved | effective_risk | unknown |
| add_sub_issue | destructiveHint | false | unresolved | effective_risk | unknown |
| add_sub_issue | idempotentHint | false | unresolved | none | — |
| add_sub_issue | openWorldHint | true | unresolved | none | — |
| assign_copilot_to_issue | readOnlyHint | false | unresolved | effective_risk | unknown |
| assign_copilot_to_issue | idempotentHint | true | unresolved | none | — |
| assign_copilot_to_issue_with_intent | readOnlyHint | false | unresolved | effective_risk | unknown |
| assign_copilot_to_issue_with_intent | idempotentHint | true | unresolved | none | — |
| create_branch | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_branch | idempotentHint | false | unresolved | none | — |
| create_gist | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_gist | idempotentHint | false | unresolved | none | — |
| create_issue | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_issue | destructiveHint | false | unresolved | effective_risk | unknown |
| create_issue | idempotentHint | false | unresolved | none | — |
| create_issue | openWorldHint | true | unresolved | none | — |
| create_or_update_file | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_or_update_file | idempotentHint | false | unresolved | none | — |
| create_pull_request | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_pull_request | idempotentHint | false | unresolved | none | — |
| create_pull_request_review | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_pull_request_review | destructiveHint | false | unresolved | effective_risk | unknown |
| create_pull_request_review | idempotentHint | false | unresolved | none | — |
| create_pull_request_review | openWorldHint | true | unresolved | none | — |
| create_repository | readOnlyHint | false | unresolved | effective_risk | unknown |
| create_repository | idempotentHint | false | unresolved | none | — |
| delete_file | readOnlyHint | false | unresolved | effective_risk | unknown |
| delete_file | destructiveHint | true | unresolved | effective_risk | unknown |
| delete_file | idempotentHint | false | unresolved | none | — |
| delete_pending_pull_request_review | readOnlyHint | false | unresolved | effective_risk | unknown |
| delete_pending_pull_request_review | destructiveHint | true | unresolved | effective_risk | unknown |
| delete_pending_pull_request_review | idempotentHint | false | unresolved | none | — |
| delete_pending_pull_request_review | openWorldHint | true | unresolved | none | — |
| delete_repository | readOnlyHint | false | unresolved | effective_risk | unknown |
| delete_repository | destructiveHint | true | unresolved | effective_risk | unknown |
| delete_repository | idempotentHint | false | unresolved | none | — |
| discussion_comment_write | readOnlyHint | false | unresolved | effective_risk | unknown |
| discussion_comment_write | destructiveHint | true | unresolved | effective_risk | unknown |
| discussion_comment_write | idempotentHint | false | unresolved | none | — |
| dismiss_notification | readOnlyHint | false | unresolved | effective_risk | unknown |
| dismiss_notification | idempotentHint | false | unresolved | none | — |
| find_duplicate | readOnlyHint | true | unresolved | effective_risk | unknown |
| find_duplicate | idempotentHint | false | inapplicable | readOnlyHint | true |
| fork_repository | readOnlyHint | false | unresolved | effective_risk | unknown |
| fork_repository | idempotentHint | false | unresolved | none | — |
| get_code_quality_finding | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_code_quality_finding | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_code_scanning_alert | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_code_scanning_alert | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_commit | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_commit | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_dependabot_alert | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_dependabot_alert | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_discussion | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_discussion | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_discussion_comments | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_discussion_comments | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_file_blame | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_file_blame | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_file_contents | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_file_contents | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_gist | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_gist | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_global_security_advisory | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_global_security_advisory | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_job_logs | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_label | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_label | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_latest_release | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_latest_release | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_me | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_me | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_notification_details | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_notification_details | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_release_by_tag | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_release_by_tag | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_repository_tree | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_repository_tree | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_secret_scanning_alert | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_secret_scanning_alert | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_tag | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_tag | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_team_members | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_team_members | idempotentHint | false | inapplicable | readOnlyHint | true |
| get_teams | readOnlyHint | true | unresolved | effective_risk | unknown |
| get_teams | idempotentHint | false | inapplicable | readOnlyHint | true |
| issue_dependency_read | readOnlyHint | true | unresolved | effective_risk | unknown |
| issue_dependency_read | idempotentHint | false | inapplicable | readOnlyHint | true |
| issue_dependency_write | readOnlyHint | false | unresolved | effective_risk | unknown |
| issue_dependency_write | idempotentHint | false | unresolved | none | — |
| issue_read | readOnlyHint | true | unresolved | effective_risk | unknown |
| issue_read | idempotentHint | false | inapplicable | readOnlyHint | true |
| issue_write | readOnlyHint | false | unresolved | effective_risk | unknown |
| issue_write | idempotentHint | false | unresolved | none | — |
| label_write | readOnlyHint | false | unresolved | effective_risk | unknown |
| label_write | destructiveHint | true | unresolved | effective_risk | unknown |
| label_write | idempotentHint | false | unresolved | none | — |
| list_branches | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_branches | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_code_scanning_alerts | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_code_scanning_alerts | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_commits | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_commits | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_dependabot_alerts | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_dependabot_alerts | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_discussion_categories | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_discussion_categories | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_discussions | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_discussions | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_gists | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_gists | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_global_security_advisories | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_global_security_advisories | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_issue_fields | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_issue_fields | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_issue_types | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_issue_types | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_issues | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_issues | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_label | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_label | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_notifications | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_notifications | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_org_repository_security_advisories | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_org_repository_security_advisories | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_pull_requests | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_pull_requests | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_releases | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_releases | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_repository_collaborators | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_repository_collaborators | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_repository_security_advisories | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_repository_security_advisories | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_secret_scanning_alerts | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_secret_scanning_alerts | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_starred_repositories | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_starred_repositories | idempotentHint | false | inapplicable | readOnlyHint | true |
| list_tags | readOnlyHint | true | unresolved | effective_risk | unknown |
| list_tags | idempotentHint | false | inapplicable | readOnlyHint | true |
| manage_notification_subscription | readOnlyHint | false | unresolved | effective_risk | unknown |
| manage_notification_subscription | destructiveHint | true | unresolved | effective_risk | unknown |
| manage_notification_subscription | idempotentHint | false | unresolved | none | — |
| manage_repository_notification_subscription | readOnlyHint | false | unresolved | effective_risk | unknown |
| manage_repository_notification_subscription | destructiveHint | true | unresolved | effective_risk | unknown |
| manage_repository_notification_subscription | idempotentHint | false | unresolved | none | — |
| mark_all_notifications_read | readOnlyHint | false | unresolved | effective_risk | unknown |
| mark_all_notifications_read | idempotentHint | false | unresolved | none | — |
| merge_pull_request | readOnlyHint | false | unresolved | effective_risk | unknown |
| merge_pull_request | idempotentHint | false | unresolved | none | — |
| projects_get | readOnlyHint | true | unresolved | effective_risk | unknown |
| projects_get | idempotentHint | false | inapplicable | readOnlyHint | true |
| projects_list | readOnlyHint | true | unresolved | effective_risk | unknown |
| projects_list | idempotentHint | false | inapplicable | readOnlyHint | true |
| projects_write | readOnlyHint | false | unresolved | effective_risk | unknown |
| projects_write | destructiveHint | true | unresolved | effective_risk | unknown |
| projects_write | idempotentHint | false | unresolved | none | — |
| pull_request_read | readOnlyHint | true | unresolved | effective_risk | unknown |
| pull_request_read | idempotentHint | false | inapplicable | readOnlyHint | true |
| pull_request_review_write | readOnlyHint | false | unresolved | effective_risk | unknown |
| pull_request_review_write | idempotentHint | false | unresolved | none | — |
| push_files | readOnlyHint | false | unresolved | effective_risk | unknown |
| push_files | idempotentHint | false | unresolved | none | — |
| remove_sub_issue | readOnlyHint | false | unresolved | effective_risk | unknown |
| remove_sub_issue | destructiveHint | true | unresolved | effective_risk | unknown |
| remove_sub_issue | idempotentHint | false | unresolved | none | — |
| remove_sub_issue | openWorldHint | true | unresolved | none | — |
| reprioritize_sub_issue | readOnlyHint | false | unresolved | effective_risk | unknown |
| reprioritize_sub_issue | destructiveHint | false | unresolved | effective_risk | unknown |
| reprioritize_sub_issue | idempotentHint | false | unresolved | none | — |
| reprioritize_sub_issue | openWorldHint | true | unresolved | none | — |
| request_copilot_review | readOnlyHint | false | unresolved | effective_risk | unknown |
| request_copilot_review | idempotentHint | false | unresolved | none | — |
| request_pull_request_reviewers | readOnlyHint | false | unresolved | effective_risk | unknown |
| request_pull_request_reviewers | destructiveHint | false | unresolved | effective_risk | unknown |
| request_pull_request_reviewers | idempotentHint | false | unresolved | none | — |
| request_pull_request_reviewers | openWorldHint | true | unresolved | none | — |
| resolve_review_thread | readOnlyHint | false | unresolved | effective_risk | unknown |
| resolve_review_thread | destructiveHint | false | unresolved | effective_risk | unknown |
| resolve_review_thread | idempotentHint | false | unresolved | none | — |
| resolve_review_thread | openWorldHint | true | unresolved | none | — |
| search_code | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_code | idempotentHint | false | inapplicable | readOnlyHint | true |
| search_commits | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_commits | idempotentHint | false | inapplicable | readOnlyHint | true |
| search_issues | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_issues | idempotentHint | false | inapplicable | readOnlyHint | true |
| search_orgs | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_orgs | idempotentHint | false | inapplicable | readOnlyHint | true |
| search_pull_requests | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_pull_requests | idempotentHint | false | inapplicable | readOnlyHint | true |
| search_repositories | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_repositories | idempotentHint | false | inapplicable | readOnlyHint | true |
| search_users | readOnlyHint | true | unresolved | effective_risk | unknown |
| search_users | idempotentHint | false | inapplicable | readOnlyHint | true |
| set_issue_fields | readOnlyHint | false | unresolved | effective_risk | unknown |
| set_issue_fields | destructiveHint | false | unresolved | effective_risk | unknown |
| set_issue_fields | idempotentHint | false | unresolved | none | — |
| set_issue_fields | openWorldHint | true | unresolved | none | — |
| star_repository | readOnlyHint | false | unresolved | effective_risk | unknown |
| star_repository | idempotentHint | false | unresolved | none | — |
| sub_issue_write | readOnlyHint | false | unresolved | effective_risk | unknown |
| sub_issue_write | idempotentHint | false | unresolved | none | — |
| submit_pending_pull_request_review | readOnlyHint | false | unresolved | effective_risk | unknown |
| submit_pending_pull_request_review | destructiveHint | false | unresolved | effective_risk | unknown |
| submit_pending_pull_request_review | idempotentHint | false | unresolved | none | — |
| submit_pending_pull_request_review | openWorldHint | true | unresolved | none | — |
| ui_get | readOnlyHint | true | unresolved | effective_risk | unknown |
| ui_get | idempotentHint | false | inapplicable | readOnlyHint | true |
| unresolve_review_thread | readOnlyHint | false | unresolved | effective_risk | unknown |
| unresolve_review_thread | destructiveHint | false | unresolved | effective_risk | unknown |
| unresolve_review_thread | idempotentHint | false | unresolved | none | — |
| unresolve_review_thread | openWorldHint | true | unresolved | none | — |
| unstar_repository | readOnlyHint | false | unresolved | effective_risk | unknown |
| unstar_repository | idempotentHint | false | unresolved | none | — |
| update_gist | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_gist | idempotentHint | false | unresolved | none | — |
| update_issue_assignees | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_issue_assignees | destructiveHint | false | unresolved | effective_risk | unknown |
| update_issue_assignees | idempotentHint | false | unresolved | none | — |
| update_issue_assignees | openWorldHint | true | unresolved | none | — |
| update_issue_body | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_issue_body | destructiveHint | false | unresolved | effective_risk | unknown |
| update_issue_body | idempotentHint | false | unresolved | none | — |
| update_issue_body | openWorldHint | true | unresolved | none | — |
| update_issue_labels | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_issue_labels | destructiveHint | false | unresolved | effective_risk | unknown |
| update_issue_labels | idempotentHint | false | unresolved | none | — |
| update_issue_labels | openWorldHint | true | unresolved | none | — |
| update_issue_milestone | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_issue_milestone | destructiveHint | false | unresolved | effective_risk | unknown |
| update_issue_milestone | idempotentHint | false | unresolved | none | — |
| update_issue_milestone | openWorldHint | true | unresolved | none | — |
| update_issue_state | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_issue_state | destructiveHint | false | unresolved | effective_risk | unknown |
| update_issue_state | idempotentHint | false | unresolved | none | — |
| update_issue_state | openWorldHint | true | unresolved | none | — |
| update_issue_title | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_issue_title | destructiveHint | false | unresolved | effective_risk | unknown |
| update_issue_title | idempotentHint | false | unresolved | none | — |
| update_issue_title | openWorldHint | true | unresolved | none | — |
| update_issue_type | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_issue_type | destructiveHint | false | unresolved | effective_risk | unknown |
| update_issue_type | idempotentHint | false | unresolved | none | — |
| update_issue_type | openWorldHint | true | unresolved | none | — |
| update_pull_request | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_pull_request | idempotentHint | false | unresolved | none | — |
| update_pull_request_body | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_pull_request_body | destructiveHint | false | unresolved | effective_risk | unknown |
| update_pull_request_body | idempotentHint | false | unresolved | none | — |
| update_pull_request_body | openWorldHint | true | unresolved | none | — |
| update_pull_request_branch | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_pull_request_branch | idempotentHint | false | unresolved | none | — |
| update_pull_request_draft_state | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_pull_request_draft_state | destructiveHint | false | unresolved | effective_risk | unknown |
| update_pull_request_draft_state | idempotentHint | false | unresolved | none | — |
| update_pull_request_draft_state | openWorldHint | true | unresolved | none | — |
| update_pull_request_state | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_pull_request_state | destructiveHint | false | unresolved | effective_risk | unknown |
| update_pull_request_state | idempotentHint | false | unresolved | none | — |
| update_pull_request_state | openWorldHint | true | unresolved | none | — |
| update_pull_request_title | readOnlyHint | false | unresolved | effective_risk | unknown |
| update_pull_request_title | destructiveHint | false | unresolved | effective_risk | unknown |
| update_pull_request_title | idempotentHint | false | unresolved | none | — |
| update_pull_request_title | openWorldHint | true | unresolved | none | — |

## Remediation guidance

> Advisory only: the report does not change a model schema, prove that
> trusted application state exists, or deploy a runtime integration.

| Tool | Argument | Status | Preferred remediation | Fallback remediation | Review reason |
|---|---|---|---|---|---|
| actions_get | method | review_required | — | — | selector_semantics_require_review |
| actions_get | owner | review_required | — | — | authority_inference_requires_review |
| actions_get | repo | review_required | — | — | authority_inference_requires_review |
| actions_get | resource_id | review_required | — | — | authority_inference_requires_review |
| actions_list | method | review_required | — | — | selector_semantics_require_review |
| actions_list | owner | review_required | — | — | authority_inference_requires_review |
| actions_list | page | review_required | — | — | authority_inference_requires_review |
| actions_list | per_page | review_required | — | — | authority_inference_requires_review |
| actions_list | repo | review_required | — | — | authority_inference_requires_review |
| actions_list | resource_id | review_required | — | — | authority_inference_requires_review |
| actions_list | workflow_jobs_filter | review_required | — | — | authority_inference_requires_review |
| actions_list | workflow_runs_filter | review_required | — | — | authority_inference_requires_review |
| actions_run_trigger | inputs | review_required | — | — | authority_inference_requires_review |
| actions_run_trigger | method | review_required | — | — | selector_semantics_require_review |
| actions_run_trigger | owner | review_required | — | — | authority_inference_requires_review |
| actions_run_trigger | ref | review_required | — | — | authority_inference_requires_review |
| actions_run_trigger | repo | review_required | — | — | authority_inference_requires_review |
| actions_run_trigger | run_id | review_required | — | — | authority_inference_requires_review |
| actions_run_trigger | workflow_id | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | line | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | owner | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| add_comment_to_pending_review | pullNumber | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | repo | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | side | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | startLine | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | startSide | review_required | — | — | authority_inference_requires_review |
| add_comment_to_pending_review | subjectType | review_required | — | — | authority_inference_requires_review |
| add_issue_comment | comment_id | review_required | — | — | authority_inference_requires_review |
| add_issue_comment | issue_number | review_required | — | — | authority_inference_requires_review |
| add_issue_comment | owner | review_required | — | — | authority_inference_requires_review |
| add_issue_comment | reaction | review_required | — | — | selector_semantics_require_review |
| add_issue_comment | repo | review_required | — | — | authority_inference_requires_review |
| add_issue_comment_reaction | comment_id | review_required | — | — | authority_inference_requires_review |
| add_issue_comment_reaction | content | review_required | — | — | authority_inference_requires_review |
| add_issue_comment_reaction | owner | review_required | — | — | authority_inference_requires_review |
| add_issue_comment_reaction | repo | review_required | — | — | authority_inference_requires_review |
| add_issue_reaction | content | review_required | — | — | authority_inference_requires_review |
| add_issue_reaction | issue_number | review_required | — | — | authority_inference_requires_review |
| add_issue_reaction | owner | review_required | — | — | authority_inference_requires_review |
| add_issue_reaction | repo | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | line | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | owner | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| add_pull_request_review_comment | pullNumber | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | repo | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | side | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | startLine | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | startSide | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment | subjectType | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment_reaction | comment_id | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment_reaction | content | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment_reaction | owner | review_required | — | — | authority_inference_requires_review |
| add_pull_request_review_comment_reaction | repo | review_required | — | — | authority_inference_requires_review |
| add_reply_to_pull_request_comment | commentId | review_required | — | — | authority_inference_requires_review |
| add_reply_to_pull_request_comment | owner | review_required | — | — | authority_inference_requires_review |
| add_reply_to_pull_request_comment | pullNumber | review_required | — | — | authority_inference_requires_review |
| add_reply_to_pull_request_comment | reaction | review_required | — | — | selector_semantics_require_review |
| add_reply_to_pull_request_comment | repo | review_required | — | — | authority_inference_requires_review |
| add_sub_issue | issue_number | review_required | — | — | authority_inference_requires_review |
| add_sub_issue | owner | review_required | — | — | authority_inference_requires_review |
| add_sub_issue | replace_parent | review_required | — | — | authority_inference_requires_review |
| add_sub_issue | repo | review_required | — | — | authority_inference_requires_review |
| add_sub_issue | sub_issue_id | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue | base_ref | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue | custom_instructions | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue | issue_number | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue | owner | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue | repo | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | base_ref | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | confidence | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | custom_instructions | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | is_suggestion | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | issue_number | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | owner | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | rationale | review_required | — | — | authority_inference_requires_review |
| assign_copilot_to_issue_with_intent | repo | review_required | — | — | authority_inference_requires_review |
| create_branch | branch | review_required | — | — | authority_inference_requires_review |
| create_branch | from_branch | review_required | — | — | authority_inference_requires_review |
| create_branch | owner | review_required | — | — | authority_inference_requires_review |
| create_branch | repo | review_required | — | — | authority_inference_requires_review |
| create_gist | filename | review_required | — | — | authority_inference_requires_review |
| create_gist | public | review_required | — | — | authority_inference_requires_review |
| create_issue | owner | review_required | — | — | authority_inference_requires_review |
| create_issue | parent_issue_number | review_required | — | — | authority_inference_requires_review |
| create_issue | parent_owner | review_required | — | — | authority_inference_requires_review |
| create_issue | parent_repo | review_required | — | — | authority_inference_requires_review |
| create_issue | repo | review_required | — | — | authority_inference_requires_review |
| create_issue | title | review_required | — | — | authority_inference_requires_review |
| create_or_update_file | allow_symlink_write | review_required | — | — | authority_inference_requires_review |
| create_or_update_file | branch | review_required | — | — | authority_inference_requires_review |
| create_or_update_file | owner | review_required | — | — | authority_inference_requires_review |
| create_or_update_file | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| create_or_update_file | repo | review_required | — | — | authority_inference_requires_review |
| create_or_update_file | sha | review_required | — | — | authority_inference_requires_review |
| create_pull_request | base | review_required | — | — | authority_inference_requires_review |
| create_pull_request | draft | review_required | — | — | authority_inference_requires_review |
| create_pull_request | head | review_required | — | — | authority_inference_requires_review |
| create_pull_request | maintainer_can_modify | review_required | — | — | authority_inference_requires_review |
| create_pull_request | owner | review_required | — | — | authority_inference_requires_review |
| create_pull_request | repo | review_required | — | — | authority_inference_requires_review |
| create_pull_request | reviewers | review_required | — | — | authority_inference_requires_review |
| create_pull_request | title | review_required | — | — | authority_inference_requires_review |
| create_pull_request_review | commitID | review_required | — | — | authority_inference_requires_review |
| create_pull_request_review | event | review_required | — | — | authority_inference_requires_review |
| create_pull_request_review | owner | review_required | — | — | authority_inference_requires_review |
| create_pull_request_review | pullNumber | review_required | — | — | authority_inference_requires_review |
| create_pull_request_review | repo | review_required | — | — | authority_inference_requires_review |
| create_repository | autoInit | review_required | — | — | authority_inference_requires_review |
| create_repository | name | review_required | — | — | authority_inference_requires_review |
| create_repository | organization | review_required | — | — | authority_inference_requires_review |
| create_repository | private | review_required | — | — | authority_inference_requires_review |
| delete_file | branch | review_required | — | — | authority_inference_requires_review |
| delete_file | owner | review_required | — | — | authority_inference_requires_review |
| delete_file | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| delete_file | repo | review_required | — | — | authority_inference_requires_review |
| delete_pending_pull_request_review | owner | review_required | — | — | authority_inference_requires_review |
| delete_pending_pull_request_review | pullNumber | review_required | — | — | authority_inference_requires_review |
| delete_pending_pull_request_review | repo | review_required | — | — | authority_inference_requires_review |
| delete_repository | owner | review_required | — | — | authority_inference_requires_review |
| delete_repository | repo | review_required | — | — | authority_inference_requires_review |
| discussion_comment_write | commentNodeID | review_required | — | — | authority_inference_requires_review |
| discussion_comment_write | discussionNumber | review_required | — | — | authority_inference_requires_review |
| discussion_comment_write | method | review_required | — | — | selector_semantics_require_review |
| discussion_comment_write | owner | review_required | — | — | authority_inference_requires_review |
| discussion_comment_write | repo | review_required | — | — | authority_inference_requires_review |
| dismiss_notification | state | review_required | — | — | authority_inference_requires_review |
| dismiss_notification | threadID | review_required | — | — | authority_inference_requires_review |
| find_duplicate | confidence_threshold | review_required | — | — | authority_inference_requires_review |
| find_duplicate | issue_number | review_required | — | — | authority_inference_requires_review |
| find_duplicate | owner | review_required | — | — | authority_inference_requires_review |
| find_duplicate | page | review_required | — | — | authority_inference_requires_review |
| find_duplicate | perPage | review_required | — | — | authority_inference_requires_review |
| find_duplicate | repo | review_required | — | — | authority_inference_requires_review |
| fork_repository | organization | review_required | — | — | authority_inference_requires_review |
| fork_repository | owner | review_required | — | — | authority_inference_requires_review |
| fork_repository | repo | review_required | — | — | authority_inference_requires_review |
| get_code_quality_finding | findingNumber | review_required | — | — | authority_inference_requires_review |
| get_code_quality_finding | owner | review_required | — | — | authority_inference_requires_review |
| get_code_quality_finding | repo | review_required | — | — | authority_inference_requires_review |
| get_code_scanning_alert | alertNumber | review_required | — | — | authority_inference_requires_review |
| get_code_scanning_alert | owner | review_required | — | — | authority_inference_requires_review |
| get_code_scanning_alert | repo | review_required | — | — | authority_inference_requires_review |
| get_commit | detail | review_required | — | — | authority_inference_requires_review |
| get_commit | owner | review_required | — | — | authority_inference_requires_review |
| get_commit | page | review_required | — | — | authority_inference_requires_review |
| get_commit | perPage | review_required | — | — | authority_inference_requires_review |
| get_commit | repo | review_required | — | — | authority_inference_requires_review |
| get_commit | sha | review_required | — | — | authority_inference_requires_review |
| get_dependabot_alert | alertNumber | review_required | — | — | authority_inference_requires_review |
| get_dependabot_alert | owner | review_required | — | — | authority_inference_requires_review |
| get_dependabot_alert | repo | review_required | — | — | authority_inference_requires_review |
| get_discussion | discussionNumber | review_required | — | — | authority_inference_requires_review |
| get_discussion | owner | review_required | — | — | authority_inference_requires_review |
| get_discussion | repo | review_required | — | — | authority_inference_requires_review |
| get_discussion_comments | after | review_required | — | — | authority_inference_requires_review |
| get_discussion_comments | discussionNumber | review_required | — | — | authority_inference_requires_review |
| get_discussion_comments | includeReplies | review_required | — | — | authority_inference_requires_review |
| get_discussion_comments | owner | review_required | — | — | authority_inference_requires_review |
| get_discussion_comments | perPage | review_required | — | — | authority_inference_requires_review |
| get_discussion_comments | repo | review_required | — | — | authority_inference_requires_review |
| get_file_blame | after | review_required | — | — | authority_inference_requires_review |
| get_file_blame | end_line | review_required | — | — | authority_inference_requires_review |
| get_file_blame | owner | review_required | — | — | authority_inference_requires_review |
| get_file_blame | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| get_file_blame | perPage | review_required | — | — | authority_inference_requires_review |
| get_file_blame | ref | review_required | — | — | authority_inference_requires_review |
| get_file_blame | repo | review_required | — | — | authority_inference_requires_review |
| get_file_blame | start_line | review_required | — | — | authority_inference_requires_review |
| get_file_contents | fields | review_required | — | — | authority_inference_requires_review |
| get_file_contents | owner | review_required | — | — | authority_inference_requires_review |
| get_file_contents | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| get_file_contents | ref | review_required | — | — | authority_inference_requires_review |
| get_file_contents | repo | review_required | — | — | authority_inference_requires_review |
| get_file_contents | sha | review_required | — | — | authority_inference_requires_review |
| get_gist | gist_id | review_required | — | — | authority_inference_requires_review |
| get_global_security_advisory | ghsaId | review_required | — | — | authority_inference_requires_review |
| get_job_logs | failed_only | review_required | — | — | authority_inference_requires_review |
| get_job_logs | job_id | review_required | — | — | authority_inference_requires_review |
| get_job_logs | owner | review_required | — | — | authority_inference_requires_review |
| get_job_logs | repo | review_required | — | — | authority_inference_requires_review |
| get_job_logs | return_content | review_required | — | — | authority_inference_requires_review |
| get_job_logs | run_id | review_required | — | — | authority_inference_requires_review |
| get_job_logs | tail_lines | review_required | — | — | authority_inference_requires_review |
| get_label | name | review_required | — | — | authority_inference_requires_review |
| get_label | owner | review_required | — | — | authority_inference_requires_review |
| get_label | repo | review_required | — | — | authority_inference_requires_review |
| get_latest_release | owner | review_required | — | — | authority_inference_requires_review |
| get_latest_release | repo | review_required | — | — | authority_inference_requires_review |
| get_notification_details | notificationID | review_required | — | — | authority_inference_requires_review |
| get_release_by_tag | owner | review_required | — | — | authority_inference_requires_review |
| get_release_by_tag | repo | review_required | — | — | authority_inference_requires_review |
| get_release_by_tag | tag | review_required | — | — | authority_inference_requires_review |
| get_repository_tree | owner | review_required | — | — | authority_inference_requires_review |
| get_repository_tree | path_filter | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| get_repository_tree | recursive | review_required | — | — | authority_inference_requires_review |
| get_repository_tree | repo | review_required | — | — | authority_inference_requires_review |
| get_repository_tree | tree_sha | review_required | — | — | authority_inference_requires_review |
| get_secret_scanning_alert | alertNumber | review_required | — | — | authority_inference_requires_review |
| get_secret_scanning_alert | owner | review_required | — | — | authority_inference_requires_review |
| get_secret_scanning_alert | repo | review_required | — | — | authority_inference_requires_review |
| get_tag | owner | review_required | — | — | authority_inference_requires_review |
| get_tag | repo | review_required | — | — | authority_inference_requires_review |
| get_tag | tag | review_required | — | — | authority_inference_requires_review |
| get_team_members | org | review_required | — | — | authority_inference_requires_review |
| get_team_members | team_slug | review_required | — | — | authority_inference_requires_review |
| get_teams | user | review_required | — | — | authority_inference_requires_review |
| issue_dependency_read | issue_number | review_required | — | — | authority_inference_requires_review |
| issue_dependency_read | method | review_required | — | — | selector_semantics_require_review |
| issue_dependency_read | owner | review_required | — | — | authority_inference_requires_review |
| issue_dependency_read | page | review_required | — | — | authority_inference_requires_review |
| issue_dependency_read | perPage | review_required | — | — | authority_inference_requires_review |
| issue_dependency_read | repo | review_required | — | — | authority_inference_requires_review |
| issue_dependency_write | issue_number | review_required | — | — | authority_inference_requires_review |
| issue_dependency_write | method | review_required | — | — | selector_semantics_require_review |
| issue_dependency_write | owner | review_required | — | — | authority_inference_requires_review |
| issue_dependency_write | related_issue_number | review_required | — | — | authority_inference_requires_review |
| issue_dependency_write | related_owner | review_required | — | — | authority_inference_requires_review |
| issue_dependency_write | related_repo | review_required | — | — | authority_inference_requires_review |
| issue_dependency_write | repo | review_required | — | — | authority_inference_requires_review |
| issue_dependency_write | type | review_required | — | — | authority_inference_requires_review |
| issue_read | issue_number | review_required | — | — | authority_inference_requires_review |
| issue_read | method | review_required | — | — | selector_semantics_require_review |
| issue_read | owner | review_required | — | — | authority_inference_requires_review |
| issue_read | page | review_required | — | — | authority_inference_requires_review |
| issue_read | perPage | review_required | — | — | authority_inference_requires_review |
| issue_read | repo | review_required | — | — | authority_inference_requires_review |
| issue_write | assignees | review_required | — | — | authority_inference_requires_review |
| issue_write | duplicate_of | review_required | — | — | authority_inference_requires_review |
| issue_write | issue_fields | review_required | — | — | authority_inference_requires_review |
| issue_write | issue_number | review_required | — | — | authority_inference_requires_review |
| issue_write | labels | review_required | — | — | authority_inference_requires_review |
| issue_write | method | review_required | — | — | selector_semantics_require_review |
| issue_write | milestone | review_required | — | — | authority_inference_requires_review |
| issue_write | owner | review_required | — | — | authority_inference_requires_review |
| issue_write | parent_issue_number | review_required | — | — | authority_inference_requires_review |
| issue_write | parent_owner | review_required | — | — | authority_inference_requires_review |
| issue_write | parent_repo | review_required | — | — | authority_inference_requires_review |
| issue_write | repo | review_required | — | — | authority_inference_requires_review |
| issue_write | state | review_required | — | — | authority_inference_requires_review |
| issue_write | state_reason | review_required | — | — | authority_inference_requires_review |
| issue_write | title | review_required | — | — | authority_inference_requires_review |
| issue_write | type | review_required | — | — | authority_inference_requires_review |
| label_write | color | review_required | — | — | authority_inference_requires_review |
| label_write | method | review_required | — | — | selector_semantics_require_review |
| label_write | name | review_required | — | — | authority_inference_requires_review |
| label_write | new_name | review_required | — | — | authority_inference_requires_review |
| label_write | owner | review_required | — | — | authority_inference_requires_review |
| label_write | repo | review_required | — | — | authority_inference_requires_review |
| list_branches | owner | review_required | — | — | authority_inference_requires_review |
| list_branches | page | review_required | — | — | authority_inference_requires_review |
| list_branches | perPage | review_required | — | — | authority_inference_requires_review |
| list_branches | repo | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | owner | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | page | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | perPage | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | ref | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | repo | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | severity | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | state | review_required | — | — | authority_inference_requires_review |
| list_code_scanning_alerts | tool_name | review_required | — | — | authority_inference_requires_review |
| list_commits | author | review_required | — | — | authority_inference_requires_review |
| list_commits | fields | review_required | — | — | authority_inference_requires_review |
| list_commits | owner | review_required | — | — | authority_inference_requires_review |
| list_commits | page | review_required | — | — | authority_inference_requires_review |
| list_commits | path | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| list_commits | perPage | review_required | — | — | authority_inference_requires_review |
| list_commits | repo | review_required | — | — | authority_inference_requires_review |
| list_commits | sha | review_required | — | — | authority_inference_requires_review |
| list_commits | since | review_required | — | — | authority_inference_requires_review |
| list_commits | until | review_required | — | — | authority_inference_requires_review |
| list_dependabot_alerts | after | review_required | — | — | authority_inference_requires_review |
| list_dependabot_alerts | owner | review_required | — | — | authority_inference_requires_review |
| list_dependabot_alerts | perPage | review_required | — | — | authority_inference_requires_review |
| list_dependabot_alerts | repo | review_required | — | — | authority_inference_requires_review |
| list_dependabot_alerts | severity | review_required | — | — | authority_inference_requires_review |
| list_dependabot_alerts | state | review_required | — | — | authority_inference_requires_review |
| list_discussion_categories | owner | review_required | — | — | authority_inference_requires_review |
| list_discussion_categories | repo | review_required | — | — | authority_inference_requires_review |
| list_discussions | after | review_required | — | — | authority_inference_requires_review |
| list_discussions | category | review_required | — | — | authority_inference_requires_review |
| list_discussions | direction | review_required | — | — | authority_inference_requires_review |
| list_discussions | orderBy | review_required | — | — | authority_inference_requires_review |
| list_discussions | owner | review_required | — | — | authority_inference_requires_review |
| list_discussions | perPage | review_required | — | — | authority_inference_requires_review |
| list_discussions | repo | review_required | — | — | authority_inference_requires_review |
| list_gists | page | review_required | — | — | authority_inference_requires_review |
| list_gists | perPage | review_required | — | — | authority_inference_requires_review |
| list_gists | since | review_required | — | — | authority_inference_requires_review |
| list_gists | username | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | affects | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | cveId | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | cwes | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | ecosystem | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | ghsaId | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | isWithdrawn | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | modified | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | published | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | severity | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | type | review_required | — | — | authority_inference_requires_review |
| list_global_security_advisories | updated | review_required | — | — | authority_inference_requires_review |
| list_issue_fields | owner | review_required | — | — | authority_inference_requires_review |
| list_issue_fields | repo | review_required | — | — | authority_inference_requires_review |
| list_issue_types | owner | review_required | — | — | authority_inference_requires_review |
| list_issue_types | repo | review_required | — | — | authority_inference_requires_review |
| list_issues | after | review_required | — | — | authority_inference_requires_review |
| list_issues | direction | review_required | — | — | authority_inference_requires_review |
| list_issues | field_filters | review_required | — | — | authority_inference_requires_review |
| list_issues | fields | review_required | — | — | authority_inference_requires_review |
| list_issues | labels | review_required | — | — | authority_inference_requires_review |
| list_issues | orderBy | review_required | — | — | authority_inference_requires_review |
| list_issues | owner | review_required | — | — | authority_inference_requires_review |
| list_issues | perPage | review_required | — | — | authority_inference_requires_review |
| list_issues | repo | review_required | — | — | authority_inference_requires_review |
| list_issues | since | review_required | — | — | authority_inference_requires_review |
| list_issues | state | review_required | — | — | authority_inference_requires_review |
| list_label | owner | review_required | — | — | authority_inference_requires_review |
| list_label | repo | review_required | — | — | authority_inference_requires_review |
| list_notifications | before | review_required | — | — | authority_inference_requires_review |
| list_notifications | filter | review_required | — | — | authority_inference_requires_review |
| list_notifications | owner | review_required | — | — | authority_inference_requires_review |
| list_notifications | page | review_required | — | — | authority_inference_requires_review |
| list_notifications | perPage | review_required | — | — | authority_inference_requires_review |
| list_notifications | repo | review_required | — | — | authority_inference_requires_review |
| list_notifications | since | review_required | — | — | authority_inference_requires_review |
| list_org_repository_security_advisories | direction | review_required | — | — | authority_inference_requires_review |
| list_org_repository_security_advisories | org | review_required | — | — | authority_inference_requires_review |
| list_org_repository_security_advisories | sort | review_required | — | — | authority_inference_requires_review |
| list_org_repository_security_advisories | state | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | base | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | direction | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | fields | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | head | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | owner | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | page | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | perPage | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | repo | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | sort | review_required | — | — | authority_inference_requires_review |
| list_pull_requests | state | review_required | — | — | authority_inference_requires_review |
| list_releases | fields | review_required | — | — | authority_inference_requires_review |
| list_releases | owner | review_required | — | — | authority_inference_requires_review |
| list_releases | page | review_required | — | — | authority_inference_requires_review |
| list_releases | perPage | review_required | — | — | authority_inference_requires_review |
| list_releases | repo | review_required | — | — | authority_inference_requires_review |
| list_repository_collaborators | affiliation | review_required | — | — | authority_inference_requires_review |
| list_repository_collaborators | owner | review_required | — | — | authority_inference_requires_review |
| list_repository_collaborators | page | review_required | — | — | authority_inference_requires_review |
| list_repository_collaborators | perPage | review_required | — | — | authority_inference_requires_review |
| list_repository_collaborators | repo | review_required | — | — | authority_inference_requires_review |
| list_repository_security_advisories | direction | review_required | — | — | authority_inference_requires_review |
| list_repository_security_advisories | owner | review_required | — | — | authority_inference_requires_review |
| list_repository_security_advisories | repo | review_required | — | — | authority_inference_requires_review |
| list_repository_security_advisories | sort | review_required | — | — | authority_inference_requires_review |
| list_repository_security_advisories | state | review_required | — | — | authority_inference_requires_review |
| list_secret_scanning_alerts | owner | review_required | — | — | authority_inference_requires_review |
| list_secret_scanning_alerts | page | review_required | — | — | authority_inference_requires_review |
| list_secret_scanning_alerts | perPage | review_required | — | — | authority_inference_requires_review |
| list_secret_scanning_alerts | repo | review_required | — | — | authority_inference_requires_review |
| list_secret_scanning_alerts | resolution | review_required | — | — | authority_inference_requires_review |
| list_secret_scanning_alerts | secret_type | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| list_secret_scanning_alerts | state | review_required | — | — | authority_inference_requires_review |
| list_starred_repositories | direction | review_required | — | — | authority_inference_requires_review |
| list_starred_repositories | page | review_required | — | — | authority_inference_requires_review |
| list_starred_repositories | perPage | review_required | — | — | authority_inference_requires_review |
| list_starred_repositories | sort | review_required | — | — | authority_inference_requires_review |
| list_starred_repositories | username | review_required | — | — | authority_inference_requires_review |
| list_tags | owner | review_required | — | — | authority_inference_requires_review |
| list_tags | page | review_required | — | — | authority_inference_requires_review |
| list_tags | perPage | review_required | — | — | authority_inference_requires_review |
| list_tags | repo | review_required | — | — | authority_inference_requires_review |
| manage_notification_subscription | action | review_required | — | — | selector_semantics_require_review |
| manage_notification_subscription | notificationID | review_required | — | — | authority_inference_requires_review |
| manage_repository_notification_subscription | action | review_required | — | — | selector_semantics_require_review |
| manage_repository_notification_subscription | owner | review_required | — | — | authority_inference_requires_review |
| manage_repository_notification_subscription | repo | review_required | — | — | authority_inference_requires_review |
| mark_all_notifications_read | lastReadAt | review_required | — | — | authority_inference_requires_review |
| mark_all_notifications_read | owner | review_required | — | — | authority_inference_requires_review |
| mark_all_notifications_read | repo | review_required | — | — | authority_inference_requires_review |
| merge_pull_request | commit_title | review_required | — | — | authority_inference_requires_review |
| merge_pull_request | expectedHeadSha | review_required | — | — | authority_inference_requires_review |
| merge_pull_request | merge_method | review_required | — | — | selector_semantics_require_review |
| merge_pull_request | owner | review_required | — | — | authority_inference_requires_review |
| merge_pull_request | pullNumber | review_required | — | — | authority_inference_requires_review |
| merge_pull_request | repo | review_required | — | — | authority_inference_requires_review |
| projects_get | field_id | review_required | — | — | authority_inference_requires_review |
| projects_get | field_names | review_required | — | — | authority_inference_requires_review |
| projects_get | fields | review_required | — | — | authority_inference_requires_review |
| projects_get | item_id | review_required | — | — | authority_inference_requires_review |
| projects_get | method | review_required | — | — | selector_semantics_require_review |
| projects_get | owner | review_required | — | — | authority_inference_requires_review |
| projects_get | owner_type | review_required | — | — | authority_inference_requires_review |
| projects_get | project_number | review_required | — | — | authority_inference_requires_review |
| projects_get | status_update_id | review_required | — | — | authority_inference_requires_review |
| projects_get | view_id | review_required | — | — | authority_inference_requires_review |
| projects_list | after | review_required | — | — | authority_inference_requires_review |
| projects_list | before | review_required | — | — | authority_inference_requires_review |
| projects_list | field_names | review_required | — | — | authority_inference_requires_review |
| projects_list | fields | review_required | — | — | authority_inference_requires_review |
| projects_list | method | review_required | — | — | selector_semantics_require_review |
| projects_list | owner | review_required | — | — | authority_inference_requires_review |
| projects_list | owner_type | review_required | — | — | authority_inference_requires_review |
| projects_list | per_page | review_required | — | — | authority_inference_requires_review |
| projects_list | project_number | review_required | — | — | authority_inference_requires_review |
| projects_list | query | review_required | — | — | authority_inference_requires_review |
| projects_write | field_name | review_required | — | — | authority_inference_requires_review |
| projects_write | filter | review_required | — | — | authority_inference_requires_review |
| projects_write | issue_number | review_required | — | — | authority_inference_requires_review |
| projects_write | item_id | review_required | — | — | authority_inference_requires_review |
| projects_write | item_owner | review_required | — | — | authority_inference_requires_review |
| projects_write | item_repo | review_required | — | — | authority_inference_requires_review |
| projects_write | item_type | review_required | — | — | authority_inference_requires_review |
| projects_write | items | review_required | — | — | authority_inference_requires_review |
| projects_write | iteration_duration | review_required | — | — | authority_inference_requires_review |
| projects_write | iterations | review_required | — | — | authority_inference_requires_review |
| projects_write | layout | review_required | — | — | authority_inference_requires_review |
| projects_write | method | review_required | — | — | selector_semantics_require_review |
| projects_write | name | review_required | — | — | authority_inference_requires_review |
| projects_write | owner | review_required | — | — | authority_inference_requires_review |
| projects_write | owner_type | review_required | — | — | authority_inference_requires_review |
| projects_write | project_number | review_required | — | — | authority_inference_requires_review |
| projects_write | pull_request_number | review_required | — | — | authority_inference_requires_review |
| projects_write | start_date | review_required | — | — | authority_inference_requires_review |
| projects_write | status | review_required | — | — | authority_inference_requires_review |
| projects_write | target_date | review_required | — | — | authority_inference_requires_review |
| projects_write | title | review_required | — | — | authority_inference_requires_review |
| projects_write | updated_field | review_required | — | — | authority_inference_requires_review |
| projects_write | view_id | review_required | — | — | authority_inference_requires_review |
| projects_write | visible_field_names | review_required | — | — | authority_inference_requires_review |
| projects_write | visible_fields | review_required | — | — | authority_inference_requires_review |
| pull_request_read | after | review_required | — | — | authority_inference_requires_review |
| pull_request_read | method | review_required | — | — | selector_semantics_require_review |
| pull_request_read | owner | review_required | — | — | authority_inference_requires_review |
| pull_request_read | page | review_required | — | — | authority_inference_requires_review |
| pull_request_read | perPage | review_required | — | — | authority_inference_requires_review |
| pull_request_read | pullNumber | review_required | — | — | authority_inference_requires_review |
| pull_request_read | repo | review_required | — | — | authority_inference_requires_review |
| pull_request_review_write | commitID | review_required | — | — | authority_inference_requires_review |
| pull_request_review_write | event | review_required | — | — | authority_inference_requires_review |
| pull_request_review_write | method | review_required | — | — | selector_semantics_require_review |
| pull_request_review_write | owner | review_required | — | — | authority_inference_requires_review |
| pull_request_review_write | pullNumber | review_required | — | — | authority_inference_requires_review |
| pull_request_review_write | repo | review_required | — | — | authority_inference_requires_review |
| pull_request_review_write | threadId | review_required | — | — | authority_inference_requires_review |
| push_files | branch | review_required | — | — | authority_inference_requires_review |
| push_files | files | recommended | remove_from_model_schema_and_inject_from_application | bind_trusted_value_at_runtime | — |
| push_files | owner | review_required | — | — | authority_inference_requires_review |
| push_files | repo | review_required | — | — | authority_inference_requires_review |
| remove_sub_issue | issue_number | review_required | — | — | authority_inference_requires_review |
| remove_sub_issue | owner | review_required | — | — | authority_inference_requires_review |
| remove_sub_issue | repo | review_required | — | — | authority_inference_requires_review |
| remove_sub_issue | sub_issue_id | review_required | — | — | authority_inference_requires_review |
| reprioritize_sub_issue | after_id | review_required | — | — | authority_inference_requires_review |
| reprioritize_sub_issue | before_id | review_required | — | — | authority_inference_requires_review |
| reprioritize_sub_issue | issue_number | review_required | — | — | authority_inference_requires_review |
| reprioritize_sub_issue | owner | review_required | — | — | authority_inference_requires_review |
| reprioritize_sub_issue | repo | review_required | — | — | authority_inference_requires_review |
| reprioritize_sub_issue | sub_issue_id | review_required | — | — | authority_inference_requires_review |
| request_copilot_review | owner | review_required | — | — | authority_inference_requires_review |
| request_copilot_review | pullNumber | review_required | — | — | authority_inference_requires_review |
| request_copilot_review | repo | review_required | — | — | authority_inference_requires_review |
| request_pull_request_reviewers | owner | review_required | — | — | authority_inference_requires_review |
| request_pull_request_reviewers | pullNumber | review_required | — | — | authority_inference_requires_review |
| request_pull_request_reviewers | repo | review_required | — | — | authority_inference_requires_review |
| request_pull_request_reviewers | reviewers | review_required | — | — | authority_inference_requires_review |
| resolve_review_thread | threadID | review_required | — | — | authority_inference_requires_review |
| search_code | fields | review_required | — | — | authority_inference_requires_review |
| search_code | order | review_required | — | — | authority_inference_requires_review |
| search_code | page | review_required | — | — | authority_inference_requires_review |
| search_code | perPage | review_required | — | — | authority_inference_requires_review |
| search_code | query | review_required | — | — | authority_inference_requires_review |
| search_code | sort | review_required | — | — | authority_inference_requires_review |
| search_commits | order | review_required | — | — | authority_inference_requires_review |
| search_commits | page | review_required | — | — | authority_inference_requires_review |
| search_commits | perPage | review_required | — | — | authority_inference_requires_review |
| search_commits | query | review_required | — | — | authority_inference_requires_review |
| search_commits | sort | review_required | — | — | authority_inference_requires_review |
| search_issues | fields | review_required | — | — | authority_inference_requires_review |
| search_issues | order | review_required | — | — | authority_inference_requires_review |
| search_issues | owner | review_required | — | — | authority_inference_requires_review |
| search_issues | page | review_required | — | — | authority_inference_requires_review |
| search_issues | perPage | review_required | — | — | authority_inference_requires_review |
| search_issues | query | review_required | — | — | authority_inference_requires_review |
| search_issues | repo | review_required | — | — | authority_inference_requires_review |
| search_issues | sort | review_required | — | — | authority_inference_requires_review |
| search_orgs | order | review_required | — | — | authority_inference_requires_review |
| search_orgs | page | review_required | — | — | authority_inference_requires_review |
| search_orgs | perPage | review_required | — | — | authority_inference_requires_review |
| search_orgs | query | review_required | — | — | authority_inference_requires_review |
| search_orgs | sort | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | fields | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | order | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | owner | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | page | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | perPage | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | query | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | repo | review_required | — | — | authority_inference_requires_review |
| search_pull_requests | sort | review_required | — | — | authority_inference_requires_review |
| search_repositories | minimal_output | review_required | — | — | authority_inference_requires_review |
| search_repositories | order | review_required | — | — | authority_inference_requires_review |
| search_repositories | page | review_required | — | — | authority_inference_requires_review |
| search_repositories | perPage | review_required | — | — | authority_inference_requires_review |
| search_repositories | query | review_required | — | — | authority_inference_requires_review |
| search_repositories | sort | review_required | — | — | authority_inference_requires_review |
| search_users | order | review_required | — | — | authority_inference_requires_review |
| search_users | page | review_required | — | — | authority_inference_requires_review |
| search_users | perPage | review_required | — | — | authority_inference_requires_review |
| search_users | query | review_required | — | — | authority_inference_requires_review |
| search_users | sort | review_required | — | — | authority_inference_requires_review |
| set_issue_fields | fields | review_required | — | — | authority_inference_requires_review |
| set_issue_fields | issue_number | review_required | — | — | authority_inference_requires_review |
| set_issue_fields | owner | review_required | — | — | authority_inference_requires_review |
| set_issue_fields | repo | review_required | — | — | authority_inference_requires_review |
| star_repository | owner | review_required | — | — | authority_inference_requires_review |
| star_repository | repo | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | after_id | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | before_id | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | issue_number | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | method | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | owner | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | replace_parent | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | repo | review_required | — | — | authority_inference_requires_review |
| sub_issue_write | sub_issue_id | review_required | — | — | authority_inference_requires_review |
| submit_pending_pull_request_review | event | review_required | — | — | authority_inference_requires_review |
| submit_pending_pull_request_review | owner | review_required | — | — | authority_inference_requires_review |
| submit_pending_pull_request_review | pullNumber | review_required | — | — | authority_inference_requires_review |
| submit_pending_pull_request_review | repo | review_required | — | — | authority_inference_requires_review |
| ui_get | method | review_required | — | — | selector_semantics_require_review |
| ui_get | owner | review_required | — | — | authority_inference_requires_review |
| ui_get | repo | review_required | — | — | authority_inference_requires_review |
| unresolve_review_thread | threadID | review_required | — | — | authority_inference_requires_review |
| unstar_repository | owner | review_required | — | — | authority_inference_requires_review |
| unstar_repository | repo | review_required | — | — | authority_inference_requires_review |
| update_gist | filename | review_required | — | — | authority_inference_requires_review |
| update_gist | gist_id | review_required | — | — | authority_inference_requires_review |
| update_issue_assignees | assignees | review_required | — | — | authority_inference_requires_review |
| update_issue_assignees | issue_number | review_required | — | — | authority_inference_requires_review |
| update_issue_assignees | owner | review_required | — | — | authority_inference_requires_review |
| update_issue_assignees | repo | review_required | — | — | authority_inference_requires_review |
| update_issue_body | issue_number | review_required | — | — | authority_inference_requires_review |
| update_issue_body | owner | review_required | — | — | authority_inference_requires_review |
| update_issue_body | repo | review_required | — | — | authority_inference_requires_review |
| update_issue_labels | issue_number | review_required | — | — | authority_inference_requires_review |
| update_issue_labels | labels | review_required | — | — | authority_inference_requires_review |
| update_issue_labels | owner | review_required | — | — | authority_inference_requires_review |
| update_issue_labels | repo | review_required | — | — | authority_inference_requires_review |
| update_issue_milestone | issue_number | review_required | — | — | authority_inference_requires_review |
| update_issue_milestone | milestone | review_required | — | — | authority_inference_requires_review |
| update_issue_milestone | owner | review_required | — | — | authority_inference_requires_review |
| update_issue_milestone | repo | review_required | — | — | authority_inference_requires_review |
| update_issue_state | confidence | review_required | — | — | authority_inference_requires_review |
| update_issue_state | duplicate_of | review_required | — | — | authority_inference_requires_review |
| update_issue_state | is_suggestion | review_required | — | — | authority_inference_requires_review |
| update_issue_state | issue_number | review_required | — | — | authority_inference_requires_review |
| update_issue_state | owner | review_required | — | — | authority_inference_requires_review |
| update_issue_state | rationale | review_required | — | — | authority_inference_requires_review |
| update_issue_state | repo | review_required | — | — | authority_inference_requires_review |
| update_issue_state | state | review_required | — | — | authority_inference_requires_review |
| update_issue_state | state_reason | review_required | — | — | authority_inference_requires_review |
| update_issue_title | issue_number | review_required | — | — | authority_inference_requires_review |
| update_issue_title | owner | review_required | — | — | authority_inference_requires_review |
| update_issue_title | repo | review_required | — | — | authority_inference_requires_review |
| update_issue_title | title | review_required | — | — | authority_inference_requires_review |
| update_issue_type | confidence | review_required | — | — | authority_inference_requires_review |
| update_issue_type | is_suggestion | review_required | — | — | authority_inference_requires_review |
| update_issue_type | issue_number | review_required | — | — | authority_inference_requires_review |
| update_issue_type | issue_type | review_required | — | — | authority_inference_requires_review |
| update_issue_type | owner | review_required | — | — | authority_inference_requires_review |
| update_issue_type | rationale | review_required | — | — | authority_inference_requires_review |
| update_issue_type | repo | review_required | — | — | authority_inference_requires_review |
| update_pull_request | base | review_required | — | — | authority_inference_requires_review |
| update_pull_request | draft | review_required | — | — | authority_inference_requires_review |
| update_pull_request | maintainer_can_modify | review_required | — | — | authority_inference_requires_review |
| update_pull_request | owner | review_required | — | — | authority_inference_requires_review |
| update_pull_request | pullNumber | review_required | — | — | authority_inference_requires_review |
| update_pull_request | repo | review_required | — | — | authority_inference_requires_review |
| update_pull_request | reviewers | review_required | — | — | authority_inference_requires_review |
| update_pull_request | state | review_required | — | — | authority_inference_requires_review |
| update_pull_request | title | review_required | — | — | authority_inference_requires_review |
| update_pull_request_body | owner | review_required | — | — | authority_inference_requires_review |
| update_pull_request_body | pullNumber | review_required | — | — | authority_inference_requires_review |
| update_pull_request_body | repo | review_required | — | — | authority_inference_requires_review |
| update_pull_request_branch | expectedHeadSha | review_required | — | — | authority_inference_requires_review |
| update_pull_request_branch | owner | review_required | — | — | authority_inference_requires_review |
| update_pull_request_branch | pullNumber | review_required | — | — | authority_inference_requires_review |
| update_pull_request_branch | repo | review_required | — | — | authority_inference_requires_review |
| update_pull_request_draft_state | draft | review_required | — | — | authority_inference_requires_review |
| update_pull_request_draft_state | owner | review_required | — | — | authority_inference_requires_review |
| update_pull_request_draft_state | pullNumber | review_required | — | — | authority_inference_requires_review |
| update_pull_request_draft_state | repo | review_required | — | — | authority_inference_requires_review |
| update_pull_request_state | owner | review_required | — | — | authority_inference_requires_review |
| update_pull_request_state | pullNumber | review_required | — | — | authority_inference_requires_review |
| update_pull_request_state | repo | review_required | — | — | authority_inference_requires_review |
| update_pull_request_state | state | review_required | — | — | authority_inference_requires_review |
| update_pull_request_title | owner | review_required | — | — | authority_inference_requires_review |
| update_pull_request_title | pullNumber | review_required | — | — | authority_inference_requires_review |
| update_pull_request_title | repo | review_required | — | — | authority_inference_requires_review |
| update_pull_request_title | title | review_required | — | — | authority_inference_requires_review |

## Findings

| Tool | Risk | Argument | Type | Required | Constraints | Policy | Review | Reason |
|---|---|---|---|---|---|---|---|---|
| actions_get | unknown | method | enum | yes | enum: 6 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_get | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_get | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_get | unknown | resource_id | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | method | enum | yes | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | per_page | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | resource_id | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | workflow_jobs_filter | object | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_list | unknown | workflow_runs_filter | object | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_run_trigger | unknown | inputs | object | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_run_trigger | unknown | method | enum | yes | enum: 5 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_run_trigger | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_run_trigger | unknown | ref | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_run_trigger | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_run_trigger | unknown | run_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| actions_run_trigger | unknown | workflow_id | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | body | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| add_comment_to_pending_review | unknown | line | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| add_comment_to_pending_review | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | side | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | startLine | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | startSide | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_comment_to_pending_review | unknown | subjectType | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| add_issue_comment | unknown | comment_id | integer | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment | unknown | reaction | enum | no | enum: 8 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment_reaction | unknown | comment_id | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment_reaction | unknown | content | enum | yes | enum: 8 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment_reaction | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_comment_reaction | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_reaction | unknown | content | enum | yes | enum: 8 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_reaction | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_reaction | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_issue_reaction | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | body | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| add_pull_request_review_comment | unknown | line | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| add_pull_request_review_comment | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | side | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | startLine | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | startSide | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment | unknown | subjectType | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment_reaction | unknown | comment_id | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment_reaction | unknown | content | enum | yes | enum: 8 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment_reaction | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_pull_request_review_comment_reaction | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_reply_to_pull_request_comment | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| add_reply_to_pull_request_comment | unknown | commentId | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_reply_to_pull_request_comment | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_reply_to_pull_request_comment | unknown | pullNumber | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_reply_to_pull_request_comment | unknown | reaction | enum | no | enum: 8 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_reply_to_pull_request_comment | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_sub_issue | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_sub_issue | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_sub_issue | unknown | replace_parent | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_sub_issue | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| add_sub_issue | unknown | sub_issue_id | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue | unknown | base_ref | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue | unknown | custom_instructions | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | base_ref | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | confidence | enum | yes | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | custom_instructions | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | is_suggestion | boolean | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | rationale | string | yes | max length: 280 | trusted_fixed | yes | ambiguous consequential argument; review required |
| assign_copilot_to_issue_with_intent | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_branch | unknown | branch | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_branch | unknown | from_branch | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_branch | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_branch | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_gist | unknown | content | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| create_gist | unknown | description | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| create_gist | unknown | filename | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_gist | unknown | public | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_issue | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| create_issue | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_issue | unknown | parent_issue_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_issue | unknown | parent_owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_issue | unknown | parent_repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_issue | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_issue | unknown | title | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_or_update_file | unknown | allow_symlink_write | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_or_update_file | unknown | branch | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_or_update_file | unknown | content | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| create_or_update_file | unknown | message | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| create_or_update_file | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_or_update_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| create_or_update_file | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_or_update_file | unknown | sha | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | base | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| create_pull_request | unknown | draft | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | head | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | maintainer_can_modify | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | reviewers | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request | unknown | title | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request_review | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| create_pull_request_review | unknown | commitID | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request_review | unknown | event | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request_review | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request_review | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_pull_request_review | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_repository | unknown | autoInit | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_repository | unknown | description | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| create_repository | unknown | name | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_repository | unknown | organization | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| create_repository | unknown | private | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_file | unknown | branch | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_file | unknown | message | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| delete_file | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_file | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| delete_file | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_pending_pull_request_review | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_pending_pull_request_review | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_pending_pull_request_review | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_repository | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| delete_repository | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| discussion_comment_write | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| discussion_comment_write | unknown | commentNodeID | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| discussion_comment_write | unknown | discussionNumber | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| discussion_comment_write | unknown | method | enum | yes | enum: 6 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| discussion_comment_write | unknown | owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| discussion_comment_write | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| dismiss_notification | unknown | state | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| dismiss_notification | unknown | threadID | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| find_duplicate | unknown | confidence_threshold | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| find_duplicate | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| find_duplicate | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| find_duplicate | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| find_duplicate | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| find_duplicate | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| fork_repository | unknown | organization | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| fork_repository | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| fork_repository | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_code_quality_finding | unknown | findingNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_code_quality_finding | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_code_quality_finding | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_code_scanning_alert | unknown | alertNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_code_scanning_alert | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_code_scanning_alert | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_commit | unknown | detail | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_commit | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_commit | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_commit | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_commit | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_commit | unknown | sha | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_dependabot_alert | unknown | alertNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_dependabot_alert | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_dependabot_alert | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion | unknown | discussionNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion_comments | unknown | after | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion_comments | unknown | discussionNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion_comments | unknown | includeReplies | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion_comments | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion_comments | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_discussion_comments | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_blame | unknown | after | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_blame | unknown | end_line | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_blame | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_blame | unknown | path | string | yes | — | trusted_fixed | no | authority-bearing name |
| get_file_blame | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_blame | unknown | ref | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_blame | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_blame | unknown | start_line | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_contents | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_contents | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_contents | unknown | path | string | no | — | trusted_fixed | no | authority-bearing name |
| get_file_contents | unknown | ref | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_contents | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_file_contents | unknown | sha | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_gist | unknown | gist_id | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_global_security_advisory | unknown | ghsaId | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_job_logs | unknown | failed_only | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_job_logs | unknown | job_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_job_logs | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_job_logs | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_job_logs | unknown | return_content | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_job_logs | unknown | run_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_job_logs | unknown | tail_lines | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_label | unknown | name | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_label | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_label | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_latest_release | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_latest_release | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_me | unknown | — | — | — | — | — | — | no arguments |
| get_notification_details | unknown | notificationID | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_release_by_tag | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_release_by_tag | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_release_by_tag | unknown | tag | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_repository_tree | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_repository_tree | unknown | path_filter | string | no | — | trusted_fixed | no | authority-bearing name |
| get_repository_tree | unknown | recursive | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_repository_tree | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_repository_tree | unknown | tree_sha | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_secret_scanning_alert | unknown | alertNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_secret_scanning_alert | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_secret_scanning_alert | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_tag | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_tag | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_tag | unknown | tag | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_team_members | unknown | org | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_team_members | unknown | team_slug | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| get_teams | unknown | user | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_read | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_read | unknown | method | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_read | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_read | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_read | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_read | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | method | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | related_issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | related_owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | related_repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_dependency_write | unknown | type | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_read | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_read | unknown | method | enum | yes | enum: 5 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_read | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_read | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_read | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_read | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | assignees | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| issue_write | unknown | duplicate_of | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | issue_fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | issue_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | labels | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | method | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | milestone | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | parent_issue_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | parent_owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | parent_repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | state | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | state_reason | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | title | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| issue_write | unknown | type | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| label_write | unknown | color | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| label_write | unknown | description | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| label_write | unknown | method | enum | yes | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| label_write | unknown | name | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| label_write | unknown | new_name | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| label_write | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| label_write | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_branches | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_branches | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_branches | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_branches | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | ref | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | severity | enum | no | enum: 7 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | state | enum | no | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_code_scanning_alerts | unknown | tool_name | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | author | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | path | string | no | — | trusted_fixed | no | authority-bearing name |
| list_commits | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | sha | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | since | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_commits | unknown | until | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_dependabot_alerts | unknown | after | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_dependabot_alerts | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_dependabot_alerts | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_dependabot_alerts | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_dependabot_alerts | unknown | severity | enum | no | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_dependabot_alerts | unknown | state | enum | no | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussion_categories | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussion_categories | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussions | unknown | after | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussions | unknown | category | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussions | unknown | direction | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussions | unknown | orderBy | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussions | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussions | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_discussions | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_gists | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_gists | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_gists | unknown | since | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_gists | unknown | username | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | affects | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | cveId | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | cwes | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | ecosystem | enum | no | enum: 12 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | ghsaId | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | isWithdrawn | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | modified | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | published | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | severity | enum | no | enum: 5 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | type | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_global_security_advisories | unknown | updated | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issue_fields | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issue_fields | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issue_types | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issue_types | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | after | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | direction | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | field_filters | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | labels | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | orderBy | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | since | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_issues | unknown | state | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_label | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_label | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_notifications | unknown | before | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_notifications | unknown | filter | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_notifications | unknown | owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_notifications | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_notifications | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_notifications | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_notifications | unknown | since | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_org_repository_security_advisories | unknown | direction | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_org_repository_security_advisories | unknown | org | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_org_repository_security_advisories | unknown | sort | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_org_repository_security_advisories | unknown | state | enum | no | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | base | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | direction | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | head | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | sort | enum | no | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_pull_requests | unknown | state | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_releases | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_releases | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_releases | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_releases | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_releases | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_collaborators | unknown | affiliation | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_collaborators | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_collaborators | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_collaborators | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_collaborators | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_security_advisories | unknown | direction | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_security_advisories | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_security_advisories | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_security_advisories | unknown | sort | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_repository_security_advisories | unknown | state | enum | no | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_secret_scanning_alerts | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_secret_scanning_alerts | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_secret_scanning_alerts | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_secret_scanning_alerts | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_secret_scanning_alerts | unknown | resolution | enum | no | enum: 6 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_secret_scanning_alerts | unknown | secret_type | string | no | — | trusted_fixed | no | authority-bearing name |
| list_secret_scanning_alerts | unknown | state | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_starred_repositories | unknown | direction | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_starred_repositories | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_starred_repositories | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_starred_repositories | unknown | sort | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_starred_repositories | unknown | username | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_tags | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_tags | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_tags | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| list_tags | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| manage_notification_subscription | unknown | action | enum | yes | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| manage_notification_subscription | unknown | notificationID | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| manage_repository_notification_subscription | unknown | action | enum | yes | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| manage_repository_notification_subscription | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| manage_repository_notification_subscription | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| mark_all_notifications_read | unknown | lastReadAt | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| mark_all_notifications_read | unknown | owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| mark_all_notifications_read | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| merge_pull_request | unknown | commit_message | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| merge_pull_request | unknown | commit_title | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| merge_pull_request | unknown | expectedHeadSha | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| merge_pull_request | unknown | merge_method | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| merge_pull_request | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| merge_pull_request | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| merge_pull_request | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | field_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | field_names | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | item_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | method | enum | yes | enum: 5 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | owner_type | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | project_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | status_update_id | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_get | unknown | view_id | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | after | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | before | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | field_names | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | method | enum | yes | enum: 5 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | owner_type | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | per_page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | project_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_list | unknown | query | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| projects_write | unknown | field_name | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | filter | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | issue_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | item_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | item_owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | item_repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | item_type | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | items | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | iteration_duration | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | iterations | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | layout | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | method | enum | yes | enum: 10 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | name | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | owner_type | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | project_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | pull_request_number | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | start_date | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | status | enum | no | enum: 5 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | target_date | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | title | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | updated_field | object | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | view_id | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | visible_field_names | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| projects_write | unknown | visible_fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_read | unknown | after | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_read | unknown | method | enum | yes | enum: 9 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_read | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_read | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_read | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_read | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_read | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_review_write | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| pull_request_review_write | unknown | commitID | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_review_write | unknown | event | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_review_write | unknown | method | enum | yes | enum: 5 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_review_write | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_review_write | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_review_write | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| pull_request_review_write | unknown | threadId | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| push_files | unknown | branch | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| push_files | unknown | files | array | yes | — | trusted_fixed | no | authority-bearing name |
| push_files | unknown | message | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| push_files | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| push_files | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| remove_sub_issue | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| remove_sub_issue | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| remove_sub_issue | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| remove_sub_issue | unknown | sub_issue_id | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| reprioritize_sub_issue | unknown | after_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| reprioritize_sub_issue | unknown | before_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| reprioritize_sub_issue | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| reprioritize_sub_issue | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| reprioritize_sub_issue | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| reprioritize_sub_issue | unknown | sub_issue_id | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| request_copilot_review | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| request_copilot_review | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| request_copilot_review | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| request_pull_request_reviewers | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| request_pull_request_reviewers | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| request_pull_request_reviewers | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| request_pull_request_reviewers | unknown | reviewers | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| resolve_review_thread | unknown | threadID | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_code | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_code | unknown | order | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_code | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_code | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_code | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_code | unknown | sort | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_commits | unknown | order | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_commits | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_commits | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_commits | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_commits | unknown | sort | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | order | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_issues | unknown | sort | enum | no | enum: 11 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_orgs | unknown | order | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_orgs | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_orgs | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_orgs | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_orgs | unknown | sort | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | fields | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | order | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | owner | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_pull_requests | unknown | sort | enum | no | enum: 11 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_repositories | unknown | minimal_output | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_repositories | unknown | order | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_repositories | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_repositories | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_repositories | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_repositories | unknown | sort | enum | no | enum: 4 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_users | unknown | order | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_users | unknown | page | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_users | unknown | perPage | number | no | maximum: 100 | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_users | unknown | query | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| search_users | unknown | sort | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| set_issue_fields | unknown | fields | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| set_issue_fields | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| set_issue_fields | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| set_issue_fields | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| star_repository | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| star_repository | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | after_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | before_id | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | method | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | replace_parent | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| sub_issue_write | unknown | sub_issue_id | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| submit_pending_pull_request_review | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| submit_pending_pull_request_review | unknown | event | enum | yes | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| submit_pending_pull_request_review | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| submit_pending_pull_request_review | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| submit_pending_pull_request_review | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| ui_get | unknown | method | enum | yes | enum: 7 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| ui_get | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| ui_get | unknown | repo | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| unresolve_review_thread | unknown | threadID | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| unstar_repository | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| unstar_repository | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_gist | unknown | content | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| update_gist | unknown | description | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| update_gist | unknown | filename | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_gist | unknown | gist_id | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_assignees | unknown | assignees | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_assignees | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_assignees | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_assignees | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_body | unknown | body | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| update_issue_body | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_body | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_body | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_labels | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_labels | unknown | labels | array | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_labels | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_labels | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_milestone | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_milestone | unknown | milestone | integer | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_milestone | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_milestone | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | confidence | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | duplicate_of | number | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | is_suggestion | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | rationale | string | no | max length: 280 | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | state | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_state | unknown | state_reason | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_title | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_title | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_title | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_title | unknown | title | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_type | unknown | confidence | enum | no | enum: 3 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_type | unknown | is_suggestion | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_type | unknown | issue_number | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_type | unknown | issue_type | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_type | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_type | unknown | rationale | string | no | max length: 280 | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_issue_type | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | base | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | body | string | no | — | outbound_payload | no | outbound payload name or bounded free text |
| update_pull_request | unknown | draft | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | maintainer_can_modify | boolean | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | reviewers | array | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | state | enum | no | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request | unknown | title | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_body | unknown | body | string | yes | — | outbound_payload | no | outbound payload name or bounded free text |
| update_pull_request_body | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_body | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_body | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_branch | unknown | expectedHeadSha | string | no | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_branch | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_branch | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_branch | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_draft_state | unknown | draft | boolean | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_draft_state | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_draft_state | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_draft_state | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_state | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_state | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_state | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_state | unknown | state | enum | yes | enum: 2 fingerprinted member(s) | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_title | unknown | owner | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_title | unknown | pullNumber | number | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_title | unknown | repo | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |
| update_pull_request_title | unknown | title | string | yes | — | trusted_fixed | yes | ambiguous consequential argument; review required |

## Interpretation boundary

This report describes Verb Authority's declared controls and review heuristics.
A tool name is caller-mutable metadata and is never treated as proof of behavior.
Without an explicit risk declaration, the effective tier remains `unknown` and
requires review and runtime confirmation. This report is not a
vulnerability verdict, does not inspect tool implementations, and does not prove
that the surrounding application supplies correct provenance or authorization.
Remediation guidance is advisory and never rewrites a model-visible schema,
discovers a trusted value source, or changes runtime registration. A protected
argument whose authority is uncertain must be reviewed before choosing a fix.
References and composed/conditional schemas are not resolved; when present,
the report marks the tool for schema review instead of claiming complete coverage.
Review every flagged argument against the real tool semantics before deployment.
