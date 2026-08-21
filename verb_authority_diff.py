"""Compare two Verb Authority scans and surface authority drift.

Inputs may be existing JSON reports or raw MCP/OpenAI/Anthropic schema exports.
Raw schemas are scanned locally before comparison; no server is started and no
networking code is used.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from verb_authority_scan import REPORT_VERSION, SchemaError, scan_documents


DIFF_VERSION = 1

_CLASSIFICATION_ORDER = {
    "authority_increase": 0,
    "review": 1,
    "protection_increase": 2,
}
_POLICY_RANK = {
    "trusted_fixed": 0,
    "typed_bounded": 1,
    "outbound_payload": 2,
}
_DECLARED_AUTHORITY_RANK = {
    "locked": 0,
    "constrained": 1,
    "free": 2,
}
_RISK_RANK = {
    "read_only": 0,
    "write": 1,
    "financial": 2,
    "destructive": 2,
    "code_exec": 2,
}


class DiffError(ValueError):
    """Raised when reports cannot be correlated safely."""


def _load_json(path: str) -> Any:
    with Path(path).open(encoding="utf-8") as source:
        return json.load(source)


def _is_report(document: Any) -> bool:
    return (
        isinstance(document, dict)
        and document.get("generator") == "verb-authority"
        and "report_version" in document
        and "tools" in document
    )


def _validate_report(report: Any, *, label: str) -> dict[str, Any]:
    if not _is_report(report):
        raise DiffError(f"{label} is not a Verb Authority JSON report")
    if report.get("report_version") != REPORT_VERSION:
        raise DiffError(
            f"{label} uses unsupported report version "
            f"{report.get('report_version')!r}; expected {REPORT_VERSION}"
        )
    privacy = report.get("privacy")
    if not isinstance(privacy, dict):
        raise DiffError(f"{label} is missing report privacy metadata")
    if privacy.get("names_redacted") is True:
        raise DiffError(
            f"{label} has redacted names; diff requires stable tool and argument "
            "names. Compare non-redacted local reports instead."
        )
    if not isinstance(report.get("tools"), list):
        raise DiffError(f"{label} has an invalid tools list")
    return report


def load_report_or_schema(
    path: str,
    *,
    controls_path: str | None = None,
    label: str = "input",
) -> dict[str, Any]:
    """Load a report, or scan a raw schema export before diffing it."""

    document = _load_json(path)
    if _is_report(document):
        if controls_path is not None:
            raise DiffError(
                f"{label} is already a report; do not also pass a controls file"
            )
        return _validate_report(document, label=label)

    controls = _load_json(controls_path) if controls_path is not None else None
    report = scan_documents([document], control_declarations=controls)
    return _validate_report(report, label=label)


def _index_report(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for raw_tool in report["tools"]:
        name = raw_tool.get("name")
        if not isinstance(name, str) or not name:
            raise DiffError("report contains a tool without a stable name")
        if name in indexed:
            raise DiffError(f"report contains duplicate tool name: {name}")
        arguments: dict[str, dict[str, Any]] = {}
        for raw_argument in raw_tool.get("arguments", []):
            argument_name = raw_argument.get("name")
            if not isinstance(argument_name, str) or not argument_name:
                raise DiffError(f"tool '{name}' contains an unnamed argument")
            arguments[argument_name] = {
                "schema_exposure": "exposed",
                "inferred_policy": raw_argument.get("policy"),
                "review_required": raw_argument.get("review_required"),
                "type": raw_argument.get("type"),
                "required": raw_argument.get("required"),
            }
        indexed[name] = {
            "risk": raw_tool.get("risk"),
            "needs_confirmation": raw_tool.get("needs_confirmation"),
            "annotation_conflicts": raw_tool.get("annotation_conflicts", []),
            "schema_closes_unknown_arguments": raw_tool.get(
                "schema_closes_unknown_arguments"
            ),
            "arguments": arguments,
        }

    declared = report.get("declared_controls")
    if declared is None:
        return indexed
    for raw_tool in declared.get("tools", []):
        name = raw_tool.get("name")
        if name not in indexed:
            raise DiffError(f"declared controls reference unknown report tool: {name}")
        indexed_tool = indexed[name]
        indexed_tool["schema_closes_unknown_arguments"] = raw_tool.get(
            "schema_closes_unknown_arguments"
        )
        for raw_argument in raw_tool.get("arguments", []):
            argument_name = raw_argument.get("name")
            if argument_name not in indexed_tool["arguments"]:
                raise DiffError(
                    f"declared controls reference unknown argument: "
                    f"{name}.{argument_name}"
                )
            indexed_argument = indexed_tool["arguments"][argument_name]
            indexed_argument.update(
                {
                    "declared_authority": raw_argument.get("authority"),
                    "evidence": raw_argument.get("evidence"),
                    "bounds": raw_argument.get("bounds", []),
                }
            )
        for raw_argument in raw_tool.get("unexposed_arguments", []):
            argument_name = raw_argument.get("name")
            if not isinstance(argument_name, str) or not argument_name:
                raise DiffError(f"tool '{name}' contains an unnamed control")
            if argument_name in indexed_tool["arguments"]:
                raise DiffError(
                    f"argument is both exposed and unexposed: "
                    f"{name}.{argument_name}"
                )
            indexed_tool["arguments"][argument_name] = {
                "schema_exposure": "unexposed",
                "exposure": raw_argument.get("exposure"),
                "evidence": raw_argument.get("evidence"),
                "enforced_by": raw_argument.get("enforced_by"),
            }
    return indexed


def _change(
    classification: str,
    kind: str,
    tool: str,
    *,
    message: str,
    argument: str | None = None,
    field: str | None = None,
    before: Any = None,
    after: Any = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "classification": classification,
        "kind": kind,
        "tool": tool,
        "message": message,
    }
    if argument is not None:
        item["argument"] = argument
    if field is not None:
        item["field"] = field
        item["before"] = before
        item["after"] = after
    return item


def _ranked_change(
    changes: list[dict[str, Any]],
    *,
    kind: str,
    tool: str,
    argument: str | None,
    field: str,
    before: str,
    after: str,
    ranks: dict[str, int],
    increase_message: str,
    reduction_message: str,
    review_message: str,
) -> None:
    before_rank = ranks.get(before)
    after_rank = ranks.get(after)
    if before_rank is not None and after_rank is not None and after_rank > before_rank:
        classification = "authority_increase"
        message = increase_message
    elif before_rank is not None and after_rank is not None and after_rank < before_rank:
        classification = "protection_increase"
        message = reduction_message
    else:
        classification = "review"
        message = review_message
    changes.append(
        _change(
            classification,
            kind,
            tool,
            argument=argument,
            field=field,
            before=before,
            after=after,
            message=message,
        )
    )


def _bounds_classification(
    before: list[dict[str, Any]], after: list[dict[str, Any]]
) -> str:
    before_mutability = [bound.get("bounds_mutability") for bound in before]
    after_mutability = [bound.get("bounds_mutability") for bound in after]
    if (
        after_mutability.count("caller") > before_mutability.count("caller")
        or after_mutability.count("immutable")
        < before_mutability.count("immutable")
    ):
        return "authority_increase"
    if (
        after_mutability.count("caller") < before_mutability.count("caller")
        or after_mutability.count("immutable")
        > before_mutability.count("immutable")
    ):
        return "protection_increase"
    return "review"


def _compare_exposed_argument(
    changes: list[dict[str, Any]],
    tool: str,
    argument: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    before_policy = before.get("inferred_policy")
    after_policy = after.get("inferred_policy")
    if before_policy != after_policy:
        _ranked_change(
            changes,
            kind="inferred_policy_changed",
            tool=tool,
            argument=argument,
            field="inferred_policy",
            before=before_policy,
            after=after_policy,
            ranks=_POLICY_RANK,
            increase_message="Inferred caller authority increased.",
            reduction_message="Inferred caller authority decreased.",
            review_message="Inferred policy changed and needs review.",
        )

    before_declared = before.get("declared_authority")
    after_declared = after.get("declared_authority")
    if before_declared is None and after_declared is not None:
        changes.append(
            _change(
                "review",
                "declared_control_added",
                tool,
                argument=argument,
                field="declared_authority",
                before=None,
                after=after_declared,
                message="Author-supplied control evidence was added.",
            )
        )
    elif before_declared is not None and after_declared is None:
        changes.append(
            _change(
                "review",
                "declared_control_removed",
                tool,
                argument=argument,
                field="declared_authority",
                before=before_declared,
                after=None,
                message="Author-supplied control evidence was removed.",
            )
        )
    elif before_declared != after_declared:
        _ranked_change(
            changes,
            kind="declared_authority_changed",
            tool=tool,
            argument=argument,
            field="declared_authority",
            before=before_declared,
            after=after_declared,
            ranks=_DECLARED_AUTHORITY_RANK,
            increase_message="Declared caller authority increased.",
            reduction_message="Declared caller authority decreased.",
            review_message="Declared authority changed and needs review.",
        )

    if before.get("evidence") != after.get("evidence") and (
        before.get("evidence") is not None or after.get("evidence") is not None
    ):
        changes.append(
            _change(
                "review",
                "evidence_changed",
                tool,
                argument=argument,
                field="evidence",
                before=before.get("evidence"),
                after=after.get("evidence"),
                message="Control evidence status changed.",
            )
        )

    before_bounds = before.get("bounds", [])
    after_bounds = after.get("bounds", [])
    if before_bounds != after_bounds:
        classification = _bounds_classification(before_bounds, after_bounds)
        messages = {
            "authority_increase": "The declared bound chain became more caller-controlled.",
            "protection_increase": "The declared bound chain gained a stronger control.",
            "review": "The declared bound chain changed and needs review.",
        }
        changes.append(
            _change(
                classification,
                "bounds_changed",
                tool,
                argument=argument,
                field="bounds",
                before=before_bounds,
                after=after_bounds,
                message=messages[classification],
            )
        )

    for field in ("type", "required", "review_required"):
        if before.get(field) != after.get(field):
            changes.append(
                _change(
                    "review",
                    f"{field}_changed",
                    tool,
                    argument=argument,
                    field=field,
                    before=before.get(field),
                    after=after.get(field),
                    message=f"Argument {field.replace('_', ' ')} changed.",
                )
            )


def _compare_unexposed_argument(
    changes: list[dict[str, Any]],
    tool: str,
    argument: str,
    before: dict[str, Any],
    after: dict[str, Any],
) -> None:
    for field in ("exposure", "evidence", "enforced_by"):
        if before.get(field) != after.get(field):
            changes.append(
                _change(
                    "review",
                    f"unexposed_{field}_changed",
                    tool,
                    argument=argument,
                    field=field,
                    before=before.get(field),
                    after=after.get(field),
                    message=f"Unexposed control {field.replace('_', ' ')} changed.",
                )
            )


def diff_reports(
    before_report: dict[str, Any], after_report: dict[str, Any]
) -> dict[str, Any]:
    """Return a deterministic, machine-readable authority diff."""

    before_report = _validate_report(before_report, label="before report")
    after_report = _validate_report(after_report, label="after report")
    before_tools = _index_report(before_report)
    after_tools = _index_report(after_report)
    changes: list[dict[str, Any]] = []

    for tool in sorted(set(before_tools) | set(after_tools)):
        before_tool = before_tools.get(tool)
        after_tool = after_tools.get(tool)
        if before_tool is None:
            changes.append(
                _change(
                    "authority_increase",
                    "tool_added",
                    tool,
                    message="A new caller-visible tool was added.",
                )
            )
            continue
        if after_tool is None:
            changes.append(
                _change(
                    "protection_increase",
                    "tool_removed",
                    tool,
                    message="A caller-visible tool was removed.",
                )
            )
            continue

        if before_tool["risk"] != after_tool["risk"]:
            _ranked_change(
                changes,
                kind="tool_risk_changed",
                tool=tool,
                argument=None,
                field="risk",
                before=before_tool["risk"],
                after=after_tool["risk"],
                ranks=_RISK_RANK,
                increase_message="Tool risk increased.",
                reduction_message="Tool risk decreased.",
                review_message="Tool risk class changed and needs review.",
            )

        before_confirmation = before_tool["needs_confirmation"]
        after_confirmation = after_tool["needs_confirmation"]
        if before_confirmation != after_confirmation:
            if before_confirmation is True and after_confirmation is False:
                classification = "authority_increase"
                message = "Required human confirmation was removed."
            elif before_confirmation is False and after_confirmation is True:
                classification = "protection_increase"
                message = "Required human confirmation was added."
            else:
                classification = "review"
                message = "Human-confirmation behavior changed."
            changes.append(
                _change(
                    classification,
                    "confirmation_changed",
                    tool,
                    field="needs_confirmation",
                    before=before_confirmation,
                    after=after_confirmation,
                    message=message,
                )
            )

        before_closed = before_tool["schema_closes_unknown_arguments"]
        after_closed = after_tool["schema_closes_unknown_arguments"]
        if before_closed != after_closed and (
            before_closed is not None and after_closed is not None
        ):
            if before_closed is True and after_closed is False:
                classification = "authority_increase"
                message = "The schema no longer rejects unknown arguments."
            else:
                classification = "protection_increase"
                message = "The schema now rejects unknown arguments."
            changes.append(
                _change(
                    classification,
                    "unknown_arguments_changed",
                    tool,
                    field="schema_closes_unknown_arguments",
                    before=before_closed,
                    after=after_closed,
                    message=message,
                )
            )

        before_conflicts = before_tool["annotation_conflicts"]
        after_conflicts = after_tool["annotation_conflicts"]
        if before_conflicts != after_conflicts:
            changes.append(
                _change(
                    "review",
                    "annotation_conflicts_changed",
                    tool,
                    field="annotation_conflicts",
                    before=before_conflicts,
                    after=after_conflicts,
                    message="MCP annotation conflicts changed.",
                )
            )

        before_arguments = before_tool["arguments"]
        after_arguments = after_tool["arguments"]
        for argument in sorted(set(before_arguments) | set(after_arguments)):
            before_argument = before_arguments.get(argument)
            after_argument = after_arguments.get(argument)
            if before_argument is None:
                if after_argument["schema_exposure"] == "exposed":
                    changes.append(
                        _change(
                            "authority_increase",
                            "argument_added",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before=None,
                            after="exposed",
                            message="A new caller-visible argument was added.",
                        )
                    )
                else:
                    changes.append(
                        _change(
                            "review",
                            "unexposed_control_added",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before=None,
                            after="unexposed",
                            message="An author-supplied unexposed control was added.",
                        )
                    )
                continue
            if after_argument is None:
                if before_argument["schema_exposure"] == "exposed":
                    changes.append(
                        _change(
                            "protection_increase",
                            "argument_removed",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before="exposed",
                            after=None,
                            message="A caller-visible argument was removed.",
                        )
                    )
                else:
                    changes.append(
                        _change(
                            "review",
                            "unexposed_control_removed",
                            tool,
                            argument=argument,
                            field="schema_exposure",
                            before="unexposed",
                            after=None,
                            message="An author-supplied unexposed control was removed.",
                        )
                    )
                continue

            before_exposure = before_argument["schema_exposure"]
            after_exposure = after_argument["schema_exposure"]
            if before_exposure != after_exposure:
                if before_exposure == "unexposed" and after_exposure == "exposed":
                    classification = "authority_increase"
                    message = "A previously unexposed argument became caller-visible."
                else:
                    classification = "protection_increase"
                    message = "A caller-visible argument became unexposed."
                changes.append(
                    _change(
                        classification,
                        "argument_exposure_changed",
                        tool,
                        argument=argument,
                        field="schema_exposure",
                        before=before_exposure,
                        after=after_exposure,
                        message=message,
                    )
                )
                continue

            if before_exposure == "exposed":
                _compare_exposed_argument(
                    changes, tool, argument, before_argument, after_argument
                )
            else:
                _compare_unexposed_argument(
                    changes, tool, argument, before_argument, after_argument
                )

    changes.sort(
        key=lambda item: (
            _CLASSIFICATION_ORDER[item["classification"]],
            item["tool"],
            item.get("argument", ""),
            item["kind"],
        )
    )
    counts = {
        classification: sum(
            change["classification"] == classification for change in changes
        )
        for classification in _CLASSIFICATION_ORDER
    }
    changed_tools = len({change["tool"] for change in changes})
    return {
        "diff_version": DIFF_VERSION,
        "generator": "verb-authority",
        "before": {
            "schema_fingerprint_sha256": before_report.get(
                "schema_fingerprint_sha256"
            ),
            "control_declaration_fingerprint_sha256": before_report.get(
                "control_declaration_fingerprint_sha256"
            ),
        },
        "after": {
            "schema_fingerprint_sha256": after_report.get(
                "schema_fingerprint_sha256"
            ),
            "control_declaration_fingerprint_sha256": after_report.get(
                "control_declaration_fingerprint_sha256"
            ),
        },
        "summary": {
            "changes": len(changes),
            "changed_tools": changed_tools,
            "authority_increases": counts["authority_increase"],
            "reviews": counts["review"],
            "protection_increases": counts["protection_increase"],
        },
        "changes": changes,
    }


def _short(value: Any) -> str:
    if value is None:
        return "none"
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list)):
        rendered = json.dumps(value, sort_keys=True, separators=(",", ":"))
        return rendered if len(rendered) <= 180 else rendered[:177] + "..."
    return str(value)


def render_text(diff: dict[str, Any]) -> str:
    """Render a compact diff intended for terminals and pull-request logs."""

    summary = diff["summary"]
    lines = [
        "Verb Authority diff",
        "",
        f"Changes: {summary['changes']} across {summary['changed_tools']} tool(s)",
        f"Authority increases: {summary['authority_increases']}",
        f"Needs review: {summary['reviews']}",
        f"Protection increases: {summary['protection_increases']}",
    ]
    if not diff["changes"]:
        lines.extend(["", "No authority-relevant changes detected."])
        return "\n".join(lines) + "\n"

    labels = {
        "authority_increase": "AUTHORITY INCREASE",
        "review": "REVIEW",
        "protection_increase": "PROTECTION INCREASE",
    }
    for change in diff["changes"]:
        subject = change["tool"]
        if change.get("argument"):
            subject += "." + change["argument"]
        lines.extend(
            [
                "",
                f"[{labels[change['classification']]}] {subject}",
                f"  {change['message']}",
            ]
        )
        if "field" in change:
            lines.append(
                f"  {change['field']}: {_short(change['before'])} -> "
                f"{_short(change['after'])}"
            )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two tool-schema exports or Verb Authority JSON reports "
            "and surface authority drift."
        )
    )
    parser.add_argument("before", help="baseline schema export or JSON report")
    parser.add_argument("after", help="candidate schema export or JSON report")
    parser.add_argument(
        "--before-controls", help="control declarations for a raw baseline schema"
    )
    parser.add_argument(
        "--after-controls", help="control declarations for a raw candidate schema"
    )
    parser.add_argument(
        "--format", choices=("text", "json"), default="text", help="diff format"
    )
    parser.add_argument("--output", help="write the diff to this file instead of stdout")
    parser.add_argument(
        "--fail-on-increase",
        action="store_true",
        help="exit with status 2 when caller authority increases",
    )
    args = parser.parse_args(argv)

    try:
        before = load_report_or_schema(
            args.before,
            controls_path=args.before_controls,
            label="before input",
        )
        after = load_report_or_schema(
            args.after,
            controls_path=args.after_controls,
            label="after input",
        )
        diff = diff_reports(before, after)
    except (OSError, json.JSONDecodeError, SchemaError, DiffError) as exc:
        parser.error(str(exc))

    if args.format == "json":
        rendered = json.dumps(diff, indent=2, sort_keys=True) + "\n"
    else:
        rendered = render_text(diff)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    if args.fail_on_increase and diff["summary"]["authority_increases"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
