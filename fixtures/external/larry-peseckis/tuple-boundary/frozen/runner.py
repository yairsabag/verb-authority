#!/usr/bin/env python3
"""
Boundary fixture runner for Verb Authority v0.10.0-beta.6.

The runner intentionally keeps the relational action-instance oracle OUTSIDE
the inputs passed to Verb Authority.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"


def load_json(name: str) -> Any:
    return json.loads((ROOT / name).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_scalar(name: str, schema: dict[str, Any], value: Any) -> list[str]:
    errors: list[str] = []
    typ = schema.get("type")
    if typ == "string" and not isinstance(value, str):
        errors.append(f"{name}: expected string")
    elif typ == "number" and not (isinstance(value, (int, float)) and not isinstance(value, bool)):
        errors.append(f"{name}: expected number")
    elif typ == "integer" and not (isinstance(value, int) and not isinstance(value, bool)):
        errors.append(f"{name}: expected integer")

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{name}: value {value!r} not in enum")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{name}: below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{name}: above maximum {schema['maximum']}")
    if isinstance(value, str) and "pattern" in schema:
        if re.fullmatch(schema["pattern"], value) is None:
            errors.append(f"{name}: does not match pattern")
    return errors


def validate_case(tool: dict[str, Any], payload: dict[str, Any]) -> list[str]:
    schema = tool["inputSchema"]
    props = schema.get("properties", {})
    required = set(schema.get("required", []))
    errors: list[str] = []

    for missing in sorted(required - payload.keys()):
        errors.append(f"missing required argument: {missing}")

    if schema.get("additionalProperties") is False:
        for extra in sorted(payload.keys() - props.keys()):
            errors.append(f"unexpected argument: {extra}")

    for name, value in payload.items():
        if name in props:
            errors.extend(validate_scalar(name, props[name], value))
    return errors


def external_oracle(policy: dict[str, Any], payload: dict[str, Any]) -> tuple[str, str | None]:
    for rule in policy["rules"]:
        if (
            payload.get("account") == rule["account"]
            and payload.get("recipient") == rule["recipient"]
            and payload.get("purpose") == rule["purpose"]
            and isinstance(payload.get("amount"), (int, float))
            and payload["amount"] <= rule["max_amount"]
        ):
            return "ALLOW", rule["id"]
    return "DENY", None


def recursively_find_keys(obj: Any, path: str = "$") -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            found.append((f"{path}.{key}", key))
            found.extend(recursively_find_keys(value, f"{path}.{key}"))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            found.extend(recursively_find_keys(value, f"{path}[{idx}]"))
    return found


def scanner_summary(report: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "report_version": report.get("report_version"),
        "generator": report.get("generator"),
        "tool_found": False,
        "effective_risk": None,
        "risk_source": None,
        "needs_confirmation": None,
        "inferred_argument_policy": {},
        "declared_argument_authority": {},
        "tuple_authorization_like_keys": [],
    }

    for tool in report.get("tools", []):
        if tool.get("name") == "submit_payment":
            summary["tool_found"] = True
            summary["effective_risk"] = tool.get("risk")
            summary["risk_source"] = tool.get("risk_source")
            summary["needs_confirmation"] = tool.get("needs_confirmation")
            for arg in tool.get("arguments", []):
                if isinstance(arg, dict) and isinstance(arg.get("name"), str):
                    summary["inferred_argument_policy"][arg["name"]] = arg.get("policy")

    declared = report.get("declared_controls", {})
    for tool in declared.get("tools", []) if isinstance(declared, dict) else []:
        if tool.get("name") == "submit_payment":
            for arg in tool.get("arguments", []):
                if isinstance(arg, dict) and isinstance(arg.get("name"), str):
                    summary["declared_argument_authority"][arg["name"]] = {
                        "authority": arg.get("authority"),
                        "evidence": arg.get("evidence"),
                    }

    suspicious_tokens = (
        "action_authorization",
        "action_authorized",
        "tuple_authorization",
        "tuple_authorized",
        "cross_argument_authorization",
        "cross_argument_authorized",
        "action_instance_authorization",
        "action_instance_authorized",
    )
    for path, key in recursively_find_keys(report):
        normalized = key.lower().replace("-", "_")
        if normalized in suspicious_tokens:
            summary["tuple_authorization_like_keys"].append(path)

    return summary


def write_assessment(result: dict[str, Any]) -> None:
    cases = result["cases"]
    scan = result.get("scanner")
    lines = [
        "# Boundary assessment",
        "",
        "## Fixture/oracle result",
        "",
        "| Case | Local schema | External oracle | Expected | Match |",
        "|---|---|---|---|---|",
    ]
    for item in cases:
        lines.append(
            f"| {item['id']} | "
            f"{'PASS' if item['schema_valid'] else 'FAIL'} | "
            f"{item['oracle_result']} | "
            f"{item['expected']} | "
            f"{'YES' if item['oracle_matches_expected'] else 'NO'} |"
        )

    lines += [
        "",
        "All cases are intentionally composed only from individually admissible values.",
        "",
    ]

    if scan is None:
        lines += [
            "## Verb Authority scan",
            "",
            "Not run (`--validate-only`).",
            "",
        ]
    else:
        lines += [
            "## Verb Authority scan",
            "",
            f"- Scanner exit code: `{scan['exit_code']}`",
            f"- Tool found: `{scan.get('summary', {}).get('tool_found')}`",
            f"- Effective risk: `{scan.get('summary', {}).get('effective_risk')}`",
            f"- Risk source: `{scan.get('summary', {}).get('risk_source')}`",
            f"- Confirmation required: `{scan.get('summary', {}).get('needs_confirmation')}`",
            f"- Tuple/action-instance authorization-like keys observed: "
            f"`{scan.get('summary', {}).get('tuple_authorization_like_keys')}`",
            "",
            "Declared per-argument authority:",
            "",
        ]
        for name, detail in scan.get("summary", {}).get("declared_argument_authority", {}).items():
            lines.append(
                f"- `{name}`: authority=`{detail.get('authority')}`, "
                f"evidence=`{detail.get('evidence')}`"
            )

    lines += [
        "",
        "## Interpretation",
        "",
        "The static Verb Authority scan and the external tuple oracle answer different questions.",
        "A denied tuple satisfying the per-argument surface is expected under the stated boundary.",
        "",
        "The review question is:",
        "",
        "> Does the generated Verb Authority evidence stop exactly at per-argument authority, "
        "without implying that the concrete tuple/action instance is authorized?",
        "",
        "See `EXPECTED.md` for the pre-registered PASS/FAIL conditions.",
    ]

    (RESULTS / "BOUNDARY-ASSESSMENT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate fixture + external oracle without invoking Verb Authority.",
    )
    args = parser.parse_args()

    RESULTS.mkdir(exist_ok=True)

    tools_doc = load_json("tools.json")
    controls = load_json("controls.json")
    policy = load_json("policy.json")
    cases_doc = load_json("cases.json")
    tool = tools_doc["tools"][0]

    result: dict[str, Any] = {
        "fixture_version": 1,
        "verb_authority_target": "v0.10.0-beta.6",
        "question": (
            "Does the evidence stop at per-argument authority rather than imply "
            "cross-argument/action-instance authorization?"
        ),
        "cases": [],
        "scanner": None,
    }

    fixture_failure = False
    for case in cases_doc["cases"]:
        errors = validate_case(tool, case["input"])
        oracle_result, matched_rule = external_oracle(policy, case["input"])
        matches = (
            oracle_result == case["expected_action_instance_authorization"]
            and matched_rule == case.get("expected_rule")
        )
        result["cases"].append(
            {
                "id": case["id"],
                "label": case["label"],
                "schema_valid": not errors,
                "schema_errors": errors,
                "oracle_result": oracle_result,
                "oracle_rule": matched_rule,
                "expected": case["expected_action_instance_authorization"],
                "expected_rule": case.get("expected_rule"),
                "oracle_matches_expected": matches,
            }
        )
        if errors or not matches:
            fixture_failure = True

    if not args.validate_only:
        report_path = RESULTS / "authority-report.json"
        cmd = [
            sys.executable,
            "-m",
            "verb_authority",
            "scan",
            str(ROOT / "tools.json"),
            "--controls",
            str(ROOT / "controls.json"),
            "--format",
            "json",
            "--output",
            str(report_path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        scan_result: dict[str, Any] = {
            "command": cmd,
            "exit_code": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
        if proc.returncode == 0 and report_path.exists():
            report = json.loads(report_path.read_text(encoding="utf-8"))
            scan_result["summary"] = scanner_summary(report)
        else:
            scan_result["summary"] = {}
            fixture_failure = True
        result["scanner"] = scan_result

    # Checksums bind the exact inputs used for the run.
    checksum_names = [
        "tools.json",
        "controls.json",
        "policy.json",
        "cases.json",
        "EXPECTED.md",
        "runner.py",
    ]
    checksum_lines = []
    for name in checksum_names:
        path = ROOT / name
        checksum_lines.append(f"{sha256(path)}  {name}")
    (RESULTS / "checksums.sha256").write_text(
        "\n".join(checksum_lines) + "\n", encoding="utf-8"
    )

    result["fixture_validation"] = "PASS" if not fixture_failure else "FAIL"
    (RESULTS / "boundary-results.json").write_text(
        json.dumps(result, indent=2) + "\n", encoding="utf-8"
    )
    write_assessment(result)

    print("External action-instance oracle:")
    for item in result["cases"]:
        print(
            f"  {item['id']}: {item['oracle_result']:<5} "
            f"(schema={'PASS' if item['schema_valid'] else 'FAIL'})"
        )

    if args.validate_only:
        print("\nVerb Authority scan skipped (--validate-only).")
    else:
        scan = result["scanner"]
        print(f"\nVerb Authority scanner exit code: {scan['exit_code']}")
        if scan["exit_code"] == 0:
            print(f"Report: {RESULTS / 'authority-report.json'}")
        else:
            print(scan["stderr"].strip() or scan["stdout"].strip())

    print(f"Assessment: {RESULTS / 'BOUNDARY-ASSESSMENT.md'}")
    return 1 if fixture_failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
