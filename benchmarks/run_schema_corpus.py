"""Run the offline schema and mixed-trust decision corpus.

The corpus records desired policy semantics separately from current behavior.
That makes conservative false blocks and dangerous false allows visible rather
than turning the benchmark into a collection of cases the implementation
already passes.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from verb_authority import Param, Registry, Tool, build_policy, dispatch


CORPUS_PATH = Path(__file__).with_name("schema_corpus.json")


@dataclass
class CorpusResult:
    schemas: int
    categories: int
    parameters: int
    policy_matches: int
    policy_false_allows: list[dict[str, str]]
    policy_false_blocks: list[dict[str, str]]
    other_policy_mismatches: list[dict[str, str]]
    calls: int
    call_matches: int
    call_false_allows: list[dict[str, str]]
    call_false_blocks: list[dict[str, str]]
    other_call_mismatches: list[dict[str, str]]
    review_queue: list[str]

    @property
    def policy_mismatches(self) -> int:
        return (
            len(self.policy_false_allows)
            + len(self.policy_false_blocks)
            + len(self.other_policy_mismatches)
        )

    @property
    def call_mismatches(self) -> int:
        return (
            len(self.call_false_allows)
            + len(self.call_false_blocks)
            + len(self.other_call_mismatches)
        )


def _load_corpus(path: Path = CORPUS_PATH) -> dict[str, Any]:
    with path.open(encoding="utf-8") as corpus_file:
        corpus = json.load(corpus_file)
    if corpus.get("version") != 1 or not isinstance(corpus.get("cases"), list):
        raise ValueError("unsupported or malformed schema corpus")
    return corpus


def _param(raw: dict[str, Any]) -> Param:
    allowed = {"name", "type", "enum", "max_len", "cap", "sink"}
    unknown = set(raw) - allowed
    if unknown:
        raise ValueError(f"unknown Param fields: {sorted(unknown)}")
    return Param(**raw)


def _decision_label(decision) -> str:
    if not decision.allow:
        return "block"
    if decision.needs_confirm:
        return "confirm"
    return "allow"


def run_corpus(path: Path = CORPUS_PATH) -> CorpusResult:
    corpus = _load_corpus(path)
    categories: set[str] = set()
    parameters = policy_matches = calls = call_matches = 0
    policy_false_allows: list[dict[str, str]] = []
    policy_false_blocks: list[dict[str, str]] = []
    other_policy_mismatches: list[dict[str, str]] = []
    call_false_allows: list[dict[str, str]] = []
    call_false_blocks: list[dict[str, str]] = []
    other_call_mismatches: list[dict[str, str]] = []
    review_queue: list[str] = []

    for case in corpus["cases"]:
        case_id = case["id"]
        categories.add(case["category"])
        raw_tool = case["tool"]
        tool = Tool(raw_tool["name"], [_param(raw) for raw in raw_tool["params"]])
        registry = Registry()
        registry.add(tool)
        policy_set = build_policy(registry)

        expected_risk = case["expected"]["risk"]
        actual_risk = policy_set.risk[tool.name].value
        if actual_risk != expected_risk:
            other_policy_mismatches.append(
                {
                    "case": case_id,
                    "parameter": "<tool risk>",
                    "expected": expected_risk,
                    "actual": actual_risk,
                }
            )

        for param_name, expected_policy in case["expected"]["policy"].items():
            parameters += 1
            actual_policy = policy_set.policy[tool.name][param_name].value
            if actual_policy == expected_policy:
                policy_matches += 1
                continue
            mismatch = {
                "case": case_id,
                "parameter": param_name,
                "expected": expected_policy,
                "actual": actual_policy,
            }
            if expected_policy == "trusted_fixed" and actual_policy != "trusted_fixed":
                policy_false_allows.append(mismatch)
            elif expected_policy != "trusted_fixed" and actual_policy == "trusted_fixed":
                policy_false_blocks.append(mismatch)
            else:
                other_policy_mismatches.append(mismatch)

        review_queue.extend(
            f"{tool_name}.{param_name}"
            for tool_name, param_name in policy_set.review
        )

        for call in case.get("calls", []):
            calls += 1
            decision = dispatch(
                registry,
                policy_set,
                {"name": tool.name, "input": call["input"]},
                trusted_args=call.get("trusted_args", {}),
            )
            actual = _decision_label(decision)
            expected = call["expected"]
            if actual == expected:
                call_matches += 1
                continue
            mismatch = {
                "case": case_id,
                "call": call["id"],
                "expected": expected,
                "actual": actual,
                "reason": decision.reason,
            }
            if expected == "block" and actual != "block":
                call_false_allows.append(mismatch)
            elif expected != "block" and actual == "block":
                call_false_blocks.append(mismatch)
            else:
                other_call_mismatches.append(mismatch)

    return CorpusResult(
        schemas=len(corpus["cases"]),
        categories=len(categories),
        parameters=parameters,
        policy_matches=policy_matches,
        policy_false_allows=policy_false_allows,
        policy_false_blocks=policy_false_blocks,
        other_policy_mismatches=other_policy_mismatches,
        calls=calls,
        call_matches=call_matches,
        call_false_allows=call_false_allows,
        call_false_blocks=call_false_blocks,
        other_call_mismatches=other_call_mismatches,
        review_queue=sorted(review_queue),
    )


def _print_human(result: CorpusResult) -> None:
    print("Verb Authority offline schema corpus")
    print(f"schemas:             {result.schemas} across {result.categories} categories")
    print(f"policy matches:      {result.policy_matches}/{result.parameters}")
    print(f"policy false allows: {len(result.policy_false_allows)}")
    print(f"policy false blocks: {len(result.policy_false_blocks)}")
    print(f"call matches:        {result.call_matches}/{result.calls}")
    print(f"call false allows:   {len(result.call_false_allows)}")
    print(f"call false blocks:   {len(result.call_false_blocks)}")
    print(f"review queue:        {len(result.review_queue)}")

    mismatches = [
        ("policy false allow", item) for item in result.policy_false_allows
    ] + [
        ("policy false block", item) for item in result.policy_false_blocks
    ] + [
        ("call false allow", item) for item in result.call_false_allows
    ] + [
        ("call false block", item) for item in result.call_false_blocks
    ] + [
        ("other policy mismatch", item) for item in result.other_policy_mismatches
    ] + [
        ("other call mismatch", item) for item in result.other_call_mismatches
    ]
    if mismatches:
        print("\nObserved gaps (kept visible by design):")
        for label, item in mismatches:
            subject = item.get("parameter") or item.get("call")
            print(
                f"- {label}: {item['case']}.{subject} "
                f"expected={item['expected']} actual={item['actual']}"
            )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="print machine-readable results")
    args = parser.parse_args()
    result = run_corpus()
    if args.json:
        print(json.dumps(asdict(result), indent=2, sort_keys=True))
    else:
        _print_human(result)


if __name__ == "__main__":
    main()
