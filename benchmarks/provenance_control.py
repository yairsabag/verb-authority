"""Offline control: identical call content, different authority evidence.

This experiment does not emulate or score another security product. It
isolates the information that a content-only check cannot observe: the tool
call JSON is byte-for-byte identical in both arms, while only one arm carries
an independent application binding for the protected argument.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
from typing import Any

from verb_authority import GuardedToolRunner, Param, Registry, Risk, Tool


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def run_experiment() -> dict[str, Any]:
    invocations: list[dict[str, str]] = []

    def local_send_email(to: str, body: str) -> dict[str, str]:
        invocations.append({"to": to, "body": body})
        return {"status": "recorded-locally"}

    registry = Registry()
    registry.add(
        Tool(
            "send_email",
            [Param("to", "email"), Param("body", "string")],
            fn=local_send_email,
            risk=Risk.WRITE,
        )
    )
    runner = GuardedToolRunner(registry)

    # The value is deliberately ordinary. A domain denylist, PII detector, or
    # malicious-string classifier has no reason to reject it.
    tool_call = {
        "name": "send_email",
        "input": {
            "to": "alice@company.com",
            "body": "Weekly project status",
        },
    }
    first_call = copy.deepcopy(tool_call)
    second_call = copy.deepcopy(tool_call)

    without_binding = runner.run(first_call)
    invocations_after_unbound = len(invocations)
    with_binding = runner.run(
        second_call,
        trusted_args={"to": "alice@company.com"},
    )
    invocations_after_bound = len(invocations)

    if first_call != second_call:
        raise RuntimeError("control arms changed the tool-call content")
    if without_binding.decision.allow or without_binding.invoked:
        raise RuntimeError("unbound protected argument reached execution")
    if invocations_after_unbound != 0:
        raise RuntimeError("unbound arm invoked the local tool")
    if not with_binding.decision.allow or not with_binding.executed:
        raise RuntimeError("independently bound control arm did not execute")
    if invocations_after_bound != 1:
        raise RuntimeError("bound control arm did not invoke exactly once")

    return {
        "experiment": "identical-content-different-authority",
        "network_used": False,
        "model_used": False,
        "external_effect_used": False,
        "tool_call_sha256": _canonical_sha256(tool_call),
        "tool_calls_identical": first_call == second_call,
        "without_application_binding": {
            "allow": without_binding.decision.allow,
            "invoked": without_binding.invoked,
            "local_invocations": invocations_after_unbound,
            "reason": without_binding.decision.reason,
        },
        "with_application_binding": {
            "allow": with_binding.decision.allow,
            "invoked": with_binding.invoked,
            "local_invocations": invocations_after_bound,
            "reason": with_binding.decision.reason,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = run_experiment()
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print("Identical tool-call content in both arms: yes")
        print(
            "Without application binding: blocked, invocations="
            f"{result['without_application_binding']['local_invocations']}"
        )
        print(
            "With application binding: allowed, invocations="
            f"{result['with_application_binding']['local_invocations']}"
        )
        print("No model, network, email service, or external effect was used.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
