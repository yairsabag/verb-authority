"""Export source-pinned AgentDojo tool schemas without running its tools.

Usage:
    python -m benchmarks.export_agentdojo_schemas \
        /path/to/agentdojo --output-dir /path/to/output

The exporter reads each suite's public ``TOOLS`` list, imports only the tool
definition modules, and asks AgentDojo's own ``make_function`` helper for the
JSON Schema it exposes to an LLM. It does not construct suite environments,
run tasks, start an agent, or execute a tool.
"""

from __future__ import annotations

import argparse
import ast
import importlib
import json
import subprocess
import sys
from pathlib import Path


SUITES = ("workspace", "travel", "banking", "slack")
BENCHMARK_VERSION = "v1.2.2"


def _git_commit(checkout: Path) -> str:
    completed = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _suite_tools(task_suite_path: Path) -> list[tuple[str, str, str]]:
    """Return (public name, module, attribute) from the suite's TOOLS list."""

    tree = ast.parse(task_suite_path.read_text(), filename=str(task_suite_path))
    imports: dict[str, tuple[str, str]] = {}
    exposed_names: list[str] | None = None

    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module is not None:
            if ".tools." not in node.module:
                continue
            for imported in node.names:
                local_name = imported.asname or imported.name
                imports[local_name] = (node.module, imported.name)
        elif isinstance(node, ast.Assign):
            if not any(
                isinstance(target, ast.Name) and target.id == "TOOLS"
                for target in node.targets
            ):
                continue
            if not isinstance(node.value, (ast.List, ast.Tuple)):
                raise ValueError(f"TOOLS is not a literal list in {task_suite_path}")
            exposed_names = []
            for item in node.value.elts:
                if not isinstance(item, ast.Name):
                    raise ValueError(
                        f"TOOLS contains a non-name entry in {task_suite_path}"
                    )
                exposed_names.append(item.id)

    if exposed_names is None:
        raise ValueError(f"TOOLS list not found in {task_suite_path}")

    tools = []
    for name in exposed_names:
        if name not in imports:
            raise ValueError(f"tool {name!r} has no public tool-module import")
        module, attribute = imports[name]
        tools.append((name, module, attribute))
    return tools


def export(checkout: Path, output_dir: Path) -> dict[str, dict[str, object]]:
    checkout = checkout.resolve()
    source_root = checkout / "src"
    suites_root = source_root / "agentdojo" / "default_suites" / "v1"
    if not suites_root.is_dir():
        raise ValueError(f"not an AgentDojo checkout: {checkout}")

    sys.path.insert(0, str(source_root))
    from agentdojo.functions_runtime import make_function

    commit = _git_commit(checkout)
    output_dir.mkdir(parents=True, exist_ok=True)
    manifests: dict[str, dict[str, object]] = {}

    for suite in SUITES:
        task_suite_path = suites_root / suite / "task_suite.py"
        pinned_url = (
            "https://github.com/ethz-spylab/agentdojo/blob/"
            f"{commit}/src/agentdojo/default_suites/v1/{suite}/task_suite.py"
        )
        tools = []
        for public_name, module_name, attribute in _suite_tools(task_suite_path):
            function = getattr(importlib.import_module(module_name), attribute)
            definition = make_function(function)
            if definition.name != public_name:
                raise ValueError(
                    f"exported name mismatch: {public_name} != {definition.name}"
                )
            tools.append(
                {
                    "type": "function",
                    "source_id": f"agentdojo-{BENCHMARK_VERSION}-{suite}",
                    "source_url": pinned_url,
                    "function": {
                        "name": definition.name,
                        "description": definition.description,
                        "parameters": definition.parameters.model_json_schema(),
                    },
                }
            )

        document = {
            "provenance": {
                "repository": "https://github.com/ethz-spylab/agentdojo",
                "commit": commit,
                "benchmark_version": BENCHMARK_VERSION,
                "suite": suite,
                "tool_definitions_executed": False,
            },
            "tools": tools,
        }
        output_path = output_dir / f"{suite}.json"
        output_path.write_text(
            json.dumps(document, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        manifests[suite] = {
            "path": str(output_path),
            "tools": len(tools),
            "source_url": pinned_url,
        }

    return manifests


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export public AgentDojo tool schemas without running tools."
    )
    parser.add_argument("checkout", type=Path, help="local AgentDojo checkout")
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="directory for one OpenAI-format JSON file per suite",
    )
    args = parser.parse_args(argv)

    try:
        manifests = export(args.checkout, args.output_dir)
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))

    print(json.dumps(manifests, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
