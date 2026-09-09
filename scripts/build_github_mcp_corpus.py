#!/usr/bin/env python3
"""Build the source-pinned GitHub MCP schema corpus from tool snapshots.

The upstream repository checks one JSON snapshot per exposed tool into
``pkg/github/__toolsnaps__``.  This script performs a mechanical extraction of
the fields consumed by Verb Authority.  It does not build or execute the MCP
server and it deliberately omits descriptions, handlers, examples, and runtime
values.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


UPSTREAM_COMMIT = "12d16ed05310876a1e6988701b109da63d69dd49"
UPSTREAM_URL = (
    "https://github.com/github/github-mcp-server/tree/"
    f"{UPSTREAM_COMMIT}/pkg/github/__toolsnaps__"
)
CAPTURED_AT = "2026-09-01"


def _load_snapshots(snapshot_directory: Path) -> tuple[list[dict[str, Any]], str]:
    snapshots = sorted(snapshot_directory.glob("*.snap"))
    if not snapshots:
        raise SystemExit(f"no .snap files found in {snapshot_directory}")

    tools: list[dict[str, Any]] = []
    names: set[str] = set()
    manifest = hashlib.sha256()
    for snapshot in snapshots:
        raw = snapshot.read_bytes()
        manifest.update(snapshot.name.encode("utf-8"))
        manifest.update(b"\0")
        manifest.update(raw)
        manifest.update(b"\0")

        document = json.loads(raw)
        if type(document) is not dict:
            raise SystemExit(f"{snapshot} must contain one JSON object")
        name = document.get("name")
        input_schema = document.get("inputSchema")
        annotations = document.get("annotations")
        if type(name) is not str or not name:
            raise SystemExit(f"{snapshot} has no valid tool name")
        if name in names:
            raise SystemExit(f"duplicate tool name: {name}")
        if type(input_schema) is not dict:
            raise SystemExit(f"{snapshot} has no object inputSchema")
        if annotations is not None and type(annotations) is not dict:
            raise SystemExit(f"{snapshot} annotations must be an object")

        tool: dict[str, Any] = {"name": name, "inputSchema": input_schema}
        if annotations:
            tool["annotations"] = annotations
        tools.append(tool)
        names.add(name)

    tools.sort(key=lambda tool: tool["name"])
    return tools, manifest.hexdigest()


def build_document(snapshot_directory: Path) -> dict[str, Any]:
    tools, manifest_sha256 = _load_snapshots(snapshot_directory)
    return {
        "version": 1,
        "captured_at": CAPTURED_AT,
        "method": (
            "Mechanical extraction of name, inputSchema, and annotations from "
            "the upstream GitHub MCP Server tool snapshots; descriptions, "
            "handlers, outputs, examples, and runtime values are omitted."
        ),
        "sources": [
            {
                "id": "github-mcp-server-tool-snapshots",
                "url": UPSTREAM_URL,
                "license": "MIT",
                "upstream_commit": UPSTREAM_COMMIT,
                "snapshot_manifest_sha256": manifest_sha256,
                "tools": tools,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "snapshot_directory",
        type=Path,
        help="path to github-mcp-server/pkg/github/__toolsnaps__",
    )
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    document = build_document(args.snapshot_directory)
    args.output.write_text(
        json.dumps(document, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
