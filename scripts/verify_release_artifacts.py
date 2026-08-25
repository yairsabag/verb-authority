"""Verify that release tags and distribution artifacts describe one release.

This script intentionally uses only the Python standard library so the release
workflow can run it before installing project dependencies.
"""

from __future__ import annotations

import argparse
import base64
import configparser
from collections import Counter
import csv
from dataclasses import dataclass
from email.parser import Parser
import gzip
import hashlib
from io import StringIO
import os
import re
import shlex
import stat
import struct
import sys
import tarfile
import tomllib
import unicodedata
import zlib
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from zipfile import BadZipFile, ZIP_DEFLATED, ZIP_STORED, ZipFile


_TAG_PATTERN = re.compile(
    r"v(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:-(?P<phase>alpha|beta|rc)\.(?P<number>[0-9]+))?"
)
_PHASE_TO_PEP440 = {"alpha": "a", "beta": "b", "rc": "rc"}
MAX_SDIST_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_SDIST_MEMBERS = 10_000
MAX_SDIST_MEMBER_BYTES = 64 * 1024 * 1024
MAX_SDIST_TOTAL_BYTES = 256 * 1024 * 1024
MAX_SDIST_DECOMPRESSED_BYTES = (
    MAX_SDIST_TOTAL_BYTES
    + MAX_SDIST_MEMBERS * (4 * tarfile.BLOCKSIZE)
    + 2 * tarfile.BLOCKSIZE
    + tarfile.RECORDSIZE
)
MAX_SDIST_RAW_HEADERS = 2 * MAX_SDIST_MEMBERS
MAX_SDIST_HEADER_DEPTH = 64
MAX_SDIST_EXTENSION_BYTES = 1024 * 1024
MAX_WHEEL_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_WHEEL_MEMBERS = 10_000
MAX_WHEEL_MEMBER_BYTES = 64 * 1024 * 1024
MAX_WHEEL_TOTAL_BYTES = 256 * 1024 * 1024
MAX_PROJECT_MODULE_BYTES = 16 * 1024 * 1024
MAX_LICENSE_BYTES = 4 * 1024 * 1024
MAX_CORE_METADATA_BYTES = 4 * 1024 * 1024
MAX_WHEEL_DESCRIPTOR_BYTES = 64 * 1024
MAX_ENTRY_POINTS_BYTES = 256 * 1024
MAX_TOP_LEVEL_BYTES = 64 * 1024
MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_ARCHIVE_PATH_CODEPOINTS = 4096
MAX_ARCHIVE_PATH_BYTES = 16 * 1024
MAX_ARCHIVE_COMPONENT_CODEPOINTS = 255
MAX_ARCHIVE_COMPONENT_BYTES = 255
_WINDOWS_RESERVED_COMPONENTS = {
    "con",
    "conin$",
    "conout$",
    "clock$",
    "prn",
    "aux",
    "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
    *(f"com{number}" for number in "¹²³"),
    *(f"lpt{number}" for number in "¹²³"),
}
_ALLOWED_PAX_KEYS = {"mtime"}
_PAX_MTIME_PATTERN = re.compile(r"-?[0-9]{1,20}(?:\.[0-9]{1,20})?")
_SUPPORTED_CORE_METADATA_VERSION = "2.4"
_SUPPORTED_WHEEL_VERSION = "1.0"
_GENERATED_SETUP_CFG = b"[egg_info]\ntag_build = \ntag_date = 0\n\n"


class VerificationError(ValueError):
    """Raised when a release identity or artifact boundary is inconsistent."""


@dataclass(frozen=True)
class _ProjectReleaseConfig:
    name: str
    version: str
    modules: tuple[str, ...]
    scripts: dict[str, str]
    requires_python: str
    dependencies: tuple[str, ...]
    optional_dependencies: dict[str, tuple[str, ...]]
    module_payloads: dict[str, bytes]
    license_payloads: dict[str, bytes]
    sdist_source_payloads: dict[str, bytes]


@dataclass(frozen=True)
class _SdistInspection:
    identity: tuple[str, str]
    metadata_payload: bytes
    module_payloads: dict[str, bytes]


def _validate_single_gzip_member(sdist_path: Path) -> None:
    """Validate one bounded gzip member with no trailing compressed payload.

    ``gzip.GzipFile`` deliberately concatenates valid gzip members.  That is
    useful for general-purpose decompression but would let a release backend
    append bytes outside the exact tar manifest.  Validate the first member
    directly with zlib and require it to consume the complete artifact before
    tar traversal begins.
    """

    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    decompressed_bytes = 0
    try:
        with sdist_path.open("rb") as source:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                pending = chunk
                while pending:
                    remaining = MAX_SDIST_DECOMPRESSED_BYTES - decompressed_bytes
                    output = decompressor.decompress(
                        pending,
                        min(1024 * 1024, remaining + 1),
                    )
                    decompressed_bytes += len(output)
                    if decompressed_bytes > MAX_SDIST_DECOMPRESSED_BYTES:
                        raise VerificationError(
                            "source distribution exceeds the decompressed "
                            "traversal limit"
                        )
                    pending = decompressor.unconsumed_tail
                    if decompressor.eof:
                        if decompressor.unused_data or source.read(1):
                            raise VerificationError(
                                "source distribution contains more than one "
                                "gzip member or trailing compressed data"
                            )
                        return
    except VerificationError:
        raise
    except (OSError, EOFError, ValueError, zlib.error) as exc:
        raise VerificationError(
            f"cannot validate source-distribution gzip stream: {exc}"
        ) from exc
    raise VerificationError(
        "source distribution contains a truncated gzip member"
    )


class _BoundedArchiveReader:
    """Cap bytes exposed to tarfile, including hidden extension headers."""

    def __init__(self, fileobj: BinaryIO, limit: int):
        self._fileobj = fileobj
        self._limit = limit
        self._consumed = 0

    def read(self, size: int = -1) -> bytes:
        if size == 0:
            return b""
        remaining = self._limit - self._consumed
        if remaining < 0:
            raise VerificationError(
                "source distribution exceeds the decompressed traversal limit"
            )
        request_size = remaining + 1 if size < 0 else min(size, remaining + 1)
        data = self._fileobj.read(request_size)
        self._consumed += len(data)
        if self._consumed > self._limit:
            raise VerificationError(
                "source distribution exceeds the decompressed traversal limit"
            )
        return data


class _BoundedTarInfo(tarfile.TarInfo):
    """Count raw and recursively nested tar extension headers."""

    def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        # Global PAX state changes the interpretation of every later raw
        # header.  In particular, a global ``size`` override creates a parser
        # differential between Python's streaming reader and command-line tar
        # extractors.  Release sdists do not need global PAX state, so reject
        # it before its payload is read or applied.
        if self.type == tarfile.XGLTYPE:
            raise VerificationError(
                "source distribution contains a global PAX header"
            )
        # CPython parses GNU sparse extension blocks before returning a member
        # to our validation loop. Reject the type at the header boundary so a
        # malformed or extended sparse map cannot allocate, recurse, or leak an
        # internal parser exception before the public verifier sees it.
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise VerificationError(
                "source distribution contains a GNU sparse member"
            )
        if self.type in {
            tarfile.XHDTYPE,
            tarfile.XGLTYPE,
            tarfile.SOLARIS_XHDTYPE,
            tarfile.GNUTYPE_LONGNAME,
            tarfile.GNUTYPE_LONGLINK,
        } and (self.size < 0 or self.size > MAX_SDIST_EXTENSION_BYTES):
            raise VerificationError(
                "source distribution extension header exceeds the size limit"
            )
        return super()._proc_member(archive)

    def _proc_pax(self, archive: tarfile.TarFile) -> tarfile.TarInfo:
        """Parse the tiny PAX subset emitted by this project's build.

        The stdlib parser processes GNU sparse maps before returning control to
        the verifier.  A compressed archive can therefore make it allocate a
        very large tuple/list graph before the ordinary member checks run.
        Parsing only the local ``mtime`` annotation used by setuptools avoids
        that pre-validation allocation and rejects ``size``, path rewrites,
        GNU sparse fields, and all other interpretation-changing extensions.
        """

        if self.type == tarfile.XGLTYPE:
            raise VerificationError(
                "source distribution contains a global PAX header"
            )
        block_size = self._block(self.size)
        payload_block = archive.fileobj.read(block_size)
        if len(payload_block) != block_size:
            raise VerificationError(
                "source distribution contains a truncated PAX header"
            )
        payload = payload_block[: self.size]
        pax_headers: dict[str, str] = {}
        position = 0
        while position < len(payload):
            space = payload.find(b" ", position)
            if space < 0 or space - position not in range(1, 11):
                raise VerificationError(
                    "source distribution contains a malformed PAX record"
                )
            length_bytes = payload[position:space]
            if not length_bytes.isdigit():
                raise VerificationError(
                    "source distribution contains a malformed PAX record"
                )
            record_length = int(length_bytes)
            record_end = position + record_length
            if (
                record_length <= space - position + 3
                or record_end > len(payload)
                or payload[record_end - 1 : record_end] != b"\n"
            ):
                raise VerificationError(
                    "source distribution contains a malformed PAX record"
                )
            record = payload[space + 1 : record_end - 1]
            separator = record.find(b"=")
            if separator <= 0:
                raise VerificationError(
                    "source distribution contains a malformed PAX record"
                )
            try:
                key = record[:separator].decode("utf-8")
                value = record[separator + 1 :].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise VerificationError(
                    "source distribution contains a non-UTF-8 PAX record"
                ) from exc
            if key not in _ALLOWED_PAX_KEYS:
                raise VerificationError(
                    f"source distribution contains unsupported PAX key {key!r}"
                )
            if key in pax_headers:
                raise VerificationError(
                    f"source distribution repeats PAX key {key!r}"
                )
            if key == "mtime" and _PAX_MTIME_PATTERN.fullmatch(value) is None:
                raise VerificationError(
                    "source distribution contains an invalid PAX mtime"
                )
            pax_headers[key] = value
            position = record_end

        try:
            next_member = self.fromtarfile(archive)
        except tarfile.HeaderError as exc:
            raise tarfile.SubsequentHeaderError(str(exc)) from None
        if self.type in {tarfile.XHDTYPE, tarfile.SOLARIS_XHDTYPE}:
            next_member._apply_pax_info(
                pax_headers,
                archive.encoding,
                archive.errors,
            )
            next_member.offset = self.offset
        return next_member

    @classmethod
    def fromtarfile(cls, archive: tarfile.TarFile) -> tarfile.TarInfo:
        header_count = getattr(archive, "_verb_authority_header_count", 0) + 1
        if header_count > MAX_SDIST_RAW_HEADERS:
            raise VerificationError(
                "source distribution exceeds the raw-header-count limit"
            )
        archive._verb_authority_header_count = header_count

        header_depth = getattr(archive, "_verb_authority_header_depth", 0) + 1
        if header_depth > MAX_SDIST_HEADER_DEPTH:
            raise VerificationError(
                "source distribution exceeds the nested-header-depth limit"
            )
        archive._verb_authority_header_depth = header_depth
        try:
            return super().fromtarfile(archive)
        finally:
            archive._verb_authority_header_depth = header_depth - 1


def _project_identity(project_path: Path) -> tuple[str, str]:
    try:
        with project_path.open("rb") as project_file:
            project = tomllib.load(project_file)["project"]
        name = project["name"]
        version = project["version"]
    except (OSError, KeyError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(f"cannot read project identity: {exc}") from exc
    if not isinstance(name, str) or not name:
        raise VerificationError("project.name must be a non-empty string")
    if not isinstance(version, str) or not version:
        raise VerificationError("project.version must be a non-empty string")
    return name, version


def _read_bounded_project_file(
    path: Path,
    *,
    label: str,
    size_limit: int,
) -> bytes:
    try:
        if not path.is_file() or path.is_symlink():
            raise VerificationError(f"{label} must be a regular project file")
        size = path.stat().st_size
        if size < 0 or size > size_limit:
            raise VerificationError(f"{label} exceeds the size limit")
        payload = path.read_bytes()
    except VerificationError:
        raise
    except OSError as exc:
        raise VerificationError(f"cannot read {label}: {exc}") from exc
    if len(payload) != size:
        raise VerificationError(f"{label} changed while it was being read")
    return payload


def _safe_project_member(project_root: Path, candidate: Path) -> str:
    """Return a portable project-relative file name without following links."""

    try:
        relative = candidate.relative_to(project_root)
    except ValueError as exc:
        raise VerificationError(
            f"source file {candidate} escapes the project root"
        ) from exc
    relative_name = relative.as_posix()
    _portable_member_key(relative_name, archive_label="project source manifest")
    if any(part.casefold().endswith(".egg-info") for part in relative.parts):
        raise VerificationError(
            f"project source manifest selects generated metadata {relative_name!r}"
        )
    current = project_root
    try:
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise VerificationError(
                    f"project source {relative_name!r} must not traverse a symlink"
                )
        resolved_root = project_root.resolve(strict=True)
        candidate.resolve(strict=True).relative_to(resolved_root)
    except VerificationError:
        raise
    except (OSError, ValueError) as exc:
        raise VerificationError(
            f"cannot resolve project source {relative_name!r}: {exc}"
        ) from exc
    if not candidate.is_file():
        raise VerificationError(
            f"project source {relative_name!r} must be a regular file"
        )
    return relative_name


def _validate_manifest_pattern(value: str, *, label: str) -> None:
    path = PurePosixPath(value)
    if (
        not value
        or path.is_absolute()
        or "\\" in value
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise VerificationError(f"{label} contains unsafe path {value!r}")


def _collect_project_source_payloads(
    project_path: Path,
    *,
    document: dict[str, object],
    modules: tuple[str, ...],
    license_patterns: list[str],
) -> dict[str, bytes]:
    """Resolve the exact trusted source-file contract for the sdist.

    The supported MANIFEST.in subset is deliberately tiny and matches this
    repository.  Extending the packaging manifest therefore requires extending
    this verifier instead of silently widening executable release input.
    """

    project_root = project_path.parent
    selected: dict[str, Path] = {}

    def add(candidate: Path) -> None:
        relative_name = _safe_project_member(project_root, candidate)
        selected[relative_name] = candidate

    add(project_path)
    for module in modules:
        add(project_root / (module.replace(".", "/") + ".py"))

    project = document["project"]
    assert isinstance(project, dict)
    readme = project.get("readme")
    if isinstance(readme, str):
        _validate_manifest_pattern(readme, label="project.readme")
        add(project_root / readme)
    elif isinstance(readme, dict):
        readme_file = readme.get("file")
        if readme_file is not None:
            if not isinstance(readme_file, str):
                raise VerificationError("project.readme.file must be a string")
            _validate_manifest_pattern(readme_file, label="project.readme.file")
            add(project_root / readme_file)
    elif readme is not None:
        raise VerificationError("project.readme must be a string or table")

    for pattern in license_patterns:
        _validate_manifest_pattern(pattern, label="project.license-files")
        matches = sorted(project_root.glob(pattern))
        regular_matches = [match for match in matches if match.is_file()]
        if not regular_matches:
            raise VerificationError(
                f"project.license-files pattern {pattern!r} matched no files"
            )
        for match in regular_matches:
            add(match)

    manifest_path = project_root / "MANIFEST.in"
    if manifest_path.exists():
        add(manifest_path)
        try:
            manifest_lines = manifest_path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise VerificationError(f"cannot read MANIFEST.in: {exc}") from exc
        for line_number, raw_line in enumerate(manifest_lines, 1):
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                tokens = shlex.split(stripped, comments=True, posix=True)
            except ValueError as exc:
                raise VerificationError(
                    f"cannot parse MANIFEST.in line {line_number}: {exc}"
                ) from exc
            if not tokens:
                continue
            directive, *arguments = tokens
            if directive == "include" and arguments:
                for pattern in arguments:
                    _validate_manifest_pattern(pattern, label="MANIFEST.in include")
                    matches = sorted(project_root.glob(pattern))
                    regular_matches = [match for match in matches if match.is_file()]
                    if not regular_matches:
                        raise VerificationError(
                            f"MANIFEST.in include pattern {pattern!r} matched no files"
                        )
                    for match in regular_matches:
                        add(match)
            elif directive == "recursive-include" and len(arguments) >= 2:
                directory, *patterns = arguments
                _validate_manifest_pattern(
                    directory,
                    label="MANIFEST.in recursive-include",
                )
                directory_path = project_root / directory
                if not directory_path.is_dir() or directory_path.is_symlink():
                    raise VerificationError(
                        f"MANIFEST.in directory {directory!r} is not a regular directory"
                    )
                for pattern in patterns:
                    _validate_manifest_pattern(
                        pattern,
                        label="MANIFEST.in recursive pattern",
                    )
                    matches = sorted(directory_path.rglob(pattern))
                    regular_matches = [match for match in matches if match.is_file()]
                    if not regular_matches:
                        raise VerificationError(
                            "MANIFEST.in recursive pattern "
                            f"{directory!r} {pattern!r} matched no files"
                        )
                    for match in regular_matches:
                        add(match)
            else:
                raise VerificationError(
                    f"unsupported MANIFEST.in directive on line {line_number}: "
                    f"{directive!r}"
                )

    payloads: dict[str, bytes] = {}
    total_size = 0
    for relative_name, candidate in sorted(selected.items()):
        payload = _read_bounded_project_file(
            candidate,
            label=f"project source {relative_name!r}",
            size_limit=MAX_SDIST_MEMBER_BYTES,
        )
        total_size += len(payload)
        if total_size > MAX_SDIST_TOTAL_BYTES:
            raise VerificationError("trusted project sources exceed the total-size limit")
        payloads[relative_name] = payload
    return payloads


def _project_release_config(project_path: Path) -> _ProjectReleaseConfig:
    """Read the exact wheel payload contract from ``pyproject.toml``."""

    try:
        with project_path.open("rb") as project_file:
            document = tomllib.load(project_file)
        project = document["project"]
        setuptools = document["tool"]["setuptools"]
        name = project["name"]
        version = project["version"]
        modules_value = setuptools["py-modules"]
        scripts_value = project["scripts"]
        license_patterns = project["license-files"]
        requires_python = project["requires-python"]
        dependencies_value = project["dependencies"]
        optional_dependencies_value = project.get("optional-dependencies", {})
    except (OSError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise VerificationError(
            f"cannot read project release configuration: {exc}"
        ) from exc
    if not isinstance(name, str) or not name:
        raise VerificationError("project.name must be a non-empty string")
    if not isinstance(version, str) or not version:
        raise VerificationError("project.version must be a non-empty string")
    if not isinstance(requires_python, str) or not requires_python:
        raise VerificationError("project.requires-python must be a non-empty string")
    if not isinstance(dependencies_value, list) or any(
        not isinstance(item, str) or not item for item in dependencies_value
    ):
        raise VerificationError("project.dependencies must be a string list")
    dependencies = tuple(dependencies_value)
    if not isinstance(optional_dependencies_value, dict) or any(
        not isinstance(extra, str)
        or not extra
        or not isinstance(requirements, list)
        or any(not isinstance(item, str) or not item for item in requirements)
        for extra, requirements in optional_dependencies_value.items()
    ):
        raise VerificationError(
            "project.optional-dependencies must map extras to string lists"
        )
    optional_dependencies = {
        extra: tuple(requirements)
        for extra, requirements in optional_dependencies_value.items()
    }
    if (
        not isinstance(modules_value, list)
        or not modules_value
        or any(not isinstance(item, str) or not item for item in modules_value)
    ):
        raise VerificationError(
            "tool.setuptools.py-modules must be a non-empty string list"
        )
    modules = tuple(modules_value)
    if len(modules) != len(set(modules)):
        raise VerificationError("tool.setuptools.py-modules contains duplicates")
    module_pattern = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*")
    if any(module_pattern.fullmatch(module) is None for module in modules):
        raise VerificationError(
            "tool.setuptools.py-modules contains an unsafe module name"
        )
    if (
        not isinstance(scripts_value, dict)
        or not scripts_value
        or any(
            not isinstance(key, str)
            or not key
            or not isinstance(value, str)
            or not value
            for key, value in scripts_value.items()
        )
    ):
        raise VerificationError(
            "project.scripts must be a non-empty string-to-string table"
        )
    scripts = dict(scripts_value)
    if (
        not isinstance(license_patterns, list)
        or not license_patterns
        or any(
            not isinstance(pattern, str) or not pattern
            for pattern in license_patterns
        )
    ):
        raise VerificationError(
            "project.license-files must be a non-empty string list"
        )

    project_root = project_path.parent
    sdist_source_payloads = _collect_project_source_payloads(
        project_path,
        document=document,
        modules=modules,
        license_patterns=license_patterns,
    )
    module_payloads: dict[str, bytes] = {}
    for module in modules:
        member_name = module.replace(".", "/") + ".py"
        _portable_member_key(member_name, archive_label="project module")
        module_payloads[member_name] = _read_bounded_project_file(
            project_root / member_name,
            label=f"project module {member_name!r}",
            size_limit=MAX_PROJECT_MODULE_BYTES,
        )

    license_payloads: dict[str, bytes] = {}
    for pattern in license_patterns:
        pattern_path = PurePosixPath(pattern)
        if (
            pattern_path.is_absolute()
            or "\\" in pattern
            or any(part in {"", ".", ".."} for part in pattern_path.parts)
        ):
            raise VerificationError(
                f"project.license-files contains unsafe pattern {pattern!r}"
            )
        try:
            matches = sorted(project_root.glob(pattern))
        except (OSError, ValueError) as exc:
            raise VerificationError(
                f"cannot expand license-file pattern {pattern!r}: {exc}"
            ) from exc
        regular_matches = []
        try:
            resolved_project_root = project_root.resolve(strict=True)
        except OSError as exc:
            raise VerificationError(
                f"cannot resolve the project root: {exc}"
            ) from exc
        for match in matches:
            if not match.is_file() or match.is_symlink():
                continue
            try:
                match.resolve(strict=True).relative_to(resolved_project_root)
            except (OSError, ValueError) as exc:
                raise VerificationError(
                    f"license file {match} escapes the project root"
                ) from exc
            regular_matches.append(match)
        if not regular_matches:
            raise VerificationError(
                f"project.license-files pattern {pattern!r} matched no files"
            )
        for match in regular_matches:
            try:
                relative = match.relative_to(project_root).as_posix()
            except ValueError as exc:
                raise VerificationError(
                    f"license file {match} escapes the project root"
                ) from exc
            wheel_member = f"licenses/{relative}"
            _portable_member_key(
                wheel_member,
                archive_label="project license payload",
            )
            if wheel_member in license_payloads:
                raise VerificationError(
                    f"project license payload is selected more than once: "
                    f"{wheel_member!r}"
                )
            license_payloads[wheel_member] = _read_bounded_project_file(
                match,
                label=f"project license file {relative!r}",
                size_limit=MAX_LICENSE_BYTES,
            )

    return _ProjectReleaseConfig(
        name=name,
        version=version,
        modules=modules,
        scripts=scripts,
        requires_python=requires_python,
        dependencies=dependencies,
        optional_dependencies=optional_dependencies,
        module_payloads=module_payloads,
        license_payloads=license_payloads,
        sdist_source_payloads=sdist_source_payloads,
    )


def _portable_member_key(member: str, *, archive_label: str) -> str:
    """Validate an archive path before Unicode normalization.

    The returned key models common Windows extraction aliases in addition to
    NFC/case aliases.  Length checks happen on the original code points and
    UTF-8 bytes so normalization cannot become an unbounded preprocessing step.
    """

    canonical = member[:-1] if member.endswith("/") else member
    if not canonical:
        raise VerificationError(
            f"{archive_label} contains an empty member path"
        )
    try:
        encoded = canonical.encode("utf-8", "strict")
    except UnicodeEncodeError as exc:
        raise VerificationError(
            f"{archive_label} contains a non-UTF-8 member path"
        ) from exc
    if (
        len(canonical) > MAX_ARCHIVE_PATH_CODEPOINTS
        or len(encoded) > MAX_ARCHIVE_PATH_BYTES
    ):
        raise VerificationError(
            f"{archive_label} member path exceeds the pre-normalization limit"
        )
    if canonical.startswith("/") or "\\" in member:
        raise VerificationError(
            f"{archive_label} contains unsafe or ambiguous member path {member!r}"
        )
    raw_parts = canonical.split("/")
    portable_parts: list[str] = []
    for part in raw_parts:
        try:
            part_bytes = part.encode("utf-8", "strict")
        except UnicodeEncodeError as exc:
            raise VerificationError(
                f"{archive_label} contains a non-UTF-8 path component"
            ) from exc
        folded_stem = part.split(".", 1)[0].rstrip(" .").casefold()
        if (
            part in {"", ".", ".."}
            or len(part) > MAX_ARCHIVE_COMPONENT_CODEPOINTS
            or len(part_bytes) > MAX_ARCHIVE_COMPONENT_BYTES
            or part.endswith((".", " "))
            or ":" in part
            or any(ord(character) < 32 or ord(character) == 127 for character in part)
            or folded_stem in _WINDOWS_RESERVED_COMPONENTS
        ):
            raise VerificationError(
                f"{archive_label} contains unsafe or ambiguous member path "
                f"{member!r}"
            )
        portable_parts.append(unicodedata.normalize("NFC", part).casefold())
    return "/".join(portable_parts)


def _pep440_version_from_tag(tag: str) -> str:
    match = _TAG_PATTERN.fullmatch(tag)
    if match is None:
        raise VerificationError(
            "release tag must be v<version>, v<version>-alpha.N, "
            "v<version>-beta.N, or v<version>-rc.N"
        )
    version = match.group("release")
    phase = match.group("phase")
    number = match.group("number")
    if phase is not None:
        version += f"{_PHASE_TO_PEP440[phase]}{number}"
    return version


def verify_tag(project_path: Path, tag: str) -> tuple[str, str]:
    name, project_version = _project_identity(project_path)
    tag_version = _pep440_version_from_tag(tag)
    if tag_version != project_version:
        raise VerificationError(
            f"release tag {tag!r} identifies {tag_version!r}, "
            f"but project.version is {project_version!r}"
        )
    return name, project_version


def _metadata_identity(metadata: str, label: str) -> tuple[str, str]:
    parsed = Parser().parsestr(metadata)
    names = parsed.get_all("Name", [])
    versions = parsed.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1 or not names[0] or not versions[0]:
        raise VerificationError(
            f"{label} metadata must contain exactly one non-empty Name and Version"
        )
    return names[0], versions[0]


_REQUIREMENT_PATTERN = re.compile(
    r"\s*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[A-Za-z0-9._-]+(?:\s*,\s*[A-Za-z0-9._-]+)*)\])?"
    r"\s*(?P<specifiers>[^;]*)\s*"
)
_SPECIFIER_PATTERN = re.compile(r"(===|~=|==|!=|<=|>=|<|>)\s*([^,\s]+)")
_EXTRA_MARKER_PATTERN = re.compile(
    r"\s*extra\s*==\s*(['\"])(?P<extra>[A-Za-z0-9._-]+)\1\s*"
)


def _canonical_requirement(
    requirement: str,
    *,
    label: str,
) -> tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]]:
    if "@" in requirement or ";" in requirement:
        raise VerificationError(
            f"{label} uses an unsupported URL or environment marker"
        )
    match = _REQUIREMENT_PATTERN.fullmatch(requirement)
    if match is None:
        raise VerificationError(f"{label} contains an invalid requirement")
    extras_value = match.group("extras")
    extras = tuple(
        sorted(
            _normalize_name(extra.strip())
            for extra in extras_value.split(",")
        )
    ) if extras_value else ()
    specifier_text = match.group("specifiers").strip()
    specifiers: list[tuple[str, str]] = []
    if specifier_text:
        position = 0
        while position < len(specifier_text):
            specifier = _SPECIFIER_PATTERN.match(specifier_text, position)
            if specifier is None:
                raise VerificationError(
                    f"{label} contains an unsupported version specifier"
                )
            specifiers.append((specifier.group(1), specifier.group(2)))
            position = specifier.end()
            while position < len(specifier_text) and specifier_text[position].isspace():
                position += 1
            if position == len(specifier_text):
                break
            if specifier_text[position] != ",":
                raise VerificationError(
                    f"{label} contains an unsupported version specifier"
                )
            position += 1
            while position < len(specifier_text) and specifier_text[position].isspace():
                position += 1
            if position == len(specifier_text):
                raise VerificationError(f"{label} ends with an empty specifier")
    if len(specifiers) != len(set(specifiers)):
        raise VerificationError(f"{label} repeats a version specifier")
    return (
        _normalize_name(match.group("name")),
        extras,
        tuple(sorted(specifiers)),
    )


def _metadata_requirement(
    value: str,
    *,
    label: str,
) -> tuple[
    tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]],
    str | None,
]:
    requirement, separator, marker = value.partition(";")
    canonical = _canonical_requirement(requirement, label=label)
    if not separator:
        return canonical, None
    marker_match = _EXTRA_MARKER_PATTERN.fullmatch(marker)
    if marker_match is None:
        raise VerificationError(
            f"{label} contains an unsupported environment marker"
        )
    return canonical, _normalize_name(marker_match.group("extra"))


def _expected_requirements(
    config: _ProjectReleaseConfig,
) -> Counter[
    tuple[
        tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]],
        str | None,
    ]
]:
    expected: Counter[
        tuple[
            tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]],
            str | None,
        ]
    ] = Counter()
    for index, requirement in enumerate(config.dependencies):
        canonical = _canonical_requirement(
            requirement,
            label=f"project.dependencies[{index}]",
        )
        expected[(canonical, None)] += 1
    normalized_extras: set[str] = set()
    for extra, requirements in config.optional_dependencies.items():
        normalized_extra = _normalize_name(extra)
        if normalized_extra in normalized_extras:
            raise VerificationError(
                "project.optional-dependencies contains colliding extra names"
            )
        normalized_extras.add(normalized_extra)
        for index, requirement in enumerate(requirements):
            canonical = _canonical_requirement(
                requirement,
                label=f"project.optional-dependencies.{extra}[{index}]",
            )
            expected[(canonical, normalized_extra)] += 1
    return expected


def _validate_core_metadata(
    payload: bytes,
    *,
    config: _ProjectReleaseConfig,
    label: str,
) -> tuple[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"{label} metadata is not UTF-8") from exc
    parsed = Parser().parsestr(text)

    def exactly_one(field: str) -> str:
        values = parsed.get_all(field, [])
        if len(values) != 1 or not values[0].strip():
            raise VerificationError(
                f"{label} metadata must contain exactly one non-empty {field}"
            )
        return values[0].strip()

    metadata_version = exactly_one("Metadata-Version")
    if metadata_version != _SUPPORTED_CORE_METADATA_VERSION:
        raise VerificationError(
            f"{label} Metadata-Version must be "
            f"{_SUPPORTED_CORE_METADATA_VERSION!r}"
        )
    name = exactly_one("Name")
    version = exactly_one("Version")
    requires_python = exactly_one("Requires-Python")
    if name != config.name:
        raise VerificationError(
            f"{label} Name {name!r} does not exactly match project.name "
            f"{config.name!r}"
        )
    if version != config.version:
        raise VerificationError(
            f"{label} Version {version!r} does not match project.version "
            f"{config.version!r}"
        )
    if requires_python != config.requires_python:
        raise VerificationError(
            f"{label} Requires-Python does not match project.requires-python"
        )

    provided_extras = parsed.get_all("Provides-Extra", [])
    normalized_provided = [_normalize_name(value.strip()) for value in provided_extras]
    expected_extras = sorted(
        _normalize_name(extra) for extra in config.optional_dependencies
    )
    if (
        any(not value.strip() for value in provided_extras)
        or len(normalized_provided) != len(set(normalized_provided))
        or sorted(normalized_provided) != expected_extras
    ):
        raise VerificationError(
            f"{label} Provides-Extra does not exactly match "
            "project.optional-dependencies"
        )

    actual_requirements: Counter[
        tuple[
            tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]],
            str | None,
        ]
    ] = Counter()
    for index, requirement in enumerate(parsed.get_all("Requires-Dist", [])):
        actual_requirements[
            _metadata_requirement(
                requirement,
                label=f"{label} Requires-Dist[{index}]",
            )
        ] += 1
    if actual_requirements != _expected_requirements(config):
        raise VerificationError(
            f"{label} Requires-Dist does not exactly match project dependencies"
        )
    return name, version


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _artifact_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _artifact_version_name(version: str) -> str:
    return re.sub(r"[^\w\d.]+", "_", version).lower()


def _expected_wheel_members(
    config: _ProjectReleaseConfig,
    *,
    expected_root: str,
) -> set[str]:
    return {
        *config.module_payloads,
        *(f"{expected_root}/{member}" for member in config.license_payloads),
        f"{expected_root}/METADATA",
        f"{expected_root}/WHEEL",
        f"{expected_root}/entry_points.txt",
        f"{expected_root}/top_level.txt",
        f"{expected_root}/RECORD",
    }


def _validate_wheel_members(
    wheel: ZipFile,
    *,
    expected_root: str,
    expected_members: set[str],
    expected_exact_sizes: dict[str, int],
    metadata_size_limits: dict[str, int],
) -> None:
    """Reject aliases, executable payload, and metadata outside the contract."""

    infos = wheel.infolist()
    if wheel.comment:
        raise VerificationError("wheel archive comments are not permitted")
    if len(infos) > MAX_WHEEL_MEMBERS:
        raise VerificationError("wheel exceeds the member-count limit")
    names = [info.filename for info in infos]
    if len(names) != len(set(names)):
        raise VerificationError("wheel contains duplicate member paths")

    canonical_paths: set[str] = set()
    portable_paths: set[str] = set()
    total_size = 0
    for info in infos:
        member = info.filename
        if info.orig_filename != member:
            raise VerificationError(
                "wheel contains a NUL-truncated or ambiguous member name"
            )
        canonical = member[:-1] if member.endswith("/") else member
        parts = canonical.split("/")
        portable = _portable_member_key(member, archive_label="wheel")
        if canonical in canonical_paths or portable in portable_paths:
            raise VerificationError(
                f"wheel contains unsafe or ambiguous member path {member!r}"
            )
        canonical_paths.add(canonical)
        portable_paths.add(portable)

        if info.file_size < 0 or info.file_size > MAX_WHEEL_MEMBER_BYTES:
            raise VerificationError(
                f"wheel member exceeds the size limit: {member!r}"
            )
        exact_size = expected_exact_sizes.get(member)
        if exact_size is not None and info.file_size != exact_size:
            raise VerificationError(
                f"wheel member size does not match the verified project "
                f"payload: {member!r}"
            )
        metadata_limit = metadata_size_limits.get(member)
        if metadata_limit is not None and info.file_size > metadata_limit:
            raise VerificationError(
                f"wheel metadata member exceeds its size limit: {member!r}"
            )
        if info.compress_size < 0:
            raise VerificationError(
                f"wheel member has an invalid compressed size: {member!r}"
            )
        total_size += info.file_size
        if total_size > MAX_WHEEL_TOTAL_BYTES:
            raise VerificationError("wheel exceeds the total-size limit")

        file_type = stat.S_IFMT(info.external_attr >> 16)
        if member.endswith("/") or file_type not in {0, stat.S_IFREG}:
            raise VerificationError(
                f"wheel contains unsupported member type at {member!r}"
            )
        if info.flag_bits & 0x1:
            raise VerificationError(
                f"wheel contains encrypted member {member!r}"
            )
        if info.extra:
            raise VerificationError(
                f"wheel contains unsupported extra fields at {member!r}"
            )
        if info.compress_type not in {ZIP_STORED, ZIP_DEFLATED}:
            raise VerificationError(
                f"wheel contains unsupported compression at {member!r}"
            )

        dist_info_parts = [
            part for part in parts if part.casefold().endswith(".dist-info")
        ]
        if dist_info_parts and not (
            len(dist_info_parts) == 1 and parts[0] == expected_root
        ):
            raise VerificationError(
                f"wheel contains metadata outside expected dist-info directory: "
                f"{member!r}"
            )

    metadata_members = [
        member
        for member in names
        if member.endswith(".dist-info/METADATA") and member.count("/") == 1
    ]
    if len(metadata_members) != 1:
        raise VerificationError(
            f"wheel must contain exactly one dist-info/METADATA; "
            f"found {len(metadata_members)}"
        )
    wheel_members = [
        member
        for member in names
        if member.endswith(".dist-info/WHEEL") and member.count("/") == 1
    ]
    if len(wheel_members) != 1:
        raise VerificationError(
            "wheel must contain exactly one dist-info/WHEEL; "
            f"found {len(wheel_members)}"
        )
    metadata_root = metadata_members[0].rsplit("/", 1)[0]
    wheel_root = wheel_members[0].rsplit("/", 1)[0]
    if wheel_root != metadata_root:
        raise VerificationError(
            "wheel METADATA and WHEEL must belong to the same dist-info directory"
        )
    if metadata_root != expected_root:
        raise VerificationError(
            f"wheel dist-info directory {metadata_root!r} does not match "
            f"expected {expected_root!r}"
        )

    actual_members = set(names)
    if actual_members != expected_members:
        missing = sorted(expected_members - actual_members)
        unexpected = sorted(actual_members - expected_members)
        raise VerificationError(
            "wheel payload does not match the pyproject allowlist: "
            f"missing={missing}; unexpected={unexpected}"
        )


def _read_wheel_members(wheel: ZipFile) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for info in wheel.infolist():
        payload = wheel.read(info)
        if len(payload) != info.file_size:
            raise VerificationError(
                f"wheel member size changed while reading {info.filename!r}"
            )
        payloads[info.filename] = payload
    return payloads


def _verify_wheel_record(
    payloads: dict[str, bytes],
    *,
    record_name: str,
) -> None:
    try:
        record_text = payloads[record_name].decode("utf-8")
        rows = list(csv.reader(StringIO(record_text, newline=""), strict=True))
    except (UnicodeDecodeError, csv.Error) as exc:
        raise VerificationError(f"wheel RECORD cannot be parsed: {exc}") from exc
    row_by_member: dict[str, tuple[str, str]] = {}
    for row in rows:
        if len(row) != 3 or not row[0]:
            raise VerificationError("wheel RECORD contains a malformed row")
        member, digest, size = row
        if member in row_by_member:
            raise VerificationError(
                f"wheel RECORD repeats member {member!r}"
            )
        row_by_member[member] = (digest, size)
    if set(row_by_member) != set(payloads):
        missing = sorted(set(payloads) - set(row_by_member))
        stale = sorted(set(row_by_member) - set(payloads))
        raise VerificationError(
            "wheel RECORD must contain exactly one row for every member: "
            f"missing={missing}; stale={stale}"
        )
    if row_by_member[record_name] != ("", ""):
        raise VerificationError(
            "wheel RECORD self row must have empty hash and size"
        )
    for member, payload in payloads.items():
        if member == record_name:
            continue
        expected_digest = base64.urlsafe_b64encode(
            hashlib.sha256(payload).digest()
        ).rstrip(b"=").decode("ascii")
        digest, size = row_by_member[member]
        if digest != f"sha256={expected_digest}" or size != str(len(payload)):
            raise VerificationError(
                f"wheel RECORD hash or size does not match {member!r}"
            )


def _verify_wheel_entry_points(
    payload: bytes,
    *,
    expected_scripts: dict[str, str],
) -> None:
    try:
        text = payload.decode("utf-8")
        parsed = configparser.ConfigParser(
            interpolation=None,
            strict=True,
            delimiters=("=",),
        )
        parsed.optionxform = str
        parsed.read_string(text)
    except (UnicodeDecodeError, configparser.Error) as exc:
        raise VerificationError(
            f"wheel entry_points.txt cannot be parsed: {exc}"
        ) from exc
    if parsed.sections() != ["console_scripts"] or parsed.defaults():
        raise VerificationError(
            "wheel entry_points.txt must contain only [console_scripts]"
        )
    actual_scripts = {
        key.strip(): value.strip()
        for key, value in parsed.items("console_scripts", raw=True)
    }
    if actual_scripts != expected_scripts:
        raise VerificationError(
            "wheel console scripts do not exactly match project.scripts"
        )


def _verify_wheel_top_level(payload: bytes, *, modules: tuple[str, ...]) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("wheel top_level.txt is not UTF-8") from exc
    lines = text.splitlines()
    expected = sorted({module.split(".", 1)[0] for module in modules})
    if lines != expected:
        raise VerificationError(
            "wheel top_level.txt does not exactly match py-modules"
        )


def _wheel_identity(
    wheel_path: Path,
    *,
    config: _ProjectReleaseConfig,
    sdist_metadata_payload: bytes,
    sdist_module_payloads: dict[str, bytes],
) -> tuple[str, str]:
    expected_root = (
        f"{_artifact_distribution_name(config.name)}-"
        f"{_artifact_version_name(config.version)}.dist-info"
    )
    expected_members = _expected_wheel_members(
        config,
        expected_root=expected_root,
    )
    expected_exact_sizes = {
        **{
            member: len(payload)
            for member, payload in config.module_payloads.items()
        },
        **{
            f"{expected_root}/{member}": len(payload)
            for member, payload in config.license_payloads.items()
        },
    }
    metadata_size_limits = {
        f"{expected_root}/METADATA": MAX_CORE_METADATA_BYTES,
        f"{expected_root}/WHEEL": MAX_WHEEL_DESCRIPTOR_BYTES,
        f"{expected_root}/entry_points.txt": MAX_ENTRY_POINTS_BYTES,
        f"{expected_root}/top_level.txt": MAX_TOP_LEVEL_BYTES,
        f"{expected_root}/RECORD": MAX_RECORD_BYTES,
    }
    try:
        if not wheel_path.is_file() or wheel_path.is_symlink():
            raise VerificationError("wheel must be a regular artifact file")
        archive_size = wheel_path.stat().st_size
        if archive_size < 0 or archive_size > MAX_WHEEL_ARCHIVE_BYTES:
            raise VerificationError("wheel exceeds the compressed-size limit")
        with ZipFile(wheel_path) as wheel:
            _validate_wheel_members(
                wheel,
                expected_root=expected_root,
                expected_members=expected_members,
                expected_exact_sizes=expected_exact_sizes,
                metadata_size_limits=metadata_size_limits,
            )
            payloads = _read_wheel_members(wheel)
    except VerificationError:
        raise
    except (
        BadZipFile,
        OSError,
        UnicodeDecodeError,
        RuntimeError,
        NotImplementedError,
        ValueError,
        OverflowError,
        EOFError,
        IndexError,
        KeyError,
        struct.error,
        zlib.error,
    ) as exc:
        raise VerificationError(
            f"cannot inspect wheel {wheel_path.name}: {exc}"
        ) from exc

    metadata_name = f"{expected_root}/METADATA"
    wheel_metadata_name = f"{expected_root}/WHEEL"
    record_name = f"{expected_root}/RECORD"
    entry_points_name = f"{expected_root}/entry_points.txt"
    top_level_name = f"{expected_root}/top_level.txt"
    try:
        metadata = payloads[metadata_name].decode("utf-8")
        wheel_metadata = payloads[wheel_metadata_name].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("wheel metadata is not UTF-8") from exc

    parsed_wheel = Parser().parsestr(wheel_metadata)
    wheel_versions = parsed_wheel.get_all("Wheel-Version", [])
    if (
        len(wheel_versions) != 1
        or wheel_versions[0].strip() != _SUPPORTED_WHEEL_VERSION
    ):
        raise VerificationError(
            "wheel WHEEL metadata must contain exactly one supported "
            f"Wheel-Version: {_SUPPORTED_WHEEL_VERSION}"
        )
    purelib_values = parsed_wheel.get_all("Root-Is-Purelib", [])
    if (
        len(purelib_values) != 1
        or purelib_values[0].strip().lower() != "true"
    ):
        raise VerificationError(
            "wheel WHEEL metadata must contain exactly one "
            "Root-Is-Purelib: true"
        )
    tags = [value.strip() for value in parsed_wheel.get_all("Tag", [])]
    if len(tags) != 1 or set(tags) != {"py3-none-any"}:
        raise VerificationError(
            "wheel WHEEL compatibility tags must be exactly "
            f"['py3-none-any']; found {tags}"
        )
    _verify_wheel_record(payloads, record_name=record_name)
    _verify_wheel_entry_points(
        payloads[entry_points_name],
        expected_scripts=config.scripts,
    )
    _verify_wheel_top_level(payloads[top_level_name], modules=config.modules)

    wheel_identity = _validate_core_metadata(
        payloads[metadata_name],
        config=config,
        label="wheel",
    )
    if (
        _normalize_name(wheel_identity[0]) == _normalize_name(config.name)
        and wheel_identity[1] == config.version
        and payloads[metadata_name] != sdist_metadata_payload
    ):
        raise VerificationError(
            "wheel METADATA differs from verified sdist PKG-INFO"
        )
    for member_name, sdist_payload in sdist_module_payloads.items():
        if payloads[member_name] != sdist_payload:
            raise VerificationError(
                f"wheel module {member_name!r} differs from the verified sdist"
            )
    for license_name, project_payload in config.license_payloads.items():
        wheel_name = f"{expected_root}/{license_name}"
        if payloads[wheel_name] != project_payload:
            raise VerificationError(
                f"wheel license payload {license_name!r} differs from the project"
            )
    return wheel_identity


def _sdist_generated_members(
    config: _ProjectReleaseConfig,
) -> tuple[str, set[str]]:
    egg_info_root = f"{_artifact_distribution_name(config.name)}.egg-info"
    generated = {
        "PKG-INFO",
        "setup.cfg",
        f"{egg_info_root}/PKG-INFO",
        f"{egg_info_root}/SOURCES.txt",
        f"{egg_info_root}/dependency_links.txt",
        f"{egg_info_root}/entry_points.txt",
        f"{egg_info_root}/requires.txt",
        f"{egg_info_root}/top_level.txt",
    }
    return egg_info_root, generated


def _verify_sdist_sources_list(
    payload: bytes,
    *,
    expected_sources: set[str],
    egg_info_root: str,
) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("sdist SOURCES.txt is not UTF-8") from exc
    lines = text.splitlines()
    if any(not line or line != line.strip() for line in lines):
        raise VerificationError("sdist SOURCES.txt contains a malformed path")
    if len(lines) != len(set(lines)):
        raise VerificationError("sdist SOURCES.txt contains duplicate paths")
    generated_sources = {
        f"{egg_info_root}/PKG-INFO",
        f"{egg_info_root}/SOURCES.txt",
        f"{egg_info_root}/dependency_links.txt",
        f"{egg_info_root}/entry_points.txt",
        f"{egg_info_root}/requires.txt",
        f"{egg_info_root}/top_level.txt",
    }
    expected = expected_sources | generated_sources
    for line in lines:
        _portable_member_key(line, archive_label="sdist SOURCES.txt")
    if set(lines) != expected:
        missing = sorted(expected - set(lines))
        unexpected = sorted(set(lines) - expected)
        raise VerificationError(
            "sdist SOURCES.txt does not match the trusted source manifest: "
            f"missing={missing}; unexpected={unexpected}"
        )


def _verify_sdist_requires(
    payload: bytes,
    *,
    config: _ProjectReleaseConfig,
) -> None:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError("sdist requires.txt is not UTF-8") from exc
    current_extra: str | None = None
    seen_sections: set[str] = set()
    actual: Counter[
        tuple[
            tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]],
            str | None,
        ]
    ] = Counter()
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            raw_extra = stripped[1:-1]
            if not raw_extra or ":" in raw_extra:
                raise VerificationError(
                    f"sdist requires.txt has unsupported section on line {line_number}"
                )
            current_extra = _normalize_name(raw_extra)
            if current_extra in seen_sections:
                raise VerificationError("sdist requires.txt repeats an extra section")
            seen_sections.add(current_extra)
            continue
        if line != stripped:
            raise VerificationError(
                f"sdist requires.txt has malformed whitespace on line {line_number}"
            )
        canonical = _canonical_requirement(
            stripped,
            label=f"sdist requires.txt line {line_number}",
        )
        actual[(canonical, current_extra)] += 1
    expected = _expected_requirements(config)
    expected_sections = {
        _normalize_name(extra) for extra in config.optional_dependencies
    }
    if seen_sections != expected_sections or actual != expected:
        raise VerificationError(
            "sdist requires.txt does not exactly match project dependencies"
        )


def _inspect_sdist(
    sdist_path: Path,
    *,
    config: _ProjectReleaseConfig,
    extract_to: Path | None = None,
) -> _SdistInspection:
    try:
        if not sdist_path.is_file() or sdist_path.is_symlink():
            raise VerificationError(
                "source distribution must be a regular artifact file"
            )
        if sdist_path.stat().st_size > MAX_SDIST_ARCHIVE_BYTES:
            raise VerificationError(
                "source distribution exceeds the compressed-size limit"
            )
        _validate_single_gzip_member(sdist_path)
        with (
            gzip.open(sdist_path, "rb") as decompressed_archive,
            tarfile.open(
                sdist_path.name,
                "r|",
                fileobj=(bounded_archive := _BoundedArchiveReader(
                    decompressed_archive,
                    MAX_SDIST_DECOMPRESSED_BYTES,
                )),
                tarinfo=_BoundedTarInfo,
            ) as source_archive,
        ):
            expected_root = (
                f"{_artifact_distribution_name(config.name)}-"
                f"{_artifact_version_name(config.version)}"
            )
            member_names: set[str] = set()
            portable_member_names: set[str] = set()
            member_count = 0
            total_size = 0
            metadata_count = 0
            metadata_bytes: bytes | None = None
            egg_info_root, generated_members = _sdist_generated_members(config)
            expected_files = set(config.sdist_source_payloads) | generated_members
            allowed_directories = {expected_root}
            for relative_name in expected_files:
                relative_parts = PurePosixPath(relative_name).parts
                for depth in range(1, len(relative_parts)):
                    allowed_directories.add(
                        f"{expected_root}/"
                        + "/".join(relative_parts[:depth])
                    )
            expected_module_members = {
                f"{expected_root}/{member}": member
                for member in config.module_payloads
            }
            module_payloads: dict[str, bytes] = {}
            file_payloads: dict[str, bytes] = {}
            while True:
                member = source_archive.next()
                if member is None:
                    break
                member_count += 1
                if member_count > MAX_SDIST_MEMBERS:
                    raise VerificationError(
                        "source distribution exceeds the member-count limit"
                    )
                canonical_name = (
                    member.name[:-1]
                    if member.name.endswith("/")
                    else member.name
                )
                portable_name = _portable_member_key(
                    member.name,
                    archive_label="source distribution",
                )
                raw_parts = canonical_name.split("/")
                relative_name = "/".join(raw_parts[1:])
                path = PurePosixPath(canonical_name)
                regular_file = member.type in {
                    tarfile.REGTYPE,
                    tarfile.AREGTYPE,
                }
                directory = member.type == tarfile.DIRTYPE
                sparse_headers = any(
                    key.startswith("GNU.sparse") or key == "SCHILY.realsize"
                    for key in member.pax_headers
                )
                unsupported_pax = set(member.pax_headers) - _ALLOWED_PAX_KEYS
                top_level_metadata = (
                    regular_file
                    and canonical_name.endswith("/PKG-INFO")
                    and canonical_name.count("/") == 1
                )
                target_module = expected_module_members.get(canonical_name)
                if path.parts and path.parts[0] != expected_root:
                    raise VerificationError(
                        f"source-distribution root {path.parts[0]!r} does not "
                        f"match expected {expected_root!r}"
                    )
                if top_level_metadata:
                    metadata_root = canonical_name.rsplit("/", 1)[0]
                    if metadata_root != expected_root:
                        raise VerificationError(
                            f"source-distribution root {metadata_root!r} does not "
                            f"match expected {expected_root!r}"
                        )
                if (
                    path.is_absolute()
                    or not path.parts
                    or path.parts[0] != expected_root
                    or not (regular_file or directory)
                    or bool(member.sparse)
                    or sparse_headers
                    or unsupported_pax
                ):
                    raise VerificationError(
                        "source distribution contains an unsafe or unexpected "
                        f"member path {member.name!r}; files must exactly match "
                        "the trusted source manifest and generated metadata"
                    )
                if canonical_name in member_names:
                    raise VerificationError(
                        "source distribution contains duplicate member paths"
                    )
                if portable_name in portable_member_names:
                    raise VerificationError(
                        "source distribution contains portable-path collisions"
                    )
                member_names.add(canonical_name)
                portable_member_names.add(portable_name)
                if member.size < 0 or member.size > MAX_SDIST_MEMBER_BYTES:
                    raise VerificationError(
                        "source distribution member exceeds the size limit: "
                        f"{member.name!r}"
                    )
                if top_level_metadata and member.size > MAX_CORE_METADATA_BYTES:
                    raise VerificationError(
                        "source distribution PKG-INFO exceeds the metadata "
                        "size limit"
                    )
                if (
                    target_module is not None
                    and member.size != len(config.module_payloads[target_module])
                ):
                    raise VerificationError(
                        f"source-distribution module size does not match the "
                        f"project: {target_module!r}"
                    )
                if directory and member.size != 0:
                    raise VerificationError(
                        "source distribution directory member has non-zero size: "
                        f"{member.name!r}"
                    )
                trusted_source_payload = config.sdist_source_payloads.get(
                    relative_name
                )
                if (
                    trusted_source_payload is not None
                    and member.size != len(trusted_source_payload)
                ):
                    raise VerificationError(
                        "source-distribution source size does not match the "
                        f"trusted checkout: {relative_name!r}"
                    )
                if (
                    (regular_file and relative_name not in expected_files)
                    or (directory and canonical_name not in allowed_directories)
                ):
                    raise VerificationError(
                        "source distribution contains an unsafe or unexpected "
                        f"member path {member.name!r}; files must exactly match "
                        "the trusted source manifest and generated metadata"
                    )
                total_size += member.size
                if total_size > MAX_SDIST_TOTAL_BYTES:
                    raise VerificationError(
                        "source distribution exceeds the total-size limit"
                    )
                if regular_file:
                    extracted = source_archive.extractfile(member)
                    if extracted is None:
                        raise VerificationError(
                            f"cannot read source distribution member "
                            f"{canonical_name!r}"
                        )
                    payload = extracted.read()
                    if len(payload) != member.size:
                        raise VerificationError(
                            f"source distribution member size changed while "
                            f"reading {canonical_name!r}"
                        )
                    file_payloads[relative_name] = payload
                    if top_level_metadata:
                        metadata_count += 1
                        metadata_bytes = payload
                    if target_module is not None:
                        if target_module in module_payloads:
                            raise VerificationError(
                                f"source distribution repeats project module "
                                f"{target_module!r}"
                            )
                        module_payloads[target_module] = payload
                    if extract_to is not None:
                        destination = extract_to.joinpath(*raw_parts)
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        try:
                            with destination.open("xb") as output:
                                output.write(payload)
                            os.chmod(destination, member.mode & 0o777)
                        except OSError as exc:
                            raise VerificationError(
                                f"cannot safely extract {canonical_name!r}: {exc}"
                            ) from exc
                elif extract_to is not None:
                    destination = extract_to.joinpath(*raw_parts)
                    try:
                        destination.mkdir(parents=True, exist_ok=True)
                        os.chmod(destination, member.mode & 0o777)
                    except OSError as exc:
                        raise VerificationError(
                            f"cannot safely extract directory "
                            f"{canonical_name!r}: {exc}"
                        ) from exc
            if metadata_count != 1 or metadata_bytes is None:
                raise VerificationError(
                    f"source distribution must contain exactly one top-level "
                    f"PKG-INFO; found {metadata_count}"
                )
            if set(file_payloads) != expected_files:
                missing = sorted(expected_files - set(file_payloads))
                unexpected = sorted(set(file_payloads) - expected_files)
                raise VerificationError(
                    "source distribution file manifest does not exactly match "
                    f"the trusted checkout: missing={missing}; "
                    f"unexpected={unexpected}"
                )
            for member_name, project_payload in config.sdist_source_payloads.items():
                if file_payloads[member_name] != project_payload:
                    raise VerificationError(
                        f"source-distribution source {member_name!r} differs "
                        "from the trusted checkout"
                    )
            if set(module_payloads) != set(config.module_payloads):
                missing = sorted(set(config.module_payloads) - set(module_payloads))
                raise VerificationError(
                    f"source distribution is missing project modules: {missing}"
                )
            for member_name, project_payload in config.module_payloads.items():
                if module_payloads[member_name] != project_payload:
                    raise VerificationError(
                        f"source-distribution module {member_name!r} differs "
                        "from the project"
                    )
            if file_payloads["setup.cfg"] != _GENERATED_SETUP_CFG:
                raise VerificationError(
                    "source distribution contains an unexpected generated setup.cfg"
                )
            egg_metadata_name = f"{egg_info_root}/PKG-INFO"
            if file_payloads[egg_metadata_name] != metadata_bytes:
                raise VerificationError(
                    "source distribution PKG-INFO copies differ"
                )
            _verify_sdist_sources_list(
                file_payloads[f"{egg_info_root}/SOURCES.txt"],
                expected_sources=set(config.sdist_source_payloads),
                egg_info_root=egg_info_root,
            )
            if file_payloads[f"{egg_info_root}/dependency_links.txt"] != b"\n":
                raise VerificationError(
                    "source distribution dependency_links.txt must be empty"
                )
            _verify_wheel_entry_points(
                file_payloads[f"{egg_info_root}/entry_points.txt"],
                expected_scripts=config.scripts,
            )
            _verify_sdist_requires(
                file_payloads[f"{egg_info_root}/requires.txt"],
                config=config,
            )
            _verify_wheel_top_level(
                file_payloads[f"{egg_info_root}/top_level.txt"],
                modules=config.modules,
            )
            metadata_identity = _validate_core_metadata(
                metadata_bytes,
                config=config,
                label="source distribution",
            )
            # tarfile's streaming parser stops at the tar end marker.  Any
            # remaining bytes in the already validated single gzip member must
            # be ordinary zero tar padding, never a hidden payload.
            while trailing := bounded_archive.read(1024 * 1024):
                if any(trailing):
                    raise VerificationError(
                        "source distribution contains non-zero data after the "
                        "tar end marker"
                    )
    except VerificationError:
        raise
    except (
        OSError,
        EOFError,
        ValueError,
        OverflowError,
        RecursionError,
        IndexError,
        KeyError,
        TypeError,
        struct.error,
        zlib.error,
        tarfile.TarError,
        UnicodeDecodeError,
    ) as exc:
        raise VerificationError(
            f"cannot inspect source distribution {sdist_path.name}: {exc}"
        ) from exc
    return _SdistInspection(
        identity=metadata_identity,
        metadata_payload=metadata_bytes,
        module_payloads=module_payloads,
    )


def _release_config(
    project_path: Path,
    tag: str | None,
) -> _ProjectReleaseConfig:
    config = _project_release_config(project_path)
    if tag is not None:
        tag_name, tag_version = verify_tag(project_path, tag)
        if tag_name != config.name or tag_version != config.version:
            raise VerificationError(
                "release tag and project release configuration disagree"
            )
    return config


def verify_sdist(
    project_path: Path, dist_path: Path, tag: str | None = None
) -> Path:
    """Verify the sole built sdist before any archive extraction occurs."""

    config = _release_config(project_path, tag)

    sdists = sorted(dist_path.glob("*.tar.gz"))
    if len(sdists) != 1:
        raise VerificationError(
            "pre-extraction release directory must contain exactly one source "
            f"distribution; found {len(sdists)}"
        )
    try:
        entries = set(dist_path.iterdir())
    except OSError as exc:
        raise VerificationError(f"cannot inspect release directory: {exc}") from exc
    if entries != {sdists[0]}:
        unexpected = sorted(path.name for path in entries - {sdists[0]})
        raise VerificationError(
            "pre-extraction release directory contains unexpected entries: "
            f"{unexpected}"
        )

    artifact_name = _artifact_distribution_name(config.name)
    expected_filename = f"{artifact_name}-{config.version}.tar.gz"
    if sdists[0].name != expected_filename:
        raise VerificationError(
            f"source-distribution filename {sdists[0].name!r} does not identify "
            f"{config.name} {config.version}"
        )

    inspection = _inspect_sdist(
        sdists[0],
        config=config,
    )
    artifact_name_value, artifact_version = inspection.identity
    if _normalize_name(artifact_name_value) != _normalize_name(config.name):
        raise VerificationError(
            f"source distribution Name {artifact_name_value!r} does not match "
            f"project.name {config.name!r}"
        )
    if artifact_version != config.version:
        raise VerificationError(
            f"source distribution Version {artifact_version!r} does not match "
            f"project.version {config.version!r}"
        )
    return sdists[0]


def extract_sdist(
    project_path: Path,
    dist_path: Path,
    output_path: Path,
    tag: str | None = None,
) -> Path:
    """Verify and extract an sdist with the same bounded streaming parser."""

    sdist = verify_sdist(project_path, dist_path, tag)
    config = _release_config(project_path, tag)
    try:
        output_path.mkdir(mode=0o700, parents=False, exist_ok=False)
    except OSError as exc:
        raise VerificationError(
            f"safe extraction output must be a new directory: {exc}"
        ) from exc
    _inspect_sdist(sdist, config=config, extract_to=output_path)
    expected_root = (
        f"{_artifact_distribution_name(config.name)}-"
        f"{_artifact_version_name(config.version)}"
    )
    extracted_root = output_path / expected_root
    if not extracted_root.is_dir() or extracted_root.is_symlink():
        raise VerificationError(
            "safe extraction did not produce the expected source root"
        )
    return extracted_root


def verify_artifacts(
    project_path: Path, dist_path: Path, tag: str | None = None
) -> tuple[Path, Path]:
    config = _release_config(project_path, tag)

    wheels = sorted(dist_path.glob("*.whl"))
    sdists = sorted(dist_path.glob("*.tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        raise VerificationError(
            "release directory must contain exactly one wheel and one source "
            f"distribution; found {len(wheels)} wheel(s) and {len(sdists)} sdist(s)"
        )
    try:
        entries = set(dist_path.iterdir())
    except OSError as exc:
        raise VerificationError(f"cannot inspect release directory: {exc}") from exc
    expected_entries = {wheels[0], sdists[0]}
    if entries != expected_entries:
        unexpected = sorted(path.name for path in entries - expected_entries)
        raise VerificationError(
            "release directory contains unexpected entries before checksums: "
            f"{unexpected}"
        )

    artifact_name = _artifact_distribution_name(config.name)
    expected_wheel_name = f"{artifact_name}-{config.version}-py3-none-any.whl"
    expected_sdist_name = f"{artifact_name}-{config.version}.tar.gz"
    if wheels[0].name != expected_wheel_name:
        raise VerificationError(
            f"wheel filename {wheels[0].name!r} does not match the expected "
            f"pure-Python artifact {expected_wheel_name!r}"
        )
    if sdists[0].name != expected_sdist_name:
        raise VerificationError(
            f"source-distribution filename {sdists[0].name!r} does not identify "
            f"{config.name} {config.version}"
        )

    sdist_inspection = _inspect_sdist(sdists[0], config=config)
    sdist_name, sdist_version = sdist_inspection.identity
    if _normalize_name(sdist_name) != _normalize_name(config.name):
        raise VerificationError(
            f"source distribution Name {sdist_name!r} does not match "
            f"project.name {config.name!r}"
        )
    if sdist_version != config.version:
        raise VerificationError(
            f"source distribution Version {sdist_version!r} does not match "
            f"project.version {config.version!r}"
        )
    wheel_identity = _wheel_identity(
        wheels[0],
        config=config,
        sdist_metadata_payload=sdist_inspection.metadata_payload,
        sdist_module_payloads=sdist_inspection.module_payloads,
    )
    identity_name, identity_version = wheel_identity
    if _normalize_name(identity_name) != _normalize_name(config.name):
        raise VerificationError(
            f"wheel Name {identity_name!r} does not match "
            f"project.name {config.name!r}"
        )
    if identity_version != config.version:
        raise VerificationError(
            f"wheel Version {identity_version!r} does not match "
            f"project.version {config.version!r}"
        )
    return wheels[0], sdists[0]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Verify release-tag and distribution-artifact identity."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    tag_parser = subparsers.add_parser(
        "tag", help="verify that a release tag identifies project.version"
    )
    tag_parser.add_argument("--project", required=True, type=Path)
    tag_parser.add_argument("--tag", required=True)

    artifacts_parser = subparsers.add_parser(
        "artifacts", help="verify exactly one wheel and sdist plus their metadata"
    )
    artifacts_parser.add_argument("--project", required=True, type=Path)
    artifacts_parser.add_argument("--dist", required=True, type=Path)
    artifacts_parser.add_argument("--tag")

    sdist_parser = subparsers.add_parser(
        "sdist",
        help="verify the sole source distribution before extracting it",
    )
    sdist_parser.add_argument("--project", required=True, type=Path)
    sdist_parser.add_argument("--dist", required=True, type=Path)
    sdist_parser.add_argument("--tag")

    extract_parser = subparsers.add_parser(
        "extract-sdist",
        help="verify and safely extract the sole source distribution",
    )
    extract_parser.add_argument("--project", required=True, type=Path)
    extract_parser.add_argument("--dist", required=True, type=Path)
    extract_parser.add_argument("--output", required=True, type=Path)
    extract_parser.add_argument("--tag")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "tag":
            name, version = verify_tag(args.project, args.tag)
            print(f"release identity verified: {name} {version} ({args.tag})")
        elif args.command == "sdist":
            sdist = verify_sdist(args.project, args.dist, args.tag)
            print(f"source distribution verified before extraction: {sdist.name}")
        elif args.command == "extract-sdist":
            root = extract_sdist(
                args.project,
                args.dist,
                args.output,
                args.tag,
            )
            print(f"source distribution safely extracted: {root}")
        else:
            wheel, sdist = verify_artifacts(args.project, args.dist, args.tag)
            print(
                "release artifacts verified: "
                f"wheel={wheel.name}; sdist={sdist.name}"
            )
    except VerificationError as exc:
        print(f"release verification failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
