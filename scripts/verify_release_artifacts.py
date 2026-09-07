"""Verify that release tags and distribution artifacts describe one release.

This script intentionally uses only the Python standard library so the release
workflow can run it before installing project dependencies.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
import csv
from dataclasses import dataclass
from email.parser import Parser
import gzip
import hashlib
import fnmatch
from io import BytesIO, StringIO
import os
import re
import shlex
import stat
import struct
import subprocess
import sys
import tarfile
import threading
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
_USTAR_MAGIC_VERSION = b"ustar\x0000"
_SUPPORTED_CORE_METADATA_VERSION = "2.4"
_SUPPORTED_WHEEL_VERSION = "1.0"
_GENERATED_SETUP_CFG = b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
_TRUSTED_GIT_EXECUTABLE = Path("/usr/bin/git")
_FULL_GIT_OBJECT_PATTERN = re.compile(r"[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}")
_ASCII_OWS = " \t"
_STATIC_CORE_METADATA_FIELDS = (
    "Summary",
    "License-Expression",
    "Project-URL",
    "Keywords",
    "Classifier",
    "Description-Content-Type",
    "License-File",
    "Dynamic",
)
_ALLOWED_CORE_METADATA_FIELDS = {
    "metadata-version",
    "name",
    "version",
    "requires-python",
    "provides-extra",
    "requires-dist",
    *(field.casefold() for field in _STATIC_CORE_METADATA_FIELDS),
}


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
    wheel_data_payloads: dict[str, bytes]
    sdist_source_payloads: dict[str, bytes]
    core_metadata_fields: dict[str, tuple[str, ...]]
    description_body: str


@dataclass(frozen=True)
class _SdistInspection:
    identity: tuple[str, str]
    metadata_payload: bytes
    module_payloads: dict[str, bytes]


@dataclass(frozen=True)
class _ImmutableGitSnapshot:
    payloads: dict[str, bytes]
    entries: dict[str, tuple[str, str]]


def _validate_single_gzip_member(sdist_path: Path) -> None:
    """Validate one bounded gzip member with no trailing compressed payload.

    ``gzip.GzipFile`` deliberately concatenates valid gzip members.  That is
    useful for general-purpose decompression but would let a release backend
    append bytes outside the exact tar manifest.  Validate the first member
    directly with zlib and require it to consume the complete artifact before
    tar traversal begins.
    """

    try:
        with sdist_path.open("rb") as source:
            header = source.read(10)
            if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
                raise VerificationError(
                    "source distribution does not use a canonical gzip header"
                )
            flags = header[3]
            if flags not in {0, 0x08}:
                raise VerificationError(
                    "source distribution gzip header contains unsupported "
                    "optional or reserved fields"
                )
            if header[8] not in {0, 2, 4} or header[9] != 255:
                raise VerificationError(
                    "source distribution does not use the supported gzip profile"
                )
            if flags == 0x08:
                expected_name = sdist_path.name.removesuffix(".gz").encode("ascii")
                encoded_name = bytearray()
                while len(encoded_name) <= MAX_ARCHIVE_COMPONENT_BYTES:
                    character = source.read(1)
                    if not character:
                        raise VerificationError(
                            "source distribution gzip file name is truncated"
                        )
                    if character == b"\0":
                        break
                    encoded_name.extend(character)
                else:
                    raise VerificationError(
                        "source distribution gzip file name exceeds the limit"
                    )
                if bytes(encoded_name) != expected_name:
                    raise VerificationError(
                        "source distribution gzip file name does not match "
                        "the artifact"
                    )
    except VerificationError:
        raise
    except (OSError, UnicodeEncodeError) as exc:
        raise VerificationError(
            f"cannot validate source-distribution gzip header: {exc}"
        ) from exc

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


def _tar_octal_size(field: bytes) -> int:
    """Parse the canonical POSIX-octal size field used by release sdists."""

    # The supported setuptools/tarfile builder emits exactly eleven octal
    # digits followed by one NUL.  Accepting leading spaces, multiple
    # terminators, an all-space field, or twelve unterminated digits would
    # broaden the raw grammar before TarInfo parses the same bytes.
    if (
        len(field) != 12
        or field[-1:] != b"\0"
        or any(character not in b"01234567" for character in field[:-1])
    ):
        raise VerificationError(
            "source distribution contains a non-canonical tar size"
        )
    return int(field[:-1], 8)


def _validate_tar_header_profiles(sdist_path: Path) -> None:
    """Reject non-USTAR headers before tarfile parses its first member.

    This preflight deliberately defers truncated payloads to the bounded
    parser and full framing validator below. Its sole job is to reach every
    header tarfile could parse and bind its format and size grammar before
    ``TarInfo.frombuf`` can apply a different one.
    """

    consumed = 0
    try:
        with gzip.open(sdist_path, "rb") as source:
            while True:
                header = source.read(tarfile.BLOCKSIZE)
                consumed += len(header)
                if consumed > MAX_SDIST_DECOMPRESSED_BYTES:
                    raise VerificationError(
                        "source distribution exceeds the decompressed traversal limit"
                    )
                if len(header) != tarfile.BLOCKSIZE or not any(header):
                    return
                if header[257:265] != _USTAR_MAGIC_VERSION:
                    raise VerificationError(
                        "source distribution contains a non-USTAR raw header"
                    )
                # Pin the size grammar here too: tarfile accepts base-256
                # values that this release format does not. Returning on such
                # a field could let tarfile skip its payload and reach a later
                # header that this preflight never inspected.
                size = _tar_octal_size(header[124:136])
                if size > MAX_SDIST_MEMBER_BYTES:
                    raise VerificationError(
                        "source distribution member exceeds the size limit"
                    )
                remaining = ((size + tarfile.BLOCKSIZE - 1) // tarfile.BLOCKSIZE) * (
                    tarfile.BLOCKSIZE
                )
                while remaining:
                    chunk = source.read(min(remaining, 1024 * 1024))
                    consumed += len(chunk)
                    if consumed > MAX_SDIST_DECOMPRESSED_BYTES:
                        raise VerificationError(
                            "source distribution exceeds the decompressed "
                            "traversal limit"
                        )
                    if not chunk:
                        return
                    remaining -= len(chunk)
    except VerificationError:
        raise
    except (OSError, EOFError, ValueError) as exc:
        raise VerificationError(
            f"cannot validate source-distribution tar headers: {exc}"
        ) from exc


def _validate_tar_zero_padding(sdist_path: Path) -> None:
    """Validate raw USTAR headers, padding, and the final tar record."""

    consumed = 0

    def read_exact(source: BinaryIO, size: int) -> bytes:
        nonlocal consumed
        payload = source.read(size)
        consumed += len(payload)
        if consumed > MAX_SDIST_DECOMPRESSED_BYTES:
            raise VerificationError(
                "source distribution exceeds the decompressed traversal limit"
            )
        if len(payload) != size:
            raise VerificationError("source distribution contains a truncated tar")
        return payload

    try:
        with gzip.open(sdist_path, "rb") as source:
            zero_headers = 0
            while True:
                header = read_exact(source, tarfile.BLOCKSIZE)
                if not any(header):
                    zero_headers += 1
                    if zero_headers < 2:
                        continue
                    while trailing := source.read(1024 * 1024):
                        consumed += len(trailing)
                        if consumed > MAX_SDIST_DECOMPRESSED_BYTES:
                            raise VerificationError(
                                "source distribution exceeds the decompressed "
                                "traversal limit"
                            )
                        if any(trailing):
                            raise VerificationError(
                                "source distribution contains non-zero data in "
                                "the final tar record"
                            )
                    if consumed % tarfile.RECORDSIZE:
                        raise VerificationError(
                            "source distribution has a non-canonical final tar "
                            "record length"
                        )
                    return
                if zero_headers:
                    raise VerificationError(
                        "source distribution contains data after a tar end marker"
                    )
                # TarInfo.frombuf accepts V7, GNU, and unknown magic/version
                # profiles and can still join their name/prefix fields using
                # USTAR semantics. Other extractors select the format from
                # these bytes and may interpret the same split path
                # differently. Pin the one archive grammar emitted by the
                # supported builder before tarfile parses any raw header.
                if header[257:265] != _USTAR_MAGIC_VERSION:
                    raise VerificationError(
                        "source distribution contains a non-USTAR raw header"
                    )
                size = _tar_octal_size(header[124:136])
                if size > MAX_SDIST_MEMBER_BYTES:
                    raise VerificationError(
                        "source distribution member exceeds the size limit"
                    )
                full_blocks = size // tarfile.BLOCKSIZE
                remainder = size % tarfile.BLOCKSIZE
                for _ in range(full_blocks):
                    read_exact(source, tarfile.BLOCKSIZE)
                if remainder:
                    final_block = read_exact(source, tarfile.BLOCKSIZE)
                    if any(final_block[remainder:]):
                        raise VerificationError(
                            "source distribution contains non-zero member padding"
                        )
    except VerificationError:
        raise
    except (OSError, EOFError, ValueError) as exc:
        raise VerificationError(
            f"cannot validate source-distribution tar framing: {exc}"
        ) from exc


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
        # GNU longname/longlink headers are consumed recursively by tarfile
        # before the resulting member reaches the manifest-validation loop.
        # Consecutive headers can therefore create a parser differential: the
        # stdlib reports the outer value while another extractor can apply the
        # inner value.  Release sdists do not need either GNU extension, so
        # reject them at the raw-header boundary before reading or applying
        # their payload.
        if self.type == tarfile.GNUTYPE_LONGNAME:
            raise VerificationError(
                "source distribution contains a GNU longname header"
            )
        if self.type == tarfile.GNUTYPE_LONGLINK:
            raise VerificationError(
                "source distribution contains a GNU longlink header"
            )
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
        or any(part in {"", ".", "..", "**"} for part in path.parts)
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


def _snapshot_glob(
    payloads: dict[str, bytes],
    pattern: str,
) -> list[str]:
    """Match a root-relative glob without consulting the mutable filesystem."""

    pattern_parts = PurePosixPath(pattern).parts
    return sorted(
        name
        for name in payloads
        if len(PurePosixPath(name).parts) == len(pattern_parts)
        and all(
            fnmatch.fnmatchcase(component, component_pattern)
            for component, component_pattern in zip(
                PurePosixPath(name).parts,
                pattern_parts,
            )
        )
    )


def _snapshot_recursive_glob(
    payloads: dict[str, bytes],
    directory: str,
    pattern: str,
) -> list[str]:
    pattern_parts = PurePosixPath(pattern).parts
    if len(pattern_parts) != 1:
        raise VerificationError(
            "MANIFEST.in recursive patterns must be single path components"
        )
    directory_parts = PurePosixPath(directory).parts
    component_pattern = pattern_parts[0]
    return sorted(
        name
        for name in payloads
        if len(PurePosixPath(name).parts) > len(directory_parts)
        and PurePosixPath(name).parts[: len(directory_parts)] == directory_parts
        and fnmatch.fnmatchcase(PurePosixPath(name).parts[-1], component_pattern)
    )


def _bounded_snapshot_payload(
    payloads: dict[str, bytes],
    relative_name: str,
    *,
    label: str,
    size_limit: int,
) -> bytes:
    try:
        payload = payloads[relative_name]
    except KeyError as exc:
        raise VerificationError(
            f"{label} is absent from the immutable source commit"
        ) from exc
    if len(payload) > size_limit:
        raise VerificationError(f"{label} exceeds the size limit")
    return payload


def _collect_snapshot_source_payloads(
    *,
    snapshot_payloads: dict[str, bytes],
    document: dict[str, object],
    modules: tuple[str, ...],
    license_patterns: list[str],
) -> dict[str, bytes]:
    """Resolve the sdist contract solely from immutable commit blobs."""

    selected: set[str] = set()

    def add(relative_name: str) -> None:
        _portable_member_key(
            relative_name,
            archive_label="immutable project source manifest",
        )
        if any(
            part.casefold().endswith(".egg-info")
            for part in PurePosixPath(relative_name).parts
        ):
            raise VerificationError(
                "immutable project source manifest selects generated metadata "
                f"{relative_name!r}"
            )
        _bounded_snapshot_payload(
            snapshot_payloads,
            relative_name,
            label=f"immutable project source {relative_name!r}",
            size_limit=MAX_SDIST_MEMBER_BYTES,
        )
        selected.add(relative_name)

    add("pyproject.toml")
    for module in modules:
        add(module.replace(".", "/") + ".py")

    project = document["project"]
    assert isinstance(project, dict)
    readme = project.get("readme")
    if isinstance(readme, str):
        _validate_manifest_pattern(readme, label="project.readme")
        add(readme)
    elif isinstance(readme, dict):
        readme_file = readme.get("file")
        if readme_file is not None:
            if not isinstance(readme_file, str):
                raise VerificationError("project.readme.file must be a string")
            _validate_manifest_pattern(readme_file, label="project.readme.file")
            add(readme_file)
    elif readme is not None:
        raise VerificationError("project.readme must be a string or table")

    for pattern in license_patterns:
        _validate_manifest_pattern(pattern, label="project.license-files")
        matches = _snapshot_glob(snapshot_payloads, pattern)
        if not matches:
            raise VerificationError(
                f"project.license-files pattern {pattern!r} matched no "
                "immutable commit files"
            )
        for match in matches:
            add(match)

    manifest_payload = snapshot_payloads.get("MANIFEST.in")
    if manifest_payload is not None:
        add("MANIFEST.in")
        try:
            manifest_lines = manifest_payload.decode("utf-8").splitlines()
        except UnicodeDecodeError as exc:
            raise VerificationError("MANIFEST.in is not UTF-8") from exc
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
                    _validate_manifest_pattern(
                        pattern,
                        label="MANIFEST.in include",
                    )
                    matches = _snapshot_glob(snapshot_payloads, pattern)
                    if not matches:
                        raise VerificationError(
                            "MANIFEST.in include pattern "
                            f"{pattern!r} matched no immutable commit files"
                        )
                    for match in matches:
                        add(match)
            elif directive == "recursive-include" and len(arguments) >= 2:
                directory, *patterns = arguments
                _validate_manifest_pattern(
                    directory,
                    label="MANIFEST.in recursive-include",
                )
                if not any(
                    PurePosixPath(name).parts[: len(PurePosixPath(directory).parts)]
                    == PurePosixPath(directory).parts
                    and len(PurePosixPath(name).parts)
                    > len(PurePosixPath(directory).parts)
                    for name in snapshot_payloads
                ):
                    raise VerificationError(
                        f"MANIFEST.in directory {directory!r} is absent from "
                        "the immutable commit"
                    )
                for pattern in patterns:
                    _validate_manifest_pattern(
                        pattern,
                        label="MANIFEST.in recursive pattern",
                    )
                    matches = _snapshot_recursive_glob(
                        snapshot_payloads,
                        directory,
                        pattern,
                    )
                    if not matches:
                        raise VerificationError(
                            "MANIFEST.in recursive pattern "
                            f"{directory!r} {pattern!r} matched no immutable "
                            "commit files"
                        )
                    for match in matches:
                        add(match)
            else:
                raise VerificationError(
                    f"unsupported MANIFEST.in directive on line {line_number}: "
                    f"{directive!r}"
                )

    total_size = sum(len(snapshot_payloads[name]) for name in selected)
    if total_size > MAX_SDIST_TOTAL_BYTES:
        raise VerificationError("trusted project sources exceed the total-size limit")
    return {name: snapshot_payloads[name] for name in sorted(selected)}


def _expected_static_core_metadata(
    project: dict[str, object],
    *,
    source_payloads: dict[str, bytes],
    license_payloads: dict[str, bytes],
) -> tuple[dict[str, tuple[str, ...]], str]:
    """Derive static Core Metadata fields from the trusted PEP 621 table."""

    expected: dict[str, tuple[str, ...]] = {}

    description = project.get("description")
    if description is not None:
        if not isinstance(description, str):
            raise VerificationError("project.description must be a string")
        expected["Summary"] = (description,)

    license_expression = project.get("license")
    if license_expression is not None:
        if not isinstance(license_expression, str) or not license_expression:
            raise VerificationError(
                "project.license must be a non-empty SPDX expression string"
            )
        expected["License-Expression"] = (license_expression,)

    keywords = project.get("keywords", [])
    if not isinstance(keywords, list) or any(
        not isinstance(value, str) or not value for value in keywords
    ):
        raise VerificationError("project.keywords must be a string list")
    if keywords:
        expected["Keywords"] = (",".join(keywords),)

    classifiers = project.get("classifiers", [])
    if not isinstance(classifiers, list) or any(
        not isinstance(value, str) or not value for value in classifiers
    ):
        raise VerificationError("project.classifiers must be a string list")
    if classifiers:
        expected["Classifier"] = tuple(classifiers)

    urls = project.get("urls", {})
    if not isinstance(urls, dict) or any(
        not isinstance(label, str)
        or not label
        or not isinstance(url, str)
        or not url
        for label, url in urls.items()
    ):
        raise VerificationError("project.urls must map labels to URL strings")
    if urls:
        expected["Project-URL"] = tuple(
            f"{label}, {url}" for label, url in urls.items()
        )

    description_body = ""
    readme = project.get("readme")
    if isinstance(readme, str):
        try:
            description_body = source_payloads[readme].decode("utf-8")
        except KeyError as exc:
            raise VerificationError(
                "project.readme is absent from the trusted source contract"
            ) from exc
        except UnicodeDecodeError as exc:
            raise VerificationError("project.readme is not UTF-8") from exc
        suffix = PurePosixPath(readme).suffix.casefold()
        content_type = {
            ".md": "text/markdown",
            ".rst": "text/x-rst",
            ".txt": "text/plain",
        }.get(suffix)
        if content_type is None:
            raise VerificationError(
                "project.readme needs a recognized extension or explicit "
                "content-type"
            )
        expected["Description-Content-Type"] = (content_type,)
    elif isinstance(readme, dict):
        content_type = readme.get("content-type")
        if not isinstance(content_type, str) or not content_type:
            raise VerificationError(
                "project.readme table must define a content-type"
            )
        readme_file = readme.get("file")
        readme_text = readme.get("text")
        if (readme_file is None) == (readme_text is None):
            raise VerificationError(
                "project.readme table must define exactly one of file or text"
            )
        if readme_file is not None:
            if not isinstance(readme_file, str):
                raise VerificationError("project.readme.file must be a string")
            try:
                description_body = source_payloads[readme_file].decode("utf-8")
            except (KeyError, UnicodeDecodeError) as exc:
                raise VerificationError(
                    "project.readme.file is absent or not UTF-8"
                ) from exc
        else:
            if not isinstance(readme_text, str):
                raise VerificationError("project.readme.text must be a string")
            description_body = readme_text
        expected["Description-Content-Type"] = (content_type,)
    elif readme is not None:
        raise VerificationError("project.readme must be a string or table")

    license_files = tuple(
        name.removeprefix("licenses/") for name in license_payloads
    )
    if license_files:
        expected["License-File"] = license_files

    dynamic = project.get("dynamic", [])
    if not isinstance(dynamic, list) or any(
        not isinstance(value, str) or not value for value in dynamic
    ):
        raise VerificationError("project.dynamic must be a string list")
    expected_dynamic = list(dynamic)
    if license_files and "license-file" not in expected_dynamic:
        expected_dynamic.append("license-file")
    if expected_dynamic:
        expected["Dynamic"] = tuple(expected_dynamic)

    return expected, description_body


def _project_release_config(
    project_path: Path,
    *,
    immutable_source_payloads: dict[str, bytes] | None = None,
) -> _ProjectReleaseConfig:
    """Read the exact wheel payload contract from ``pyproject.toml``."""

    try:
        if immutable_source_payloads is None:
            with project_path.open("rb") as project_file:
                document = tomllib.load(project_file)
        else:
            project_payload = _bounded_snapshot_payload(
                immutable_source_payloads,
                "pyproject.toml",
                label="immutable pyproject.toml",
                size_limit=MAX_SDIST_MEMBER_BYTES,
            )
            document = tomllib.loads(project_payload.decode("utf-8"))
        project = document["project"]
        setuptools = document["tool"]["setuptools"]
        name = project["name"]
        version = project["version"]
        modules_value = setuptools["py-modules"]
        data_files_value = setuptools.get("data-files", {})
        scripts_value = project["scripts"]
        license_patterns = project["license-files"]
        requires_python = project["requires-python"]
        dependencies_value = project["dependencies"]
        optional_dependencies_value = project.get("optional-dependencies", {})
    except (
        OSError,
        KeyError,
        TypeError,
        UnicodeDecodeError,
        tomllib.TOMLDecodeError,
    ) as exc:
        raise VerificationError(
            f"cannot read project release configuration: {exc}"
        ) from exc
    if not isinstance(name, str) or not name:
        raise VerificationError("project.name must be a non-empty string")
    if not isinstance(version, str) or not version:
        raise VerificationError("project.version must be a non-empty string")
    if not isinstance(requires_python, str) or not requires_python:
        raise VerificationError("project.requires-python must be a non-empty string")
    _validate_ascii_pep508(
        requires_python,
        label="project.requires-python",
    )
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
    if not isinstance(data_files_value, dict) or any(
        not isinstance(destination, str)
        or not destination
        or not isinstance(sources, list)
        or not sources
        or any(not isinstance(source, str) or not source for source in sources)
        for destination, sources in data_files_value.items()
    ):
        raise VerificationError(
            "tool.setuptools.data-files must map destinations to non-empty "
            "string lists"
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
    script_name_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*", re.ASCII)
    script_target_pattern = re.compile(
        r"[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*"
        r":[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*",
        re.ASCII,
    )
    for script_name, script_target in scripts.items():
        if (
            _ascii_control_value(
                script_name,
                label="project.scripts command name",
            )
            != script_name
            or _ascii_control_value(
                script_target,
                label=f"project.scripts target for {script_name!r}",
            )
            != script_target
            or script_name_pattern.fullmatch(script_name) is None
            or script_target_pattern.fullmatch(script_target) is None
        ):
            raise VerificationError(
                "project.scripts contains an unsafe command name or target"
            )
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
    if immutable_source_payloads is None:
        sdist_source_payloads = _collect_project_source_payloads(
            project_path,
            document=document,
            modules=modules,
            license_patterns=license_patterns,
        )
    else:
        sdist_source_payloads = _collect_snapshot_source_payloads(
            snapshot_payloads=immutable_source_payloads,
            document=document,
            modules=modules,
            license_patterns=license_patterns,
        )
    module_payloads: dict[str, bytes] = {}
    for module in modules:
        member_name = module.replace(".", "/") + ".py"
        _portable_member_key(member_name, archive_label="project module")
        if immutable_source_payloads is None:
            module_payloads[member_name] = _read_bounded_project_file(
                project_root / member_name,
                label=f"project module {member_name!r}",
                size_limit=MAX_PROJECT_MODULE_BYTES,
            )
        else:
            module_payloads[member_name] = _bounded_snapshot_payload(
                immutable_source_payloads,
                member_name,
                label=f"immutable project module {member_name!r}",
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
        if immutable_source_payloads is None:
            try:
                matches = sorted(project_root.glob(pattern))
            except (OSError, ValueError) as exc:
                raise VerificationError(
                    f"cannot expand license-file pattern {pattern!r}: {exc}"
                ) from exc
            regular_matches: list[Path | str] = []
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
        else:
            regular_matches = _snapshot_glob(
                immutable_source_payloads,
                pattern,
            )
        if not regular_matches:
            raise VerificationError(
                f"project.license-files pattern {pattern!r} matched no files"
            )
        for match in regular_matches:
            if isinstance(match, Path):
                try:
                    relative = match.relative_to(project_root).as_posix()
                except ValueError as exc:
                    raise VerificationError(
                        f"license file {match} escapes the project root"
                    ) from exc
                license_payload = _read_bounded_project_file(
                    match,
                    label=f"project license file {relative!r}",
                    size_limit=MAX_LICENSE_BYTES,
                )
            else:
                relative = match
                license_payload = _bounded_snapshot_payload(
                    immutable_source_payloads,
                    relative,
                    label=f"immutable project license file {relative!r}",
                    size_limit=MAX_LICENSE_BYTES,
                )
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
            license_payloads[wheel_member] = license_payload

    wheel_data_payloads: dict[str, bytes] = {}
    portable_data_members: set[str] = set()
    for destination, sources in data_files_value.items():
        destination_path = PurePosixPath(destination)
        documentation_root = ("share", "doc", name)
        if (
            destination_path.is_absolute()
            or "\\" in destination
            or any(part in {"", ".", ".."} for part in destination_path.parts)
            or destination_path.parts[:3] != documentation_root
            or any(
                part.casefold().endswith((".data", ".dist-info"))
                for part in destination_path.parts
            )
        ):
            raise VerificationError(
                "tool.setuptools.data-files must stay under the project "
                "documentation root and contains an unsafe destination "
                f"{destination!r}"
            )
        for source in sources:
            _validate_manifest_pattern(
                source,
                label="tool.setuptools.data-files source",
            )
            if any(character in source for character in "*?["):
                raise VerificationError(
                    "tool.setuptools.data-files sources must be exact paths"
                )
            source_path = PurePosixPath(source)
            member = f"{destination}/{source_path.name}"
            portable = _portable_member_key(
                member,
                archive_label="project wheel data payload",
            )
            if member in wheel_data_payloads or portable in portable_data_members:
                raise VerificationError(
                    "tool.setuptools.data-files selects a duplicate wheel "
                    f"payload {member!r}"
                )
            try:
                payload = sdist_source_payloads[source]
            except KeyError as exc:
                raise VerificationError(
                    "tool.setuptools.data-files source is absent from the "
                    f"source-distribution contract: {source!r}"
                ) from exc
            if len(payload) > MAX_WHEEL_MEMBER_BYTES:
                raise VerificationError(
                    f"wheel data payload exceeds the size limit: {source!r}"
                )
            wheel_data_payloads[member] = payload
            portable_data_members.add(portable)

    core_metadata_fields, description_body = _expected_static_core_metadata(
        project,
        source_payloads=sdist_source_payloads,
        license_payloads=license_payloads,
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
        wheel_data_payloads=wheel_data_payloads,
        sdist_source_payloads=sdist_source_payloads,
        core_metadata_fields=core_metadata_fields,
        description_body=description_body,
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


def _run_git(
    repository: Path,
    *arguments: str,
    output_limit: int = MAX_SDIST_TOTAL_BYTES,
) -> bytes:
    try:
        git_stat = _TRUSTED_GIT_EXECUTABLE.lstat()
    except OSError as exc:
        raise VerificationError(
            f"trusted git executable is unavailable: {exc}"
        ) from exc
    if (
        not stat.S_ISREG(git_stat.st_mode)
        or git_stat.st_uid != 0
        or bool(git_stat.st_mode & 0o022)
        or not os.access(_TRUSTED_GIT_EXECUTABLE, os.X_OK)
    ):
        raise VerificationError(
            "trusted git executable must be a root-owned, non-writable, "
            "executable regular file at /usr/bin/git"
        )
    # Construct an allowlisted environment instead of trying to enumerate all
    # Git, dynamic-loader, locale, pager, remote-helper, and tracing knobs that
    # an earlier untrusted build step could have set.
    environment = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "LANG": "C",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_LITERAL_PATHSPECS": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }

    def drain_bounded(
        stream: BinaryIO,
        limit: int,
        result: dict[str, bytes | bool | BaseException],
        key: str,
    ) -> None:
        chunks: list[bytes] = []
        retained = 0
        exceeded = False
        try:
            while chunk := stream.read(64 * 1024):
                remaining = limit + 1 - retained
                if remaining > 0:
                    kept = chunk[:remaining]
                    chunks.append(kept)
                    retained += len(kept)
                if retained > limit or len(chunk) > max(remaining, 0):
                    exceeded = True
        except BaseException as exc:  # pragma: no cover - defensive pipe boundary
            result[f"{key}_error"] = exc
        finally:
            try:
                stream.close()
            except OSError:
                pass
        result[key] = b"".join(chunks)
        result[f"{key}_exceeded"] = exceeded

    try:
        process = subprocess.Popen(
            [
                os.fspath(_TRUSTED_GIT_EXECUTABLE),
                "--no-pager",
                "--no-replace-objects",
                "-c",
                "core.fsmonitor=false",
                "-c",
                f"core.hooksPath={os.devnull}",
                "-c",
                "diff.external=",
                "-c",
                "protocol.allow=never",
                "-c",
                "protocol.ext.allow=never",
                "-c",
                "protocol.file.allow=never",
                "-C",
                os.fspath(repository),
                *arguments,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
    except (OSError, ValueError) as exc:
        raise VerificationError(f"cannot execute git: {exc}") from exc
    assert process.stdout is not None
    assert process.stderr is not None
    pipe_result: dict[str, bytes | bool | BaseException] = {}
    stdout_thread = threading.Thread(
        target=drain_bounded,
        args=(process.stdout, output_limit, pipe_result, "stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=drain_bounded,
        args=(process.stderr, 4096, pipe_result, "stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()
    return_code = process.wait()
    stdout_thread.join()
    stderr_thread.join()
    pipe_error = pipe_result.get("stdout_error") or pipe_result.get("stderr_error")
    if isinstance(pipe_error, BaseException):
        raise VerificationError(f"cannot read git output: {pipe_error}") from pipe_error
    stdout = pipe_result.get("stdout", b"")
    stderr = pipe_result.get("stderr", b"")
    assert isinstance(stdout, bytes)
    assert isinstance(stderr, bytes)
    if return_code != 0:
        detail = stderr.decode("utf-8", "replace").strip()
        if pipe_result.get("stderr_exceeded"):
            detail += " [stderr truncated]"
        raise VerificationError(
            f"git {' '.join(arguments[:2])} failed: {detail or 'unknown error'}"
        )
    if pipe_result.get("stdout_exceeded"):
        raise VerificationError("git output exceeds the release-verification limit")
    return stdout


def _canonical_git_repository(repository: Path) -> Path:
    try:
        canonical = repository.resolve(strict=True)
    except OSError as exc:
        raise VerificationError(f"cannot resolve source repository: {exc}") from exc
    top_level_payload = _run_git(
        canonical,
        "rev-parse",
        "--show-toplevel",
        output_limit=MAX_ARCHIVE_PATH_BYTES,
    )
    try:
        top_level_text = top_level_payload.decode("utf-8")
        if top_level_text.endswith("\n"):
            top_level_text = top_level_text[:-1]
            if top_level_text.endswith("\r"):
                top_level_text = top_level_text[:-1]
        if not top_level_text or "\n" in top_level_text or "\r" in top_level_text:
            raise VerificationError(
                "git repository top level contains an ambiguous newline"
            )
        top_level = Path(top_level_text).resolve(strict=True)
    except VerificationError:
        raise
    except (OSError, UnicodeDecodeError) as exc:
        raise VerificationError(
            f"cannot resolve git repository top level: {exc}"
        ) from exc
    if top_level != canonical:
        raise VerificationError(
            "--repository must identify the exact git worktree top level"
        )
    return canonical


def _resolve_exact_source_commit(repository: Path, source_commit: str) -> str:
    if _FULL_GIT_OBJECT_PATTERN.fullmatch(source_commit) is None:
        raise VerificationError(
            "--source-commit must be a complete hexadecimal commit object ID"
        )
    resolved = _run_git(
        repository,
        "rev-parse",
        "--verify",
        f"{source_commit}^{{commit}}",
        output_limit=256,
    ).decode("ascii").strip()
    if resolved.casefold() != source_commit.casefold():
        raise VerificationError(
            "--source-commit must identify the exact commit object, not a tag "
            "or another indirect object"
        )
    head = _run_git(
        repository,
        "rev-parse",
        "--verify",
        "HEAD^{commit}",
        output_limit=256,
    ).decode("ascii").strip()
    if head != resolved:
        raise VerificationError(
            "checked-out HEAD does not exactly match --source-commit"
        )
    return resolved


def _allowed_generated_untracked_path(path: str, *, egg_info_root: str) -> bool:
    parts = PurePosixPath(path).parts
    if not parts:
        return False
    if parts[0] in {
        "dist",
        "build",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
    }:
        return True
    if "__pycache__" in parts:
        return True
    return parts[0].casefold() == egg_info_root.casefold()


def _verify_git_worktree_state(
    repository: Path,
    *,
    source_commit: str,
    egg_info_root: str,
    project_path: Path,
    immutable_payloads: dict[str, bytes],
    immutable_entries: dict[str, tuple[str, str]],
) -> None:
    project_root, project_directory, tree_path = _resolved_project_location(
        repository,
        project_path,
    )
    commit_tree = immutable_entries
    index_payload = _run_git(
        repository,
        "ls-files",
        "--stage",
        "-z",
        "--",
        tree_path,
        output_limit=MAX_SDIST_TOTAL_BYTES,
    )
    index_tree: dict[str, tuple[str, str]] = {}
    for record in (value for value in index_payload.split(b"\0") if value):
        try:
            metadata, raw_name = record.split(b"\t", 1)
            raw_mode, raw_object_id, raw_stage = metadata.split()
            repository_name = raw_name.decode("utf-8")
            mode = raw_mode.decode("ascii")
            object_id = raw_object_id.decode("ascii")
            stage = raw_stage.decode("ascii")
        except (ValueError, UnicodeDecodeError) as exc:
            raise VerificationError("cannot parse git index entry") from exc
        _portable_member_key(repository_name, archive_label="git index")
        if stage != "0" or repository_name in index_tree:
            raise VerificationError(
                "release git index contains an unresolved or duplicate entry"
            )
        index_tree[repository_name] = (mode, object_id)
    if index_tree != commit_tree:
        raise VerificationError(
            "release git index does not exactly match the source commit tree"
        )
    for relative_name, committed_payload in immutable_payloads.items():
        working_payload = _read_bounded_project_file(
            project_root.joinpath(*PurePosixPath(relative_name).parts),
            label=f"tracked project source {relative_name!r}",
            size_limit=MAX_SDIST_MEMBER_BYTES,
        )
        if working_payload != committed_payload:
            raise VerificationError(
                "tracked project source differs from the exact source commit: "
                f"{relative_name!r}"
            )
        repository_name = (
            PurePosixPath(*project_directory.parts, *PurePosixPath(relative_name).parts)
            .as_posix()
        )
        expected_mode = commit_tree[repository_name][0]
        try:
            working_mode = project_root.joinpath(
                *PurePosixPath(relative_name).parts
            ).stat().st_mode
        except OSError as exc:
            raise VerificationError(
                f"cannot inspect tracked project source mode: {exc}"
            ) from exc
        executable = bool(working_mode & 0o111)
        if executable != (expected_mode == "100755"):
            raise VerificationError(
                "tracked project source mode differs from the exact source "
                f"commit: {relative_name!r}"
            )
    untracked_payload = _run_git(
        repository,
        "ls-files",
        "--others",
        "-z",
        output_limit=MAX_SDIST_TOTAL_BYTES,
    )
    try:
        untracked = [
            value.decode("utf-8")
            for value in untracked_payload.split(b"\0")
            if value
        ]
    except UnicodeDecodeError as exc:
        raise VerificationError(
            "release worktree contains a non-UTF-8 untracked path"
        ) from exc
    unexpected = []
    for path in untracked:
        _portable_member_key(path, archive_label="git untracked source")
        if not _allowed_generated_untracked_path(
            path,
            egg_info_root=egg_info_root,
        ):
            unexpected.append(path)
    if unexpected:
        raise VerificationError(
            "release worktree contains untracked source selection outside "
            f"generated build directories: {sorted(unexpected)}"
        )


def _resolved_project_location(
    repository: Path,
    project_path: Path,
) -> tuple[Path, PurePosixPath, str]:
    try:
        project_resolved = project_path.resolve(strict=True)
        project_relative = project_resolved.relative_to(repository)
    except (OSError, ValueError) as exc:
        raise VerificationError(
            "--project must resolve inside --repository without escaping it"
        ) from exc
    if project_relative.name != "pyproject.toml":
        raise VerificationError("--project must identify pyproject.toml")
    project_directory = PurePosixPath(*project_relative.parent.parts)
    tree_path = "." if not project_directory.parts else project_directory.as_posix()
    return project_resolved.parent, project_directory, tree_path


def _git_object_digest(kind: str, payload: bytes, *, hexadecimal_size: int) -> str:
    framed = f"{kind} {len(payload)}\0".encode("ascii") + payload
    if hexadecimal_size == 40:
        return hashlib.sha1(framed).hexdigest()
    if hexadecimal_size == 64:
        return hashlib.sha256(framed).hexdigest()
    raise VerificationError("unsupported git object format")


def _validated_git_object(
    repository: Path,
    *,
    object_type: str,
    object_id: str,
    hexadecimal_size: int,
    output_limit: int,
) -> bytes:
    payload = _run_git(
        repository,
        "cat-file",
        object_type,
        object_id,
        output_limit=output_limit,
    )
    actual_id = _git_object_digest(
        object_type,
        payload,
        hexadecimal_size=hexadecimal_size,
    )
    if actual_id != object_id.casefold():
        raise VerificationError(
            f"git {object_type} object content does not match its object ID"
        )
    return payload


def _parse_validated_git_tree(
    repository: Path,
    *,
    tree_id: str,
    hexadecimal_size: int,
) -> list[tuple[str, str, str]]:
    payload = _validated_git_object(
        repository,
        object_type="tree",
        object_id=tree_id,
        hexadecimal_size=hexadecimal_size,
        output_limit=MAX_SDIST_TOTAL_BYTES,
    )
    identifier_size = hexadecimal_size // 2
    entries: list[tuple[str, str, str]] = []
    names: set[str] = set()
    position = 0
    while position < len(payload):
        if len(entries) >= MAX_SDIST_MEMBERS:
            raise VerificationError(
                "immutable git tree exceeds the entry-count limit"
            )
        separator = payload.find(b" ", position)
        terminator = payload.find(b"\0", separator + 1)
        object_end = terminator + 1 + identifier_size
        if (
            separator <= position
            or terminator <= separator + 1
            or object_end > len(payload)
        ):
            raise VerificationError("immutable git tree object is malformed")
        try:
            mode = payload[position:separator].decode("ascii")
            name = payload[separator + 1 : terminator].decode("utf-8")
        except UnicodeDecodeError as exc:
            raise VerificationError(
                "immutable git tree contains a non-UTF-8 entry"
            ) from exc
        if (
            mode not in {"40000", "040000", "100644", "100755"}
            or not name
            or "/" in name
            or name in {".", ".."}
            or name in names
        ):
            raise VerificationError(
                f"immutable git tree contains an unsupported entry {name!r}"
            )
        names.add(name)
        object_id = payload[terminator + 1 : object_end].hex()
        entries.append((mode.removeprefix("0"), name, object_id))
        position = object_end
    return entries


def _immutable_commit_snapshot(
    repository: Path,
    *,
    source_commit: str,
    project_path: Path,
) -> _ImmutableGitSnapshot:
    _, project_directory, _ = _resolved_project_location(repository, project_path)
    hexadecimal_size = len(source_commit)
    commit_payload = _validated_git_object(
        repository,
        object_type="commit",
        object_id=source_commit,
        hexadecimal_size=hexadecimal_size,
        output_limit=MAX_SDIST_MEMBER_BYTES,
    )
    commit_headers = commit_payload.split(b"\n\n", 1)[0].splitlines()
    tree_headers = [line[5:] for line in commit_headers if line.startswith(b"tree ")]
    if len(tree_headers) != 1:
        raise VerificationError("immutable git commit has no unique root tree")
    try:
        tree_id = tree_headers[0].decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError("immutable git commit has an invalid tree ID") from exc
    if (
        len(tree_id) != hexadecimal_size
        or _FULL_GIT_OBJECT_PATTERN.fullmatch(tree_id) is None
    ):
        raise VerificationError("immutable git commit has an invalid tree ID")

    tree_cache: dict[str, list[tuple[str, str, str]]] = {}

    def parsed_tree(object_id: str) -> list[tuple[str, str, str]]:
        entries = tree_cache.get(object_id)
        if entries is None:
            entries = _parse_validated_git_tree(
                repository,
                tree_id=object_id,
                hexadecimal_size=hexadecimal_size,
            )
            tree_cache[object_id] = entries
        return entries

    if len(project_directory.parts) > MAX_SDIST_HEADER_DEPTH:
        raise VerificationError(
            "project path exceeds the immutable tree-depth limit"
        )
    for component in project_directory.parts:
        matching = [
            entry
            for entry in parsed_tree(tree_id)
            if entry[1] == component
        ]
        if len(matching) != 1 or matching[0][0] != "40000":
            raise VerificationError(
                "project directory is absent from the immutable git commit"
            )
        tree_id = matching[0][2]

    payloads: dict[str, bytes] = {}
    git_entries: dict[str, tuple[str, str]] = {}
    blob_cache: dict[str, bytes] = {}
    total_size = 0
    visited_entry_count = 0

    def visit_tree(
        current_tree: str,
        relative_parent: PurePosixPath,
        depth: int,
    ) -> None:
        nonlocal total_size, visited_entry_count
        if depth > MAX_SDIST_HEADER_DEPTH:
            raise VerificationError(
                "immutable source commit exceeds the tree-depth limit"
            )
        for mode, name, object_id in parsed_tree(current_tree):
            visited_entry_count += 1
            if visited_entry_count > MAX_SDIST_MEMBERS:
                raise VerificationError(
                    "immutable source commit exceeds the tree-entry-count limit"
                )
            relative_path = PurePosixPath(*relative_parent.parts, name)
            relative_name = relative_path.as_posix()
            _portable_member_key(
                relative_name,
                archive_label="immutable git source tree",
            )
            if mode == "40000":
                visit_tree(object_id, relative_path, depth + 1)
                continue
            if len(payloads) >= MAX_SDIST_MEMBERS:
                raise VerificationError(
                    "immutable source commit exceeds the member-count limit"
                )
            payload = blob_cache.get(object_id)
            if payload is None:
                payload = _validated_git_object(
                    repository,
                    object_type="blob",
                    object_id=object_id,
                    hexadecimal_size=hexadecimal_size,
                    output_limit=MAX_SDIST_MEMBER_BYTES,
                )
                blob_cache[object_id] = payload
            total_size += len(payload)
            if total_size > MAX_SDIST_TOTAL_BYTES:
                raise VerificationError(
                    "immutable source commit exceeds the total-size limit"
                )
            repository_name = PurePosixPath(
                *project_directory.parts,
                *relative_path.parts,
            ).as_posix()
            payloads[relative_name] = payload
            git_entries[repository_name] = (mode, object_id)

    visit_tree(tree_id, PurePosixPath(), 0)
    if "pyproject.toml" not in payloads:
        raise VerificationError(
            "pyproject.toml is absent from the immutable source commit"
        )
    return _ImmutableGitSnapshot(payloads=payloads, entries=git_entries)


def _verify_tag_commit(
    repository: Path,
    *,
    tag: str,
    source_commit: str,
) -> None:
    tag_commit = _run_git(
        repository,
        "rev-parse",
        "--verify",
        f"refs/tags/{tag}^{{commit}}",
        output_limit=256,
    ).decode("ascii").strip()
    if tag_commit != source_commit:
        raise VerificationError(
            f"release tag {tag!r} does not point to the exact source commit"
        )


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


def _verify_tag_identity(
    name: str,
    project_version: str,
    tag: str,
) -> tuple[str, str]:
    tag_version = _pep440_version_from_tag(tag)
    if tag_version != project_version:
        raise VerificationError(
            f"release tag {tag!r} identifies {tag_version!r}, "
            f"but project.version is {project_version!r}"
        )
    return name, project_version


def verify_tag(
    project_path: Path,
    tag: str,
    *,
    repository: Path | None = None,
    source_commit: str | None = None,
) -> tuple[str, str]:
    if repository is None and source_commit is None:
        name, project_version = _project_identity(project_path)
        return _verify_tag_identity(name, project_version, tag)
    config = _release_config(
        project_path,
        tag,
        repository=repository,
        source_commit=source_commit,
    )
    return config.name, config.version


def _validate_ascii_control_chars(value: str, *, label: str) -> None:
    if any(
        character != "\t" and not (0x20 <= ord(character) <= 0x7E)
        for character in value
    ):
        raise VerificationError(
            f"{label} contains non-ASCII or control material"
        )


def _ascii_control_value(value: str, *, label: str) -> str:
    """Return an ASCII SP/HTAB-trimmed release-control value."""

    _validate_ascii_control_chars(value, label=label)
    stripped = value.strip(_ASCII_OWS)
    if not stripped:
        raise VerificationError(f"{label} must be non-empty")
    return stripped


def _metadata_identity(metadata: str, label: str) -> tuple[str, str]:
    parsed = Parser().parsestr(metadata)
    names = parsed.get_all("Name", [])
    versions = parsed.get_all("Version", [])
    if len(names) != 1 or len(versions) != 1:
        raise VerificationError(
            f"{label} metadata must contain exactly one non-empty Name and Version"
        )
    return (
        _ascii_control_value(names[0], label=f"{label} Name"),
        _ascii_control_value(versions[0], label=f"{label} Version"),
    )


_REQUIREMENT_PATTERN = re.compile(
    r"[ \t]*(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"(?:\[(?P<extras>[A-Za-z0-9._-]+(?:[ \t]*,[ \t]*[A-Za-z0-9._-]+)*)\])?"
    r"[ \t]*(?P<specifiers>[^;]*)[ \t]*",
    flags=re.ASCII,
)
_SPECIFIER_PATTERN = re.compile(
    r"(===|~=|==|!=|<=|>=|<|>)[ \t]*([^, \t]+)",
    flags=re.ASCII,
)
_EXTRA_MARKER_PATTERN = re.compile(
    r"[ \t]*extra[ \t]*==[ \t]*(['\"])(?P<extra>[A-Za-z0-9._-]+)\1[ \t]*",
    flags=re.ASCII,
)


def _validate_ascii_pep508(value: str, *, label: str) -> None:
    r"""Reject Unicode and controls before parsing package requirement syntax.

    PEP 508's grammar is ASCII.  In particular, Python's Unicode-aware
    ``\s``/``isspace`` APIs must not make NBSP or another lookalike compare as
    an ordinary SP/HTAB separator in a signed release contract.
    """

    _validate_ascii_control_chars(value, label=label)


def _strip_ascii_ows(value: str) -> str:
    return value.strip(_ASCII_OWS)


def _canonical_requirement(
    requirement: str,
    *,
    label: str,
) -> tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]]:
    _validate_ascii_pep508(requirement, label=label)
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
            _normalize_name(_strip_ascii_ows(extra))
            for extra in extras_value.split(",")
        )
    ) if extras_value else ()
    specifier_text = _strip_ascii_ows(match.group("specifiers"))
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
            while (
                position < len(specifier_text)
                and specifier_text[position] in _ASCII_OWS
            ):
                position += 1
            if position == len(specifier_text):
                break
            if specifier_text[position] != ",":
                raise VerificationError(
                    f"{label} contains an unsupported version specifier"
                )
            position += 1
            while (
                position < len(specifier_text)
                and specifier_text[position] in _ASCII_OWS
            ):
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
    _validate_ascii_pep508(value, label=label)
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
        _validate_ascii_pep508(
            extra,
            label="project.optional-dependencies extra name",
        )
        if re.fullmatch(r"[A-Za-z0-9._-]+", extra, flags=re.ASCII) is None:
            raise VerificationError(
                "project.optional-dependencies contains an invalid extra name"
            )
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
    if parsed.defects:
        raise VerificationError(f"{label} metadata contains parser defects")
    unexpected_fields = sorted(
        {
            field
            for field in parsed.keys()
            if field.casefold() not in _ALLOWED_CORE_METADATA_FIELDS
        }
    )
    if unexpected_fields:
        raise VerificationError(
            f"{label} metadata contains unexpected fields: {unexpected_fields}"
        )

    def exactly_one(field: str) -> str:
        values = parsed.get_all(field, [])
        if len(values) != 1:
            raise VerificationError(
                f"{label} metadata must contain exactly one non-empty {field}"
            )
        return _ascii_control_value(
            values[0],
            label=f"{label} {field}",
        )

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

    for field in _STATIC_CORE_METADATA_FIELDS:
        actual_values = tuple(parsed.get_all(field, []))
        expected_values = config.core_metadata_fields.get(field, ())
        if actual_values != expected_values:
            raise VerificationError(
                f"{label} {field} does not exactly match the immutable "
                "project metadata"
            )
    payload_body = parsed.get_payload()
    if not isinstance(payload_body, str) or payload_body != config.description_body:
        raise VerificationError(
            f"{label} description body does not exactly match the immutable "
            "project readme"
        )

    provided_extras = parsed.get_all("Provides-Extra", [])
    normalized_provided: list[str] = []
    for value in provided_extras:
        stripped_value = _ascii_control_value(
            value,
            label=f"{label} Provides-Extra",
        )
        if (
            re.fullmatch(
                r"[A-Za-z0-9._-]+",
                stripped_value,
                flags=re.ASCII,
            )
            is None
        ):
            raise VerificationError(
                f"{label} Provides-Extra contains an invalid extra name"
            )
        normalized_provided.append(_normalize_name(stripped_value))
    expected_extras = sorted(
        _normalize_name(extra) for extra in config.optional_dependencies
    )
    if (
        len(normalized_provided) != len(set(normalized_provided))
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
    expected_data_root: str,
) -> set[str]:
    return {
        *config.module_payloads,
        *(f"{expected_root}/{member}" for member in config.license_payloads),
        *(
            f"{expected_data_root}/{member}"
            for member in config.wheel_data_payloads
        ),
        f"{expected_root}/METADATA",
        f"{expected_root}/WHEEL",
        f"{expected_root}/entry_points.txt",
        f"{expected_root}/top_level.txt",
        f"{expected_root}/RECORD",
    }


def _validate_canonical_wheel_zip(payload: bytes, wheel: ZipFile) -> None:
    """Bind the ZIP container to one canonical, gap-free wheel framing."""

    eocd_size = struct.calcsize("<4s4H2LH")
    if len(payload) < eocd_size or payload[:4] != b"PK\x03\x04":
        raise VerificationError("wheel contains a prefix or truncated ZIP framing")
    eocd_offset = len(payload) - eocd_size
    try:
        (
            signature,
            disk_number,
            central_disk,
            disk_entries,
            total_entries,
            central_size,
            central_offset,
            comment_size,
        ) = struct.unpack_from("<4s4H2LH", payload, eocd_offset)
    except struct.error as exc:
        raise VerificationError("wheel contains a malformed ZIP end record") from exc
    if (
        signature != b"PK\x05\x06"
        or disk_number != 0
        or central_disk != 0
        or disk_entries != total_entries
        or total_entries in {0xFFFF}
        or central_size == 0xFFFFFFFF
        or central_offset == 0xFFFFFFFF
        or comment_size != 0
        or central_offset + central_size != eocd_offset
    ):
        raise VerificationError(
            "wheel contains a non-canonical ZIP end or central-directory record"
        )

    infos = wheel.infolist()
    if total_entries != len(infos):
        raise VerificationError("wheel ZIP member count disagrees with its directory")

    central_cursor = central_offset
    central_header_size = struct.calcsize("<4s6H3L5H2L")
    for info in infos:
        if central_cursor + central_header_size > eocd_offset:
            raise VerificationError("wheel central directory is truncated")
        try:
            (
                central_signature,
                created_version,
                extracted_version,
                flags,
                compression,
                _modified_time,
                _modified_date,
                crc,
                compressed_size,
                file_size,
                name_size,
                extra_size,
                member_comment_size,
                member_disk,
                _internal_attributes,
                external_attributes,
                local_offset,
            ) = struct.unpack_from(
                "<4s6H3L5H2L",
                payload,
                central_cursor,
            )
        except struct.error as exc:
            raise VerificationError("wheel central directory is malformed") from exc
        name_start = central_cursor + central_header_size
        name_end = name_start + name_size
        entry_end = name_end + extra_size + member_comment_size
        try:
            expected_name = info.filename.encode("ascii")
        except UnicodeEncodeError as exc:
            raise VerificationError("wheel member names must be ASCII") from exc
        if (
            central_signature != b"PK\x01\x02"
            or entry_end > eocd_offset
            or payload[name_start:name_end] != expected_name
            or extra_size != 0
            or member_comment_size != 0
            or member_disk != 0
            or created_version != (info.create_system << 8) | info.create_version
            or extracted_version != info.extract_version
            or flags != info.flag_bits
            or compression != info.compress_type
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
            or external_attributes != info.external_attr
            or local_offset != info.header_offset
        ):
            raise VerificationError(
                f"wheel contains non-canonical central metadata at {info.filename!r}"
            )
        central_cursor = entry_end
    if central_cursor != eocd_offset:
        raise VerificationError("wheel contains a central-directory gap or suffix")

    local_cursor = 0
    local_header_size = struct.calcsize("<4s5H3L2H")
    for info in sorted(infos, key=lambda item: item.header_offset):
        if info.header_offset != local_cursor:
            raise VerificationError("wheel contains a prefix or inter-member ZIP gap")
        if local_cursor + local_header_size > central_offset:
            raise VerificationError("wheel local header is truncated")
        try:
            (
                local_signature,
                extracted_version,
                flags,
                compression,
                _modified_time,
                _modified_date,
                crc,
                compressed_size,
                file_size,
                name_size,
                extra_size,
            ) = struct.unpack_from(
                "<4s5H3L2H",
                payload,
                local_cursor,
            )
        except struct.error as exc:
            raise VerificationError("wheel local header is malformed") from exc
        name_start = local_cursor + local_header_size
        name_end = name_start + name_size
        data_start = name_end + extra_size
        data_end = data_start + compressed_size
        expected_name = info.filename.encode("ascii")
        if (
            local_signature != b"PK\x03\x04"
            or data_end > central_offset
            or payload[name_start:name_end] != expected_name
            or extra_size != 0
            or extracted_version != info.extract_version
            or flags != 0
            or flags != info.flag_bits
            or compression != info.compress_type
            or crc != info.CRC
            or compressed_size != info.compress_size
            or file_size != info.file_size
        ):
            raise VerificationError(
                f"wheel contains non-canonical local framing at {info.filename!r}"
            )
        compressed_payload = payload[data_start:data_end]
        if compression == ZIP_DEFLATED:
            try:
                decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
                member_payload = decompressor.decompress(
                    compressed_payload,
                    file_size + 1,
                )
            except zlib.error as exc:
                raise VerificationError(
                    f"wheel member has an invalid DEFLATE stream at "
                    f"{info.filename!r}"
                ) from exc
            if (
                len(member_payload) != file_size
                or not decompressor.eof
                or decompressor.unused_data
                or decompressor.unconsumed_tail
                or zlib.crc32(member_payload) != crc
            ):
                raise VerificationError(
                    f"wheel member DEFLATE framing is not exact at "
                    f"{info.filename!r}"
                )
        elif compression == ZIP_STORED and (
            compressed_size != file_size
            or zlib.crc32(compressed_payload) != crc
        ):
            raise VerificationError(
                f"wheel stored member framing is not exact at {info.filename!r}"
            )
        local_cursor = data_end
    if local_cursor != central_offset:
        raise VerificationError("wheel contains data outside its ZIP members")


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

        archived_mode = info.external_attr >> 16
        file_type = stat.S_IFMT(archived_mode)
        expected_mode = 0o664 if member.endswith(".dist-info/RECORD") else 0o644
        if (
            member.endswith("/")
            or info.create_system != 3
            or info.create_version != 20
            or info.extract_version != 20
            or info.flag_bits != 0
            or info.internal_attr != 0
            or file_type != stat.S_IFREG
            or (archived_mode & 0o7777) != expected_mode
        ):
            raise VerificationError(
                f"wheel member type or mode does not match the release "
                f"contract at {member!r}"
            )
        if info.flag_bits & 0x1:
            raise VerificationError(
                f"wheel contains encrypted member {member!r}"
            )
        if info.extra:
            raise VerificationError(
                f"wheel contains unsupported extra fields at {member!r}"
            )
        if info.comment:
            raise VerificationError(
                f"wheel contains a member comment at {member!r}"
            )
        if info.compress_type not in {ZIP_STORED, ZIP_DEFLATED}:
            raise VerificationError(
                f"wheel contains unsupported compression at {member!r}"
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
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(
            "wheel entry_points.txt contains non-ASCII material"
        ) from exc
    if any(
        character not in "\t\r\n" and not (0x20 <= ord(character) <= 0x7E)
        for character in text
    ):
        raise VerificationError(
            "wheel entry_points.txt contains control material"
        )
    lines = text.splitlines()
    if (
        not lines
        or _ascii_control_value(
            lines[0],
            label="wheel entry_points.txt section",
        )
        != "[console_scripts]"
    ):
        raise VerificationError(
            "wheel entry_points.txt must contain only [console_scripts]"
        )
    actual_scripts: dict[str, str] = {}
    for line_number, line in enumerate(lines[1:], 2):
        if not line.strip(_ASCII_OWS):
            continue
        if line.count("=") != 1:
            raise VerificationError(
                "wheel entry_points.txt contains a malformed console script "
                f"on line {line_number}"
            )
        raw_key, raw_value = line.split("=", 1)
        key = _ascii_control_value(
            raw_key,
            label=f"wheel entry_points.txt key on line {line_number}",
        )
        value = _ascii_control_value(
            raw_value,
            label=f"wheel entry_points.txt value on line {line_number}",
        )
        if key in actual_scripts:
            raise VerificationError(
                f"wheel entry_points.txt repeats console script {key!r}"
            )
        actual_scripts[key] = value
    if actual_scripts != expected_scripts:
        raise VerificationError(
            "wheel console scripts do not exactly match project.scripts"
        )


def _verify_wheel_top_level(payload: bytes, *, modules: tuple[str, ...]) -> None:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as exc:
        raise VerificationError(
            "wheel top_level.txt contains non-ASCII material"
        ) from exc
    if any(
        character not in "\r\n" and not (0x20 <= ord(character) <= 0x7E)
        for character in text
    ):
        raise VerificationError("wheel top_level.txt contains control material")
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
    expected_data_root = (
        f"{_artifact_distribution_name(config.name)}-"
        f"{_artifact_version_name(config.version)}.data/data"
    )
    expected_members = _expected_wheel_members(
        config,
        expected_root=expected_root,
        expected_data_root=expected_data_root,
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
        **{
            f"{expected_data_root}/{member}": len(payload)
            for member, payload in config.wheel_data_payloads.items()
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
        archive_payload = wheel_path.read_bytes()
        if len(archive_payload) != archive_size:
            raise VerificationError("wheel changed while it was being read")
        with ZipFile(BytesIO(archive_payload)) as wheel:
            _validate_wheel_members(
                wheel,
                expected_root=expected_root,
                expected_members=expected_members,
                expected_exact_sizes=expected_exact_sizes,
                metadata_size_limits=metadata_size_limits,
            )
            _validate_canonical_wheel_zip(archive_payload, wheel)
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
    if parsed_wheel.defects:
        raise VerificationError("wheel WHEEL metadata contains parser defects")
    if parsed_wheel.get_payload() != "":
        raise VerificationError("wheel WHEEL metadata must not contain a body")
    wheel_versions = parsed_wheel.get_all("Wheel-Version", [])
    if len(wheel_versions) != 1:
        raise VerificationError(
            "wheel WHEEL metadata must contain exactly one supported "
            f"Wheel-Version: {_SUPPORTED_WHEEL_VERSION}"
        )
    wheel_version = _ascii_control_value(
        wheel_versions[0],
        label="wheel Wheel-Version",
    )
    if wheel_version != _SUPPORTED_WHEEL_VERSION:
        raise VerificationError(
            "wheel WHEEL metadata must contain exactly one supported "
            f"Wheel-Version: {_SUPPORTED_WHEEL_VERSION}"
        )
    purelib_values = parsed_wheel.get_all("Root-Is-Purelib", [])
    if len(purelib_values) != 1:
        raise VerificationError(
            "wheel WHEEL metadata must contain exactly one "
            "Root-Is-Purelib: true"
        )
    purelib = _ascii_control_value(
        purelib_values[0],
        label="wheel Root-Is-Purelib",
    )
    if purelib.lower() != "true":
        raise VerificationError(
            "wheel WHEEL metadata must contain exactly one "
            "Root-Is-Purelib: true"
        )
    tags = [
        _ascii_control_value(value, label="wheel Tag")
        for value in parsed_wheel.get_all("Tag", [])
    ]
    if len(tags) != 1 or set(tags) != {"py3-none-any"}:
        raise VerificationError(
            "wheel WHEEL compatibility tags must be exactly "
            f"['py3-none-any']; found {tags}"
        )
    generator_values = parsed_wheel.get_all("Generator", [])
    if len(generator_values) != 1:
        raise VerificationError(
            "wheel WHEEL metadata must contain exactly one Generator"
        )
    _ascii_control_value(generator_values[0], label="wheel Generator")
    wheel_field_counts = Counter(field.casefold() for field in parsed_wheel.keys())
    if wheel_field_counts != Counter(
        {
            "wheel-version": 1,
            "generator": 1,
            "root-is-purelib": 1,
            "tag": 1,
        }
    ):
        raise VerificationError(
            "wheel WHEEL metadata fields do not match the release contract"
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
    for data_name, project_payload in config.wheel_data_payloads.items():
        wheel_name = f"{expected_data_root}/{data_name}"
        if payloads[wheel_name] != project_payload:
            raise VerificationError(
                f"wheel data payload {data_name!r} differs from the project"
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
    if any(
        character not in "\t\r\n" and not (0x20 <= ord(character) <= 0x7E)
        for character in text
    ):
        raise VerificationError(
            "sdist requires.txt contains non-ASCII or control material"
        )
    current_extra: str | None = None
    seen_sections: set[str] = set()
    actual: Counter[
        tuple[
            tuple[str, tuple[str, ...], tuple[tuple[str, str], ...]],
            str | None,
        ]
    ] = Counter()
    for line_number, line in enumerate(text.splitlines(), 1):
        _validate_ascii_pep508(
            line,
            label=f"sdist requires.txt line {line_number}",
        )
        stripped = _strip_ascii_ows(line)
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
        _validate_tar_header_profiles(sdist_path)
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
                expected_mode = 0o644 if regular_file else 0o755
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
                if directory and member.size != 0:
                    raise VerificationError(
                        "source distribution directory member has non-zero size: "
                        f"{member.name!r}"
                    )
                if (regular_file or directory) and member.mode != expected_mode:
                    raise VerificationError(
                        "source distribution member mode does not match the "
                        f"release contract at {member.name!r}"
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
            _validate_tar_zero_padding(sdist_path)
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
    *,
    repository: Path | None = None,
    source_commit: str | None = None,
) -> _ProjectReleaseConfig:
    if (repository is None) != (source_commit is None):
        raise VerificationError(
            "--repository and --source-commit must be supplied together"
        )
    canonical_repository: Path | None = None
    resolved_commit: str | None = None
    if repository is None:
        config = _project_release_config(project_path)
    else:
        assert source_commit is not None
        canonical_repository = _canonical_git_repository(repository)
        resolved_commit = _resolve_exact_source_commit(
            canonical_repository,
            source_commit,
        )
        immutable_snapshot = _immutable_commit_snapshot(
            canonical_repository,
            source_commit=resolved_commit,
            project_path=project_path,
        )
        config = _project_release_config(
            project_path,
            immutable_source_payloads=immutable_snapshot.payloads,
        )
        _verify_git_worktree_state(
            canonical_repository,
            source_commit=resolved_commit,
            egg_info_root=f"{_artifact_distribution_name(config.name)}.egg-info",
            project_path=project_path,
            immutable_payloads=immutable_snapshot.payloads,
            immutable_entries=immutable_snapshot.entries,
        )
    if tag is not None:
        _verify_tag_identity(config.name, config.version, tag)
        if canonical_repository is not None and resolved_commit is not None:
            _verify_tag_commit(
                canonical_repository,
                tag=tag,
                source_commit=resolved_commit,
            )
    return config


def verify_sdist(
    project_path: Path,
    dist_path: Path,
    tag: str | None = None,
    *,
    repository: Path | None = None,
    source_commit: str | None = None,
) -> Path:
    """Verify the sole built sdist before any archive extraction occurs."""

    config = _release_config(
        project_path,
        tag,
        repository=repository,
        source_commit=source_commit,
    )

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
    *,
    repository: Path | None = None,
    source_commit: str | None = None,
) -> Path:
    """Verify and extract an sdist with the same bounded streaming parser."""

    sdist = verify_sdist(
        project_path,
        dist_path,
        tag,
        repository=repository,
        source_commit=source_commit,
    )
    config = _release_config(
        project_path,
        tag,
        repository=repository,
        source_commit=source_commit,
    )
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
    project_path: Path,
    dist_path: Path,
    tag: str | None = None,
    *,
    repository: Path | None = None,
    source_commit: str | None = None,
) -> tuple[Path, Path]:
    config = _release_config(
        project_path,
        tag,
        repository=repository,
        source_commit=source_commit,
    )

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

    def add_immutable_source_arguments(
        command_parser: argparse.ArgumentParser,
    ) -> None:
        command_parser.add_argument(
            "--repository",
            type=Path,
            help="exact git worktree top level containing the trusted source",
        )
        command_parser.add_argument(
            "--source-commit",
            help="complete git commit object ID that defines source bytes",
        )
        command_parser.add_argument(
            "--allow-mutable-source",
            action="store_true",
            help=(
                "explicitly use current filesystem bytes (local tests only; "
                "never for CI or release verification)"
            ),
        )

    add_immutable_source_arguments(tag_parser)

    artifacts_parser = subparsers.add_parser(
        "artifacts", help="verify exactly one wheel and sdist plus their metadata"
    )
    artifacts_parser.add_argument("--project", required=True, type=Path)
    artifacts_parser.add_argument("--dist", required=True, type=Path)
    artifacts_parser.add_argument("--tag")
    add_immutable_source_arguments(artifacts_parser)

    sdist_parser = subparsers.add_parser(
        "sdist",
        help="verify the sole source distribution before extracting it",
    )
    sdist_parser.add_argument("--project", required=True, type=Path)
    sdist_parser.add_argument("--dist", required=True, type=Path)
    sdist_parser.add_argument("--tag")
    add_immutable_source_arguments(sdist_parser)

    extract_parser = subparsers.add_parser(
        "extract-sdist",
        help="verify and safely extract the sole source distribution",
    )
    extract_parser.add_argument("--project", required=True, type=Path)
    extract_parser.add_argument("--dist", required=True, type=Path)
    extract_parser.add_argument("--output", required=True, type=Path)
    extract_parser.add_argument("--tag")
    add_immutable_source_arguments(extract_parser)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        immutable_source_selected = (
            args.repository is not None or args.source_commit is not None
        )
        if args.allow_mutable_source and immutable_source_selected:
            raise VerificationError(
                "--allow-mutable-source cannot be combined with immutable git "
                "source arguments"
            )
        if not args.allow_mutable_source and not immutable_source_selected:
            raise VerificationError(
                "release verification requires --repository and "
                "--source-commit; use --allow-mutable-source only for local "
                "non-git tests"
            )
        if args.command == "tag":
            name, version = verify_tag(
                args.project,
                args.tag,
                repository=args.repository,
                source_commit=args.source_commit,
            )
            print(f"release identity verified: {name} {version} ({args.tag})")
        elif args.command == "sdist":
            sdist = verify_sdist(
                args.project,
                args.dist,
                args.tag,
                repository=args.repository,
                source_commit=args.source_commit,
            )
            print(f"source distribution verified before extraction: {sdist.name}")
        elif args.command == "extract-sdist":
            root = extract_sdist(
                args.project,
                args.dist,
                args.output,
                args.tag,
                repository=args.repository,
                source_commit=args.source_commit,
            )
            print(f"source distribution safely extracted: {root}")
        else:
            wheel, sdist = verify_artifacts(
                args.project,
                args.dist,
                args.tag,
                repository=args.repository,
                source_commit=args.source_commit,
            )
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
