"""Verify that release tags and distribution artifacts describe one release.

This script intentionally uses only the Python standard library so the release
workflow can run it before installing project dependencies.
"""

from __future__ import annotations

import argparse
from email.parser import Parser
import gzip
import re
import stat
import sys
import tarfile
import tomllib
import unicodedata
from pathlib import Path, PurePosixPath
from typing import BinaryIO
from zipfile import BadZipFile, ZipFile


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


class VerificationError(ValueError):
    """Raised when a release identity or artifact boundary is inconsistent."""


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


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _artifact_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def _artifact_version_name(version: str) -> str:
    return re.sub(r"[^\w\d.]+", "_", version).lower()


def _validate_wheel_members(wheel: ZipFile, *, expected_root: str) -> None:
    """Reject archive paths or package metadata outside this distribution."""

    infos = wheel.infolist()
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
        canonical = member[:-1] if member.endswith("/") else member
        parts = canonical.split("/")
        path = PurePosixPath(canonical)
        portable = unicodedata.normalize("NFC", canonical).casefold()
        if (
            not canonical
            or path.is_absolute()
            or "\\" in member
            or any(part in {"", ".", ".."} for part in parts)
            or parts[0].endswith(":")
            or canonical in canonical_paths
            or portable in portable_paths
        ):
            raise VerificationError(
                f"wheel contains unsafe or ambiguous member path {member!r}"
            )
        canonical_paths.add(canonical)
        portable_paths.add(portable)

        if info.file_size < 0 or info.file_size > MAX_WHEEL_MEMBER_BYTES:
            raise VerificationError(
                f"wheel member exceeds the size limit: {member!r}"
            )
        total_size += info.file_size
        if total_size > MAX_WHEEL_TOTAL_BYTES:
            raise VerificationError("wheel exceeds the total-size limit")

        file_type = stat.S_IFMT(info.external_attr >> 16)
        if file_type not in {0, stat.S_IFREG, stat.S_IFDIR}:
            raise VerificationError(
                f"wheel contains unsupported member type at {member!r}"
            )
        if info.flag_bits & 0x1:
            raise VerificationError(
                f"wheel contains encrypted member {member!r}"
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


def _wheel_identity(
    wheel_path: Path,
    *,
    expected_name: str,
    expected_version: str,
) -> tuple[str, str]:
    expected_root = (
        f"{_artifact_distribution_name(expected_name)}-"
        f"{_artifact_version_name(expected_version)}.dist-info"
    )
    try:
        if wheel_path.stat().st_size > MAX_WHEEL_ARCHIVE_BYTES:
            raise VerificationError("wheel exceeds the compressed-size limit")
        with ZipFile(wheel_path) as wheel:
            _validate_wheel_members(wheel, expected_root=expected_root)
            metadata_members = [
                member
                for member in wheel.namelist()
                if member.endswith(".dist-info/METADATA")
                and member.count("/") == 1
            ]
            if len(metadata_members) != 1:
                raise VerificationError(
                    f"wheel must contain exactly one dist-info/METADATA; "
                    f"found {len(metadata_members)}"
                )
            wheel_members = [
                member
                for member in wheel.namelist()
                if member.endswith(".dist-info/WHEEL")
                and member.count("/") == 1
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
                    "wheel METADATA and WHEEL must belong to the same "
                    "dist-info directory"
                )
            if metadata_root != expected_root:
                raise VerificationError(
                    f"wheel dist-info directory {metadata_root!r} does not "
                    f"match expected {expected_root!r}"
                )
            metadata = wheel.read(metadata_members[0]).decode("utf-8")
            wheel_metadata = wheel.read(wheel_members[0]).decode("utf-8")
    except (BadZipFile, OSError, UnicodeDecodeError) as exc:
        raise VerificationError(
            f"cannot inspect wheel {wheel_path.name}: {exc}"
        ) from exc
    parsed_wheel = Parser().parsestr(wheel_metadata)
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
    return _metadata_identity(metadata, "wheel")


def _sdist_identity(
    sdist_path: Path,
    *,
    expected_name: str,
    expected_version: str,
) -> tuple[str, str]:
    try:
        if sdist_path.stat().st_size > MAX_SDIST_ARCHIVE_BYTES:
            raise VerificationError(
                "source distribution exceeds the compressed-size limit"
            )
        with (
            gzip.open(sdist_path, "rb") as decompressed_archive,
            tarfile.open(
                sdist_path.name,
                "r|",
                fileobj=_BoundedArchiveReader(
                    decompressed_archive,
                    MAX_SDIST_DECOMPRESSED_BYTES,
                ),
                tarinfo=_BoundedTarInfo,
            ) as source_archive,
        ):
            expected_root = (
                f"{_artifact_distribution_name(expected_name)}-"
                f"{_artifact_version_name(expected_version)}"
            )
            member_names: set[str] = set()
            portable_member_names: set[str] = set()
            member_count = 0
            total_size = 0
            metadata_count = 0
            metadata_bytes: bytes | None = None
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
                raw_parts = canonical_name.split("/")
                path = PurePosixPath(canonical_name)
                regular_file = member.type in {
                    tarfile.REGTYPE,
                    tarfile.AREGTYPE,
                }
                directory = member.type == tarfile.DIRTYPE
                portable_name = unicodedata.normalize(
                    "NFC", canonical_name
                ).casefold()
                sparse_headers = any(
                    key.startswith("GNU.sparse") or key == "SCHILY.realsize"
                    for key in member.pax_headers
                )
                top_level_metadata = (
                    regular_file
                    and member.name.endswith("/PKG-INFO")
                    and member.name.count("/") == 1
                )
                if top_level_metadata:
                    metadata_root = member.name.rsplit("/", 1)[0]
                    if metadata_root != expected_root:
                        raise VerificationError(
                            f"source-distribution root {metadata_root!r} does not "
                            f"match expected {expected_root!r}"
                        )
                if (
                    path.is_absolute()
                    or not path.parts
                    or any(part in {"", ".", ".."} for part in raw_parts)
                    or path.parts[0] != expected_root
                    or "\\" in member.name
                    or not (regular_file or directory)
                    or bool(member.sparse)
                    or sparse_headers
                ):
                    raise VerificationError(
                        f"source distribution contains unsafe or unexpected "
                        f"member path {member.name!r}; every member must remain "
                        f"under {expected_root!r}"
                    )
                if member.name in member_names:
                    raise VerificationError(
                        "source distribution contains duplicate member paths"
                    )
                if portable_name in portable_member_names:
                    raise VerificationError(
                        "source distribution contains portable-path collisions"
                    )
                member_names.add(member.name)
                portable_member_names.add(portable_name)
                if member.size < 0 or member.size > MAX_SDIST_MEMBER_BYTES:
                    raise VerificationError(
                        "source distribution member exceeds the size limit: "
                        f"{member.name!r}"
                    )
                if directory and member.size != 0:
                    raise VerificationError(
                        "source distribution directory member has non-zero size: "
                        f"{member.name!r}"
                    )
                total_size += member.size
                if total_size > MAX_SDIST_TOTAL_BYTES:
                    raise VerificationError(
                        "source distribution exceeds the total-size limit"
                    )
                if regular_file:
                    if top_level_metadata:
                        metadata_count += 1
                        extracted = source_archive.extractfile(member)
                        if extracted is None:
                            raise VerificationError(
                                "cannot read source distribution PKG-INFO"
                            )
                        metadata_bytes = extracted.read()
            if metadata_count != 1 or metadata_bytes is None:
                raise VerificationError(
                    f"source distribution must contain exactly one top-level "
                    f"PKG-INFO; found {metadata_count}"
                )
            metadata = metadata_bytes.decode("utf-8")
    except VerificationError:
        raise
    except (
        OSError,
        EOFError,
        ValueError,
        OverflowError,
        RecursionError,
        IndexError,
        tarfile.TarError,
        UnicodeDecodeError,
    ) as exc:
        raise VerificationError(
            f"cannot inspect source distribution {sdist_path.name}: {exc}"
        ) from exc
    return _metadata_identity(metadata, "source distribution")


def verify_sdist(
    project_path: Path, dist_path: Path, tag: str | None = None
) -> Path:
    """Verify the sole built sdist before any archive extraction occurs."""

    if tag is None:
        expected_name, expected_version = _project_identity(project_path)
    else:
        expected_name, expected_version = verify_tag(project_path, tag)

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

    artifact_name = _artifact_distribution_name(expected_name)
    expected_filename = f"{artifact_name}-{expected_version}.tar.gz"
    if sdists[0].name != expected_filename:
        raise VerificationError(
            f"source-distribution filename {sdists[0].name!r} does not identify "
            f"{expected_name} {expected_version}"
        )

    artifact_name_value, artifact_version = _sdist_identity(
        sdists[0],
        expected_name=expected_name,
        expected_version=expected_version,
    )
    if _normalize_name(artifact_name_value) != _normalize_name(expected_name):
        raise VerificationError(
            f"source distribution Name {artifact_name_value!r} does not match "
            f"project.name {expected_name!r}"
        )
    if artifact_version != expected_version:
        raise VerificationError(
            f"source distribution Version {artifact_version!r} does not match "
            f"project.version {expected_version!r}"
        )
    return sdists[0]


def verify_artifacts(
    project_path: Path, dist_path: Path, tag: str | None = None
) -> tuple[Path, Path]:
    if tag is None:
        expected_name, expected_version = _project_identity(project_path)
    else:
        expected_name, expected_version = verify_tag(project_path, tag)

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

    artifact_name = _artifact_distribution_name(expected_name)
    expected_wheel_name = f"{artifact_name}-{expected_version}-py3-none-any.whl"
    expected_sdist_name = f"{artifact_name}-{expected_version}.tar.gz"
    if wheels[0].name != expected_wheel_name:
        raise VerificationError(
            f"wheel filename {wheels[0].name!r} does not match the expected "
            f"pure-Python artifact {expected_wheel_name!r}"
        )
    if sdists[0].name != expected_sdist_name:
        raise VerificationError(
            f"source-distribution filename {sdists[0].name!r} does not identify "
            f"{expected_name} {expected_version}"
        )

    for label, path, identity_reader in (
        (
            "wheel",
            wheels[0],
            lambda wheel_path: _wheel_identity(
                wheel_path,
                expected_name=expected_name,
                expected_version=expected_version,
            ),
        ),
        (
            "source distribution",
            sdists[0],
            lambda sdist_path: _sdist_identity(
                sdist_path,
                expected_name=expected_name,
                expected_version=expected_version,
            ),
        ),
    ):
        artifact_name, artifact_version = identity_reader(path)
        if _normalize_name(artifact_name) != _normalize_name(expected_name):
            raise VerificationError(
                f"{label} Name {artifact_name!r} does not match "
                f"project.name {expected_name!r}"
            )
        if artifact_version != expected_version:
            raise VerificationError(
                f"{label} Version {artifact_version!r} does not match "
                f"project.version {expected_version!r}"
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
