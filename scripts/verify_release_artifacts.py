"""Verify that release tags and distribution artifacts describe one release.

This script intentionally uses only the Python standard library so the release
workflow can run it before installing project dependencies.
"""

from __future__ import annotations

import argparse
from email.parser import Parser
import re
import sys
import tarfile
import tomllib
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile


_TAG_PATTERN = re.compile(
    r"v(?P<release>[0-9]+(?:\.[0-9]+)*)"
    r"(?:-(?P<phase>alpha|beta|rc)\.(?P<number>[0-9]+))?"
)
_PHASE_TO_PEP440 = {"alpha": "a", "beta": "b", "rc": "rc"}


class VerificationError(ValueError):
    """Raised when a release identity or artifact boundary is inconsistent."""


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


def _wheel_identity(
    wheel_path: Path,
    *,
    expected_name: str,
    expected_version: str,
) -> tuple[str, str]:
    try:
        with ZipFile(wheel_path) as wheel:
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
            expected_root = (
                f"{_artifact_distribution_name(expected_name)}-"
                f"{_artifact_version_name(expected_version)}.dist-info"
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
        with tarfile.open(sdist_path, "r:gz") as source_archive:
            expected_root = (
                f"{_artifact_distribution_name(expected_name)}-"
                f"{_artifact_version_name(expected_version)}"
            )
            members = source_archive.getmembers()
            metadata_members = [
                member
                for member in members
                if member.isfile()
                and member.name.endswith("/PKG-INFO")
                and member.name.count("/") == 1
            ]
            if len(metadata_members) != 1:
                raise VerificationError(
                    f"source distribution must contain exactly one top-level "
                    f"PKG-INFO; found {len(metadata_members)}"
                )
            metadata_root = metadata_members[0].name.rsplit("/", 1)[0]
            if metadata_root != expected_root:
                raise VerificationError(
                    f"source-distribution root {metadata_root!r} does not "
                    f"match expected {expected_root!r}"
                )
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or not path.parts
                    or path.parts[0] != expected_root
                    or ".." in path.parts
                    or "\\" in member.name
                    or not (member.isfile() or member.isdir())
                ):
                    raise VerificationError(
                        f"source distribution contains unsafe or unexpected "
                        f"member path {member.name!r}; every member must remain "
                        f"under {expected_root!r}"
                    )
            extracted = source_archive.extractfile(metadata_members[0])
            if extracted is None:
                raise VerificationError("cannot read source distribution PKG-INFO")
            metadata = extracted.read().decode("utf-8")
    except (OSError, tarfile.TarError, UnicodeDecodeError) as exc:
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
