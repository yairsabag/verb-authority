from io import BytesIO
from pathlib import Path
import tarfile
from zipfile import ZIP_DEFLATED, ZipFile

import pytest


pytest.importorskip(
    "tomllib",
    reason="the stdlib release verifier runs on Python 3.11 and newer",
)

from scripts.verify_release_artifacts import (  # noqa: E402
    VerificationError,
    verify_artifacts,
    verify_tag,
)


PROJECT_NAME = "verb-authority"
PROJECT_VERSION = "0.10.0b8"
ARTIFACT_NAME = "verb_authority"


def _write_project(path: Path, *, version: str = PROJECT_VERSION) -> Path:
    project_path = path / "pyproject.toml"
    project_path.write_text(
        "\n".join(
            (
                "[project]",
                f'name = "{PROJECT_NAME}"',
                f'version = "{version}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    return project_path


def _metadata(*, name: str = PROJECT_NAME, version: str = PROJECT_VERSION) -> str:
    return "\n".join(
        (
            "Metadata-Version: 2.4",
            f"Name: {name}",
            f"Version: {version}",
            "",
        )
    )


def _write_wheel(
    dist: Path,
    *,
    filename_version: str = PROJECT_VERSION,
    metadata_name: str = PROJECT_NAME,
    metadata_version: str = PROJECT_VERSION,
    suffix: str = "py3-none-any",
    root_is_purelib: str = "true",
    tags: tuple[str, ...] = ("py3-none-any",),
    wheel_dist_info_name: str | None = None,
    include_wheel_metadata: bool = True,
) -> Path:
    wheel_path = dist / f"{ARTIFACT_NAME}-{filename_version}-{suffix}.whl"
    metadata_member = (
        f"{ARTIFACT_NAME}-{filename_version}.dist-info/METADATA"
    )
    with ZipFile(wheel_path, "w", compression=ZIP_DEFLATED) as wheel:
        wheel.writestr(
            metadata_member,
            _metadata(name=metadata_name, version=metadata_version),
        )
        if include_wheel_metadata:
            dist_info_name = wheel_dist_info_name or (
                f"{ARTIFACT_NAME}-{filename_version}.dist-info"
            )
            wheel.writestr(
                f"{dist_info_name}/WHEEL",
                "\n".join(
                    (
                        "Wheel-Version: 1.0",
                        "Generator: release-verifier-test",
                        f"Root-Is-Purelib: {root_is_purelib}",
                        *(f"Tag: {tag}" for tag in tags),
                        "",
                    )
                ),
            )
    return wheel_path


def _write_sdist(
    dist: Path,
    *,
    filename_version: str = PROJECT_VERSION,
    metadata_name: str = PROJECT_NAME,
    metadata_version: str = PROJECT_VERSION,
) -> Path:
    sdist_path = dist / f"{ARTIFACT_NAME}-{filename_version}.tar.gz"
    metadata_bytes = _metadata(
        name=metadata_name,
        version=metadata_version,
    ).encode("utf-8")
    metadata_member = tarfile.TarInfo(
        f"{ARTIFACT_NAME}-{filename_version}/PKG-INFO"
    )
    metadata_member.size = len(metadata_bytes)
    with tarfile.open(sdist_path, "w:gz") as source_archive:
        source_archive.addfile(metadata_member, BytesIO(metadata_bytes))
    return sdist_path


def _write_valid_release(tmp_path: Path) -> tuple[Path, Path, Path]:
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    return project_path, wheel, sdist


def test_beta_8_tag_matches_project_version(tmp_path):
    project_path = _write_project(tmp_path)

    assert verify_tag(project_path, "v0.10.0-beta.8") == (
        PROJECT_NAME,
        PROJECT_VERSION,
    )


def test_beta_7_tag_is_rejected_for_beta_8_project(tmp_path):
    project_path = _write_project(tmp_path)

    with pytest.raises(VerificationError, match="0.10.0b7.*0.10.0b8"):
        verify_tag(project_path, "v0.10.0-beta.7")


def test_exactly_one_wheel_and_sdist_are_accepted(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)

    assert verify_artifacts(
        project_path,
        wheel.parent,
        "v0.10.0-beta.8",
    ) == (wheel, sdist)


def test_second_wheel_is_rejected(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    _write_wheel(wheel.parent, suffix="cp312-cp312-any")

    with pytest.raises(
        VerificationError,
        match=r"found 2 wheel\(s\) and 1 sdist\(s\)",
    ):
        verify_artifacts(project_path, wheel.parent)


def test_non_universal_wheel_tag_is_rejected(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist, suffix="cp312-cp312-macosx_14_0_arm64")
    _write_sdist(dist)

    with pytest.raises(
        VerificationError,
        match="does not match the expected pure-Python artifact",
    ):
        verify_artifacts(project_path, dist)


def test_internal_wheel_tag_must_match_universal_filename(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(
        dist,
        root_is_purelib="false",
        tags=("cp312-cp312-macosx_14_0_arm64",),
    )
    _write_sdist(dist)

    with pytest.raises(
        VerificationError,
        match="Root-Is-Purelib: true|compatibility tags",
    ):
        verify_artifacts(project_path, dist)


def test_internal_wheel_tag_set_must_be_exact(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(
        dist,
        tags=("py3-none-any", "cp312-none-any"),
    )
    _write_sdist(dist)

    with pytest.raises(VerificationError, match="compatibility tags"):
        verify_artifacts(project_path, dist)


def test_wheel_metadata_must_share_the_metadata_dist_info(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist, wheel_dist_info_name="other.dist-info")
    _write_sdist(dist)

    with pytest.raises(VerificationError, match="same dist-info directory"):
        verify_artifacts(project_path, dist)


def test_wheel_metadata_is_required(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist, include_wheel_metadata=False)
    _write_sdist(dist)

    with pytest.raises(VerificationError, match="exactly one dist-info/WHEEL"):
        verify_artifacts(project_path, dist)


def test_unexpected_release_directory_entry_is_rejected(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    (wheel.parent / "notes.txt").write_text("not a release artifact", encoding="utf-8")

    with pytest.raises(VerificationError, match="unexpected entries.*notes.txt"):
        verify_artifacts(project_path, wheel.parent)


def test_corrupted_wheel_raises_clean_verification_error(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    wheel.write_bytes(b"this is not a zip archive")

    with pytest.raises(
        VerificationError,
        match=r"^cannot inspect wheel .*\.whl:",
    ):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    "metadata_name, metadata_version, message",
    [
        ("different-project", PROJECT_VERSION, "wheel Name.*project.name"),
        (PROJECT_NAME, "0.10.0b7", "wheel Version.*project.version"),
    ],
)
def test_wheel_metadata_must_match_filename_and_project(
    tmp_path,
    metadata_name,
    metadata_version,
    message,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(
        dist,
        metadata_name=metadata_name,
        metadata_version=metadata_version,
    )
    _write_sdist(dist)

    with pytest.raises(VerificationError, match=message):
        verify_artifacts(project_path, dist)


@pytest.mark.parametrize(
    "metadata_name, metadata_version, message",
    [
        ("different-project", PROJECT_VERSION, "source distribution Name.*project.name"),
        (PROJECT_NAME, "0.10.0b7", "source distribution Version.*project.version"),
    ],
)
def test_sdist_metadata_must_match_filename_and_project(
    tmp_path,
    metadata_name,
    metadata_version,
    message,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(
        dist,
        metadata_name=metadata_name,
        metadata_version=metadata_version,
    )

    with pytest.raises(VerificationError, match=message):
        verify_artifacts(project_path, dist)


def test_artifact_filename_version_must_match_project(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    wheel.rename(
        wheel.with_name(wheel.name.replace(PROJECT_VERSION, "0.10.0b7", 1))
    )

    with pytest.raises(VerificationError, match="wheel filename.*0.10.0b8"):
        verify_artifacts(project_path, wheel.parent)
