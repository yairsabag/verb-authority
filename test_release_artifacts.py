from io import BytesIO
import gzip
from pathlib import Path
import tarfile
from zipfile import ZIP_DEFLATED, ZipFile

import pytest

pytest.importorskip(
    "tomllib",
    reason="the stdlib release verifier runs on Python 3.11 and newer",
)

import scripts.verify_release_artifacts as release_verifier  # noqa: E402
from scripts.verify_release_artifacts import (  # noqa: E402
    MAX_SDIST_MEMBER_BYTES,
    VerificationError,
    main,
    verify_artifacts,
    verify_sdist,
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
    internal_dist_info_name: str | None = None,
    wheel_dist_info_name: str | None = None,
    include_wheel_metadata: bool = True,
) -> Path:
    wheel_path = dist / f"{ARTIFACT_NAME}-{filename_version}-{suffix}.whl"
    expected_dist_info_name = (
        f"{ARTIFACT_NAME}-{filename_version}.dist-info"
    )
    metadata_dist_info_name = internal_dist_info_name or expected_dist_info_name
    metadata_member = f"{metadata_dist_info_name}/METADATA"
    with ZipFile(wheel_path, "w", compression=ZIP_DEFLATED) as wheel:
        wheel.writestr(
            metadata_member,
            _metadata(name=metadata_name, version=metadata_version),
        )
        if include_wheel_metadata:
            dist_info_name = (
                wheel_dist_info_name
                or internal_dist_info_name
                or expected_dist_info_name
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
    internal_root_name: str | None = None,
    extra_member_name: str | None = None,
    extra_member_type: bytes | None = None,
) -> Path:
    sdist_path = dist / f"{ARTIFACT_NAME}-{filename_version}.tar.gz"
    metadata_bytes = _metadata(
        name=metadata_name,
        version=metadata_version,
    ).encode("utf-8")
    root_name = internal_root_name or f"{ARTIFACT_NAME}-{filename_version}"
    metadata_member = tarfile.TarInfo(f"{root_name}/PKG-INFO")
    metadata_member.size = len(metadata_bytes)
    with tarfile.open(sdist_path, "w:gz") as source_archive:
        source_archive.addfile(metadata_member, BytesIO(metadata_bytes))
        if extra_member_name is not None:
            extra_member = tarfile.TarInfo(extra_member_name)
            if extra_member_type is not None:
                extra_member.type = extra_member_type
            extra_member.size = 0
            source_archive.addfile(extra_member, BytesIO())
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


def test_normalized_internal_wheel_dist_info_root_is_accepted(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(
        dist,
        internal_dist_info_name="verb_authority-0.10.0b8.dist-info",
    )
    sdist = _write_sdist(dist)

    assert verify_artifacts(project_path, dist) == (wheel, sdist)


def test_wrong_internal_wheel_dist_info_root_is_rejected(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(
        dist,
        internal_dist_info_name="verb_authority-0.10.0b7.dist-info",
    )
    _write_sdist(dist)

    with pytest.raises(
        VerificationError,
        match="metadata outside expected dist-info directory",
    ):
        verify_artifacts(project_path, dist)


def test_normalized_internal_sdist_root_is_accepted(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(
        dist,
        internal_root_name="verb_authority-0.10.0b8",
    )

    assert verify_artifacts(project_path, dist) == (wheel, sdist)


def test_pre_extraction_sdist_verifier_accepts_sole_valid_archive(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    sdist = _write_sdist(dist)

    assert verify_sdist(project_path, dist, "v0.10.0-beta.8") == sdist
    assert (
        main(
            [
                "sdist",
                "--project",
                str(project_path),
                "--dist",
                str(dist),
                "--tag",
                "v0.10.0-beta.8",
            ]
        )
        == 0
    )


def test_pre_extraction_sdist_cli_rejects_wrong_root(tmp_path, capsys):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_sdist(
        dist,
        internal_root_name="verb_authority-0.10.0b7",
    )

    assert (
        main(
            [
                "sdist",
                "--project",
                str(project_path),
                "--dist",
                str(dist),
            ]
        )
        == 2
    )
    assert "source-distribution root" in capsys.readouterr().err


def test_wrong_internal_sdist_root_is_rejected(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(
        dist,
        internal_root_name="verb_authority-0.10.0b7",
    )

    with pytest.raises(
        VerificationError,
        match="source-distribution root.*verb_authority-0.10.0b8",
    ):
        verify_artifacts(project_path, dist)


def test_sdist_member_path_cannot_escape_expected_root(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(
        dist,
        extra_member_name="verb_authority-0.10.0b8/../escape.txt",
    )

    with pytest.raises(VerificationError, match="unsafe or unexpected member path"):
        verify_artifacts(project_path, dist)


@pytest.mark.parametrize(
    ("member_type", "message"),
    (
        (tarfile.GNUTYPE_SPARSE, "GNU sparse member"),
        (tarfile.CONTTYPE, "unsafe or unexpected member path"),
    ),
)
def test_sdist_rejects_non_regular_file_member_before_extraction(
    tmp_path,
    member_type,
    message,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(
        dist,
        extra_member_name=f"{ARTIFACT_NAME}-{PROJECT_VERSION}/README.md",
        extra_member_type=member_type,
    )

    with pytest.raises(VerificationError, match=message):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_truncated_extended_sparse_header_before_parser(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    sparse = tarfile.TarInfo(f"{ARTIFACT_NAME}-{PROJECT_VERSION}/sparse")
    sparse.type = tarfile.GNUTYPE_SPARSE
    sparse.size = 0
    header = bytearray(sparse.tobuf(format=tarfile.GNU_FORMAT))
    header[482] = 1
    header[483:495] = tarfile.itn(0, 12, tarfile.GNU_FORMAT)
    header[148:156] = b"        "
    checksum, _ = tarfile.calc_chksums(bytes(header))
    header[148:156] = f"{checksum:06o}\0 ".encode()
    with gzip.open(sdist, "wb") as archive:
        archive.write(header)

    with pytest.raises(VerificationError, match="GNU sparse member"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_oversized_header_before_traversing_member_payload(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    oversized = tarfile.TarInfo(
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}/oversized.bin"
    )
    oversized.size = MAX_SDIST_MEMBER_BYTES + 1
    # Header-only on purpose. Incremental verification must reject the declared
    # size before tarfile attempts to seek across or inflate the absent body.
    with gzip.open(sdist, "wb") as archive:
        archive.write(oversized.tobuf(format=tarfile.USTAR_FORMAT))

    with pytest.raises(VerificationError, match="member exceeds the size limit"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_nonempty_directory_before_traversing_payload(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    directory = tarfile.TarInfo(f"{ARTIFACT_NAME}-{PROJECT_VERSION}/payload/")
    directory.type = tarfile.DIRTYPE
    directory.size = 1
    with gzip.open(sdist, "wb") as archive:
        archive.write(directory.tobuf(format=tarfile.USTAR_FORMAT))

    with pytest.raises(VerificationError, match="directory member has non-zero size"):
        verify_artifacts(project_path, dist)


def test_sdist_bounds_hidden_pax_payload_before_tarfile_materializes_it(
    tmp_path,
    monkeypatch,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    monkeypatch.setattr(
        release_verifier,
        "MAX_SDIST_DECOMPRESSED_BYTES",
        12 * 1024,
    )
    pax_header = tarfile.TarInfo("././@PaxHeader")
    pax_header.type = tarfile.XHDTYPE
    pax_header.size = 20 * 1024
    with gzip.open(sdist, "wb") as archive:
        archive.write(pax_header.tobuf(format=tarfile.USTAR_FORMAT))
        archive.write(b"0" * pax_header.size)

    with pytest.raises(VerificationError, match="decompressed traversal limit"):
        verify_artifacts(project_path, dist)


@pytest.mark.parametrize(
    "extension_type",
    (tarfile.XHDTYPE, tarfile.SOLARIS_XHDTYPE),
)
def test_sdist_rejects_oversized_extension_header_before_reading_payload(
    tmp_path,
    extension_type,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    extension = tarfile.TarInfo("././@PaxHeader")
    extension.type = extension_type
    extension.size = release_verifier.MAX_SDIST_EXTENSION_BYTES + 1
    with gzip.open(sdist, "wb") as archive:
        archive.write(extension.tobuf(format=tarfile.USTAR_FORMAT))

    with pytest.raises(VerificationError, match="extension header exceeds"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_nested_extension_headers_before_python_recursion_limit(
    tmp_path,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    extension = tarfile.TarInfo("././@PaxHeader")
    extension.type = tarfile.XHDTYPE
    extension.size = 0
    with gzip.open(sdist, "wb") as archive:
        for _ in range(release_verifier.MAX_SDIST_HEADER_DEPTH + 1):
            archive.write(extension.tobuf(format=tarfile.USTAR_FORMAT))

    with pytest.raises(VerificationError, match="nested-header-depth limit"):
        verify_artifacts(project_path, dist)


def test_sdist_malformed_pax_integer_fails_without_raw_value_error(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    payload = b"9" * 5_000 + b" x=y\n"
    extension = tarfile.TarInfo("././@PaxHeader")
    extension.type = tarfile.XHDTYPE
    extension.size = len(payload)
    padding = (-len(payload)) % tarfile.BLOCKSIZE
    with gzip.open(sdist, "wb") as archive:
        archive.write(extension.tobuf(format=tarfile.USTAR_FORMAT))
        archive.write(payload)
        archive.write(b"\0" * padding)

    with pytest.raises(VerificationError, match="cannot inspect source distribution"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_duplicate_member_paths(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    duplicate_name = f"{ARTIFACT_NAME}-{PROJECT_VERSION}/PKG-INFO"
    _write_sdist(dist, extra_member_name=duplicate_name)

    with pytest.raises(VerificationError, match="duplicate member paths"):
        verify_artifacts(project_path, dist)


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

    with pytest.raises(
        VerificationError, match="metadata outside expected dist-info directory"
    ):
        verify_artifacts(project_path, dist)


def test_wheel_metadata_is_required(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist, include_wheel_metadata=False)
    _write_sdist(dist)

    with pytest.raises(VerificationError, match="exactly one dist-info/WHEEL"):
        verify_artifacts(project_path, dist)


def test_wheel_member_path_cannot_escape_expected_dist_info(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    expected_root = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info"
    with ZipFile(wheel, "a", compression=ZIP_DEFLATED) as archive:
        archive.writestr(
            f"{expected_root}/../other_project-99.dist-info/METADATA",
            _metadata(name="other-project", version="99"),
        )
        archive.writestr(
            f"{expected_root}/../other_project-99.dist-info/WHEEL",
            "\n".join(
                (
                    "Wheel-Version: 1.0",
                    "Root-Is-Purelib: true",
                    "Tag: py3-none-any",
                    "",
                )
            ),
        )

    with pytest.raises(VerificationError, match="unsafe or ambiguous member path"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    "member",
    (
        "/absolute.py",
        "../escape.py",
        "package/./module.py",
        "package\\module.py",
        "C:/absolute.py",
    ),
)
def test_wheel_rejects_unsafe_member_paths(tmp_path, member):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    with ZipFile(wheel, "a", compression=ZIP_DEFLATED) as archive:
        archive.writestr(member, "")

    with pytest.raises(VerificationError, match="unsafe or ambiguous member path"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_rejects_foreign_dist_info_directory(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    with ZipFile(wheel, "a", compression=ZIP_DEFLATED) as archive:
        archive.writestr("other_project-99.dist-info/entry_points.txt", "")

    with pytest.raises(VerificationError, match="metadata outside expected"):
        verify_artifacts(project_path, wheel.parent)


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
