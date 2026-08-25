import base64
import hashlib
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
    extract_sdist,
    main,
    verify_artifacts,
    verify_sdist,
    verify_tag,
)


PROJECT_NAME = "verb-authority"
PROJECT_VERSION = "0.10.0b8"
ARTIFACT_NAME = "verb_authority"
MODULES = ("verb_authority", "verb_authority_scan", "verb_authority_diff")
SCRIPTS = {
    "verb-authority": "verb_authority:main",
    "verb-authority-scan": "verb_authority_scan:main",
    "verb-authority-diff": "verb_authority_diff:main",
}


def _write_project(path: Path, *, version: str = PROJECT_VERSION) -> Path:
    for module in MODULES:
        (path / f"{module}.py").write_text(
            f'VALUE = "{module}"\n',
            encoding="utf-8",
        )
    (path / "LICENSE").write_text("test license\n", encoding="utf-8")
    project_path = path / "pyproject.toml"
    project_path.write_text(
        "\n".join(
            (
                "[project]",
                f'name = "{PROJECT_NAME}"',
                f'version = "{version}"',
                'requires-python = ">=3.10"',
                'license-files = ["LICENSE"]',
                'dependencies = []',
                "",
                "[project.optional-dependencies]",
                'dev = ["build>=1.2,<2", "pytest>=8,<10"]',
                "",
                "[project.scripts]",
                *(f'"{name}" = "{target}"' for name, target in SCRIPTS.items()),
                "",
                "[tool.setuptools]",
                'py-modules = ["verb_authority", "verb_authority_scan", '
                '"verb_authority_diff"]',
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
            "Requires-Python: >=3.10",
            "Provides-Extra: dev",
            'Requires-Dist: build<2,>=1.2; extra == "dev"',
            'Requires-Dist: pytest<10,>=8; extra == "dev"',
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
    members: dict[str, bytes] = {
        f"{module}.py": (dist.parent / f"{module}.py").read_bytes()
        for module in MODULES
    }
    members[f"{metadata_dist_info_name}/licenses/LICENSE"] = (
        dist.parent / "LICENSE"
    ).read_bytes()
    members[metadata_member] = _metadata(
        name=metadata_name,
        version=metadata_version,
    ).encode("utf-8")
    dist_info_name = (
        wheel_dist_info_name
        or internal_dist_info_name
        or expected_dist_info_name
    )
    if include_wheel_metadata:
        members[f"{dist_info_name}/WHEEL"] = "\n".join(
            (
                "Wheel-Version: 1.0",
                "Generator: release-verifier-test",
                f"Root-Is-Purelib: {root_is_purelib}",
                *(f"Tag: {tag}" for tag in tags),
                "",
            )
        ).encode("utf-8")
    members[f"{metadata_dist_info_name}/entry_points.txt"] = (
        "[console_scripts]\n"
        + "".join(f"{name} = {target}\n" for name, target in SCRIPTS.items())
    ).encode("utf-8")
    members[f"{metadata_dist_info_name}/top_level.txt"] = (
        "".join(f"{module}\n" for module in sorted(MODULES))
    ).encode("utf-8")
    record_name = f"{metadata_dist_info_name}/RECORD"
    record_rows = []
    for member, payload in members.items():
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(payload).digest()
        ).rstrip(b"=").decode("ascii")
        record_rows.append(f"{member},sha256={digest},{len(payload)}\n")
    record_rows.append(f"{record_name},,\n")
    members[record_name] = "".join(record_rows).encode("utf-8")
    with ZipFile(wheel_path, "w", compression=ZIP_DEFLATED) as wheel:
        for member, payload in members.items():
            wheel.writestr(member, payload)
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
    metadata_extra: bytes = b"",
    module_payload_overrides: dict[str, bytes] | None = None,
) -> Path:
    sdist_path = dist / f"{ARTIFACT_NAME}-{filename_version}.tar.gz"
    metadata_bytes = _metadata(
        name=metadata_name,
        version=metadata_version,
    ).encode("utf-8") + metadata_extra
    module_payload_overrides = module_payload_overrides or {}
    root_name = internal_root_name or f"{ARTIFACT_NAME}-{filename_version}"
    config = release_verifier._project_release_config(dist.parent / "pyproject.toml")
    egg_info_root = f"{ARTIFACT_NAME}.egg-info"
    source_payloads = dict(config.sdist_source_payloads)
    for module, payload in module_payload_overrides.items():
        source_payloads[f"{module}.py"] = payload
    generated_source_names = {
        f"{egg_info_root}/PKG-INFO",
        f"{egg_info_root}/SOURCES.txt",
        f"{egg_info_root}/dependency_links.txt",
        f"{egg_info_root}/entry_points.txt",
        f"{egg_info_root}/requires.txt",
        f"{egg_info_root}/top_level.txt",
    }
    payloads = {
        **source_payloads,
        "PKG-INFO": metadata_bytes,
        "setup.cfg": release_verifier._GENERATED_SETUP_CFG,
        f"{egg_info_root}/PKG-INFO": metadata_bytes,
        f"{egg_info_root}/SOURCES.txt": (
            "".join(
                f"{name}\n"
                for name in sorted(set(source_payloads) | generated_source_names)
            ).encode("utf-8")
        ),
        f"{egg_info_root}/dependency_links.txt": b"\n",
        f"{egg_info_root}/entry_points.txt": (
            "[console_scripts]\n"
            + "".join(f"{name} = {target}\n" for name, target in SCRIPTS.items())
        ).encode("utf-8"),
        f"{egg_info_root}/requires.txt": (
            b"\n[dev]\nbuild<2,>=1.2\npytest<10,>=8\n"
        ),
        f"{egg_info_root}/top_level.txt": (
            "".join(f"{module}\n" for module in sorted(MODULES))
        ).encode("utf-8"),
    }
    with tarfile.open(sdist_path, "w:gz") as source_archive:
        for relative_name, payload in payloads.items():
            member = tarfile.TarInfo(f"{root_name}/{relative_name}")
            member.size = len(payload)
            source_archive.addfile(member, BytesIO(payload))
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


def _pax_record(key: str, value: str) -> bytes:
    body = f" {key}={value}\n".encode("utf-8")
    length = len(body) + 1
    while True:
        record = str(length).encode("ascii") + body
        if len(record) == length:
            return record
        length = len(record)


def _tar_block(info: tarfile.TarInfo, payload: bytes = b"") -> bytes:
    assert info.size == len(payload)
    return (
        info.tobuf(format=tarfile.USTAR_FORMAT)
        + payload
        + b"\0" * ((-len(payload)) % tarfile.BLOCKSIZE)
    )


def _rewrite_wheel(
    wheel: Path,
    *,
    changes: dict[str, bytes] | None = None,
    remove: set[str] | None = None,
    refresh_record: bool = True,
) -> None:
    changes = changes or {}
    remove = remove or set()
    record_name = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/RECORD"
    with ZipFile(wheel) as archive:
        members = {
            info.filename: archive.read(info)
            for info in archive.infolist()
            if info.filename not in remove
        }
    members.update(changes)
    if refresh_record:
        members.pop(record_name, None)
        rows = []
        for member, payload in members.items():
            digest = base64.urlsafe_b64encode(
                hashlib.sha256(payload).digest()
            ).rstrip(b"=").decode("ascii")
            rows.append(f"{member},sha256={digest},{len(payload)}\n")
        rows.append(f"{record_name},,\n")
        members[record_name] = "".join(rows).encode("utf-8")
    buffer = BytesIO()
    with ZipFile(buffer, "w", compression=ZIP_DEFLATED) as archive:
        for member, payload in members.items():
            archive.writestr(member, payload)
    wheel.write_bytes(buffer.getvalue())


def _rewrite_sdist(
    sdist: Path,
    *,
    changes: dict[str, bytes] | None = None,
    remove: set[str] | None = None,
) -> None:
    changes = changes or {}
    remove = remove or set()
    with tarfile.open(sdist, "r:gz") as archive:
        payloads = {
            member.name: archive.extractfile(member).read()
            for member in archive.getmembers()
            if member.isfile() and member.name not in remove
        }
    payloads.update(changes)
    buffer = BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for member_name, payload in payloads.items():
            member = tarfile.TarInfo(member_name)
            member.size = len(payload)
            archive.addfile(member, BytesIO(payload))
    sdist.write_bytes(buffer.getvalue())


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

    with pytest.raises(VerificationError, match="unsafe or (?:unexpected|ambiguous) member path"):
        verify_artifacts(project_path, dist)


@pytest.mark.parametrize(
    "leaf",
    (
        "payload.",
        "payload ",
        "CON.txt",
        "CONIN$.txt",
        "CONOUT$",
        "CLOCK$.txt",
        "name:stream",
        "control\x1f",
    ),
)
def test_sdist_rejects_windows_portable_path_aliases(tmp_path, leaf):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(
        dist,
        extra_member_name=f"{ARTIFACT_NAME}-{PROJECT_VERSION}/{leaf}",
    )

    with pytest.raises(VerificationError, match="unsafe or ambiguous member path"):
        verify_artifacts(project_path, dist)


@pytest.mark.parametrize(
    "member",
    ("COM¹.py", "COM².py", "LPT³.py"),
)
def test_portable_path_boundary_rejects_windows_superscript_devices(member):
    with pytest.raises(VerificationError, match="unsafe or ambiguous member path"):
        release_verifier._portable_member_key(member, archive_label="test archive")


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


def test_sdist_rejects_project_module_size_mismatch_before_reading_it(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    expected = (tmp_path / "verb_authority.py").read_bytes()
    _write_sdist(
        dist,
        module_payload_overrides={"verb_authority": expected + b"X"},
    )

    with pytest.raises(VerificationError, match="module size does not match"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_oversized_pkg_info_before_reading_payload(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(
        dist,
        metadata_extra=b"X" * release_verifier.MAX_CORE_METADATA_BYTES,
    )

    with pytest.raises(VerificationError, match="PKG-INFO exceeds"):
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

    with pytest.raises(VerificationError, match="malformed PAX record"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_global_pax_before_size_override_can_smuggle_members(
    tmp_path,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    payload = _pax_record("size", "0")
    global_pax = tarfile.TarInfo("GlobalHead")
    global_pax.type = tarfile.XGLTYPE
    global_pax.size = len(payload)
    with gzip.open(sdist, "wb") as archive:
        archive.write(_tar_block(global_pax, payload))

    with pytest.raises(VerificationError, match="global PAX header"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_local_pax_size_override(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    payload = _pax_record("size", "0")
    local_pax = tarfile.TarInfo("././@PaxHeader")
    local_pax.type = tarfile.XHDTYPE
    local_pax.size = len(payload)
    with gzip.open(sdist, "wb") as archive:
        archive.write(_tar_block(local_pax, payload))

    with pytest.raises(VerificationError, match="unsupported PAX key 'size'"):
        verify_artifacts(project_path, dist)


def test_sdist_rejects_gnu_sparse_pax_before_reading_sparse_map(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = dist / f"{ARTIFACT_NAME}-{PROJECT_VERSION}.tar.gz"
    payload = b"".join(
        (
            _pax_record("GNU.sparse.major", "1"),
            _pax_record("GNU.sparse.minor", "0"),
            _pax_record("GNU.sparse.realsize", "0"),
        )
    )
    local_pax = tarfile.TarInfo("././@PaxHeader")
    local_pax.type = tarfile.XHDTYPE
    local_pax.size = len(payload)
    # No following member or sparse-map body is needed: the extension itself
    # must be rejected before stdlib sparse processing asks for either one.
    with gzip.open(sdist, "wb") as archive:
        archive.write(_tar_block(local_pax, payload))

    with pytest.raises(
        VerificationError,
        match="unsupported PAX key 'GNU.sparse.major'",
    ):
        verify_artifacts(project_path, dist)


def test_safe_sdist_extraction_uses_verified_parser(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    sdist = _write_sdist(dist)
    output = tmp_path / "extracted"

    root = extract_sdist(project_path, dist, output)

    assert root == output / f"{ARTIFACT_NAME}-{PROJECT_VERSION}"
    assert (root / "verb_authority.py").read_bytes() == (
        tmp_path / "verb_authority.py"
    ).read_bytes()
    assert sdist.exists()


def test_safe_sdist_extraction_requires_new_output_directory(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_sdist(dist)
    output = tmp_path / "extracted"
    output.mkdir()

    with pytest.raises(VerificationError, match="must be a new directory"):
        extract_sdist(project_path, dist, output)


def test_safe_sdist_extraction_cli(tmp_path):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_sdist(dist)
    output = tmp_path / "cli-extracted"

    assert (
        main(
            [
                "extract-sdist",
                "--project",
                str(project_path),
                "--dist",
                str(dist),
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert (output / f"{ARTIFACT_NAME}-{PROJECT_VERSION}").is_dir()


def test_workflows_use_bounded_extractor_instead_of_command_line_tar():
    repository = Path(__file__).resolve().parent
    for workflow in (
        repository / ".github/workflows/ci.yml",
        repository / ".github/workflows/release.yml",
    ):
        text = workflow.read_text(encoding="utf-8")
        assert "extract-sdist" in text
        assert "tar -x" not in text
        assert 'python -I scripts/verify_release_artifacts.py artifacts' in text
        assert '$SDIST_ROOT/scripts/verify_release_artifacts.py" artifacts' not in text


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


@pytest.mark.parametrize(
    "member",
    (
        "verb_authority.py.",
        "verb_authority.py ",
        "CON.txt",
        "CON .txt",
        "CONIN$.txt",
        "CONOUT$",
        "CLOCK$.txt",
        "package/COM¹.py",
        "package/COM².py",
        "package/LPT³.py",
        "package/aux.py",
        "package/name:stream.py",
        "package/control\x1f.py",
    ),
)
def test_wheel_rejects_windows_portable_path_aliases(tmp_path, member):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    with ZipFile(wheel, "a", compression=ZIP_DEFLATED) as archive:
        archive.writestr(member, b"unexpected")

    with pytest.raises(VerificationError, match="unsafe or ambiguous member path"):
        verify_artifacts(project_path, wheel.parent)


def test_member_path_caps_run_before_unicode_normalization(tmp_path, monkeypatch):
    original_normalize = release_verifier.unicodedata.normalize

    def bounded_normalize(form, value):
        assert len(value) <= release_verifier.MAX_ARCHIVE_COMPONENT_CODEPOINTS
        return original_normalize(form, value)

    monkeypatch.setattr(
        release_verifier.unicodedata,
        "normalize",
        bounded_normalize,
    )
    project_path, wheel, _ = _write_valid_release(tmp_path)
    with ZipFile(wheel, "a", compression=ZIP_DEFLATED) as archive:
        archive.writestr("a" * 256, b"")

    with pytest.raises(VerificationError, match="pre-normalization|unsafe"):
        verify_artifacts(project_path, wheel.parent)


def test_member_component_encoded_byte_cap_runs_before_normalization(
    tmp_path,
    monkeypatch,
):
    original_normalize = release_verifier.unicodedata.normalize

    def bounded_normalize(form, value):
        assert len(value.encode("utf-8")) <= (
            release_verifier.MAX_ARCHIVE_COMPONENT_BYTES
        )
        return original_normalize(form, value)

    monkeypatch.setattr(
        release_verifier.unicodedata,
        "normalize",
        bounded_normalize,
    )
    project_path, wheel, _ = _write_valid_release(tmp_path)
    with ZipFile(wheel, "a", compression=ZIP_DEFLATED) as archive:
        archive.writestr("é" * 128, b"")

    with pytest.raises(VerificationError, match="unsafe or ambiguous"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    "member",
    (
        "other_project-99.egg-info/PKG-INFO",
        "other_project-99.data/scripts/foreign-tool",
        "verb_authority_startup.pth",
        "sitecustomize.py",
    ),
)
def test_wheel_rejects_payload_outside_pyproject_allowlist(tmp_path, member):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    _rewrite_wheel(
        wheel,
        changes={member: b"unexpected"},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="pyproject allowlist"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_record_must_cover_and_authenticate_every_member(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    metadata_name = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA"
    _rewrite_wheel(
        wheel,
        changes={metadata_name: _metadata().encode("utf-8") + b"X"},
        refresh_record=False,
    )

    with pytest.raises(VerificationError, match="RECORD hash or size"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_metadata_must_match_verified_sdist_bytes(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    metadata_name = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA"
    _rewrite_wheel(
        wheel,
        changes={metadata_name: _metadata().encode("utf-8") + b"Summary: changed\n"},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="differs from verified sdist"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_metadata_caps_apply_before_member_payloads_are_read(
    tmp_path,
    monkeypatch,
):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    metadata_name = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA"
    _rewrite_wheel(
        wheel,
        changes={
            metadata_name: b"X" * (release_verifier.MAX_CORE_METADATA_BYTES + 1)
        },
        refresh_record=True,
    )

    def unexpected_read(_wheel):
        raise AssertionError("wheel payload was read before metadata size checks")

    monkeypatch.setattr(
        release_verifier,
        "_read_wheel_members",
        unexpected_read,
    )
    with pytest.raises(VerificationError, match="metadata member exceeds"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    "member",
    (
        "verb_authority.py",
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/licenses/LICENSE",
    ),
)
def test_wheel_project_payload_sizes_are_checked_before_reading(tmp_path, member):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    with ZipFile(wheel) as archive:
        original = archive.read(member)
    _rewrite_wheel(
        wheel,
        changes={member: original + b"X"},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="size does not match"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_record_is_required(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    record_name = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/RECORD"
    _rewrite_wheel(
        wheel,
        remove={record_name},
        refresh_record=False,
    )

    with pytest.raises(VerificationError, match="pyproject allowlist"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_entry_points_must_exactly_match_project_scripts(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    entry_points = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/entry_points.txt"
    _rewrite_wheel(
        wheel,
        changes={
            entry_points: (
                b"[console_scripts]\n"
                b"verb-authority = verb_authority:main\n"
                b"verb-authority-scan = verb_authority_scan:main\n"
                b"verb-authority-diff = evil:main\n"
            )
        },
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="console scripts"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_top_level_must_exactly_match_py_modules(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    top_level = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/top_level.txt"
    _rewrite_wheel(
        wheel,
        changes={top_level: b"verb_authority\nevil\n"},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="top_level.txt"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_module_bytes_must_match_verified_sdist(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    source = (tmp_path / "verb_authority.py").read_bytes()
    _rewrite_wheel(
        wheel,
        changes={"verb_authority.py": b"X" * len(source)},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="differs from the verified sdist"):
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


def test_sdist_pyproject_bytes_are_bound_to_trusted_checkout(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}/pyproject.toml"
    trusted = project_path.read_bytes()
    _rewrite_sdist(
        sdist,
        changes={member: trusted.replace(b"dependencies = []", b'dependencies = ["evil"]')},
    )

    with pytest.raises(VerificationError, match="trusted checkout.*pyproject.toml"):
        verify_artifacts(project_path, wheel.parent)


def test_sdist_expected_verifier_bytes_are_bound_to_trusted_checkout(tmp_path):
    project_path = _write_project(tmp_path)
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    verifier = scripts / "verify_release_artifacts.py"
    verifier.write_text("TRUSTED = True\n", encoding="utf-8")
    (tmp_path / "MANIFEST.in").write_text(
        "include scripts/verify_release_artifacts.py\n",
        encoding="utf-8",
    )
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = _write_sdist(dist)
    member = (
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}/"
        "scripts/verify_release_artifacts.py"
    )
    _rewrite_sdist(sdist, changes={member: b"TRUSTED = False\n"})

    with pytest.raises(
        VerificationError,
        match="trusted checkout.*verify_release_artifacts.py",
    ):
        verify_artifacts(project_path, dist)


@pytest.mark.parametrize(
    "member",
    (
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}/pytest.py",
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}/evil_build_backend.py",
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}/scripts/verify_release_artifacts.py",
    ),
)
def test_sdist_rejects_untrusted_executable_or_build_inputs(tmp_path, member):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    _rewrite_sdist(sdist, changes={member: b"raise SystemExit('executed')\n"})

    with pytest.raises(VerificationError, match="trusted source manifest"):
        verify_artifacts(project_path, wheel.parent)


def test_sdist_generated_setup_cfg_is_not_an_untrusted_build_input(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}/setup.cfg"
    _rewrite_sdist(
        sdist,
        changes={member: b"[options]\npy_modules = evil\n"},
    )

    with pytest.raises(VerificationError, match="generated setup.cfg"):
        verify_artifacts(project_path, wheel.parent)


def test_sdist_generated_sources_manifest_is_exact(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    member = (
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}/"
        f"{ARTIFACT_NAME}.egg-info/SOURCES.txt"
    )
    with tarfile.open(sdist, "r:gz") as archive:
        original = archive.extractfile(member).read()
    _rewrite_sdist(sdist, changes={member: original + b"pytest.py\n"})

    with pytest.raises(VerificationError, match="SOURCES.txt.*trusted source manifest"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    ("metadata_payload", "message"),
    (
        (
            _metadata().encode("utf-8")
            + b"Requires-Dist: attacker-only-on-windows>=1\n",
            "Requires-Dist.*project dependencies",
        ),
        (
            _metadata().encode("utf-8") + b"Provides-Extra: attacker\n",
            "Provides-Extra.*optional-dependencies",
        ),
        (
            _metadata().encode("utf-8") + b"Requires-Python: >=2\n",
            "exactly one non-empty Requires-Python",
        ),
        (
            _metadata().replace("Metadata-Version: 2.4", "Metadata-Version: 2.3").encode("utf-8"),
            "Metadata-Version must be '2.4'",
        ),
        (
            _metadata().replace("Metadata-Version: 2.4\n", "").encode("utf-8"),
            "exactly one non-empty Metadata-Version",
        ),
    ),
)
def test_sdist_and_wheel_metadata_cannot_share_a_forged_dependency_contract(
    tmp_path,
    metadata_payload,
    message,
):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    sdist_root = f"{ARTIFACT_NAME}-{PROJECT_VERSION}"
    sdist_changes = {
        f"{sdist_root}/PKG-INFO": metadata_payload,
        f"{sdist_root}/{ARTIFACT_NAME}.egg-info/PKG-INFO": metadata_payload,
    }
    _rewrite_sdist(sdist, changes=sdist_changes)
    wheel_metadata = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA"
    _rewrite_wheel(
        wheel,
        changes={wheel_metadata: metadata_payload},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match=message):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_requires_supported_wheel_version(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    wheel_member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/WHEEL"
    with ZipFile(wheel) as archive:
        descriptor = archive.read(wheel_member)
    without_version = b"\n".join(
        line
        for line in descriptor.splitlines()
        if not line.startswith(b"Wheel-Version:")
    ) + b"\n"
    _rewrite_wheel(
        wheel,
        changes={wheel_member: without_version},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="supported Wheel-Version: 1.0"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize("damage", ("missing-trailer", "bad-crc"))
def test_sdist_gzip_trailer_is_fully_validated(tmp_path, damage):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    archive = bytearray(sdist.read_bytes())
    if damage == "missing-trailer":
        del archive[-8:]
    else:
        archive[-8] ^= 0x01
    sdist.write_bytes(archive)

    with pytest.raises(VerificationError, match="gzip"):
        verify_artifacts(project_path, wheel.parent)


def test_sdist_rejects_a_second_valid_gzip_member(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    sdist.write_bytes(
        sdist.read_bytes() + gzip.compress(b"MALICIOUS-TRAILING-MEMBER")
    )

    with pytest.raises(
        VerificationError,
        match="more than one gzip member or trailing compressed data",
    ):
        verify_artifacts(project_path, wheel.parent)
