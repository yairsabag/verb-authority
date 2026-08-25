import base64
import hashlib
from io import BytesIO
import gzip
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tarfile
import zlib
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

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


def _git(repository: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def _commit_test_project(repository: Path) -> str:
    _git(repository, "init")
    _git(repository, "config", "user.name", "Release Verifier Test")
    _git(repository, "config", "user.email", "release-verifier@example.invalid")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "trusted source")
    return _git(repository, "rev-parse", "HEAD")


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
            "License-File: LICENSE",
            "Provides-Extra: dev",
            'Requires-Dist: build<2,>=1.2; extra == "dev"',
            'Requires-Dist: pytest<10,>=8; extra == "dev"',
            "Dynamic: license-file",
            "",
        )
    )


def _static_metadata(*, project_url: str, summary: str, body: str) -> bytes:
    headers = (
        "Metadata-Version: 2.4",
        f"Name: {PROJECT_NAME}",
        f"Version: {PROJECT_VERSION}",
        f"Summary: {summary}",
        "License-Expression: Apache-2.0",
        f"Project-URL: Repository, {project_url}",
        "Keywords: agent-security,tool-calling",
        "Classifier: Topic :: Security",
        "Requires-Python: >=3.10",
        "Description-Content-Type: text/markdown",
        "License-File: LICENSE",
        "Provides-Extra: dev",
        'Requires-Dist: build<2,>=1.2; extra == "dev"',
        'Requires-Dist: pytest<10,>=8; extra == "dev"',
        "Dynamic: license-file",
    )
    return ("\n".join((*headers, "", body))).encode("utf-8")


def _enable_static_project_metadata(path: Path) -> tuple[str, str, str]:
    summary = "Immutable release metadata"
    project_url = "https://example.invalid/trusted"
    body = "# Trusted readme\n\nExact committed description.\n"
    project = path / "pyproject.toml"
    project.write_text(
        project.read_text(encoding="utf-8").replace(
            'license-files = ["LICENSE"]\n',
            'description = "Immutable release metadata"\n'
            'readme = "README.md"\n'
            'license = "Apache-2.0"\n'
            'license-files = ["LICENSE"]\n'
            'keywords = ["agent-security", "tool-calling"]\n'
            'classifiers = ["Topic :: Security"]\n',
        )
        + '\n[project.urls]\nRepository = "https://example.invalid/trusted"\n',
        encoding="utf-8",
    )
    (path / "README.md").write_text(body, encoding="utf-8")
    return summary, project_url, body


def _wheel_info(member: str, *, mode: int | None = None) -> ZipInfo:
    info = ZipInfo(member)
    info.compress_type = ZIP_DEFLATED
    info.create_system = 3
    if mode is None:
        mode = 0o664 if member.endswith(".dist-info/RECORD") else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


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
            wheel.writestr(_wheel_info(member), payload)
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
    mode_changes: dict[str, int] | None = None,
    comment_changes: dict[str, bytes] | None = None,
    extra_changes: dict[str, bytes] | None = None,
) -> None:
    changes = changes or {}
    remove = remove or set()
    mode_changes = mode_changes or {}
    comment_changes = comment_changes or {}
    extra_changes = extra_changes or {}
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
            info = _wheel_info(member, mode=mode_changes.get(member))
            info.comment = comment_changes.get(member, b"")
            info.extra = extra_changes.get(member, b"")
            archive.writestr(info, payload)
    wheel.write_bytes(buffer.getvalue())


def _rewrite_static_metadata_pair(
    wheel: Path,
    sdist: Path,
    metadata: bytes,
) -> None:
    sdist_root = f"{ARTIFACT_NAME}-{PROJECT_VERSION}"
    _rewrite_sdist(
        sdist,
        changes={
            f"{sdist_root}/PKG-INFO": metadata,
            f"{sdist_root}/{ARTIFACT_NAME}.egg-info/PKG-INFO": metadata,
        },
    )
    _rewrite_wheel(
        wheel,
        changes={
            f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA": metadata
        },
    )


def _gzip_sdist_payload(sdist: Path, payload: bytes) -> None:
    buffer = BytesIO()
    with gzip.GzipFile(
        filename=sdist.name.removesuffix(".gz"),
        mode="wb",
        fileobj=buffer,
        mtime=0,
    ) as archive:
        archive.write(payload)
    sdist.write_bytes(buffer.getvalue())


def _rewrite_sdist(
    sdist: Path,
    *,
    changes: dict[str, bytes] | None = None,
    remove: set[str] | None = None,
    mode_changes: dict[str, int] | None = None,
) -> None:
    changes = changes or {}
    remove = remove or set()
    mode_changes = mode_changes or {}
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
            if member_name in mode_changes:
                member.mode = mode_changes[member_name]
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


def test_real_setuptools_build_uses_the_verified_archive_contract(tmp_path):
    build_available = subprocess.run(
        [sys.executable, "-I", "-m", "build", "--version"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    if build_available.returncode:
        pytest.skip("the build frontend is installed by the release CI job")
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(dist),
        ],
        cwd=tmp_path,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    wheel, sdist = verify_artifacts(project_path, dist)
    assert wheel.suffix == ".whl"
    assert sdist.name.endswith(".tar.gz")


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
                "--allow-mutable-source",
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
                "--allow-mutable-source",
            ]
        )
        == 2
    )
    assert "source-distribution root" in capsys.readouterr().err


def test_release_cli_requires_immutable_git_source_or_explicit_local_mode(
    tmp_path,
    capsys,
):
    project_path = _write_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_sdist(dist)

    assert main(
        [
            "sdist",
            "--project",
            str(project_path),
            "--dist",
            str(dist),
        ]
    ) == 2
    assert "requires --repository and --source-commit" in capsys.readouterr().err


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
                "--allow-mutable-source",
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
        assert 'python -I "$RELEASE_VERIFIER" artifacts' in text
        assert "/usr/bin/git --no-pager --no-replace-objects" in text
        assert "GIT_NO_REPLACE_OBJECTS=1" in text
        assert "GIT_NO_LAZY_FETCH=1" in text
        assert "persist-credentials: false" in text
        assert "LD_*|DYLD_*|GCONV_PATH|LOCPATH|PYTHONPATH|PYTHONHOME" in text
        assert "export PATH=/usr/bin:/bin" in text
        assert "export LC_ALL=C" in text
        assert "export LANG=C" in text
        assert "protocol.ext.allow=never" in text
        assert "protocol.file.allow=never" in text
        assert 'read_object("commit", source_commit' in text
        assert 'read_object("tree", tree_id' in text
        assert 'read_object("blob", current' in text
        assert "git {kind} object hash mismatch" in text
        assert "verifier path is absent or has an unsafe mode" in text
        assert 'verifier_blob=$("$python_safe" -I -' in text
        assert 'verifier_blob=$("$python_safe" - \\' not in text
        assert 'hash-object --no-filters "$verifier"' in text
        assert "git show" not in text
        assert '--repository "${{ github.workspace }}"' in text
        assert '--source-commit "$SOURCE_COMMIT"' in text
        assert '$SDIST_ROOT/scripts/verify_release_artifacts.py" artifacts' not in text
        assert 'python -I scripts/verify_release_artifacts.py artifacts' not in text


def test_workflows_pin_every_remote_action_to_the_reviewed_commit():
    repository = Path(__file__).resolve().parent
    expected = {
        "actions/checkout": (
            "3d3c42e5aac5ba805825da76410c181273ba90b1",
            "v7.0.1",
        ),
        "actions/setup-python": (
            "5fda3b95a4ea91299a34e894583c3862153e4b97",
            "v7.0.0",
        ),
        "actions/upload-artifact": (
            "043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
            "v7.0.1",
        ),
        "actions/download-artifact": (
            "70fc10c6e5e1ce46ad2ea6f2b72d43f7d47b13c3",
            "v8.0.0",
        ),
    }
    observed = set()
    workflow_directory = repository / ".github/workflows"
    workflows = sorted(
        (*workflow_directory.glob("*.yml"), *workflow_directory.glob("*.yaml"))
    )
    for workflow in workflows:
        workflow_lines = workflow.read_text(encoding="utf-8").splitlines()
        for line_number, raw_line in enumerate(workflow_lines):
            line = raw_line.strip()
            if not line.startswith("uses: "):
                continue
            reference = line.removeprefix("uses: ")
            if reference.startswith("./"):
                continue
            action_reference, separator, comment = reference.partition(" # ")
            action, at, revision = action_reference.partition("@")
            assert separator == " # ", f"missing reviewed-version comment: {line}"
            assert at == "@" and action in expected, f"unreviewed remote action: {line}"
            expected_revision, expected_tag = expected[action]
            assert revision == expected_revision
            assert comment == expected_tag
            if action == "actions/checkout":
                checkout_block = "\n".join(
                    workflow_lines[line_number : line_number + 8]
                )
                assert "persist-credentials: false" in checkout_block
            observed.add(action)
    assert observed == set(expected)


def test_release_candidate_is_reverified_on_a_fresh_read_only_runner():
    repository = Path(__file__).resolve().parent
    text = (repository / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    pre_jobs, jobs = text.split("\njobs:\n", 1)
    build, verify_and_later = jobs.split("\n  verify_and_stage:\n", 1)
    verify = verify_and_later.split("\n  publish:\n", 1)[0]

    assert "permissions:\n  contents: read" in pre_jobs
    assert "contents: write" not in pre_jobs
    assert "  build:\n" in f"  {build}"
    assert "    permissions:\n      contents: read" in build
    assert "candidate_artifact_id:" in build
    assert "candidate_artifact_digest:" in build
    assert "id: upload_candidate" in build
    assert "overwrite: false" in build
    assert "include-hidden-files: false" in build
    assert 'test "${#entries[@]}" -eq 3' in build
    assert "cmp -s \"$expected\" dist/SHA256SUMS" in build

    assert "    needs: build" in verify
    assert "    permissions:\n      contents: read" in verify
    assert "actions/checkout@" in verify
    assert "persist-credentials: false" in verify
    assert "actions/download-artifact@" in verify
    assert "artifact-ids: ${{ needs.build.outputs.candidate_artifact_id }}" in verify
    assert "merge-multiple: false" in verify
    assert "digest-mismatch: error" in verify
    assert "CANDIDATE_ARTIFACT_DIGEST" in verify
    assert "actions/setup-python@" not in verify
    assert "pip install" not in verify
    assert "python -m build" not in verify
    assert "python -m pytest" not in verify
    assert "installed_wheel_smoke" not in verify
    assert '"$RELEASE_PYTHON" -I "$RELEASE_VERIFIER" artifacts' in verify
    assert "--repository \"${{ github.workspace }}\"" in verify
    assert '--source-commit "$SOURCE_COMMIT"' in verify
    assert 'test "${#entries[@]}" -eq 3' in verify
    assert "cmp -s incoming/SHA256SUMS staged/SHA256SUMS" in verify
    assert "id: upload_verified" in verify
    assert "verified_artifact_id:" in verify
    assert "verified_artifact_digest:" in verify


def test_release_publish_job_has_only_the_minimal_write_boundary():
    repository = Path(__file__).resolve().parent
    text = (repository / ".github/workflows/release.yml").read_text(
        encoding="utf-8"
    )
    pre_publish, publish_body = text.split("\n  publish:\n", 1)
    publish = "  publish:\n" + publish_body

    assert "contents: write" not in pre_publish
    assert "    needs: verify_and_stage" in publish
    assert "    permissions:\n      contents: write" in publish
    assert "actions/checkout@" not in publish
    assert "actions/setup-python@" not in publish
    assert "pip install" not in publish
    assert "python " not in publish.lower()
    assert "RELEASE_VERIFIER" not in publish
    assert "scripts/" not in publish
    assert "verified_artifact_id" in publish
    assert "verified_artifact_digest" in publish
    assert "artifact-ids: ${{ needs.verify_and_stage.outputs.verified_artifact_id }}" in publish
    assert "merge-multiple: false" in publish
    assert "digest-mismatch: error" in publish
    assert 'test "${#entries[@]}" -eq 3' in publish
    assert 'test "${#wheels[@]}" -eq 1' in publish
    assert 'test "${#sdists[@]}" -eq 1' in publish
    assert "sha256sum --" in publish
    assert "cmp -s \"$expected\" release-assets/SHA256SUMS" in publish
    assert "GH_TOKEN: ${{ github.token }}" in publish
    assert "GH_REPO: ${{ github.repository }}" in publish
    assert "RELEASE_ID: ${{ github.event.release.id }}" in publish
    assert '"repos/$GH_REPO/releases/$RELEASE_ID"' in publish
    assert (
        '"https://uploads.github.com/repos/$GH_REPO/releases/'
        '$RELEASE_ID/assets?name=$name"' in publish
    )
    assert "gh release view" not in publish
    assert "gh release upload" not in publish
    assert "--clobber" not in publish
    assert "--method POST" in publish
    assert "--input \"$candidate\"" in publish
    assert (
        "[(.id | tostring), .tag_name, (.draft | tostring)] | @tsv"
        in publish
    )
    assert "(.size | tostring), .digest, .state" in publish
    assert "comm -23 \"$existing_assets\" \"$expected_assets\"" in publish
    assert "grep -Fqx -- \"$expected_asset\" \"$existing_assets\"" in publish
    assert "grep -Fqx -- \"$expected_asset\" \"$recovered_assets\"" in publish
    assert "continue" in publish
    assert 'cmp -s "$expected_assets" "$actual_assets"' in publish
    assert publish.count('"repos/$GH_REPO/commits/tags/$RELEASE_TAG"') == 2
    assert publish.count('test "$current_tag_commit" = "$SOURCE_COMMIT"') == 2


def test_workflow_bootstraps_reject_group_or_world_writable_tools():
    repository = Path(__file__).resolve().parent
    workflows = [
        (repository / ".github/workflows/ci.yml").read_text(encoding="utf-8"),
        (repository / ".github/workflows/release.yml").read_text(
            encoding="utf-8"
        ),
    ]
    combined = "\n".join(workflows)

    assert 'stat -c %a /usr/bin/git)" -le 755' not in combined
    assert 'stat -c %a "$python_safe")" -le 755' not in combined
    assert combined.count('test "$((8#$git_mode & 8#022))" -eq 0') == 3
    assert combined.count('test "$((8#$python_mode & 8#022))" -eq 0') == 3
    assert combined.count('[[ "$git_mode" =~ ^[0-7]{3,4}$ ]]') == 3
    assert combined.count('[[ "$python_mode" =~ ^[0-7]{3,4}$ ]]') == 3
    assert combined.count("stat -c %a -- /usr/bin/git") == 3
    assert combined.count('stat -c %a -- "$python_safe"') == 3


def test_workflow_bootstrap_shape_defeats_local_replace_ref(tmp_path):
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    verifier = scripts / "verify_release_artifacts.py"
    verifier.write_text("TRUSTED = True\n", encoding="utf-8")
    trusted_commit = _commit_test_project(tmp_path)
    verifier.write_text("TRUSTED = False\n", encoding="utf-8")
    _git(tmp_path, "add", "scripts/verify_release_artifacts.py")
    _git(tmp_path, "commit", "-m", "malicious replacement")
    replacement_commit = _git(tmp_path, "rev-parse", "HEAD")
    _git(tmp_path, "replace", trusted_commit, replacement_commit)

    assert _git(
        tmp_path,
        "show",
        f"{trusted_commit}:scripts/verify_release_artifacts.py",
    ) == "TRUSTED = False"
    hardened = subprocess.run(
        [
            "git",
            "--no-pager",
            "--no-replace-objects",
            "-C",
            str(tmp_path),
            "show",
            f"{trusted_commit}:scripts/verify_release_artifacts.py",
        ],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert hardened.stdout == "TRUSTED = True\n"


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

    with pytest.raises(
        VerificationError,
        match="differs from verified sdist|immutable project metadata",
    ):
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


@pytest.mark.parametrize(
    "forged_requirement",
    (
        'build\u00a0<2,>=1.2; extra == "dev"',
        'build<2,>=1.2; extra\u00a0== "dev"',
    ),
)
def test_consistent_wheel_and_sdist_metadata_reject_non_ascii_pep508_space(
    tmp_path,
    forged_requirement,
):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    forged_metadata = _metadata().replace(
        'build<2,>=1.2; extra == "dev"',
        forged_requirement,
    ).encode("utf-8")
    sdist_root = f"{ARTIFACT_NAME}-{PROJECT_VERSION}"
    _rewrite_sdist(
        sdist,
        changes={
            f"{sdist_root}/PKG-INFO": forged_metadata,
            f"{sdist_root}/{ARTIFACT_NAME}.egg-info/PKG-INFO": forged_metadata,
        },
    )
    _rewrite_wheel(
        wheel,
        changes={
            f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA": (
                forged_metadata
            )
        },
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="non-ASCII or control material"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("Metadata-Version", "2.4"),
        ("Name", PROJECT_NAME),
        ("Version", PROJECT_VERSION),
    ),
)
def test_consistent_wheel_and_sdist_reject_nbsp_in_core_identity_field(
    tmp_path,
    field,
    value,
):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    forged_metadata = _metadata().replace(
        f"{field}: {value}",
        f"{field}: {value}\u00a0",
        1,
    ).encode("utf-8")
    sdist_root = f"{ARTIFACT_NAME}-{PROJECT_VERSION}"
    _rewrite_sdist(
        sdist,
        changes={
            f"{sdist_root}/PKG-INFO": forged_metadata,
            f"{sdist_root}/{ARTIFACT_NAME}.egg-info/PKG-INFO": forged_metadata,
        },
    )
    _rewrite_wheel(
        wheel,
        changes={
            f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA": (
                forged_metadata
            )
        },
        refresh_record=True,
    )

    with pytest.raises(
        VerificationError,
        match=rf"{field}.*non-ASCII or control material",
    ):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("Wheel-Version", "1.0"),
        ("Root-Is-Purelib", "true"),
        ("Tag", "py3-none-any"),
    ),
)
def test_wheel_control_field_rejects_trailing_nbsp(
    tmp_path,
    field,
    value,
):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    wheel_member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/WHEEL"
    with ZipFile(wheel) as archive:
        descriptor = archive.read(wheel_member)
    forged = descriptor.replace(
        f"{field}: {value}".encode("ascii"),
        f"{field}: {value}\u00a0".encode("utf-8"),
        1,
    )
    _rewrite_wheel(
        wheel,
        changes={wheel_member: forged},
        refresh_record=True,
    )

    with pytest.raises(
        VerificationError,
        match=rf"{field}.*non-ASCII or control material",
    ):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_descriptor_rejects_hidden_body(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    wheel_member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/WHEEL"
    with ZipFile(wheel) as archive:
        descriptor = archive.read(wheel_member)
    _rewrite_wheel(
        wheel,
        changes={wheel_member: descriptor + b"\nHIDDEN-WHEEL-BODY\n"},
    )

    with pytest.raises(VerificationError, match="WHEEL metadata must not contain a body"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize("target", ("key", "value"))
def test_wheel_entry_point_rejects_trailing_nbsp(tmp_path, target):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/entry_points.txt"
    with ZipFile(wheel) as archive:
        entry_points = archive.read(member)
    if target == "key":
        forged = entry_points.replace(
            b"verb-authority =",
            "verb-authority\u00a0 =".encode("utf-8"),
            1,
        )
    else:
        forged = entry_points.replace(
            b"verb_authority:main\n",
            "verb_authority:main\u00a0\n".encode("utf-8"),
            1,
        )
    _rewrite_wheel(
        wheel,
        changes={member: forged},
        refresh_record=True,
    )

    with pytest.raises(VerificationError, match="entry_points.*non-ASCII"):
        verify_artifacts(project_path, wheel.parent)


def test_ascii_space_and_tab_pep508_separators_remain_valid(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    ascii_metadata = _metadata().replace(
        'build<2,>=1.2; extra == "dev"',
        'build\t<2,\t>=1.2;\textra\t==\t"dev"',
    ).encode("utf-8")
    sdist_root = f"{ARTIFACT_NAME}-{PROJECT_VERSION}"
    requires_name = f"{sdist_root}/{ARTIFACT_NAME}.egg-info/requires.txt"
    _rewrite_sdist(
        sdist,
        changes={
            f"{sdist_root}/PKG-INFO": ascii_metadata,
            f"{sdist_root}/{ARTIFACT_NAME}.egg-info/PKG-INFO": ascii_metadata,
            requires_name: b"\n[dev]\nbuild\t<2,\t>=1.2\npytest<10,>=8\n",
        },
    )
    _rewrite_wheel(
        wheel,
        changes={
            f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA": (
                ascii_metadata
            )
        },
        refresh_record=True,
    )

    assert verify_artifacts(project_path, wheel.parent) == (wheel, sdist)


def test_static_core_metadata_and_body_match_immutable_project(tmp_path):
    project_path = _write_project(tmp_path)
    summary, project_url, body = _enable_static_project_metadata(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    metadata = _static_metadata(
        project_url=project_url,
        summary=summary,
        body=body,
    )
    _rewrite_static_metadata_pair(wheel, sdist, metadata)

    assert verify_artifacts(project_path, dist) == (wheel, sdist)


@pytest.mark.parametrize(
    ("target", "replacement", "message"),
    (
        (
            b"https://example.invalid/trusted",
            b"https://evil.invalid/phish",
            "Project-URL.*immutable project metadata",
        ),
        (
            b"Summary: Immutable release metadata",
            b"Summary: Forged release metadata",
            "Summary.*immutable project metadata",
        ),
        (
            b"Exact committed description.",
            b"Forged artifact description.",
            "description body.*immutable project readme",
        ),
    ),
)
def test_consistent_wheel_and_sdist_cannot_forge_static_metadata_or_body(
    tmp_path,
    target,
    replacement,
    message,
):
    project_path = _write_project(tmp_path)
    summary, project_url, body = _enable_static_project_metadata(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    metadata = _static_metadata(
        project_url=project_url,
        summary=summary,
        body=body,
    ).replace(target, replacement)
    _rewrite_static_metadata_pair(wheel, sdist, metadata)

    with pytest.raises(VerificationError, match=message):
        verify_artifacts(project_path, dist)


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


@pytest.mark.parametrize("optional_flag", (0x04, 0x10))
def test_sdist_rejects_gzip_extra_and_comment_fields(tmp_path, optional_flag):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    payload = bytearray(sdist.read_bytes())
    payload[3] |= optional_flag
    if optional_flag == 0x04:
        payload[10:10] = struct.pack("<H", 4) + b"HIDE"
    else:
        file_name_end = payload.index(0, 10) + 1 if payload[3] & 0x08 else 10
        payload[file_name_end:file_name_end] = b"hidden-comment\0"
    sdist.write_bytes(payload)

    with pytest.raises(VerificationError, match="unsupported optional"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize("location", ("prefix", "suffix"))
def test_wheel_rejects_bytes_outside_canonical_zip_span(tmp_path, location):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    payload = wheel.read_bytes()
    if location == "prefix":
        wheel.write_bytes(b"HIDDEN-PREFIX" + payload)
    else:
        wheel.write_bytes(payload + b"HIDDEN-SUFFIX")

    with pytest.raises(VerificationError, match="prefix|end|suffix"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_rejects_per_entry_comments(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/METADATA"
    _rewrite_wheel(
        wheel,
        comment_changes={member: b"hidden-central-directory-comment"},
    )

    with pytest.raises(VerificationError, match="member comment"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_rejects_local_only_extra_fields(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    payload = bytearray(wheel.read_bytes())
    old_central_offset = struct.unpack_from("<L", payload, len(payload) - 6)[0]
    name_size = struct.unpack_from("<H", payload, 26)[0]
    insertion = 30 + name_size
    local_extra = b"\xfe\xca\x00\x00"
    payload[insertion:insertion] = local_extra
    struct.pack_into("<H", payload, 28, len(local_extra))
    central_offset = old_central_offset + len(local_extra)
    cursor = central_offset
    while payload[cursor : cursor + 4] == b"PK\x01\x02":
        name_size, extra_size, comment_size = struct.unpack_from(
            "<3H",
            payload,
            cursor + 28,
        )
        local_offset = struct.unpack_from("<L", payload, cursor + 42)[0]
        if local_offset:
            struct.pack_into(
                "<L",
                payload,
                cursor + 42,
                local_offset + len(local_extra),
            )
        cursor += 46 + name_size + extra_size + comment_size
    eocd_offset = len(payload) - 22
    struct.pack_into("<L", payload, eocd_offset + 16, central_offset)
    wheel.write_bytes(payload)

    with pytest.raises(VerificationError, match="local framing"):
        verify_artifacts(project_path, wheel.parent)


def test_wheel_rejects_unused_bytes_after_raw_deflate_stream(tmp_path):
    project_path, wheel, _ = _write_valid_release(tmp_path)
    record_name = f"{ARTIFACT_NAME}-{PROJECT_VERSION}.dist-info/RECORD"
    with ZipFile(wheel) as archive:
        info = archive.getinfo(record_name)
    payload = bytearray(wheel.read_bytes())
    name_size, extra_size = struct.unpack_from(
        "<2H",
        payload,
        info.header_offset + 26,
    )
    data_start = info.header_offset + 30 + name_size + extra_size
    data_end = data_start + info.compress_size
    old_central_offset = struct.unpack_from("<L", payload, len(payload) - 6)[0]
    assert data_end == old_central_offset
    tail = b"NOT-PART-OF-THE-RAW-DEFLATE-STREAM" * 128
    payload[data_end:data_end] = tail
    struct.pack_into(
        "<L",
        payload,
        info.header_offset + 18,
        info.compress_size + len(tail),
    )
    central_offset = old_central_offset + len(tail)
    cursor = central_offset
    while payload[cursor : cursor + 4] == b"PK\x01\x02":
        name_size, extra_size, comment_size = struct.unpack_from(
            "<3H",
            payload,
            cursor + 28,
        )
        member_name = bytes(payload[cursor + 46 : cursor + 46 + name_size])
        if member_name.decode("ascii") == record_name:
            struct.pack_into(
                "<L",
                payload,
                cursor + 20,
                info.compress_size + len(tail),
            )
        cursor += 46 + name_size + extra_size + comment_size
    eocd_offset = len(payload) - 22
    struct.pack_into("<L", payload, eocd_offset + 16, central_offset)
    wheel.write_bytes(payload)

    with pytest.raises(VerificationError, match="DEFLATE framing is not exact"):
        verify_artifacts(project_path, wheel.parent)


@pytest.mark.parametrize(
    ("artifact", "mode"),
    (("wheel", 0o755), ("sdist", 0o777)),
)
def test_release_modules_reject_executable_or_world_writable_modes(
    tmp_path,
    artifact,
    mode,
):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    module = "verb_authority.py"
    if artifact == "wheel":
        _rewrite_wheel(wheel, mode_changes={module: mode})
    else:
        root_member = f"{ARTIFACT_NAME}-{PROJECT_VERSION}/{module}"
        _rewrite_sdist(sdist, mode_changes={root_member: mode})

    with pytest.raises(VerificationError, match="mode|release contract"):
        verify_artifacts(project_path, wheel.parent)


def test_sdist_rejects_nonzero_member_padding(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    tar_payload = bytearray(gzip.decompress(sdist.read_bytes()))
    first_size = release_verifier._tar_octal_size(tar_payload[124:136])
    assert first_size % tarfile.BLOCKSIZE
    padding_offset = tarfile.BLOCKSIZE + first_size
    tar_payload[padding_offset] = 1
    _gzip_sdist_payload(sdist, tar_payload)

    with pytest.raises(VerificationError, match="non-zero member padding"):
        verify_artifacts(project_path, wheel.parent)


def test_sdist_rejects_nonzero_final_tar_record_padding(tmp_path):
    project_path, wheel, sdist = _write_valid_release(tmp_path)
    tar_payload = bytearray(gzip.decompress(sdist.read_bytes()))
    assert tar_payload[-1] == 0
    tar_payload[-1] = 1
    _gzip_sdist_payload(sdist, tar_payload)

    with pytest.raises(VerificationError, match="non-zero data|final tar record"):
        verify_artifacts(project_path, wheel.parent)


def test_artifacts_can_be_bound_to_exact_clean_git_commit(tmp_path):
    project_path = _write_project(tmp_path)
    source_commit = _commit_test_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)

    assert verify_artifacts(
        project_path,
        dist,
        repository=tmp_path,
        source_commit=source_commit,
    ) == (wheel, sdist)
    assert main(
        [
            "artifacts",
            "--project",
            str(project_path),
            "--dist",
            str(dist),
            "--repository",
            str(tmp_path),
            "--source-commit",
            source_commit,
        ]
    ) == 0


def test_git_source_accepts_equivalent_resolved_project_path_and_nbsp_repo(
    tmp_path,
):
    repository = tmp_path / "repository\u00a0"
    repository.mkdir()
    _write_project(repository)
    source_commit = _commit_test_project(repository)
    dist = repository / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    alias = tmp_path / "repository-alias"
    alias.symlink_to(repository, target_is_directory=True)

    assert verify_artifacts(
        alias / "pyproject.toml",
        dist,
        repository=repository,
        source_commit=source_commit,
    ) == (wheel, sdist)


def test_immutable_git_source_ignores_hostile_git_environment(
    tmp_path,
    monkeypatch,
):
    project_path = _write_project(tmp_path)
    source_commit = _commit_test_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    trace_path = tmp_path / "hostile-git-trace"
    hostile_environment = {
        "GIT_DIR": str(tmp_path / "not-the-repository"),
        "GIT_COMMON_DIR": str(tmp_path / "not-the-common-dir"),
        "GIT_NAMESPACE": "attacker",
        "GIT_REPLACE_REF_BASE": "refs/attacker/replace/",
        "GIT_CONFIG_COUNT": "not-an-integer",
        "GIT_CONFIG_KEY_0": "core.fsmonitor",
        "GIT_CONFIG_VALUE_0": str(tmp_path / "attacker-hook"),
        "GIT_EXEC_PATH": str(tmp_path / "attacker-exec-path"),
        "GIT_TRACE": str(trace_path),
    }
    for key, value in hostile_environment.items():
        monkeypatch.setenv(key, value)

    assert verify_artifacts(
        project_path,
        dist,
        repository=tmp_path,
        source_commit=source_commit,
    ) == (wheel, sdist)
    assert not trace_path.exists()


def test_immutable_git_source_never_uses_path_git(tmp_path, monkeypatch):
    project_path = _write_project(tmp_path)
    source_commit = _commit_test_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    fake_bin = tmp_path / "build" / "fake-bin"
    fake_bin.mkdir(parents=True)
    marker = tmp_path / "build" / "path-git-ran"
    fake_git = fake_bin / "git"
    fake_git.write_text(
        f"#!/bin/sh\n/usr/bin/touch {marker}\nexit 99\n",
        encoding="utf-8",
    )
    fake_git.chmod(0o755)
    monkeypatch.setenv("PATH", str(fake_bin))

    assert verify_artifacts(
        project_path,
        dist,
        repository=tmp_path,
        source_commit=source_commit,
    ) == (wheel, sdist)
    assert not marker.exists()


def test_immutable_git_source_uses_allowlisted_loader_and_locale_environment(
    tmp_path,
    monkeypatch,
):
    project_path = _write_project(tmp_path)
    source_commit = _commit_test_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    for variable in (
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "GCONV_PATH",
        "LOCPATH",
    ):
        monkeypatch.setenv(variable, str(tmp_path / "hostile-loader"))
    original_popen = release_verifier.subprocess.Popen

    def checked_popen(*args, **kwargs):
        environment = kwargs["env"]
        assert set(environment) == {
            "PATH",
            "LC_ALL",
            "LANG",
            "GIT_OPTIONAL_LOCKS",
            "GIT_CONFIG_NOSYSTEM",
            "GIT_CONFIG_GLOBAL",
            "GIT_NO_REPLACE_OBJECTS",
            "GIT_NO_LAZY_FETCH",
            "GIT_LITERAL_PATHSPECS",
            "GIT_TERMINAL_PROMPT",
        }
        assert environment["PATH"] == "/usr/bin:/bin"
        assert environment["LC_ALL"] == environment["LANG"] == "C"
        return original_popen(*args, **kwargs)

    monkeypatch.setattr(release_verifier.subprocess, "Popen", checked_popen)

    assert verify_artifacts(
        project_path,
        dist,
        repository=tmp_path,
        source_commit=source_commit,
    ) == (wheel, sdist)


def test_worktree_verification_never_executes_configured_clean_filter(tmp_path):
    project_path = _write_project(tmp_path)
    (tmp_path / ".gitattributes").write_text(
        "*.py filter=release-verifier-hostile\n",
        encoding="utf-8",
    )
    source_commit = _commit_test_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    wheel = _write_wheel(dist)
    sdist = _write_sdist(dist)
    marker = tmp_path.parent / f"{tmp_path.name}-clean-filter-marker"
    _git(
        tmp_path,
        "config",
        "filter.release-verifier-hostile.clean",
        f"sh -c 'touch {marker}; cat'",
    )
    _git(
        tmp_path,
        "config",
        "filter.release-verifier-hostile.required",
        "true",
    )
    (tmp_path / "verb_authority.py").touch()

    assert verify_artifacts(
        project_path,
        dist,
        repository=tmp_path,
        source_commit=source_commit,
    ) == (wheel, sdist)
    assert not marker.exists()


def test_immutable_git_snapshot_rehashes_loose_object_contents(tmp_path):
    project_path = _write_project(tmp_path)
    source_commit = _commit_test_project(tmp_path)
    blob_line = _git(
        tmp_path,
        "ls-tree",
        source_commit,
        "verb_authority.py",
    )
    blob_id = blob_line.split()[2]
    attacker_payload = b'VALUE = "attacker-controlled"\n'
    loose_object = tmp_path / ".git" / "objects" / blob_id[:2] / blob_id[2:]
    forged_object = (
        f"blob {len(attacker_payload)}\0".encode("ascii") + attacker_payload
    )
    loose_object.chmod(0o644)
    loose_object.write_bytes(zlib.compress(forged_object))
    (tmp_path / "verb_authority.py").write_bytes(attacker_payload)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(dist)

    with pytest.raises(
        VerificationError,
        match="blob object content does not match its object ID",
    ):
        verify_artifacts(
            project_path,
            dist,
            repository=tmp_path,
            source_commit=source_commit,
        )


@pytest.mark.parametrize("object_type", ("commit", "tree"))
def test_immutable_git_snapshot_rehashes_commit_and_tree_objects(
    tmp_path,
    object_type,
):
    project_path = _write_project(tmp_path)
    source_commit = _commit_test_project(tmp_path)
    object_id = (
        source_commit
        if object_type == "commit"
        else _git(tmp_path, "rev-parse", f"{source_commit}^{{tree}}")
    )
    original = subprocess.run(
        ["git", "-C", str(tmp_path), "cat-file", object_type, object_id],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    forged_payload = original + b"X"
    forged_object = (
        f"{object_type} {len(forged_payload)}\0".encode("ascii")
        + forged_payload
    )
    loose_object = tmp_path / ".git" / "objects" / object_id[:2] / object_id[2:]
    loose_object.chmod(0o644)
    loose_object.write_bytes(zlib.compress(forged_object))
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(dist)

    with pytest.raises(
        VerificationError,
        match=(
            r"hash mismatch|commit object content does not match its object ID"
            if object_type == "commit"
            else r"tree object content does not match its object ID"
        ),
    ):
        verify_artifacts(
            project_path,
            dist,
            repository=tmp_path,
            source_commit=source_commit,
        )


def test_untracked_recursive_manifest_match_cannot_join_source_contract(
    tmp_path,
):
    project_path = _write_project(tmp_path)
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "public.md").write_text("public\n", encoding="utf-8")
    (tmp_path / "MANIFEST.in").write_text(
        "recursive-include docs *.md\n",
        encoding="utf-8",
    )
    (tmp_path / ".gitignore").write_text(
        "docs/private.md\n",
        encoding="utf-8",
    )
    source_commit = _commit_test_project(tmp_path)
    private = docs / "private.md"
    private.write_text("not committed\n", encoding="utf-8")
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    sdist = _write_sdist(dist)
    private_member = (
        f"{ARTIFACT_NAME}-{PROJECT_VERSION}/docs/private.md"
    )
    with tarfile.open(sdist, "r:gz") as archive:
        assert private_member in archive.getnames()

    with pytest.raises(
        VerificationError,
        match="untracked source selection.*docs/private.md",
    ):
        verify_artifacts(
            project_path,
            dist,
            repository=tmp_path,
            source_commit=source_commit,
        )


def test_post_build_tracked_mutation_cannot_redefine_source_bytes(tmp_path):
    project_path = _write_project(tmp_path)
    source_commit = _commit_test_project(tmp_path)
    dist = tmp_path / "dist"
    dist.mkdir()
    _write_wheel(dist)
    _write_sdist(dist)
    (tmp_path / "verb_authority.py").write_text(
        'VALUE = "post-build mutation"\n',
        encoding="utf-8",
    )
    # Do not let a local index performance hint turn the mutable worktree into
    # the release trust root.  The verifier compares bytes with commit blobs.
    _git(tmp_path, "update-index", "--assume-unchanged", "verb_authority.py")

    with pytest.raises(
        VerificationError,
        match="tracked project source differs.*verb_authority.py",
    ):
        verify_artifacts(
            project_path,
            dist,
            repository=tmp_path,
            source_commit=source_commit,
        )


def test_release_tag_must_point_to_exact_source_commit(tmp_path):
    project_path = _write_project(tmp_path)
    tagged_commit = _commit_test_project(tmp_path)
    _git(tmp_path, "tag", "v0.10.0-beta.8", tagged_commit)
    (tmp_path / "verb_authority.py").write_text(
        'VALUE = "second commit"\n',
        encoding="utf-8",
    )
    _git(tmp_path, "add", "verb_authority.py")
    _git(tmp_path, "commit", "-m", "later source")
    later_commit = _git(tmp_path, "rev-parse", "HEAD")

    with pytest.raises(VerificationError, match="does not point.*source commit"):
        verify_tag(
            project_path,
            "v0.10.0-beta.8",
            repository=tmp_path,
            source_commit=later_commit,
        )
