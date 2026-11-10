#!/usr/bin/env python3
"""Offline, fail-closed import of an independently approved release-bundle.tar.gz.

The NEW --output directory contains release/ and import-receipt.json. No network,
credentials, downloaded Python imports, subprocesses, or compilation are used.
Run on the controlled Linux deployment agent (or Windows); Linux publication
requires renameat2(RENAME_NOREPLACE), never a check-then-overwrite rename.
"""
from __future__ import annotations

import sys
sys.dont_write_bytecode = True

import argparse
import ctypes
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
import tempfile
from typing import BinaryIO

import build_release as build
import deploy_release as deploy

HERE = Path(__file__).resolve().parent
MAX_ARCHIVE_BYTES = 4 * 1024**3
MAX_TAR_BYTES = 12 * 1024**3
MAX_FILE_BYTES = 8 * 1024**3
MAX_METADATA_BYTES = 16 * 1024**2
MAX_MEMBERS = 20000
MAX_PATH_BYTES = 512
CHUNK = 1024 * 1024


class ImportFailure(Exception):
    """The input cannot be safely promoted; no output was published."""


class _BoundedReader:
    def __init__(self, stream: BinaryIO):
        self.stream = stream
        self.count = 0

    def read(self, size: int = -1) -> bytes:
        remaining = MAX_TAR_BYTES - self.count
        data = self.stream.read(min(size if size >= 0 else CHUNK, remaining + 1))
        self.count += len(data)
        if self.count > MAX_TAR_BYTES:
            raise ImportFailure("decompressed tar exceeds byte limit")
        return data


class _BoundedTarInfo(tarfile.TarInfo):
    def _proc_member(self, tar):
        # tarfile consumes extension records before yielding a member. Bound
        # their allocation and recursion as well as eventual extracted files.
        tar.import_header_count = getattr(tar, "import_header_count", 0) + 1
        if tar.import_header_count > MAX_MEMBERS:
            raise ImportFailure("archive header count exceeds limit")
        depth = getattr(tar, "import_header_depth", 0)
        if depth >= 16:
            raise ImportFailure("archive extension nesting exceeds limit")
        if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE):
            if self.size > 65536:
                raise ImportFailure("archive extended metadata exceeds limit")
        elif self.type == tarfile.GNUTYPE_LONGNAME:
            if self.size > MAX_PATH_BYTES + 1:
                raise ImportFailure("archive extended name exceeds limit")
        elif not (self.isdir() or self.isreg()) or self.issparse():
            raise ImportFailure("archive links, sparse files and special entries are forbidden")
        tar.import_header_depth = depth + 1
        try:
            return super()._proc_member(tar)
        finally:
            tar.import_header_depth = depth


def _extract(archive: Path, stage: Path) -> None:
    seen = set()
    total = 0
    with gzip.open(archive, "rb") as compressed:
        bounded = _BoundedReader(compressed)
        with tarfile.open(fileobj=bounded, mode="r|", tarinfo=_BoundedTarInfo) as tar:
            for member in tar:
                name = member.name
                # Reject alternate spellings as well as traversal. Backslashes,
                # colons and Windows reserved components are unsafe cross-platform.
                canonical = name[:-1] if member.isdir() and name.endswith("/") else name
                parts = canonical.split("/")
                if (len(name.encode("utf-8")) > MAX_PATH_BYTES
                        or not parts or parts[0] != "release"
                        or any(p in ("", ".", "..") or "\\" in p or ":" in p
                               or p.endswith((" ", "."))
                               or re.fullmatch(r"(?i:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\..*)?", p)
                               or any(ord(c) < 32 or ord(c) == 127 for c in p)
                               for p in parts)):
                    raise ImportFailure("unsafe archive member path")
                if canonical in seen:
                    raise ImportFailure("duplicate archive member")
                seen.add(canonical)
                if len(seen) > MAX_MEMBERS:
                    raise ImportFailure("archive member count exceeds limit")
                if not (member.isdir() or member.isreg()) or member.issparse():
                    raise ImportFailure("archive links, sparse files and special entries are forbidden")
                if member.mode & 0o7000:
                    raise ImportFailure("archive privileged permission bits are forbidden")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise ImportFailure("archive file size exceeds limit")
                if (canonical in ("release/manifest.json", "release/qualification.json")
                        or canonical.startswith("release/migrations/")) and member.size > MAX_METADATA_BYTES:
                    raise ImportFailure("parsed release metadata exceeds size limit")
                total += member.size
                if total > MAX_TAR_BYTES:
                    raise ImportFailure("archive expanded size exceeds limit")
                target = stage.joinpath(*parts)
                if member.isdir():
                    if member.size:
                        raise ImportFailure("archive directory has file payload")
                    target.mkdir(mode=0o700, parents=True, exist_ok=True)
                else:
                    if len(parts) == 1:
                        raise ImportFailure("release root must be a directory")
                    target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    source = tar.extractfile(member)
                    if source is None:
                        raise ImportFailure("archive file payload missing")
                    with source, target.open("xb") as dest:
                        remaining = member.size
                        while remaining:
                            data = source.read(min(CHUNK, remaining))
                            if not data:
                                raise ImportFailure("truncated archive file")
                            dest.write(data)
                            remaining -= len(data)
                    target.chmod(member.mode & 0o777)
            # Drain tarfile's own buffered stream, not just its underlying
            # gzip reader: hidden entries after the first EOF are forbidden.
            # This also bounds all padding and forces gzip CRC verification.
            while True:
                padding = tar.fileobj.read(CHUNK)
                if not padding:
                    break
                if padding.strip(b"\0"):
                    raise ImportFailure("nonzero data follows archive EOF")


def _publish(stage: Path, output: Path) -> None:
    if sys.platform.startswith("linux"):
        libc = ctypes.CDLL(None, use_errno=True)
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise ImportFailure("atomic no-replace publication requires Linux renameat2")
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        if rename(-100, os.fsencode(stage), -100, os.fsencode(output), 1) != 0:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))
    elif os.name == "nt":
        os.rename(stage, output)  # Windows rename never replaces an existing directory.
    else:
        raise ImportFailure("atomic no-replace directory publication unsupported on this platform")


def _verify_release(release: Path):
    manifest = deploy.verify_bundle_locally(str(release))
    controller = {}
    for name in ("import_release.py", "build_release.py") + build.DEPLOY_TOOL_FILES:
        local = HERE / name
        if local.is_symlink() or not local.is_file():
            raise ImportFailure("trusted controller file missing or symlinked: " + name)
        controller[name] = deploy.rd.sha256_file(str(local))
        if name in build.DEPLOY_TOOL_FILES and manifest["files"].get("tools/" + name) != controller[name]:
            raise ImportFailure("bundled deployment tool differs from trusted controller: " + name)
    identity = hashlib.sha256(json.dumps(controller, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return manifest, {"sha256": identity, "files": controller}


def verify_import(output: Path) -> dict:
    """Revalidate a promoted import against THIS trusted controller, offline.

    The receipt is a provenance record, not a signature. The orchestrator must
    separately pin its tag/SHA/archive digest to its approved release inputs;
    without the original archive its digest cannot be independently recomputed.
    A trusted controller/ sibling added by the import plan is intentionally
    outside the release manifest and is never loaded from release/tools/.
    """
    output = Path(output)
    receipt_path = output / "import-receipt.json"
    release = output / "release"
    if output.is_symlink() or receipt_path.is_symlink() or release.is_symlink():
        raise ImportFailure("import root, receipt and release must not be symlinks")
    with receipt_path.open("rb") as stream:
        raw = stream.read(MAX_METADATA_BYTES + 1)
    if len(raw) > MAX_METADATA_BYTES:
        raise ImportFailure("import receipt exceeds size limit")
    receipt = json.loads(raw)
    required = {"schema", "mode", "tag", "sha", "archive_sha256", "manifest_sha256",
                "controller", "deployment_tools_match_controller"}
    if not isinstance(receipt, dict) or set(receipt) != required:
        raise ImportFailure("import receipt has invalid exact schema")
    if (type(receipt["schema"]) is not int or receipt["schema"] != 1
            or receipt["mode"] != "offline-approved-archive"
            or receipt["deployment_tools_match_controller"] is not True):
        raise ImportFailure("import receipt has invalid provenance fields")
    for name in ("archive_sha256", "manifest_sha256"):
        if not isinstance(receipt[name], str) or not re.fullmatch(r"[0-9a-f]{64}", receipt[name]):
            raise ImportFailure("import receipt has invalid " + name)
    manifest, controller = _verify_release(release)
    if (receipt["tag"] != manifest["tag"] or receipt["sha"] != manifest["sha"]
            or receipt["manifest_sha256"] != deploy.rd.sha256_file(str(release / "manifest.json"))
            or receipt["controller"] != controller):
        raise ImportFailure("import receipt does not match verified release/controller identity")
    return receipt


def import_release(archive: Path, archive_sha256: str, tag: str,
                   expected_sha: str, output: Path) -> dict:
    """Promote validated bytes; return the same nonsecret receipt stored in output."""
    if not isinstance(archive_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", archive_sha256):
        raise ImportFailure("archive-sha256 must be 64 lowercase hex characters")
    if not isinstance(expected_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", expected_sha):
        raise ImportFailure("expected-sha must be the full 40-character lowercase commit SHA")
    if not isinstance(tag, str) or deploy.rd.SEMVER_TAG_RE.fullmatch(tag) is None:
        raise ImportFailure("tag must be v-prefixed strict SemVer")
    output = Path(os.path.abspath(output))
    archive = Path(archive)
    if os.path.lexists(output):
        raise ImportFailure("output already exists; refusing to replace it")
    if not output.parent.is_dir():
        raise ImportFailure("output parent must already exist")
    stage = Path(tempfile.mkdtemp(prefix=".release-import-", dir=output.parent))
    try:
        # Verify a private snapshot, not a pathname that could be replaced between
        # digest verification and extraction. Never retain the downloaded archive.
        snapshot = stage / "archive.tar.gz"
        digest = hashlib.sha256()
        count = 0
        with archive.open("rb") as src, snapshot.open("xb") as dst:
            if not stat.S_ISREG(os.fstat(src.fileno()).st_mode):
                raise ImportFailure("archive must be a regular file")
            while True:
                data = src.read(CHUNK)
                if not data:
                    break
                count += len(data)
                if count > MAX_ARCHIVE_BYTES:
                    raise ImportFailure("compressed archive exceeds byte limit")
                digest.update(data)
                dst.write(data)
        if digest.hexdigest() != archive_sha256:
            raise ImportFailure("archive sha256 does not match independently approved digest")
        _extract(snapshot, stage)
        snapshot.unlink()
        release = stage / "release"
        manifest, controller = _verify_release(release)
        if manifest["tag"] != tag or manifest["sha"] != expected_sha:
            raise ImportFailure("manifest tag/SHA does not match approved release identity")
        receipt = {
            "schema": 1, "mode": "offline-approved-archive", "tag": tag,
            "sha": expected_sha, "archive_sha256": archive_sha256,
            "manifest_sha256": deploy.rd.sha256_file(str(release / "manifest.json")),
            "controller": controller,
            "deployment_tools_match_controller": True,
        }
        with (stage / "import-receipt.json").open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2)
            stream.write("\n")
        _publish(stage, output)
        return receipt
    finally:
        if stage.exists():
            # Failed input can contain read-only modes; cleanup owns only this stage.
            def writable_retry(fn, path, _exc):
                os.chmod(path, 0o700)
                fn(path)
            shutil.rmtree(stage, onerror=writable_retry)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--expected-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = import_release(args.archive, args.archive_sha256, args.tag, args.expected_sha, args.output)
    except (ImportFailure, deploy.rd.DeployFailure, deploy.OrchestratorBlocker,
            OSError, ValueError, tarfile.TarError, EOFError) as exc:
        print("[import_release] import rejected: %s" % exc, file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
