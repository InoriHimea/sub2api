"""Hermetic behavior coverage; run: python3 -B scripts/ci/test_import_release.py.

The deployment controller is Linux: real POSIX modes and atomic no-replace
publication are exercised there. No SSH, network, compilation or credentials.
"""
import sys
sys.dont_write_bytecode = True

import contextlib
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

import import_release as importer
from test_deploy_release import build_fixture_bundle


@unittest.skipUnless(sys.platform.startswith("linux"), "controlled Linux deployment agent required")
class OfflineImportBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="offline-import-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bundle = self.root / "fixture"
        self.bundle.mkdir()
        self.manifest = build_fixture_bundle(self.bundle)
        # Reuse the real fixture but include EVERY privileged tool, including
        # deploy.sh, whose bytes must come from the trusted local controller.
        for name in importer.build.DEPLOY_TOOL_FILES:
            shutil.copyfile(importer.HERE / name, self.bundle / "tools" / name)
        self.rehash()
        self.archive = self.root / "release-bundle.tar.gz"
        self.output = self.root / "imported"
        self.pack()

    def rehash(self):
        self.manifest["files"] = {
            p.relative_to(self.bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.bundle.rglob("*") if p.is_file() and p.name != "manifest.json"
        }
        (self.bundle / "manifest.json").write_text(json.dumps(self.manifest), encoding="utf-8")

    def pack(self, extras=()):
        with tarfile.open(self.archive, "w:gz") as tar:
            tar.add(self.bundle, arcname="release")
            for info, data in extras:
                tar.addfile(info, io.BytesIO(data) if data else None)

    def invoke(self, **overrides):
        params = dict(archive=self.archive,
                      archive_sha256=hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                      tag="v1.0.0", expected_sha="a" * 40, output=self.output)
        params.update(overrides)
        return importer.import_release(**params)

    def rejected(self, **overrides):
        with self.assertRaises((importer.ImportFailure, importer.deploy.rd.DeployFailure,
                                importer.deploy.OrchestratorBlocker, OSError, ValueError,
                                tarfile.TarError, EOFError)):
            self.invoke(**overrides)
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual(list(self.root.glob(".release-import-*")), [])

    def test_accepts_real_controller_bytes_and_publishes_receipt_with_release(self):
        # Import must never execute even the fixture's harmless fake binary.
        with mock.patch("subprocess.run", side_effect=AssertionError("execution forbidden")):
            receipt = self.invoke()
        self.assertEqual(set(p.name for p in self.output.iterdir()), {"release", "import-receipt.json"})
        saved = json.loads((self.output / "import-receipt.json").read_text())
        self.assertEqual(saved, receipt)
        self.assertEqual(receipt["archive_sha256"], hashlib.sha256(self.archive.read_bytes()).hexdigest())
        self.assertEqual((receipt["tag"], receipt["sha"]), ("v1.0.0", "a" * 40))
        self.assertEqual(receipt["manifest_sha256"], hashlib.sha256((self.bundle / "manifest.json").read_bytes()).hexdigest())
        identity = receipt["controller"]["files"]
        for name in ("import_release.py", "build_release.py") + importer.build.DEPLOY_TOOL_FILES:
            self.assertEqual(identity[name], hashlib.sha256((importer.HERE / name).read_bytes()).hexdigest())
        self.assertEqual(receipt["controller"]["sha256"], hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        self.assertTrue(receipt["deployment_tools_match_controller"])
        for source in self.bundle.rglob("*"):
            if source.is_file():
                dest = self.output / "release" / source.relative_to(self.bundle)
                self.assertEqual(dest.read_bytes(), source.read_bytes())
                self.assertEqual(stat.S_IMODE(dest.stat().st_mode), stat.S_IMODE(source.stat().st_mode))
        self.assertEqual(stat.S_IMODE((self.output / "release" / "sub2api").stat().st_mode), 0o755)
        self.assertEqual(list(self.root.glob(".release-import-*")), [])

    def test_revalidates_without_archive_and_allows_trusted_controller_sibling(self):
        receipt = self.invoke()
        self.archive.unlink()
        (self.output / "controller").mkdir()
        self.assertEqual(importer.verify_import(self.output), receipt)

    def test_revalidation_rejects_payload_and_receipt_changes(self):
        receipt = self.invoke()
        record = self.output / "import-receipt.json"
        for field, value in (("tag", "v9.0.0"), ("sha", "b" * 40),
                             ("manifest_sha256", "0" * 64), ("archive_sha256", "invalid"),
                             ("controller", {"sha256": "0" * 64, "files": {}}),
                             ("deployment_tools_match_controller", False)):
            with self.subTest(field=field):
                modified = dict(receipt)
                modified[field] = value
                record.write_text(json.dumps(modified), encoding="utf-8")
                with self.assertRaises(importer.ImportFailure):
                    importer.verify_import(self.output)
        record.write_text(json.dumps(receipt), encoding="utf-8")
        resource = self.output / "release" / "resources" / "readme.txt"
        resource.write_bytes(b"tampered after publication")
        with self.assertRaises(importer.deploy.rd.DeployFailure):
            importer.verify_import(self.output)

    def test_rejects_wrong_digest_tag_and_full_sha(self):
        for params in ({"archive_sha256": "0" * 64}, {"tag": "v1.0.1"}, {"expected_sha": "b" * 40}):
            with self.subTest(params=params):
                self.rejected(**params)

    def test_requires_exact_full_sha_and_strict_v_semver(self):
        for tag in ("1.0.0", "refs/tags/v1.0.0", "v01.0.0", "v1.0.0-01", "v1.0.0\n"):
            with self.subTest(tag=tag):
                self.rejected(tag=tag)
        for sha in ("a" * 12, "A" * 40, "a" * 40 + "\n"):
            with self.subTest(sha=sha):
                self.rejected(expected_sha=sha)
        self.rejected(archive_sha256="A" * 64)

    def test_rejects_archive_escape_and_alternate_paths(self):
        for name in ("/escape", "release/../../escape", "release/../escape", "other/file",
                     "release/a\\b", "release/C:/escape", "release//file", "release/./file",
                     "release/NUL.txt", "release/trailing."):
            with self.subTest(name=name):
                info = tarfile.TarInfo(name)
                info.size = 1
                self.pack([(info, b"x")])
                self.rejected()
        self.assertFalse((self.root / "escape").exists())

    def test_rejects_links_special_entries_and_sparse_files(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE,
                     tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.GNUTYPE_SPARSE):
            with self.subTest(kind=kind):
                info = tarfile.TarInfo("release/unsafe")
                info.type = kind
                info.linkname = "../../escape"
                self.pack([(info, b"")])
                self.rejected()

    def test_rejects_duplicate_members(self):
        for name, kind in (("release", tarfile.DIRTYPE), ("release/sub2api", tarfile.REGTYPE)):
            with self.subTest(name=name):
                info = tarfile.TarInfo(name)
                info.type = kind
                self.pack([(info, b"")])
                self.rejected()

    def test_rejects_bounded_compressed_expanded_member_and_path_sizes(self):
        for limit, value in (("MAX_ARCHIVE_BYTES", 1), ("MAX_TAR_BYTES", 1024),
                             ("MAX_FILE_BYTES", 1), ("MAX_MEMBERS", 2), ("MAX_PATH_BYTES", 8)):
            with self.subTest(limit=limit), mock.patch.object(importer, limit, value):
                self.rejected()

    def test_bounds_extended_metadata_before_allocation(self):
        # A declared giant extension must fail before tarfile attempts to read
        # that payload. This intentionally truncated header needs no huge data.
        header = tarfile.TarInfo("metadata")
        header.type = tarfile.XHDTYPE
        header.size = 1024**3
        self.archive.write_bytes(gzip.compress(header.tobuf(format=tarfile.USTAR_FORMAT)))
        self.rejected()

    def test_parsed_metadata_size_limit_is_enforced(self):
        with mock.patch.object(importer, "MAX_METADATA_BYTES", 1):
            self.rejected()

    def test_hidden_members_after_tar_eof_are_rejected(self):
        hidden = tarfile.TarInfo("outside-release")
        hidden.size = 1
        trailing = hidden.tobuf(format=tarfile.USTAR_FORMAT) + b"x" + b"\0" * 511
        self.archive.write_bytes(self.archive.read_bytes() + gzip.compress(trailing))
        self.rejected()

    def test_rejects_privileged_modes_and_wrong_binary_mode(self):
        for mode in (0o4755, 0o644):
            with self.subTest(mode=oct(mode)):
                (self.bundle / "sub2api").chmod(mode)
                self.pack()
                self.rejected()

    def test_tampered_bytes_fail_even_with_approved_archive_digest(self):
        (self.bundle / "resources" / "readme.txt").write_bytes(b"changed after manifest")
        self.pack()
        self.rejected()

    def test_manifest_consistent_untrusted_tool_bytes_are_rejected(self):
        for name in importer.build.DEPLOY_TOOL_FILES:
            with self.subTest(name=name):
                path = self.bundle / "tools" / name
                original = path.read_bytes()
                path.write_bytes(original + b"\n# untrusted\n")
                self.rehash()
                self.pack()
                self.rejected()
                path.write_bytes(original)

    def test_missing_privileged_tool_is_rejected(self):
        (self.bundle / "tools" / "deploy.sh").unlink()
        self.rehash()
        self.pack()
        self.rejected()

    def test_qualification_failure_and_migration_checksum_mismatch_are_rejected(self):
        qual = self.bundle / "qualification.json"
        original = qual.read_bytes()
        data = json.loads(original)
        data["qualified"] = False
        qual.write_text(json.dumps(data), encoding="utf-8")
        self.rehash()
        self.pack()
        self.rejected()
        qual.write_bytes(original)
        (self.bundle / "migrations" / "250_fixture.sql").write_bytes(b"SELECT 2;\n")
        self.rehash()
        self.pack()
        self.rejected()

    def test_existing_output_is_untouched(self):
        self.output.mkdir()
        marker = self.output / "operator-owned"
        marker.write_bytes(b"keep me")
        with self.assertRaises(importer.ImportFailure):
            self.invoke()
        self.assertEqual(marker.read_bytes(), b"keep me")
        self.assertEqual(list(self.output.iterdir()), [marker])
        self.assertEqual(list(self.root.glob(".release-import-*")), [])

    def test_existing_empty_directory_file_and_symlink_are_never_replaced(self):
        for kind in ("directory", "file", "symlink"):
            with self.subTest(kind=kind):
                if kind == "directory":
                    self.output.mkdir()
                elif kind == "file":
                    self.output.write_bytes(b"owned")
                else:
                    self.output.symlink_to(self.root / "missing", target_is_directory=True)
                with self.assertRaises(importer.ImportFailure):
                    self.invoke()
                self.assertTrue(os.path.lexists(self.output))
                if kind == "directory":
                    self.output.rmdir()
                else:
                    self.output.unlink()

    def test_racing_output_creation_is_not_overwritten(self):
        real_publish = importer._publish

        def race(stage, output):
            output.mkdir()
            real_publish(stage, output)

        with mock.patch.object(importer, "_publish", side_effect=race):
            with self.assertRaises(FileExistsError):
                self.invoke()
        self.assertEqual(list(self.output.iterdir()), [])
        self.assertEqual(list(self.root.glob(".release-import-*")), [])

    def test_truncated_gzip_does_not_publish(self):
        self.archive.write_bytes(self.archive.read_bytes()[:-8])
        self.rejected()

    def test_cli_reports_failure_without_partial_publication(self):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()) as stdout:
            status = importer.main(["--archive", str(self.archive), "--archive-sha256", "0" * 64,
                                    "--tag", "v1.0.0", "--expected-sha", "a" * 40,
                                    "--output", str(self.output)])
        self.assertEqual(status, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".release-import-*")), [])


if __name__ == "__main__":
    unittest.main()
