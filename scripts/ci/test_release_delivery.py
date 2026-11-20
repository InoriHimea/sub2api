"""Focused tests for release_delivery.py pure logic: URL building, checksum
parsing, manifest extraction from a real tar, controller identity aggregate,
bundle-tool equality guard, version naming and the environment variable
reconciliation decision. Network-touching layers are not covered here."""

import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

import release_delivery as rd


class NexusUrlTest(unittest.TestCase):
    def test_release_asset_url(self):
        self.assertEqual(
            rd.release_asset_url("v0.2.24", "release-bundle.tar.gz"),
            "https://nexus.mellivora.com.cn:18082/repository/github-group/"
            "InoriHimea/sub2api/releases/download/v0.2.24/release-bundle.tar.gz",
        )

    def test_repo_raw_url(self):
        self.assertEqual(
            rd.repo_raw_url("d9e9965d" + "f" * 32, "scripts/ci/bamboo_cd.py"),
            "https://nexus.mellivora.com.cn:18082/repository/github-group/"
            "InoriHimea/sub2api/raw/d9e9965dffffffffffffffffffffffffffffffff/scripts/ci/bamboo_cd.py",
        )


class ChecksumParsingTest(unittest.TestCase):
    def test_standard_sha256sum_line(self):
        digest = "a" * 64
        self.assertEqual(rd.parse_sha256_file(f"{digest}  release-bundle.tar.gz\n",
                                             "release-bundle.tar.gz"), digest)

    def test_binary_mode_line(self):
        digest = "b" * 64
        self.assertEqual(rd.parse_sha256_file(f"{digest} *release-bundle.tar.gz",
                                             "release-bundle.tar.gz"), digest)

    def test_rejects_missing_entry(self):
        with self.assertRaises(rd.DeliveryError):
            rd.parse_sha256_file("c" * 64 + "  other.txt", "release-bundle.tar.gz")

    def test_rejects_non_digest(self):
        with self.assertRaises(rd.DeliveryError):
            rd.parse_sha256_file("nothex  release-bundle.tar.gz", "release-bundle.tar.gz")


class ControllerIdentityTest(unittest.TestCase):
    def test_identity_matches_bamboo_cd_algorithm(self):
        # Reference implementation copied from bamboo_cd.py controller_identity.
        import hashlib

        def reference(files: dict) -> str:
            return hashlib.sha256(
                json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        files = {name: hashlib.sha256(name.encode()).hexdigest() for name in rd.CONTROLLER_FILES}
        self.assertEqual(rd.controller_identity(files), reference(files))

    def test_identity_rejects_wrong_file_set(self):
        files = {name: "x" for name in rd.CONTROLLER_FILES}
        files.pop("deploy.sh")
        with self.assertRaises(rd.DeliveryError):
            rd.controller_identity(files)


class ManifestAndToolsTest(unittest.TestCase):
    def _make_bundle(self, root: Path) -> Path:
        manifest = {"schema": 1, "tag": "v9.9.9", "sha": "c" * 40, "version": "9.9.9",
                    "binary_sha256": "d" * 64, "image_id": "sha256:e" * 1}
        tools = {name: f"content-of-{name}".encode() for name in rd.BUNDLE_TOOL_FILES}
        bundle = root / "release-bundle.tar.gz"
        with tarfile.open(bundle, "w:gz") as archive:
            info = tarfile.TarInfo("release/manifest.json")
            payload = json.dumps(manifest).encode()
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
            for name, payload_bytes in tools.items():
                info = tarfile.TarInfo(f"release/tools/{name}")
                info.size = len(payload_bytes)
                archive.addfile(info, io.BytesIO(payload_bytes))
        return bundle

    def test_read_bundle_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = self._make_bundle(Path(tmp))
            manifest = rd.read_bundle_manifest(bundle)
            self.assertEqual(manifest["tag"], "v9.9.9")
            self.assertEqual(manifest["sha"], "c" * 40)

    def test_extract_bundle_tools_and_equality(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = self._make_bundle(Path(tmp))
            stage = Path(tmp) / "tools"
            rd.extract_bundle_files(bundle, list(rd.BUNDLE_TOOL_FILES), stage)
            for name in rd.BUNDLE_TOOL_FILES:
                self.assertEqual((stage / name).read_text(), f"content-of-{name}")

    def test_extract_rejects_incomplete_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            bundle = Path(tmp) / "thin.tar.gz"
            with tarfile.open(bundle, "w:gz") as archive:
                info = tarfile.TarInfo("release/tools/deploy.sh")
                payload = b"x"
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
            with self.assertRaises(rd.DeliveryError):
                rd.extract_bundle_files(bundle, list(rd.BUNDLE_TOOL_FILES), Path(tmp) / "out")


class NamingAndStateTest(unittest.TestCase):
    def test_release_version_name(self):
        self.assertEqual(rd.release_version_name("v0.2.23-2", "d9e9965df618ccb0"), "v0.2.23-2-intake-d9e9965d")

    def test_state_roundtrip(self):
        original = rd.save_state
        try:
            with tempfile.TemporaryDirectory() as tmp:
                rd.DELIVERY_DIR = Path(tmp)
                rd.save_state("v1.2.3", {"tag": "v1.2.3", "commit": "abc"})
                self.assertEqual(rd.load_state("v1.2.3")["tag"], "v1.2.3")
        finally:
            rd.DELIVERY_DIR = original


if __name__ == "__main__":
    unittest.main()
