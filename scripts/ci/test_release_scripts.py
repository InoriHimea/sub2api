#!/usr/bin/env python3
"""Scoped behavior tests for scripts/ci/qualify_release.py and
scripts/ci/build_release.py.

These exercise observable behavior only -- rejecting a dirty source tree,
rejecting a non-tag/ambiguous/mismatched ref, rejecting stale or failed
qualification, rejecting a corrupted/path-escaping artifact (a symlink in
the release bundle), and refusing to invent missing deploy tooling -- never
the literal text of this module's own source or workflow YAML.

Every fixture (temp git repos, temp release directories) is created and torn
down by the test itself; nothing here touches real Docker, Go toolchains,
network services or any file outside a TemporaryDirectory.

Python3.9 compatibility is retained for controlled self-hosted deployment tooling.

Run with:
    python3 -m unittest scripts/ci/test_release_scripts.py -v
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import build_release  # noqa: E402
import qualify_release  # noqa: E402

GO_MOD_TEMPLATE = "module example.com/fixture\n\ngo 1.27.3\n"


def _git(repo, *args):
    result = subprocess.run(
        ["git"] + list(args),
        cwd=str(repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=True,
    )
    return result.stdout.decode("utf-8", "replace")


def make_fixture_repo(tmp_path):
    """A minimal, owned, throwaway git repository with a fixture go.mod."""
    repo = Path(tmp_path) / "repo"
    (repo / "backend").mkdir(parents=True)
    (repo / "backend" / "go.mod").write_text(GO_MOD_TEMPLATE, encoding="utf-8")
    subprocess.run(["git", "init", "--quiet", str(repo)], check=True)
    _git(repo, "config", "user.email", "fixture@example.com")
    _git(repo, "config", "user.name", "Fixture")
    _git(repo, "add", "-A")
    _git(repo, "commit", "--quiet", "-m", "initial fixture commit")
    sha = _git(repo, "rev-parse", "HEAD").strip()
    return repo, sha


class _PatchRoots(unittest.TestCase):
    """Shared helper: point a module's path constants at an owned fixture
    repo for the duration of a test, then restore the originals."""

    def patch_module_roots(self, module, repo):
        originals = {
            name: getattr(module, name)
            for name in ("REPO_ROOT", "BACKEND_DIR", "GO_MOD")
            if hasattr(module, name)
        }
        module.REPO_ROOT = repo
        module.BACKEND_DIR = repo / "backend"
        module.GO_MOD = repo / "backend" / "go.mod"
        self.addCleanup(lambda: [setattr(module, k, v) for k, v in originals.items()])


class VerifyCleanSourceTests(_PatchRoots):
    def test_rejects_dirty_tree_build(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, _sha = make_fixture_repo(tmp)
            (repo / "backend" / "untracked.txt").write_text("dirty", encoding="utf-8")
            self.patch_module_roots(build_release, repo)
            with self.assertRaises(build_release.BuildError):
                build_release.verify_clean_source()


    def test_rejects_dirty_tree_qualify(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, _sha = make_fixture_repo(tmp)
            (repo / "backend" / "untracked.txt").write_text("dirty", encoding="utf-8")
            self.patch_module_roots(qualify_release, repo)
            with self.assertRaises(qualify_release.QualifyError):
                qualify_release.verify_clean_source()


class ResolveTagAndShaTests(_PatchRoots):
    """Only an exact GitHub tag ref and matching triggering commit may release."""

    def setUp(self):
        self._env_backup = dict(os.environ)
        for name in ("GITHUB_SHA", "GITHUB_REF"):
            os.environ.pop(name, None)
        os.environ["GITHUB_REF"] = "refs/tags/v1.2.3"
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_rejects_missing_revision_variable(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "v1.2.3")
            self.patch_module_roots(build_release, repo)
            with self.assertRaises(build_release.BuildError):
                build_release.resolve_tag_and_sha()

    def test_rejects_revision_mismatch(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "v1.2.3")
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = "0" * 40
            with self.assertRaises(build_release.BuildError):
                build_release.resolve_tag_and_sha()

    def test_rejects_zero_tags_on_head(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = sha
            with self.assertRaises(build_release.BuildError):
                build_release.resolve_tag_and_sha()

    def test_rejects_non_semver_tag_only(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "not-a-release")
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = sha
            with self.assertRaises(build_release.BuildError):
                build_release.resolve_tag_and_sha()

    def test_rejects_multiple_semver_tags_on_same_commit(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "v1.2.3")
            _git(repo, "tag", "v1.2.4")
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = sha
            with self.assertRaises(build_release.BuildError):
                build_release.resolve_tag_and_sha()

    def test_rejects_leading_zero_semver(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "v01.2.3")
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = sha
            with self.assertRaises(build_release.BuildError):
                build_release.resolve_tag_and_sha()

    def test_does_not_infer_nearest_tag_from_later_commit(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "v1.2.3")
            (repo / "backend" / "extra.txt").write_text("more", encoding="utf-8")
            _git(repo, "add", "-A")
            _git(repo, "commit", "--quiet", "-m", "second commit")
            new_sha = _git(repo, "rev-parse", "HEAD").strip()
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = new_sha
            # HEAD moved past the tag; it must never fall back to "nearest".
            with self.assertRaises(build_release.BuildError):
                build_release.resolve_tag_and_sha()

    def test_accepts_exactly_one_matching_tag_with_matching_revision(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "v1.2.3")
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = sha
            tag, version, resolved_sha = build_release.resolve_tag_and_sha()
            self.assertEqual((tag, version, resolved_sha), ("v1.2.3", "1.2.3", sha))

    def test_rejects_branch_or_different_tag_even_when_head_is_tagged(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "v1.2.3")
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = sha
            for ref in ("", "refs/heads/main", "refs/pull/1/merge", "refs/tags/v9.9.9"):
                with self.subTest(ref=ref):
                    os.environ["GITHUB_REF"] = ref
                    with self.assertRaises(build_release.BuildError):
                        build_release.resolve_tag_and_sha()

    def test_accepts_annotated_release_tag(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            repo, sha = make_fixture_repo(tmp)
            _git(repo, "tag", "-a", "v1.2.3", "-m", "reviewed release")
            self.patch_module_roots(build_release, repo)
            os.environ["GITHUB_SHA"] = sha
            self.assertEqual(build_release.resolve_tag_and_sha(), ("v1.2.3", "1.2.3", sha))


MANDATORY_TEST_NAMES = build_release.MANDATORY_TEST_NAMES


def _valid_qualification(sha, compiler="go1.27.3"):
    return {
        "schema": 1,
        "sha": sha,
        "compiler": compiler,
        "qualified": True,
        "go_test_exit_code": 0,
        "frontend_build_exit_code": 0,
        "frontend_dist_sha256": "0" * 64,
        "tests": {name: "PASS" for name in MANDATORY_TEST_NAMES},
    }


class LoadQualificationTests(unittest.TestCase):
    def _write(self, tmp, data):
        path = Path(tmp) / "qualification.json"
        path.write_text(json.dumps(data), encoding="utf-8")
        return path

    def test_rejects_missing_file(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            missing = Path(tmp) / "absent.json"
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(missing, "a" * 40, "go1.27.3")

    def test_rejects_stale_sha(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            path = self._write(tmp, _valid_qualification("b" * 40))
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, "a" * 40, "go1.27.3")

    def test_rejects_mismatched_compiler(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            sha = "a" * 40
            path = self._write(tmp, _valid_qualification(sha, compiler="go1.26.4"))
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, sha, "go1.27.3")

    def test_rejects_not_qualified_flag(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            sha = "a" * 40
            data = _valid_qualification(sha)
            data["qualified"] = False
            path = self._write(tmp, data)
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, sha, "go1.27.3")

    def test_rejects_nonzero_go_test_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            sha = "a" * 40
            data = _valid_qualification(sha)
            data["go_test_exit_code"] = 1
            path = self._write(tmp, data)
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, sha, "go1.27.3")

    def test_rejects_nonzero_frontend_build_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            sha = "a" * 40
            data = _valid_qualification(sha)
            data["frontend_build_exit_code"] = 2
            path = self._write(tmp, data)
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, sha, "go1.27.3")

    def test_rejects_missing_frontend_dist_hash(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            sha = "a" * 40
            data = _valid_qualification(sha)
            del data["frontend_dist_sha256"]
            path = self._write(tmp, data)
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, sha, "go1.27.3")

    def test_rejects_failed_mandatory_test(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            sha = "a" * 40
            data = _valid_qualification(sha)
            data["tests"][MANDATORY_TEST_NAMES[0]] = "FAIL"
            path = self._write(tmp, data)
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, sha, "go1.27.3")

    def test_rejects_missing_mandatory_test_key(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            sha = "a" * 40
            data = _valid_qualification(sha)
            del data["tests"][MANDATORY_TEST_NAMES[1]]
            path = self._write(tmp, data)
            with self.assertRaises(build_release.BuildError):
                build_release.load_qualification(path, sha, "go1.27.3")



class ReleaseBundleIntegrityTests(unittest.TestCase):
    def test_build_manifest_rejects_symlink_in_bundle(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            release_root = Path(tmp) / "release"
            release_root.mkdir()
            (release_root / "sub2api").write_bytes(b"binary")
            (release_root / "qualification.json").write_text("{}", encoding="utf-8")
            (release_root / "resources").mkdir()
            (release_root / "migrations").mkdir()
            tools_dir = release_root / "tools"
            tools_dir.mkdir()
            real_target = Path(tmp) / "outside.txt"
            real_target.write_text("escape", encoding="utf-8")
            try:
                (tools_dir / "known_hosts").symlink_to(real_target)
            except (OSError, NotImplementedError):
                self.skipTest("symlinks are not supported on this filesystem/user")
            (release_root / "sub2api-image.tar").write_bytes(b"tar")
            with self.assertRaises(build_release.BuildError):
                build_release.build_manifest(
                    release_root, "v1.2.3", "1.2.3", "a" * 40, "go1.27.3",
                    release_root / "sub2api", "sha256:" + "0" * 64, [],
                )

    def test_build_manifest_succeeds_on_first_run_before_manifest_exists(self):
        # Regression guard: manifest.json must not be required to already
        # exist at self-check time -- it is written by the caller only
        # AFTER build_manifest() returns.
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            release_root = Path(tmp) / "release"
            release_root.mkdir()
            (release_root / "sub2api").write_bytes(b"binary")
            (release_root / "qualification.json").write_text("{}", encoding="utf-8")
            (release_root / "resources").mkdir()
            (release_root / "migrations").mkdir()
            (release_root / "tools").mkdir()
            (release_root / "sub2api-image.tar").write_bytes(b"tar")
            manifest = build_release.build_manifest(
                release_root, "v1.2.3", "1.2.3", "a" * 40, "go1.27.3",
                release_root / "sub2api", "sha256:" + "0" * 64, [],
            )
            self.assertEqual(manifest["tag"], "v1.2.3")
            self.assertNotIn("manifest.json", manifest["files"])

    def test_copy_deploy_tools_refuses_to_invent_missing_files(self):
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            empty_script_dir = Path(tmp) / "empty-scripts-ci"
            empty_script_dir.mkdir()
            original = build_release.SCRIPT_DIR
            build_release.SCRIPT_DIR = empty_script_dir
            try:
                release_root = Path(tmp) / "release"
                release_root.mkdir()
                with self.assertRaises(build_release.BuildError):
                    build_release.copy_deploy_tools(release_root)
                # No placeholder/stub files may appear for the missing tools.
                tools_dir = release_root / "tools"
                leftover = list(tools_dir.iterdir()) if tools_dir.exists() else []
                self.assertEqual(leftover, [])
            finally:
                build_release.SCRIPT_DIR = original


class MigrationChecksumTests(unittest.TestCase):
    def test_matches_go_trimspace_semantics_not_universal_newlines(self):
        # A CRLF-terminated migration file: Path.read_text() would normalize
        # \r\n to \n (wrong), while Go's strings.TrimSpace on raw bytes only
        # trims the leading/trailing whitespace, preserving internal CRLF.
        with tempfile.TemporaryDirectory(prefix="sub2api-fixture-") as tmp:
            path = Path(tmp) / "001_fixture.sql"
            raw = b"  \r\nSELECT 1;\r\nSELECT 2;\r\n  "
            path.write_bytes(raw)
            expected_stripped = raw.decode("utf-8").strip()
            import hashlib
            expected = hashlib.sha256(expected_stripped.encode("utf-8")).hexdigest()
            self.assertEqual(build_release.migration_applied_checksum(path), expected)
            # The CRLF must be preserved in what gets hashed (not collapsed).
            self.assertIn("\r\n", expected_stripped)


class ParseRequiredOutcomesTests(unittest.TestCase):
    def test_flags_missing_skip_and_fail_by_bare_name(self):
        names = sorted(qualify_release.REQUIRED_TESTS)
        pkg_a = qualify_release.REQUIRED_TESTS[names[0]]
        pkg_b = qualify_release.REQUIRED_TESTS[names[1]]
        lines = "\n".join([
            '{"Package": "%s", "Test": "%s", "Action": "fail"}' % (pkg_a, names[0]),
            '{"Package": "%s", "Test": "%s", "Action": "skip"}' % (pkg_b, names[1]),
        ])
        outcomes = qualify_release.parse_required_outcomes(lines)
        self.assertEqual(outcomes[names[0]], "fail")
        self.assertEqual(outcomes[names[1]], "skip")
        self.assertEqual(outcomes[names[2]], "missing")

    def test_all_pass_required_for_qualification(self):
        lines = "\n".join(
            '{"Package": "%s", "Test": "%s", "Action": "pass"}' % (pkg, name)
            for name, pkg in qualify_release.REQUIRED_TESTS.items()
        )
        outcomes = qualify_release.parse_required_outcomes(lines)
        self.assertTrue(all(status == "pass" for status in outcomes.values()))

    def test_malformed_json_lines_are_ignored_not_fatal(self):
        lines = "not json\n{broken\n"
        outcomes = qualify_release.parse_required_outcomes(lines)
        self.assertTrue(all(status == "missing" for status in outcomes.values()))

    def test_ignores_event_from_wrong_package_for_same_test_name(self):
        # A same-named test in an unrelated package must not satisfy the
        # mandatory requirement -- the package must match too.
        name = sorted(qualify_release.REQUIRED_TESTS)[0]
        lines = '{"Package": "unexpected/other/pkg", "Test": "%s", "Action": "pass"}' % name
        outcomes = qualify_release.parse_required_outcomes(lines)
        self.assertEqual(outcomes[name], "missing")


if __name__ == "__main__":
    unittest.main()
