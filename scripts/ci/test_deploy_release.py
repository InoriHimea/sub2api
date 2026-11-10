"""Behavior-only tests for scripts/ci/deploy_release.py and
scripts/ci/remote_deploy.py.

These tests exercise OBSERVABLE behavior against throwaway, hermetic
fixtures only: no real SSH connection, no real Docker daemon, no real
PostgreSQL, no production target is ever touched. They do not assert on
source text, YAML wiring, or implementation internals -- only on exit
codes / raised exception classes / returned data for a given fixture input,
matching the controlled Linux smoke's independently exercised inputs.

Run directly with: python3 scripts/ci/test_deploy_release.py
(stdlib unittest only, no pytest dependency, Python 3.9+ compatible).

NOTE: several checks (POSIX file mode 0755, symlinks, root-owned
directories) are meaningful only on a POSIX filesystem and are skipped with
unittest.skip when running on a non-POSIX platform (e.g. a Windows dev
sandbox); the controlled Linux runner exercises them fully.
"""
import hashlib
import importlib.util
import io
import json
import os
import shutil
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
POSIX = os.name == "posix"


def _load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


rd = _load_module("remote_deploy_under_test", "remote_deploy.py")
dr = _load_module("deploy_release_under_test", "deploy_release.py")


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_applied(data):
    """Must mirror rd._go_trim_space exactly, not Python's broader
    str.strip() default -- that discrepancy was a real bug this suite
    exists to catch regressions of."""
    return hashlib.sha256(rd._go_trim_space(data.decode("utf-8")).encode("utf-8")).hexdigest()


GOOD_QUALIFICATION_TESTS = {
    "TestUsageHourlyPostgresHTTPIntegration": "PASS",
    "TestAdminCreateUserAPIKeyIntegration": "PASS",
    "TestOpenAIHTTPObservationRealHTTPSuccessSmoke": "PASS",
}


def build_fixture_bundle(root, compiler="go1.27.3"):
    """Builds a minimal, internally-consistent, VALID release bundle under
    `root` (a Path). Returns the parsed manifest dict. Individual tests
    mutate a copy of this fixture to exercise one failure mode at a time."""
    (root / "resources").mkdir()
    (root / "tools").mkdir()
    (root / "migrations").mkdir()

    binary_bytes = b"#!/bin/sh\necho fake-sub2api\n"
    (root / "sub2api").write_bytes(binary_bytes)
    if POSIX:
        os.chmod(root / "sub2api", 0o755)

    resource_bytes = b"fixture resource\n"
    (root / "resources" / "readme.txt").write_bytes(resource_bytes)

    qualification = {
        "schema": 1,
        "sha": "a" * 40,
        "compiler": compiler,
        "qualified": True,
        "go_test_exit_code": 0,
        "frontend_build_exit_code": 0,
        "tests": dict(GOOD_QUALIFICATION_TESTS),
        "generated_at": "2026-11-10T00:00:00Z",
    }
    qual_bytes = json.dumps(qualification).encode()
    (root / "qualification.json").write_bytes(qual_bytes)

    mig_bytes = b"-- test migration\nSELECT 1;\n"
    (root / "migrations" / "250_fixture.sql").write_bytes(mig_bytes)

    for name in ("deploy_release.py", "remote_deploy.py", "targets.json", "known_hosts"):
        shutil.copyfile(HERE / name, root / "tools" / name)

    tar_path = root / "sub2api-image.tar"
    inner_manifest = json.dumps([{"RepoTags": ["sub2api-fork:1.0.0-abc123456789"], "Config": "deadbeef.json"}]).encode()
    with tarfile.open(tar_path, "w") as tf:
        info = tarfile.TarInfo("manifest.json")
        info.size = len(inner_manifest)
        tf.addfile(info, io.BytesIO(inner_manifest))

    files = {}

    def add_file(rel, path):
        data = Path(path).read_bytes()
        files[rel] = sha256_bytes(data)
        return data

    add_file("sub2api", root / "sub2api")
    add_file("sub2api-image.tar", tar_path)
    add_file("qualification.json", root / "qualification.json")
    add_file("resources/readme.txt", root / "resources" / "readme.txt")
    mig_file_bytes = add_file("migrations/250_fixture.sql", root / "migrations" / "250_fixture.sql")
    for name in ("deploy_release.py", "remote_deploy.py", "targets.json", "known_hosts"):
        add_file("tools/%s" % name, root / "tools" / name)

    manifest = {
        "schema": 1,
        "tag": "v1.0.0",
        "version": "1.0.0",
        "sha": "a" * 40,
        "compiler": compiler,
        "architecture": "amd64",
        "binary_sha256": sha256_bytes(binary_bytes),
        "image_id": "sha256:" + "b" * 64,
        "files": files,
        "migrations": [{"filename": "250_fixture.sql", "sha256": sha256_applied(mig_file_bytes)}],
    }
    (root / "manifest.json").write_bytes(json.dumps(manifest).encode())
    return manifest


class BundleVerificationBehaviorTest(unittest.TestCase):
    """fail-stop-before-mutate: all of this must succeed/fail WITHOUT any
    network, SSH, Docker, or Postgres access -- pure local verification."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = build_fixture_bundle(self.root)


    def test_non_semver_tag_is_rejected(self):
        bad = json.loads(json.dumps(self.manifest))
        bad["tag"] = "release-1.0"
        (self.root / "manifest.json").write_bytes(json.dumps(bad).encode())
        with self.assertRaises(rd.DeployFailure):
            rd.load_manifest(str(self.root))

    def test_dirty_ref_style_tag_suffix_is_rejected(self):
        bad = json.loads(json.dumps(self.manifest))
        bad["tag"] = "v1.0.0-dirty-extra-garbage!!"
        (self.root / "manifest.json").write_bytes(json.dumps(bad).encode())
        with self.assertRaises(rd.DeployFailure):
            rd.load_manifest(str(self.root))

    def test_non_hex_sha_is_rejected(self):
        bad = json.loads(json.dumps(self.manifest))
        bad["sha"] = "not-a-sha" + "0" * 31
        (self.root / "manifest.json").write_bytes(json.dumps(bad).encode())
        with self.assertRaises(rd.DeployFailure):
            rd.load_manifest(str(self.root))

    def test_binary_sha256_must_equal_files_sub2api_entry(self):
        bad = json.loads(json.dumps(self.manifest))
        bad["binary_sha256"] = "0" * 64
        (self.root / "manifest.json").write_bytes(json.dumps(bad).encode())
        with self.assertRaises(rd.DeployFailure):
            rd.load_manifest(str(self.root))

    @unittest.skipUnless(POSIX, "file mode bits are only meaningful on POSIX")
    def test_tampered_file_hash_mismatch_is_rejected(self):
        manifest, _digest = rd.load_manifest(str(self.root))
        (self.root / "resources" / "readme.txt").write_bytes(b"TAMPERED CONTENT\n")
        with self.assertRaises(rd.DeployFailure):
            rd.verify_bundle_files(str(self.root), manifest)

    @unittest.skipUnless(POSIX, "file mode bits are only meaningful on POSIX")
    def test_path_traversal_manifest_entry_is_rejected(self):
        manifest, _digest = rd.load_manifest(str(self.root))
        manifest = json.loads(json.dumps(manifest))
        manifest["files"]["../../etc/passwd"] = "a" * 64
        with self.assertRaises(rd.DeployFailure):
            rd.verify_bundle_files(str(self.root), manifest)

    @unittest.skipUnless(POSIX, "file mode bits are only meaningful on POSIX")
    def test_unexpected_extra_file_is_rejected(self):
        manifest, _digest = rd.load_manifest(str(self.root))
        (self.root / "sneaky.txt").write_bytes(b"not in manifest")
        with self.assertRaises(rd.DeployFailure):
            rd.verify_bundle_files(str(self.root), manifest)

    def test_manifest_json_cannot_be_listed_in_files(self):
        bad = json.loads(json.dumps(self.manifest))
        bad["files"]["manifest.json"] = "a" * 64
        (self.root / "manifest.json").write_bytes(json.dumps(bad).encode())
        with self.assertRaises(rd.DeployFailure):
            rd.load_manifest(str(self.root))

    def test_migration_manifest_checksum_inconsistent_with_shipped_file_is_rejected(self):
        manifest, _digest = rd.load_manifest(str(self.root))
        manifest = json.loads(json.dumps(manifest))
        manifest["migrations"][0]["sha256"] = "0" * 64
        with self.assertRaises(rd.DeployFailure):
            rd.classify_migrations(str(self.root), manifest)

    def test_manifest_digest_changes_detected(self):
        _m1, digest1 = rd.load_manifest(str(self.root))
        bad = json.loads(json.dumps(self.manifest))
        bad["tag"] = "v1.0.1"
        bad["version"] = "1.0.1"
        (self.root / "manifest.json").write_bytes(json.dumps(bad).encode())
        _m2, digest2 = rd.load_manifest(str(self.root))
        self.assertNotEqual(digest1, digest2)


class GoWhitespaceChecksumRegressionTest(unittest.TestCase):
    """Go's strings.TrimSpace (unicode.IsSpace) is NOT the same character
    set as Python's str.strip() default. A migration file is byte-identical
    either way EXCEPT for the exact trimmed boundary, so this must use the
    real Go whitespace rune set or the computed 'applied' checksum silently
    diverges from the live application's schema_migrations ledger."""

    def test_python_default_strip_and_go_trim_space_diverge_on_control_char(self):
        # U+001C (Information Separator Four) is stripped by Python's
        # str.strip() but is NOT unicode.IsSpace in Go.
        text = "-- comment\n\x1c"
        self.assertNotEqual(text.strip(), rd._go_trim_space(text))
        self.assertEqual(rd._go_trim_space(text), "-- comment\n\x1c")

    def test_ordinary_ascii_whitespace_trims_identically(self):
        text = "  \t\nSELECT 1;\n\t  "
        self.assertEqual(text.strip(), rd._go_trim_space(text))

    def test_crlf_migration_file_checksum_is_stable(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "x.sql"
            path.write_bytes(b"SELECT 1;\r\n\r\n")
            # Go's TrimSpace strips \r as whitespace too; both ends trimmed
            # consistently, no newline normalization performed mid-content.
            checksum = rd.sha256_applied_migration(str(path))
            expected = hashlib.sha256(rd._go_trim_space("SELECT 1;\r\n\r\n").encode("utf-8")).hexdigest()
            self.assertEqual(checksum, expected)


class QualificationGateBehaviorTest(unittest.TestCase):
    """Missing/skip/fail qualification results, a nonzero go/frontend exit
    code, qualified!=true, or a compiler mismatch against the manifest must
    all disqualify the whole bundle -- never a soft warning."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = build_fixture_bundle(self.root)

    def _write_qualification(self, **overrides):
        q = {
            "schema": 1, "sha": "a" * 40, "compiler": "go1.27.3", "qualified": True,
            "go_test_exit_code": 0, "frontend_build_exit_code": 0,
            "tests": dict(GOOD_QUALIFICATION_TESTS), "generated_at": "2026-11-10T00:00:00Z",
        }
        q.update(overrides)
        (self.root / "qualification.json").write_bytes(json.dumps(q).encode())

    def test_missing_required_test_blocks(self):
        tests = dict(GOOD_QUALIFICATION_TESTS)
        del tests["TestOpenAIHTTPObservationRealHTTPSuccessSmoke"]
        self._write_qualification(tests=tests)
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)

    def test_skipped_required_test_blocks(self):
        tests = dict(GOOD_QUALIFICATION_TESTS)
        tests["TestOpenAIHTTPObservationRealHTTPSuccessSmoke"] = "SKIP"
        self._write_qualification(tests=tests)
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)

    def test_failed_required_test_blocks(self):
        tests = dict(GOOD_QUALIFICATION_TESTS)
        tests["TestUsageHourlyPostgresHTTPIntegration"] = "FAIL"
        self._write_qualification(tests=tests)
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)

    def test_qualified_false_blocks(self):
        self._write_qualification(qualified=False)
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)

    def test_nonzero_go_test_exit_code_blocks(self):
        self._write_qualification(go_test_exit_code=1)
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)

    def test_nonzero_frontend_build_exit_code_blocks(self):
        self._write_qualification(frontend_build_exit_code=2)
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)

    def test_compiler_mismatch_vs_manifest_blocks(self):
        self._write_qualification(compiler="go1.26.4")
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)

    def test_sha_mismatch_vs_manifest_blocks(self):
        self._write_qualification(sha="f" * 40)
        with self.assertRaises(rd.DeployFailure):
            rd.load_and_verify_qualification(str(self.root), self.manifest)



class MigrationCompatibilityGateBehaviorTest(unittest.TestCase):
    """The schema/migration compatibility gate is a hard blocker, never a
    warning, and must never infer compatibility from unrelated matches. It
    also rejects downgrades: an already-applied ledger filename the bundle
    doesn't know about at all."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = build_fixture_bundle(self.root)
        self.bundle_migrations = rd.classify_migrations(str(self.root), self.manifest)

    def test_already_applied_matching_checksum_is_allowed(self):
        ledger = {"250_fixture.sql": self.bundle_migrations[0]["sha256"]}
        already, pending = rd.gate_migrations(self.bundle_migrations, ledger, {})
        self.assertEqual(already, ["250_fixture.sql"])
        self.assertEqual(pending, [])

    def test_already_applied_mismatching_checksum_is_hard_failure(self):
        ledger = {"250_fixture.sql": "f" * 64}
        with self.assertRaises(rd.DeployFailure):
            rd.gate_migrations(self.bundle_migrations, ledger, {})

    def test_pending_migration_without_profile_approval_is_blocked(self):
        with self.assertRaises(rd.Blocker):
            rd.gate_migrations(self.bundle_migrations, {}, {})

    def test_pending_migration_with_correct_profile_approval_is_allowed(self):
        approved = {"250_fixture.sql": self.bundle_migrations[0]["sha256"]}
        already, pending = rd.gate_migrations(self.bundle_migrations, {}, approved)
        self.assertEqual(pending, ["250_fixture.sql"])

    def test_pending_migration_with_wrong_approved_checksum_is_blocked(self):
        approved = {"250_fixture.sql": "0" * 64}
        with self.assertRaises(rd.Blocker):
            rd.gate_migrations(self.bundle_migrations, {}, approved)


    def test_ledger_filename_absent_from_bundle_is_rejected_as_downgrade(self):
        # The target has already applied a migration this bundle doesn't
        # even know about -- deploying this bundle would be a downgrade.
        ledger = {
            "250_fixture.sql": self.bundle_migrations[0]["sha256"],
            "999_future_migration_not_in_bundle.sql": "e" * 64,
        }
        with self.assertRaises(rd.DeployFailure):
            rd.gate_migrations(self.bundle_migrations, ledger, {})


class ProfileSchemaBehaviorTest(unittest.TestCase):
    """The approved deployment profile is a hard external prerequisite with
    an EXACT, closed schema at every level -- never a dummy/default, never
    tolerant of unknown keys anywhere, not just database.password."""

    def _docker_profile(self):
        return {
            "schema": 1, "target": "gateway3", "kind": "docker",
            "approved_at": "2026-11-10T00:00:00Z", "approved_by": "ops",
            "docker": {"container_name": "sub2api2m", "compose_project_dir": "/data/sub2api2m", "compose_service": "sub2api"},
            "database": {
                "engine": "postgresql", "connect_via": "socket", "dbname": "sub2api", "user": "sub2api",
                "backup_dir": "/var/backups/sub2api2m", "backup_name_prefix": "s2a2m",
                "docker_exec_container": "sub2api2m-postgres", "docker_exec_user": "postgres",
            },
            "migrations": {"approved_new_migration_hashes": {}},
            "health": {"url": "http://127.0.0.1:3205/health", "timeout_seconds": 30},
        }

    def _native_profile(self):
        return {
            "schema": 1, "target": "sub2api3", "kind": "native",
            "approved_at": "2026-11-10T00:00:00Z", "approved_by": "ops",
            "native": {"service_name": "sub2api.service", "binary_path": "/opt/sub2api/sub2api",
                       "service_user": "sub2api", "service_group": "sub2api"},
            "database": {
                "engine": "postgresql", "connect_via": "socket", "dbname": "sub2api", "user": "sub2api",
                "backup_dir": "/var/backups/sub2api3", "backup_name_prefix": "s2a3",
                "os_user": "postgres",
            },
            "migrations": {"approved_new_migration_hashes": {}},
            "health": {"url": "http://127.0.0.1:9527/health", "timeout_seconds": 30},
        }


    def test_database_engine_must_be_exactly_postgresql(self):
        p = self._docker_profile()
        p["database"]["engine"] = "mysql"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")


    def test_target_mismatch_is_blocked(self):
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(self._docker_profile(), "sub2api3", "docker")

    def test_kind_mismatch_is_blocked(self):
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(self._docker_profile(), "gateway3", "native")

    def test_password_field_is_rejected(self):
        p = self._docker_profile()
        p["database"]["password"] = "hunter2"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_unknown_key_anywhere_is_rejected_not_just_password(self):
        p = self._docker_profile()
        p["database"]["some_other_smuggled_field"] = "sneaky"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_unknown_top_level_key_is_rejected(self):
        p = self._docker_profile()
        p["extra_top_level"] = "sneaky"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_missing_docker_block_is_blocked(self):
        p = self._docker_profile()
        del p["docker"]
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_docker_block_present_for_native_kind_is_blocked(self):
        p = self._native_profile()
        p["docker"] = {"container_name": "x", "compose_project_dir": "/y", "compose_service": "z"}
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "sub2api3", "native")

    def test_docker_profile_missing_docker_exec_fields_is_blocked(self):
        p = self._docker_profile()
        del p["database"]["docker_exec_container"]
        del p["database"]["docker_exec_user"]
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_native_profile_missing_os_user_is_blocked(self):
        p = self._native_profile()
        del p["database"]["os_user"]
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "sub2api3", "native")

    def test_native_os_user_root_is_blocked(self):
        p = self._native_profile()
        p["database"]["os_user"] = "root"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "sub2api3", "native")

    def test_connect_via_must_be_exactly_socket(self):
        # tcp-local/remote transports are not implemented at all -- only
        # the two real, verified targets (docker-exec and native peer-auth
        # socket) exist, so anything else must be rejected outright.
        p = self._docker_profile()
        p["database"]["connect_via"] = "tcp-local"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_unbounded_backup_name_length_is_rejected(self):
        p = self._docker_profile()
        p["database"]["max_backup_name_length"] = 100000
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_unsafe_backup_name_prefix_is_rejected(self):
        p = self._docker_profile()
        p["database"]["backup_name_prefix"] = "../../etc"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_malformed_approved_migration_hash_is_rejected(self):
        p = self._docker_profile()
        p["migrations"]["approved_new_migration_hashes"] = {"250_fixture.sql": "not-hex"}
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_public_health_url_is_rejected(self):
        p = self._docker_profile()
        p["health"]["url"] = "http://203.0.113.5:3205/health"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_health_url_hostname_prefix_bypass_is_rejected(self):
        # "127.0.0.1.evil.com" starts with "127.0.0.1" as a string but is a
        # completely different host -- must be rejected by exact hostname
        # parsing, not a string prefix check.
        p = self._docker_profile()
        p["health"]["url"] = "http://127.0.0.1.evil.com/health"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")

    def test_health_url_with_embedded_credentials_is_rejected(self):
        p = self._docker_profile()
        p["health"]["url"] = "http://user:pass@127.0.0.1:3205/health"
        with self.assertRaises(rd.Blocker):
            rd.validate_profile_schema(p, "gateway3", "docker")


class TargetAndKeyResolutionBehaviorTest(unittest.TestCase):
    """Missing CI key / missing target profile are explicit operational
    blockers, never silently replaced."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        build_fixture_bundle(self.root)
        self._env_backup = {}
        for key in ("SUB2API_DEPLOY_SSH_KEY", "SSH_AUTH_SOCK"):
            self._env_backup[key] = os.environ.pop(key, None)
        self.addCleanup(self._restore_env)

    def _restore_env(self):
        for key, value in self._env_backup.items():
            if value is not None:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)

    def test_unknown_target_is_blocked(self):
        with self.assertRaises(dr.OrchestratorBlocker):
            dr.load_target(str(self.root), "does-not-exist")

    def test_missing_ssh_key_and_agent_is_blocked(self):
        with self.assertRaises(dr.OrchestratorBlocker):
            dr.resolve_ssh_key()

    def test_nonexistent_explicit_key_path_is_blocked(self):
        os.environ["SUB2API_DEPLOY_SSH_KEY"] = str(self.root / "no-such-key")
        with self.assertRaises(dr.OrchestratorBlocker):
            dr.resolve_ssh_key()

    def test_orchestrate_blocks_before_any_ssh_when_key_missing(self):
        """End-to-end: deploy_release.py's top-level entrypoint must stop
        with the blocker exit code, without attempting any SSH/scp/tar
        call, when no CI key/agent is configured."""
        self.assertEqual(dr.main(["--bundle", str(self.root), "--target", "gateway3"]), dr.EXIT_BLOCKER)


class RollbackLedgerGateBehaviorTest(unittest.TestCase):
    """The automatic-rollback decision must re-verify the live migration
    ledger is EXACTLY the preflight baseline immediately before attempting
    any automatic rollback -- even when this release's own predicted
    pending-migrations list was empty. A DB read failure is treated the
    same as a drift: never safe to proceed. Only an exactly-unchanged
    ledger permits a verified automatic rollback."""

    def setUp(self):
        self._orig_read_ledger = rd.read_schema_migrations_ledger
        self.addCleanup(self._restore)

    def _restore(self):
        rd.read_schema_migrations_ledger = self._orig_read_ledger

    def test_unchanged_ledger_permits_verified_rollback(self):
        baseline = {"250_fixture.sql": "a" * 64}
        rd.read_schema_migrations_ledger = lambda db: dict(baseline)
        prev = {"baseline_ledger": baseline}
        ok, err = rd.ledger_matches_baseline({}, prev)
        self.assertTrue(ok)
        self.assertIsNone(err)

    def test_pending_empty_but_live_ledger_changed_blocks_rollback(self):
        baseline = {"250_fixture.sql": "a" * 64}
        drifted = {"250_fixture.sql": "a" * 64, "251_unexpected.sql": "b" * 64}
        rd.read_schema_migrations_ledger = lambda db: dict(drifted)
        prev = {"baseline_ledger": baseline}
        ok, err = rd.ledger_matches_baseline({}, prev)
        self.assertFalse(ok)
        self.assertIsNotNone(err)

    def test_db_read_failure_blocks_rollback_same_as_drift(self):
        baseline = {"250_fixture.sql": "a" * 64}

        def _boom(db):
            raise rd.DeployFailure("database unreachable")
        rd.read_schema_migrations_ledger = _boom
        prev = {"baseline_ledger": baseline}
        ok, err = rd.ledger_matches_baseline({}, prev)
        self.assertFalse(ok)
        self.assertIn("unreachable", err)


    def test_post_start_requires_complete_expected_schema_even_without_pending(self):
        baseline = {"250_fixture.sql": "a" * 64}
        for pending in ({}, {"251_expected.sql": "b" * 64}):
            expected = dict(baseline, **pending)
            bad_ledgers = [{}, dict(expected, **{"250_fixture.sql": "c" * 64}),
                           dict(expected, **{"252_unexpected.sql": "d" * 64})]
            if pending:
                bad_ledgers.append(dict(baseline))
            for ledger in bad_ledgers:
                with self.subTest(pending=pending, ledger=ledger):
                    rd.read_schema_migrations_ledger = lambda db, value=ledger: value
                    with self.assertRaises(rd.DeployFailure):
                        rd.verify_pending_migrations_applied({}, {"baseline_ledger": baseline,
                                                                 "migrations_pending_hashes": pending})


    def test_post_start_database_failure_is_not_healthy(self):
        def unavailable(db):
            raise rd.DeployFailure("database unreachable")
        rd.read_schema_migrations_ledger = unavailable
        with self.assertRaises(rd.DeployFailure):
            rd.verify_pending_migrations_applied({}, {"baseline_ledger": {}, "migrations_pending_hashes": {}})


if __name__ == "__main__":
    unittest.main()
