#!/usr/bin/env python3
"""remote_deploy.py -- runs ON a deploy target (gateway3 or sub2api3), invoked
over SSH by scripts/ci/deploy_release.py. Never run this against a target
without first going through deploy_release.py's artifact verification; this
script re-verifies independently anyway (defense in depth) but intentionally
contains no network-fetch, registry-login, or secret-reading logic itself.

Python 3.9 compatible (no hashlib.file_digest, no match/case, no PEP604
unions). Stdlib only -- no pip dependencies on the target.

Stages (run as three SEPARATE invocations by the orchestrator -- this is the
"separate pure verification, staging and activation" boundary from the
deployment safety contract):

    preflight   Read-only. Validates the root-protected approved deployment
                profile, cross-checks it against the LIVE running
                service/container (and the live OS identity it runs as),
                re-verifies bundle file hashes and migration checksum
                classification against the live DB ledger (queried via the
                profile-bound, non-interactive, password-free route: a
                peer-authenticated local OS user for native, or `docker exec`
                into the profile-bound Postgres container for Docker
                targets). Writes NOTHING except a root-only state/receipt
                file under --state-dir, binding this run to a digest of the
                manifest and the profile so neither can silently change
                underneath a multi-stage run.

    stage       Takes a real, streamed PostgreSQL backup on the target
                (bounded safe filename, written 0600 from creation, never
                buffered whole in memory). Loads the Docker image or stages
                the native binary/resources atomically. Does not touch the
                running service/container or any compose config file.

    activate    Re-validates the manifest/profile digests and live baseline
                have not drifted since preflight, then swaps to the new
                artifact (compose image override + `up -d --no-deps --pull
                never`, or systemd binary/resources replace + restart),
                verifies health/version/artifact identity (image ID or
                binary SHA -- never a mutable tag string), and applies the
                documented failure/rollback policy. Every exception raised
                during the mutation window is caught so diagnostics and the
                backup receipt are always preserved and the correct
                rollback/manual-intervention decision is always made.

Every stage requires the state file written by the previous stage, matching
--run-id, within a bounded freshness window. There is no "deploy" subcommand
that silently does all three -- each must be invoked explicitly, so a partial
or interrupted sequence always stops instead of guessing.

Exit codes:
    0  success
    1  verification/runtime failure (no target mutation attempted, or a
       deterministic rollback was attempted and its outcome is in the output)
    2  operational blocker -- a real external prerequisite is missing
       (approved profile absent/invalid, trust/auth missing, backup
       prerequisite absent, schema/migration approval absent). Never
       replaced by a default/guess.
    3  manual intervention required -- activation failed AFTER migrations
       may have been applied by the new binary's own startup migrator; no
       automatic binary rollback was attempted (would be unsafe against the
       new schema). Backup + diagnostics are preserved.

Each stage prints exactly one compact, single-line JSON object as the LAST
line of stdout (all other output, including `log()`, goes to stderr) so the
orchestrator can parse it reliably with a single json.loads() call.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_BLOCKER = 2
EXIT_MANUAL_INTERVENTION = 3

PROFILE_PATH = "/etc/sub2api/deploy-profile.json"
STATE_FRESHNESS_SECONDS = 1800  # bounded: a stage must follow the previous one within 30 minutes
HEALTH_POLL_TIMEOUT_SECONDS = 60
HEALTH_POLL_INTERVAL_SECONDS = 2
MAX_BACKUP_NAME_LENGTH_CEILING = 200
SAFE_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
# Full SemVer 2.0.0 grammar (https://semver.org), v-prefixed per contract.
SEMVER_TAG_RE = re.compile(
    r"^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?"
    r"(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$"
)
COMPILER_RE = re.compile(r"^go\d+\.\d+\.\d+$")
REQUIRED_QUALIFICATION_TESTS = (
    "TestUsageHourlyPostgresHTTPIntegration",
    "TestAdminCreateUserAPIKeyIntegration",
    "TestOpenAIHTTPObservationRealHTTPSuccessSmoke",
)
# Marker written into any compose override file this tool creates, so a
# later run can tell "ours, safe to update" apart from an operator's own
# pre-existing override, which must never be silently clobbered.
COMPOSE_OVERRIDE_MARKER = "# sub2api-deploy-tool-owned-override: do not hand-edit"


class Blocker(Exception):
    """A real external prerequisite is missing. Fail closed, exit code 2."""


class DeployFailure(Exception):
    """Verification or runtime failure. Exit code 1 unless migrations_applied."""


def log(msg: str) -> None:
    sys.stderr.write("[remote_deploy] %s\n" % msg)
    sys.stderr.flush()


def emit_result(obj: Dict[str, Any]) -> None:
    """The ONLY thing ever written to stdout: one compact JSON line."""
    sys.stdout.write(json.dumps(obj, separators=(",", ":"), sort_keys=True))
    sys.stdout.write("\n")
    sys.stdout.flush()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# Go's strings.TrimSpace trims runes where unicode.IsSpace is true. That set
# is NOT the same as Python's str.strip() default (which additionally strips
# ASCII 0x1C-0x1F, the "information separator" control characters, that Go
# does NOT treat as whitespace). Using Python's default would silently
# diverge from the real application ledger for any migration file that
# happens to contain one of those bytes (e.g. inside a comment). This is the
# exact rune set unicode.IsSpace recognizes in Go's unicode package.
_GO_TRIM_SPACE_CHARS = (
    "\t\n\v\f\r \u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)


def _go_trim_space(text: str) -> str:
    return text.strip(_GO_TRIM_SPACE_CHARS)


def sha256_applied_migration(path: str) -> str:
    """Authoritative 'applied' checksum per
    backend/internal/repository/migrations_runner.go:189-197 ---
    hex(sha256(strings.TrimSpace(file_content_as_utf8))). This is NOT the
    same as the raw-byte file hash used in manifest.files. Trims EXACTLY
    Go's unicode.IsSpace rune set, not Python's broader str.strip()
    default."""
    with open(path, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-8")
    trimmed = _go_trim_space(text)
    return hashlib.sha256(trimmed.encode("utf-8")).hexdigest()


def open_private(path: str, mode: int = 0o600):
    """Opens a NEW file descriptor that is 0600 (or stricter) from the
    moment of creation -- never world/group readable even for an instant.
    Raises FileExistsError if the path already exists (no silent overwrite
    of a pre-existing file through this helper)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    return os.fdopen(fd, "wb")


def clean_pg_env() -> Dict[str, str]:
    """A minimal subprocess environment for psql/pg_dump that can NEVER
    inherit ambient business credentials or silently fall back to
    ~/.pgpass, PGPASSWORD, or PGSERVICE. -w/--no-password alone is not
    enough: it still consults ~/.pgpass. PGPASSFILE=/dev/null defeats
    that unconditionally."""
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "PGPASSFILE": "/dev/null",
        "PGCONNECT_TIMEOUT": "10",
        "LC_ALL": "C",
    }


def run(argv: List[str], check: bool = True, input_bytes: Optional[bytes] = None,
        timeout: Optional[float] = None, env: Optional[Dict[str, str]] = None) -> "subprocess.CompletedProcess[bytes]":
    log("exec: %s" % " ".join(argv))
    proc = subprocess.run(
        argv,
        input=input_bytes,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        env=env,
    )
    if check and proc.returncode != 0:
        raise DeployFailure(
            "command failed (%d): %s\nstdout=%s\nstderr=%s"
            % (proc.returncode, " ".join(argv), proc.stdout.decode(errors="replace")[-2000:],
               proc.stderr.decode(errors="replace")[-2000:])
        )
    return proc


# ---------------------------------------------------------------------------
# Profile loading and schema validation -- EXACT key sets at every level,
# nonsecret only.
# ---------------------------------------------------------------------------

def require_root() -> None:
    if os.geteuid() != 0:
        raise Blocker("remote_deploy.py must run as root on the target (SSH user is root per contract); current euid=%d" % os.geteuid())


def load_approved_profile(target: str, kind: str) -> Tuple[Dict[str, Any], str]:
    """Loads and fully validates the root-owned, non-world/group-readable
    approved deployment profile. Returns (profile, sha256_of_profile_bytes).
    This file is a REAL external prerequisite maintained by target
    operators -- it is never written, defaulted, or invented by this
    tooling. Missing/invalid profile is an explicit operational blocker
    (exit 2), not a soft warning. Its presence or absence on a target this
    tooling has never successfully reached over SSH is UNVERIFIED, not
    confirmed-absent -- callers/report text must preserve that distinction."""
    if not os.path.isfile(PROFILE_PATH):
        raise Blocker(
            "approved deployment profile missing at %s -- this is a required "
            "root-owned operational prerequisite that must be provisioned by "
            "target operators before any deploy; refusing to invent defaults"
            % PROFILE_PATH
        )
    st = os.stat(PROFILE_PATH)
    if st.st_uid != 0:
        raise Blocker("approved deployment profile %s is not owned by root (uid=%d); refusing to trust it" % (PROFILE_PATH, st.st_uid))
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise Blocker(
            "approved deployment profile %s is group/other accessible (mode=%o); "
            "it must be root:root and mode 0600/0400 to be trusted"
            % (PROFILE_PATH, stat.S_IMODE(st.st_mode))
        )
    with open(PROFILE_PATH, "rb") as stream:
        raw = stream.read()
    try:
        profile = json.loads(raw.decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise Blocker("approved deployment profile %s is unreadable or not valid JSON: %s" % (PROFILE_PATH, exc))

    validate_profile_schema(profile, target, kind)
    return profile, hashlib.sha256(raw).hexdigest()


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise Blocker("approved deployment profile invalid: %s" % msg)


def _require_exact_keys(obj: Dict[str, Any], required: Tuple[str, ...], optional: Tuple[str, ...], where: str) -> None:
    allowed = set(required) | set(optional)
    actual = set(obj.keys())
    missing = set(required) - actual
    extra = actual - allowed
    _require(not missing, "%s is missing required key(s): %s" % (where, sorted(missing)))
    _require(not extra, "%s has unexpected/unknown key(s) not in the exact schema: %s" % (where, sorted(extra)))


ROOT_PROFILE_REQUIRED = ("schema", "target", "kind", "approved_at", "approved_by", "database", "migrations", "health")
ROOT_PROFILE_OPTIONAL = ("docker", "native")
DOCKER_PROFILE_KEYS = ("container_name", "compose_project_dir", "compose_service")
NATIVE_PROFILE_REQUIRED = ("service_name", "binary_path", "service_user", "service_group")
NATIVE_PROFILE_OPTIONAL = ("resources_dir",)
DATABASE_REQUIRED_COMMON = ("engine", "connect_via", "dbname", "user", "backup_dir", "backup_name_prefix")
DATABASE_OPTIONAL_COMMON = ("max_backup_name_length",)
DATABASE_NATIVE_SOCKET_REQUIRED = ("os_user",)
DATABASE_DOCKER_REQUIRED = ("docker_exec_container", "docker_exec_user")
MIGRATIONS_KEYS = ("approved_new_migration_hashes",)
HEALTH_REQUIRED = ("url", "timeout_seconds")


def validate_profile_schema(profile: Dict[str, Any], target: str, kind: str) -> None:
    """Exact, closed schema -- every top-level and nested object's key set
    is fully enumerated; anything else is rejected, not just
    database.password. See the module-level docstring / returned report for
    the authoritative schema reference."""
    _require(isinstance(profile, dict), "root must be a JSON object")
    _require_exact_keys(profile, ROOT_PROFILE_REQUIRED, ROOT_PROFILE_OPTIONAL, "profile root")
    _require(profile.get("schema") == 1, "schema must be exactly 1")
    _require(profile.get("target") == target, "profile.target (%r) does not match requested --target (%r)" % (profile.get("target"), target))
    _require(profile.get("kind") == kind, "profile.kind (%r) does not match target kind (%r)" % (profile.get("kind"), kind))
    _require(isinstance(profile.get("approved_at"), str) and profile["approved_at"], "approved_at must be a non-empty ISO8601 string")
    _require(isinstance(profile.get("approved_by"), str) and profile["approved_by"], "approved_by must be a non-empty string")

    if kind == "docker":
        _require("docker" in profile, "docker block required for kind=docker")
        _require("native" not in profile, "native block must not be present for kind=docker")
        d = profile["docker"]
        _require(isinstance(d, dict), "docker must be an object")
        _require_exact_keys(d, DOCKER_PROFILE_KEYS, (), "profile.docker")
        for key in DOCKER_PROFILE_KEYS:
            _require(isinstance(d.get(key), str) and d[key], "docker.%s must be a non-empty string" % key)
    elif kind == "native":
        _require("native" in profile, "native block required for kind=native")
        _require("docker" not in profile, "docker block must not be present for kind=native")
        n = profile["native"]
        _require(isinstance(n, dict), "native must be an object")
        _require_exact_keys(n, NATIVE_PROFILE_REQUIRED, NATIVE_PROFILE_OPTIONAL, "profile.native")
        for key in NATIVE_PROFILE_REQUIRED:
            _require(isinstance(n.get(key), str) and n[key], "native.%s must be a non-empty string" % key)
        _require(n["binary_path"].startswith("/"), "native.binary_path must be an absolute path")
        if "resources_dir" in n:
            _require(isinstance(n["resources_dir"], str) and n["resources_dir"].startswith("/"), "native.resources_dir must be an absolute path if present")
    else:
        raise Blocker("unknown target kind %r" % kind)

    db = profile.get("database")
    _require(isinstance(db, dict), "database block required")
    # Boring, exactly-two-real-targets scope: gateway3 Docker-local (via
    # `docker exec` into the profile-bound Postgres container) and
    # sub2api3 native (local peer-auth socket as a dedicated OS user).
    # There is no verified target needing a TCP/remote database route, so
    # that transport is not implemented at all -- never a generic
    # unneeded API surface.
    _require(db.get("connect_via") == "socket", "database.connect_via must be exactly 'socket' (the only implemented, verified transport)")
    _require(db.get("engine") == "postgresql", "database.engine must be exactly 'postgresql'")
    required = set(DATABASE_REQUIRED_COMMON)
    optional = set(DATABASE_OPTIONAL_COMMON)
    if kind == "docker":
        required |= set(DATABASE_DOCKER_REQUIRED)
    else:
        required |= set(DATABASE_NATIVE_SOCKET_REQUIRED)
    _require_exact_keys(db, tuple(sorted(required)), tuple(sorted(optional)), "profile.database")
    _require(isinstance(db.get("dbname"), str) and db["dbname"], "database.dbname must be a non-empty string")
    _require(isinstance(db.get("user"), str) and db["user"], "database.user must be a non-empty string")
    _require(isinstance(db.get("backup_dir"), str) and db["backup_dir"].startswith("/"), "database.backup_dir must be an absolute path")
    _require(isinstance(db.get("backup_name_prefix"), str) and SAFE_TOKEN_RE.match(db["backup_name_prefix"]) and len(db["backup_name_prefix"]) <= 32,
              "database.backup_name_prefix must match ^[A-Za-z0-9_-]{1,32}$")
    max_len = db.get("max_backup_name_length", 128)
    _require(isinstance(max_len, int) and 16 <= max_len <= MAX_BACKUP_NAME_LENGTH_CEILING,
              "database.max_backup_name_length must be an int between 16 and %d" % MAX_BACKUP_NAME_LENGTH_CEILING)
    if kind == "native":
        _require(isinstance(db.get("os_user"), str) and SAFE_TOKEN_RE.match(db["os_user"]), "database.os_user must be a safe OS username (peer-auth identity, never root)")
        _require(db["os_user"] != "root", "database.os_user must not be root -- use the dedicated Postgres peer-auth OS identity")
    if kind == "docker":
        _require(isinstance(db.get("docker_exec_container"), str) and db["docker_exec_container"], "database.docker_exec_container must be a non-empty string")
        _require(isinstance(db.get("docker_exec_user"), str) and SAFE_TOKEN_RE.match(db["docker_exec_user"]), "database.docker_exec_user must be a safe in-container OS username")

    mig = profile.get("migrations")
    _require(isinstance(mig, dict), "migrations block required")
    _require_exact_keys(mig, MIGRATIONS_KEYS, (), "profile.migrations")
    approved = mig["approved_new_migration_hashes"]
    _require(isinstance(approved, dict), "migrations.approved_new_migration_hashes must be an object")
    for fname, csum in approved.items():
        _require(isinstance(fname, str) and fname.endswith(".sql") and "/" not in fname and ".." not in fname,
                  "migrations.approved_new_migration_hashes key %r must be a bare .sql filename" % fname)
        _require(isinstance(csum, str) and HEX64_RE.match(csum), "migrations.approved_new_migration_hashes[%s] must be 64 lowercase hex chars" % fname)

    health = profile.get("health")
    _require(isinstance(health, dict), "health block required")
    _require_exact_keys(health, HEALTH_REQUIRED, (), "profile.health")
    validate_local_health_url(health.get("url"))
    _require(isinstance(health.get("timeout_seconds"), (int, float)) and 1 <= health["timeout_seconds"] <= 120, "health.timeout_seconds must be between 1 and 120")


def validate_local_health_url(url: Any) -> None:
    _require(isinstance(url, str) and url, "health.url must be a non-empty string")
    parsed = urlparse(url)
    _require(parsed.scheme == "http", "health.url scheme must be http (local-only check)")
    _require(parsed.hostname == "127.0.0.1", "health.url host must be exactly 127.0.0.1 (got %r) -- no hostnames, no suffix tricks" % parsed.hostname)
    _require(parsed.username is None and parsed.password is None, "health.url must not embed credentials")
    _require(parsed.path.startswith("/"), "health.url must have an absolute path")


# ---------------------------------------------------------------------------
# Bundle / manifest verification (defense in depth -- deploy_release.py
# already verified the bundle before transfer; we never trust that blindly
# once it's on the target, we re-derive everything from the bytes actually
# present here).
# ---------------------------------------------------------------------------

def load_manifest(bundle_dir: str) -> Tuple[Dict[str, Any], str]:
    """Returns (manifest, sha256_of_manifest_bytes)."""
    manifest_path = os.path.join(bundle_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise DeployFailure("manifest.json missing from transferred bundle at %s" % manifest_path)
    with open(manifest_path, "rb") as stream:
        raw = stream.read()
    manifest = json.loads(raw.decode("utf-8"))
    _require_manifest(isinstance(manifest, dict), "manifest root must be an object")
    _require_manifest(manifest.get("schema") == 1, "manifest.schema must be 1")
    _require_manifest(isinstance(manifest.get("tag"), str) and SEMVER_TAG_RE.match(manifest["tag"]), "manifest.tag must be v-prefixed strict SemVer")
    _require_manifest(isinstance(manifest.get("version"), str) and manifest["version"] and manifest["tag"] == "v" + manifest["version"], "manifest.version must equal manifest.tag without the leading v")
    _require_manifest(isinstance(manifest.get("sha"), str) and HEX40_RE.match(manifest["sha"]), "manifest.sha must be 40 lowercase hex chars")
    _require_manifest(isinstance(manifest.get("compiler"), str) and COMPILER_RE.match(manifest["compiler"]), "manifest.compiler must match goX.Y.Z")
    _require_manifest(manifest.get("architecture") == "amd64", "manifest.architecture must be amd64")
    _require_manifest(isinstance(manifest.get("binary_sha256"), str) and HEX64_RE.match(manifest["binary_sha256"]), "manifest.binary_sha256 must be 64 lowercase hex chars")
    _require_manifest(isinstance(manifest.get("image_id"), str) and manifest["image_id"].startswith("sha256:") and HEX64_RE.match(manifest["image_id"][7:]), "manifest.image_id must be sha256:<64hex>")
    _require_manifest(isinstance(manifest.get("files"), dict) and manifest["files"], "manifest.files must be a non-empty object")
    _require_manifest(isinstance(manifest.get("migrations"), list), "manifest.migrations must be a list")
    _require_manifest("manifest.json" not in manifest["files"], "manifest.files must not list manifest.json itself")
    _require_manifest(manifest["files"].get("sub2api") == manifest["binary_sha256"], "manifest.binary_sha256 must equal manifest.files['sub2api']")
    return manifest, hashlib.sha256(raw).hexdigest()


def _require_manifest(cond: bool, msg: str) -> None:
    if not cond:
        raise DeployFailure("manifest invalid: %s" % msg)


REQUIRED_BUNDLE_FILES = (
    "sub2api",
    "sub2api-image.tar",
    "qualification.json",
)
REQUIRED_BUNDLE_PREFIXES = ("resources/", "tools/", "migrations/")
QUALIFICATION_REQUIRED_KEYS = (
    "schema", "sha", "compiler", "qualified", "go_test_exit_code",
    "frontend_build_exit_code", "tests", "generated_at",
)


def load_and_verify_qualification(bundle_dir: str, manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Validates the exact qualification.json shape confirmed by the
    builder: {schema, sha, compiler, qualified, go_test_exit_code,
    frontend_build_exit_code, tests:{3 named tests: 'PASS'}, generated_at}.
    Missing/skip/fail on any required test, a nonzero go/frontend exit code,
    qualified!=true, or a compiler mismatch against the manifest all
    disqualify the whole bundle."""
    qualification_path = os.path.join(bundle_dir, "qualification.json")
    if not os.path.isfile(qualification_path):
        raise DeployFailure("qualification.json missing from bundle at %s" % qualification_path)
    with open(qualification_path, "r", encoding="utf-8") as f:
        q = json.load(f)
    _require_manifest(isinstance(q, dict), "qualification.json root must be an object")
    missing = set(QUALIFICATION_REQUIRED_KEYS) - set(q.keys())
    _require_manifest(not missing, "qualification.json missing required key(s): %s" % sorted(missing))
    _require_manifest(q.get("schema") == 1, "qualification.json schema must be 1")
    _require_manifest(q.get("sha") == manifest["sha"], "qualification.json sha does not match manifest.sha")
    _require_manifest(q.get("compiler") == manifest["compiler"], "qualification.json compiler (%r) does not match manifest.compiler (%r)" % (q.get("compiler"), manifest["compiler"]))
    _require_manifest(q.get("qualified") is True, "qualification.json qualified must be exactly true")
    _require_manifest(q.get("go_test_exit_code") == 0, "qualification.json go_test_exit_code must be 0, got %r" % q.get("go_test_exit_code"))
    _require_manifest(q.get("frontend_build_exit_code") == 0, "qualification.json frontend_build_exit_code must be 0, got %r" % q.get("frontend_build_exit_code"))
    tests = q.get("tests")
    _require_manifest(isinstance(tests, dict), "qualification.json tests must be an object")
    for t in REQUIRED_QUALIFICATION_TESTS:
        status = tests.get(t)
        if status != "PASS":
            raise DeployFailure("qualification.json test %s status is %r, required PASS (missing/skip/fail disqualifies)" % (t, status))
    _require_manifest(isinstance(q.get("generated_at"), str) and q["generated_at"], "qualification.json generated_at must be a non-empty string")
    return q


def verify_bundle_files(bundle_dir: str, manifest: Dict[str, Any]) -> None:
    """Hash-verify every file the manifest claims, reject anything the
    bundle contains that the manifest does not list (plus manifest.json
    itself), reject symlinks and path traversal. No target mutation may
    happen until this passes."""
    files = manifest["files"]
    bundle_real = os.path.realpath(bundle_dir)

    for rel, expected_sha in files.items():
        _require_manifest(isinstance(rel, str) and rel and not rel.startswith("/") and ".." not in rel.split("/"),
                           "files key %r is not a safe relative path" % rel)
        _require_manifest(isinstance(expected_sha, str) and HEX64_RE.match(expected_sha), "files[%s] sha must be 64 lowercase hex chars" % rel)
        full = os.path.join(bundle_dir, rel)
        full_real = os.path.realpath(full)
        if os.path.commonpath([bundle_real, full_real]) != bundle_real:
            raise DeployFailure("files[%s] escapes bundle directory (path traversal)" % rel)
        if os.path.islink(full):
            raise DeployFailure("files[%s] is a symlink -- rejected" % rel)
        if not os.path.isfile(full):
            raise DeployFailure("files[%s] is missing from transferred bundle" % rel)
        actual_sha = sha256_file(full)
        if actual_sha != expected_sha:
            raise DeployFailure("files[%s] sha256 mismatch: manifest=%s actual=%s" % (rel, expected_sha, actual_sha))

    for required in REQUIRED_BUNDLE_FILES:
        _require_manifest(required in files, "manifest.files is missing required entry %r" % required)
    for prefix in REQUIRED_BUNDLE_PREFIXES:
        _require_manifest(any(k.startswith(prefix) for k in files), "manifest.files has no entries under required prefix %r" % prefix)

    # Reject unexpected extra files/symlinks anywhere under the bundle.
    allowed = set(files.keys())
    allowed.add("manifest.json")
    for root, dirnames, filenames in os.walk(bundle_dir):
        for d in list(dirnames):
            full_d = os.path.join(root, d)
            if os.path.islink(full_d):
                raise DeployFailure("bundle contains a symlinked directory %r -- rejected" % os.path.relpath(full_d, bundle_dir))
            if os.path.relpath(full_d, bundle_dir) == "__pycache__" or d == "__pycache__":
                raise DeployFailure("bundle contains a __pycache__ directory -- a prior run's bytecode cache leaked into the immutable bundle; this indicates sys.dont_write_bytecode was not honored")
        for fn in filenames:
            full_f = os.path.join(root, fn)
            rel_f = os.path.relpath(full_f, bundle_dir).replace(os.sep, "/")
            if os.path.islink(full_f):
                raise DeployFailure("bundle contains a symlinked file %r -- rejected" % rel_f)
            if not stat.S_ISREG(os.stat(full_f).st_mode):
                raise DeployFailure("bundle contains a non-regular file %r -- rejected" % rel_f)
            if rel_f not in allowed:
                raise DeployFailure("bundle contains unexpected file not listed in manifest.files: %r" % rel_f)

    sub2api_mode = stat.S_IMODE(os.stat(os.path.join(bundle_dir, "sub2api")).st_mode)
    if sub2api_mode != 0o755:
        raise DeployFailure("bundle sub2api binary mode is %o, expected 0755" % sub2api_mode)


def classify_migrations(bundle_dir: str, manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Independently recomputes the TrimSpace-applied checksum from the
    actual shipped SQL bytes for every migration filename in
    manifest.migrations, and cross-checks it against manifest.migrations
    itself."""
    migrations_dir = os.path.join(bundle_dir, "migrations")
    out = []
    for entry in manifest["migrations"]:
        _require_manifest(isinstance(entry, dict) and isinstance(entry.get("filename"), str) and isinstance(entry.get("sha256"), str),
                           "manifest.migrations entries must be {filename, sha256} objects")
        fname = entry["filename"]
        _require_manifest(fname.endswith(".sql") and "/" not in fname and ".." not in fname, "manifest.migrations filename %r unsafe" % fname)
        _require_manifest(HEX64_RE.match(entry["sha256"]), "manifest.migrations[%s].sha256 must be 64 lowercase hex" % fname)
        sql_path = os.path.join(migrations_dir, fname)
        if not os.path.isfile(sql_path):
            raise DeployFailure("manifest.migrations references %s but release/migrations/%s is not in the bundle" % (fname, fname))
        recomputed = sha256_applied_migration(sql_path)
        if recomputed != entry["sha256"]:
            raise DeployFailure(
                "migration %s: manifest.migrations sha256 (%s) does not match independently "
                "recomputed TrimSpace-applied checksum of the shipped file (%s) -- refusing to "
                "trust inconsistent manifest-vs-payload metadata" % (fname, entry["sha256"], recomputed)
            )
        out.append({"filename": fname, "sha256": recomputed, "path": sql_path})
    return out


# ---------------------------------------------------------------------------
# Live target identity discovery -- NEVER trust the profile's declared
# identity alone; it must match what is actually running. We use `--format`
# everywhere so full container/image inspect JSON (which can contain
# business secrets in Config.Env) never enters this process at all.
# ---------------------------------------------------------------------------

DOCKER_INSPECT_FORMAT = (
    "{{.Id}}\t{{.Image}}\t{{.Config.Image}}\t{{.State.Status}}\t"
    "{{index .Config.Labels \"com.docker.compose.project\"}}\t"
    "{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}\t"
    "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}\t"
    "{{index .Config.Labels \"com.docker.compose.service\"}}"
)


def discover_docker_identity(container_name: str) -> Dict[str, Any]:
    """Only the specific fields needed, via --format -- never a full
    `docker inspect` JSON dump (which includes Config.Env and could leak
    business secrets such as database passwords configured in Compose)."""
    proc = run(["docker", "inspect", "--format", DOCKER_INSPECT_FORMAT, container_name])
    line = proc.stdout.decode("utf-8").strip()
    parts = line.split("\t")
    if len(parts) != 8:
        raise Blocker("docker inspect --format for %s returned an unexpected shape -- refusing to parse" % container_name)
    container_id, image_id, image_ref, state, compose_project, compose_working_dir, compose_config_files, compose_service = parts
    return {
        "id": container_id,
        "image": image_id,
        "image_ref": image_ref or None,
        "state": state,
        "compose_project": compose_project or None,
        "compose_working_dir": compose_working_dir or None,
        "compose_config_files": compose_config_files or None,
        "compose_service": compose_service or None,
    }


def discover_docker_image_id_for_ref(image_ref: str) -> str:
    proc = run(["docker", "image", "inspect", "--format", "{{.Id}}", image_ref])
    return proc.stdout.decode("utf-8").strip()


def _uid_to_username(uid: int) -> Optional[str]:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return None


def discover_native_identity(service_name: str) -> Dict[str, Any]:
    proc = run(["systemctl", "show", service_name, "-p", "MainPID,ActiveState,SubState,User,Group"])
    props = {}
    for line in proc.stdout.decode("utf-8").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
    main_pid = props.get("MainPID", "0")
    if main_pid in ("0", ""):
        raise Blocker("systemd service %s has no MainPID (ActiveState=%s) -- cannot discover live binary path, refusing to guess" % (service_name, props.get("ActiveState")))
    exe_link = "/proc/%s/exe" % main_pid
    try:
        binary_path = os.path.realpath(exe_link)
    except OSError as exc:
        raise Blocker("cannot resolve %s: %s" % (exe_link, exc))
    if not binary_path or binary_path == exe_link:
        raise Blocker("could not resolve live binary path for %s via %s" % (service_name, exe_link))

    # Live OS account the process actually runs as -- the systemd unit's
    # configured User=/Group= directives are a declaration, not proof; read
    # the real /proc/<pid>/status Uid/Gid lines for ground truth.
    try:
        with open("/proc/%s/status" % main_pid, "r", encoding="utf-8") as f:
            status_text = f.read()
    except OSError as exc:
        raise Blocker("cannot read /proc/%s/status: %s" % (main_pid, exc))
    live_uid = None
    live_gid = None
    for line in status_text.splitlines():
        if line.startswith("Uid:"):
            live_uid = int(line.split()[1])
        elif line.startswith("Gid:"):
            live_gid = int(line.split()[1])
    live_user = _uid_to_username(live_uid) if live_uid is not None else None

    return {
        "main_pid": main_pid,
        "active_state": props.get("ActiveState"),
        "sub_state": props.get("SubState"),
        "binary_path": binary_path,
        "live_uid": live_uid,
        "live_gid": live_gid,
        "live_user": live_user,
        "unit_declared_user": props.get("User") or None,
        "unit_declared_group": props.get("Group") or None,
    }


def verify_native_service_account(live: Dict[str, Any], profile_native: Dict[str, Any]) -> None:
    expected_user = profile_native["service_user"]
    live_user = live.get("live_user")
    if live_user != expected_user:
        raise Blocker(
            "live sub2api.service process runs as OS user %r (uid=%s) but approved profile "
            "native.service_user is %r -- refusing to trust an account mismatch"
            % (live_user, live.get("live_uid"), expected_user)
        )


def capture_native_version(binary_path: str) -> str:
    proc = run([binary_path, "--version"], check=False, timeout=10)
    combined = (proc.stdout + proc.stderr).decode("utf-8", errors="replace").strip()
    return combined


# ---------------------------------------------------------------------------
# PostgreSQL access. gateway3's Postgres is a dedicated, unpublished Docker
# container with no host-reachable socket or port -- it must be reached via
# `docker exec` as the profile-bound in-container OS user. sub2api3's
# Postgres is a real native OS service reachable via a local peer-auth
# connection as the profile-bound OS user (never root, never a password).
# Only this one real transport (local socket, two routes) is implemented --
# no generic/unneeded TCP path.
#
# `docker exec` by default inherits the TARGET CONTAINER's own image/env
# configuration (e.g. a postgres image's baked-in POSTGRES_PASSWORD-derived
# env, or a .pgpass file inside the container) -- NOT the host's
# environment. A clean host-side env dict is therefore not sufficient by
# itself for the docker-exec route: the command line run INSIDE the
# container must also start with `env -i <explicit safe vars>` so psql/
# pg_dump see nothing from the container's own ambient environment either.
# PGPASSFILE=/dev/null always; no .pgpass, PGPASSWORD, or PGSERVICE is ever
# consulted, on either route.
# ---------------------------------------------------------------------------

_CLEAN_ENV_PREFIX = ["env", "-i", "PATH=/usr/local/bin:/usr/bin:/bin", "PGPASSFILE=/dev/null", "PGCONNECT_TIMEOUT=10", "LC_ALL=C"]


def psql_command(db: Dict[str, Any]) -> List[str]:
    return ["psql", "-X", "-v", "ON_ERROR_STOP=1", "--no-password", "-U", db["user"], "-d", db["dbname"]]


def wrap_db_command(db: Dict[str, Any], inner_argv: List[str]) -> Tuple[List[str], Optional[Dict[str, str]]]:
    """Returns (argv, host_env). The in-container/in-session environment is
    ALWAYS wiped to an explicit safe set via `env -i ...` regardless of
    route; host_env is additionally used for the native (runuser) route
    since that one executes directly in the host process tree."""
    if "docker_exec_container" in db:
        argv = ["docker", "exec", "-u", db["docker_exec_user"], db["docker_exec_container"]] + _CLEAN_ENV_PREFIX + inner_argv
        return argv, None
    argv = ["runuser", "-u", db["os_user"], "--"] + _CLEAN_ENV_PREFIX + inner_argv
    return argv, clean_pg_env()


def run_psql(db: Dict[str, Any], sql: str) -> str:
    argv, env = wrap_db_command(db, psql_command(db) + ["-Atqc", sql])
    proc = run(argv, env=env)
    return proc.stdout.decode("utf-8")


def read_schema_migrations_ledger(db: Dict[str, Any]) -> Dict[str, str]:
    out = run_psql(db, "SELECT filename, checksum FROM schema_migrations ORDER BY filename")
    ledger = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or "|" not in line:
            continue
        fname, csum = line.split("|", 1)
        ledger[fname.strip()] = csum.strip()
    return ledger


def db_identification(db: Dict[str, Any]) -> Dict[str, Any]:
    out = run_psql(db, "SELECT current_database(), current_user, pg_postmaster_start_time()").strip()
    line = out.splitlines()[0] if out else ""
    parts = line.split("|")
    return {
        "database": parts[0] if len(parts) > 0 else None,
        "role": parts[1] if len(parts) > 1 else None,
        "postmaster_start_time": parts[2] if len(parts) > 2 else None,
    }


def safe_backup_filename(db: Dict[str, Any], target: str, run_id: str) -> str:
    prefix = db["backup_name_prefix"]
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    run_token = re.sub(r"[^A-Za-z0-9]", "", run_id)[:12] or "run"
    target_token = re.sub(r"[^A-Za-z0-9_-]", "", target)[:32] or "target"
    # pg_dump custom format (-Fc), already compressed internally -- no
    # Python-side gzip streaming/looping needed.
    name = "%s-%s-%s-%s.dump" % (prefix, target_token, stamp, run_token)
    max_len = min(db.get("max_backup_name_length", 128), MAX_BACKUP_NAME_LENGTH_CEILING)
    if len(name) > max_len:
        raise Blocker("computed backup filename length %d exceeds bound %d -- refusing to write an unbounded name" % (len(name), max_len))
    if not SAFE_TOKEN_RE.match(name.replace(".dump", "").replace("-", "")):
        raise Blocker("computed backup filename failed safe-character validation: %r" % name)
    return name


def pg_dump_command(db: Dict[str, Any]) -> List[str]:
    return ["pg_dump", "--no-password", "-U", db["user"], "-d", db["dbname"], "-F", "c", "-Z", "6"]


def take_postgres_backup(db: Dict[str, Any], target: str, run_id: str) -> Dict[str, Any]:
    """Boring and deadlock-free: pg_dump's custom-format, already-compressed
    output is written DIRECTLY to our 0600-from-creation file via stdout
    redirection (the OS handles the buffering, not a Python read loop), and
    stderr goes to a real temp file (never a fixed-size PIPE that can fill
    and block pg_dump while we're busy elsewhere) so there is no deadlock
    window. A single bounded subprocess.run() covers the whole operation."""
    backup_dir = db["backup_dir"]
    bst = os.stat(backup_dir) if os.path.isdir(backup_dir) else None
    if bst is None:
        raise Blocker("database.backup_dir %s does not exist on target -- must be provisioned root:root by operators" % backup_dir)
    if bst.st_uid != 0 or (bst.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        raise Blocker("database.backup_dir %s is not root-owned/root-writable-only (mode=%o uid=%d) -- refusing to write backups there" % (backup_dir, stat.S_IMODE(bst.st_mode), bst.st_uid))

    fname = safe_backup_filename(db, target, run_id)
    final_path = os.path.join(backup_dir, fname)
    tmp_path = final_path + ".partial"
    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    dump_argv, env = wrap_db_command(db, pg_dump_command(db))
    log("taking postgres backup (pg_dump -Fc) -> %s" % final_path)

    out_f = open_private(tmp_path, 0o600)
    stderr_f = tempfile.TemporaryFile()
    try:
        proc = subprocess.run(dump_argv, stdout=out_f, stderr=stderr_f, env=env, timeout=3600)
    finally:
        out_f.close()
    stderr_f.seek(0)
    stderr_tail = stderr_f.read().decode(errors="replace")[-2000:]
    stderr_f.close()

    if proc.returncode != 0:
        os.remove(tmp_path)
        raise DeployFailure("pg_dump failed (%d): %s" % (proc.returncode, stderr_tail))

    total_bytes = os.path.getsize(tmp_path)
    if total_bytes < 32:
        os.remove(tmp_path)
        raise DeployFailure("pg_dump output suspiciously small (%d bytes) -- refusing to treat as a valid backup" % total_bytes)

    verify_backup_listable(tmp_path)

    os.replace(tmp_path, final_path)
    sha = sha256_file(final_path)
    size = os.path.getsize(final_path)
    log("postgres backup complete: %s (%d bytes, sha256=%s)" % (final_path, size, sha))
    return {"path": final_path, "sha256": sha, "size": size, "db": db_identification(db)}


def verify_backup_listable(path: str) -> None:
    """Best-effort structural validity check: pg_restore --list reads only
    the archive's table-of-contents, no DB connection needed. Runs with a
    local (host) pg_restore binary if one happens to be present; if not
    present, this is skipped (not every host has postgresql-client tools
    installed, e.g. the gateway3 Docker host itself) -- but if pg_restore
    IS present and reports the archive as unreadable/corrupt, that is a
    hard failure, never silently ignored."""
    pg_restore = shutil.which("pg_restore")
    if not pg_restore:
        log("pg_restore not found on PATH -- skipping optional backup structural validity check")
        return
    proc = subprocess.run([pg_restore, "--list", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if proc.returncode != 0:
        raise DeployFailure("pg_restore --list reports the just-written backup archive as invalid: %s" % proc.stderr.decode(errors="replace")[-1000:])


# ---------------------------------------------------------------------------
# State file -- bounds the preflight -> stage -> activate sequence to one
# coherent run, root-only, under --state-dir. Binds to a digest of BOTH the
# manifest and the approved profile so neither can silently change
# underneath a multi-stage run; every stage re-hashes both and compares.
# ---------------------------------------------------------------------------

def state_path(state_dir: str, target: str) -> str:
    return os.path.join(state_dir, "%s.run-state.json" % target)


def write_state(state_dir: str, target: str, state: Dict[str, Any]) -> None:
    os.makedirs(state_dir, exist_ok=True)
    os.chmod(state_dir, 0o700)
    path = state_path(state_dir, target)
    tmp = path + ".tmp"
    if os.path.exists(tmp):
        os.remove(tmp)
    state["written_at"] = time.time()
    out_f = open_private(tmp, 0o600)
    try:
        out_f.write(json.dumps(state, indent=2, sort_keys=True).encode("utf-8"))
    finally:
        out_f.close()
    os.replace(tmp, path)


def read_state(state_dir: str, target: str, run_id: str, require_stage: str,
                manifest_digest: str, profile_digest: str) -> Dict[str, Any]:
    path = state_path(state_dir, target)
    if not os.path.isfile(path):
        raise Blocker("no deploy state found at %s -- run 'preflight' first" % path)
    st = os.stat(path)
    if st.st_uid != 0 or (st.st_mode & (stat.S_IRWXG | stat.S_IRWXO)):
        raise Blocker("state file %s has unsafe ownership/permissions -- refusing to trust it" % path)
    with open(path, "r", encoding="utf-8") as f:
        state = json.load(f)
    if state.get("run_id") != run_id:
        raise Blocker("--run-id %r does not match in-progress run %r recorded at %s -- refusing to continue a mismatched sequence" % (run_id, state.get("run_id"), path))
    if state.get("stage") != require_stage:
        raise Blocker("expected previous stage %r to be complete, but recorded stage is %r -- stages must run in order (preflight -> stage -> activate)" % (require_stage, state.get("stage")))
    age = time.time() - state.get("written_at", 0)
    if age > STATE_FRESHNESS_SECONDS:
        raise Blocker("recorded state for run %r is %.0fs old (bound is %ds) -- refusing to continue a stale sequence; re-run preflight" % (run_id, age, STATE_FRESHNESS_SECONDS))
    if state.get("manifest_digest") != manifest_digest:
        raise Blocker("the release bundle's manifest.json has changed since preflight (digest mismatch) -- refusing to continue with a different artifact than was verified")
    if state.get("profile_digest") != profile_digest:
        raise Blocker("the approved deployment profile has changed on disk since preflight (digest mismatch) -- refusing to continue; re-run preflight against the new profile")
    return state


# ---------------------------------------------------------------------------
# Migration compatibility gate. This is a hard gate, never a warning. It
# checks BOTH directions: every bundle migration must be either already
# applied with a matching checksum or explicitly profile-approved as
# pending, AND every already-applied ledger filename must appear in the
# bundle at all -- an applied filename the bundle doesn't know about means
# the target is running a NEWER schema than this release, i.e. this would
# be a silent downgrade, which is always rejected.
# ---------------------------------------------------------------------------

def gate_migrations(bundle_migrations: List[Dict[str, Any]], ledger: Dict[str, str], profile_approved: Dict[str, str]) -> Tuple[List[str], List[str]]:
    bundle_filenames = set(entry["filename"] for entry in bundle_migrations)
    downgrade = sorted(set(ledger.keys()) - bundle_filenames)
    if downgrade:
        raise DeployFailure(
            "target has migration(s) already applied that are NOT present in this release bundle "
            "(%s) -- deploying this bundle would be a downgrade relative to the target's current "
            "schema; refusing" % ", ".join(downgrade)
        )

    already_ok: List[str] = []
    pending_ok: List[str] = []
    for entry in bundle_migrations:
        fname = entry["filename"]
        recomputed = entry["sha256"]
        if fname in ledger:
            if ledger[fname] != recomputed:
                raise DeployFailure(
                    "migration %s is already applied on target with checksum %s but the release "
                    "bundle's recomputed applied-checksum is %s -- this means either the migration "
                    "file was modified after being applied, or this bundle targets an incompatible "
                    "baseline; refusing to touch the target" % (fname, ledger[fname], recomputed)
                )
            already_ok.append(fname)
        else:
            approved_csum = profile_approved.get(fname)
            if approved_csum is None:
                raise Blocker(
                    "migration %s is not yet applied on target and has NO entry in the approved "
                    "deployment profile's migrations.approved_new_migration_hashes -- new/changed "
                    "SQL migrations require an explicit approved hash plus a valid backup receipt; "
                    "this is a hard operational blocker, not a default" % fname
                )
            if approved_csum != recomputed:
                raise Blocker(
                    "migration %s profile-approved checksum (%s) does not match the bundle's "
                    "independently recomputed applied-checksum (%s) -- refusing to treat as approved"
                    % (fname, approved_csum, recomputed)
                )
            pending_ok.append(fname)
    return already_ok, pending_ok


def verify_pending_migrations_applied(db: Dict[str, Any], prev: Dict[str, Any]) -> None:
    """Health is not schema proof: require the complete expected final ledger,
    including unchanged baseline rows, even when no migration was pending.
    """
    expected = dict(prev["baseline_ledger"])
    expected.update(prev.get("migrations_pending_hashes") or {})
    try:
        ledger_now = read_schema_migrations_ledger(db)
    except (DeployFailure, Blocker) as exc:
        raise DeployFailure("post-activation migration ledger could not be verified: %s" % exc)
    if ledger_now != expected:
        raise DeployFailure("post-activation migration ledger does not match the complete approved release schema; refusing to declare success")



def ledger_matches_baseline(db: Dict[str, Any], prev: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
    """Re-reads the live migration ledger and requires it to be EXACTLY
    the baseline captured at preflight. Called immediately before any
    automatic rollback decision (not just once at the top of 'activate'):
    real wall-clock time (the failed `up`/`swap_in` attempt, the health
    poll timeout) has passed since the top-of-activate check, during which
    an unrelated/concurrent migration could have landed, or this run's own
    failed start could have partially applied something even though it
    was predicted not to. A DB read failure is treated the same as a
    mismatch: never safe to proceed with an automatic rollback when the
    schema state is unknown. Returns (matches, error_message_or_None)."""
    try:
        current = read_schema_migrations_ledger(db)
    except (DeployFailure, Blocker) as exc:
        return False, "could not re-read schema_migrations ledger before the planned rollback: %s" % exc
    baseline = prev.get("baseline_ledger")
    if current != baseline:
        return False, (
            "schema_migrations ledger no longer matches the preflight baseline immediately before "
            "the planned rollback (current=%r, baseline=%r)" % (sorted(current.keys()), sorted((baseline or {}).keys()))
        )
    return True, None


# ---------------------------------------------------------------------------
# Health polling -- local-only, bounded, no redirects, no response body ever
# echoed into logs/JSON output.
# ---------------------------------------------------------------------------

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


# Explicitly empty ProxyHandler({}) overrides urllib's default behavior of
# reading HTTP_PROXY/http_proxy (and friends) from the environment -- a
# "local-only" health check to 127.0.0.1 must never be routed through an
# ambient proxy, which would defeat the whole point of the loopback check
# and could leak it externally.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def poll_health(url: str, timeout_seconds: float) -> Dict[str, Any]:
    validate_local_health_url(url)  # re-validate at the point of use too
    deadline = time.time() + timeout_seconds
    last_error = None
    while time.time() < deadline:
        try:
            req = urllib.request.Request(url, method="GET")
            with _NO_REDIRECT_OPENER.open(req, timeout=HEALTH_POLL_INTERVAL_SECONDS) as resp:
                resp.read(2048)  # drain without retaining/echoing body content
                if resp.status == 200:
                    return {"ok": True, "status": resp.status}
                last_error = "status=%d" % resp.status
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last_error = type(exc).__name__
        time.sleep(HEALTH_POLL_INTERVAL_SECONDS)
    return {"ok": False, "error": last_error}


# ---------------------------------------------------------------------------
# Compose override -- ACTIVATE time only. Never written during preflight or
# stage. Preserves every discovered compose config file; only ever creates
# or updates an override this tool itself owns (marked), and fails closed
# rather than clobbering an operator's pre-existing, unrelated override.
# ---------------------------------------------------------------------------

def discover_compose_config_files(compose_working_dir: str, labels_config_files: Optional[str]) -> List[str]:
    if not labels_config_files:
        raise Blocker(
            "live container has no com.docker.compose.project.config_files label -- cannot "
            "determine the real compose file set without guessing; refusing to invent a default "
            "docker-compose.yml path"
        )
    files = [f.strip() for f in labels_config_files.split(",") if f.strip()]
    if not files:
        raise Blocker("com.docker.compose.project.config_files label was empty after parsing")
    resolved = []
    for f in files:
        resolved.append(f if os.path.isabs(f) else os.path.join(compose_working_dir, f))
    return resolved


def resolve_or_create_override_path(config_files: List[str], compose_working_dir: str) -> Tuple[str, bool]:
    """Returns (override_path, already_existed_and_tool_owned). If a
    previously-discovered config file is already tool-owned (has our
    marker), reuse it. If the LAST config file in the discovered list does
    not exist yet, that's the natural place Compose would look for an
    override on this project (Compose auto-appends
    docker-compose.override.yml when present) -- we only create a NEW file
    there, never overwrite an existing file we don't already own."""
    for path in config_files:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                head = f.read(200)
            if COMPOSE_OVERRIDE_MARKER in head:
                return path, True
    candidate = os.path.join(compose_working_dir, "docker-compose.override.yml")
    if candidate in config_files:
        # Labels already reference it but it doesn't exist / isn't ours per
        # the loop above -- treat as unowned-but-absent, safe to create.
        return candidate, False
    if os.path.exists(candidate):
        raise Blocker(
            "a docker-compose.override.yml already exists at %s but is NOT referenced by the "
            "live container's compose config_files label and does not carry this tool's "
            "ownership marker -- refusing to clobber an operator-owned file; the compose project "
            "must be reloaded with this override included, or the override removed/approved "
            "manually first" % candidate
        )
    return candidate, False


def write_compose_image_override(override_path: str, service: str, image_ref: str) -> None:
    content = (
        "%s\n"
        "# Written by scripts/ci/remote_deploy.py at ACTIVATE time only -- pins the deployed\n"
        "# image so future `docker compose up -d` invocations in this directory do not silently\n"
        "# revert to an older image reference. Safe to version-control.\n"
        "services:\n"
        "  %s:\n"
        "    image: %s\n" % (COMPOSE_OVERRIDE_MARKER, service, image_ref)
    )
    tmp = override_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(content)
    os.replace(tmp, override_path)


# ---------------------------------------------------------------------------
# Stage implementations
# ---------------------------------------------------------------------------

def cmd_preflight(args: argparse.Namespace) -> int:
    require_root()
    target, kind, bundle_dir = args.target, args.kind, args.bundle

    profile, profile_digest = load_approved_profile(target, kind)
    manifest, manifest_digest = load_manifest(bundle_dir)
    verify_bundle_files(bundle_dir, manifest)
    load_and_verify_qualification(bundle_dir, manifest)
    bundle_migrations = classify_migrations(bundle_dir, manifest)

    baseline: Dict[str, Any] = {}
    if kind == "docker":
        live = discover_docker_identity(profile["docker"]["container_name"])
        if live.get("compose_working_dir") != profile["docker"]["compose_project_dir"]:
            raise Blocker("live container compose working_dir (%r) does not match profile.docker.compose_project_dir (%r)" % (live.get("compose_working_dir"), profile["docker"]["compose_project_dir"]))
        if live.get("compose_service") != profile["docker"]["compose_service"]:
            raise Blocker("live container compose service (%r) does not match profile.docker.compose_service (%r)" % (live.get("compose_service"), profile["docker"]["compose_service"]))
        baseline["docker"] = live
        # Cross-check the profile-bound Postgres exec target actually
        # exists and is a distinct, verified container (never the app
        # container itself).
        if profile["database"]["docker_exec_container"] == profile["docker"]["container_name"]:
            raise Blocker("database.docker_exec_container must not be the same container as docker.container_name")
        run(["docker", "inspect", "--format", "{{.Id}}", profile["database"]["docker_exec_container"]])
    else:
        live = discover_native_identity(profile["native"]["service_name"])
        if live["binary_path"] != profile["native"]["binary_path"]:
            raise Blocker(
                "live service binary path (%s, discovered via MainPID %s -> /proc/.../exe) does not "
                "match approved profile native.binary_path (%s) -- refusing to guess or trust an "
                "unverified install path" % (live["binary_path"], live["main_pid"], profile["native"]["binary_path"])
            )
        verify_native_service_account(live, profile["native"])
        live["version_output"] = capture_native_version(live["binary_path"])
        baseline["native"] = live

    ledger = read_schema_migrations_ledger(profile["database"])
    already_ok, pending_ok = gate_migrations(bundle_migrations, ledger, profile["migrations"]["approved_new_migration_hashes"])
    migrations_applied_this_run = len(pending_ok) > 0

    state = {
        "run_id": args.run_id,
        "target": target,
        "kind": kind,
        "stage": "preflight",
        "bundle": os.path.realpath(bundle_dir),
        "manifest_digest": manifest_digest,
        "profile_digest": profile_digest,
        "manifest_sha": manifest["sha"],
        "manifest_tag": manifest["tag"],
        "manifest_binary_sha256": manifest["binary_sha256"],
        "manifest_image_id": manifest["image_id"],
        "baseline": baseline,
        "baseline_ledger": ledger,
        "migrations_already_applied_ok": already_ok,
        "migrations_pending_approved": pending_ok,
        "migrations_pending_hashes": dict((e["filename"], e["sha256"]) for e in bundle_migrations if e["filename"] in pending_ok),
        "migrations_applied_this_run": migrations_applied_this_run,
        "db_identification": db_identification(profile["database"]),
    }
    write_state(args.state_dir, target, state)
    log("preflight OK: target=%s kind=%s already_applied=%d pending_approved=%d migrations_applied_this_run=%s" %
        (target, kind, len(already_ok), len(pending_ok), migrations_applied_this_run))
    emit_result({"stage": "preflight", "ok": True, "target": target, "pending_migrations": pending_ok})
    return EXIT_OK


def cmd_stage(args: argparse.Namespace) -> int:
    require_root()
    target, kind, bundle_dir = args.target, args.kind, args.bundle
    profile, profile_digest = load_approved_profile(target, kind)
    manifest, manifest_digest = load_manifest(bundle_dir)
    prev = read_state(args.state_dir, target, args.run_id, require_stage="preflight",
                       manifest_digest=manifest_digest, profile_digest=profile_digest)
    verify_bundle_files(bundle_dir, manifest)

    if kind == "docker":
        live = discover_docker_identity(profile["docker"]["container_name"])
        if live["id"] != prev["baseline"]["docker"]["id"]:
            raise Blocker("live container id changed since preflight (%s -> %s) -- a concurrent deploy may be in progress; aborting" % (prev["baseline"]["docker"]["id"], live["id"]))
    else:
        live = discover_native_identity(profile["native"]["service_name"])
        if live["main_pid"] != prev["baseline"]["native"]["main_pid"]:
            raise Blocker("live service MainPID changed since preflight (%s -> %s) -- a concurrent restart may have occurred; aborting" % (prev["baseline"]["native"]["main_pid"], live["main_pid"]))

    backup_receipt = take_postgres_backup(profile["database"], target, args.run_id)

    staged: Dict[str, Any] = {}
    if kind == "docker":
        tar_path = os.path.join(bundle_dir, "sub2api-image.tar")
        run(["docker", "load", "--input", tar_path])
        repo_tag = parse_image_repo_tag_from_tar(tar_path)
        loaded_id = discover_docker_image_id_for_ref(repo_tag)
        if loaded_id != manifest["image_id"]:
            raise DeployFailure("loaded docker image id (%s) does not match manifest.image_id (%s) for tag %s" % (loaded_id, manifest["image_id"], repo_tag))
        staged["docker"] = {"repo_tag": repo_tag, "image_id": loaded_id}
    else:
        live_binary = prev["baseline"]["native"]["binary_path"]
        stage_dir = os.path.join(os.path.dirname(live_binary), ".sub2api-staged-%s" % args.run_id[:12])
        if os.path.exists(stage_dir):
            shutil.rmtree(stage_dir)
        os.makedirs(stage_dir, mode=0o700)
        live_st = os.stat(live_binary)
        staged_binary = os.path.join(stage_dir, "sub2api")
        shutil.copyfile(os.path.join(bundle_dir, "sub2api"), staged_binary)
        os.chmod(staged_binary, stat.S_IMODE(live_st.st_mode))
        os.chown(staged_binary, live_st.st_uid, live_st.st_gid)
        actual_sha = sha256_file(staged_binary)
        if actual_sha != manifest["binary_sha256"]:
            raise DeployFailure("staged binary sha256 (%s) does not match manifest.binary_sha256 (%s)" % (actual_sha, manifest["binary_sha256"]))
        staged["native"] = {"stage_dir": stage_dir, "staged_binary": staged_binary, "live_binary": live_binary,
                             "owner_uid": live_st.st_uid, "owner_gid": live_st.st_gid, "mode": oct(stat.S_IMODE(live_st.st_mode))}
        resources_dir = profile["native"].get("resources_dir")
        if resources_dir and os.path.isdir(resources_dir):
            staged_resources = os.path.join(stage_dir, "resources")
            shutil.copytree(os.path.join(bundle_dir, "resources"), staged_resources)
            res_st = os.stat(resources_dir)
            for root, dirnames, filenames in os.walk(staged_resources):
                for name in dirnames + filenames:
                    os.chown(os.path.join(root, name), res_st.st_uid, res_st.st_gid)
            os.chown(staged_resources, res_st.st_uid, res_st.st_gid)
            staged["native"]["staged_resources"] = staged_resources
            staged["native"]["live_resources"] = resources_dir

    prev.update({
        "stage": "stage",
        "manifest_digest": manifest_digest,
        "profile_digest": profile_digest,
        "backup_receipt": backup_receipt,
        "staged": staged,
    })
    write_state(args.state_dir, target, prev)
    log("stage OK: target=%s backup=%s" % (target, backup_receipt["path"]))
    emit_result({"stage": "stage", "ok": True, "target": target,
                 "backup_receipt": {"path": backup_receipt["path"], "sha256": backup_receipt["sha256"], "size": backup_receipt["size"]}})
    return EXIT_OK


def parse_image_repo_tag_from_tar(tar_path: str) -> str:
    """Reads the RepoTags recorded inside a `docker save` tar without
    needing the image already loaded -- used to know what tag `docker load`
    just registered."""
    import tarfile
    with tarfile.open(tar_path, mode="r") as tf:
        member = tf.getmember("manifest.json")
        f = tf.extractfile(member)
        if f is None:
            raise DeployFailure("sub2api-image.tar has no readable manifest.json entry")
        data = json.loads(f.read().decode("utf-8"))
    if not data or not data[0].get("RepoTags"):
        raise DeployFailure("sub2api-image.tar manifest.json has no RepoTags")
    return data[0]["RepoTags"][0]


def cmd_activate(args: argparse.Namespace) -> int:
    require_root()
    target, kind, bundle_dir = args.target, args.kind, args.bundle
    profile, profile_digest = load_approved_profile(target, kind)
    manifest, manifest_digest = load_manifest(bundle_dir)
    verify_bundle_files(bundle_dir, manifest)

    prev = read_state(args.state_dir, target, args.run_id, require_stage="stage",
                       manifest_digest=manifest_digest, profile_digest=profile_digest)

    backup_receipt = prev["backup_receipt"]
    if not os.path.isfile(backup_receipt["path"]) or sha256_file(backup_receipt["path"]) != backup_receipt["sha256"]:
        raise Blocker("backup receipt at %s is missing or no longer matches its recorded sha256 -- refusing to activate without a verified backup" % backup_receipt["path"])

    migrations_applied_this_run = bool(prev.get("migrations_applied_this_run"))
    health_cfg = profile["health"]

    # Re-read the live migration ledger ONE more time, immediately before
    # any mutation, and require it to be EXACTLY what preflight observed
    # (same filenames, same checksums, nothing added or removed). A DB
    # read failure, or ANY drift -- even if this release's own pending
    # list was empty -- means something changed the schema outside this
    # run's knowledge; that is never safe to blindly proceed past, so it
    # is ALWAYS treated as manual-intervention, unconditionally, before
    # any mutation is even attempted.
    ledger_ok, ledger_err = ledger_matches_baseline(profile["database"], prev)
    if not ledger_ok:
        prev.update({"stage": "activate", "result": {
            "exit_code": EXIT_MANUAL_INTERVENTION, "activated": False, "rollback_attempted": False,
            "reason": "%s -- refusing to activate; this indicates a concurrent or unknown migration "
                      "occurred and requires manual review, never a blind proceed or automatic "
                      "rollback" % ledger_err,
            "backup_receipt": backup_receipt,
        }})
        write_state(args.state_dir, target, prev)
        emit_result({"stage": "activate", "target": target, "result": prev["result"]})
        return EXIT_MANUAL_INTERVENTION

    try:
        if kind == "docker":
            result = activate_docker(profile, prev, migrations_applied_this_run, health_cfg)
        else:
            result = activate_native(profile, prev, migrations_applied_this_run, health_cfg)
    except (DeployFailure, Blocker, subprocess.SubprocessError, OSError) as exc:
        # ANY exception raised during the mutation/verification window must
        # still result in captured diagnostics and the correct
        # rollback/manual-intervention decision -- never an uncaught
        # traceback that skips both. Do NOT blindly trust the static
        # migrations_applied_this_run prediction here: re-check the live
        # ledger one more time; if it can't be confirmed unchanged (read
        # failure or drift), the schema state is UNKNOWN and that alone
        # forces manual intervention regardless of what this release
        # predicted at preflight.
        ledger_ok, _ledger_err = ledger_matches_baseline(profile["database"], prev)
        result = {
            "exit_code": EXIT_MANUAL_INTERVENTION if (migrations_applied_this_run or not ledger_ok) else EXIT_FAILURE,
            "activated": False,
            "rollback_attempted": False,
            "reason": "unexpected exception during activation: %s: %s" % (type(exc).__name__, exc),
            "backup_receipt": backup_receipt,
        }

    prev.update({"stage": "activate", "result": result})
    write_state(args.state_dir, target, prev)
    emit_result({"stage": "activate", "target": target, "result": result})
    return result["exit_code"]


def activate_docker(profile: Dict[str, Any], prev: Dict[str, Any], migrations_applied_this_run: bool, health_cfg: Dict[str, Any]) -> Dict[str, Any]:
    d = profile["docker"]
    staged = prev["staged"]["docker"]
    baseline = prev["baseline"]["docker"]

    # Re-discover live identity ONE more time, immediately before mutating,
    # to catch any drift since 'stage' (contract: recheck baseline/ledger
    # immediately before activation).
    live_now = discover_docker_identity(d["container_name"])
    if live_now["id"] != baseline["id"]:
        raise Blocker("live container id changed since staging (%s -> %s) -- a concurrent deploy may have occurred; aborting before any mutation" % (baseline["id"], live_now["id"]))

    config_files = discover_compose_config_files(baseline["compose_working_dir"], live_now.get("compose_config_files"))
    override_path, _owned = resolve_or_create_override_path(config_files, baseline["compose_working_dir"])

    # Pin the staged image's identity ONE more time immediately before the
    # `up` call -- defense against anything retagging staged["repo_tag"]
    # between 'stage' and 'activate'.
    pre_up_id = discover_docker_image_id_for_ref(staged["repo_tag"])
    if pre_up_id != staged["image_id"]:
        raise DeployFailure(
            "staged image tag %s now resolves to %s, not the pinned %s captured at stage time -- "
            "refusing to activate against a drifted image reference" % (staged["repo_tag"], pre_up_id, staged["image_id"])
        )

    write_compose_image_override(override_path, d["compose_service"], staged["repo_tag"])
    compose_f_args = []
    for cf in config_files:
        compose_f_args += ["-f", cf]
    if override_path not in config_files:
        compose_f_args += ["-f", override_path]
    compose_argv = ["docker", "compose", "--project-directory", d["compose_project_dir"]] + compose_f_args

    up_argv = compose_argv + ["up", "-d", "--no-deps", "--pull", "never", d["compose_service"]]
    run(up_argv)

    health = poll_health(health_cfg["url"], health_cfg["timeout_seconds"])
    live_after = discover_docker_identity(d["container_name"])
    # Artifact identity is the IMAGE id, never the (mutable) container id or
    # a tag string.
    sha_ok = live_after["image"] == staged["image_id"]

    if health.get("ok") and sha_ok:
        verify_pending_migrations_applied(profile["database"], prev)
        return {
            "exit_code": EXIT_OK,
            "activated": True,
            "compose_invocation": up_argv,
            "override_path": override_path,
            "image_id": live_after["image"],
            "health": health,
        }

    failure_detail = {"health": health, "sha_ok": sha_ok, "expected_image_id": staged["image_id"], "live_image_id": live_after["image"]}

    if migrations_applied_this_run:
        return {
            "exit_code": EXIT_MANUAL_INTERVENTION,
            "activated": False,
            "rollback_attempted": False,
            "reason": "activation health/SHA check failed AFTER migrations may have been applied by the new binary's startup migrator; automatic binary rollback against a changed schema is unsafe and was not attempted",
            "failure_detail": failure_detail,
            "backup_receipt": prev["backup_receipt"],
            "compose_invocation": up_argv,
        }

    # No migrations were applied this run -- a deterministic rollback to
    # the pre-existing baseline image MAY be safe, but only if the schema
    # is still exactly what preflight observed. Real wall-clock time has
    # passed (the failed `up` call, the health poll timeout) during which
    # an unrelated/concurrent migration could have landed, so this is
    # re-verified HERE, immediately before the rollback attempt, not
    # assumed from the static migrations_applied_this_run prediction.
    ledger_ok, ledger_err = ledger_matches_baseline(profile["database"], prev)
    if not ledger_ok:
        return {
            "exit_code": EXIT_MANUAL_INTERVENTION,
            "activated": False,
            "rollback_attempted": False,
            "reason": "%s -- refusing to attempt an automatic rollback against an unknown/changed schema state; manual review required" % ledger_err,
            "failure_detail": failure_detail,
            "backup_receipt": prev["backup_receipt"],
        }

    # Roll back to the pre-existing baseline image, PROVIDED we actually
    # know its IMMUTABLE id. Rather than trusting the baseline's mutable
    # tag reference (which could have been reassigned to a different image
    # behind our back between preflight and now), we `docker tag` the
    # captured baseline IMAGE ID into a tool-owned, run-scoped tag FIRST,
    # verify that tag actually resolves to the pinned id, and only then
    # point compose at that deterministic tag -- compose is never started
    # against a possibly-wrong artifact.
    baseline_image_id = baseline["image"]
    if not baseline_image_id:
        return {
            "exit_code": EXIT_FAILURE,
            "activated": False,
            "rollback_attempted": False,
            "reason": "activation failed and no baseline image id was captured at preflight -- refusing to guess a rollback target",
            "failure_detail": failure_detail,
            "backup_receipt": prev["backup_receipt"],
        }
    rollback_tag = "sub2api-rollback:%s-%s" % (re.sub(r"[^a-z0-9]", "", d["container_name"].lower()), prev["run_id"][:12])
    rollback_argv = compose_argv + ["up", "-d", "--no-deps", "--pull", "never", d["compose_service"]]
    try:
        run(["docker", "tag", baseline_image_id, rollback_tag])
        tagged_id = discover_docker_image_id_for_ref(rollback_tag)
        if tagged_id != baseline_image_id:
            raise DeployFailure("docker tag of baseline image id %s as %s did not resolve back to the same id (got %s) -- refusing to start compose against an unverified artifact" % (baseline_image_id, rollback_tag, tagged_id))
        write_compose_image_override(override_path, d["compose_service"], rollback_tag)
        run(rollback_argv)
        rollback_health = poll_health(health_cfg["url"], health_cfg["timeout_seconds"])
        rollback_identity = discover_docker_identity(d["container_name"])
        rollback_image_ok = rollback_identity["image"] == baseline_image_id
    except DeployFailure as exc:
        return {
            "exit_code": EXIT_FAILURE,
            "activated": False,
            "rollback_attempted": True,
            "rollback_ok": False,
            "rollback_error": str(exc),
            "failure_detail": failure_detail,
            "backup_receipt": prev["backup_receipt"],
        }
    return {
        "exit_code": EXIT_FAILURE,
        "activated": False,
        "rollback_attempted": True,
        "rollback_ok": bool(rollback_health.get("ok")) and rollback_image_ok,
        "rollback_health": rollback_health,
        "rollback_image_id_matches_baseline": rollback_image_ok,
        "rollback_tag": rollback_tag,
        "failure_detail": failure_detail,
        "backup_receipt": prev["backup_receipt"],
    }


def _chown_tree(path: str, uid: int, gid: int) -> None:
    os.chown(path, uid, gid)
    for root, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            os.chown(os.path.join(root, name), uid, gid)


def activate_native(profile: Dict[str, Any], prev: Dict[str, Any], migrations_applied_this_run: bool, health_cfg: Dict[str, Any]) -> Dict[str, Any]:
    n = profile["native"]
    staged = prev["staged"]["native"]
    service = n["service_name"]

    # Re-discover live identity immediately before mutating, to catch any
    # drift since 'stage'.
    live_now = discover_native_identity(service)
    if live_now["main_pid"] != prev["baseline"]["native"]["main_pid"]:
        raise Blocker("live service MainPID changed since staging (%s -> %s) -- a concurrent restart may have occurred; aborting before any mutation" % (prev["baseline"]["native"]["main_pid"], live_now["main_pid"]))
    verify_native_service_account(live_now, n)

    # Baseline retained as a STABLE ".previous" path (overwritten each
    # successful deploy, not deleted) so there is always exactly one real
    # rollback artifact an operator can use manually, even after success.
    previous_binary = staged["live_binary"] + ".previous"
    previous_resources = (staged["live_resources"] + ".previous") if "staged_resources" in staged else None

    # Fresh per-run baseline copies used for THIS run's own rollback
    # decision (kept separate from the stable .previous slot so a
    # mid-sequence failure can't corrupt the last-known-good .previous).
    run_baseline_binary = staged["live_binary"] + ".baseline-%s" % os.path.basename(staged["stage_dir"])
    shutil.copyfile(staged["live_binary"], run_baseline_binary)
    shutil.copystat(staged["live_binary"], run_baseline_binary)
    run_baseline_resources = None
    if "staged_resources" in staged and os.path.isdir(staged["live_resources"]):
        run_baseline_resources = staged["live_resources"].rstrip("/") + ".baseline-%s" % os.path.basename(staged["stage_dir"])
        shutil.copytree(staged["live_resources"], run_baseline_resources)

    def swap_resources_atomically(new_resources_src: str) -> None:
        """Two back-to-back atomic renames on the same filesystem: live ->
        backup-slot, then staged -> live. Never deletes the live tree
        before the replacement exists on disk, and the new tree's
        ownership is normalized to match the original live tree's owner
        before the swap."""
        live_resources = staged["live_resources"]
        res_st = os.stat(live_resources)
        _chown_tree(new_resources_src, res_st.st_uid, res_st.st_gid)
        swap_tmp = live_resources + ".swap-out-tmp"
        if os.path.exists(swap_tmp):
            shutil.rmtree(swap_tmp)
        os.rename(live_resources, swap_tmp)
        try:
            os.rename(new_resources_src, live_resources)
        except OSError:
            os.rename(swap_tmp, live_resources)
            raise
        shutil.rmtree(swap_tmp, ignore_errors=True)

    def swap_in(binary_src: str, resources_src: Optional[str]) -> None:
        run(["systemctl", "stop", service])
        os.replace(binary_src, staged["live_binary"])
        os.chmod(staged["live_binary"], int(staged["mode"], 8))
        os.chown(staged["live_binary"], staged["owner_uid"], staged["owner_gid"])
        if resources_src and "staged_resources" in staged:
            swap_resources_atomically(resources_src)
        run(["systemctl", "start", service])

    swap_in(staged["staged_binary"], staged.get("staged_resources"))

    health = poll_health(health_cfg["url"], health_cfg["timeout_seconds"])
    live_after = discover_native_identity(service)
    actual_sha = sha256_file(live_after["binary_path"]) if os.path.isfile(live_after["binary_path"]) else None
    sha_ok = actual_sha == prev["manifest_binary_sha256"]

    if health.get("ok") and sha_ok:
        verify_pending_migrations_applied(profile["database"], prev)
        # Retain the baseline for real manual rollback: move this run's
        # fresh baseline copies into the stable .previous slot (replacing
        # whichever was there before), then clean up only the per-run temp
        # copies and the now-empty stage dir.
        if os.path.exists(previous_binary):
            os.remove(previous_binary)
        os.rename(run_baseline_binary, previous_binary)
        if run_baseline_resources and previous_resources:
            if os.path.isdir(previous_resources):
                shutil.rmtree(previous_resources)
            os.rename(run_baseline_resources, previous_resources)
        shutil.rmtree(staged["stage_dir"], ignore_errors=True)
        return {"exit_code": EXIT_OK, "activated": True, "binary_sha256": actual_sha, "health": health,
                "baseline_binary_retained_at": previous_binary, "baseline_resources_retained_at": previous_resources}

    failure_detail = {"health": health, "sha_ok": sha_ok, "expected_sha256": prev["manifest_binary_sha256"], "actual_sha256": actual_sha}

    if migrations_applied_this_run:
        return {
            "exit_code": EXIT_MANUAL_INTERVENTION,
            "activated": False,
            "rollback_attempted": False,
            "reason": "activation health/SHA check failed AFTER migrations may have been applied by the new binary's startup migrator; automatic binary rollback against a changed schema is unsafe and was not attempted",
            "failure_detail": failure_detail,
            "backup_receipt": prev["backup_receipt"],
            "baseline_binary_preserved_at": run_baseline_binary,
            "baseline_resources_preserved_at": run_baseline_resources,
        }

    ledger_ok, ledger_err = ledger_matches_baseline(profile["database"], prev)
    if not ledger_ok:
        return {
            "exit_code": EXIT_MANUAL_INTERVENTION,
            "activated": False,
            "rollback_attempted": False,
            "reason": "%s -- refusing to attempt an automatic rollback against an unknown/changed schema state; manual review required" % ledger_err,
            "failure_detail": failure_detail,
            "backup_receipt": prev["backup_receipt"],
            "baseline_binary_preserved_at": run_baseline_binary,
            "baseline_resources_preserved_at": run_baseline_resources,
        }

    try:
        restore_binary = staged["live_binary"] + ".restore-tmp"
        shutil.copyfile(run_baseline_binary, restore_binary)
        shutil.copystat(run_baseline_binary, restore_binary)
        restore_resources = None
        if run_baseline_resources:
            restore_resources = staged["stage_dir"] + "-restore-resources"
            if os.path.exists(restore_resources):
                shutil.rmtree(restore_resources)
            shutil.copytree(run_baseline_resources, restore_resources)
        swap_in(restore_binary, restore_resources)
        rollback_health = poll_health(health_cfg["url"], health_cfg["timeout_seconds"])
        rollback_live = discover_native_identity(service)
        rollback_sha = sha256_file(rollback_live["binary_path"]) if os.path.isfile(rollback_live["binary_path"]) else None
        rollback_artifact_ok = rollback_sha == sha256_file(run_baseline_binary) if os.path.isfile(run_baseline_binary) else (rollback_sha is not None)
    except (DeployFailure, OSError) as exc:
        return {
            "exit_code": EXIT_FAILURE,
            "activated": False,
            "rollback_attempted": True,
            "rollback_ok": False,
            "rollback_error": str(exc),
            "failure_detail": failure_detail,
            "backup_receipt": prev["backup_receipt"],
            "baseline_binary_preserved_at": run_baseline_binary,
            "baseline_resources_preserved_at": run_baseline_resources,
        }
    return {
        "exit_code": EXIT_FAILURE,
        "activated": False,
        "rollback_attempted": True,
        "rollback_ok": bool(rollback_health.get("ok")) and rollback_artifact_ok,
        "rollback_health": rollback_health,
        "rollback_artifact_matches_baseline": rollback_artifact_ok,
        "failure_detail": failure_detail,
        "backup_receipt": prev["backup_receipt"],
        "baseline_binary_preserved_at": run_baseline_binary,
        "baseline_resources_preserved_at": run_baseline_resources,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="remote_deploy.py",
        description="Runs ON a deploy target. Three separate, explicit stages: preflight, stage, activate. "
                     "There is no single 'deploy' command -- see module docstring.",
    )
    p.add_argument("command", choices=["preflight", "stage", "activate"])
    p.add_argument("--target", required=True, choices=["gateway3", "sub2api3"])
    p.add_argument("--kind", required=True, choices=["docker", "native"])
    p.add_argument("--bundle", default=None, help="path to the transferred bundle directory (required for preflight/stage; optional but recommended for activate)")
    p.add_argument("--run-id", required=True, help="opaque nonce binding preflight -> stage -> activate into one bounded sequence")
    p.add_argument("--state-dir", default="/var/lib/sub2api-deploy", help="root-only directory for the run-state/receipt file")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    sys.dont_write_bytecode = True
    args = build_arg_parser().parse_args(argv)
    if args.command in ("preflight", "stage") and not args.bundle:
        sys.stderr.write("error: --bundle is required for %s\n" % args.command)
        return EXIT_FAILURE
    if args.bundle:
        args.bundle = os.path.realpath(args.bundle)
    try:
        if args.command == "preflight":
            return cmd_preflight(args)
        if args.command == "stage":
            return cmd_stage(args)
        return cmd_activate(args)
    except Blocker as exc:
        log("BLOCKER: %s" % exc)
        emit_result({"stage": args.command, "ok": False, "blocker": str(exc)})
        return EXIT_BLOCKER
    except DeployFailure as exc:
        log("FAILURE: %s" % exc)
        emit_result({"stage": args.command, "ok": False, "failure": str(exc)})
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
