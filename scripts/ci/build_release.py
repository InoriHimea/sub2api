#!/usr/bin/env python3
"""Build a provenance-bound release bundle from an already-qualified checkout.

Produces the shared binary+image bundle described by the release contract
(schema 1 manifest.json) under --output (default CLI usage: `release/`):

    release/
      sub2api                 (0755 Linux/amd64 executable, embeds the
                                frozen frontend build)
      sub2api-image.tar       (docker save of sub2api-fork:<version>-<sha12>)
      qualification.json      (written earlier by qualify_release.py; copied
                                here verbatim if --qualification pointed
                                elsewhere)
      manifest.json           (schema 1, written LAST -- its own existence
                                is intentionally excluded from its own file
                                list/top-level self-check, see build_manifest)
      resources/...           (copy of backend/resources)
      migrations/*.sql        (copy of backend/migrations/*.sql, raw bytes)
      tools/                  (deploy_release.py, remote_deploy.py,
                                targets.json, known_hosts -- copied verbatim
                                from scripts/ci/, owned by ReleaseDeployer;
                                this script only copies them, never creates
                                or stubs them)

Hard gates, all fail-closed (no manifest.json, no partial publication):
  * working tree must be clean (no uncommitted/untracked changes)
  * the checked-out HEAD must carry exactly one v-prefixed strict-SemVer
    tag (verified against the actual git tag state of this checkout, never
    inferred from a nearest tag). GitHub's GITHUB_SHA must equal HEAD and
    GITHUB_REF must name that exact release tag.
  * qualification.json must exist, bind the exact current HEAD sha and the
    exact backend/go.mod compiler, and record PASS for every mandatory
    test plus a clean go_test_exit_code/frontend_build_exit_code -- stale
    or mismatched qualification is rejected
  * the frontend dist this script embeds must hash-match the one
    qualify_release.py actually built in this same workspace (no silently
    stale or hand-edited frontend output can enter the image)
  * the active `go` toolchain must match backend/go.mod exactly
  * every required deploy tool file must already exist on disk (this
    script copies them; it never invents placeholders)
  * every file written under the release root must be a plain regular file
    (no symlinks), and the final file set must match exactly what this
    script produced

This script never logs in to, pulls from or pushes to any container
registry -- the Docker image is only built locally and saved to a tar
artifact for transfer over the already-pinned SSH deployment path.

Python 3.9 compatible; see qualify_release.py for the same constraint.

CLI:
    python3 scripts/ci/build_release.py --output release
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
DEPLOY_DIR = REPO_ROOT / "deploy"
GO_MOD = BACKEND_DIR / "go.mod"
MIGRATIONS_DIR = BACKEND_DIR / "migrations"
RESOURCES_DIR = BACKEND_DIR / "resources"
WEB_DIST_DIR = BACKEND_DIR / "internal" / "web" / "dist"
DOCKERFILE_GORELEASER = REPO_ROOT / "Dockerfile.goreleaser"
ENTRYPOINT_SH = DEPLOY_DIR / "docker-entrypoint.sh"

# Deploy tooling is owned by ReleaseDeployer; this script only ever reads
# these exact files and copies them verbatim into release/tools/.
DEPLOY_TOOL_FILES = ("deploy_release.py", "remote_deploy.py", "targets.json", "known_hosts", "deploy.sh")

# This script's own generated outputs under the release root. A rebuild
# resets exactly these paths (reset_release_root below) so repeated builds
# are idempotent; qualification.json is deliberately never in this set, so
# a freshly produced/copied qualification is always preserved across a
# rebuild in the same release root.
MANAGED_OUTPUT_NAMES = frozenset({"sub2api", "sub2api-image.tar", "manifest.json", "resources", "migrations", "tools"})

# Canonical qualification.json shape agreed with the deploy-tools interface:
# bare mandatory test names (unique across the whole module) each mapped to
# the literal string "PASS".
MANDATORY_TEST_NAMES = (
    "TestUsageHourlyPostgresHTTPIntegration",
    "TestAdminCreateUserAPIKeyIntegration",
    "TestOpenAIHTTPObservationRealHTTPSuccessSmoke",
)

# Official SemVer 2.0.0 grammar (semver.org), v-prefixed: no leading zeros in
# any numeric identifier, optional dot-separated prerelease identifiers,
# optional dot-separated build metadata. Deliberately the same strict
# grammar on both the build and deploy sides of this interface.
STRICT_SEMVER_RE = re.compile(
    r"^v(?P<version>"
    r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
    r"(?:-(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*)?"
    r"(?:\+[0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*)?"
    r")$"
)



class BuildError(RuntimeError):
    """Fatal, user-facing build failure."""


def log(message):
    print("[build] %s" % message, file=sys.stderr)
    sys.stderr.flush()


def run(args, cwd=None, env=None, timeout=120, check=True, capture=True):
    try:
        result = subprocess.run(
            args,
            cwd=str(cwd) if cwd else None,
            env=env,
            timeout=timeout,
            stdout=subprocess.PIPE if capture else None,
            stderr=subprocess.STDOUT if capture else None,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BuildError("required executable not found: %s (%s)" % (args[0], exc))
    except subprocess.TimeoutExpired:
        raise BuildError("command timed out after %ss: %s" % (timeout, " ".join(args)))
    if check and result.returncode != 0:
        output = result.stdout.decode("utf-8", "replace") if capture and result.stdout else ""
        raise BuildError("command failed (exit %s): %s\n%s" % (result.returncode, " ".join(args), output[-4000:]))
    return result


def sha256_hex(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_directory_tree(root):
    """Deterministic aggregate sha256 over every regular file under root:
    hash of the sorted "relpath\\0sha256\\n" lines. Order-independent and
    stable regardless of filesystem directory-listing order."""
    entries = []
    for current_dir, dirnames, filenames in os.walk(root):
        dirnames.sort()
        current_path = Path(current_dir)
        for filename in sorted(filenames):
            candidate = current_path / filename
            if candidate.is_symlink() or not candidate.is_file():
                raise BuildError("refusing symlinked/non-regular file while hashing %s: %s" % (root, candidate))
            relative = candidate.relative_to(root).as_posix()
            entries.append("%s\0%s\n" % (relative, sha256_hex(candidate)))
    entries.sort()
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(entry.encode("utf-8"))
    return digest.hexdigest()


def required_compiler():
    text = GO_MOD.read_text(encoding="utf-8")
    match = re.search(r"^go (\d+\.\d+\.\d+)\s*$", text, re.MULTILINE)
    if not match:
        raise BuildError("backend/go.mod must declare an exact Go patch version (e.g. 'go 1.27.3')")
    return "go" + match.group(1)


def go_env(name, expected_compiler, timeout):
    """Run `go env <name>` from inside the backend module with GOTOOLCHAIN
    pinned to the exact compiler backend/go.mod requires, so Go's own
    auto-toolchain download (its default behavior) can fetch that exact
    version when the agent's installed `go` binary differs, instead of
    silently reporting the base installed toolchain's version."""
    env = dict(os.environ)
    env["GOTOOLCHAIN"] = expected_compiler
    result = run(["go", "env", name], cwd=BACKEND_DIR, env=env, timeout=timeout)
    return result.stdout.decode("utf-8", "replace").strip()


def verify_compiler():
    expected = required_compiler()
    actual = go_env("GOVERSION", expected, 600)
    if actual != expected:
        raise BuildError("Go toolchain mismatch: backend/go.mod requires %s, resolved toolchain is %s" % (expected, actual))
    return expected


def verify_clean_source():
    result = run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=REPO_ROOT, timeout=60)
    dirty = result.stdout.decode("utf-8", "replace").strip()
    if dirty:
        raise BuildError(
            "refusing to build from a dirty working tree (uncommitted/untracked changes present):\n" + dirty[:4000]
        )


def current_sha():
    result = run(["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=REPO_ROOT, timeout=30)
    sha = result.stdout.decode("utf-8", "replace").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise BuildError("unable to resolve a 40-hex-character HEAD commit sha")
    return sha




def resolve_tag_and_sha():
    """Reject dirty source (caller's responsibility, see verify_clean_source),
    non-tag refs, ambiguous/nearest-tag inference and tag/revision mismatches.

    Bind the local immutable tag to GitHub's triggering tag ref and commit.
    A branch push with a coincidental tag at HEAD is not a release event.

    Returns (tag, version, sha).
    """
    sha = current_sha()

    rev_value = os.environ.get("GITHUB_SHA", "").strip()
    if not re.fullmatch(r"[0-9a-fA-F]{40}", rev_value):
        raise BuildError("GITHUB_SHA must be a full 40-hex commit SHA")
    if rev_value.lower() != sha:
        raise BuildError("GITHUB_SHA does not match the actual checked-out HEAD %s" % sha)
    ref = os.environ.get("GITHUB_REF", "")
    if not ref.startswith("refs/tags/"):
        raise BuildError("GITHUB_REF must be a release tag ref, not a branch or pull request")

    points_at = run(["git", "tag", "--points-at", sha, "--list", "v*"], cwd=REPO_ROOT, timeout=30)
    candidates = [line.strip() for line in points_at.stdout.decode("utf-8", "replace").splitlines() if line.strip()]
    matches = [name for name in candidates if STRICT_SEMVER_RE.match(name)]
    if not matches:
        raise BuildError(
            "no exact v-prefixed strict-SemVer release tag points at checked-out HEAD %s "
            "(candidates seen: %s); refusing to build a release artifact from a non-tag ref" % (sha, candidates)
        )
    if len(matches) > 1:
        raise BuildError("multiple exact release tags point at HEAD %s, refusing to pick one: %s" % (sha, matches))
    tag = matches[0]
    if ref != "refs/tags/" + tag:
        raise BuildError("GITHUB_REF does not match the exact release tag at HEAD: %s" % tag)
    version = STRICT_SEMVER_RE.match(tag).group("version")

    tagged_commit = run(
        ["git", "rev-parse", "--verify", "refs/tags/%s^{commit}" % tag],
        cwd=REPO_ROOT, timeout=30, check=False,
    )
    resolved = tagged_commit.stdout.decode("utf-8", "replace").strip().lower()
    if tagged_commit.returncode != 0 or not resolved:
        raise BuildError("tag %s does not resolve to a commit object in this checkout" % tag)
    if resolved != sha:
        raise BuildError("tag %s resolves to %s, which does not match checked-out HEAD %s" % (tag, resolved, sha))

    return tag, version, sha


def docker_safe_tag_component(version):
    """Docker image tags cannot contain '+'; map SemVer build metadata to a
    deterministic, collision-safe component without ever altering the exact
    manifest.version/tag fields that keep the real SemVer value intact."""
    return version.replace("+", "_")


def load_qualification(path, expected_sha, expected_compiler):
    if not path.exists():
        raise BuildError("qualification file not found: %s (run qualify_release.py first)" % path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise BuildError("qualification file is not valid JSON: %s" % exc)

    if data.get("sha") != expected_sha:
        raise BuildError(
            "stale qualification: qualification.json sha=%s does not match current checkout sha=%s"
            % (data.get("sha"), expected_sha)
        )
    if data.get("compiler") != expected_compiler:
        raise BuildError(
            "mismatched qualification: qualification.json compiler=%s does not match required %s"
            % (data.get("compiler"), expected_compiler)
        )
    if data.get("qualified") is not True:
        raise BuildError("qualification.json does not report qualified=true")
    if data.get("go_test_exit_code") != 0:
        raise BuildError("qualification.json go_test_exit_code=%r, not 0" % data.get("go_test_exit_code"))
    if data.get("frontend_build_exit_code") != 0:
        raise BuildError("qualification.json frontend_build_exit_code=%r, not 0" % data.get("frontend_build_exit_code"))

    tests = data.get("tests")
    if not isinstance(tests, dict):
        raise BuildError("qualification.json is missing its tests outcome map")
    for name in MANDATORY_TEST_NAMES:
        if tests.get(name) != "PASS":
            raise BuildError("qualification.json records %s=%r, not PASS; cannot build from this qualification" % (name, tests.get(name)))

    dist_hash = data.get("frontend_dist_sha256")
    if not isinstance(dist_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", dist_hash):
        raise BuildError("qualification.json is missing a valid frontend_dist_sha256")
    return data


def verify_frontend_dist(expected_hash):
    """The frontend was already built once by qualify_release.py in this
    same workspace; never repeat the frozen install/build here. Only prove
    the dist tree this script is about to embed is byte-identical to what
    was actually qualified."""
    index_html = WEB_DIST_DIR / "index.html"
    if not index_html.exists() or index_html.stat().st_size == 0:
        raise BuildError(
            "%s is missing/empty; expected qualify_release.py to have already produced the frozen frontend build "
            "in this workspace" % index_html
        )
    actual_hash = hash_directory_tree(WEB_DIST_DIR)
    if actual_hash != expected_hash:
        raise BuildError(
            "frontend dist does not match the qualified build (qualification=%s actual=%s); "
            "refusing to embed a stale or hand-modified frontend output" % (expected_hash, actual_hash)
        )


def build_binary(version, sha, output_path):
    if not GO_MOD.exists():
        raise BuildError("backend/go.mod not found under %s" % REPO_ROOT)
    expected_compiler = required_compiler()
    build_date = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    env = dict(os.environ)
    env.update({
        "CGO_ENABLED": "0",
        "GOOS": "linux",
        "GOARCH": "amd64",
        "GOFLAGS": "-mod=readonly",
        "GOTOOLCHAIN": expected_compiler,
    })
    ldflags = (
        "-s -w "
        "-X main.Version=%s "
        "-X main.Commit=%s "
        "-X main.Date=%s "
        "-X main.BuildType=release" % (version, sha, build_date)
    )
    # output_path is resolved absolute by the caller: go build's cwd is
    # backend/, so a relative -o path here would otherwise land under
    # backend/release/... instead of the actual release bundle root.
    log("compiling linux/amd64 binary (version=%s sha=%s)" % (version, sha))
    run(
        [
            "go", "build",
            "-tags=embed",
            "-trimpath",
            "-ldflags", ldflags,
            "-o", str(output_path),
            "./cmd/server",
        ],
        cwd=BACKEND_DIR, env=env, timeout=900,
    )
    if not output_path.exists():
        raise BuildError("go build did not produce %s" % output_path)
    output_path.chmod(0o755)


def build_docker_image(binary_path, version, sha):
    if not DOCKERFILE_GORELEASER.exists():
        raise BuildError("%s not found" % DOCKERFILE_GORELEASER)
    if not ENTRYPOINT_SH.exists():
        raise BuildError("%s not found" % ENTRYPOINT_SH)
    if not RESOURCES_DIR.exists():
        raise BuildError("%s not found" % RESOURCES_DIR)

    image_tag = "sub2api-fork:%s-%s" % (docker_safe_tag_component(version), sha[:12])
    context_dir = Path(tempfile.mkdtemp(prefix="sub2api-release-ctx-"))
    try:
        shutil.copy2(binary_path, context_dir / "sub2api")
        (context_dir / "sub2api").chmod(0o755)
        shutil.copy2(DOCKERFILE_GORELEASER, context_dir / "Dockerfile")
        (context_dir / "deploy").mkdir(parents=True, exist_ok=True)
        shutil.copy2(ENTRYPOINT_SH, context_dir / "deploy" / "docker-entrypoint.sh")
        # Explicit 0755, never trust whatever mode bits copy2 preserved from
        # the source tree/filesystem the build happened to run on.
        (context_dir / "deploy" / "docker-entrypoint.sh").chmod(0o755)
        shutil.copytree(RESOURCES_DIR, context_dir / "backend" / "resources", dirs_exist_ok=True)
        _make_tree_world_readable(context_dir / "backend" / "resources")

        log("building Docker image %s (no registry login/push)" % image_tag)
        run(
            [
                "docker", "build",
                "--pull=false",
                "-f", str(context_dir / "Dockerfile"),
                "-t", image_tag,
                "--label", "org.opencontainers.image.version=" + version,
                "--label", "org.opencontainers.image.revision=" + sha,
                str(context_dir),
            ],
            timeout=900,
        )
    finally:
        shutil.rmtree(context_dir, ignore_errors=True)

    inspect = run(["docker", "image", "inspect", image_tag, "--format", "{{.Id}}"], timeout=60)
    image_id = inspect.stdout.decode("utf-8", "replace").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise BuildError("unexpected docker image id format: %r" % image_id)
    return image_tag, image_id


def _make_tree_world_readable(root):
    """Defensive, explicit permission bits for staged Docker build context:
    directories 0755, files at least 0644, so the image's eventual
    `--chown=sub2api:sub2api` COPY step and the uid1000 runtime user can
    always read them regardless of the source tree's on-disk permissions."""
    for current_dir, dirnames, filenames in os.walk(root):
        current_path = Path(current_dir)
        current_path.chmod(0o755)
        for filename in filenames:
            path = current_path / filename
            if not path.is_symlink():
                path.chmod(path.stat().st_mode | 0o644)


def save_docker_image(image_tag, destination):
    log("saving %s -> %s" % (image_tag, destination))
    run(["docker", "save", "-o", str(destination), image_tag], timeout=600)
    if not destination.exists() or destination.stat().st_size == 0:
        raise BuildError("docker save did not produce a non-empty archive at %s" % destination)


def reset_release_root(release_root):
    """Make a rebuild idempotent: remove only this script's own previously
    generated output paths (MANAGED_OUTPUT_NAMES), never qualification.json
    (which may have just been produced/copied by this same invocation).
    Refuses to run at all -- never silently deletes anything -- if the
    directory contains any entry this script does not recognize as either
    one of its own managed outputs or qualification.json."""
    if not release_root.exists():
        return
    allowed = MANAGED_OUTPUT_NAMES | {"qualification.json"}
    unexpected = sorted(entry.name for entry in release_root.iterdir() if entry.name not in allowed)
    if unexpected:
        raise BuildError(
            "release output directory %s contains unrecognized entries, refusing to delete them automatically: %s"
            % (release_root, unexpected)
        )
    for name in MANAGED_OUTPUT_NAMES:
        target = release_root / name
        if target.is_symlink() or target.exists():
            if target.is_symlink() or target.is_file():
                target.unlink()
            elif target.is_dir():
                shutil.rmtree(target)


def copy_resources(release_root):
    dest = release_root / "resources"
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(RESOURCES_DIR, dest)


def copy_migrations(release_root):
    dest = release_root / "migrations"
    dest.mkdir(parents=True, exist_ok=True)
    if not MIGRATIONS_DIR.exists():
        raise BuildError("%s not found" % MIGRATIONS_DIR)
    sql_files = sorted(p for p in MIGRATIONS_DIR.iterdir() if p.is_file() and p.suffix == ".sql")
    if not sql_files:
        raise BuildError("no migration files found under %s" % MIGRATIONS_DIR)
    copied = []
    for source in sql_files:
        target = dest / source.name
        shutil.copy2(source, target)
        copied.append(source)
    return copied


def copy_deploy_tools(release_root):
    dest = release_root / "tools"
    dest.mkdir(parents=True, exist_ok=True)
    missing = []
    for filename in DEPLOY_TOOL_FILES:
        source = SCRIPT_DIR / filename
        if not source.is_file():
            missing.append(str(source))
            continue
        shutil.copy2(source, dest / filename)
        if filename.endswith(".sh"):
            (dest / filename).chmod(0o755)
    if missing:
        raise BuildError(
            "required deploy tooling is missing (owned by the deploy-tools interface, not generated here): %s"
            % ", ".join(missing)
        )


# Exact character set Go's unicode.IsSpace() treats as whitespace (consumed
# by strings.TrimSpace in the migration runner). Deliberately NOT Python's
# str.strip() default set: Python's str.isspace() additionally treats
# U+001C-U+001F (file/group/record/unit separator control characters) as
# whitespace, which Go's unicode.IsSpace does not -- using the bare Python
# default could silently diverge from the real applied-migration checksum
# for any file whose content happens to contain those bytes.
GO_TRIMSPACE_CHARS = (
    "\t\n\v\f\r \u0085\u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000"
)


def migration_applied_checksum(path):
    """Authoritative applied-content checksum: sha256 of the raw file bytes
    decoded as UTF-8 with leading/trailing Go-whitespace stripped, matching
    the Go migration runner's `sha256(strings.TrimSpace(content))` exactly
    (backend/internal/repository/migrations_runner.go). Deliberately reads
    raw bytes rather than Path.read_text(), which would perform universal
    newline translation and silently change the checksum for any file
    containing CRLF line endings, and strips only GO_TRIMSPACE_CHARS rather
    than Python's broader default whitespace set."""
    content = path.read_bytes().decode("utf-8")
    stripped = content.strip(GO_TRIMSPACE_CHARS)
    return hashlib.sha256(stripped.encode("utf-8")).hexdigest()


def walk_release_files(release_root):
    """Yield every regular file under release_root (relative posix path),
    rejecting symlinks and anything that is not a plain file or directory."""
    for current_dir, dirnames, filenames in os.walk(release_root):
        current_path = Path(current_dir)
        for dirname in dirnames:
            candidate = current_path / dirname
            if candidate.is_symlink():
                raise BuildError("refusing symlinked directory in release bundle: %s" % candidate)
        for filename in filenames:
            candidate = current_path / filename
            if candidate.is_symlink():
                raise BuildError("refusing symlinked file in release bundle: %s" % candidate)
            if not candidate.is_file():
                raise BuildError("refusing non-regular file in release bundle: %s" % candidate)
            relative = candidate.relative_to(release_root).as_posix()
            yield relative, candidate


def build_manifest(release_root, tag, version, sha, compiler, binary_path, image_id, migrations):
    binary_sha256 = sha256_hex(binary_path)

    files = {}
    for relative, path in walk_release_files(release_root):
        if relative == "manifest.json":
            continue
        files[relative] = sha256_hex(path)

    # manifest.json itself is written by the caller only AFTER this function
    # returns (its presence is the sole "build succeeded" signal), so it is
    # intentionally excluded from this pre-write self-check.
    expected_top_level = {"sub2api", "sub2api-image.tar", "qualification.json", "resources", "migrations", "tools"}
    actual_top_level = {entry.name for entry in release_root.iterdir()}
    unexpected = actual_top_level - expected_top_level
    if unexpected:
        raise BuildError("unexpected top-level entries in release bundle: %s" % ", ".join(sorted(unexpected)))
    missing_top_level = expected_top_level - actual_top_level
    if missing_top_level:
        raise BuildError("missing required top-level entries in release bundle: %s" % ", ".join(sorted(missing_top_level)))

    manifest = {
        "schema": 1,
        "tag": tag,
        "version": version,
        "sha": sha,
        "compiler": compiler,
        "architecture": "amd64",
        "binary_sha256": binary_sha256,
        "image_id": image_id,
        "files": files,
        "migrations": [
            {"filename": path.name, "sha256": migration_applied_checksum(path)}
            for path in migrations
        ],
    }
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="release bundle root directory")
    parser.add_argument("--qualification", default=None, help="path to qualification.json (default: <output>/qualification.json)")
    args = parser.parse_args()

    # Resolve absolute: go build's cwd is backend/, so any later relative
    # path built from release_root would otherwise be misplaced under
    # backend/ instead of the real repository-root-relative bundle.
    release_root = Path(args.output).resolve()
    release_root.mkdir(parents=True, exist_ok=True)
    reset_release_root(release_root)
    bundle_qualification_path = release_root / "qualification.json"
    qualification_path = Path(args.qualification).resolve() if args.qualification else bundle_qualification_path
    if qualification_path != bundle_qualification_path:
        if not qualification_path.exists():
            raise BuildError("qualification file not found: %s" % qualification_path)
        bundle_qualification_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(qualification_path, bundle_qualification_path)
        qualification_path = bundle_qualification_path

    verify_clean_source()
    tag, version, sha = resolve_tag_and_sha()
    compiler = verify_compiler()
    qualification = load_qualification(qualification_path, expected_sha=sha, expected_compiler=compiler)

    verify_frontend_dist(qualification["frontend_dist_sha256"])

    binary_path = release_root / "sub2api"
    build_binary(version, sha, binary_path)

    copy_resources(release_root)
    migrations = copy_migrations(release_root)
    copy_deploy_tools(release_root)

    image_tag, image_id = build_docker_image(binary_path, version, sha)
    save_docker_image(image_tag, release_root / "sub2api-image.tar")

    manifest = build_manifest(release_root, tag, version, sha, compiler, binary_path, image_id, migrations)
    manifest_path = release_root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")

    log("build PASSED: tag=%s version=%s sha=%s image=%s -> %s" % (tag, version, sha, image_tag, manifest_path))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BuildError as exc:
        log("FAIL: %s" % exc)
        sys.exit(1)
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(130)
