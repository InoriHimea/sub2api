#!/usr/bin/env python3
"""Qualify the currently checked-out fork commit for release.

Runs the frontend frozen build and the backend's real-transport Go test
suite (`-tags=unit`) against an owned, ephemeral PostgreSQL + Redis fixture
that this script starts and tears down itself, then strictly requires PASS
(never skip/fail/missing) for the three mandatory downstream acceptance
tests AND a clean overall `go test` exit code (so a regression in any other
package also blocks qualification, not only the three named tests). On
success it writes a qualification.json binding the exact qualified commit,
the exact Go compiler used, the frontend build outcome and the individual
test outcomes, so build_release.py can refuse to produce artifacts from a
stale or mismatched qualification and can reuse the already-built frontend
output instead of repeating the frozen install/build.

Intentionally minimal external footprint: this script talks to the Docker
CLI and `go`/`git`/`npm` only through explicit argument lists (no shell
strings), only touches containers/networks it created itself (unique name
prefix), and never mutates tracked source (no `go mod tidy`, no VERSION
rewrite, no GOSUMDB/GOFLAGS weakening).

Python3.9 compatibility is retained for controlled Linux runners; no
alternate interpreter or globally installed package manager is assumed.

CLI:
    python3 scripts/ci/qualify_release.py --output release/qualification.json
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
BACKEND_DIR = REPO_ROOT / "backend"
FRONTEND_DIR = REPO_ROOT / "frontend"
GO_MOD = BACKEND_DIR / "go.mod"
WEB_DIST_DIR = BACKEND_DIR / "internal" / "web" / "dist"

# Bare test names (unique across the whole module) mapped to their owning
# Go package, used only to parse `go test -json` events. The qualification
# record itself keys outcomes by the bare name, agreed with the deploy-tools
# interface so both sides read the same simple shape.
REQUIRED_TESTS = {
    "TestUsageHourlyPostgresHTTPIntegration": "github.com/Wei-Shaw/sub2api/internal/server/routes",
    "TestAdminCreateUserAPIKeyIntegration": "github.com/Wei-Shaw/sub2api/internal/server/routes",
    "TestOpenAIHTTPObservationRealHTTPSuccessSmoke": "github.com/Wei-Shaw/sub2api/internal/service",
}

QUALIFY_DB = "sub2api_fork_test"
GO_TEST_TIMEOUT_SECONDS = int(os.environ.get("QUALIFY_GO_TEST_TIMEOUT_SECONDS", "1800"))
GO_TOOLCHAIN_TIMEOUT_SECONDS = int(os.environ.get("QUALIFY_GO_TOOLCHAIN_TIMEOUT_SECONDS", "600"))
FIXTURE_READY_TIMEOUT_SECONDS = 90
POSTGRES_IMAGE = os.environ.get("QUALIFY_POSTGRES_IMAGE", "postgres:18-alpine")
REDIS_IMAGE = os.environ.get("QUALIFY_REDIS_IMAGE", "redis:8-alpine")


class QualifyError(RuntimeError):
    """Fatal, user-facing qualification failure."""


def log(message):
    print("[qualify] %s" % message, file=sys.stderr)
    sys.stderr.flush()


def run(args, cwd=None, env=None, timeout=120, check=True, capture=True):
    """Run an external command safely: list-form args only, never shell=True."""
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
        raise QualifyError("required executable not found: %s (%s)" % (args[0], exc))
    except subprocess.TimeoutExpired:
        raise QualifyError("command timed out after %ss: %s" % (timeout, " ".join(args)))
    if check and result.returncode != 0:
        output = result.stdout.decode("utf-8", "replace") if capture and result.stdout else ""
        raise QualifyError(
            "command failed (exit %s): %s\n%s" % (result.returncode, " ".join(args), output[-4000:])
        )
    return result


def required_compiler():
    text = GO_MOD.read_text(encoding="utf-8")
    match = re.search(r"^go (\d+\.\d+\.\d+)\s*$", text, re.MULTILINE)
    if not match:
        raise QualifyError("backend/go.mod must declare an exact Go patch version (e.g. 'go 1.27.3')")
    return "go" + match.group(1)


def go_env(name, expected_compiler, timeout):
    """Run `go env <name>` from inside the backend module with GOTOOLCHAIN
    pinned to the exact compiler backend/go.mod requires, so Go's own
    auto-toolchain download (its default behavior) can fetch that exact
    version when the agent's installed `go` binary is older/newer, instead
    of silently reporting the base installed toolchain's version."""
    env = dict(os.environ)
    env["GOTOOLCHAIN"] = expected_compiler
    result = run(["go", "env", name], cwd=BACKEND_DIR, env=env, timeout=timeout)
    return result.stdout.decode("utf-8", "replace").strip()


def verify_compiler():
    expected = required_compiler()
    actual = go_env("GOVERSION", expected, GO_TOOLCHAIN_TIMEOUT_SECONDS)
    if actual != expected:
        raise QualifyError("Go toolchain mismatch: backend/go.mod requires %s, resolved toolchain is %s" % (expected, actual))
    return expected


def verify_clean_source():
    result = run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=REPO_ROOT, timeout=60)
    dirty = result.stdout.decode("utf-8", "replace").strip()
    if dirty:
        raise QualifyError(
            "refusing to qualify a dirty working tree (uncommitted/untracked changes present); "
            "qualification must bind to an exact immutable commit:\n" + dirty[:4000]
        )


def sha256_hex(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def hash_directory_tree(root):
    """Deterministic aggregate sha256 over every regular file under root:
    hash of the sorted "relpath\\0sha256\\n" lines. Order-independent and
    stable regardless of filesystem directory-listing order. build_release.py
    recomputes this same function over the same directory and requires an
    exact match before embedding it, so a stale or hand-edited dist tree
    between the two script invocations is rejected rather than silently
    shipped."""
    entries = []
    for current_dir, dirnames, filenames in os.walk(root):
        dirnames.sort()
        current_path = Path(current_dir)
        for filename in sorted(filenames):
            candidate = current_path / filename
            if candidate.is_symlink() or not candidate.is_file():
                raise QualifyError("refusing symlinked/non-regular file while hashing %s: %s" % (root, candidate))
            relative = candidate.relative_to(root).as_posix()
            entries.append("%s\0%s\n" % (relative, sha256_hex(candidate)))
    entries.sort()
    digest = hashlib.sha256()
    for entry in entries:
        digest.update(entry.encode("utf-8"))
    return digest.hexdigest()


def current_sha():
    result = run(["git", "rev-parse", "--verify", "HEAD^{commit}"], cwd=REPO_ROOT, timeout=30)
    sha = result.stdout.decode("utf-8", "replace").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise QualifyError("unable to resolve a 40-hex-character HEAD commit sha")
    return sha


class DockerFixture:
    """An owned, ephemeral Postgres + Redis pair used only for qualification.

    Every resource is named with a random run id prefix so cleanup never
    touches pre-existing containers/networks. __enter__ cleans up anything
    it already created if a later setup step fails (Python only calls
    __exit__ when __enter__ returns successfully), and __exit__ always
    cleans up on both success and failure paths.
    """

    def __init__(self):
        self.run_id = "sub2api-qualify-%d-%s" % (os.getpid(), secrets.token_hex(4))
        self.network = self.run_id + "-net"
        self.pg_container = self.run_id + "-pg"
        self.redis_container = self.run_id + "-redis"
        self.pg_port = None
        self.redis_port = None
        self._created = []

    def __enter__(self):
        try:
            run(["docker", "version"], timeout=30)
            run(["docker", "network", "create", self.network], timeout=30)
            self._created.append(("network", self.network))
            self._start_postgres()
            self._start_redis()
            self._wait_ready()
        except BaseException:
            self.cleanup()
            raise
        return self

    def __exit__(self, exc_type, exc, tb):
        self.cleanup()
        return False

    def _start_postgres(self):
        log("starting owned Postgres fixture %s (%s)" % (self.pg_container, POSTGRES_IMAGE))
        try:
            run(
                [
                    "docker", "run", "-d",
                    "--name", self.pg_container,
                    "--network", self.network,
                    "-p", "127.0.0.1::5432",
                    "-e", "POSTGRES_HOST_AUTH_METHOD=trust",
                    "-e", "POSTGRES_DB=" + QUALIFY_DB,
                    POSTGRES_IMAGE,
                ],
                timeout=180,
            )
        finally:
            # Register for cleanup even on a failed `docker run`: a failed
            # start can still leave a (stopped/created) container behind.
            self._created.append(("container", self.pg_container))
        self.pg_port = self._published_port(self.pg_container, "5432/tcp")

    def _start_redis(self):
        log("starting owned Redis fixture %s (%s)" % (self.redis_container, REDIS_IMAGE))
        try:
            run(
                [
                    "docker", "run", "-d",
                    "--name", self.redis_container,
                    "--network", self.network,
                    "-p", "127.0.0.1::6379",
                    REDIS_IMAGE,
                ],
                timeout=60,
            )
        finally:
            self._created.append(("container", self.redis_container))
        self.redis_port = self._published_port(self.redis_container, "6379/tcp")

    def _published_port(self, container, container_port):
        result = run(["docker", "port", container, container_port], timeout=30)
        line = result.stdout.decode("utf-8", "replace").strip().splitlines()[0]
        # Format: "127.0.0.1:54321"
        port = line.rsplit(":", 1)[-1].strip()
        if not port.isdigit():
            raise QualifyError("could not determine published port for %s/%s (%r)" % (container, container_port, line))
        return int(port)

    def _wait_ready(self):
        deadline = time.monotonic() + FIXTURE_READY_TIMEOUT_SECONDS
        pg_ready = False
        redis_ready = False
        while time.monotonic() < deadline and not (pg_ready and redis_ready):
            if not pg_ready:
                probe = run(
                    ["docker", "exec", self.pg_container, "pg_isready", "-U", "postgres", "-d", QUALIFY_DB],
                    timeout=15, check=False,
                )
                pg_ready = probe.returncode == 0
            if not redis_ready:
                probe = run(["docker", "exec", self.redis_container, "redis-cli", "ping"], timeout=15, check=False)
                redis_ready = probe.returncode == 0 and b"PONG" in (probe.stdout or b"")
            if not (pg_ready and redis_ready):
                time.sleep(1.5)
        if not pg_ready:
            raise QualifyError("owned Postgres fixture did not become ready within %ss" % FIXTURE_READY_TIMEOUT_SECONDS)
        if not redis_ready:
            raise QualifyError("owned Redis fixture did not become ready within %ss" % FIXTURE_READY_TIMEOUT_SECONDS)

    def env_overrides(self):
        dsn = "postgres://postgres@127.0.0.1:%d/%s?sslmode=disable" % (self.pg_port, QUALIFY_DB)
        return {
            "SUB2API_USAGE_HOURLY_TEST_OWNED": "1",
            "SUB2API_USAGE_HOURLY_TEST_DSN": dsn,
            "SUB2API_ADMIN_KEY_TEST_OWNED": "1",
            "SUB2API_ADMIN_KEY_TEST_DSN": dsn,
            "SUB2API_ADMIN_KEY_TEST_REDIS_ADDR": "127.0.0.1:%d" % self.redis_port,
            "SCOPED_ADMIN_TEST_DSN": "host=127.0.0.1 port=%d user=postgres dbname=%s sslmode=disable" % (self.pg_port, QUALIFY_DB),
        }

    def cleanup(self):
        """Remove only the resources this instance created, best-effort.
        `-v` also removes this container's own anonymous volumes (both the
        Postgres and Redis images can create one even with no explicit `-v`
        mount on `docker run`) so per-run fixture volumes do not silently
        accumulate on the agent; this never touches any shared/named volume
        or runs a global prune."""
        for kind, name in reversed(self._created):
            if kind == "container":
                run(["docker", "rm", "-f", "-v", name], timeout=30, check=False)
            elif kind == "network":
                run(["docker", "network", "rm", name], timeout=30, check=False)
        self._created = []


def run_pnpm(args, cwd, timeout, check=True):
    # Pin pnpm9 through npm exec; do not depend on global pnpm or corepack.
    return run(["npm", "exec", "--yes", "--package", "pnpm@9", "--", "pnpm"] + args, cwd=cwd, timeout=timeout, check=check)


def build_frontend():
    """Run the frozen frontend build exactly once. build_release.py reuses
    backend/internal/web/dist from this same workspace instead of repeating
    the pnpm install/build in the later build step."""
    if not (FRONTEND_DIR / "package.json").exists():
        raise QualifyError("frontend/package.json not found under %s" % REPO_ROOT)
    version_check = run_pnpm(["--version"], cwd=REPO_ROOT, timeout=180)
    version = version_check.stdout.decode("utf-8", "replace").strip()
    if not version.startswith("9."):
        raise QualifyError("pinned pnpm9 required, npm exec resolved pnpm %s" % version)
    log("frontend frozen install (pnpm %s)" % version)
    run_pnpm(["install", "--frozen-lockfile"], cwd=FRONTEND_DIR, timeout=900)
    log("frontend frozen build (includes i18n completeness check + vue-tsc)")
    result = run_pnpm(["run", "build"], cwd=FRONTEND_DIR, timeout=900, check=False)
    exit_code = result.returncode
    if exit_code != 0:
        output = result.stdout.decode("utf-8", "replace") if result.stdout else ""
        raise QualifyError("frontend frozen build failed (exit %s):\n%s" % (exit_code, output[-4000:]))
    index_html = WEB_DIST_DIR / "index.html"
    if not index_html.exists() or index_html.stat().st_size == 0:
        raise QualifyError("frontend build did not produce %s; Go embed would fail" % index_html)
    dist_hash = hash_directory_tree(WEB_DIST_DIR)
    return exit_code, dist_hash


def _kill_process_group(process):
    """Kill only this one subprocess's own process group/session (created
    via start_new_session below), never a global pkill. go test forks a
    separate process per compiled test binary; killing only the `go`
    launcher on timeout can leave those descendants orphaned and still
    running against the (about to be torn down) fixture."""
    try:
        if hasattr(os, "killpg") and hasattr(os, "getpgid"):
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
    except OSError:
        process.kill()


def run_go_tests(env_overrides, expected_compiler):
    env = dict(os.environ)
    env.update(env_overrides)
    env["GOFLAGS"] = "-mod=readonly"
    env["GOTOOLCHAIN"] = expected_compiler
    # Deliberately do not touch GOSUMDB/GOPROXY/GONOSUMCHECK: module
    # verification must stay on, never disabled for a release qualification.
    log("running: go test -json -tags=unit -count=1 -p 1 ./... (timeout %ss)" % GO_TEST_TIMEOUT_SECONDS)
    popen_kwargs = {}
    if hasattr(os, "setsid"):
        # Linux: own process group/session so a timeout can terminate every
        # descendant, not just the immediate `go` launcher process.
        popen_kwargs["start_new_session"] = True
    try:
        process = subprocess.Popen(
            ["go", "test", "-json", "-tags=unit", "-count=1", "-p", "1", "./..."],
            cwd=str(BACKEND_DIR),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            **popen_kwargs
        )
    except FileNotFoundError as exc:
        raise QualifyError("go executable not found: %s" % exc)
    try:
        stdout, _ = process.communicate(timeout=GO_TEST_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        _kill_process_group(process)
        try:
            stdout, _ = process.communicate(timeout=30)
        except subprocess.TimeoutExpired:
            stdout = b""
        partial = stdout.decode("utf-8", "replace") if stdout else ""
        raise QualifyError(
            "go test did not finish within %ss; terminated its process group; partial output tail:\n%s"
            % (GO_TEST_TIMEOUT_SECONDS, partial[-4000:])
        )
    return process.returncode, stdout.decode("utf-8", "replace")


def parse_required_outcomes(go_test_json_output):
    """Return {bare_test_name: status} for every required test, status one
    of pass/fail/skip/missing. Never trusts the process exit code alone: go
    test -json still emits per-test pass/fail/skip events on a failing run,
    which is exactly what a strict parser must inspect. The overall exit
    code is checked separately so a regression anywhere else in the suite
    also blocks qualification."""
    outcomes = {name: "missing" for name in REQUIRED_TESTS}
    for line in go_test_json_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        pkg = event.get("Package")
        test = event.get("Test")
        action = event.get("Action")
        if not pkg or not test or action not in ("pass", "fail", "skip"):
            continue
        expected_pkg = REQUIRED_TESTS.get(test)
        if expected_pkg is not None and pkg == expected_pkg:
            # Last terminal action wins; a test only has one terminal event.
            outcomes[test] = action
    return outcomes


# Full go test -json output is preserved here on failure for diagnosis --
# never under release/ (not a shipped artifact) and already covered by the
# repository-wide `.cache/` gitignore rule, so it is never committed.
FAILURE_LOG_DIR = REPO_ROOT / ".cache" / "qualify-logs"
MAX_DIAGNOSTIC_FAILURES = 20
MAX_DIAGNOSTIC_OUTPUT_CHARS = 2000


def save_failure_log(go_test_json_output, sha):
    FAILURE_LOG_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = FAILURE_LOG_DIR / ("go-test-%s-%s.jsonl" % (stamp, sha[:12]))
    log_path.write_text(go_test_json_output, encoding="utf-8")
    return log_path


def collect_diagnostics(go_test_json_output):
    """Second, cheap pass over the same captured stream: accumulate each
    (package, test)'s own incremental "output" events (bounded per key) and
    list any OTHER (non-mandatory) test that failed, so a strict overall
    exit-code gate stays diagnosable without dumping the full raw stream to
    stdout -- the full stream is preserved separately by save_failure_log."""
    other_failed = []
    output_by_key = {}
    for line in go_test_json_output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        pkg = event.get("Package")
        test = event.get("Test")
        action = event.get("Action")
        if not pkg or not test:
            continue
        key = (pkg, test)
        if action == "output":
            existing = output_by_key.get(key, "")
            if len(existing) < MAX_DIAGNOSTIC_OUTPUT_CHARS:
                output_by_key[key] = existing + str(event.get("Output", ""))
            continue
        if action == "fail" and REQUIRED_TESTS.get(test) != pkg:
            other_failed.append("%s.%s" % (pkg, test))
    return other_failed, output_by_key


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="path to write qualification.json")
    args = parser.parse_args()

    output_path = Path(args.output)
    # Never leave a stale PASS sitting at the output path if this run fails
    # or is interrupted: invalidate any prior result up front so the output
    # file's mere existence always reflects THIS invocation's outcome, not
    # a reused prior success from a failed retry.
    if output_path.exists():
        output_path.unlink()

    if not GO_MOD.exists():
        raise QualifyError("backend/go.mod not found under %s; run from the repository checkout" % REPO_ROOT)
    verify_clean_source()
    compiler = verify_compiler()
    sha = current_sha()

    frontend_build_exit_code, frontend_dist_sha256 = build_frontend()

    with DockerFixture() as fixture:
        go_test_exit_code, output_text = run_go_tests(fixture.env_overrides(), compiler)
    outcomes = parse_required_outcomes(output_text)

    problems = {name: status for name, status in sorted(outcomes.items()) if status != "pass"}
    if go_test_exit_code != 0:
        problems["<overall go test exit code>"] = go_test_exit_code
    if problems:
        other_failed, output_by_key = collect_diagnostics(output_text)
        log_path = save_failure_log(output_text, sha)
        lines = []
        for name, status in sorted(outcomes.items()):
            if status == "pass":
                continue
            pkg = REQUIRED_TESTS.get(name)
            captured = output_by_key.get((pkg, name), "").strip()
            if captured:
                lines.append("%s (%s): %s -- %s" % (name, pkg, status, captured[-800:]))
            else:
                lines.append("%s (%s): %s" % (name, pkg, status))
        if go_test_exit_code != 0:
            lines.append("overall go test exit code: %s" % go_test_exit_code)
        if other_failed:
            shown = other_failed[:MAX_DIAGNOSTIC_FAILURES]
            lines.append(
                "other failing tests (%d of %d shown): %s" % (len(shown), len(other_failed), shown)
            )
        raise QualifyError(
            "mandatory downstream acceptance tests did not pass, or the overall suite failed "
            "(missing/skip/fail cannot qualify):\n%s\nfull go test -json output saved to %s"
            % ("\n".join(lines), log_path)
        )

    qualification = {
        "schema": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "sha": sha,
        "compiler": compiler,
        "qualified": True,
        "go_test_exit_code": go_test_exit_code,
        "frontend_build_exit_code": frontend_build_exit_code,
        "frontend_dist_sha256": frontend_dist_sha256,
        "tests": {name: "PASS" for name in sorted(outcomes)},
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(qualification, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    log("qualification PASSED for sha=%s compiler=%s -> %s" % (sha, compiler, output_path))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except QualifyError as exc:
        log("FAIL: %s" % exc)
        sys.exit(1)
    except KeyboardInterrupt:
        log("interrupted")
        sys.exit(130)
