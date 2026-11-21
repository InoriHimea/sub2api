"""Release delivery automation for the dedicated deployment VM.

Operator tooling OUTSIDE the strict controller trust set: it fetches the
published release bundle through the Nexus github-group proxy, reinstalls the
trusted controller for the exact release commit, updates the Bamboo pins,
triggers intake, creates the deployment version and, after the human
approval, runs the per-target deployment window. It never writes target
profiles, never invents migration approvals and never approves releases.

Phases (each idempotent, state kept under /data/sub2api-cd/delivery/):
  fetch           download + verify bundle and checksum from the tag release
  controller      reinstall the trusted controller from bundle + repo@commit
  pins            update plan release pins and env approved_target/key_path
  intake          trigger SUB2API-INTAKE, wait for a successful build
  release-create  create the deployment version from the intake build
  deploy          run one approved target window and verify acceptance
  run             fetch -> controller -> pins -> intake -> release-create,
                  then stop so a human can approve; optionally --await-approval
                  and --target to continue through deploy.

Authentication to Bamboo: `--bamboo-token-file` (a Personal Access Token,
recommended; sent as `Authorization: Bearer`) or `--bamboo-cookie` (a
cookie-string exported from an administrator browser session; XSRF tokens are
then scraped per page as the browser flow does). Token behaviour against the
admin ajax endpoints must be probed once with the owner-minted token.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

NEXUS_GITHUB_BASE = os.environ.get(
    "NEXUS_GITHUB_BASE", "https://nexus.mellivora.com.cn:18082/repository/github-group/"
)
GITHUB_REPO = os.environ.get("DELIVERY_GITHUB_REPO", "InoriHimea/sub2api")
BAMBOO_BASE = os.environ.get("DELIVERY_BAMBOO_BASE", "https://deploy.mellivora.com.cn")

CD_ROOT = Path("/data/sub2api-cd")
RELEASES_DIR = CD_ROOT / "releases"
CONTROLLERS_DIR = CD_ROOT / "controllers"
CURRENT_LINK = CD_ROOT / "current"
DELIVERY_DIR = CD_ROOT / "delivery"
KEY_DIR = CD_ROOT / "keys"
BAMBOO_PAT_FILE = CD_ROOT / "bamboo.pat"
TARGETS_JSON = CD_ROOT / "current" / "targets.json"

PLAN_KEY = os.environ.get("DELIVERY_PLAN_KEY", "SUB2API-INTAKE")
DEPLOY_PROJECT_ID = 36995074
PRODUCTION_ENV_ID = 37093378

CONTROLLER_FILES = (
    "bamboo_cd.py", "bamboo_cd.sh", "import_release.py", "build_release.py",
    "deploy_release.py", "remote_deploy.py", "targets.json", "known_hosts", "deploy.sh",
)
BUNDLE_TOOL_FILES = ("deploy.sh", "deploy_release.py", "known_hosts", "remote_deploy.py", "targets.json")
INTAKE_REPO_FILES = ("bamboo_cd.py", "bamboo_cd.sh", "import_release.py", "build_release.py")
ARCHIVE_NAME = "release-bundle.tar.gz"

ASSET_ATTEMPTS = 6          # Nexus negative-caches fresh release listings ~60s
ASSET_RETRY_SECONDS = 20
POLL_SECONDS = 20
POLL_ATTEMPTS = 60          # 20 minutes for intake/stage/activate style waits


class DeliveryError(Exception):
    """Explicit blocker: message is operator-facing, nothing is retried."""


# ---------------------------------------------------------------------------
# Small pure helpers (unit-tested)
# ---------------------------------------------------------------------------

def nexus_url(repo: str, github_path: str) -> str:
    return NEXUS_GITHUB_BASE + repo + "/" + github_path.lstrip("/")


def release_asset_url(tag: str, filename: str) -> str:
    return nexus_url(GITHUB_REPO, f"releases/download/{tag}/{filename}")


def repo_raw_url(commit: str, repo_path: str) -> str:
    return nexus_url(GITHUB_REPO, f"raw/{commit}/{repo_path}")


def parse_sha256_file(text: str, expected_name: str) -> str:
    """Parse `sha256sum` output; return the digest for expected_name."""
    for line in text.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) == 2 and re.fullmatch(r"[0-9a-f]{64}", parts[0]):
            name = parts[1].lstrip("*").strip()
            if name == expected_name or name.endswith("/" + expected_name):
                return parts[0]
    raise DeliveryError(f"checksum file does not contain {expected_name}: {text[:200]!r}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: os.PathLike | str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def controller_identity(files: dict[str, str]) -> str:
    """Same aggregate as controller_identity() in bamboo_cd.py: sha256 over a
    sorted, compact JSON map of file name -> file sha256."""
    if set(files) != set(CONTROLLER_FILES):
        raise DeliveryError(f"controller file set mismatch: {sorted(files)}")
    return hashlib.sha256(
        json.dumps(files, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def release_version_name(tag: str, commit: str) -> str:
    return f"{tag}-intake-{commit[:8]}"


def read_bundle_manifest(bundle_path: os.PathLike | str) -> dict:
    with tarfile.open(bundle_path, "r:gz") as archive:
        member = archive.extractfile("release/manifest.json")
        if member is None:
            raise DeliveryError("bundle does not contain release/manifest.json")
        manifest = json.loads(member.read().decode("utf-8"))
    for key in ("tag", "sha", "version", "binary_sha256"):
        if not manifest.get(key):
            raise DeliveryError(f"manifest missing {key}: {manifest}")
    return manifest


def extract_bundle_files(bundle_path: os.PathLike | str, prefixes: list[str],
                         destination: Path) -> None:
    """Extract release/tools/* (and only that) into destination/."""
    destination.mkdir(parents=True, exist_ok=True)
    seen = 0
    with tarfile.open(bundle_path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.name.startswith("release/tools/") and member.isfile():
                relative = os.path.relpath(member.name, "release/tools")
                if os.path.isabs(relative) or relative.startswith(".."):
                    raise DeliveryError(f"unsafe bundle path {member.name}")
                target = destination / relative
                with archive.extractfile(member) as source, open(target, "wb") as out:
                    shutil.copyfileobj(source, out)
                seen += 1
    if seen < len(prefixes):
        raise DeliveryError(f"bundle tools incomplete: found {seen}, expected >= {len(prefixes)}")


# ---------------------------------------------------------------------------
# HTTP + filesystem layers
# ---------------------------------------------------------------------------

def http_get(url: str, timeout: int = 120, auth_header: dict | None = None) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "release-delivery/1.0"})
    if auth_header:
        request.headers.update(auth_header)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_release_assets(tag: str, destination_dir: Path) -> tuple[Path, Path, str]:
    """Download bundle + checksum through Nexus with negative-cache retries."""
    destination_dir.mkdir(parents=True, exist_ok=True)
    bundle_path = destination_dir / ARCHIVE_NAME
    checksum_path = destination_dir / (ARCHIVE_NAME + ".sha256")
    last_error: Exception | None = None
    for attempt in range(1, ASSET_ATTEMPTS + 1):
        try:
            data = http_get(release_asset_url(tag, ARCHIVE_NAME))
            checksums = http_get(release_asset_url(tag, ARCHIVE_NAME + ".sha256"))
            expected = parse_sha256_file(checksums.decode("utf-8"), ARCHIVE_NAME)
            actual = sha256_bytes(data)
            if actual != expected:
                raise DeliveryError(f"asset digest mismatch: {actual} != {expected}")
            tmp = bundle_path.with_suffix(".partial")
            tmp.write_bytes(data)
            os.replace(tmp, bundle_path)
            checksum_path.write_bytes(checksums)
            print(f"[fetch] {ARCHIVE_NAME} {actual} ({len(data)} bytes, attempt {attempt})")
            return bundle_path, checksum_path, actual
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code == 404 and attempt < ASSET_ATTEMPTS:
                print(f"[fetch] 404 (fresh release negative cache), retry {attempt}/{ASSET_ATTEMPTS}")
                time.sleep(ASSET_RETRY_SECONDS)
                continue
            raise DeliveryError(f"asset fetch failed for {tag}: {error}") from error
    raise DeliveryError(f"asset fetch exhausted retries: {last_error}")


def _fetch_to_file(url: str, destination: Path, attempts: int = 3) -> None:
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        try:
            data = http_get(url, timeout=60)
            destination.write_bytes(data)
            return
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code == 404 and attempt < attempts:
                time.sleep(ASSET_RETRY_SECONDS)
                continue
            raise DeliveryError(f"fetch failed {url}: {error}") from error
    raise DeliveryError(f"fetch exhausted retries: {last_error}")


# ---------------------------------------------------------------------------
# Controller installation
# ---------------------------------------------------------------------------

def install_controller(bundle_path: Path, commit: str) -> tuple[str, Path]:
    """Reinstall the trusted controller for this release commit and atomically
    flip `current`. Verifies bundle-tools equality BEFORE the flip."""
    if os.geteuid() != 0:
        raise DeliveryError("controller installation must run as root on the deployment VM")
    tools_dir = Path(tempfile.mkdtemp(prefix=".delivery-tools-"))
    try:
        extract_bundle_files(bundle_path, BUNDLE_TOOL_FILES, tools_dir)

        content: dict[str, bytes] = {}
        for name in CONTROLLER_FILES:
            if name in BUNDLE_TOOL_FILES:
                content[name] = (tools_dir / name).read_bytes()
            else:
                assert name in INTAKE_REPO_FILES
                target_dir = tools_dir / "repo"
                target_dir.mkdir(exist_ok=True)
                repo_file = target_dir / name
                _fetch_to_file(repo_raw_url(commit, f"scripts/ci/{name}"), repo_file)
                content[name] = repo_file.read_bytes()

        files = {name: sha256_bytes(data) for name, data in content.items()}
        identity = controller_identity(files)

        target_dir = CONTROLLERS_DIR / identity
        if target_dir.is_dir():
            existing = {name: sha256_file(target_dir / name) for name in CONTROLLER_FILES}
            if existing != files:
                raise DeliveryError(f"controller dir {identity} exists with different content")
            print(f"[controller] identity {identity[:12]}… already installed")
        else:
            target_dir.mkdir(mode=0o750)
            for name, data in content.items():
                (target_dir / name).write_bytes(data)
            for name in CONTROLLER_FILES:
                path = target_dir / name
                os.chown(path, 0, -1)
                os.chown(path, -1, _group_bamboo())
                os.chmod(path, 0o550 if name == "bamboo_cd.sh" else 0o440)
            os.chown(target_dir, 0, _group_bamboo())
            os.chmod(target_dir, 0o750)
            on_disk = {name: sha256_file(target_dir / name) for name in CONTROLLER_FILES}
            if on_disk != files:
                raise DeliveryError("installed controller content differs from staged content")
            print(f"[controller] installed {identity}")

        for name in BUNDLE_TOOL_FILES:
            if content[name] != (target_dir / name).read_bytes():
                raise DeliveryError(f"strict contract guard: bundled {name} != trusted controller")
        if subprocess.run(
            ["python3", "-B", str(target_dir / "bamboo_cd.py"), "identity"],
            capture_output=True, text=True,
        ).stdout.strip() != identity:
            raise DeliveryError("on-VM identity command disagrees with computed identity")

        tmp_link = CURRENT_LINK.with_name(CURRENT_LINK.name + f".flip-{os.getpid()}")
        os.symlink(str(target_dir), tmp_link)
        os.replace(tmp_link, CURRENT_LINK)
        if Path(os.path.realpath(CURRENT_LINK)) != target_dir:
            raise DeliveryError("current flip verification failed")
        print(f"[controller] current -> {identity}")
        return identity, target_dir
    finally:
        shutil.rmtree(tools_dir, ignore_errors=True)


def _group_bamboo() -> int:
    import grp
    return grp.getgrnam("bamboo").gr_gid


# ---------------------------------------------------------------------------
# Bamboo client
# ---------------------------------------------------------------------------

class Bamboo:
    """Minimal Bamboo driver. Token mode uses `Authorization: Bearer`; cookie
    mode replays an exported administrator cookie string and scrapes XSRF."""

    def __init__(self, base: str, token: str | None = None, cookie: str | None = None):
        self.base = base.rstrip("/")
        self.token = token
        self.cookie = cookie

    def _headers(self, extra: dict | None = None) -> dict:
        headers = {"Accept": "application/json", "User-Agent": "release-delivery/1.0"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
            headers["X-Atlassian-Token"] = "no-check"
        if self.cookie:
            headers["Cookie"] = self.cookie
        if extra:
            headers.update(extra)
        return headers

    def request(self, method: str, path: str, *, form: dict | None = None,
                json_body: dict | None = None, expect: tuple[int, ...] = (200, 201)) -> tuple[int, str]:
        url = path if path.startswith("http") else self.base + path
        headers = self._headers()
        data = None
        if json_body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(json_body).encode()
        elif form is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            data = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in form.items()).encode()
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")
            if error.code in expect:
                return error.code, body
            raise DeliveryError(f"{method} {path} -> {error.code}: {body[:300]}") from error

    def xsrf_token(self, page_path: str = "/chain/admin/config/configureChainVariables.action?buildKey=" + PLAN_KEY) -> str:
        code, body = self.request("GET", page_path, expect=(200,))
        if code != 200:
            raise DeliveryError(f"cannot read admin page for XSRF token: HTTP {code}")
        match = (re.search(r'name="atl_token"\s+value="([^"]+)"', body)
                 or re.search(r'"atl_token","([^"]+)"', body))
        if not match:
            raise DeliveryError("admin page reachable but no XSRF token found")
        return match.group(1)


def update_plan_variables(bamboo: Bamboo, updates: dict[str, str]) -> None:
    """Full-form mimic of the admin variables widget: variableId+Key+Value and
    the row key_<id>/value_<id> fields. Plain variableValue POSTs are no-ops."""
    code, body = bamboo.request(
        "GET", f"/chain/admin/config/configureChainVariables.action?buildKey={PLAN_KEY}",
        expect=(200,),
    )
    if code != 200:
        raise DeliveryError(f"cannot read plan variables page: HTTP {code}")
    ids = dict(re.findall(r'name="key_(\d+)"\s+value="([^"]*)"', body))
    ids.update({m.group(1): m.group(2) for m in re.finditer(r'name="key_(\d+)"[^>]*value="([^"]*)"', body)})
    token_match = re.search(r'name="atl_token"\s+value="([^"]+)"', body)
    token = token_match.group(1) if token_match else ""
    for key, value in updates.items():
        variable_id = next((i for i, name in ids.items() if name == key), None)
        if variable_id is None:
            raise DeliveryError(f"plan variable {key} not found on the variables page")
        form = {
            "atl_token": token, "planKey": PLAN_KEY, "variableId": variable_id,
            "variableKey": key, "variableValue": value,
            f"key_{variable_id}": key, f"value_{variable_id}": value,
        }
        code, body = bamboo.request(
            "POST", "/build/admin/ajax/updatePlanVariable.action", form=form, expect=(200,),
        )
        if '"OK"' not in body:
            raise DeliveryError(f"plan variable {key} update failed: {body[:200]}")
        print(f"[pins] plan {key} -> {value[:16]}…")


def set_environment_variables(bamboo: Bamboo, env_id: int, updates: dict[str, str]) -> None:
    for name, value in updates.items():
        code, _ = bamboo.request(
            "POST", f"/rest/api/latest/deploy/environment/{env_id}/variable",
            json_body={"name": name, "value": value}, expect=(200, 201, 400),
        )
        if code == 400:
            # Duplicate name: the REST resource offers no update; replace it.
            bamboo.request("DELETE", f"/rest/api/latest/deploy/environment/{env_id}/variable/{name}",
                           expect=(204, 200, 404))
            bamboo.request("POST", f"/rest/api/latest/deploy/environment/{env_id}/variable",
                           json_body={"name": name, "value": value}, expect=(200, 201))
        code, body = bamboo.request(
            "GET", f"/rest/api/latest/deploy/environment/{env_id}/variable/{name}",
            expect=(200, 404),
        )
        if code != 200 or f'"value":"{value}"' not in body.replace("\\", ""):
            raise DeliveryError(f"env variable {name} verification failed: {body[:200]}")
        print(f"[pins] env {name} -> {value[:16]}…")


# ---------------------------------------------------------------------------
# Flow phases
# ---------------------------------------------------------------------------

def state_path(tag: str) -> Path:
    return DELIVERY_DIR / f"{tag}.json"


def load_state(tag: str) -> dict:
    path = state_path(tag)
    if not path.exists():
        raise DeliveryError(f"no delivery state for {tag}; run the fetch phase first")
    return json.loads(path.read_text())


def save_state(tag: str, state: dict) -> None:
    DELIVERY_DIR.mkdir(parents=True, exist_ok=True)
    path = state_path(tag)
    temporary = path.with_suffix(".pending")
    with open(temporary, "w", encoding="utf-8") as stream:
        json.dump(state, stream, sort_keys=True, indent=1)
    os.replace(temporary, path)


def cmd_fetch(args) -> dict:
    tag = args.tag
    bundle_path, _, archive_sha = fetch_release_assets(tag, DELIVERY_DIR / f"{tag}.assets")
    manifest = read_bundle_manifest(bundle_path)
    if args.commit and manifest["sha"] != args.commit:
        raise DeliveryError(f"manifest commit {manifest['sha']} != requested {args.commit}")
    if manifest["tag"] != tag:
        raise DeliveryError(f"manifest tag {manifest['tag']} != requested {tag}")
    commit = manifest["sha"]
    release_dir = RELEASES_DIR / f"{tag}-{commit[:8]}"
    release_dir.mkdir(parents=True, exist_ok=True)
    final = release_dir / ARCHIVE_NAME
    os.replace(bundle_path, final)
    os.chmod(final, 0o440)
    state = load_state(tag) if state_path(tag).exists() else {}
    state.update({"tag": tag, "commit": commit, "version": manifest.get("version"),
                  "archive_sha256": archive_sha, "release_dir": str(release_dir),
                  "binary_sha256": manifest.get("binary_sha256")})
    save_state(tag, state)
    print(f"[fetch] release_dir={release_dir} commit={commit[:12]}… sha={archive_sha[:16]}…")
    return state


def cmd_controller(args) -> dict:
    state = load_state(args.tag)
    identity, _ = install_controller(Path(state["release_dir"]) / ARCHIVE_NAME, state["commit"])
    state["controller_sha256"] = identity
    save_state(args.tag, state)
    return state


def require_cookie_session(bamboo: Bamboo) -> None:
    """Admin ajax (.action) endpoints reject PATs with a login redirect
    (probed 2026-11-22: updatePlanVariable.action -> 302 userlogin); they need
    an exported administrator session cookie. REST endpoints accept the PAT."""
    if bamboo.cookie:
        return
    if bamboo.token:
        raise DeliveryError(
            "this phase drives Bamboo admin ajax endpoints, which reject PATs "
            "(302 userlogin redirect, probed 2026-11-22); rerun with "
            "--bamboo-cookie '<exported administrator cookie header>'"
        )
    raise DeliveryError("Bamboo auth required: --bamboo-token-file or --bamboo-cookie")


def bamboo_from_args(args) -> Bamboo:
    cookie = getattr(args, "bamboo_cookie", None)
    if cookie:
        return Bamboo(BAMBOO_BASE, cookie=cookie)
    token_file = getattr(args, "bamboo_token_file", None)
    if not token_file and BAMBOO_PAT_FILE.exists():
        token_file = str(BAMBOO_PAT_FILE)
    if token_file:
        token = Path(token_file).read_text().strip()
        if not token:
            raise DeliveryError("empty bamboo token file")
        return Bamboo(BAMBOO_BASE, token=token)
    raise DeliveryError(
        f"Bamboo auth required: install the PAT at {BAMBOO_PAT_FILE} "
        "(root:bamboo 0440) or pass --bamboo-token-file/--bamboo-cookie"
    )


def cmd_pins(args) -> dict:
    state = load_state(args.tag)
    bamboo = bamboo_from_args(args)
    require_cookie_session(bamboo)
    release_dir = state["release_dir"]
    update_plan_variables(bamboo, {
        "release_tag": state["tag"],
        "release_commit": state["commit"],
        "release_archive_sha256": state["archive_sha256"],
        "release_archive_path": f"{release_dir}/{ARCHIVE_NAME}",
        "controller_sha256": state["controller_sha256"],
    })
    state["pins"] = "done"
    save_state(args.tag, state)
    return state


def latest_build_number(bamboo: Bamboo) -> int:
    code, body = bamboo.request(
        "GET", f"/rest/api/latest/result/{PLAN_KEY}?max-results=1&start-index=0", expect=(200,),
    )
    results = json.loads(body).get("results", {}).get("result", [])
    return int(results[0]["buildNumber"]) if results else 0


def cmd_intake(args) -> dict:
    state = load_state(args.tag)
    bamboo = bamboo_from_args(args)
    before = latest_build_number(bamboo)
    code, body = bamboo.request(
        "POST", f"/rest/api/latest/queue/{PLAN_KEY}?executeAllStages=true",
        json_body={}, expect=(200, 201, 400),
    )
    if code == 400:
        raise DeliveryError(f"intake queue rejected: HTTP 400: {body[:200]}")
    match = re.search(re.escape(PLAN_KEY) + r"-(\d+)", body)
    target = int(match.group(1)) if match else before + 1
    print(f"[intake] queued via REST (previous latest build #{before}); waiting for #{target}")
    for _ in range(POLL_ATTEMPTS):
        time.sleep(POLL_SECONDS)
        code, body = bamboo.request(
            "GET", f"/rest/api/latest/result/{PLAN_KEY}-{target}", expect=(200, 404),
        )
        if code == 404:
            print(f"[intake] waiting for {PLAN_KEY}-{target} to be created…")
            continue
        result = json.loads(body)
        if result.get("lifeCycleState") == "Finished":
            if result.get("buildState") != "Successful":
                raise DeliveryError(f"{PLAN_KEY}-{target} finished {result.get('buildState')}")
            state["intake_build"] = target
            save_state(args.tag, state)
            print(f"[intake] {PLAN_KEY}-{target} SUCCESSFUL")
            return state
        print(f"[intake] #{target} {result.get('lifeCycleState')}…")
    raise DeliveryError("intake polling timed out")


def cmd_release_create(args) -> dict:
    state = load_state(args.tag)
    bamboo = bamboo_from_args(args)
    name = release_version_name(state["tag"], state["commit"])
    bamboo.request(
        "POST", f"/rest/api/latest/deploy/project/{DEPLOY_PROJECT_ID}/version",
        json_body={"name": name,
                   "planResultKey": f"{PLAN_KEY}-{state['intake_build']}"},
        expect=(200, 201),
    )
    code, body = bamboo.request(
        "GET", f"/rest/api/latest/deploy/project/{DEPLOY_PROJECT_ID}/versions?max-results=20",
        expect=(200,),
    )
    for version in json.loads(body).get("versions", []):
        if version.get("name") == name:
            state["version_id"] = version["id"]
            state["version_name"] = name
            save_state(args.tag, state)
            print(f"[release] {name} -> version id {version['id']}")
            return state
    raise DeliveryError(f"release {name} not found after creation")


def deployment_approval_state(bamboo: Bamboo, version_id: int) -> str:
    code, body = bamboo.request(
        "GET", f"/rest/api/latest/deploy/version/{version_id}/status?environmentId={PRODUCTION_ENV_ID}",
        expect=(200,),
    )
    return json.loads(body).get("versionGeneralState", "UNKNOWN")


def cmd_deploy(args) -> dict:
    state = load_state(args.tag)
    bamboo = bamboo_from_args(args)
    target = args.target
    version_id = state.get("version_id")
    if not version_id:
        raise DeliveryError("no deployment version in state; run release-create first")
    approval = deployment_approval_state(bamboo, version_id)
    if approval != "APPROVED":
        raise DeliveryError(
            f"release is {approval} for Production — human approval required before deploy"
        )
    key_path = f"{KEY_DIR}/{target}-deploy.ed25519"
    set_environment_variables(bamboo, PRODUCTION_ENV_ID, {
        "approved_target": target,
        "approved_target_key_path": key_path,
    })
    code, body = bamboo.request(
        "POST",
        f"/rest/api/latest/queue/deployment?environmentId={PRODUCTION_ENV_ID}"
        f"&versionId={version_id}&executeAllStages=true",
        json_body={},
        expect=(200,),
    )
    result_id = json.loads(body).get("deploymentResultId")
    if not result_id:
        raise DeliveryError(f"deployment queue failed: {body[:200]}")
    print(f"[deploy] {target} deployment result {result_id}")
    for _ in range(POLL_ATTEMPTS):
        time.sleep(POLL_SECONDS)
        code, body = bamboo.request("GET", f"/rest/api/latest/deploy/result/{result_id}", expect=(200,))
        result = json.loads(body)
        if result.get("lifeCycleState") == "Finished":
            if result.get("deploymentState") != "SUCCESS":
                raise DeliveryError(f"deployment {result_id} finished {result.get('deploymentState')}")
            break
        print(f"[deploy] {result_id} {result.get('lifeCycleState')}…")
    else:
        raise DeliveryError("deployment polling timed out")
    set_environment_variables(bamboo, PRODUCTION_ENV_ID, {
        "approved_target": "UNAPPROVED", "approved_target_key_path": "UNAPPROVED",
    })
    state.setdefault("deployments", {})[target] = result_id
    save_state(args.tag, state)
    print(f"[deploy] {target} SUCCESS; env approved_target reset to UNAPPROVED")
    return state


def cmd_status(args) -> None:
    print(json.dumps(json.loads(state_path(args.tag).read_text()), indent=1, sort_keys=True))


def cmd_run(args) -> dict:
    state = {}
    state.update(cmd_fetch(args))
    state = cmd_controller(args)
    state = cmd_pins(args)
    state = cmd_intake(args)
    state = cmd_release_create(args)
    if args.target:
        if not args.await_approval:
            print("[run] STOPPED before deploy: approve the release in Bamboo, then run "
                  f"`release_delivery.py deploy --tag {args.tag} --target {args.target}`")
            return state
        print("[run] waiting for human approval…")
        bamboo = bamboo_from_args(args)
        for _ in range(POLL_ATTEMPTS * 3):
            if deployment_approval_state(bamboo, state["version_id"]) == "APPROVED":
                break
            time.sleep(POLL_SECONDS)
        else:
            raise DeliveryError("approval wait timed out")
        args2 = argparse.Namespace(**{**vars(args)})
        return cmd_deploy(args2)
    print(f"[run] STOPPED before deploy: approve the release, then deploy with "
          f"`release_delivery.py deploy --tag {args.tag} --target <gateway3|sub2api3>`")
    return state


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    def tag_parser(name: str, help_text: str) -> argparse.ArgumentParser:
        sub = commands.add_parser(name, help=help_text)
        sub.add_argument("--tag", required=True, help="release tag, e.g. v0.2.23-3")
        sub.add_argument("--commit", default=None, help="optional expected commit (cross-check)")
        sub.add_argument("--bamboo-token-file", default=os.environ.get("DELIVERY_BAMBOO_TOKEN_FILE"))
        sub.add_argument("--bamboo-cookie", default=os.environ.get("DELIVERY_BAMBOO_COOKIE"))
        return sub

    tag_parser("fetch", "download and verify the published bundle").set_defaults(func=cmd_fetch)
    tag_parser("controller", "reinstall the trusted controller for this release").set_defaults(func=cmd_controller)
    tag_parser("pins", "update plan and environment release pins").set_defaults(func=cmd_pins)
    tag_parser("intake", "trigger and wait for a successful intake build").set_defaults(func=cmd_intake)
    tag_parser("release-create", "create the deployment version from the intake build").set_defaults(func=cmd_release_create)
    deploy_parser = tag_parser("deploy", "run one approved production target window")
    deploy_parser.add_argument("--target", choices=("gateway3", "sub2api3"), required=True)
    deploy_parser.set_defaults(func=cmd_deploy)
    tag_parser("status", "print delivery state").set_defaults(func=cmd_status)
    run_parser = tag_parser("run", "full pre-approval chain; optionally continue after approval")
    run_parser.add_argument("--target", choices=("gateway3", "sub2api3"), default=None)
    run_parser.add_argument("--await-approval", action="store_true")
    run_parser.set_defaults(func=cmd_run)
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        args.func(args)
        return 0
    except DeliveryError as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
