#!/usr/bin/env python3
"""deploy_release.py -- runs on the controlled CI runner (NOT on the target).
Invoked by the GitHub Actions deployment job as:

    python3 release/tools/deploy_release.py --bundle release --target gateway3
    python3 release/tools/deploy_release.py --bundle release --target sub2api3

It never deploys both targets itself; each target is a separate, explicit
GitHub job per the release contract (gateway3 then sub2api3, stop sequence
on failure). This script:

  1. Verifies the release bundle's manifest/files/qualification locally
     (same logic as remote_deploy.py, imported from this directory -- both
     files ship side by side under release/tools/, so there is exactly one
     source of truth for artifact verification, not two scripts that can
     drift apart).
  2. Resolves the pinned target host identity from targets.json (shipped in
     the same bundle) -- never invents or guesses a host.
  3. Resolves SSH trust material: a pinned known_hosts file (never the
     system/user known_hosts), a fully isolated SSH config (`-F /dev/null`
     so no ambient ~/.ssh/config Host block, ProxyCommand, or ambient
     IdentityFile can apply), plus either an explicit CI deploy key
     (SUB2API_DEPLOY_SSH_KEY, used with IdentitiesOnly=yes so nothing else
     is ever tried) or an already-configured ssh-agent (SSH_AUTH_SOCK, used
     with IdentityFile=none so no default ~/.ssh/id_* file is additionally
     attempted -- only the agent's own offered identities). A missing
     key/agent is an explicit operational blocker -- this script NEVER
     reads Windows DPAPI, a browser keystore, or any other workstation
     credential store, and never copies an SSH private key into the
     repo/bundle/logs.
  4. Transfers the ENTIRE verified bundle directory into a fresh remote
     temp directory via `tar | ssh ... tar -x` (not a hand-picked subset --
     remote_deploy.py's verify_bundle_files requires every manifest.files
     entry to be present and rejects anything extra, so a partial transfer
     would always fail that check).
  5. Runs tools/remote_deploy.py on the target three times, as three
     SEPARATE SSH commands: preflight, stage, activate -- never a single
     combined "deploy" call. Each stage's exit code gates whether the next
     stage runs at all. Each stage's stdout is exactly one compact JSON
     line, parsed with a single json.loads() call (not a per-line scan,
     which can never match remote_deploy.py's actual single-line output
     format).

Python 3.9 compatible (no hashlib.file_digest, no match/case, no PEP604
unions). Stdlib only.
"""
from __future__ import annotations

# Must be set before importing remote_deploy (or anything else local):
# otherwise Python writes release/tools/__pycache__/remote_deploy*.pyc into
# the just-verified, supposedly-immutable release bundle, and the NEXT
# verify_bundle_files() call -- including remote_deploy.py's own, run on the
# target after transfer -- rejects it as an unexpected file not listed in
# manifest.files. This must be a process-wide flag set first, not an
# environment variable the caller might forget.
import sys as _sys
_sys.dont_write_bytecode = True

import argparse
import json
import os
import subprocess
import sys
import uuid
from typing import Any, Dict, List, Optional

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, SCRIPT_DIR)
import remote_deploy as rd  # noqa: E402  (shares verification logic; see module docstring)

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_BLOCKER = 2
EXIT_MANUAL_INTERVENTION = 3

REMOTE_STATE_DIR = "/var/lib/sub2api-deploy"
SSH_CONNECT_TIMEOUT = 15


class OrchestratorBlocker(Exception):
    """Mirrors remote_deploy.Blocker for the local (pre-SSH) side."""


def log(msg: str) -> None:
    sys.stderr.write("[deploy_release] %s\n" % msg)
    sys.stderr.flush()


# ---------------------------------------------------------------------------
# Local bundle verification (reuses remote_deploy's validators so both sides
# of the SSH boundary apply IDENTICAL rules, including the exact
# qualification.json schema the builder confirmed).
# ---------------------------------------------------------------------------

def verify_bundle_locally(bundle_dir: str) -> Dict[str, Any]:
    manifest, _digest = rd.load_manifest(bundle_dir)
    rd.verify_bundle_files(bundle_dir, manifest)
    rd.classify_migrations(bundle_dir, manifest)
    rd.load_and_verify_qualification(bundle_dir, manifest)

    for required_tool in ("deploy_release.py", "remote_deploy.py", "targets.json", "known_hosts"):
        rel = "tools/%s" % required_tool
        if rel not in manifest["files"]:
            raise OrchestratorBlocker("manifest.files is missing required entry %r" % rel)

    log("local bundle verification OK: tag=%s sha=%s version=%s" % (manifest["tag"], manifest["sha"], manifest["version"]))
    return manifest


# ---------------------------------------------------------------------------
# Target + SSH trust resolution
# ---------------------------------------------------------------------------

def load_target(bundle_dir: str, target: str) -> Dict[str, Any]:
    targets_path = os.path.join(bundle_dir, "tools", "targets.json")
    if not os.path.isfile(targets_path):
        raise OrchestratorBlocker("tools/targets.json missing from bundle at %s" % targets_path)
    with open(targets_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if data.get("schema") != 1:
        raise OrchestratorBlocker("targets.json schema must be 1")
    entry = (data.get("targets") or {}).get(target)
    if not entry:
        raise OrchestratorBlocker("targets.json has no entry for target %r -- missing approved target profile is an explicit operational blocker, never defaulted" % target)
    for key in ("kind", "ssh"):
        if key not in entry:
            raise OrchestratorBlocker("targets.json entry for %r is missing required key %r" % (target, key))
    ssh_cfg = entry["ssh"]
    for key in ("host", "port", "user"):
        if key not in ssh_cfg:
            raise OrchestratorBlocker("targets.json entry for %r ssh block missing %r" % (target, key))
    return entry


def resolve_known_hosts(bundle_dir: str) -> str:
    path = os.path.join(bundle_dir, "tools", "known_hosts")
    if not os.path.isfile(path):
        raise OrchestratorBlocker("tools/known_hosts missing from bundle at %s -- pinned host identities are a hard prerequisite" % path)
    return path


def resolve_ssh_key() -> Optional[str]:
    """Returns an explicit key path, or None to rely on an already-running
    ssh-agent. Raises OrchestratorBlocker if neither is available. NEVER
    reads DPAPI/browser/OS keystores and NEVER copies a key from anywhere
    else in the filesystem -- the only inputs honored are the two documented
    environment variables below, provisioned for the controlled runner by ops."""
    key_path = os.environ.get("SUB2API_DEPLOY_SSH_KEY", "").strip()
    if key_path:
        if not os.path.isfile(key_path):
            raise OrchestratorBlocker("SUB2API_DEPLOY_SSH_KEY=%s does not exist -- missing CI deploy key is an explicit operational blocker (never substituted with a workstation key)" % key_path)
        return key_path
    agent_sock = os.environ.get("SSH_AUTH_SOCK", "").strip()
    if agent_sock and os.path.exists(agent_sock):
        log("SUB2API_DEPLOY_SSH_KEY not set; relying on existing ssh-agent at SSH_AUTH_SOCK (IdentityFile=none, config isolated)")
        return None
    raise OrchestratorBlocker(
        "no CI SSH key configured: SUB2API_DEPLOY_SSH_KEY is unset and no ssh-agent is reachable "
        "(SSH_AUTH_SOCK unset or socket missing). This is an explicit operational blocker -- it is "
        "never replaced by Windows DPAPI, a workstation credential store, or a copied private key."
    )


def _ssh_common_opts(ssh_cfg: Dict[str, Any], known_hosts: str, key_path: Optional[str]) -> List[str]:
    """Options shared by ssh and scp/tar-pipe invocations. `-F /dev/null`
    ignores any ambient ~/.ssh/config or /etc/ssh/ssh_config entirely
    (killing ambient ProxyCommand/Host-alias surprises). In explicit-key
    mode, IdentitiesOnly=yes restricts to exactly that key. In agent-only
    mode, IdentityFile=none cancels OpenSSH's built-in default identity
    file search (~/.ssh/id_rsa, id_ecdsa, id_ed25519, ...) so ONLY the
    identities actually offered by the agent via SSH_AUTH_SOCK are ever
    tried -- never an unrelated ambient key that happens to exist in the
    CI runner's home directory."""
    opts = [
        "-F", "/dev/null",
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=%s" % known_hosts,
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "BatchMode=yes",
        "-o", "PreferredAuthentications=publickey",
        "-o", "ConnectTimeout=%d" % SSH_CONNECT_TIMEOUT,
    ]
    if key_path:
        opts += ["-i", key_path, "-o", "IdentitiesOnly=yes"]
    else:
        opts += ["-o", "IdentityFile=none"]
    return opts


def ssh_base_argv(ssh_cfg: Dict[str, Any], known_hosts: str, key_path: Optional[str]) -> List[str]:
    argv = ["ssh"] + _ssh_common_opts(ssh_cfg, known_hosts, key_path) + ["-p", str(ssh_cfg["port"])]
    argv.append("%s@%s" % (ssh_cfg["user"], ssh_cfg["host"]))
    return argv


def run_ssh(ssh_cfg: Dict[str, Any], known_hosts: str, key_path: Optional[str], remote_cmd: List[str],
            timeout: int = 180) -> "subprocess.CompletedProcess[bytes]":
    import shlex
    argv = ssh_base_argv(ssh_cfg, known_hosts, key_path) + [" ".join(shlex.quote(c) for c in remote_cmd)]
    log("ssh exec: %s" % " ".join(remote_cmd))
    try:
        return subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise OrchestratorBlocker("ssh command timed out after %ds: %s" % (timeout, " ".join(remote_cmd))) from exc


# ---------------------------------------------------------------------------
# Transfer -- the ENTIRE verified bundle, not a hand-picked subset.
# remote_deploy.py's verify_bundle_files requires every manifest.files
# entry present and rejects anything unexpected, so a partial transfer can
# never pass that check on the target.
# ---------------------------------------------------------------------------

def transfer_bundle(bundle_dir: str, ssh_cfg: Dict[str, Any], known_hosts: str, key_path: Optional[str],
                     target: str, run_id: str) -> str:
    remote_dir = "%s/%s/incoming-%s" % (REMOTE_STATE_DIR, target, run_id)
    mkdir_proc = run_ssh(ssh_cfg, known_hosts, key_path, ["mkdir", "-p", "-m", "700", remote_dir])
    if mkdir_proc.returncode != 0:
        raise OrchestratorBlocker("failed to create remote staging dir %s: %s" % (remote_dir, mkdir_proc.stderr.decode(errors="replace")[-1000:]))

    ssh_argv = ["ssh"] + _ssh_common_opts(ssh_cfg, known_hosts, key_path) + ["-p", str(ssh_cfg["port"]),
                "%s@%s" % (ssh_cfg["user"], ssh_cfg["host"]),
                "tar -xf - -C %s" % remote_dir]
    log("transferring full bundle (%s) -> %s via tar|ssh" % (bundle_dir, remote_dir))
    tar_proc = subprocess.Popen(["tar", "-cf", "-", "-C", bundle_dir, "."], stdout=subprocess.PIPE)
    ssh_proc = subprocess.Popen(ssh_argv, stdin=tar_proc.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    tar_proc.stdout.close()  # let tar_proc see SIGPIPE if ssh_proc exits early
    try:
        ssh_out, ssh_err = ssh_proc.communicate(timeout=600)
    except subprocess.TimeoutExpired as exc:
        tar_proc.kill()
        ssh_proc.kill()
        raise OrchestratorBlocker("bundle transfer timed out") from exc
    tar_proc.wait(timeout=30)
    if tar_proc.returncode != 0:
        raise OrchestratorBlocker("local tar failed while packing the bundle for transfer (exit %d)" % tar_proc.returncode)
    if ssh_proc.returncode != 0:
        raise OrchestratorBlocker("remote tar extraction failed (exit %d): %s" % (ssh_proc.returncode, ssh_err.decode(errors="replace")[-1000:]))
    return remote_dir


# ---------------------------------------------------------------------------
# Three bounded, explicit remote stages -- never collapsed into one call.
# ---------------------------------------------------------------------------

def run_remote_stage(stage: str, ssh_cfg: Dict[str, Any], known_hosts: str, key_path: Optional[str],
                      target: str, kind: str, remote_bundle_dir: str, run_id: str, timeout: int) -> Dict[str, Any]:
    remote_cmd = [
        "python3", "%s/tools/remote_deploy.py" % remote_bundle_dir, stage,
        "--target", target, "--kind", kind,
        "--run-id", run_id,
        "--state-dir", "%s/%s/state" % (REMOTE_STATE_DIR, target),
    ]
    if stage in ("preflight", "stage", "activate"):
        remote_cmd += ["--bundle", remote_bundle_dir]
    proc = run_ssh(ssh_cfg, known_hosts, key_path, remote_cmd, timeout=timeout)
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    sys.stderr.write(stderr)
    parsed: Optional[Dict[str, Any]] = None
    # remote_deploy.py's emit_result() writes EXACTLY one compact JSON line
    # as the last line of stdout; parse that single line directly rather
    # than scanning for lines that merely start with "{" (which can never
    # match a pretty-printed multi-line object and is fragile in general).
    lines = [l for l in stdout.splitlines() if l.strip()]
    if lines:
        try:
            parsed = json.loads(lines[-1])
        except ValueError:
            parsed = None
    return {"exit_code": proc.returncode, "stdout": stdout, "stderr": stderr, "parsed": parsed}


def classify_exit(code: int) -> str:
    if code == EXIT_OK:
        return "ok"
    if code == EXIT_BLOCKER:
        return "blocker"
    if code == EXIT_MANUAL_INTERVENTION:
        return "manual-intervention-required"
    return "failure"


def orchestrate(args: argparse.Namespace) -> int:
    bundle_dir = os.path.realpath(args.bundle)
    if not os.path.isdir(bundle_dir):
        raise OrchestratorBlocker("--bundle %s is not a directory" % bundle_dir)

    manifest = verify_bundle_locally(bundle_dir)
    target_entry = load_target(bundle_dir, args.target)
    kind = target_entry["kind"]
    ssh_cfg = target_entry["ssh"]
    known_hosts = resolve_known_hosts(bundle_dir)
    key_path = resolve_ssh_key()
    run_id = uuid.uuid4().hex

    log("target=%s kind=%s host=%s run_id=%s" % (args.target, kind, ssh_cfg["host"], run_id))

    remote_bundle_dir = transfer_bundle(bundle_dir, ssh_cfg, known_hosts, key_path, args.target, run_id)

    summary: Dict[str, Any] = {"target": args.target, "kind": kind, "run_id": run_id, "tag": manifest["tag"], "sha": manifest["sha"], "stages": {}}

    for stage, timeout in (("preflight", 180), ("stage", 900), ("activate", 300)):
        result = run_remote_stage(stage, ssh_cfg, known_hosts, key_path, args.target, kind, remote_bundle_dir, run_id, timeout)
        summary["stages"][stage] = {"exit_code": result["exit_code"], "classification": classify_exit(result["exit_code"]), "output": result["parsed"]}
        print(json.dumps(summary, indent=2))
        if result["exit_code"] != EXIT_OK:
            log("stage %s exited %d (%s) -- stopping, no further stages run" % (stage, result["exit_code"], classify_exit(result["exit_code"])))
            return result["exit_code"]

    log("deploy complete: target=%s tag=%s sha=%s" % (args.target, manifest["tag"], manifest["sha"]))
    return EXIT_OK


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="deploy_release.py", description=__doc__)
    p.add_argument("--bundle", required=True, help="path to the release bundle directory (e.g. release)")
    p.add_argument("--target", required=True, choices=["gateway3", "sub2api3"])
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        return orchestrate(args)
    except OrchestratorBlocker as exc:
        log("BLOCKER: %s" % exc)
        print(json.dumps({"ok": False, "blocker": str(exc)}, indent=2))
        return EXIT_BLOCKER
    except rd.Blocker as exc:
        log("BLOCKER: %s" % exc)
        print(json.dumps({"ok": False, "blocker": str(exc)}, indent=2))
        return EXIT_BLOCKER
    except rd.DeployFailure as exc:
        log("FAILURE: %s" % exc)
        print(json.dumps({"ok": False, "failure": str(exc)}, indent=2))
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())
