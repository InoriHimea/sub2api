#!/usr/bin/env python3
"""Bamboo intake and separately approved production deployment windows."""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import argparse
import fcntl
import hashlib
import json
import os
import stat
import tarfile
from pathlib import Path
import shutil
import tempfile
import uuid

import deploy_release as deploy
import import_release as intake

HERE = Path(__file__).resolve().parent
CONTROLLER_FILES = ("bamboo_cd.py", "bamboo_cd.sh", "import_release.py", "build_release.py",
                    "deploy_release.py", "remote_deploy.py", "targets.json", "known_hosts", "deploy.sh")
TARGETS = ("gateway3", "sub2api3")
ARCHIVE_NAME = "release-bundle.tar.gz"


def controller_identity(directory=HERE):
    files = {}
    for name in CONTROLLER_FILES:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise intake.ImportFailure("trusted controller file missing/symlinked: " + name)
        files[name] = deploy.rd.sha256_file(str(path))
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def require_controller(expected):
    if not isinstance(expected, str) or not deploy.rd.HEX64_RE.fullmatch(expected):
        raise intake.ImportFailure("independently approved controller SHA256 is required")
    if controller_identity() != expected:
        raise intake.ImportFailure("controller does not match independently approved identity")


def prepare(args):
    require_controller(args.controller_sha256)
    output = Path(os.path.abspath(args.output))
    if os.path.lexists(output):
        raise intake.ImportFailure("output already exists")
    stage = Path(tempfile.mkdtemp(prefix=".cd-prepare-", dir=output.parent))
    try:
        payload = stage / "payload"
        payload.mkdir(mode=0o700)
        archive = payload / ARCHIVE_NAME
        # Publish the exact private snapshot verified by the strict importer.
        with Path(args.archive).open("rb") as src, archive.open("xb") as dst:
            info = os.fstat(src.fileno())
            if not stat.S_ISREG(info.st_mode):
                raise intake.ImportFailure("archive must be a regular file")
            remaining = intake.MAX_ARCHIVE_BYTES
            while chunk := src.read(intake.CHUNK):
                remaining -= len(chunk)
                if remaining < 0:
                    raise intake.ImportFailure("compressed archive exceeds byte limit")
                dst.write(chunk)
        receipt = intake.import_release(archive, args.archive_sha256, args.tag,
                                        args.expected_sha, stage / "verified")
        intake._publish(payload, output)
        return receipt
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def with_downloaded_release(args, operation):
    require_controller(args.controller_sha256)
    with tempfile.TemporaryDirectory(prefix=".cd-download-", dir=Path.cwd()) as scratch:
        directory = Path(scratch) / "imported"
        receipt = intake.import_release(Path(args.archive), args.archive_sha256, args.tag,
                                        args.expected_sha, directory)
        return operation(args, receipt, str(directory / "release"))


def _save_state(path, state):
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("x", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(state, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_DIRECTORY | os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def production(args, receipt, bundle):
    target = args.target
    if target not in TARGETS:
        raise deploy.OrchestratorBlocker("one explicit production target is required")
    key = args.key_path
    if not key or not Path(key).is_absolute() or not Path(key).is_file():
        raise deploy.OrchestratorBlocker("approved absolute SSH key path missing for " + target)
    state_dir = Path(args.state_dir)
    if not args.state_dir or not state_dir.is_absolute():
        raise deploy.OrchestratorBlocker("production state directory must be an explicit absolute path")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if state_dir.is_symlink() or state_dir.stat().st_uid != os.geteuid() or state_dir.stat().st_mode & 0o077:
        raise deploy.OrchestratorBlocker("production state directory must be privately owned mode0700")
    with (state_dir / "production.lock").open("a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise deploy.OrchestratorBlocker("another production deployment holds the controller lock") from error
        path = state_dir / "production-state.json"
        if (state_dir / "production-state.json.pending").exists():
            raise deploy.OrchestratorBlocker("unknown previous journal write requires operator review")
        previous = json.loads(path.read_text()) if path.exists() else None
        identity = {key: receipt[key] for key in ("tag", "sha", "archive_sha256")}
        identity["controller_sha256"] = args.controller_sha256
        if previous is not None and (previous.get("schema") != 2 or previous.get("status") not in
                                     ("failed", "blocked", "gateway-succeeded", "succeeded")):
            raise deploy.OrchestratorBlocker("previous production attempt requires operator reconciliation")
        same_release = previous is not None and all(previous.get(k) == v for k, v in identity.items())
        completed_gateway = {"preflight": 0, "stage": 0, "activate": 0}
        if target == "sub2api3":
            if (not same_release or previous["status"] != "gateway-succeeded" or
                    previous.get("targets", {}).get("gateway3") != completed_gateway):
                raise deploy.OrchestratorBlocker("sub2api3 requires recorded gateway3 success for the identical release")
            targets = {"gateway3": previous["targets"]["gateway3"]}
        else:
            if previous is not None and (previous["status"] == "gateway-succeeded" or
                                         (same_release and previous["status"] == "succeeded")):
                raise deploy.OrchestratorBlocker("gateway3 already activated; refusing replay or release replacement")
            targets = {}
        targets[target] = {}
        state = {"schema": 2, **identity, "status": "running", "targets": targets,
                 "active_target": target, "active_phase": "admission"}
        _save_state(path, state)
        activation_attempted = False
        try:
            hosts = deploy.resolve_known_hosts(bundle)
            entry = deploy.load_target(bundle, target)
            run_id = uuid.uuid4().hex
            remote = deploy.transfer_bundle(bundle, entry["ssh"], hosts, key, target, run_id)
            for phase, timeout in (("preflight", 180), ("stage", 900), ("activate", 300)):
                state["active_phase"] = phase
                _save_state(path, state)
                if phase == "activate":
                    activation_attempted = True
                result = deploy.run_remote_stage(phase, entry["ssh"], hosts, key,
                                                 target, entry["kind"], remote, run_id, timeout)
                code = result["exit_code"]
                targets[target][phase] = code
                if code:
                    state["status"] = ("manual-intervention" if activation_attempted or code == 3 or
                                       target == "sub2api3" else "blocked" if phase == "preflight" else "failed")
                    _save_state(path, state)
                    return code
            state["status"] = "gateway-succeeded" if target == "gateway3" else "succeeded"
            _save_state(path, state)
            return 0
        except Exception:
            review = activation_attempted or target == "sub2api3"
            state["status"] = "manual-intervention" if review else "blocked"
            _save_state(path, state)
            if review:
                return 3
            raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("identity", help="print trusted controller content identity")
    prepare_parser = commands.add_parser("intake", help="validate and publish only the immutable archive")
    prepare_parser.add_argument("--output", required=True)
    verify_parser = commands.add_parser("verify", help="strictly reimport and verify a downloaded archive")
    production_parser = commands.add_parser("deploy-production", help="deploy one explicitly approved target")
    production_parser.add_argument("--target", choices=TARGETS, required=True)
    production_parser.add_argument("--key-path", required=True)
    production_parser.add_argument("--state-dir", required=True)
    for child in (prepare_parser, verify_parser, production_parser):
        child.add_argument("--archive", required=True)
        child.add_argument("--tag", required=True)
        child.add_argument("--expected-sha", required=True)
        child.add_argument("--archive-sha256", required=True)
        child.add_argument("--controller-sha256", required=True)
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if args.command == "identity":
            print(controller_identity())
            return 0
        if args.command == "intake":
            print(json.dumps(prepare(args), sort_keys=True))
            return 0
        if args.command == "verify":
            receipt = with_downloaded_release(args, lambda _args, receipt, _bundle: receipt)
            print(json.dumps(receipt, sort_keys=True))
            return 0
        return with_downloaded_release(args, production)
    except (intake.ImportFailure, deploy.OrchestratorBlocker, deploy.rd.Blocker,
            OSError, ValueError, KeyError, tarfile.TarError, EOFError) as error:
        print("[bamboo-cd] BLOCKED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
