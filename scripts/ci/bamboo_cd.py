#!/usr/bin/env python3
"""Bamboo-only release intake and ordered deployment of TWO production targets."""
from __future__ import annotations
import sys
sys.dont_write_bytecode = True
import argparse
import fcntl
import hashlib
import json
import os
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
        receipt = intake.import_release(Path(args.archive), args.archive_sha256, args.tag,
                                        args.expected_sha, payload)
        controller = payload / "controller"
        controller.mkdir(mode=0o700)
        for name in CONTROLLER_FILES:
            shutil.copyfile(HERE / name, controller / name)
            (controller / name).chmod(0o755 if name.endswith(".sh") else 0o644)
        if controller_identity(controller) != args.controller_sha256:
            raise intake.ImportFailure("controller changed while preparing snapshot")
        intake._publish(payload, output)
        return receipt
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def verify(args):
    require_controller(args.controller_sha256)
    receipt = intake.verify_import(Path(args.import_dir))
    if (receipt["tag"], receipt["sha"], receipt["archive_sha256"]) != (
            args.tag, args.expected_sha, args.archive_sha256):
        raise intake.ImportFailure("import differs from independently approved production release")
    return receipt


def _save_state(path, state):
    temporary = path.with_name(path.name + ".pending")
    with temporary.open("w", encoding="utf-8") as stream:
        os.chmod(temporary, 0o600)
        json.dump(state, stream, sort_keys=True, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def production(args):
    receipt = verify(args)
    keys = {"gateway3": args.gateway3_key_path, "sub2api3": args.sub2api3_key_path}
    for target, key in keys.items():
        if not key or not Path(key).is_file():
            raise deploy.OrchestratorBlocker("approved dedicated SSH key path missing for " + target)
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
        if path.exists():
            previous = json.loads(path.read_text())
            if previous.get("status") in ("running", "manual-intervention"):
                raise deploy.OrchestratorBlocker("previous production attempt requires operator reconciliation")
        state = {"schema": 1, "tag": receipt["tag"], "sha": receipt["sha"],
                 "archive_sha256": receipt["archive_sha256"], "status": "running", "targets": {}}
        _save_state(path, state)
        bundle = str(Path(args.import_dir).resolve() / "release")
        hosts = deploy.resolve_known_hosts(bundle)
        contexts = {}
        phase = "admission"
        activation_attempted = False
        try:
            # Admit BOTH production targets before staging/activation of either.
            for target in TARGETS:
                entry = deploy.load_target(bundle, target)
                run_id = uuid.uuid4().hex
                remote = deploy.transfer_bundle(bundle, entry["ssh"], hosts, keys[target], target, run_id)
                contexts[target] = (entry, run_id, remote)
                state["targets"][target] = {}
                result = deploy.run_remote_stage("preflight", entry["ssh"], hosts, keys[target],
                                                 target, entry["kind"], remote, run_id, 180)
                state["targets"][target]["preflight"] = result["exit_code"]
                if result["exit_code"]:
                    state["status"] = "blocked"
                    _save_state(path, state)
                    return result["exit_code"]
            for target in TARGETS:
                entry, run_id, remote = contexts[target]
                for phase, timeout in (("stage", 900), ("activate", 300)):
                    state["active_target"] = target
                    state["active_phase"] = phase
                    _save_state(path, state)
                    if phase == "activate":
                        activation_attempted = True
                    result = deploy.run_remote_stage(phase, entry["ssh"], hosts, keys[target],
                                                     target, entry["kind"], remote, run_id, timeout)
                    code = result["exit_code"]
                    state["targets"][target][phase] = code
                    if code:
                        # Once either host may have changed, retrying the whole
                        # rollout is unsafe, including a later staging failure.
                        state["status"] = "manual-intervention" if activation_attempted or code == 3 else "failed"
                        _save_state(path, state)
                        return code
            state["status"] = "succeeded"
            _save_state(path, state)
            return 0
        except Exception:
            state["status"] = "manual-intervention" if activation_attempted else "blocked"
            _save_state(path, state)
            if activation_attempted:
                return 3
            raise


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("identity", help="print trusted controller content identity")
    prepare_parser = commands.add_parser("intake", help="offline import, verify and snapshot trusted controller")
    prepare_parser.add_argument("--archive", required=True)
    prepare_parser.add_argument("--output", required=True)
    for name in ("verify", "deploy-production"):
        child = commands.add_parser(name)
        child.add_argument("--import-dir", required=True)
        if name == "deploy-production":
            child.add_argument("--gateway3-key-path", required=True)
            child.add_argument("--sub2api3-key-path", required=True)
            child.add_argument("--state-dir", required=True)
    for child in (prepare_parser, commands.choices["verify"], commands.choices["deploy-production"]):
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
            print(json.dumps(verify(args), sort_keys=True))
            return 0
        return production(args)
    except (intake.ImportFailure, deploy.OrchestratorBlocker, deploy.rd.Blocker,
            OSError, ValueError, KeyError) as error:
        print("[bamboo-cd] BLOCKED: " + str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
