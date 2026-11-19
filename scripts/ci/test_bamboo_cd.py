"""Hermetic controller regressions; run on Linux with python3 -B this_file.

Real offline intake, publication, controller identities and persistent journals;
only the SSH transfer/remote execution boundary is replaced. No production I/O.
"""
import sys
sys.dont_write_bytecode = True

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

# fcntl and no-replace publication require the controlled Linux agent.
if sys.platform.startswith("linux"):
    import bamboo_cd as cd
    from test_deploy_release import build_fixture_bundle
else:
    cd = None


@unittest.skipUnless(sys.platform.startswith("linux"), "controlled Linux deployment agent required")
class ControllerBehaviorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bamboo-cd-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        bundle = self.root / "fixture"
        bundle.mkdir()
        manifest = build_fixture_bundle(bundle)
        for name in cd.intake.build.DEPLOY_TOOL_FILES:
            shutil.copyfile(cd.HERE / name, bundle / "tools" / name)
        manifest["files"] = {
            p.relative_to(bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in bundle.rglob("*") if p.is_file() and p.name != "manifest.json"
        }
        (bundle / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        archive = self.root / "release.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(bundle, arcname="release")
        self.args = argparse.Namespace(
            archive=str(archive), output=str(self.root / "imported"),
            import_dir=str(self.root / "imported"), archive_sha256=hashlib.sha256(archive.read_bytes()).hexdigest(),
            tag="v1.0.0", expected_sha="a" * 40, controller_sha256=cd.controller_identity(),
            state_dir=str(self.root / "state"),
            target="gateway3", key_path=str(self.root / "fixture.key"))
        Path(self.args.key_path).write_bytes(b"fixture-only-not-an-SSH-key")
        Path(self.args.key_path).chmod(0o600)
        self.events = []
        self.results = {}
        self.addCleanup(mock.patch.stopall)
        mock.patch.object(cd.deploy, "transfer_bundle", side_effect=self.transfer).start()
        mock.patch.object(cd.deploy, "run_remote_stage", side_effect=self.remote).start()

    def transfer(self, bundle, ssh, hosts, key, target, run_id):
        self.assertTrue(Path(bundle, "manifest.json").is_file())
        self.assertTrue(Path(hosts).is_file())
        self.assertEqual(target, self.args.target)
        self.events.append((target, "transfer"))
        return "/fixture/incoming-" + run_id

    def remote(self, phase, ssh, hosts, key, target, kind, remote, run_id, timeout):
        self.events.append((target, phase))
        # Observe the durable intent before a remote mutating operation starts.
        if phase in ("stage", "activate"):
            saved = self.state()
            self.assertEqual(saved["status"], "running")
            self.assertEqual((saved["active_target"], saved["active_phase"]), (target, phase))
            self.assertEqual(saved["targets"][target]["preflight"], 0)
        outcome = self.results.get((target, phase), 0)
        if isinstance(outcome, Exception):
            raise outcome
        return {"exit_code": outcome}

    def state(self):
        return json.loads(Path(self.args.state_dir, "production-state.json").read_text())

    def prepared(self):
        receipt = cd.prepare(self.args)
        self.args.archive = str(Path(self.args.output) / cd.ARCHIVE_NAME)
        return receipt

    def production(self, args=None):
        return cd.with_downloaded_release(args or self.args, cd.production)

    def assert_replay_blocked(self):
        before = list(self.events)
        with self.assertRaises(cd.deploy.OrchestratorBlocker):
            self.production()
        self.assertEqual(self.events, before)

    def test_separate_windows_requires_first_success_and_blocks_replay(self):
        receipt = self.prepared()
        self.args.target = "sub2api3"
        self.assert_replay_blocked()
        self.args.target = "gateway3"
        self.assertEqual(self.production(), 0)
        self.assertEqual(self.events, [("gateway3", phase) for phase in
                                      ("transfer", "preflight", "stage", "activate")])
        self.assertEqual(self.state()["status"], "gateway-succeeded")
        self.assert_replay_blocked()
        self.args.target = "sub2api3"
        self.assertEqual(self.production(), 0)
        self.assertEqual(self.events[4:], [("sub2api3", phase) for phase in
                                          ("transfer", "preflight", "stage", "activate")])
        state = self.state()
        self.assertEqual(state["status"], "succeeded")
        self.assertEqual((state["tag"], state["sha"], state["archive_sha256"]),
                         (receipt["tag"], receipt["sha"], receipt["archive_sha256"]))
        self.assert_replay_blocked()

    def test_sub2api3_refuses_valid_release_with_different_archive_identity(self):
        self.prepared()
        self.assertEqual(self.production(), 0)
        # Recompress the same tar stream with a different gzip header.
        archive = Path(self.args.archive)
        data = bytearray(archive.read_bytes())
        data[4] ^= 1
        altered = self.root / "other.tar.gz"
        altered.write_bytes(data)
        self.args.archive = str(altered)
        self.args.archive_sha256 = hashlib.sha256(data).hexdigest()
        self.args.target = "sub2api3"
        self.assert_replay_blocked()

    def test_gateway_stage_failure_stops_second_target_without_activation(self):
        self.prepared()
        self.results[("gateway3", "stage")] = 2
        self.assertEqual(self.production(), 2)
        self.assertEqual(self.events[-1], ("gateway3", "stage"))
        self.assertNotIn(("gateway3", "activate"), self.events)
        self.assertNotIn(("sub2api3", "stage"), self.events)
        self.assertEqual(self.state()["status"], "failed")

    def test_gateway_activation_failure_stops_second_target_and_blocks_replay(self):
        self.prepared()
        self.results[("gateway3", "activate")] = 2
        self.assertEqual(self.production(), 2)
        self.assertNotIn(("sub2api3", "stage"), self.events)
        self.assertEqual(self.state()["status"], "manual-intervention")
        self.assert_replay_blocked()

    def test_activation_exception_is_unknown_and_blocks_replay(self):
        self.prepared()
        self.results[("gateway3", "activate")] = OSError("fixture connection lost after activation")
        self.assertEqual(self.production(), 3)
        self.assertEqual(self.state()["status"], "manual-intervention")
        self.assertNotIn("activate", self.state()["targets"]["gateway3"])
        self.assertNotIn(("sub2api3", "stage"), self.events)
        self.assert_replay_blocked()

    def test_manual_intervention_code_before_activation_also_blocks_replay(self):
        self.prepared()
        self.results[("gateway3", "stage")] = 3
        self.assertEqual(self.production(), 3)
        self.assertEqual(self.state()["status"], "manual-intervention")
        self.assert_replay_blocked()

    def test_partial_rollout_second_stage_failure_never_replays_first_host(self):
        self.prepared()
        self.assertEqual(self.production(), 0)
        self.args.target = "sub2api3"
        self.results[("sub2api3", "stage")] = 2
        self.assertEqual(self.production(), 2)
        self.assertEqual(self.state()["targets"]["gateway3"]["activate"], 0)
        self.assertEqual(self.state()["status"], "manual-intervention")
        self.assertNotIn(("sub2api3", "activate"), self.events)
        self.assert_replay_blocked()

    def test_partial_rollout_second_stage_exception_blocks_replay(self):
        self.prepared()
        self.assertEqual(self.production(), 0)
        self.args.target = "sub2api3"
        self.results[("sub2api3", "stage")] = OSError("fixture staging transport lost")
        self.assertEqual(self.production(), 3)
        self.assertEqual(self.state()["targets"]["gateway3"]["activate"], 0)
        self.assertEqual(self.state()["status"], "manual-intervention")
        self.assert_replay_blocked()

    def test_second_activation_manual_code_preserves_partial_success_and_blocks_replay(self):
        self.prepared()
        self.assertEqual(self.production(), 0)
        self.args.target = "sub2api3"
        self.results[("sub2api3", "activate")] = 3
        self.assertEqual(self.production(), 3)
        self.assertEqual(self.state()["targets"]["gateway3"]["activate"], 0)
        self.assertEqual(self.state()["targets"]["sub2api3"]["activate"], 3)
        self.assertEqual(self.state()["status"], "manual-intervention")
        self.assert_replay_blocked()

    def test_pending_journal_blocks_all_remote_work(self):
        self.prepared()
        directory = Path(self.args.state_dir)
        directory.mkdir(mode=0o700)
        (directory / "production-state.json.pending").write_bytes(b"unknown interrupted write")
        self.assert_replay_blocked()
        self.assertEqual(self.events, [])

    def test_intake_rejects_each_independent_pin_without_publishing(self):
        for field, value in (("tag", "v9.0.0"), ("expected_sha", "b" * 40),
                             ("archive_sha256", "0" * 64), ("controller_sha256", "0" * 64)):
            with self.subTest(pin=field):
                args = argparse.Namespace(**vars(self.args))
                setattr(args, field, value)
                with self.assertRaises(cd.intake.ImportFailure):
                    cd.prepare(args)
                self.assertFalse(os.path.lexists(args.output))
                self.assertEqual(list(self.root.glob(".cd-prepare-*")), [])
        self.assertEqual(self.events, [])

    def test_empty_and_relative_journal_locations_are_rejected_before_remote_work(self):
        self.prepared()
        for location in ("", ".", "relative-controller-state"):
            with self.subTest(location=location):
                args = argparse.Namespace(**vars(self.args))
                args.state_dir = location
                with self.assertRaises(cd.deploy.OrchestratorBlocker):
                    self.production(args)
        self.assertEqual(self.events, [])

    def test_production_rejects_each_independent_pin_before_remote_work(self):
        self.prepared()
        for field, value in (("tag", "v9.0.0"), ("expected_sha", "b" * 40),
                             ("archive_sha256", "0" * 64), ("controller_sha256", "0" * 64)):
            with self.subTest(pin=field):
                args = argparse.Namespace(**vars(self.args))
                setattr(args, field, value)
                with self.assertRaises(cd.intake.ImportFailure):
                    self.production(args)
                self.assertFalse(Path(args.state_dir).exists())
        self.assertEqual(self.events, [])

    def test_native_download_mode_is_irrelevant_but_bytes_are_verified(self):
        receipt = self.prepared()
        archive = Path(self.args.archive)
        self.assertEqual(list(archive.parent.iterdir()), [archive])
        archive.chmod(0o711)
        observed = cd.with_downloaded_release(self.args, lambda _, value, bundle: (
            value, stat.S_IMODE(Path(bundle, "sub2api").stat().st_mode)))
        self.assertEqual(observed, (receipt, 0o755))
        with archive.open("ab") as stream:
            stream.write(b"changed")
        with self.assertRaises(cd.intake.ImportFailure):
            self.production()
        self.assertEqual(self.events, [])

    def test_prepared_output_is_never_replaced(self):
        self.prepared()
        archive = Path(self.args.archive)
        original = archive.read_bytes()
        with self.assertRaises(cd.intake.ImportFailure):
            self.prepared()
        self.assertEqual(archive.read_bytes(), original)

    def test_existing_dangling_output_symlink_is_not_followed_or_replaced(self):
        output = Path(self.args.output)
        destination = self.root / "operator-owned-missing"
        output.symlink_to(destination, target_is_directory=True)
        with self.assertRaises(cd.intake.ImportFailure):
            self.prepared()
        self.assertTrue(output.is_symlink())
        self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
