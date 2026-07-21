import os
import unittest

from cyberrange import execution, lifecycle, provisioning
from cyberrange.db import Database
from cyberrange.service import CyberRangeService

DOCKER = execution.docker_available()


class LifecycleResetTest(unittest.TestCase):
    """No Docker needed — just the state machine."""

    def test_reset_action_returns_to_ready(self):
        self.assertEqual(lifecycle.apply_action("READY", "reset"), "READY")
        self.assertEqual(lifecycle.apply_action("RUNNING", "reset"), "READY")
        self.assertEqual(lifecycle.apply_action("PAUSED", "reset"), "READY")

    def test_reset_illegal_before_ready(self):
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.apply_action("REQUESTED", "reset")

    def test_reset_via_service_when_not_live(self):
        svc = CyberRangeService(Database(":memory:"))  # live off by default
        rng = svc.create_range("i", "instructor", "CR-DOCKER-001")
        for a in ("preflight", "provision", "seed", "ready"):
            svc.lifecycle_action("i", "instructor", rng["id"], a)
        out = svc.lifecycle_action("i", "instructor", rng["id"], "reset")
        self.assertEqual(out["state"], "READY")


@unittest.skipUnless(DOCKER, "Docker not available")
class LiveRangeTest(unittest.TestCase):
    """Real per-range containers. Cleans up after itself."""

    def setUp(self):
        os.environ["CR_LIVE_RANGES"] = "1"
        self.svc = CyberRangeService(Database(":memory:"))
        self.rid = None

    def tearDown(self):
        os.environ.pop("CR_LIVE_RANGES", None)
        if self.rid:
            provisioning.teardown(self.rid)

    def _ready_range(self):
        rng = self.svc.create_range("red", "instructor", "CR-DOCKER-001")
        self.rid = rng["id"]
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("red", "instructor", self.rid, a)
        return rng

    def test_provision_stands_up_targets(self):
        self.assertTrue(self.svc._live_ranges)
        self._ready_range()
        self.assertTrue(provisioning.is_provisioned(self.rid))
        meta = self.svc.get_range(self.rid)["meta"]
        hostnames = {t["hostname"] for t in meta["targets"]}
        self.assertEqual(hostnames, {"victim", "webapp"})

    def test_module_runs_in_victim_and_foothold_persists(self):
        self._ready_range()
        ex = self.svc.start_exercise("red", "instructor", self.rid)
        res = self.svc.execute_module("red", "red", ex["id"], "CR-MOD-DOCKER-RUNTIME-001")
        self.assertTrue(res["real"])
        self.assertEqual(res["adapter"], "docker-exec")
        # the file written by the module persists in the victim (real foothold)
        out, _, _, _ = provisioning.exec_in_victim(
            self.rid, ["sh", "-c", "test -f /tmp/payload.sh && echo YES"])
        self.assertIn("YES", out)

    def test_web_target_reachable_over_range_network(self):
        self._ready_range()
        out, _, _, _ = provisioning.exec_in_victim(
            self.rid, ["sh", "-c", "wget -qO- http://webapp"])
        self.assertIn("vulnerable-app", out)

    def test_reset_recycles_the_foothold(self):
        self._ready_range()
        ex = self.svc.start_exercise("red", "instructor", self.rid)
        self.svc.execute_module("red", "red", ex["id"], "CR-MOD-DOCKER-RUNTIME-001")
        self.svc.lifecycle_action("red", "instructor", self.rid, "reset")
        out, _, _, _ = provisioning.exec_in_victim(
            self.rid, ["sh", "-c", "test -f /tmp/payload.sh && echo YES || echo CLEAN"])
        self.assertIn("CLEAN", out)


if __name__ == "__main__":
    unittest.main()
