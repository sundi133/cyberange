"""The flagship ransomware chain (CR-RANSOM-FLAG-001).

What this pins:

- The three new chain modules exist, are signed, and declare adapter:vm
  (so they execute real on the Proxmox tier and simulate off it).
- Each new module's log-basis detection fires on its marker line - this is
  the whole point of a detection-training range, so it is worth testing
  end-to-end rather than only on schema.
- The flagship scenario builds cleanly: every module exists, every module
  is signed, the chain's technique set lines up with its module set, and
  the chain is ordered so the containment window (inhibit-recovery /
  service-stop) comes BEFORE the impact event. If anyone reorders those,
  this test flags the regression.
"""
import unittest

from cyberrange import catalog
from cyberrange.db import Database
from cyberrange.provisioners.base import ExecResult
from cyberrange.service import CyberRangeService

NEW_MODULES = (
    "CR-MOD-INHIBIT-RECOVERY-001",
    "CR-MOD-SVCSTOP-001",
    "CR-MOD-RANSOM-NOTE-001",
)


class StubVMTier:
    name = "proxmox"

    def __init__(self, stdout=""):
        self._stdout = stdout
        self.calls = []

    def is_provisioned(self, _): return True
    def has_target(self, _r, _t): return True

    def exec_in(self, range_id, target, cmd, timeout=60):
        self.calls.append((range_id, target, tuple(cmd)))
        return ExecResult(stdout=self._stdout, stderr="", returncode=0, duration_s=0.05)

    def provision(self, range_id, with_directory=False):
        return {"network": f"vlan-{range_id}",
                "targets": [{"name": "cr-x", "hostname": "win-endpoint",
                             "role": "vm:win-endpoint"}]}

    def reset(self, _): return self.provision(_)
    def teardown(self, _): pass


def _ready_exercise(svc, scenario_id):
    rng = svc.create_range("inst", "instructor", scenario_id)
    for a in ("preflight", "provision", "seed", "ready"):
        rng = svc.lifecycle_action("inst", "instructor", rng["id"], a)
    return svc.start_exercise("inst", "instructor", rng["id"])


class RansomwareChainTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def _pin_tier(self, tier):
        self.svc._provisioner = tier
        self.svc._live_ranges = False

    def test_new_modules_are_signed_and_vm_wired(self):
        by_id = {m["id"]: m for m in catalog.modules()}
        for mid in NEW_MODULES:
            with self.subTest(module=mid):
                self.assertIn(mid, by_id, f"missing module: {mid}")
                m = by_id[mid]
                self.assertTrue(m.get("signed"))
                self.assertEqual(m.get("safety_class"), "S2")
                self.assertEqual((m.get("execution") or {}).get("adapter"), "vm")

    def test_inhibit_recovery_marker_fires_log_detection(self):
        tier = StubVMTier(stdout="[inhibit-recovery] shadow-copy deletion pattern\n")
        self._pin_tier(tier)
        ex = _ready_exercise(self.svc, "CR-RANSOM-FLAG-001")
        result = self.svc.execute_module(
            "inst", "instructor", ex["id"],
            "CR-MOD-INHIBIT-RECOVERY-001", in_lesson=True)
        self.assertTrue(result["real"])
        fired = {d["rule_id"] for d in result["detections"]}
        self.assertIn("DR-INHIBIT-RECOVERY-LOG", fired,
                      f"inhibit-recovery rule did not fire; got {fired}")

    def test_svcstop_marker_fires_log_detection(self):
        tier = StubVMTier(stdout="[svcstop] backup/EDR service-stop pattern\n")
        self._pin_tier(tier)
        ex = _ready_exercise(self.svc, "CR-RANSOM-FLAG-001")
        result = self.svc.execute_module(
            "inst", "instructor", ex["id"],
            "CR-MOD-SVCSTOP-001", in_lesson=True)
        fired = {d["rule_id"] for d in result["detections"]}
        self.assertIn("DR-SVCSTOP-LOG", fired)

    def test_ransom_note_marker_fires_log_detection(self):
        tier = StubVMTier(stdout="[ransom-note] lab-only drop pattern\n")
        self._pin_tier(tier)
        ex = _ready_exercise(self.svc, "CR-RANSOM-FLAG-001")
        result = self.svc.execute_module(
            "inst", "instructor", ex["id"],
            "CR-MOD-RANSOM-NOTE-001", in_lesson=True)
        fired = {d["rule_id"] for d in result["detections"]}
        self.assertIn("DR-RANSOM-NOTE-LOG", fired)

    def test_flagship_scenario_builds_from_signed_modules(self):
        scn = {s["id"]: s for s in catalog.scenarios()}
        self.assertIn("CR-RANSOM-FLAG-001", scn)
        s = scn["CR-RANSOM-FLAG-001"]
        by_id = {m["id"]: m for m in catalog.modules()}
        for mid in s["module_ids"]:
            with self.subTest(module=mid):
                self.assertIn(mid, by_id)
                self.assertTrue(by_id[mid].get("signed"),
                                f"scenario would run unsigned module {mid}")

    def test_chain_order_puts_containment_before_impact(self):
        """The teaching value depends on this ordering."""
        s = next(x for x in catalog.scenarios() if x["id"] == "CR-RANSOM-FLAG-001")
        order = s["module_ids"]
        inhibit = order.index("CR-MOD-INHIBIT-RECOVERY-001")
        svcstop = order.index("CR-MOD-SVCSTOP-001")
        impact = order.index("CR-MOD-IMPACT-001")
        self.assertLess(inhibit, impact,
                        "inhibit-recovery must come before impact "
                        "(it is the containment window)")
        self.assertLess(svcstop, impact,
                        "service-stop must come before impact "
                        "(it is the containment window)")

    def test_scenario_techniques_are_covered_by_its_modules(self):
        """A scenario's technique_ids claim what it exercises; the modules it
        runs must actually be mapped to those techniques, or the claim is wrong."""
        s = next(x for x in catalog.scenarios() if x["id"] == "CR-RANSOM-FLAG-001")
        by_id = {m["id"]: m for m in catalog.modules()}
        module_techs = set()
        for mid in s["module_ids"]:
            module_techs.update(by_id[mid].get("technique_ids", []))
        missing = set(s["technique_ids"]) - module_techs
        self.assertFalse(
            missing,
            f"scenario claims techniques its modules do not run: {missing}")


if __name__ == "__main__":
    unittest.main()
