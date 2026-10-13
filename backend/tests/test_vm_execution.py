"""The Windows/AD VM-execution path.

A module with ``execution.adapter == "vm"`` must route through the configured
VM tier (``tier.exec_in(range, target, cmd)``), produce real ``process-output``
events from the captured stdout, and fire a log-basis detection whose regex
matches those lines - this is what makes the Windows/AD content fire on
telemetry rather than only on coverage counters. Off-tier (no live target),
the service must simulate instead of raising.

The Proxmox adapter itself is covered by tests.test_proxmox; this test is
about the service wiring between an ``adapter:vm`` module and the detection
engine.
"""

import unittest

from cyberrange import catalog
from cyberrange.db import Database
from cyberrange.provisioners.base import ExecResult
from cyberrange.service import CyberRangeService


class StubVMTier:
    """Minimal stand-in for a VM provisioner, with configurable stdout."""

    name = "proxmox"

    def __init__(self, stdout: str = "", up_targets=("win-endpoint", "directory")):
        self._stdout = stdout
        self._up = set(up_targets)
        self.calls = []

    def is_provisioned(self, range_id): return True
    def has_target(self, range_id, target): return target in self._up

    def exec_in(self, range_id, target, cmd, timeout=60):
        self.calls.append((range_id, target, tuple(cmd)))
        return ExecResult(stdout=self._stdout, stderr="", returncode=0, duration_s=0.05)

    def provision(self, range_id, with_directory=False):
        return {"network": f"vlan-{range_id}",
                "targets": [{"name": "cr-x", "hostname": t, "role": f"vm:{t}"}
                            for t in sorted(self._up)]}

    def reset(self, range_id): return self.provision(range_id)
    def teardown(self, range_id): pass


def _mint_ready_exercise(svc, scenario_id):
    rng = svc.create_range("inst", "instructor", scenario_id)
    for a in ("preflight", "provision", "seed", "ready"):
        rng = svc.lifecycle_action("inst", "instructor", rng["id"], a)
    return svc.start_exercise("inst", "instructor", rng["id"])


class VMExecutionTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def _pin_tier(self, tier):
        # Simulate the environment picking the VM tier at startup.
        self.svc._provisioner = tier
        self.svc._live_ranges = False  # VM path doesn't need the docker flag

    # ---- schema: the upgraded Windows modules carry a vm spec ------------
    def test_windows_modules_declare_vm_execution(self):
        wanted = {
            "CR-MOD-EXEC-WIN-001", "CR-MOD-PERSIST-WIN-001", "CR-MOD-PRIVESC-WIN-001",
            "CR-MOD-EVADE-WIN-001", "CR-MOD-CRED-WIN-001", "CR-MOD-DISC-WIN-001",
            "CR-MOD-LATERAL-WIN-001", "CR-MOD-IMPACT-001", "CR-MOD-IDENT-001",
        }
        by_id = {m["id"]: m for m in catalog.modules()}
        for mid in wanted:
            with self.subTest(module=mid):
                m = by_id[mid]
                spec = (m.get("execution") or {})
                self.assertEqual(spec.get("adapter"), "vm",
                                 f"{mid} is still sim-only (no vm execution spec)")
                self.assertIn(spec.get("target"), ("win-endpoint", "directory"))

    def test_new_ad_modules_are_present_and_signed(self):
        new_ids = {"CR-MOD-KERBEROAST-001", "CR-MOD-ASREP-001",
                   "CR-MOD-REPL-EXPOSURE-001", "CR-MOD-NTLM-LATERAL-001"}
        by_id = {m["id"]: m for m in catalog.modules()}
        self.assertTrue(new_ids.issubset(by_id), f"missing: {new_ids - set(by_id)}")
        for mid in new_ids:
            self.assertTrue(by_id[mid].get("signed"),
                            f"{mid} must be signed to be executable")
            self.assertEqual(by_id[mid].get("execution", {}).get("adapter"), "vm")

    # ---- routing: adapter:vm goes through tier.exec_in -------------------
    def test_vm_module_routes_through_tier_and_fires_log_detection(self):
        # The AS-REP module emits a line that starts with '[asrep]', which the
        # DR-ASREP-LOG rule matches on. We feed exactly one such line as the
        # VM's stdout and assert both the real event and the detection.
        stdout = "[asrep] preauth-disabled enumeration pattern\n"
        tier = StubVMTier(stdout=stdout)
        self._pin_tier(tier)

        ex = _mint_ready_exercise(self.svc, "CR-ADATTACK-001")
        result = self.svc.execute_module(
            "inst", "instructor", ex["id"], "CR-MOD-ASREP-001", in_lesson=True)

        # tier was actually called, and with the module's cmd
        self.assertEqual(len(tier.calls), 1)
        _, target, cmd = tier.calls[0]
        self.assertEqual(target, "directory")
        self.assertIn("powershell", cmd[0].lower())

        # the ExecutionResult carries real=true from tier output
        self.assertTrue(result["real"], "vm execution must report real, not simulated")
        self.assertEqual(result["adapter"], "proxmox-exec")

        # a log-basis detection fired on the captured line
        fired = {d["rule_id"] for d in result["detections"]}
        self.assertIn("DR-ASREP-LOG", fired,
                      f"log-basis rule did not fire; detections were {fired}")

    def test_vm_module_simulates_when_target_is_down(self):
        # Same module, but the stub reports no 'directory' target up.
        tier = StubVMTier(up_targets=())
        self._pin_tier(tier)
        ex = _mint_ready_exercise(self.svc, "CR-ADATTACK-001")
        result = self.svc.execute_module(
            "inst", "instructor", ex["id"], "CR-MOD-ASREP-001", in_lesson=True)
        # Off-tier: no exec_in call, no crash, and a sim-basis detection fires
        self.assertEqual(tier.calls, [])
        self.assertFalse(result["real"],
                         "with no live target the service must simulate, not fail")
        fired = {d["rule_id"] for d in result["detections"]}
        self.assertIn("DR-ASREP-SIM", fired,
                      f"sim fallback did not fire; detections were {fired}")

    # ---- content: the flagship AD scenario is well-formed ----------------
    def test_ad_attack_scenario_builds_from_signed_modules(self):
        scn = {s["id"]: s for s in catalog.scenarios()}
        self.assertIn("CR-ADATTACK-001", scn)
        s = scn["CR-ADATTACK-001"]
        by_id = {m["id"]: m for m in catalog.modules()}
        for mid in s["module_ids"]:
            self.assertIn(mid, by_id, f"scenario refs unknown module {mid}")
            self.assertTrue(by_id[mid].get("signed"),
                            f"scenario would run unsigned module {mid}")


if __name__ == "__main__":
    unittest.main()
