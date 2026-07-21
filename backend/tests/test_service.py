import unittest

from cyberrange import rbac
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError


class ServiceTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def _ready_range(self):
        rng = self.svc.create_range("inst", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            rng = self.svc.lifecycle_action("inst", "instructor", rng["id"], a)
        return rng

    def test_full_exercise_flow(self):
        rng = self._ready_range()
        self.assertEqual(rng["state"], "READY")
        ex = self.svc.start_exercise("inst", "instructor", rng["id"])
        self.svc.execute_module("red", "red", ex["id"], "CR-MOD-PHISH-001")
        self.svc.submit_evidence("blue", "blue", ex["id"], description="alert triaged")
        self.svc.record_detection("blue", "blue", ex["id"], technique_id="T1566",
                                  verdict="detected", rule_version="v1")
        report = self.svc.build_report(ex["id"])
        self.assertIn("T1566", report["coverage"]["observed"])
        self.assertIn("T1566", report["coverage"]["detected"])

    def test_unsigned_or_prohibited_blocked(self):
        rng = self._ready_range()
        ex = self.svc.start_exercise("inst", "instructor", rng["id"])
        with self.assertRaises(ServiceError):
            self.svc.execute_module("red", "red", ex["id"], "NON-EXISTENT")

    def test_s2_requires_privilege(self):
        rng = self.svc.create_range("inst", "instructor", "CR-RANSOM-001")
        for a in ("preflight", "provision", "seed", "ready"):
            rng = self.svc.lifecycle_action("inst", "instructor", rng["id"], a)
        ex = self.svc.start_exercise("inst", "instructor", rng["id"])
        # red role cannot run an S2 module (canary encryption)
        with self.assertRaises(ServiceError):
            self.svc.execute_module("red", "red", ex["id"], "CR-MOD-IMPACT-001")
        # instructor can
        res = self.svc.execute_module("inst", "instructor", ex["id"], "CR-MOD-IMPACT-001")
        self.assertEqual(res["executed"], "CR-MOD-IMPACT-001")

    def test_rbac_blocks_range_create_for_blue(self):
        with self.assertRaises(rbac.AuthorizationError):
            self.svc.create_range("blue", "blue", "CR-PHISH-001")

    def test_illegal_lifecycle_returns_conflict(self):
        rng = self.svc.create_range("inst", "instructor", "CR-PHISH-001")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.lifecycle_action("inst", "instructor", rng["id"], "start")
        self.assertEqual(ctx.exception.status, 409)

    def test_quarantine_release_admin_only(self):
        rng = self._ready_range()
        self.svc.lifecycle_action("inst", "instructor", rng["id"], "start")
        self.svc.lifecycle_action("inst", "instructor", rng["id"], "quarantine")
        # instructor cannot destroy a quarantined range
        with self.assertRaises(ServiceError):
            self.svc.lifecycle_action("inst", "instructor", rng["id"], "destroy")
        # admin can
        out = self.svc.lifecycle_action("adm", "admin", rng["id"], "destroy")
        self.assertEqual(out["state"], "DESTROYED")

    def test_evidence_integrity_hash(self):
        rng = self._ready_range()
        ex = self.svc.start_exercise("inst", "instructor", rng["id"])
        ev = self.svc.submit_evidence("blue", "blue", ex["id"], description="hash me")
        self.assertEqual(len(ev["integrity_hash"]), 64)

    def test_audit_records_actions(self):
        rng = self.svc.create_range("inst", "instructor", "CR-PHISH-001")
        log = self.svc.audit_log()
        self.assertTrue(any(a["action"] == "range:create" for a in log))


if __name__ == "__main__":
    unittest.main()
