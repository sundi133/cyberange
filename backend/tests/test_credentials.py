import unittest
from datetime import datetime, timedelta, timezone

from cyberrange import rbac
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError


def _iso(delta_s):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_s)).isoformat()


class CredentialsTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        self.svc.create_user("admin", "admin", "learner1", "pw-learner1", "red",
                             display_name="Learner One")
        # A live competition with one solvable challenge, solved by the learner.
        c = self.svc.competitions
        comp = c.create("admin", "admin", name="Quals", mode="ctf",
                        start_at=_iso(-60), end_at=_iso(3600), published=True)
        ch = c.add_challenge("admin", "admin", comp["id"], title="Map it",
                             flag="T1059", category="detection", technique_id="T1059",
                             points=150)
        res = c.submit_flag("learner1", "red", comp["id"], ch["id"], "T1059")
        self.assertTrue(res["correct"])

    # ---- skills aggregation ----
    def test_skills_reflect_solved_work(self):
        sk = self.svc.credentials.skills("learner1", "red")
        self.assertEqual(sk["username"], "learner1")
        self.assertEqual(sk["stats"]["labs_solved"], 1)
        self.assertIn("T1059", sk["techniques"])
        self.assertEqual(sk["stats"]["techniques_demonstrated"], 1)
        # T1059 maps to a NICE role in the crosswalk, so coverage is non-empty.
        self.assertTrue(sk["framework_coverage"]["nice"])

    def test_learner_cannot_see_another_profile(self):
        with self.assertRaises(rbac.AuthorizationError):
            self.svc.credentials.skills("learner1", "red", "admin")

    def test_instructor_can_view_learner(self):
        sk = self.svc.credentials.skills("admin", "admin", "learner1")
        self.assertEqual(sk["stats"]["labs_solved"], 1)

    # ---- certificates ----
    def test_issue_requires_manage(self):
        with self.assertRaises(rbac.AuthorizationError):
            self.svc.credentials.issue("learner1", "red", username="learner1")

    def test_issue_and_verify(self):
        cert = self.svc.credentials.issue("admin", "admin", username="learner1")
        self.assertEqual(cert["username"], "learner1")
        self.assertTrue(cert["verify_code"])
        self.assertEqual(cert["meta"]["stats"]["techniques_demonstrated"], 1)
        # Public verify returns an attestation, not internals.
        v = self.svc.credentials.verify(cert["verify_code"])
        self.assertTrue(v["valid"])
        self.assertEqual(v["holder"], "Learner One")
        self.assertEqual(v["techniques_demonstrated"], 1)
        self.assertNotIn("verify_code", v)

    def test_verify_unknown_code(self):
        self.assertFalse(self.svc.credentials.verify("deadbeef")["valid"])

    def test_cohort_certificate_needs_subject(self):
        with self.assertRaises(ServiceError):
            self.svc.credentials.issue("admin", "admin", username="learner1", kind="cohort")

    def test_renderers_produce_docx(self):
        from cyberrange import reporting
        sk = self.svc.credentials.skills("admin", "admin", "learner1")
        cert = self.svc.credentials.issue("admin", "admin", username="learner1")
        self.assertTrue(reporting.skills_report_docx(sk).startswith(b"PK"))
        self.assertTrue(reporting.certificate_docx(cert).startswith(b"PK"))


if __name__ == "__main__":
    unittest.main()
