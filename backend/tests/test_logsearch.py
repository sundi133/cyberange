import json
import unittest

from cyberrange.db import Database
from cyberrange.service import CyberRangeService


class LogSearchTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        rng = self.svc.create_range("i", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("i", "instructor", rng["id"], a)
        self.ex = self.svc.start_exercise("i", "instructor", rng["id"])["id"]
        self.svc.execute_module("i", "instructor", self.ex, "CR-MOD-PHISH-001")

    def test_attacker_view_sees_everything(self):
        res = self.svc.search_logs(self.ex, "instructor")
        self.assertFalse(res["redacted"])
        kinds = {e["kind"] for e in res["results"]}
        self.assertTrue(kinds & {"ttp-exec", "ttp-emulation"},
                        "attacker/instructor should see their own TTP events")

    def test_blue_never_sees_the_answer_key(self):
        res = self.svc.search_logs(self.ex, "blue")
        self.assertTrue(res["redacted"])
        kinds = {e["kind"] for e in res["results"]}
        self.assertFalse(kinds & {"ttp-exec", "ttp-emulation", "expected-telemetry"})
        blob = json.dumps(res["results"])
        self.assertNotIn("CR-MOD", blob, "module id leaked to blue")
        for e in res["results"]:
            self.assertIsNone(e.get("technique_id"), "technique attribution leaked to blue")

    def test_blue_source_is_a_host_not_a_module(self):
        for e in self.svc.search_logs(self.ex, "blue")["results"]:
            self.assertFalse((e.get("source") or "").startswith("module:"))

    def test_blue_still_sees_alerts_and_telemetry(self):
        self.svc.record_detection("i", "instructor", self.ex,
                                  technique_id="T1566", verdict="detected",
                                  rule_version="v1")
        kinds = {e["kind"] for e in self.svc.search_logs(self.ex, "blue")["results"]}
        self.assertIn("detection", kinds, "blue must still see alerts")

    def test_free_text_search_filters(self):
        all_logs = self.svc.search_logs(self.ex, "instructor")["count"]
        hits = self.svc.search_logs(self.ex, "instructor", q="zzz-no-such-string")
        self.assertEqual(hits["count"], 0)
        self.assertGreater(all_logs, 0)

    def test_kind_filter(self):
        res = self.svc.search_logs(self.ex, "instructor", kind="detection")
        self.assertTrue(all(e["kind"] == "detection" for e in res["results"]))

    def test_log_sources_lists_filters(self):
        meta = self.svc.log_sources(self.ex, "blue")
        self.assertIn("sources", meta)
        self.assertIn("kinds", meta)
        self.assertFalse(any(s.startswith("module:") for s in meta["sources"]))


if __name__ == "__main__":
    unittest.main()
