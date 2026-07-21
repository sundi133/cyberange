import unittest
from datetime import datetime, timezone

from cyberrange import catalog, detection, execution
from cyberrange.db import Database
from cyberrange.service import CyberRangeService

DOCKER = execution.docker_available()


class RuleEngineTest(unittest.TestCase):
    def test_log_rule_matches_real_line(self):
        rules = catalog.detection_rules()
        events = [{"id": 1, "kind": "process-output", "technique_id": None,
                   "ts_utc": "2026-07-21T00:00:00+00:00",
                   "payload": {"line": "--- spawning nested shell ---"}}]
        hits = detection.evaluate(rules, events, now=datetime.now(timezone.utc))
        ids = {h["rule_id"] for h in hits}
        self.assertIn("DR-CONTAINER-RUNTIME-EXEC", ids)
        hit = next(h for h in hits if h["rule_id"] == "DR-CONTAINER-RUNTIME-EXEC")
        self.assertEqual(hit["basis"], "log")
        self.assertEqual(hit["technique_id"], "T1610")

    def test_technique_rule_matches_emulation(self):
        rules = catalog.detection_rules()
        events = [{"id": 5, "kind": "ttp-emulation", "technique_id": "T1566",
                   "ts_utc": "2026-07-21T00:00:00+00:00", "payload": {"real": False}}]
        hits = detection.evaluate(rules, events, now=datetime.now(timezone.utc))
        hit = next(h for h in hits if h["rule_id"] == "DR-PHISH-DELIVERY")
        self.assertEqual(hit["basis"], "technique")

    def test_no_false_positive_on_unrelated_line(self):
        rules = catalog.detection_rules()
        events = [{"id": 2, "kind": "process-output", "technique_id": None,
                   "ts_utc": "2026-07-21T00:00:00+00:00",
                   "payload": {"line": "the quick brown fox"}}]
        hits = detection.evaluate(rules, events, now=datetime.now(timezone.utc))
        self.assertEqual(hits, [])

    def test_already_fired_rules_skipped(self):
        rules = catalog.detection_rules()
        events = [{"id": 1, "kind": "process-output", "technique_id": None,
                   "ts_utc": "2026-07-21T00:00:00+00:00",
                   "payload": {"line": "spawning nested shell"}}]
        hits = detection.evaluate(rules, events, now=datetime.now(timezone.utc),
                                  already_fired={"DR-CONTAINER-RUNTIME-EXEC"})
        self.assertNotIn("DR-CONTAINER-RUNTIME-EXEC", {h["rule_id"] for h in hits})

    def test_latency_is_positive(self):
        rules = catalog.detection_rules()
        events = [{"id": 1, "kind": "process-output", "technique_id": None,
                   "ts_utc": "2026-07-21T00:00:00+00:00",
                   "payload": {"line": "spawning nested shell"}}]
        now = datetime(2026, 7, 21, 0, 0, 10, tzinfo=timezone.utc)
        hits = detection.evaluate(rules, events, now=now)
        self.assertEqual(hits[0]["latency_s"], 10.0)

    def test_all_rules_reference_known_techniques(self):
        attacks = set()
        for t in catalog.tactics():
            attacks.update(t["attack"].split("/"))
        for rule in catalog.detection_rules():
            self.assertIn("id", rule)
            self.assertIn("technique_id", rule)
            self.assertIn("match", rule)


class ServiceDetectionTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def _running_docker_exercise(self):
        rng = self.svc.create_range("inst", "instructor", "CR-DOCKER-001")
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("inst", "instructor", rng["id"], a)
        return self.svc.start_exercise("inst", "instructor", rng["id"])

    def test_phish_emulation_auto_detects(self):
        # Uses the standard 5-VM phishing scenario (simulated module) so this
        # test runs without Docker.
        rng = self.svc.create_range("inst", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("inst", "instructor", rng["id"], a)
        ex = self.svc.start_exercise("inst", "instructor", rng["id"])
        res = self.svc.execute_module("red", "red", ex["id"], "CR-MOD-PHISH-001")
        self.assertGreaterEqual(res["detections_fired"], 1)
        dets = self.svc.list_detections(ex["id"])
        self.assertTrue(any(d["technique_id"] == "T1566" for d in dets))
        # detection also appears on the timeline
        self.assertTrue(any(e["kind"] == "detection" for e in self.svc.timeline(ex["id"])))

    def test_detections_are_idempotent(self):
        rng = self.svc.create_range("inst", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("inst", "instructor", rng["id"], a)
        ex = self.svc.start_exercise("inst", "instructor", rng["id"])
        self.svc.execute_module("red", "red", ex["id"], "CR-MOD-PHISH-001")
        first = len(self.svc.list_detections(ex["id"]))
        # Re-running detections should not duplicate the same rule.
        self.svc.run_detections(ex["id"])
        self.assertEqual(len(self.svc.list_detections(ex["id"])), first)

    @unittest.skipUnless(DOCKER, "Docker not available")
    def test_real_container_output_triggers_log_rule(self):
        ex = self._running_docker_exercise()
        res = self.svc.execute_module("red", "red", ex["id"], "CR-MOD-DOCKER-RUNTIME-001")
        self.assertTrue(res["real"])
        self.assertGreaterEqual(res["detections_fired"], 1)
        dets = self.svc.list_detections(ex["id"])
        self.assertTrue(any(d["basis"] == "log" for d in dets),
                        "expected at least one detection from a real log line")


if __name__ == "__main__":
    unittest.main()
