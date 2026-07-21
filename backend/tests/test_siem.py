import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

from cyberrange import rbac, siem
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError

# Load the standalone forwarder module from deploy/wazuh/forwarder.
_FWD = Path(__file__).resolve().parents[2] / "deploy" / "wazuh" / "forwarder" / "forwarder.py"
_spec = importlib.util.spec_from_file_location("cr_forwarder", _FWD)
forwarder = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(forwarder)


class EventSinkTest(unittest.TestCase):
    def test_disabled_by_default(self):
        self.assertFalse(siem.EventSink(enabled=False).enabled)

    def test_writes_json_lines_when_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "events.json")
            sink = siem.EventSink(path=path, enabled=True)
            sink.write({"kind": "ttp-exec", "technique_id": "T1610"})
            sink.write({"kind": "process-output", "payload": {"line": "x"}})
            lines = Path(path).read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)
            import json
            first = json.loads(lines[0])
            self.assertTrue(first["cyberrange"])          # marker for Wazuh rules
            self.assertEqual(first["technique_id"], "T1610")

    def test_disabled_sink_writes_nothing(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "events.json")
            sink = siem.EventSink(path=path, enabled=False)
            sink.write({"kind": "x"})
            self.assertFalse(os.path.exists(path))


class SinkIntegrationTest(unittest.TestCase):
    def test_service_forwards_events_when_enabled(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "events.json")
            svc = CyberRangeService(Database(":memory:"),
                                    event_sink=siem.EventSink(path=path, enabled=True))
            rng = svc.create_range("i", "instructor", "CR-PHISH-001")
            for a in ("preflight", "provision", "seed", "ready"):
                svc.lifecycle_action("i", "instructor", rng["id"], a)
            ex = svc.start_exercise("i", "instructor", rng["id"])
            svc.execute_module("i", "instructor", ex["id"], "CR-MOD-PHISH-001")
            lines = Path(path).read_text().strip().splitlines()
            self.assertTrue(lines)
            # detection events are NOT forwarded (avoid feedback loop)
            import json
            kinds = [json.loads(l)["kind"] for l in lines]
            self.assertNotIn("detection", kinds)


class IngestAlertTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        rng = self.svc.create_range("i", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            self.svc.lifecycle_action("i", "instructor", rng["id"], a)
        self.ex = self.svc.start_exercise("i", "instructor", rng["id"])

    def test_ingest_records_siem_detection(self):
        out = self.svc.ingest_siem_alert(
            "wazuh", "admin", exercise_id=self.ex["id"], rule_id="100110",
            level=12, description="TTP executed", technique_id="T1610")
        self.assertEqual(out["severity"], "high")
        dets = self.svc.list_detections(self.ex["id"])
        self.assertTrue(any(d["basis"] == "siem" and d["technique_id"] == "T1610"
                            for d in dets))
        # a detection event also appears on the timeline, attributed to wazuh
        self.assertTrue(any(e["kind"] == "detection" and e["actor"] == "wazuh"
                            for e in self.svc.timeline(self.ex["id"])))

    def test_ingest_requires_admin(self):
        with self.assertRaises(rbac.AuthorizationError):
            self.svc.ingest_siem_alert(
                "s", "solo", exercise_id=self.ex["id"], rule_id="1", level=5,
                description="x")

    def test_severity_mapping(self):
        for lvl, sev in [(12, "high"), (8, "medium"), (3, "low")]:
            out = self.svc.ingest_siem_alert(
                "wazuh", "admin", exercise_id=self.ex["id"], rule_id=str(lvl),
                level=lvl, description="d")
            self.assertEqual(out["severity"], sev)


class ForwarderParseTest(unittest.TestCase):
    def test_maps_cyberrange_alert(self):
        alert = {
            "rule": {"id": "100120", "level": 12, "groups": ["cyberrange"],
                     "description": "suspicious runtime"},
            "data": {"exercise_id": "run-abc", "technique_id": "T1610",
                     "kind": "process-output"},
            "full_log": "spawning nested shell",
        }
        body = forwarder.parse_alert(alert)
        self.assertEqual(body["exercise_id"], "run-abc")
        self.assertEqual(body["rule_id"], "100120")
        self.assertEqual(body["level"], 12)
        self.assertEqual(body["technique_id"], "T1610")

    def test_ignores_non_cyberrange_alert(self):
        self.assertIsNone(forwarder.parse_alert(
            {"rule": {"id": "5502", "level": 3, "groups": ["pam"]}, "data": {}}))

    def test_ignores_cyberrange_alert_without_exercise(self):
        self.assertIsNone(forwarder.parse_alert(
            {"rule": {"id": "100100", "level": 2, "groups": ["cyberrange"]}, "data": {}}))


if __name__ == "__main__":
    unittest.main()
