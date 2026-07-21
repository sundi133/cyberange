import json
import threading
import unittest
from http.client import HTTPConnection

from cyberrange.server import make_server


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # dev_auth=True so the header-identity tests exercise that path;
        # production defaults to token-only (see test_auth_required_by_default).
        cls.httpd = make_server("127.0.0.1", 0, db_path=":memory:", dev_auth=True)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def _req(self, method, path, body=None, role="instructor", user="tester"):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = {"Content-Type": "application/json", "X-CR-Role": role, "X-CR-User": user}
        conn.request(method, path, json.dumps(body) if body is not None else None, headers)
        resp = conn.getresponse()
        data = json.loads(resp.read() or b"{}")
        conn.close()
        return resp.status, data

    def test_health(self):
        status, data = self._req("GET", "/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ok")

    def test_catalog_endpoints(self):
        status, scenarios = self._req("GET", "/api/scenarios")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(len(scenarios), 7)
        status, mods = self._req("GET", "/api/modules?platform=docker")
        self.assertTrue(all(m["platform"] == "docker" for m in mods))

    def test_unknown_role_rejected(self):
        status, _ = self._req("GET", "/api/ranges", role="hacker")
        self.assertEqual(status, 401)

    def test_provision_isolate_two_ranges(self):
        # Acceptance: two simultaneous ranges start independently.
        s1, r1 = self._req("POST", "/api/ranges", {"scenario_id": "CR-PHISH-001"})
        s2, r2 = self._req("POST", "/api/ranges", {"scenario_id": "CR-IDENT-001"})
        self.assertEqual(s1, 200)
        self.assertEqual(s2, 200)
        self.assertNotEqual(r1["id"], r2["id"])
        for a in ("preflight", "provision", "seed", "ready"):
            self._req("POST", f"/api/ranges/{r1['id']}/actions", {"action": a})
            self._req("POST", f"/api/ranges/{r2['id']}/actions", {"action": a})
        _, g1 = self._req("GET", f"/api/ranges/{r1['id']}")
        _, g2 = self._req("GET", f"/api/ranges/{r2['id']}")
        self.assertEqual(g1["state"], "READY")
        self.assertEqual(g2["state"], "READY")

    def test_safety_unsigned_and_forbidden_blocked(self):
        _, r = self._req("POST", "/api/ranges", {"scenario_id": "CR-PHISH-001"})
        for a in ("preflight", "provision", "seed", "ready"):
            self._req("POST", f"/api/ranges/{r['id']}/actions", {"action": a})
        _, ex = self._req("POST", "/api/exercises", {"range_id": r["id"]})
        # blue cannot create ranges
        status, _ = self._req("POST", "/api/ranges",
                              {"scenario_id": "CR-PHISH-001"}, role="blue")
        self.assertEqual(status, 403)
        # unknown module blocked
        status, _ = self._req("POST", f"/api/exercises/{ex['id']}/modules",
                              {"module_id": "FAKE"}, role="red")
        self.assertEqual(status, 404)

    def test_end_to_end_report(self):
        _, r = self._req("POST", "/api/ranges", {"scenario_id": "CR-DOCKER-001"})
        for a in ("preflight", "provision", "seed", "ready"):
            self._req("POST", f"/api/ranges/{r['id']}/actions", {"action": a})
        _, ex = self._req("POST", "/api/exercises", {"range_id": r["id"]})
        self._req("POST", f"/api/exercises/{ex['id']}/modules",
                  {"module_id": "CR-MOD-DOCKER-DISC-001"}, role="red")
        self._req("POST", f"/api/exercises/{ex['id']}/detections",
                  {"technique_id": "T1613", "verdict": "detected", "rule_version": "v1"})
        self._req("POST", f"/api/exercises/{ex['id']}/end", {})
        status, rep = self._req("GET", f"/api/exercises/{ex['id']}/report")
        self.assertEqual(status, 200)
        self.assertIn("T1613", rep["coverage"]["detected"])
        self.assertEqual(rep["status"], "completed")

    def test_purple_compare(self):
        status, data = self._req("POST", "/api/purple/compare", {
            "baseline": {"T1059": 0.3}, "replay": {"T1059": 0.8},
        })
        self.assertEqual(status, 200)
        self.assertAlmostEqual(data["improvement"], 0.5, places=3)

    def test_auth_required_by_default(self):
        # A server WITHOUT dev_auth must reject unauthenticated API calls
        # instead of defaulting them to admin (the Railway/public-deploy case).
        httpd = make_server("127.0.0.1", 0, db_path=":memory:")  # dev_auth off
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            # No token, no dev headers -> must be 401, not admin access.
            conn.request("GET", "/api/users")
            self.assertEqual(conn.getresponse().status, 401)
            conn.close()
            # Even an explicit admin header is ignored without dev_auth.
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/api/users", headers={"X-CR-Role": "admin"})
            self.assertEqual(conn.getresponse().status, 401)
            conn.close()
            # Login still works and yields a usable token.
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("POST", "/api/login",
                         json.dumps({"username": "admin", "password": "admin"}),
                         {"Content-Type": "application/json"})
            resp = conn.getresponse()
            self.assertEqual(resp.status, 200)
            token = json.loads(resp.read())["token"]
            conn.close()
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/api/users", headers={"Authorization": f"Bearer {token}"})
            self.assertEqual(conn.getresponse().status, 200)
            conn.close()
        finally:
            httpd.shutdown()

    def test_static_dashboard_served(self):
        conn = HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/")
        resp = conn.getresponse()
        body = resp.read().decode()
        conn.close()
        self.assertEqual(resp.status, 200)
        self.assertIn("CyberRange", body)


if __name__ == "__main__":
    unittest.main()
