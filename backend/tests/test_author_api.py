"""In-product scenario authoring (POST /api/scenarios, service.create_scenario)."""

import json
import pathlib
import tempfile
import unittest

from cyberrange import catalog, rbac
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError


class AuthorScenarioAPITest(unittest.TestCase):
    def setUp(self):
        # Point the staged-scenarios file at a temp location so the real seed
        # is never touched, and reset the catalog cache around it.
        self.tmp = tempfile.TemporaryDirectory()
        self._orig_seed = catalog.SEED_DIR
        # copy the real seed files the service reads, into the temp dir
        self.seed = pathlib.Path(self.tmp.name)
        for f in self._orig_seed.glob("*.json"):
            (self.seed / f.name).write_text(f.read_text())
        catalog.SEED_DIR = self.seed
        catalog._load.cache_clear()
        catalog._staged_scenarios.cache_clear()
        catalog._staged_modules.cache_clear()
        self.svc = CyberRangeService(Database(":memory:"))

    def tearDown(self):
        catalog.SEED_DIR = self._orig_seed
        catalog._load.cache_clear()
        catalog._staged_scenarios.cache_clear()
        catalog._staged_modules.cache_clear()
        self.tmp.cleanup()

    def _signed_module(self):
        return next(m["id"] for m in catalog.modules() if m.get("signed"))

    def test_instructor_can_author_and_it_appears(self):
        before = len(catalog.scenarios())
        s = self.svc.create_scenario("prof", "instructor", {
            "name": "Authored in product", "mode": "solo",
            "modules": [self._signed_module()]})
        self.assertTrue(s["id"].startswith("CR-CUSTOM-"))
        self.assertTrue(s["custom"])
        self.assertEqual(len(catalog.scenarios()), before + 1)
        # and it is launchable: a range can be created from it
        rng = self.svc.create_range("prof", "instructor", s["id"])
        self.assertEqual(rng["scenario_id"], s["id"])

    def test_admin_can_author(self):
        s = self.svc.create_scenario("admin", "admin", {
            "name": "Admin authored", "mode": "red-blue",
            "modules": [self._signed_module()]})
        self.assertIn("id", s)

    def test_non_author_roles_refused(self):
        mod = self._signed_module()
        for role in ("red", "blue", "purple", "solo", "security_leader"):
            with self.assertRaises(rbac.AuthorizationError):
                self.svc.create_scenario("u", role, {
                    "name": "nope", "mode": "solo", "modules": [mod]})

    def test_validation_errors_surface_as_400(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_scenario("prof", "instructor", {
                "name": "bad", "mode": "solo", "modules": ["NO-SUCH-MODULE"]})
        self.assertEqual(ctx.exception.status, 400)

    def test_cannot_author_on_unsigned_module(self):
        # inject an unsigned module into the catalog
        path = self.seed / "modules.staged.json"
        path.write_text(json.dumps([{
            "id": "CR-UNSIGNED-X", "name": "x", "platform": "linux",
            "safety_class": "S1", "technique_ids": ["T1059"], "signed": False}]))
        catalog._staged_modules.cache_clear()
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_scenario("prof", "instructor", {
                "name": "on unsigned", "mode": "solo", "modules": ["CR-UNSIGNED-X"]})
        self.assertEqual(ctx.exception.status, 400)
        self.assertIn("unsigned", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()
