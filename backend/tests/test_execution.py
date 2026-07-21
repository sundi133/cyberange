import unittest

from cyberrange import catalog, execution
from cyberrange.db import Database
from cyberrange.service import CyberRangeService

DOCKER = execution.docker_available()


class AdapterSelectionTest(unittest.TestCase):
    def test_simulated_for_module_without_execution_spec(self):
        mod = catalog.get_module("CR-MOD-PHISH-001")  # no execution spec
        adapter = execution.select_adapter(mod, docker_ok=True)
        self.assertIsInstance(adapter, execution.SimulatedAdapter)

    def test_simulated_when_docker_down(self):
        mod = catalog.get_module("CR-MOD-DOCKER-DISC-001")  # has docker spec
        adapter = execution.select_adapter(mod, docker_ok=False)
        self.assertIsInstance(adapter, execution.SimulatedAdapter)

    def test_docker_selected_when_available(self):
        mod = catalog.get_module("CR-MOD-DOCKER-DISC-001")
        adapter = execution.select_adapter(mod, docker_ok=True)
        self.assertIsInstance(adapter, execution.DockerAdapter)


class SimulatedAdapterTest(unittest.TestCase):
    def test_emits_records_flagged_not_real(self):
        mod = catalog.get_module("CR-MOD-PHISH-001")
        result = execution.SimulatedAdapter().run(mod, {}, 60)
        self.assertFalse(result.real)
        self.assertTrue(result.records)
        techs = [r["technique_id"] for r in result.records if r["technique_id"]]
        self.assertIn("T1566", techs)
        self.assertTrue(all(r["payload"]["real"] is False for r in result.records))


class SomeModulesHaveExecutionSpecTest(unittest.TestCase):
    def test_at_least_five_runnable_modules(self):
        runnable = [m for m in catalog.modules()
                    if (m.get("execution") or {}).get("adapter") == "docker"]
        self.assertGreaterEqual(len(runnable), 5)
        for m in runnable:
            self.assertIn("image", m["execution"])
            self.assertIn("cmd", m["execution"])
            self.assertEqual(m["execution"].get("network", "none"), "none")


@unittest.skipUnless(DOCKER, "Docker not available")
class DockerAdapterIntegrationTest(unittest.TestCase):
    def test_real_container_execution_produces_logs(self):
        mod = catalog.get_module("CR-MOD-DISC-LNX-001")
        result = execution.DockerAdapter().run(mod, {}, 60)
        self.assertTrue(result.real)
        self.assertEqual(result.summary["exit_code"], 0)
        outputs = [r for r in result.records if r["kind"] == "process-output"]
        self.assertTrue(outputs, "expected real stdout lines")
        self.assertTrue(all(r["payload"]["real"] for r in result.records))

    def test_service_execute_records_real_events(self):
        svc = CyberRangeService(Database(":memory:"))
        rng = svc.create_range("inst", "instructor", "CR-DOCKER-001")
        for a in ("preflight", "provision", "seed", "ready"):
            svc.lifecycle_action("inst", "instructor", rng["id"], a)
        ex = svc.start_exercise("inst", "instructor", rng["id"])
        res = svc.execute_module("red", "red", ex["id"], "CR-MOD-DOCKER-DISC-001")
        self.assertTrue(res["real"])
        self.assertEqual(res["adapter"], "docker")
        kinds = {e["kind"] for e in svc.timeline(ex["id"])}
        self.assertIn("ttp-exec", kinds)
        self.assertIn("process-output", kinds)


if __name__ == "__main__":
    unittest.main()
