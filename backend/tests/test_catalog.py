import unittest

from cyberrange import catalog


class CatalogTest(unittest.TestCase):
    def test_mvp_module_count(self):
        # Spec MVP: at least 24 signed behavior modules.
        self.assertGreaterEqual(len(catalog.modules()), 24)

    def test_all_modules_signed(self):
        for m in catalog.modules():
            self.assertTrue(m.get("signed"), f"{m['id']} not signed")
            self.assertIn(m["safety_class"], {"S0", "S1", "S2"})

    def test_launch_scenarios(self):
        # Spec MVP: seven launch scenarios.
        self.assertGreaterEqual(len(catalog.scenarios()), 7)

    def test_scenarios_reference_valid_topologies_and_modules(self):
        topo_ids = {t["id"] for t in catalog.topologies()}
        mod_ids = {m["id"] for m in catalog.modules()}
        for s in catalog.scenarios():
            self.assertIn(s["topology_id"], topo_ids, s["id"])
            for mid in s.get("module_ids", []):
                self.assertIn(mid, mod_ids, f"{s['id']} -> {mid}")

    def test_platform_coverage(self):
        platforms = {m["platform"] for m in catalog.modules()}
        self.assertTrue({"windows", "linux", "docker"} <= platforms)

    def test_search_by_platform(self):
        docker = catalog.search_modules(platform="docker")
        self.assertTrue(all(m["platform"] == "docker" for m in docker))
        self.assertTrue(docker)

    def test_search_scenarios_by_difficulty(self):
        adv = catalog.search_scenarios(difficulty="advanced")
        self.assertTrue(all(s["difficulty"] == "advanced" for s in adv))

    def test_search_scenarios_by_technique(self):
        res = catalog.search_scenarios(technique="T1486")
        self.assertTrue(any(s["id"] == "CR-RANSOM-001" for s in res))

    def test_tactics_cover_containers(self):
        attacks = {t["attack"] for t in catalog.tactics()}
        self.assertIn("T1613", attacks)
        self.assertIn("T1611", attacks)


if __name__ == "__main__":
    unittest.main()
