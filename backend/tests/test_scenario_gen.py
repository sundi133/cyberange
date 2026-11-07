import unittest

from cyberrange import catalog, scenario_gen


class ScenarioGenTest(unittest.TestCase):
    def setUp(self):
        self.scs = scenario_gen.generate_scenarios()

    def test_generates_a_real_batch(self):
        self.assertGreaterEqual(len(self.scs), 15)
        self.assertTrue(all(s["id"].startswith("CR-DRILL-") for s in self.scs))

    def test_only_signed_modules_and_valid_topology(self):
        mods = {m["id"]: m for m in catalog.modules()}
        topos = {t["id"] for t in catalog.topologies()}
        for s in self.scs:
            self.assertIn(s["topology_id"], topos, s["id"])
            self.assertGreaterEqual(len(s["module_ids"]), scenario_gen.MIN_ATOMICS)
            self.assertLessEqual(len(s["module_ids"]), scenario_gen.MAX_PER_DRILL)
            for mid in s["module_ids"]:
                self.assertIn(mid, mods, mid)
                self.assertTrue(mods[mid].get("signed"), mid)  # never unsigned

    def test_committed_pack_is_in_the_catalog(self):
        # The shipped scenarios.imported.json shows up for launch in the catalog.
        drills = [s for s in catalog.scenarios() if s["id"].startswith("CR-DRILL-")]
        self.assertGreaterEqual(len(drills), 15)

    def test_each_drill_has_role_objectives(self):
        for s in self.scs:
            roles = {o["role"] for o in s["objectives"]}
            self.assertEqual(roles, {"red", "blue"}, s["id"])


if __name__ == "__main__":
    unittest.main()
