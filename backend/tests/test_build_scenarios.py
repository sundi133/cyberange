"""The scenario builder (scripts/build_scenarios.py).

Verifies the compose-and-validate contract: a config becomes a full scenario,
fields are derived, and - the safety boundary - a scenario cannot be built on
unknown or unsigned modules.
"""

import importlib.util
import pathlib
import unittest

from cyberrange import catalog
from cyberrange import authoring

_BUILDER = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "build_scenarios.py"
_spec = importlib.util.spec_from_file_location("build_scenarios", _BUILDER)
bs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bs)

# A small module table to build against, instead of the real catalog.
MODS = {
    "M-WEB": {"id": "M-WEB", "platform": "linux", "safety_class": "S1",
              "technique_ids": ["T1190"], "signed": True},
    "M-PRIV": {"id": "M-PRIV", "platform": "linux", "safety_class": "S2",
               "technique_ids": ["T1548"], "signed": True},
    "M-DOCK": {"id": "M-DOCK", "platform": "docker", "safety_class": "S1",
               "technique_ids": ["T1613"], "signed": True},
    "M-UNSIGNED": {"id": "M-UNSIGNED", "platform": "linux", "safety_class": "S1",
                   "technique_ids": ["T1059"], "signed": False},
}


class BuildScenarioTest(unittest.TestCase):
    def build(self, cfg):
        return authoring.build_scenario(cfg, MODS, set())

    def test_minimal_config_produces_full_scenario(self):
        s = self.build({"name": "Web to root", "mode": "red-blue",
                        "modules": ["M-WEB", "M-PRIV"]})
        self.assertEqual(s["name"], "Web to root")
        self.assertTrue(s["id"].startswith("CR-CUSTOM-"))
        self.assertEqual(s["module_ids"], ["M-WEB", "M-PRIV"])
        self.assertTrue(s["custom"])

    def test_techniques_are_derived_as_union(self):
        s = self.build({"name": "x", "modules": ["M-WEB", "M-PRIV"]})
        self.assertEqual(s["technique_ids"], ["T1190", "T1548"])

    def test_safety_class_is_the_highest_of_the_modules(self):
        s = self.build({"name": "x", "modules": ["M-WEB", "M-PRIV"]})  # S1 + S2
        self.assertEqual(s["safety_class"], "S2")

    def test_docker_module_selects_the_container_topology(self):
        s = self.build({"name": "x", "modules": ["M-DOCK"]})
        self.assertEqual(s["topology_id"], "TOPO-DOCKER")
        s2 = self.build({"name": "x", "modules": ["M-WEB"]})
        self.assertEqual(s2["topology_id"], "TOPO-STD5")

    def test_default_objectives_by_mode(self):
        rb = self.build({"name": "x", "mode": "red-blue", "modules": ["M-WEB"]})
        roles = {o["role"] for o in rb["objectives"]}
        self.assertEqual(roles, {"red", "blue"})
        solo = self.build({"name": "x", "mode": "solo", "modules": ["M-WEB"]})
        self.assertEqual([o["role"] for o in solo["objectives"]], ["solo"])

    def test_author_objectives_override(self):
        s = self.build({"name": "x", "modules": ["M-WEB"],
                        "objectives": {"red": {"text": "own it", "points": 70}}})
        self.assertEqual(s["objectives"], [{"role": "red", "text": "own it", "points": 70}])

    # ---- validation: the safety boundary --------------------------------
    def test_unknown_module_rejected(self):
        with self.assertRaises(authoring.ConfigError):
            self.build({"name": "x", "modules": ["M-WEB", "NOPE"]})

    def test_unsigned_module_rejected(self):
        with self.assertRaises(authoring.ConfigError) as ctx:
            self.build({"name": "x", "modules": ["M-WEB", "M-UNSIGNED"]})
        self.assertIn("unsigned", str(ctx.exception).lower())

    def test_bad_mode_rejected(self):
        with self.assertRaises(authoring.ConfigError):
            self.build({"name": "x", "mode": "green", "modules": ["M-WEB"]})

    def test_no_modules_rejected(self):
        with self.assertRaises(authoring.ConfigError):
            self.build({"name": "x", "modules": []})

    def test_no_name_rejected(self):
        with self.assertRaises(authoring.ConfigError):
            self.build({"modules": ["M-WEB"]})

    def test_ids_stay_unique_within_a_batch(self):
        used = set()
        a = authoring.build_scenario({"name": "Same", "modules": ["M-WEB"]}, MODS, used)
        b = authoring.build_scenario({"name": "Same", "modules": ["M-WEB"]}, MODS, used)
        self.assertNotEqual(a["id"], b["id"])


class ExampleConfigsBuildTest(unittest.TestCase):
    """The shipped example configs must build against the real catalog."""

    def test_examples_build(self):
        examples = pathlib.Path(__file__).resolve().parents[2] / "examples" / "scenario-configs"
        mods = {m["id"]: m for m in catalog.modules()}
        used = set()
        for path in examples.glob("*.yaml"):
            cfg = bs._load_config(path)
            s = authoring.build_scenario(cfg, mods, used)
            self.assertTrue(s["module_ids"])
        for path in examples.glob("*.json"):
            cfg = bs._load_config(path)
            s = authoring.build_scenario(cfg, mods, used)
            self.assertTrue(s["module_ids"])


if __name__ == "__main__":
    unittest.main()
