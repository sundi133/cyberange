import unittest

from cyberrange import catalog
from cyberrange.db import Database
from cyberrange.service import CyberRangeService


class FrameworkCrosswalkTest(unittest.TestCase):
    def test_every_used_technique_is_mapped(self):
        import json, re, pathlib
        seed = pathlib.Path(catalog.SEED_DIR)
        used = set()
        for f in ("tactics.json", "modules.json", "scenarios.json", "detections.json"):
            used.update(re.findall(r"T1\d{3}", (seed / f).read_text()))
        mapped = set(catalog.frameworks()["techniques"])
        missing = used - mapped
        self.assertFalse(missing, f"techniques with no framework crosswalk: {missing}")

    def test_each_entry_has_all_frameworks(self):
        for tid, e in catalog.frameworks()["techniques"].items():
            for key in ("nist_csf", "nice", "cis", "cae"):
                self.assertTrue(e.get(key), f"{tid} missing {key}")

    def test_coverage_aggregates_distinct_items(self):
        cov = catalog.framework_coverage(["T1613", "T1610", "T1611"])
        self.assertIn("DE.CM", cov["nist_csf"])
        self.assertIn("Cyber Defense Analyst", cov["nice"])
        self.assertEqual(cov["unmapped_techniques"], [])

    def test_unmapped_technique_reported(self):
        cov = catalog.framework_coverage(["T9999"])
        self.assertEqual(cov["unmapped_techniques"], ["T9999"])

    def test_report_includes_framework_coverage(self):
        svc = CyberRangeService(Database(":memory:"))
        rng = svc.create_range("i", "instructor", "CR-PHISH-001")
        for a in ("preflight", "provision", "seed", "ready"):
            svc.lifecycle_action("i", "instructor", rng["id"], a)
        ex = svc.start_exercise("i", "instructor", rng["id"])
        svc.execute_module("i", "instructor", ex["id"], "CR-MOD-PHISH-001")
        rep = svc.build_report(ex["id"])
        self.assertIn("framework_coverage", rep)
        self.assertIn("nist_csf", rep["framework_coverage"])


if __name__ == "__main__":
    unittest.main()
