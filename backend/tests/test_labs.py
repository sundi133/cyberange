import re
import unittest

from cyberrange import labs
from cyberrange.competitions import hash_flag, verify_flag
from cyberrange.db import Database
from cyberrange.service import CyberRangeService


class LabGeneratorTest(unittest.TestCase):
    def setUp(self):
        self.labs = labs.generate_labs()

    def test_depth_is_a_real_library(self):
        # The generated library should be a substantial, multi-category set.
        self.assertGreaterEqual(len(self.labs), 100)
        cats = {l["category"] for l in self.labs}
        self.assertTrue({"detection", "adversary", "threat-intel"} <= cats)

    def test_every_lab_is_gradeable(self):
        for lab in self.labs:
            self.assertTrue(lab["title"])
            self.assertTrue(lab["flag"])
            self.assertGreater(lab["points"], 0)
            h, s = hash_flag(lab["flag"])
            self.assertTrue(verify_flag(lab["flag"], s, h))

    def test_titles_unique(self):
        titles = [l["title"] for l in self.labs]
        self.assertEqual(len(titles), len(set(titles)))

    def test_technique_flags_are_attack_ids(self):
        for lab in self.labs:
            if lab["category"] in ("detection", "adversary"):
                self.assertRegex(lab["flag"], r"^T\d{4}(\.\d{3})?$")

    def test_summary_matches(self):
        s = labs.lab_summary()
        self.assertEqual(s["total"], len(self.labs))
        self.assertEqual(sum(s["by_category"].values()), len(self.labs))


class PracticeArenaSeedTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def test_seed_is_idempotent_and_playable(self):
        res1 = self.svc.competitions.seed_practice_arena()
        self.assertTrue(res1["created"])
        self.assertGreaterEqual(res1["challenges"], 100)

        # Second call does not duplicate.
        res2 = self.svc.competitions.seed_practice_arena()
        self.assertFalse(res2["created"])
        self.assertEqual(res1["id"], res2["id"])

        comp = self.svc.competitions.get(res1["id"])
        self.assertEqual(comp["status"], "live")  # always-open
        self.assertEqual(len(comp["challenges"]), res1["challenges"])
        # flags are not exposed
        self.assertFalse(any("flag" in c for c in comp["challenges"]))

    def test_a_generated_lab_can_be_solved(self):
        cid = self.svc.competitions.seed_practice_arena()["id"]
        # Pick a known detection→technique lab and solve it with its real answer.
        from cyberrange import catalog
        rule = next(d for d in catalog.detection_rules() if d.get("technique_id"))
        comp = self.svc.competitions.get(cid)
        target = next(c for c in comp["challenges"]
                      if c["title"] == f"Triage: {rule.get('title', rule['id'])}")
        res = self.svc.competitions.submit_flag(
            "red1", "red", cid, target["id"], rule["technique_id"])
        self.assertTrue(res["correct"])
        self.assertEqual(res["points"], target["points"])


if __name__ == "__main__":
    unittest.main()
