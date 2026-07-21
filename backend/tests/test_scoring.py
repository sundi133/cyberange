import unittest

from cyberrange import scoring


class ScoringTest(unittest.TestCase):
    def test_weights_sum_to_one(self):
        self.assertAlmostEqual(sum(scoring.DEFAULT_WEIGHTS.values()), 1.0, places=6)

    def test_weighted_score(self):
        res = scoring.compute_score({
            "red_execution": 100, "detection": 100, "investigation": 100,
            "response": 100, "collaboration": 100,
        })
        self.assertEqual(res.total, 100.0)

    def test_penalties_subtracted(self):
        res = scoring.compute_score(
            {"red_execution": 80, "detection": 80, "investigation": 80,
             "response": 80, "collaboration": 80},
            penalties=[scoring.Penalty("egress attempt", 15.0)],
        )
        self.assertEqual(res.weighted_before_penalty, 80.0)
        self.assertEqual(res.total, 65.0)

    def test_override_applied_and_audited(self):
        res = scoring.compute_score(
            {"detection": 10, "red_execution": 0, "investigation": 0,
             "response": 0, "collaboration": 0},
            overrides=[scoring.Override("detection", 10, 90, "inst-1", "manual review")],
        )
        det = next(d for d in res.dimensions if d.dimension == "detection")
        self.assertEqual(det.raw, 90.0)
        self.assertEqual(len(res.overrides), 1)

    def test_score_never_negative(self):
        res = scoring.compute_score(
            {"red_execution": 10, "detection": 0, "investigation": 0,
             "response": 0, "collaboration": 0},
            penalties=[scoring.Penalty("multiple violations", 999)],
        )
        self.assertEqual(res.total, 0.0)

    def test_purple_delta_reports_improvement(self):
        d = scoring.purple_delta({"T1059": 0.4, "T1071": 0.2},
                                 {"T1059": 0.9, "T1071": 0.6})
        self.assertGreater(d["improvement"], 0)
        self.assertEqual(d["per_technique"]["T1059"]["delta"], 0.5)

    def test_explainable_dict(self):
        res = scoring.compute_score({"detection": 50})
        payload = res.to_dict()
        self.assertIn("dimensions", payload)
        self.assertIn("total", payload)


if __name__ == "__main__":
    unittest.main()
