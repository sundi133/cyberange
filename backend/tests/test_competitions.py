import unittest
from datetime import datetime, timedelta, timezone

from cyberrange import rbac
from cyberrange.competitions import hash_flag, verify_flag
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError


def _iso(delta_s):
    return (datetime.now(timezone.utc) + timedelta(seconds=delta_s)).isoformat()


class FlagHashTest(unittest.TestCase):
    def test_roundtrip_and_salt(self):
        h, s = hash_flag("CR{flag}")
        self.assertTrue(verify_flag("CR{flag}", s, h))
        self.assertTrue(verify_flag("  CR{flag}  ", s, h))  # trimmed
        self.assertFalse(verify_flag("CR{wrong}", s, h))
        h2, s2 = hash_flag("CR{flag}")
        self.assertNotEqual(s, s2)
        self.assertNotEqual(h, h2)


class CompetitionTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        self.c = self.svc.competitions

    def _live_comp(self):
        comp = self.c.create("admin", "admin", name="Fall CTF", mode="ctf",
                             start_at=_iso(-60), end_at=_iso(3600), published=True)
        self.assertEqual(comp["status"], "live")
        ch = self.c.add_challenge("admin", "admin", comp["id"], title="Recon",
                                  flag="CR{recon}", category="recon", points=100)
        return comp, ch

    # ---- authoring & RBAC ----
    def test_only_managers_can_create(self):
        with self.assertRaises(rbac.AuthorizationError):
            self.c.create("red1", "red", name="x")
        comp = self.c.create("prof", "instructor", name="Class CTF")
        self.assertEqual(comp["status"], "draft")  # unpublished

    def test_participant_cannot_author_challenge(self):
        comp, _ = self._live_comp()
        with self.assertRaises(rbac.AuthorizationError):
            self.c.add_challenge("red1", "red", comp["id"], title="x", flag="y")

    def test_challenge_flag_never_leaked(self):
        comp, _ = self._live_comp()
        got = self.c.get(comp["id"], "red1", "red")
        for ch in got["challenges"]:
            self.assertNotIn("flag_hash", ch)
            self.assertNotIn("flag_salt", ch)
            self.assertNotIn("flag", ch)

    # ---- scheduling window ----
    def test_submit_blocked_before_and_after_window(self):
        scheduled = self.c.create("admin", "admin", name="Later", mode="ctf",
                                  start_at=_iso(3600), end_at=_iso(7200), published=True)
        ch = self.c.add_challenge("admin", "admin", scheduled["id"], title="q",
                                  flag="CR{x}")
        self.assertEqual(self.c.get(scheduled["id"])["status"], "scheduled")
        with self.assertRaises(ServiceError) as cm:
            self.c.submit_flag("red1", "red", scheduled["id"], ch["id"], "CR{x}")
        self.assertEqual(cm.exception.status, 409)

        ended = self.c.create("admin", "admin", name="Over", mode="ctf",
                              start_at=_iso(-7200), end_at=_iso(-60), published=True)
        ch2 = self.c.add_challenge("admin", "admin", ended["id"], title="q", flag="CR{y}")
        self.assertEqual(self.c.get(ended["id"])["status"], "ended")
        with self.assertRaises(ServiceError):
            self.c.submit_flag("red1", "red", ended["id"], ch2["id"], "CR{y}")

    def test_draft_is_not_live(self):
        comp = self.c.create("admin", "admin", name="Draft", mode="ctf",
                             start_at=_iso(-60), end_at=_iso(3600), published=False)
        self.assertEqual(self.c.get(comp["id"])["status"], "draft")

    # ---- submit / scoring ----
    def test_wrong_flag_scores_nothing(self):
        comp, ch = self._live_comp()
        res = self.c.submit_flag("red1", "red", comp["id"], ch["id"], "CR{nope}")
        self.assertFalse(res["correct"])
        board = self.c.leaderboard(comp["id"])
        total = sum(r["points"] for r in board["standings"])
        self.assertEqual(total, 0)

    def test_correct_flag_scores_and_first_blood(self):
        comp, ch = self._live_comp()
        res = self.c.submit_flag("red1", "red", comp["id"], ch["id"], "CR{recon}")
        self.assertTrue(res["correct"])
        self.assertTrue(res["first_blood"])
        self.assertEqual(res["points"], 100)
        # second team solving same challenge is not first blood
        res2 = self.c.submit_flag("blue1", "blue", comp["id"], ch["id"], "CR{recon}")
        self.assertTrue(res2["correct"])
        self.assertFalse(res2["first_blood"])

    def test_resolve_is_idempotent(self):
        comp, ch = self._live_comp()
        self.c.submit_flag("red1", "red", comp["id"], ch["id"], "CR{recon}")
        again = self.c.submit_flag("red1", "red", comp["id"], ch["id"], "CR{recon}")
        self.assertTrue(again["already_solved"])
        self.assertEqual(again["points"], 0)
        board = self.c.leaderboard(comp["id"])
        mine = [r for r in board["standings"] if "red1" in r["members"]][0]
        self.assertEqual(mine["points"], 100)  # counted once

    # ---- teams & leaderboard ----
    def test_team_join_and_one_team_per_user(self):
        comp, _ = self._live_comp()
        t = self.c.join("red1", "red", comp["id"], "Wolves")
        self.assertEqual(t["name"], "Wolves")
        # same user joining a different team is refused
        with self.assertRaises(ServiceError):
            self.c.join("red1", "red", comp["id"], "Foxes")
        # a second user can join the same team
        self.c.join("blue1", "blue", comp["id"], "Wolves")

    def test_leaderboard_ranks_by_points(self):
        comp = self.c.create("admin", "admin", name="Multi", mode="ctf",
                             start_at=_iso(-60), end_at=_iso(3600), published=True)
        easy = self.c.add_challenge("admin", "admin", comp["id"], title="e",
                                    flag="CR{e}", points=100)
        hard = self.c.add_challenge("admin", "admin", comp["id"], title="h",
                                    flag="CR{h}", points=500)
        self.c.join("red1", "red", comp["id"], "A")
        self.c.join("blue1", "blue", comp["id"], "B")
        self.c.submit_flag("red1", "red", comp["id"], easy["id"], "CR{e}")      # A=100
        self.c.submit_flag("blue1", "blue", comp["id"], hard["id"], "CR{h}")    # B=500
        board = self.c.leaderboard(comp["id"])["standings"]
        self.assertEqual(board[0]["team"], "B")
        self.assertEqual(board[0]["rank"], 1)
        self.assertEqual(board[0]["points"], 500)
        self.assertEqual(board[1]["team"], "A")

    def test_end_before_start_rejected(self):
        with self.assertRaises(ServiceError):
            self.c.create("admin", "admin", name="bad",
                          start_at=_iso(3600), end_at=_iso(60), published=True)


if __name__ == "__main__":
    unittest.main()
