import unittest
from datetime import datetime, timedelta, timezone

from cyberrange import rbac
from cyberrange.competitions import dynamic_value, hash_flag, verify_flag
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


class DynamicValueTest(unittest.TestCase):
    def test_no_solves_is_full_value(self):
        self.assertEqual(dynamic_value(500, 100, 20, 0), 500)

    def test_monotonic_decay(self):
        vals = [dynamic_value(500, 100, 20, n) for n in range(0, 25)]
        self.assertEqual(vals[0], 500)
        for a, b in zip(vals, vals[1:]):
            self.assertGreaterEqual(a, b)  # never increases

    def test_floor_is_respected(self):
        self.assertEqual(dynamic_value(500, 100, 20, 20), 100)   # ~floor at decay
        self.assertEqual(dynamic_value(500, 100, 20, 999), 100)  # clamped below

    def test_static_like_when_no_decay_or_floor(self):
        self.assertEqual(dynamic_value(300, 300, 20, 5), 300)  # min == initial
        self.assertEqual(dynamic_value(300, 100, 0, 5), 300)   # decay disabled


class DynamicScoringTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        self.c = self.svc.competitions
        self.comp = self.c.create("admin", "admin", name="Dyn", mode="ctf",
                                  scoring="dynamic", start_at=_iso(-60),
                                  end_at=_iso(3600), published=True)
        self.ch = self.c.add_challenge("admin", "admin", self.comp["id"],
                                       title="Pwn", flag="CR{x}", points=500)

    def test_defaults_applied(self):
        got = self.c.get(self.comp["id"])
        c = got["challenges"][0]
        self.assertEqual(c["max_points"], 500)
        self.assertEqual(c["min_points"], 250)   # 50% default
        self.assertEqual(c["decay"], 20)
        self.assertEqual(c["points"], 500)       # current value, no solves yet
        self.assertEqual(c["solves"], 0)

    def test_value_decays_as_teams_solve(self):
        r1 = self.c.submit_flag("red1", "red", self.comp["id"], self.ch["id"], "CR{x}")
        self.assertTrue(r1["dynamic"])
        self.assertLess(r1["points"], 500)       # already below ceiling
        first = r1["points"]
        self.c.submit_flag("blue1", "blue", self.comp["id"], self.ch["id"], "CR{x}")
        got = self.c.get(self.comp["id"])
        self.assertLess(got["challenges"][0]["points"], first)  # decayed further
        self.assertEqual(got["challenges"][0]["solves"], 2)

    def test_all_solvers_share_current_value(self):
        self.c.submit_flag("red1", "red", self.comp["id"], self.ch["id"], "CR{x}")
        self.c.submit_flag("blue1", "blue", self.comp["id"], self.ch["id"], "CR{x}")
        board = {b["team"]: b["points"] for b in
                 self.c.leaderboard(self.comp["id"])["standings"]}
        # Both teams hold the same (current, decayed) value for the one challenge.
        self.assertEqual(board["red1"], board["blue1"])
        self.assertEqual(board["red1"], dynamic_value(500, 250, 20, 2))

    def test_first_blood_bonus_locked_on_top_of_live_value(self):
        comp = self.c.create("admin", "admin", name="Blood", mode="ctf",
                             scoring="dynamic", first_blood_bonus_pct=10,
                             start_at=_iso(-60), end_at=_iso(3600), published=True)
        ch = self.c.add_challenge("admin", "admin", comp["id"], title="q",
                                  flag="CR{b}", points=500)
        self.c.join("red1", "red", comp["id"], "A")
        self.c.join("blue1", "blue", comp["id"], "B")
        r1 = self.c.submit_flag("red1", "red", comp["id"], ch["id"], "CR{b}")
        self.assertTrue(r1["first_blood"])
        self.assertEqual(r1["bonus"], round(r1["points"] * 0.10))  # 10% of value
        r2 = self.c.submit_flag("blue1", "blue", comp["id"], ch["id"], "CR{b}")
        self.assertFalse(r2["first_blood"])
        self.assertEqual(r2["bonus"], 0)
        board = {b["team"]: b for b in self.c.leaderboard(comp["id"])["standings"]}
        # Both hold the same live value; A also keeps the locked blood bonus.
        self.assertEqual(board["A"]["points"], board["B"]["points"] + r1["bonus"])
        self.assertEqual(board["A"]["bloods"], 1)
        self.assertEqual(board["B"]["bloods"], 0)

    def test_no_bonus_when_disabled(self):
        # Default competitions (0%) award no blood bonus.
        r = self.c.submit_flag("red1", "red", self.comp["id"], self.ch["id"], "CR{x}")
        self.assertTrue(r["first_blood"])
        self.assertEqual(r["bonus"], 0)

    def test_static_competition_does_not_decay(self):
        comp = self.c.create("admin", "admin", name="Stat", mode="ctf",
                             scoring="static", start_at=_iso(-60),
                             end_at=_iso(3600), published=True)
        ch = self.c.add_challenge("admin", "admin", comp["id"], title="q",
                                  flag="CR{s}", points=300)
        self.c.submit_flag("red1", "red", comp["id"], ch["id"], "CR{s}")
        self.c.submit_flag("blue1", "blue", comp["id"], ch["id"], "CR{s}")
        got = self.c.get(comp["id"])
        self.assertEqual(got["challenges"][0]["points"], 300)  # unchanged


class HandsOnLabTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        self.c = self.svc.competitions
        self.cid = self.c.seed_practice_arena()["id"]

    def _handson_challenge(self):
        comp = self.c.get(self.cid)
        return next(c for c in comp["challenges"] if c.get("module_id"))

    def test_handson_labs_exist_and_reference_signed_modules(self):
        from cyberrange import catalog
        comp = self.c.get(self.cid)
        handson = [c for c in comp["challenges"] if c.get("module_id")]
        self.assertGreaterEqual(len(handson), 10)
        for c in handson:
            mod = catalog.get_module(c["module_id"])
            self.assertTrue(mod and mod.get("signed"))
            self.assertEqual((mod.get("execution") or {}).get("adapter"), "docker")

    def test_run_reveals_token_and_it_solves(self):
        ch = self._handson_challenge()
        # Submitting without running: the player doesn't know the token yet.
        run = self.c.run_lab("red1", "red", self.cid, ch["id"])
        self.assertIn("output", run)
        # The proof token (CR{...}) is present in the run output.
        token = next(ln for ln in run["output"] if ln.startswith("CR{"))
        res = self.c.submit_flag("red1", "red", self.cid, ch["id"], token)
        self.assertTrue(res["correct"])
        self.assertEqual(res["points"], ch["points"])

    def test_run_rejected_for_non_handson_challenge(self):
        comp = self.c.get(self.cid)
        knowledge = next(c for c in comp["challenges"] if not c.get("module_id"))
        with self.assertRaises(ServiceError) as cm:
            self.c.run_lab("red1", "red", self.cid, knowledge["id"])
        self.assertEqual(cm.exception.status, 400)

    def test_run_requires_participation(self):
        ch = self._handson_challenge()
        with self.assertRaises(rbac.AuthorizationError):
            self.c.run_lab("obs", "security_leader", self.cid, ch["id"])


if __name__ == "__main__":
    unittest.main()
