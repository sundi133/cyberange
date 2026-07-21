import unittest

from cyberrange import catalog, execution, rbac
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError

DOCKER = execution.docker_available()


class LearningContentTest(unittest.TestCase):
    def test_scenarios_have_lessons(self):
        withlesson = [s for s in catalog.scenarios() if s.get("learning")]
        self.assertGreaterEqual(len(withlesson), 5)
        for s in withlesson:
            L = s["learning"]
            self.assertTrue(L.get("overview"))
            self.assertTrue(L.get("steps"))
            for q in L.get("quiz", []):
                self.assertIn("answer", q)
                self.assertTrue(0 <= q["answer"] < len(q["options"]))
                for st in L["steps"]:
                    self.assertIn("title", st)


class CohortTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def test_instructor_creates_class_and_imports_roster(self):
        c = self.svc.create_cohort("prof", "instructor", "CS101")
        r = self.svc.import_roster("prof", "instructor", c["id"],
                                   "alice,Alice\nbob,Bob,bobpass")
        self.assertEqual(r["created"], 2)
        self.assertEqual(r["enrolled"], 2)
        # alice got a generated password; bob used the provided one
        self.assertTrue(any(x["username"] == "alice" for x in r["credentials"]))
        self.assertTrue(self.svc.login("bob", "bobpass"))
        got = self.svc.get_cohort(c["id"])
        self.assertEqual(len(got["members"]), 2)
        # imported students are 'solo' learners
        self.assertEqual(self.svc.get_user("alice")["role"], "solo")

    def test_roster_header_row_skipped(self):
        c = self.svc.create_cohort("prof", "instructor", "CS")
        r = self.svc.import_roster("prof", "instructor", c["id"], "username,name\nzoe,Zoe")
        self.assertEqual(r["created"], 1)

    def test_student_cannot_manage_cohorts(self):
        with self.assertRaises(rbac.AuthorizationError):
            self.svc.create_cohort("alice", "solo", "hack")

    def test_assignment_and_my_assignments(self):
        c = self.svc.create_cohort("prof", "instructor", "CS")
        self.svc.import_roster("prof", "instructor", c["id"], "alice,Alice")
        a = self.svc.create_assignment("prof", "instructor", c["id"], "CR-PHISH-001")
        mine = self.svc.my_assignments("alice", "solo")
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["id"], a["id"])
        self.assertEqual(mine[0]["progress"]["status"], "not_started")


class LessonFlowTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))
        self.c = self.svc.create_cohort("prof", "instructor", "CS")
        self.svc.import_roster("prof", "instructor", self.c["id"], "alice,Alice")
        self.a = self.svc.create_assignment("prof", "instructor", self.c["id"], "CR-PHISH-001")

    def test_start_lesson_provisions_exercise(self):
        started = self.svc.start_lesson("alice", "solo", "CR-PHISH-001", self.a["id"])
        self.assertTrue(started["exercise_id"])
        self.assertEqual(started["progress"]["status"], "in_progress")
        # the exercise really exists
        self.assertTrue(self.svc.get_exercise(started["exercise_id"]))

    def test_steps_and_quiz_complete_lesson(self):
        started = self.svc.start_lesson("alice", "solo", "CR-PHISH-001", self.a["id"])
        n = len(started["lesson"]["steps"])
        for i in range(n):
            self.svc.run_lesson_step("alice", "solo", "CR-PHISH-001", i, self.a["id"])
        # correct answers
        quiz = catalog.get_scenario("CR-PHISH-001")["learning"]["quiz"]
        answers = [q["answer"] for q in quiz]
        res = self.svc.submit_quiz("alice", "solo", "CR-PHISH-001", answers, self.a["id"])
        self.assertEqual(res["score"], len(quiz))
        self.assertEqual(res["status"], "completed")

    def test_quiz_grades_wrong_answers(self):
        self.svc.start_lesson("alice", "solo", "CR-PHISH-001", self.a["id"])
        res = self.svc.submit_quiz("alice", "solo", "CR-PHISH-001", [9, 9], self.a["id"])
        self.assertEqual(res["score"], 0)
        self.assertFalse(res["results"][0]["correct"])
        self.assertTrue(res["results"][0]["explain"])

    def test_lesson_step_can_run_s2_module(self):
        # Ransomware lesson includes an S2 module; the platform runs it for the
        # student even though solo can't execute S2 free-form.
        a2 = self.svc.create_assignment("prof", "instructor", self.c["id"], "CR-RANSOM-001")
        self.svc.start_lesson("alice", "solo", "CR-RANSOM-001", a2["id"])
        steps = catalog.get_scenario("CR-RANSOM-001")["learning"]["steps"]
        s2_idx = next(i for i, s in enumerate(steps) if s["module_id"] == "CR-MOD-IMPACT-001")
        out = self.svc.run_lesson_step("alice", "solo", "CR-RANSOM-001", s2_idx, a2["id"])
        self.assertIn(s2_idx, out["progress"]["steps_done"])

    def test_gradebook_reflects_progress(self):
        started = self.svc.start_lesson("alice", "solo", "CR-PHISH-001", self.a["id"])
        for i in range(len(started["lesson"]["steps"])):
            self.svc.run_lesson_step("alice", "solo", "CR-PHISH-001", i, self.a["id"])
        quiz = catalog.get_scenario("CR-PHISH-001")["learning"]["quiz"]
        self.svc.submit_quiz("alice", "solo", "CR-PHISH-001",
                             [q["answer"] for q in quiz], self.a["id"])
        gb = self.svc.gradebook("prof", "instructor", self.c["id"])
        alice = next(r for r in gb["rows"] if r["username"] == "alice")
        self.assertEqual(alice["completed"], 1)
        self.assertEqual(alice["avg_score"], 100.0)


if __name__ == "__main__":
    unittest.main()
