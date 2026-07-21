import unittest

from cyberrange import lifecycle


class LifecycleTest(unittest.TestCase):
    def test_happy_path(self):
        state = lifecycle.INITIAL_STATE
        for action in ("preflight", "provision", "seed", "ready", "start",
                       "pause", "resume", "complete", "lock_evidence", "archive",
                       "destroy"):
            state = lifecycle.apply_action(state, action)
        self.assertEqual(state, "DESTROYED")
        self.assertTrue(lifecycle.is_terminal(state))

    def test_illegal_transition_rejected(self):
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.apply_action("REQUESTED", "start")

    def test_quarantine_from_running(self):
        dst = lifecycle.apply_action("RUNNING", "quarantine")
        self.assertEqual(dst, "QUARANTINED")

    def test_quarantine_release_requires_admin(self):
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.apply_action("QUARANTINED", "destroy", is_admin=False)
        # admin may release
        dst = lifecycle.apply_action("QUARANTINED", "destroy", is_admin=True)
        self.assertEqual(dst, "DESTROYED")

    def test_destroyed_is_terminal(self):
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.apply_action("DESTROYED", "archive")

    def test_unknown_action(self):
        with self.assertRaises(lifecycle.LifecycleError):
            lifecycle.apply_action("READY", "teleport")


if __name__ == "__main__":
    unittest.main()
