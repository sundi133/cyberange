import os
import unittest

from cyberrange import service as svcmod
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError


def _svc():
    return CyberRangeService(Database(":memory:"))


class DefaultAdminTest(unittest.TestCase):
    def test_no_hardcoded_admin_admin(self):
        old = os.environ.pop("CR_ADMIN_PASSWORD", None)
        try:
            svc = _svc()
            with self.assertRaises(ServiceError):   # the old default must not work
                svc.login("admin", "admin")
        finally:
            if old is not None:
                os.environ["CR_ADMIN_PASSWORD"] = old

    def test_env_password_used_when_set(self):
        os.environ["CR_ADMIN_PASSWORD"] = "s3cret-pw-123"
        try:
            self.assertTrue(_svc().login("admin", "s3cret-pw-123")["token"])
        finally:
            os.environ.pop("CR_ADMIN_PASSWORD", None)


class LoginRateLimitTest(unittest.TestCase):
    def setUp(self):
        os.environ["CR_ADMIN_PASSWORD"] = "correct-horse-1"
        self.addCleanup(lambda: os.environ.pop("CR_ADMIN_PASSWORD", None))
        self.svc = _svc()

    def test_lockout_after_max_fails(self):
        for _ in range(svcmod._LOGIN_MAX_FAILS):
            with self.assertRaises(ServiceError):
                self.svc.login("admin", "wrong")
        # Locked: even the correct password is refused, with 429.
        with self.assertRaises(ServiceError) as cm:
            self.svc.login("admin", "correct-horse-1")
        self.assertEqual(cm.exception.status, 429)

    def test_unknown_username_also_throttles(self):
        # Lockout by submitted name, so it can't be used to enumerate accounts.
        for _ in range(svcmod._LOGIN_MAX_FAILS):
            with self.assertRaises(ServiceError):
                self.svc.login("ghost", "x")
        with self.assertRaises(ServiceError) as cm:
            self.svc.login("ghost", "x")
        self.assertEqual(cm.exception.status, 429)

    def test_success_resets_counter(self):
        for _ in range(svcmod._LOGIN_MAX_FAILS - 1):
            with self.assertRaises(ServiceError):
                self.svc.login("admin", "wrong")
        self.assertTrue(self.svc.login("admin", "correct-horse-1")["token"])
        # Counter cleared: another near-threshold burst still logs in fine.
        for _ in range(svcmod._LOGIN_MAX_FAILS - 1):
            with self.assertRaises(ServiceError):
                self.svc.login("admin", "wrong")
        self.assertTrue(self.svc.login("admin", "correct-horse-1")["token"])


class ChangePasswordTest(unittest.TestCase):
    def setUp(self):
        os.environ["CR_ADMIN_PASSWORD"] = "old-pw-1234"
        self.addCleanup(lambda: os.environ.pop("CR_ADMIN_PASSWORD", None))
        self.svc = _svc()

    def test_wrong_old_rejected(self):
        with self.assertRaises(ServiceError) as cm:
            self.svc.change_password("admin", "admin", "nope", "new-pw-1234")
        self.assertEqual(cm.exception.status, 403)

    def test_short_new_rejected(self):
        with self.assertRaises(ServiceError):
            self.svc.change_password("admin", "admin", "old-pw-1234", "ab")

    def test_change_then_old_fails_new_works(self):
        self.svc.change_password("admin", "admin", "old-pw-1234", "new-pw-5678")
        with self.assertRaises(ServiceError):
            self.svc.login("admin", "old-pw-1234")
        self.assertTrue(self.svc.login("admin", "new-pw-5678")["token"])


if __name__ == "__main__":
    unittest.main()
