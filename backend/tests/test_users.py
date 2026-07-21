import unittest

from cyberrange import auth, rbac
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError


class AuthHashTest(unittest.TestCase):
    def test_hash_roundtrip(self):
        h, salt = auth.hash_password("hunter2")
        self.assertTrue(auth.verify_password("hunter2", salt, h))
        self.assertFalse(auth.verify_password("wrong", salt, h))

    def test_salts_differ(self):
        h1, s1 = auth.hash_password("same")
        h2, s2 = auth.hash_password("same")
        self.assertNotEqual(s1, s2)
        self.assertNotEqual(h1, h2)


class UserProvisioningTest(unittest.TestCase):
    def setUp(self):
        self.svc = CyberRangeService(Database(":memory:"))

    def test_default_admin_seeded(self):
        user = self.svc.get_user("admin")
        self.assertEqual(user["role"], "admin")
        self.assertTrue(user["active"])

    def test_admin_can_provision_and_login(self):
        self.svc.create_user("admin", "admin", "red-op", "redpass", "red", "Red Op")
        sess = self.svc.login("red-op", "redpass")
        self.assertEqual(sess["role"], "red")
        self.assertIn("module:execute", sess["permissions"])
        resolved = self.svc.resolve_token(sess["token"])
        self.assertEqual(resolved["username"], "red-op")

    def test_non_admin_cannot_provision(self):
        self.svc.create_user("admin", "admin", "blue-1", "bluepass", "blue")
        with self.assertRaises(rbac.AuthorizationError):
            self.svc.create_user("blue-1", "blue", "sneaky", "pw1234", "admin")

    def test_duplicate_user_rejected(self):
        self.svc.create_user("admin", "admin", "dup", "pw1234", "red")
        with self.assertRaises(ServiceError) as ctx:
            self.svc.create_user("admin", "admin", "dup", "pw1234", "red")
        self.assertEqual(ctx.exception.status, 409)

    def test_unknown_role_rejected(self):
        with self.assertRaises(ServiceError):
            self.svc.create_user("admin", "admin", "x", "pw1234", "wizard")

    def test_short_password_rejected(self):
        with self.assertRaises(ServiceError):
            self.svc.create_user("admin", "admin", "x", "ab", "red")

    def test_bad_login_rejected(self):
        with self.assertRaises(ServiceError) as ctx:
            self.svc.login("admin", "nope")
        self.assertEqual(ctx.exception.status, 401)

    def test_deactivated_user_cannot_login_or_use_session(self):
        self.svc.create_user("admin", "admin", "temp", "temppass", "red")
        sess = self.svc.login("temp", "temppass")
        self.svc.set_user_active("admin", "admin", "temp", False)
        # existing session is revoked
        self.assertIsNone(self.svc.resolve_token(sess["token"]))
        # cannot log in again
        with self.assertRaises(ServiceError):
            self.svc.login("temp", "temppass")

    def test_logout_revokes_session(self):
        sess = self.svc.login("admin", "admin")
        self.svc.logout(sess["token"])
        self.assertIsNone(self.svc.resolve_token(sess["token"]))

    def test_cannot_deactivate_self(self):
        with self.assertRaises(ServiceError):
            self.svc.set_user_active("admin", "admin", "admin", False)

    def test_role_matrix_covers_all_roles(self):
        matrix = rbac.role_matrix()
        self.assertEqual({m["role"] for m in matrix}, set(rbac.ROLES))
        for entry in matrix:
            self.assertTrue(entry["summary"])
            self.assertEqual(len(entry["permissions"]), len(entry["capabilities"]))


if __name__ == "__main__":
    unittest.main()
