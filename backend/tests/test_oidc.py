import os
import unittest
import urllib.parse as up

from cyberrange import oidc
from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError


class StubIdP:
    """A fake OIDC provider: discovery, token, userinfo - no network."""
    def __init__(self, email="Alice@Example.com", name="Alice"):
        self.email, self.name, self.calls = email, name, []

    def __call__(self, method, url, data, headers):
        self.calls.append((method, url))
        if url.endswith("/.well-known/openid-configuration"):
            return {"authorization_endpoint": "https://idp/auth",
                    "token_endpoint": "https://idp/token",
                    "userinfo_endpoint": "https://idp/userinfo"}
        if url.endswith("/token"):
            assert data and data.get("code"), "token exchange needs the code"
            return {"access_token": "at-123", "token_type": "Bearer"}
        if url.endswith("/userinfo"):
            assert headers.get("Authorization") == "Bearer at-123"
            return {"sub": "abc", "email": self.email, "name": self.name}
        raise AssertionError(f"unexpected call {url}")


def _svc(stub=None):
    svc = CyberRangeService(Database(":memory:"))
    if stub is not None:
        svc._oidc = oidc.OIDCClient(client_id="cid", client_secret="sec",
                                    redirect_uri="https://app/cb", issuer="https://idp",
                                    opener=stub)
    return svc


class OidcDisabledTest(unittest.TestCase):
    def test_disabled_without_config(self):
        svc = _svc()
        self.assertFalse(svc.oidc_enabled())
        with self.assertRaises(ServiceError):
            svc.oidc_login_url()


class OidcFlowTest(unittest.TestCase):
    def setUp(self):
        self.stub = StubIdP()
        self.svc = _svc(self.stub)

    def _state(self):
        url = self.svc.oidc_login_url()
        return up.parse_qs(up.urlparse(url).query)["state"][0]

    def test_login_url(self):
        url = self.svc.oidc_login_url()
        self.assertTrue(url.startswith("https://idp/auth?"))
        q = up.parse_qs(up.urlparse(url).query)
        self.assertEqual(q["client_id"], ["cid"])
        self.assertEqual(q["response_type"], ["code"])
        self.assertIn("state", q)

    def test_callback_provisions_and_exchange_issues_session(self):
        onetime = self.svc.oidc_callback("the-code", self._state())
        u = self.svc.get_user("alice@example.com")        # email lower-cased
        self.assertEqual(u["role"], "solo")               # default JIT role
        self.assertEqual(u["display_name"], "Alice")
        sess = self.svc.oidc_exchange(onetime)
        self.assertEqual(sess["username"], "alice@example.com")
        self.assertTrue(sess["token"])
        self.assertIsNotNone(self.svc.resolve_token(sess["token"]))

    def test_bad_state_rejected(self):
        with self.assertRaises(ServiceError) as cm:
            self.svc.oidc_callback("code", "not-a-real-state")
        self.assertEqual(cm.exception.status, 400)

    def test_state_is_single_use(self):
        state = self._state()
        self.svc.oidc_callback("c", state)
        with self.assertRaises(ServiceError):
            self.svc.oidc_callback("c", state)           # state already consumed

    def test_onetime_code_is_single_use(self):
        onetime = self.svc.oidc_callback("c", self._state())
        self.svc.oidc_exchange(onetime)
        with self.assertRaises(ServiceError) as cm:
            self.svc.oidc_exchange(onetime)
        self.assertEqual(cm.exception.status, 401)

    def test_admin_email_maps_to_admin(self):
        os.environ["CR_OIDC_ADMIN_EMAILS"] = "alice@example.com"
        self.addCleanup(lambda: os.environ.pop("CR_OIDC_ADMIN_EMAILS", None))
        self.svc.oidc_callback("c", self._state())
        self.assertEqual(self.svc.get_user("alice@example.com")["role"], "admin")

    def test_returning_user_is_not_duplicated(self):
        self.svc.oidc_exchange(self.svc.oidc_callback("c", self._state()))
        self.svc.oidc_exchange(self.svc.oidc_callback("c", self._state()))
        users = self.svc.list_users("admin", "admin")
        self.assertEqual(sum(1 for u in users if u["username"] == "alice@example.com"), 1)


if __name__ == "__main__":
    unittest.main()
