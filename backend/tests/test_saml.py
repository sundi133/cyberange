"""SAML SP tests.

These exercise the real signature-verification path (python3-saml / xmlsec)
against assertions we sign at runtime with a throwaway IdP key, so there is no
network and no reliance on a live IdP. The whole module is skipped when the
optional dependency is absent, mirroring how the Postgres tests treat psycopg.

The security cases are the point: a tampered, expired, wrong-audience, or
unsigned assertion MUST be rejected. If any of those ever authenticated, SAML
would be an auth bypass.
"""

import base64
import datetime
import os
import tempfile
import unittest
import urllib.parse as up
import uuid

try:
    from onelogin.saml2.utils import OneLogin_Saml2_Utils
    from onelogin.saml2.constants import OneLogin_Saml2_Constants as C
    HAVE_SAML = True
except ImportError:  # pragma: no cover - optional dependency
    HAVE_SAML = False

from cyberrange.db import Database
from cyberrange.service import CyberRangeService, ServiceError

if HAVE_SAML:
    from cyberrange import saml

# A throwaway RSA keypair + self-signed cert, generated once for these tests
# only. NOT a secret and NOT used anywhere but here.
IDP_KEY = """-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCZgapaBaeLZfIO
VBBC1XdaYxT21n2qXd1QFEApinSE/xs2W7kpdX1D7QJRhIjUyelB9h25uvpoYhQW
7mwSBIB5fb+0ISolZdxa7nBb7cqZCnl+mD+sd55Qd+hrMRuz2VwUWTxq2WbwTXGD
ADoNfC6bgZ+8xXZzZ4xz0F0U4JX5+S11TckYnk/gJqGVey7yFYRtM70lKdMT9EvL
m26wGJKHmELTd9lrthtNdWUXYos47fCWM49juB1XNT2yFJCr/8cByWh1rZvlDJ38
al5U6wEMJFjEFh0q2x/jFKiJO+szD1LiXVmJCsxZh4osyXm5om3NjcdBc7H0B6RS
FQhlxaDtAgMBAAECggEAK8oAVVO9mpdHOG0kglwwgtk21r8S8/F4u2o7b14upO28
zoHVzQzV4fWPLr/W5JSAdK+HhT7gRbyMrInwzCb6my2S7Qh05FwtQsc3yBGKNKP3
SnSV3VX2FFBQPZuxollD2g4mnPhNVAlTcyIybTxac0PD1G6jvoHwX+01UEpMnhTU
jyMxqoQpnwf8olCScYD2Ul5ncPMSHfIePfWt8QmGGRGLH73suwZ9mn7vcnm0zLnV
lXftrQYq2/7ENn4gvKaZ1rL58o1XHdvBOjO2j6jsDxITG70wgJ7B9IxcUOW0Ek1p
p2rgWjNjTgn7PFd0M65Y7jboj3/bumyRx05zKBU4xQKBgQDLWD5dhH/AuPGAW53h
K3t7HXwm0H3xBWC4tF/tiS3VsdxusMwa387hRFLGSSdhGu2Ka2uM1OZQ5ES8CWrf
O90aPoBYq+q5SjMJC1XZW58dGgquAMqqaqWyuTqTY0U1DZb7hmb6U8YsYk+RtGtY
rBJb0tYtAZqAca3s3om52D+m7wKBgQDBQaOSqe96ozwlO+3q1tYuPPz5jIwuge1j
Pp2zstguXA7kCxqLsIRBUiC+vzUNrv5Mu/BnYj/T11vqWxWixntm6/+rWk5RIteD
ThnV87ry1KTKYjsp0mPd7N7SiiGkHKiVhC/HOQ0QO50e50aOHq+SEwn/2X9Y40hd
OgA+NY0V4wKBgQCVxc5RtTkfq1j90P1Nj2ho+wOp1yEcOHjQMtMBM2wWHOYehYwg
Mz6+v0M0l0cxB9N0g8B4v4tQg4F4+nrEJ+Sn4udH6IB/r349qCK4cPqWRcsd9KlR
sjGPnUzeqFyeQf82Df2lXbT2lgbDbB8w9bSj+3wTND4nYxPXBuZsgzIG8wKBgC5O
5DtIrTHd25OwgJo9UKVTx+qkWxLp31BguLlOqa6yMH9Eid/fNFHStDYA612UCSup
/TlIubKxcD0ABncyyG8pLeKJiSq4BpxYIqi59popijNUxoiG+Zc8I0igAN+qXls1
iZ1bdl3lawj0sltrzvZZyZOdMn7CN5zfQR+nBV+xAoGBALkduLFvsOdvj0bfd0Zs
AmjHRfEQZ5fa3xbnpgippHSm+mcP+lLa0ddDibXQrrwxlEziRQEy3ZMXxgk5+GLF
yahb5Zo2v6JBWlVRmBRaw56jj0jYrNEZtMYB/jN6XulMd+ijiRawMqj2UWgB9xfb
rtd6Q9To+0Eqmcbv/fam/e90
-----END PRIVATE KEY-----"""

IDP_CERT = """-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUD4uCpTRifbt5rhivPz1lyNOr7DcwDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIVGVzdCBJZFAwHhcNMjYxMTE0MDMzNDA2WhcNMzYxMTEx
MDMzNDA2WjATMREwDwYDVQQDDAhUZXN0IElkUDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAJmBqloFp4tl8g5UEELVd1pjFPbWfapd3VAUQCmKdIT/GzZb
uSl1fUPtAlGEiNTJ6UH2Hbm6+mhiFBbubBIEgHl9v7QhKiVl3FrucFvtypkKeX6Y
P6x3nlB36GsxG7PZXBRZPGrZZvBNcYMAOg18LpuBn7zFdnNnjHPQXRTglfn5LXVN
yRieT+AmoZV7LvIVhG0zvSUp0xP0S8ubbrAYkoeYQtN32Wu2G011ZRdiizjt8JYz
j2O4HVc1PbIUkKv/xwHJaHWtm+UMnfxqXlTrAQwkWMQWHSrbH+MUqIk76zMPUuJd
WYkKzFmHiizJebmibc2Nx0FzsfQHpFIVCGXFoO0CAwEAAaNTMFEwHQYDVR0OBBYE
FHcjLhnzwwYlOPQPmieo7gskrDs2MB8GA1UdIwQYMBaAFHcjLhnzwwYlOPQPmieo
7gskrDs2MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJMYl+iX
xPDmd6Xzs5ZRzDSOxR9bBuX2g9qkvecFw7vTxEqVa1nSH18xhvpXk16ZGjL5eRN+
feDLQhXam1/+rOePaNLNsT0pKCGivOzLjdpTJb03nJoZAkvTflf2lKk+75jqTVUD
8fEXt1s8NpvfGU6bydwB1cI87iSUzYt3lblBCED8L7HOjnM9xQtiVlN/ya1C6l0Q
/NyqsvMGXns/f4WHlTrU0yLwCEjqh8wbOzCHAQrUl7LFGQKUhGPvVBSDjRpJwOoK
m+S9YgtTygGavAsty0wOokx6v2TzLPDsAf+f6IGtNtwMhV2tNkrKVj8K74hzjQox
+XMyP5wAwp9ZwyE=
-----END CERTIFICATE-----"""

SP_ENTITY = "https://range.test/sp"
ACS_URL = "https://range.test/api/auth/saml/acs"
IDP_ENTITY = "https://idp.test/metadata"
IDP_SSO = "https://idp.test/sso"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def signed_response(email="Alice@Example.com", name="Alice Example",
                    audience=SP_ENTITY, dest=ACS_URL, not_after_mins=5,
                    sign=True):
    """Build a SAMLResponse and (by default) sign its Assertion with the IdP
    key, returning base64 ready for the HTTP-POST binding."""
    now = datetime.datetime.utcnow()
    not_before = _iso(now - datetime.timedelta(minutes=1))
    not_after = _iso(now + datetime.timedelta(minutes=not_after_mins))
    resp_id = "_" + uuid.uuid4().hex
    assert_id = "_" + uuid.uuid4().hex
    assertion = (
        f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" '
        f'xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="{assert_id}" '
        f'Version="2.0" IssueInstant="{_iso(now)}">'
        f'<saml:Issuer>{IDP_ENTITY}</saml:Issuer>'
        f'<saml:Subject>'
        f'<saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">{email}</saml:NameID>'
        f'<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
        f'<saml:SubjectConfirmationData NotOnOrAfter="{not_after}" Recipient="{dest}"/>'
        f'</saml:SubjectConfirmation></saml:Subject>'
        f'<saml:Conditions NotBefore="{not_before}" NotOnOrAfter="{not_after}">'
        f'<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience>'
        f'</saml:AudienceRestriction></saml:Conditions>'
        f'<saml:AuthnStatement AuthnInstant="{_iso(now)}" SessionIndex="{assert_id}">'
        f'<saml:AuthnContext><saml:AuthnContextClassRef>'
        f'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport'
        f'</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
        f'<saml:AttributeStatement>'
        f'<saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
        f'<saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{email}</saml:AttributeValue>'
        f'</saml:Attribute>'
        f'<saml:Attribute Name="displayName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">'
        f'<saml:AttributeValue xsi:type="xs:string" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">{name}</saml:AttributeValue>'
        f'</saml:Attribute>'
        f'</saml:AttributeStatement></saml:Assertion>')
    if sign:
        signed = OneLogin_Saml2_Utils.add_sign(
            assertion, IDP_KEY, IDP_CERT, debug=False,
            sign_algorithm=C.RSA_SHA256, digest_algorithm=C.SHA256)
        assertion = signed.decode() if isinstance(signed, bytes) else signed
    xml = (
        f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        f'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{resp_id}" '
        f'Version="2.0" IssueInstant="{_iso(now)}" Destination="{dest}">'
        f'<saml:Issuer>{IDP_ENTITY}</saml:Issuer>'
        f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
        f'{assertion}</samlp:Response>')
    return base64.b64encode(xml.encode()).decode()


def _client(**over):
    kw = dict(sp_entity_id=SP_ENTITY, acs_url=ACS_URL, idp_entity_id=IDP_ENTITY,
              idp_sso_url=IDP_SSO, idp_x509cert=IDP_CERT)
    kw.update(over)
    return saml.SamlClient(**kw)


@unittest.skipUnless(HAVE_SAML, "python3-saml not installed")
class SamlClientTest(unittest.TestCase):
    def test_metadata_describes_this_sp(self):
        md = _client().metadata()
        self.assertIn(SP_ENTITY, md)
        self.assertIn(ACS_URL, md)
        self.assertIn("AssertionConsumerService", md)

    def test_login_redirect_targets_idp(self):
        url = _client().login_redirect()
        self.assertTrue(url.startswith(IDP_SSO))
        self.assertIn("SAMLRequest", up.parse_qs(up.urlparse(url).query))

    def test_valid_assertion_authenticates(self):
        result = _client().acs({"SAMLResponse": signed_response()})
        self.assertEqual(result["nameid"], "Alice@Example.com")
        self.assertIn("email", result["attributes"])
        self.assertTrue(result["assertion_id"])

    def test_email_and_display_extraction(self):
        c = _client()
        result = c.acs({"SAMLResponse": signed_response()})
        self.assertEqual(c.email_of(result), "alice@example.com")   # lower-cased
        self.assertEqual(c.display_of(result, "fallback"), "Alice Example")

    def test_tampered_assertion_rejected(self):
        # Flip a byte of the signed+base64 payload: signature must fail.
        good = signed_response()
        raw = base64.b64decode(good).replace(
            b"Alice Example", b"Mallory Attack")
        tampered = base64.b64encode(raw).decode()
        with self.assertRaises(saml.SamlError):
            _client().acs({"SAMLResponse": tampered})

    def test_unsigned_assertion_rejected(self):
        with self.assertRaises(saml.SamlError):
            _client().acs({"SAMLResponse": signed_response(sign=False)})

    def test_expired_assertion_rejected(self):
        with self.assertRaises(saml.SamlError):
            _client().acs({"SAMLResponse": signed_response(not_after_mins=-5)})

    def test_wrong_audience_rejected(self):
        with self.assertRaises(saml.SamlError):
            _client().acs({"SAMLResponse": signed_response(audience="https://evil/sp")})

    def test_wrong_destination_rejected(self):
        with self.assertRaises(saml.SamlError):
            _client().acs({"SAMLResponse": signed_response(dest="https://evil/acs")})

    def test_refuses_config_with_no_signature_requirement(self):
        # Both signature requirements off would accept unsigned assertions.
        with self.assertRaises(saml.SamlError):
            _client(want_assertions_signed=False, want_messages_signed=False)


@unittest.skipUnless(HAVE_SAML, "python3-saml not installed")
class SamlServiceTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.NamedTemporaryFile(
            mode="w", suffix=".pem", delete=False)
        self._tmp.write(IDP_CERT)
        self._tmp.close()
        self.addCleanup(lambda: os.unlink(self._tmp.name))
        env = {
            "CR_SAML_ENABLED": "1",
            "CR_SAML_ACS_URL": ACS_URL,
            "CR_SAML_SP_ENTITY_ID": SP_ENTITY,
            "CR_SAML_IDP_ENTITY_ID": IDP_ENTITY,
            "CR_SAML_IDP_SSO_URL": IDP_SSO,
            "CR_SAML_IDP_X509_CERT": "@" + self._tmp.name,
        }
        self._saved = {k: os.environ.get(k) for k in env}
        os.environ.update(env)

        def restore():
            for k, v in self._saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        self.addCleanup(restore)
        self.svc = CyberRangeService(Database(":memory:"))

    def test_enabled_from_env(self):
        self.assertTrue(self.svc.saml_enabled())

    def test_acs_provisions_and_exchange_issues_session(self):
        code = self.svc.saml_acs({"SAMLResponse": signed_response()})
        u = self.svc.get_user("alice@example.com")        # email lower-cased
        self.assertEqual(u["role"], "solo")               # default JIT role
        self.assertEqual(u["display_name"], "Alice Example")
        self.assertEqual(u["created_by"], "saml")
        sess = self.svc.oidc_exchange(code)               # shared one-time jar
        self.assertEqual(sess["username"], "alice@example.com")
        self.assertIsNotNone(self.svc.resolve_token(sess["token"]))

    def test_replayed_assertion_rejected(self):
        resp = signed_response()
        self.svc.saml_acs({"SAMLResponse": resp})
        with self.assertRaises(ServiceError) as cm:
            self.svc.saml_acs({"SAMLResponse": resp})      # same assertion id
        self.assertEqual(cm.exception.status, 400)

    def test_forged_assertion_rejected(self):
        with self.assertRaises(ServiceError) as cm:
            self.svc.saml_acs({"SAMLResponse": signed_response(sign=False)})
        self.assertEqual(cm.exception.status, 400)

    def test_admin_email_maps_to_admin(self):
        os.environ["CR_SAML_ADMIN_EMAILS"] = "alice@example.com"
        self.addCleanup(lambda: os.environ.pop("CR_SAML_ADMIN_EMAILS", None))
        self.svc.saml_acs({"SAMLResponse": signed_response()})
        self.assertEqual(self.svc.get_user("alice@example.com")["role"], "admin")

    def test_metadata_served(self):
        self.assertIn(SP_ENTITY, self.svc.saml_metadata())


class SamlDisabledTest(unittest.TestCase):
    def test_disabled_without_config(self):
        svc = CyberRangeService(Database(":memory:"))
        self.assertFalse(svc.saml_enabled())
        with self.assertRaises(ServiceError):
            svc.saml_login_redirect()


if __name__ == "__main__":
    unittest.main()
