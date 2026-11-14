"""SAML 2.0 Service Provider (optional dependency).

Enterprise SSO for IdPs that speak SAML rather than OIDC (ADFS, Shibboleth,
many on-prem Okta/Ping/Azure AD deployments). Unlike the OIDC client in
`oidc.py`, SAML **cannot** be done with the standard library: the IdP's
assertion arrives through the user's browser over an untrusted channel, so the
only thing that makes it trustworthy is its XML-DSig signature, and verifying
that needs asymmetric crypto the stdlib does not provide. We therefore delegate
to `python3-saml` (OneLogin), which verifies the signature with the C `xmlsec`
library. **The signature is never skipped** - `wantAssertionsSigned` is on by
default and this module refuses to start with all signature requirements off.

This is the control plane's one SAML dependency. It is imported lazily so the
rest of the platform stays standard-library-only: a deployment that does not
set CR_SAML_ENABLED never imports `python3-saml`, and an air-gapped install that
does enable SAML simply vendors the wheel (python3-saml, xmlsec, lxml, isodate).

Config comes from the environment (see from_env). The SAML library objects are
built per request (they are cheap and carry no state), which keeps the surface
easy to unit-test against a locally signed assertion with no network.
"""

from __future__ import annotations

import os
import urllib.parse

# HTTP-binding URIs (spelled out so we don't import the library just to name a
# constant; the library validates against the same strings).
_BINDING_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
_BINDING_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
_NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

# Attribute names an IdP commonly uses to carry the email address and display
# name, tried in order when the operator has not pinned one explicitly.
_EMAIL_ATTRS = (
    "email", "mail", "emailaddress", "urn:oid:0.9.2342.19200300.100.1.3",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
    "http://schemas.xmlsoap.org/claims/emailaddress",
)
_NAME_ATTRS = (
    "displayname", "name", "cn", "urn:oid:2.16.840.1.113730.3.1.241",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/displayname",
)


class SamlError(Exception):
    pass


def _lib():
    """Import python3-saml, turning the ImportError into a clear operator message
    (mirrors the psycopg guard in db.py)."""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth
        from onelogin.saml2.settings import OneLogin_Saml2_Settings
        return OneLogin_Saml2_Auth, OneLogin_Saml2_Settings
    except ImportError as exc:  # pragma: no cover - env dependent
        raise SamlError(
            "SAML is enabled (CR_SAML_ENABLED=1) but the optional dependency is "
            "not installed. Run: pip install python3-saml") from exc


class SamlClient:
    """A minimal SAML SP: build an AuthnRequest redirect, consume a POSTed
    assertion, and publish SP metadata. All verification is delegated to
    python3-saml / xmlsec; this class only assembles config and extracts the
    verified identity."""

    def __init__(self, *, sp_entity_id: str, acs_url: str,
                 idp_entity_id: str, idp_sso_url: str, idp_x509cert: str,
                 sp_x509cert: str = "", sp_private_key: str = "",
                 name_id_format: str = _NAMEID_EMAIL,
                 want_assertions_signed: bool = True,
                 want_messages_signed: bool = False,
                 sign_requests: bool = False, strict: bool = True,
                 email_attr: str = "", name_attr: str = ""):
        if not (idp_entity_id and idp_sso_url and idp_x509cert):
            raise SamlError("SAML needs the IdP entityID, SSO URL and X.509 cert")
        if not (want_assertions_signed or want_messages_signed):
            # Refuse the one configuration that would be an auth bypass: accepting
            # an assertion whose signature we never require.
            raise SamlError(
                "refusing to run SAML with both wantAssertionsSigned and "
                "wantMessagesSigned off - that would accept unsigned assertions")
        self.sp_entity_id = sp_entity_id
        self.acs_url = acs_url
        self.idp_entity_id = idp_entity_id
        self.idp_sso_url = idp_sso_url
        self.idp_x509cert = idp_x509cert
        self.sp_x509cert = sp_x509cert
        self.sp_private_key = sp_private_key
        self.name_id_format = name_id_format
        self.want_assertions_signed = want_assertions_signed
        self.want_messages_signed = want_messages_signed
        self.sign_requests = bool(sign_requests and sp_private_key)
        self.strict = strict
        self.email_attr = (email_attr or "").strip()
        self.name_attr = (name_attr or "").strip()

    # ---------------------------------------------------------- config ------
    def settings(self) -> dict:
        return {
            "strict": self.strict,
            "debug": False,
            "sp": {
                "entityId": self.sp_entity_id,
                "assertionConsumerService": {
                    "url": self.acs_url, "binding": _BINDING_POST},
                "NameIDFormat": self.name_id_format,
                "x509cert": self.sp_x509cert,
                "privateKey": self.sp_private_key,
            },
            "idp": {
                "entityId": self.idp_entity_id,
                "singleSignOnService": {
                    "url": self.idp_sso_url, "binding": _BINDING_REDIRECT},
                "x509cert": self.idp_x509cert,
            },
            "security": {
                "wantAssertionsSigned": self.want_assertions_signed,
                "wantMessagesSigned": self.want_messages_signed,
                "authnRequestsSigned": self.sign_requests,
                "requestedAuthnContext": False,
                "wantNameId": True,
                "signatureAlgorithm":
                    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256",
            },
        }

    def _request_data(self, post_data: dict | None = None) -> dict:
        """Synthesize python3-saml's request dict from the *configured* ACS URL
        rather than from live Host headers. This makes the library's Destination
        check compare the assertion against the URL we actually published, which
        is correct behind a reverse proxy that rewrites Host."""
        p = urllib.parse.urlparse(self.acs_url)
        https = "on" if p.scheme == "https" else "off"
        port = str(p.port or (443 if https == "on" else 80))
        return {
            "https": https,
            "http_host": p.hostname or "",
            "server_port": port,
            "script_name": p.path or "/",
            "request_uri": p.path or "/",
            "get_data": {},
            "post_data": post_data or {},
        }

    def _auth(self, post_data: dict | None = None):
        Auth, _ = _lib()
        return Auth(self._request_data(post_data), old_settings=self.settings())

    # ------------------------------------------------------------ flow ------
    def login_redirect(self, relay_state: str | None = None) -> str:
        """URL to send the browser to for SP-initiated SSO (HTTP-Redirect)."""
        return self._auth().login(return_to=relay_state)

    def acs(self, post_data: dict) -> dict:
        """Verify a POSTed SAMLResponse and return the identity it carries.

        Raises SamlError on any failure - a bad signature, a failed condition
        (NotBefore/NotOnOrAfter/Audience), a non-success status, or a missing
        subject. A return value therefore means the assertion was cryptographically
        verified against the configured IdP certificate."""
        auth = self._auth(post_data)
        try:
            auth.process_response()
        except Exception as exc:  # noqa: BLE001 - library raises various types
            raise SamlError(f"could not parse SAML response: {exc}") from exc
        errors = auth.get_errors()
        if errors:
            raise SamlError(
                f"SAML response rejected ({', '.join(errors)}): "
                f"{auth.get_last_error_reason() or 'no detail'}")
        if not auth.is_authenticated():
            raise SamlError("SAML response did not authenticate the subject")
        attrs = {k.lower(): v for k, v in (auth.get_attributes() or {}).items()}
        return {
            "nameid": auth.get_nameid(),
            "nameid_format": auth.get_nameid_format(),
            "attributes": attrs,
            "assertion_id": auth.get_last_assertion_id(),
            "session_index": auth.get_session_index(),
        }

    def email_of(self, result: dict) -> str:
        """Pull the email from a verified acs() result: the pinned attribute if
        configured, then common attribute names, then the NameID when it is an
        email-format identifier."""
        attrs = result.get("attributes", {})
        if self.email_attr:
            vals = attrs.get(self.email_attr.lower())
            if vals:
                return str(vals[0]).strip().lower()
        for key in _EMAIL_ATTRS:
            vals = attrs.get(key.lower())
            if vals:
                return str(vals[0]).strip().lower()
        nameid = (result.get("nameid") or "").strip()
        if "@" in nameid:
            return nameid.lower()
        return ""

    def display_of(self, result: dict, fallback: str) -> str:
        attrs = result.get("attributes", {})
        if self.name_attr:
            vals = attrs.get(self.name_attr.lower())
            if vals:
                return str(vals[0]).strip()
        for key in _NAME_ATTRS:
            vals = attrs.get(key.lower())
            if vals:
                return str(vals[0]).strip()
        return fallback

    def metadata(self) -> str:
        """SP metadata XML for the IdP admin to register this SP."""
        _, Settings = _lib()
        settings = Settings(self.settings(), sp_validation_only=True)
        md = settings.get_sp_metadata()
        errors = settings.validate_metadata(md)
        if errors:
            raise SamlError(f"generated SP metadata is invalid: {errors}")
        return md.decode("utf-8") if isinstance(md, bytes) else md


# ------------------------------------------------------------- env ----------
def _flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _load_pem(value: str | None) -> str:
    """Accept a cert/key as a literal PEM, or as @/path/to/file to read from
    disk. Returns the text as-is (python3-saml accepts PEM with or without the
    -----BEGIN----- armor)."""
    if not value:
        return ""
    value = value.strip()
    if value.startswith("@"):
        with open(value[1:], "r", encoding="utf-8") as fh:
            return fh.read().strip()
    return value


def _enabled() -> bool:
    return _flag("CR_SAML_ENABLED", False)


def from_env() -> "SamlClient | None":
    """Build a SamlClient from CR_SAML_* env vars, or None when SAML is off.

    Required when enabled: CR_SAML_ACS_URL, and the IdP coordinates - either
    supplied directly (CR_SAML_IDP_ENTITY_ID, CR_SAML_IDP_SSO_URL,
    CR_SAML_IDP_X509_CERT) or parsed from IdP metadata (CR_SAML_IDP_METADATA_FILE
    or CR_SAML_IDP_METADATA_URL)."""
    if not _enabled():
        return None
    acs_url = os.environ.get("CR_SAML_ACS_URL")
    if not acs_url:
        raise SamlError("CR_SAML_ENABLED is set but CR_SAML_ACS_URL is missing")

    # SP entityID defaults to this SP's metadata URL (ACS origin + /metadata).
    origin = urllib.parse.urlparse(acs_url)
    default_entity = f"{origin.scheme}://{origin.netloc}/api/auth/saml/metadata"
    sp_entity_id = os.environ.get("CR_SAML_SP_ENTITY_ID", default_entity)

    idp_entity = os.environ.get("CR_SAML_IDP_ENTITY_ID", "")
    idp_sso = os.environ.get("CR_SAML_IDP_SSO_URL", "")
    idp_cert = _load_pem(os.environ.get("CR_SAML_IDP_X509_CERT"))

    meta_file = os.environ.get("CR_SAML_IDP_METADATA_FILE")
    meta_url = os.environ.get("CR_SAML_IDP_METADATA_URL")
    if meta_file or meta_url:
        idp_entity, idp_sso, idp_cert = _merge_idp_metadata(
            meta_file, meta_url, idp_entity, idp_sso, idp_cert)

    return SamlClient(
        sp_entity_id=sp_entity_id,
        acs_url=acs_url,
        idp_entity_id=idp_entity,
        idp_sso_url=idp_sso,
        idp_x509cert=idp_cert,
        sp_x509cert=_load_pem(os.environ.get("CR_SAML_SP_X509_CERT")),
        sp_private_key=_load_pem(os.environ.get("CR_SAML_SP_PRIVATE_KEY")),
        name_id_format=os.environ.get("CR_SAML_NAMEID_FORMAT", _NAMEID_EMAIL),
        want_assertions_signed=_flag("CR_SAML_WANT_ASSERTIONS_SIGNED", True),
        want_messages_signed=_flag("CR_SAML_WANT_MESSAGES_SIGNED", False),
        sign_requests=_flag("CR_SAML_SIGN_REQUESTS", False),
        strict=_flag("CR_SAML_STRICT", True),
        email_attr=os.environ.get("CR_SAML_EMAIL_ATTR", ""),
        name_attr=os.environ.get("CR_SAML_NAME_ATTR", ""),
    )


def _merge_idp_metadata(meta_file, meta_url, idp_entity, idp_sso, idp_cert):
    """Fill any missing IdP coordinate from a metadata document. Explicit env
    values win; metadata only fills the gaps."""
    try:
        from onelogin.saml2.idp_metadata_parser import OneLogin_Saml2_IdPMetadataParser
    except ImportError as exc:  # pragma: no cover - env dependent
        raise SamlError(
            "SAML IdP metadata parsing needs python3-saml. Run: "
            "pip install python3-saml") from exc
    if meta_file:
        with open(meta_file, "r", encoding="utf-8") as fh:
            parsed = OneLogin_Saml2_IdPMetadataParser.parse(fh.read())
    else:
        parsed = OneLogin_Saml2_IdPMetadataParser.parse_remote(
            meta_url, validate_cert=True)
    idp = (parsed or {}).get("idp", {})
    idp_entity = idp_entity or idp.get("entityId", "")
    sso = idp.get("singleSignOnService", {}) or {}
    idp_sso = idp_sso or sso.get("url", "")
    idp_cert = idp_cert or _load_pem(idp.get("x509cert", ""))
    return idp_entity, idp_sso, idp_cert
