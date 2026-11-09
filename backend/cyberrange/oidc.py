"""Minimal OIDC Authorization-Code client (standard library only).

Enterprise SSO without adding a crypto dependency. We run the confidential-
client Authorization Code flow and read identity from the IdP's **userinfo**
endpoint rather than verifying an id_token signature locally: the code is
exchanged server-to-IdP over TLS (authenticated with the client secret) and
userinfo is fetched over TLS, so every token we trust came straight from the
IdP, never through the browser. That keeps the control plane stdlib-only while
staying a correct code flow (CSRF-protected by `state`, single-use `code`).

Config comes from the environment (see from_env). HTTP is injectable so the
flow is unit-tested against a stub with no network.
"""

from __future__ import annotations

import json
import os
import urllib.parse
import urllib.request


class OIDCError(Exception):
    pass


class OIDCClient:
    def __init__(self, *, client_id: str, client_secret: str, redirect_uri: str,
                 issuer: str | None = None, auth_url: str | None = None,
                 token_url: str | None = None, userinfo_url: str | None = None,
                 scopes: str = "openid email profile", opener=None):
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self._issuer = issuer
        self._auth_url = auth_url
        self._token_url = token_url
        self._userinfo_url = userinfo_url
        # opener(method, url, data: dict|None, headers: dict|None) -> dict
        self._opener = opener

    # ----------------------------------------------------------- http ------
    def _http(self, method: str, url: str, data: dict | None = None,
              headers: dict | None = None) -> dict:
        if self._opener is not None:
            return self._opener(method, url, data, headers)
        body = urllib.parse.urlencode(data).encode() if data else None
        req = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 - IdP URL from config
                return json.loads(resp.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - surface as an OIDC error
            raise OIDCError(f"OIDC HTTP {method} {url} failed: {exc}") from exc

    def _discover(self) -> None:
        if self._auth_url and self._token_url and self._userinfo_url:
            return
        if not self._issuer:
            raise OIDCError("OIDC needs an issuer or explicit endpoint URLs")
        doc = self._http("GET", self._issuer.rstrip("/") + "/.well-known/openid-configuration")
        self._auth_url = self._auth_url or doc.get("authorization_endpoint")
        self._token_url = self._token_url or doc.get("token_endpoint")
        self._userinfo_url = self._userinfo_url or doc.get("userinfo_endpoint")
        if not (self._auth_url and self._token_url and self._userinfo_url):
            raise OIDCError("OIDC discovery did not return all required endpoints")

    # --------------------------------------------------------- flow --------
    def auth_url(self, state: str) -> str:
        self._discover()
        q = urllib.parse.urlencode({
            "response_type": "code", "client_id": self.client_id,
            "redirect_uri": self.redirect_uri, "scope": self.scopes, "state": state})
        return f"{self._auth_url}?{q}"

    def exchange_code(self, code: str) -> str:
        self._discover()
        tok = self._http("POST", self._token_url, data={
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": self.redirect_uri, "client_id": self.client_id,
            "client_secret": self.client_secret},
            headers={"Content-Type": "application/x-www-form-urlencoded",
                     "Accept": "application/json"})
        access = tok.get("access_token")
        if not access:
            raise OIDCError("token exchange returned no access_token")
        return access

    def userinfo(self, access_token: str) -> dict:
        self._discover()
        return self._http("GET", self._userinfo_url,
                          headers={"Authorization": "Bearer " + access_token})


def _enabled() -> bool:
    return os.environ.get("CR_OIDC_ENABLED", "").lower() in ("1", "true", "yes")


def from_env(opener=None) -> OIDCClient | None:
    """Build a client from CR_OIDC_* env vars, or None when SSO is off."""
    if not _enabled():
        return None
    cid = os.environ.get("CR_OIDC_CLIENT_ID")
    secret = os.environ.get("CR_OIDC_CLIENT_SECRET")
    redirect = os.environ.get("CR_OIDC_REDIRECT_URI")
    if not (cid and secret and redirect):
        return None
    return OIDCClient(
        client_id=cid, client_secret=secret, redirect_uri=redirect,
        issuer=os.environ.get("CR_OIDC_ISSUER"),
        auth_url=os.environ.get("CR_OIDC_AUTH_URL"),
        token_url=os.environ.get("CR_OIDC_TOKEN_URL"),
        userinfo_url=os.environ.get("CR_OIDC_USERINFO_URL"),
        scopes=os.environ.get("CR_OIDC_SCOPES", "openid email profile"),
        opener=opener)
