"""OIDC client guards that don't need an IdP."""

import pytest

from app.config import Settings
from app.services.oidc_client import OidcClient, OidcError, pkce_pair
from app.services.sso_service import safe_return_to


def _settings(env: str, insecure: bool) -> Settings:
    return Settings.model_construct(app_env=env, oidc_allow_insecure_http=insecure)


def test_http_issuer_is_never_allowed_in_production():
    with pytest.raises(OidcError):
        OidcClient(_settings("production", True)).check_url("http://idp.internal", "issuer")
    OidcClient(_settings("development", True)).check_url("http://idp.internal", "issuer")
    with pytest.raises(OidcError):
        OidcClient(_settings("development", False)).check_url("http://idp.internal", "issuer")
    OidcClient(_settings("production", False)).check_url("https://idp.internal", "issuer")


def test_pkce_pair_is_s256():
    import base64
    import hashlib

    verifier, challenge = pkce_pair()
    assert 43 <= len(verifier) <= 128
    assert challenge == base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")


@pytest.mark.parametrize("value,expected", [
    ("/tools", "/tools"), ("/servers/srv_1?tab=health", "/servers/srv_1?tab=health"), (None, "/"), ("", "/"),
    ("//evil.example", "/"), ("/\evil.example", "/"), ("https://evil.example", "/"), ("/api/v1/auth/me", "/"),
    ("/x\r\nSet-Cookie: a=b", "/"),
])
def test_safe_return_to(value, expected):
    assert safe_return_to(value) == expected
