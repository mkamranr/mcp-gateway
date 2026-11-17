"""LDAP client internals: DN normalisation, ID decoding, and TLS verification against a real TLS socket."""

from __future__ import annotations

import socket
import ssl
import tempfile
import threading
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

from app.config import Settings
from app.models.ldap import LdapConfigBase, normalize_dn
from app.services.ldap_client import LdapDirectory, LdapError, _unique_id, check_username
from tests.pki import Issued, make_ca, make_leaf


def test_normalize_dn_ignores_case_and_spacing():
    assert normalize_dn("CN=MGW Admins, OU=Groups,DC=Corp, DC=Example") == "cn=mgw admins,ou=groups,dc=corp,dc=example"
    assert normalize_dn("cn=a\\,b,dc=x") == normalize_dn("CN=a\\,b, DC=X")
    for bad in ("", "MGW Admins", "cn=", "=x"):
        with pytest.raises(ValueError):
            normalize_dn(bad)


def test_unique_id_decoding():
    guid = uuid.uuid4()
    assert _unique_id([guid.bytes_le]) == str(guid)  # AD objectGUID: binary, little-endian layout
    assert _unique_id([b"5A1B-C"]) == "5a1b-c"
    assert _unique_id([]) is None


def test_username_checks():
    assert check_username("  alice ") == "alice"
    for bad in ("", "   ", "a\x00b", "x" * 257):
        with pytest.raises(LdapError):
            check_username(bad)


def test_defaults_are_openldap_and_ad_is_expressible():
    d = LdapConfigBase()
    assert d.user_filter == "(&(objectClass=person)(uid={username}))" and d.unique_id_attribute == "entryUUID"
    ad = LdapConfigBase(user_filter="(&(objectClass=user)(sAMAccountName={username})"
                                    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))",
                        username_attribute="sAMAccountName", unique_id_attribute="objectGUID",
                        group_search_base="DC=corp,DC=example",
                        group_search_filter="(member:1.2.840.113556.1.4.1941:={user_dn})")
    assert ad.username_attribute == "sAMAccountName"


# ---------------------------------------------------------------- TLS against a real socket
@pytest.fixture(scope="module")
def pki() -> tuple[Issued, Issued]:
    ca = make_ca("Test Directory CA")
    return ca, make_leaf(ca, "ldap.test", dns=("localhost",), usage="server")


@pytest.fixture
def tls_server(pki: tuple[Issued, Issued]) -> Iterator[int]:
    """Completes TLS handshakes on 127.0.0.1 and then closes; enough to prove what the client accepts."""
    _, leaf = pki
    with tempfile.TemporaryDirectory() as d:
        cert, key = Path(d, "c.pem"), Path(d, "k.pem")
        cert.write_text(leaf.cert_pem)
        key.write_text(leaf.key_pem)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)
    sock.settimeout(0.2)
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = sock.accept()
            except OSError:
                continue
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.settimeout(1)
                    try:
                        tls.recv(1)
                    except OSError:
                        pass
            except (ssl.SSLError, OSError):
                conn.close()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    yield sock.getsockname()[1]
    stop.set()
    t.join(2)
    sock.close()


def _cfg(url: str, ca: str = "", **kw: object) -> dict[str, object]:
    return {"server_urls": [url], "ca_pem": ca, "timeout_seconds": 3, "start_tls": False, **kw}


def _settings(**kw: object) -> Settings:
    return Settings(app_env="test", session_secret="s" * 40, data_encryption_key="A" * 43 + "=",
                    api_key_hash_pepper="p" * 40, **kw)  # type: ignore[arg-type]


def test_ldaps_with_the_right_ca_and_host_name_connects(pki, tls_server):
    ca, _ = pki
    conn = LdapDirectory(_settings())._open(f"ldaps://localhost:{tls_server}", _cfg("", ca.cert_pem), None, None)
    assert conn.server.ssl and not conn.closed
    conn.unbind()


def test_ldaps_rejects_a_host_name_mismatch(pki, tls_server):
    ca, _ = pki
    with pytest.raises(LdapError) as exc:  # the certificate names "localhost", not 127.0.0.1
        LdapDirectory(_settings())._open(f"ldaps://127.0.0.1:{tls_server}", _cfg("", ca.cert_pem), None, None)
    assert exc.value.code == "tls"


def test_ldaps_rejects_an_untrusted_ca(tls_server):
    other = make_ca("Someone else")
    with pytest.raises(LdapError) as exc:
        LdapDirectory(_settings())._open(f"ldaps://localhost:{tls_server}", _cfg("", other.cert_pem), None, None)
    assert exc.value.code == "tls"


def test_clear_text_is_refused_unless_explicitly_allowed_outside_production():
    with pytest.raises(LdapError) as exc:
        LdapDirectory(_settings())._open("ldap://localhost:1", _cfg(""), None, None)
    assert exc.value.code == "config"
    prod = _settings(ldap_allow_insecure=True)
    prod.app_env = "production"
    with pytest.raises(LdapError) as exc:
        LdapDirectory(prod)._open("ldap://localhost:1", _cfg(""), None, None)
    assert exc.value.code == "config"
    with pytest.raises(LdapError) as exc:  # allowed, but nothing listens on port 1
        LdapDirectory(_settings(ldap_allow_insecure=True))._open("ldap://localhost:1", _cfg(""), None, None)
    assert exc.value.code == "unavailable"


def test_service_account_without_password_is_a_config_error():
    with pytest.raises(LdapError) as exc:
        LdapDirectory(_settings()).check({**_cfg("ldaps://localhost:1"), "bind_dn": "cn=svc,dc=x"}, None)
    assert exc.value.code == "config"
