"""SIEM forwarding (Phase 6): real syslog/HTTP receivers on localhost, delivery guarantees, formats, config."""

from __future__ import annotations

import asyncio
import datetime as dt
import json
import ssl
import tempfile
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from app.core.ids import new_id, utcnow
from app.services import siem_service
from app.services.siem_format import frame_tcp, syslog_message, to_cef

TOKEN = "Splunk 0f6c-hec-token"  # noqa: S105 (test value)


@pytest.fixture(autouse=True)
def no_lag(monkeypatch):
    monkeypatch.setattr(siem_service, "LAG_SECONDS", 0)


# ---------------------------------------------------------------- receivers
def _pki() -> tuple[str, str, str]:
    """(CA PEM, server cert PEM, server key PEM) for 127.0.0.1 / localhost."""
    now = dt.datetime.now(dt.UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test SIEM CA")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    import ipaddress

    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"),
                                                        x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
                           critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    return (ca.public_bytes(pem).decode(), cert.public_bytes(pem).decode(),
            key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode())


class StreamReceiver:
    """Syslog over TCP or TLS with RFC 6587 octet counting."""

    def __init__(self) -> None:
        self.messages: list[str] = []
        self.server: asyncio.Server | None = None
        self.port = 0

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        buf = b""
        try:
            while chunk := await reader.read(65536):
                buf += chunk
                while b" " in buf:
                    length, _, rest = buf.partition(b" ")
                    n = int(length)
                    if len(rest) < n:
                        break
                    self.messages.append(rest[:n].decode())
                    buf = rest[n:]
        finally:
            writer.close()

    async def start(self, tls: ssl.SSLContext | None = None) -> StreamReceiver:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=tls)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


class HttpReceiver:
    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.requests: list[dict[str, Any]] = []
        self.server: asyncio.Server | None = None
        self.port = 0

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        head = await reader.readuntil(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        headers = {k.lower(): v.strip() for k, _, v in (h.partition(":") for h in lines[1:] if h)}
        body = await reader.readexactly(int(headers.get("content-length", "0")))
        self.requests.append({"line": lines[0], "headers": headers, "body": body.decode()})
        writer.write(f"HTTP/1.1 {self.status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".encode())
        await writer.drain()
        writer.close()

    async def start(self, tls: ssl.SSLContext | None = None) -> HttpReceiver:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=tls)
        self.port = self.server.sockets[0].getsockname()[1]
        return self

    async def stop(self) -> None:
        if self.server:
            self.server.close()
            await self.server.wait_closed()


def _server_tls(cert: str, key: str) -> ssl.SSLContext:
    d = Path(tempfile.mkdtemp())
    (d / "c.pem").write_text(cert)
    (d / "k.pem").write_text(key)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    return ctx


async def configure(admin: Any, **kw: Any) -> dict[str, Any]:
    body = {"enabled": True, "transport": "syslog_tcp", "host": "127.0.0.1", "port": 9, **kw}
    r = await admin.put("/api/v1/siem/config", json=body)
    assert r.status_code == 200, r.text
    return r.json()


async def emit(container: Any, n: int = 3, severity: str = "info", prefix: str = "drill.event") -> list[str]:
    ids = []
    for i in range(n):
        e = await container.audit.record("ten_x", f"{prefix}.{i}", severity=severity,
                                         principal={"type": "user", "id": "usr_1", "name": "alice"},
                                         metadata={"source_ip": "10.1.2.3", "i": i})
        ids.append(e["event_id"])
    return ids


async def until(cond: Any, timeout: float = 5.0) -> None:
    """The sender returns once the bytes are written; the receiver task may not have parsed them yet."""
    for _ in range(int(timeout / 0.02)):
        if cond():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("receiver did not get the expected data in time")


def payload_of(msg: str) -> str:
    # RFC 5424: PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP SD SP MSG
    return msg.split(" ", 7)[7]


# ---------------------------------------------------------------- delivery
async def test_tcp_json_delivery_in_order_without_duplicates(admin, container):
    rx = await StreamReceiver().start()
    try:
        await configure(admin, port=rx.port)
        ids = await emit(container, 5)
        sent = await container.siem.forward_once("w1")
        assert sent >= 5
        await until(lambda: len(rx.messages) >= sent)
        got = [json.loads(payload_of(m)) for m in rx.messages]
        drill = [(g, m) for g, m in zip(got, rx.messages, strict=True) if g["event_type"].startswith("drill.event")]
        assert sorted(g["event_id"] for g, _ in drill) == sorted(ids)  # each exactly once
        stamps = [g["@timestamp"] for g in got]
        assert stamps == sorted(stamps)  # timestamp order (millisecond resolution)
        g, m = drill[0]
        assert m.startswith("<110>1 ")  # facility 13 (log audit) * 8 + severity 6 (info)
        assert g["principal"]["name"] == "alice" and g["metadata"]["source_ip"] == "10.1.2.3"
        before = len(rx.messages)
        assert await container.siem.forward_once("w1") == 0  # nothing new: nothing re-sent
        assert len(rx.messages) == before
        st = (await admin.get("/api/v1/siem/status")).json()
        assert st["enabled"] and not st["failing"] and st["forwarded_total"] >= 5 and st["pending_events"] == 0
    finally:
        await rx.stop()


async def test_enabling_starts_from_now(admin, container):
    old = await emit(container, 2, prefix="before.enable")
    rx = await StreamReceiver().start()
    try:
        await configure(admin, port=rx.port)
        new = await emit(container, 1, prefix="after.enable")
        await container.siem.forward_once("w1")
        await until(lambda: any(new[0] in m for m in rx.messages))
        types = [json.loads(payload_of(m))["event_id"] for m in rx.messages]
        assert new[0] in types and not set(old) & set(types)
    finally:
        await rx.stop()


async def test_outage_loses_nothing_and_is_audited_once(admin, container, monkeypatch):
    rx = StreamReceiver()
    await configure(admin, port=1)  # nothing listens on port 1
    ids = await emit(container, 4)
    assert await container.siem.forward_once("w1") == 0
    st = (await admin.get("/api/v1/siem/status")).json()
    assert st["failing"] and "connect" in st["last_error"] and st["pending_events"] >= 4
    assert await container.siem.forward_once("w1") == 0  # backing off: no hammering
    await container.redis.delete(siem_service.STATUS_KEY + ":backoff")
    await container.siem.forward_once("w1")  # second failure
    failed = [e async for e in container.repos.audit.col.find({"event_type": "siem.forwarding.failed"})]
    assert len(failed) == 1 and failed[0]["severity"] == "high"
    await rx.start()
    try:
        await configure(admin, port=rx.port)  # saving the config also clears the backoff
        await container.siem.forward_once("w1")
        await until(lambda: all(any(i in m for m in rx.messages) for i in ids))
        got = [json.loads(payload_of(m))["event_id"] for m in rx.messages]
        assert all(i in got for i in ids)  # everything written during the outage arrives
        assert (await admin.get("/api/v1/siem/status")).json()["failing"] is False
        assert await container.repos.audit.col.find_one({"event_type": "siem.forwarding.recovered"})
    finally:
        await rx.stop()


async def test_late_committed_event_inside_overlap_is_still_delivered(admin, container):
    rx = await StreamReceiver().start()
    try:
        await configure(admin, port=rx.port)
        await emit(container, 1)
        await container.siem.forward_once("w1")
        # A slow writer commits an event stamped 30 s ago, behind the cursor but after enabling.
        state = await container.repos.settings.get_value(siem_service.STATE_KEY)
        floor = dt.datetime.fromisoformat(state["floor"])
        await container.repos.settings.set_value(siem_service.STATE_KEY, {
            **state, "floor": (floor - dt.timedelta(minutes=5)).isoformat()}, "test")
        late = {"event_id": new_id("evt"), "timestamp": utcnow() - dt.timedelta(seconds=30),
                "event_type": "late.event", "severity": "info", "metadata": {}}
        await container.repos.audit.append("ten_x", late)
        await container.siem.forward_once("w1")
        await until(lambda: any(late["event_id"] in m for m in rx.messages))
        got = [json.loads(payload_of(m))["event_id"] for m in rx.messages]
        assert got.count(late["event_id"]) == 1
    finally:
        await rx.stop()


async def test_filters_by_severity_and_event_type(admin, container):
    rx = await StreamReceiver().start()
    try:
        await configure(admin, port=rx.port, min_severity="high", event_types=["auth.", "drill.keep"])
        await emit(container, 2, severity="info", prefix="auth.noise")
        keep = await emit(container, 1, severity="high", prefix="auth.login")
        await emit(container, 1, severity="critical", prefix="other.thing")
        keep += await emit(container, 1, severity="critical", prefix="drill.keep")
        await container.siem.forward_once("w1")
        await until(lambda: len(rx.messages) >= len(keep))
        got = [json.loads(payload_of(m))["event_id"] for m in rx.messages]
        assert sorted(got) == sorted(keep)
        assert (await admin.get("/api/v1/siem/status")).json()["pending_events"] == 0  # filtered still advance
    finally:
        await rx.stop()


async def test_tls_requires_the_configured_ca(admin, container):
    ca, cert, key = _pki()
    rx = await StreamReceiver().start(_server_tls(cert, key))
    try:
        await configure(admin, transport="syslog_tls", port=rx.port)  # system trust store: cert is unknown
        await emit(container, 1)
        assert await container.siem.forward_once("w1") == 0
        assert "SSL" in (await admin.get("/api/v1/siem/status")).json()["last_error"].upper()
        await configure(admin, transport="syslog_tls", port=rx.port, tls_ca_pem=ca)
        assert await container.siem.forward_once("w1") >= 1
        await until(lambda: bool(rx.messages))
    finally:
        await rx.stop()


async def test_udp_delivery(admin, container):
    got: list[bytes] = []

    class Proto(asyncio.DatagramProtocol):
        def datagram_received(self, data: bytes, addr: Any) -> None:
            got.append(data)

    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(Proto, local_addr=("127.0.0.1", 0))
    try:
        port = transport.get_extra_info("sockname")[1]
        await configure(admin, transport="syslog_udp", port=port, format="cef")
        await emit(container, 2)
        await container.siem.forward_once("w1")
        for _ in range(50):
            if len(got) >= 2:
                break
            await asyncio.sleep(0.02)
        assert any(b"CEF:0|MCP-Gateway|MCP-Gateway|" in g for g in got)
    finally:
        transport.close()


async def test_https_splunk_hec_with_write_only_token(admin, container):
    ca, cert, key = _pki()
    rx = await HttpReceiver().start(_server_tls(cert, key))
    try:
        cfg = await configure(admin, transport="http", url=f"https://127.0.0.1:{rx.port}/services/collector/event",
                              http_body="splunk_hec", http_auth_value=TOKEN, tls_ca_pem=ca)
        assert cfg["has_http_auth_value"] is True and TOKEN not in json.dumps(cfg)
        ids = await emit(container, 3)
        await container.siem.forward_once("w1")
        await until(lambda: bool(rx.requests))
        req = rx.requests[0]
        assert req["headers"]["authorization"] == TOKEN and req["line"].startswith("POST /services/collector/event")
        events = [json.loads(line) for line in req["body"].splitlines()]
        assert {e["event"]["event_id"] for e in events} >= set(ids)
        assert all(e["sourcetype"] == "mcp-gateway:audit" and isinstance(e["time"], float) for e in events)
        audits = [e async for e in container.repos.audit.col.find({"event_type": "siem.config.updated"})]
        assert audits and all(TOKEN not in json.dumps(a, default=str) for a in audits)
        raw = await container.repos.settings.col.find_one({"key": "siem"})
        assert TOKEN not in json.dumps(raw, default=str)
    finally:
        await rx.stop()


async def test_http_error_status_is_a_failure(admin, container):
    rx = await HttpReceiver(status=503).start()
    try:
        await configure(admin, transport="http", url=f"http://127.0.0.1:{rx.port}/ingest")
        await emit(container, 1)
        assert await container.siem.forward_once("w1") == 0
        assert "503" in (await admin.get("/api/v1/siem/status")).json()["last_error"]
        rx.status = 200
        await container.redis.delete(siem_service.STATUS_KEY + ":backoff")
        assert await container.siem.forward_once("w1") >= 1
        await until(lambda: len(rx.requests) >= 2)
        body = rx.requests[-1]["body"]
        assert all(json.loads(line)["source"] == "mcp-gateway" for line in body.splitlines())  # ndjson
    finally:
        await rx.stop()


async def test_only_one_worker_forwards(admin, container):
    rx = await StreamReceiver().start()
    try:
        await configure(admin, port=rx.port)
        await emit(container, 2)
        assert await container.siem.forward_once("w1") >= 2
        await emit(container, 1)
        assert await container.siem.forward_once("w2") == 0  # w1 holds the lease
        assert await container.siem.forward_once("w1") >= 1
    finally:
        await rx.stop()


async def test_connection_test_endpoint(admin, container):
    rx = await StreamReceiver().start()
    try:
        await configure(admin, port=rx.port, enabled=False)
        r = (await admin.post("/api/v1/siem/test")).json()
        assert r["ok"]
        await until(lambda: bool(rx.messages))
        assert json.loads(payload_of(rx.messages[0]))["event_type"] == "siem.test"
    finally:
        await rx.stop()
    await configure(admin, port=1, enabled=False)
    r = (await admin.post("/api/v1/siem/test")).json()
    assert r["ok"] is False and "connect" in r["error"]


# ---------------------------------------------------------------- configuration
async def test_config_validation_and_access(app, admin):
    bad = [
        {"enabled": True, "transport": "syslog_tcp", "host": ""},
        {"enabled": True, "transport": "http", "url": ""},
        {"enabled": True, "transport": "http", "url": "https://user:pw@siem.example/x"},
        {"enabled": True, "transport": "syslog_tcp", "host": "169.254.169.254", "port": 514},
        {"enabled": True, "transport": "syslog_tls", "host": "siem", "tls_ca_pem": "not a pem"},
        {"enabled": True, "transport": "syslog_tls", "host": "siem",
         "tls_ca_pem": "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"},
        {"transport": "http", "url": "https://s.example", "http_body": "splunk_hec", "format": "cef"},
        {"transport": "syslog_tcp", "host": "s.example:514"},
    ]
    for body in bad:
        assert (await admin.put("/api/v1/siem/config", json=body)).status_code == 422, body
    r = await admin.post("/api/v1/tenants", json={"name": "Siem T", "slug": "siem-t", "admin_username": "siem-ta",
                                                   "admin_password": "Siem-Tenant-Admin-1"})
    assert r.status_code == 201, r.text
    from tests.conftest import ApiClient, make_client

    async with make_client(app) as http:
        c = ApiClient(http)
        await c.login("siem-ta", "Siem-Tenant-Admin-1")
        assert (await c.get("/api/v1/siem/config")).status_code == 403
        assert (await c.put("/api/v1/siem/config", json={})).status_code == 403


# ---------------------------------------------------------------- encodings
def _event(**kw: Any) -> dict[str, Any]:
    return {"event_id": "evt_1", "timestamp": dt.datetime(2026, 11, 16, 6, 0, tzinfo=dt.UTC),
            "event_type": "auth.login.failed", "severity": "high", "tenant_id": "ten_1",
            "principal": {"type": "user", "id": "usr_1", "name": "a|b=c\\d"}, "status": "failure",
            "metadata": {"source_ip": "10.0.0.1", "note": "line1\nline2"}, **kw}


def test_cef_escaping():
    cef = to_cef(_event(event_type="weird|type"))
    head, _, ext = cef.partition("|8|")  # severity high -> 8 closes the 7-field header
    assert head.startswith("CEF:0|MCP-Gateway|MCP-Gateway|") and "weird\\|type" in head
    assert ext.startswith("rt=1794808800000 externalId=evt_1 ")
    assert "suser=a|b\\=c\\\\d" in cef and "src=10.0.0.1" in cef and "outcome=failure" in cef
    assert "\n" not in cef and "\\n" in cef
    assert "|8|" in cef  # high -> CEF severity 8
    assert ext


def test_syslog_framing():
    msg = syslog_message(_event(), "json", facility=13, hostname="gw 1")
    assert msg.startswith(b"<107>1 2026-11-16T06:00:00.000Z gw1 mcp-gateway - auth.login.failed - {")
    framed = frame_tcp(msg)
    assert framed == str(len(msg)).encode() + b" " + msg
    assert json.loads(msg.split(b" - ", 2)[2])["event_id"] == "evt_1"


async def test_metrics_expose_siem_state_to_platform_admins_only(app, admin, container):
    rx = await StreamReceiver().start()
    try:
        await configure(admin, port=rx.port)
        await emit(container, 1)
        await container.siem.forward_once("w1")
        body = (await admin.get("/api/v1/metrics")).text
        assert "mgw_siem_up 1" in body and "mgw_siem_forwarded_events" in body
    finally:
        await rx.stop()
    r = await admin.post("/api/v1/tenants", json={"name": "Metrics T", "slug": "metrics-t",
                                                   "admin_username": "metrics-ta", "admin_password": "Metrics-Admin-Pass-1"})
    assert r.status_code == 201
    from tests.conftest import ApiClient, make_client

    async with make_client(app) as http:
        c = ApiClient(http)
        await c.login("metrics-ta", "Metrics-Admin-Pass-1")
        body = (await c.get("/api/v1/metrics")).text
        assert "mgw_invocations_total" in body and "mgw_siem" not in body
