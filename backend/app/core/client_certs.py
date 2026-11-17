"""X.509 client certificates: agent authentication through a TLS-terminating proxy, and the certificates the
gateway presents to upstream MCP servers (docs/mtls.md).

The TLS handshake, which proves the client holds the private key, happens at the proxy. The gateway trusts the
forwarded certificate only from configured proxy addresses, and re-checks that it was issued by a trusted CA and
is within its validity period before matching it to a credential.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import ssl
import tempfile
import urllib.parse
from dataclasses import dataclass, field
from datetime import UTC, datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

PEM_HEADER = "-----BEGIN CERTIFICATE-----"
MAX_HEADER_BYTES = 16_384


class CertificateError(ValueError):
    """The certificate is malformed, untrusted, expired, or not meant for client authentication."""


@dataclass(frozen=True)
class CertInfo:
    fingerprint_sha256: str
    subject: str
    issuer: str
    serial: str
    not_before: datetime
    not_after: datetime
    san_uris: tuple[str, ...] = field(default_factory=tuple)
    san_dns: tuple[str, ...] = field(default_factory=tuple)

    @property
    def sans(self) -> tuple[str, ...]:
        return self.san_uris + self.san_dns

    def to_api(self) -> dict[str, object]:
        return {"fingerprint_sha256": self.fingerprint_sha256, "subject": self.subject, "issuer": self.issuer,
                "serial": self.serial, "not_before": self.not_before, "not_after": self.not_after,
                "sans": list(self.sans)}


def load_pem_certificates(pem: str) -> list[x509.Certificate]:
    if PEM_HEADER not in pem:
        raise CertificateError("Expected a PEM certificate (-----BEGIN CERTIFICATE-----).")
    try:
        return x509.load_pem_x509_certificates(pem.encode())
    except ValueError as exc:
        raise CertificateError("The certificate could not be parsed.") from exc


def load_certificate(pem: str) -> x509.Certificate:
    certs = load_pem_certificates(pem)
    return certs[0]  # the leaf; anything after it is chain


def describe(cert: x509.Certificate) -> CertInfo:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        uris = tuple(san.get_values_for_type(x509.UniformResourceIdentifier))
        dns = tuple(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        uris, dns = (), ()
    return CertInfo(
        fingerprint_sha256=cert.fingerprint(hashes.SHA256()).hex(),
        subject=cert.subject.rfc4514_string(), issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc, not_after=cert.not_valid_after_utc, san_uris=uris, san_dns=dns,
    )


def common_name(cert: x509.Certificate) -> str | None:
    attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    return str(attrs[0].value) if attrs else None


def decode_forwarded(value: str) -> x509.Certificate:
    """The certificate as a proxy forwards it: URL-escaped PEM (nginx ``$ssl_client_escaped_cert``, Traefik), or
    base64 DER without PEM armour (HAProxy ``ssl_c_der,base64``)."""
    if not value or len(value) > MAX_HEADER_BYTES:
        raise CertificateError("Missing or oversized client certificate header.")
    text = urllib.parse.unquote(value.strip().strip('"'))
    if PEM_HEADER in text:
        return load_certificate(text)
    try:
        return x509.load_der_x509_certificate(base64.b64decode(text, validate=True))
    except ValueError as exc:
        raise CertificateError("The forwarded client certificate could not be parsed.") from exc


class ClientCertVerifier:
    """Checks a forwarded agent certificate against the CA bundle that may issue agent certificates.

    The bundle must contain each certificate's direct issuer (the issuing intermediate, or the root for a
    single-level PKI). Revocation of individual certificates is the proxy's job (``ssl_crl``) or done by revoking
    the credential in the console."""

    def __init__(self, ca_pem: str) -> None:
        self.cas = load_pem_certificates(ca_pem)

    @classmethod
    def from_file(cls, path: str) -> ClientCertVerifier:
        with open(path, encoding="utf-8") as f:
            return cls(f.read())

    def verify(self, cert: x509.Certificate, now: datetime | None = None) -> CertInfo:
        now = now or datetime.now(UTC)
        issuer = next((ca for ca in self.cas if _issued_by(cert, ca)), None)
        if issuer is None:
            raise CertificateError("The client certificate was not issued by a trusted CA.")
        if not (issuer.not_valid_before_utc <= now <= issuer.not_valid_after_utc):
            raise CertificateError("The issuing CA certificate is not valid now.")
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise CertificateError("The client certificate is expired or not yet valid.")
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if ExtendedKeyUsageOID.CLIENT_AUTH not in eku and ExtendedKeyUsageOID.ANY_EXTENDED_KEY_USAGE not in eku:
                raise CertificateError("The certificate is not valid for client authentication.")
        except x509.ExtensionNotFound:
            pass  # no EKU extension: any usage
        try:
            if cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
                raise CertificateError("A CA certificate can't be used as a client certificate.")
        except x509.ExtensionNotFound:
            pass
        return describe(cert)


def _issued_by(cert: x509.Certificate, ca: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(ca)
        return True
    except Exception:  # noqa: BLE001 - name mismatch, bad signature, unsupported key type
        return False


def parse_networks(cidrs: list[str]) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    return [ipaddress.ip_network(c, strict=False) for c in cidrs]


def address_in(host: str | None, networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bool:
    if not host or not networks:
        return False
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(ip in n for n in networks)


# ---------------------------------------------------------------- upstream (outbound) client certificates
def check_key_pair(cert_pem: str, key_pem: str) -> CertInfo:
    """Validate an upstream client certificate and its private key, and that they belong together."""
    cert = load_certificate(cert_pem)
    try:
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise CertificateError("The private key could not be parsed (PEM, unencrypted).") from exc
    pub = serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(serialization.Encoding.DER, pub) != \
            cert.public_key().public_bytes(serialization.Encoding.DER, pub):
        raise CertificateError("The private key does not match the certificate.")
    return describe(cert)


def build_ssl_context(*, verify: bool, ca_pem: str | None, cert_pem: str | None, key_pem: str | None,
                      default_cafile: str | None = None) -> ssl.SSLContext:
    """An SSL context for an upstream: its CA bundle (or the default trust store) and, optionally, the client
    certificate the gateway presents. ``ssl`` only loads key pairs from files, so the pair is written to a
    private temporary file (tmpfs in the containers) and removed as soon as it is loaded."""
    ctx = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context(cafile=default_cafile)
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if cert_pem and key_pem:
        fd, path = tempfile.mkstemp(prefix="mgw-upstream-", suffix=".pem")
        try:
            os.chmod(path, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(cert_pem.strip() + "\n" + key_pem.strip() + "\n")
            ctx.load_cert_chain(path)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass
    return ctx
