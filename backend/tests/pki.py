"""A throwaway PKI for the mTLS tests: CAs, agent client certificates and upstream server certificates."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


@dataclass
class Issued:
    cert: x509.Certificate
    key: ec.EllipticCurvePrivateKey

    @property
    def cert_pem(self) -> str:
        return self.cert.public_bytes(serialization.Encoding.PEM).decode()

    @property
    def key_pem(self) -> str:
        return self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()).decode()

    @property
    def fingerprint(self) -> str:
        return self.cert.fingerprint(hashes.SHA256()).hex()


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MCP-Gateway tests"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn: str = "Test Agent CA") -> Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    cert = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                                         key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return Issued(cert, key)


def make_leaf(ca: Issued, cn: str, *, uris: tuple[str, ...] = (), dns: tuple[str, ...] = (),
              ips: tuple[str, ...] = (), usage: str = "client", valid_from_days: int = -1,
              valid_days: int = 7) -> Issued:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(UTC)
    sans: list[x509.GeneralName] = [x509.UniformResourceIdentifier(u) for u in uris]
    sans += [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    eku = {"client": [ExtendedKeyUsageOID.CLIENT_AUTH], "server": [ExtendedKeyUsageOID.SERVER_AUTH]}[usage]
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca.cert.subject).public_key(key.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now + timedelta(days=valid_from_days))
         .not_valid_after(now + timedelta(days=valid_from_days + valid_days))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage(eku), critical=False))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(sans), critical=False)
    return Issued(b.sign(ca.key, hashes.SHA256()), key)
