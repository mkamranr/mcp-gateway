"""A small stand-in for HashiCorp Vault's transit engine and login endpoints, for tests and the dev stack.

Implements, with Vault's request and response shapes:
  POST /v1/<mount>/encrypt/<key>   {"plaintext": b64}       -> {"data": {"ciphertext": "vault:vN:..."}}
  POST /v1/<mount>/decrypt/<key>   {"ciphertext": ...}      -> {"data": {"plaintext": b64}}
  POST /v1/<mount>/rewrap/<key>    {"ciphertext": ...}      -> {"data": {"ciphertext": "vault:vLATEST:..."}}
  POST /v1/auth/<approle mount>/login     {"role_id", "secret_id"} -> {"auth": {"client_token"}}
  POST /v1/auth/<kubernetes mount>/login  {"role", "jwt"}          -> {"auth": {"client_token"}}
Key versions (rotate(), min_decryption_version), a sealed state (503), permission denial (403) and namespaces.
Not a security boundary: test use only.
"""

from __future__ import annotations

import base64
import os
import secrets
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route


@dataclass
class MockVault:
    mount: str = "transit"
    key_name: str = "mgw-kek"
    root_token: str = "root-token"  # noqa: S105 (test double)
    namespace: str = ""  # required X-Vault-Namespace when set
    approle: dict[str, str] = field(default_factory=lambda: {"role-mgw": "secret-mgw"})
    k8s: dict[str, str] = field(default_factory=lambda: {"mcp-gateway": "k8s-sa-jwt"})  # role -> accepted jwt
    keys: list[bytes] = field(default_factory=lambda: [AESGCM.generate_key(bit_length=256)])
    min_decryption_version: int = 1
    sealed: bool = False
    denied: bool = False  # the token's policy no longer allows transit
    tokens: set[str] = field(default_factory=set)
    requests: list[str] = field(default_factory=list)

    def reset(self) -> None:
        fresh = MockVault()
        self.__dict__.update({k: v for k, v in fresh.__dict__.items()
                              if k not in ("mount", "key_name", "root_token")})

    def rotate(self) -> int:
        self.keys.append(AESGCM.generate_key(bit_length=256))
        return len(self.keys)

    def encrypt(self, plaintext: bytes, version: int | None = None) -> str:
        v = version or len(self.keys)
        nonce = os.urandom(12)
        ct = AESGCM(self.keys[v - 1]).encrypt(nonce, plaintext, None)
        return f"vault:v{v}:" + base64.b64encode(nonce + ct).decode()

    def decrypt(self, ciphertext: str) -> bytes:
        _, version, payload = ciphertext.split(":", 2)
        v = int(version[1:])
        if v < self.min_decryption_version or v > len(self.keys):
            raise ValueError("ciphertext version is disallowed by policy (too old)")
        raw = base64.b64decode(payload)
        return AESGCM(self.keys[v - 1]).decrypt(raw[:12], raw[12:], None)


def _error(status: int, *errors: str) -> JSONResponse:
    return JSONResponse({"errors": list(errors)}, status_code=status)


def build_app(vault: MockVault) -> Starlette:
    async def handle(request: Request) -> JSONResponse:
        path = request.path_params["path"]
        vault.requests.append(path)
        if vault.sealed:
            return _error(503, "Vault is sealed")
        if vault.namespace and request.headers.get("x-vault-namespace") != vault.namespace:
            return _error(403, "permission denied")
        try:
            body: dict[str, Any] = await request.json()
        except ValueError:
            return _error(400, "failed to parse JSON input")
        parts = path.split("/")
        if parts[0] == "auth" and len(parts) == 3 and parts[2] == "login":
            ok = (vault.approle.get(str(body.get("role_id"))) == body.get("secret_id") if "role_id" in body
                  else vault.k8s.get(str(body.get("role"))) == body.get("jwt"))
            if not ok:
                return _error(400, "invalid role or secret ID")
            token = "hvs." + secrets.token_urlsafe(16)
            vault.tokens.add(token)
            return JSONResponse({"auth": {"client_token": token, "lease_duration": 3600, "renewable": True}})
        token = request.headers.get("x-vault-token", "")
        if token != vault.root_token and token not in vault.tokens:
            return _error(403, "permission denied", "invalid token")
        if vault.denied:
            return _error(403, "1 error occurred:\n\t* permission denied\n\n")
        if len(parts) != 3 or parts[0] != vault.mount or parts[2] != vault.key_name:
            return _error(404, f"no handler for route \"{path}\"")
        op = parts[1]
        try:
            if op == "encrypt":
                return JSONResponse({"data": {"ciphertext": vault.encrypt(base64.b64decode(body["plaintext"])),
                                              "key_version": len(vault.keys)}})
            if op == "decrypt":
                return JSONResponse({"data": {"plaintext": base64.b64encode(
                    vault.decrypt(str(body["ciphertext"]))).decode()}})
            if op == "rewrap":
                return JSONResponse({"data": {"ciphertext": vault.encrypt(vault.decrypt(str(body["ciphertext"]))),
                                              "key_version": len(vault.keys)}})
        except (KeyError, ValueError) as exc:
            return _error(400, str(exc) or "invalid ciphertext")
        except Exception:  # noqa: BLE001 (authentication failure of the ciphertext)
            return _error(400, "cipher: message authentication failed")
        return _error(404, f"no handler for route \"{path}\"")

    return Starlette(routes=[Route("/v1/{path:path}", handle, methods=["POST"])])
