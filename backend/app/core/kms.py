"""Keys protected by an external key management service (docs/key-management.md).

Envelope encryption: the secret files hold *wrapped* values, encrypted under a key-encryption key that never
leaves the key service (HashiCorp Vault Transit, or any KMS/HSM through an operator-supplied command). At startup
each wrapped value is unwrapped once; the plain value lives only in process memory. Copies of the secret files,
the env file or a backup are useless without access to the key service, and destroying or revoking the
key-encryption key there makes the data unreadable (crypto-shredding).

Wrapped values look like ``mgw-kms:v1:<provider>:<opaque>``. Plain values are still accepted, so wrapping can be
adopted one secret at a time.

Everything here is synchronous: it runs once, while settings are loaded, before the event loop starts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shlex
import subprocess  # noqa: S404 (runs an operator-configured command, never user input)
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

PREFIX = "mgw-kms:v1:"
PROVIDERS = ("vault", "command")
WRAPPABLE = ("data_encryption_key", "api_key_hash_pepper", "session_secret")
TIMEOUT = 15.0
ATTEMPTS = 3
BACKOFF = (1.0, 3.0, 0.0)  # seconds after each failed attempt (Vault sealed, restarting or failing over)


class KmsError(Exception):
    """Unwrapping or wrapping failed. Messages never contain key material."""


def is_wrapped(value: str | None) -> bool:
    return bool(value) and str(value).startswith(PREFIX)


def fingerprint(value: str) -> str:
    """A short, non-reversible identifier for comparing values (e.g. before and after rewrapping)."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]


def _env(name: str, default: str = "") -> str:
    value = os.environ.get(name, "").strip()
    if not value and os.environ.get(f"{name}_FILE"):
        path = Path(os.environ[f"{name}_FILE"])
        value = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
    return value or default


@dataclass
class KmsConfig:
    provider: str = ""  # "" = no key service; wrapped values are then refused
    # HashiCorp Vault Transit
    vault_addr: str = ""
    vault_namespace: str = ""
    vault_transit_mount: str = "transit"
    vault_transit_key: str = ""
    vault_ca_bundle_file: str = ""
    vault_token: str = field(default="", repr=False)
    vault_approle_role_id: str = ""
    vault_approle_secret_id: str = field(default="", repr=False)
    vault_approle_mount: str = "approle"
    vault_k8s_role: str = ""
    vault_k8s_mount: str = "kubernetes"
    vault_k8s_token_file: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"  # noqa: S105 (a path)
    # Command: argv (JSON list or shell-style words, never run through a shell). Wrapped value on stdin for
    # unwrap, plain value on stdin for wrap; the result on stdout.
    unwrap_command: list[str] = field(default_factory=list)
    wrap_command: list[str] = field(default_factory=list)
    command_timeout: float = 30.0
    allow_insecure: bool = False

    @staticmethod
    def _argv(raw: str) -> list[str]:
        if not raw:
            return []
        if raw.lstrip().startswith("["):
            argv = json.loads(raw)
            if not isinstance(argv, list) or not all(isinstance(a, str) for a in argv):
                raise KmsError("KMS command must be a JSON list of strings")
            return argv
        return shlex.split(raw)

    @classmethod
    def from_env(cls) -> KmsConfig:
        insecure = _env("KMS_ALLOW_INSECURE_HTTP").lower() == "true" and _env("APP_ENV", "production") != "production"
        return cls(
            provider=_env("KMS_PROVIDER").lower(),
            vault_addr=_env("VAULT_ADDR").rstrip("/"),
            vault_namespace=_env("VAULT_NAMESPACE"),
            vault_transit_mount=_env("VAULT_TRANSIT_MOUNT", "transit").strip("/"),
            vault_transit_key=_env("VAULT_TRANSIT_KEY"),
            vault_ca_bundle_file=_env("VAULT_CA_BUNDLE_FILE"),
            vault_token=_env("VAULT_TOKEN"),
            vault_approle_role_id=_env("VAULT_APPROLE_ROLE_ID"),
            vault_approle_secret_id=_env("VAULT_APPROLE_SECRET_ID"),
            vault_approle_mount=_env("VAULT_APPROLE_MOUNT", "approle").strip("/"),
            vault_k8s_role=_env("VAULT_K8S_ROLE"),
            vault_k8s_mount=_env("VAULT_K8S_MOUNT", "kubernetes").strip("/"),
            vault_k8s_token_file=_env("VAULT_K8S_TOKEN_PATH", "/var/run/secrets/kubernetes.io/serviceaccount/token"),
            unwrap_command=cls._argv(_env("KMS_UNWRAP_COMMAND")),
            wrap_command=cls._argv(_env("KMS_WRAP_COMMAND")),
            command_timeout=float(_env("KMS_COMMAND_TIMEOUT_SECONDS", "30")),
            allow_insecure=insecure,
        )

    def describe(self) -> dict[str, Any]:
        """Non-secret summary for the console and logs."""
        if self.provider == "vault":
            auth = ("kubernetes" if self.vault_k8s_role else "approle" if self.vault_approle_role_id
                    else "token" if self.vault_token else "none")
            return {"provider": "vault", "address": self.vault_addr, "key": self.vault_transit_key,
                    "mount": self.vault_transit_mount, "namespace": self.vault_namespace or None, "auth": auth}
        if self.provider == "command":
            return {"provider": "command", "command": Path(self.unwrap_command[0]).name if self.unwrap_command else None}
        return {"provider": None}


class Provider:
    name = ""

    def unwrap(self, opaque: str) -> str:
        raise NotImplementedError

    def wrap(self, plaintext: str) -> str:
        raise NotImplementedError

    def rewrap(self, opaque: str) -> str:
        return self.wrap(self.unwrap(opaque))


class VaultTransit(Provider):
    """Vault's transit secrets engine: the key-encryption key stays in Vault (which may itself be HSM-backed)."""

    name = "vault"

    def __init__(self, cfg: KmsConfig, client: httpx.Client | None = None) -> None:
        if not cfg.vault_addr or not cfg.vault_transit_key:
            raise KmsError("VAULT_ADDR and VAULT_TRANSIT_KEY are required with KMS_PROVIDER=vault")
        if not cfg.vault_addr.startswith("https://") and not (cfg.allow_insecure and cfg.vault_addr.startswith("http://")):
            raise KmsError("VAULT_ADDR must be https:// (http:// only with KMS_ALLOW_INSECURE_HTTP outside production)")
        if not (cfg.vault_token or cfg.vault_approle_role_id or cfg.vault_k8s_role):
            raise KmsError("Vault authentication is required: VAULT_TOKEN(_FILE), VAULT_APPROLE_ROLE_ID with "
                           "VAULT_APPROLE_SECRET_ID(_FILE), or VAULT_K8S_ROLE")
        self.cfg = cfg
        verify: Any = cfg.vault_ca_bundle_file or True
        self.http = client or httpx.Client(timeout=TIMEOUT, verify=verify, follow_redirects=False, trust_env=False)
        self._token = cfg.vault_token

    def _headers(self, token: str | None = None) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if token:
            h["X-Vault-Token"] = token
        if self.cfg.vault_namespace:
            h["X-Vault-Namespace"] = self.cfg.vault_namespace
        return h

    def _post(self, path: str, body: dict[str, Any], token: str | None) -> dict[str, Any]:
        last = "unreachable"
        for attempt in range(ATTEMPTS):
            try:
                r = self.http.post(f"{self.cfg.vault_addr}/v1/{path}", json=body, headers=self._headers(token))
            except httpx.HTTPError as exc:
                last = f"unreachable ({type(exc).__name__})"
                time.sleep(BACKOFF[attempt])
                continue
            if r.status_code == 200:
                return dict(r.json())
            if r.status_code in (429, 500, 502, 503, 504):  # sealed, standby, overloaded: retry
                last = f"HTTP {r.status_code}"
                time.sleep(BACKOFF[attempt])
                continue
            # 400/403/404: configuration or permission problem; Vault's error text names no secret.
            try:
                errors = "; ".join(str(e) for e in r.json().get("errors", []))[:200]
            except ValueError:
                errors = ""
            raise KmsError(f"Vault refused {path.split('/')[-2] if '/' in path else path}: HTTP {r.status_code}"
                           + (f" ({errors})" if errors else ""))
        raise KmsError(f"Vault at {self.cfg.vault_addr} is {last}")

    def _login(self) -> str:
        if self._token:
            return self._token
        if self.cfg.vault_k8s_role:
            try:
                jwt = Path(self.cfg.vault_k8s_token_file).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise KmsError(f"cannot read the Kubernetes service account token at {self.cfg.vault_k8s_token_file}") from exc
            data = self._post(f"auth/{self.cfg.vault_k8s_mount}/login", {"role": self.cfg.vault_k8s_role, "jwt": jwt}, None)
        else:
            data = self._post(f"auth/{self.cfg.vault_approle_mount}/login",
                              {"role_id": self.cfg.vault_approle_role_id, "secret_id": self.cfg.vault_approle_secret_id},
                              None)
        token = (data.get("auth") or {}).get("client_token")
        if not token:
            raise KmsError("Vault login returned no token")
        self._token = str(token)
        return self._token

    def _transit(self, op: str, body: dict[str, Any]) -> dict[str, Any]:
        path = f"{self.cfg.vault_transit_mount}/{op}/{self.cfg.vault_transit_key}"
        return dict(self._post(path, body, self._login()).get("data") or {})

    def unwrap(self, opaque: str) -> str:
        if not opaque.startswith("vault:"):
            raise KmsError("not a Vault transit ciphertext")
        plain = self._transit("decrypt", {"ciphertext": opaque}).get("plaintext")
        if not isinstance(plain, str):
            raise KmsError("Vault returned no plaintext")
        return base64.b64decode(plain).decode()

    def wrap(self, plaintext: str) -> str:
        ct = self._transit("encrypt", {"plaintext": base64.b64encode(plaintext.encode()).decode()}).get("ciphertext")
        if not isinstance(ct, str):
            raise KmsError("Vault returned no ciphertext")
        return ct

    def rewrap(self, opaque: str) -> str:
        ct = self._transit("rewrap", {"ciphertext": opaque}).get("ciphertext")
        if not isinstance(ct, str):
            raise KmsError("Vault returned no ciphertext")
        return ct


class CommandProvider(Provider):
    """Runs an operator-supplied program (AWS/GCP/Azure CLIs, an HSM vendor tool, a script). No shell."""

    name = "command"

    def __init__(self, cfg: KmsConfig) -> None:
        if not cfg.unwrap_command:
            raise KmsError("KMS_UNWRAP_COMMAND is required with KMS_PROVIDER=command")
        self.cfg = cfg

    def _run(self, argv: list[str], data: str, what: str) -> str:
        try:
            proc = subprocess.run(argv, input=data.encode(), capture_output=True, timeout=self.cfg.command_timeout,  # noqa: S603
                                  check=False)
        except FileNotFoundError as exc:
            raise KmsError(f"KMS {what} command not found: {argv[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            raise KmsError(f"KMS {what} command timed out after {self.cfg.command_timeout:g}s") from exc
        if proc.returncode != 0:
            # stderr may help, but could echo input: report only its length.
            raise KmsError(f"KMS {what} command failed with exit code {proc.returncode} "
                           f"({len(proc.stderr)} bytes on stderr)")
        out = proc.stdout.decode().strip()
        if not out:
            raise KmsError(f"KMS {what} command printed nothing")
        return out

    def unwrap(self, opaque: str) -> str:
        return self._run(self.cfg.unwrap_command, opaque, "unwrap")

    def wrap(self, plaintext: str) -> str:
        if not self.cfg.wrap_command:
            raise KmsError("KMS_WRAP_COMMAND is required to wrap values")
        return self._run(self.cfg.wrap_command, plaintext, "wrap")


def provider_for(cfg: KmsConfig) -> Provider:
    if cfg.provider == "vault":
        return VaultTransit(cfg)
    if cfg.provider == "command":
        return CommandProvider(cfg)
    if not cfg.provider:
        raise KmsError("a wrapped secret needs KMS_PROVIDER (vault or command)")
    raise KmsError(f"unknown KMS_PROVIDER {cfg.provider!r}; use vault or command")


def wrap(provider: Provider, plaintext: str) -> str:
    return f"{PREFIX}{provider.name}:{provider.wrap(plaintext)}"


def unwrap(provider: Provider, value: str) -> str:
    name, _, opaque = value[len(PREFIX):].partition(":")
    if name != provider.name:
        raise KmsError(f"value was wrapped with {name!r}, but KMS_PROVIDER is {provider.name!r}")
    if not opaque:
        raise KmsError("wrapped value is empty")
    return provider.unwrap(opaque)


def rewrap(provider: Provider, value: str) -> str:
    name, _, opaque = value[len(PREFIX):].partition(":")
    if name != provider.name:
        raise KmsError(f"value was wrapped with {name!r}, but KMS_PROVIDER is {provider.name!r}")
    return f"{PREFIX}{provider.name}:{provider.rewrap(opaque)}"


def unwrap_values(values: dict[str, str], cfg: KmsConfig | None = None,
                  provider: Provider | None = None) -> tuple[dict[str, str], list[str]]:
    """Unwrap every wrapped value. Returns (values with plain text, names that were wrapped)."""
    wrapped = [k for k, v in values.items() if is_wrapped(v)]
    if not wrapped:
        return values, []
    provider = provider or provider_for(cfg or KmsConfig.from_env())
    out = dict(values)
    for name in wrapped:
        try:
            out[name] = unwrap(provider, values[name])
        except KmsError as exc:
            raise KmsError(f"{name.upper()}: {exc}") from None
    return out, wrapped
