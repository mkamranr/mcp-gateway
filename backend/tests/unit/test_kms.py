"""Secrets wrapped by a key service (docs/key-management.md): Vault Transit against a protocol-level mock, and the
command provider against real subprocesses."""

from __future__ import annotations

import base64
import io
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from typing import Any

import pytest
import uvicorn

from app.config import Settings
from app.core import kms
from app.core.crypto import Encryptor
from devtools import mock_vault
from tests.conftest import _free_port

DEK = base64.urlsafe_b64encode(b"k" * 32).decode()
PEPPER = "p" * 48


@pytest.fixture(scope="module")
def _vault_server() -> Iterator[tuple[mock_vault.MockVault, str]]:
    port = _free_port()
    vault = mock_vault.MockVault()
    server = uvicorn.Server(uvicorn.Config(mock_vault.build_app(vault), host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(100):
        if server.started:
            break
        time.sleep(0.05)
    yield vault, f"http://127.0.0.1:{port}"
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def vault(_vault_server: tuple[mock_vault.MockVault, str], monkeypatch: pytest.MonkeyPatch) -> mock_vault.MockVault:
    v, addr = _vault_server
    v.reset()
    for name in ("VAULT_TOKEN", "VAULT_APPROLE_ROLE_ID", "VAULT_APPROLE_SECRET_ID", "VAULT_K8S_ROLE", "VAULT_NAMESPACE",
                 "KMS_UNWRAP_COMMAND", "KMS_WRAP_COMMAND"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("KMS_PROVIDER", "vault")
    monkeypatch.setenv("KMS_ALLOW_INSECURE_HTTP", "true")
    monkeypatch.setenv("VAULT_ADDR", addr)
    monkeypatch.setenv("VAULT_TRANSIT_KEY", v.key_name)
    monkeypatch.setenv("VAULT_TOKEN", v.root_token)
    monkeypatch.setattr(kms, "BACKOFF", (0.0, 0.0, 0.0))
    return v


def wrapped(value: str) -> str:
    return kms.wrap(kms.provider_for(kms.KmsConfig.from_env()), value)


# ---------------------------------------------------------------- Vault Transit
def test_settings_unwrap_wrapped_secrets_at_startup(vault):
    w_dek, w_pepper = wrapped(DEK), wrapped(PEPPER)
    assert w_dek.startswith("mgw-kms:v1:vault:vault:v1:") and DEK not in w_dek
    s = Settings(app_env="test", data_encryption_key=w_dek, api_key_hash_pepper=w_pepper, session_secret="s" * 40)
    assert s.data_encryption_key == DEK and s.api_key_hash_pepper == PEPPER
    assert sorted(s.kms_wrapped) == ["api_key_hash_pepper", "data_encryption_key"]
    # Data written with the plain key reads back through the unwrapped one.
    token = Encryptor(base64.urlsafe_b64decode(DEK)).encrypt(b"upstream secret", "t:1")
    assert Encryptor(s.encryption_key_bytes()).decrypt(token, "t:1") == b"upstream secret"
    assert DEK not in repr(s) and PEPPER not in repr(s)


def test_plain_secrets_need_no_key_service(monkeypatch):
    monkeypatch.delenv("KMS_PROVIDER", raising=False)
    s = Settings(app_env="test", data_encryption_key=DEK)
    assert s.kms_wrapped == []


def test_wrapped_secret_without_a_key_service_is_refused(vault, monkeypatch):
    w = wrapped(DEK)
    monkeypatch.delenv("KMS_PROVIDER")
    with pytest.raises(kms.KmsError, match="KMS_PROVIDER"):
        Settings(app_env="test", data_encryption_key=w)


@pytest.mark.parametrize("auth", ["approle", "kubernetes"])
def test_approle_and_kubernetes_login(vault, monkeypatch, tmp_path, auth):
    w = wrapped(DEK)
    monkeypatch.delenv("VAULT_TOKEN")
    if auth == "approle":
        monkeypatch.setenv("VAULT_APPROLE_ROLE_ID", "role-mgw")
        monkeypatch.setenv("VAULT_APPROLE_SECRET_ID", "secret-mgw")
    else:
        jwt = tmp_path / "token"
        jwt.write_text("k8s-sa-jwt")
        monkeypatch.setenv("VAULT_K8S_ROLE", "mcp-gateway")
        monkeypatch.setenv("VAULT_K8S_TOKEN_PATH", str(jwt))
    s = Settings(app_env="test", data_encryption_key=w)
    assert s.data_encryption_key == DEK
    assert any(p.startswith("auth/") for p in vault.requests)
    # Wrong credentials: a clear error, nothing secret in it.
    monkeypatch.setenv("VAULT_APPROLE_SECRET_ID", "wrong") if auth == "approle" else jwt.write_text("other")
    with pytest.raises(kms.KmsError, match="HTTP 400") as exc:
        Settings(app_env="test", data_encryption_key=w)
    assert "secret-mgw" not in str(exc.value) and "wrong" not in str(exc.value)


def test_namespace_header(vault, monkeypatch):
    vault.namespace = "corp/gateway"
    with pytest.raises(kms.KmsError, match="HTTP 403"):
        wrapped(DEK)
    monkeypatch.setenv("VAULT_NAMESPACE", "corp/gateway")
    assert Settings(app_env="test", data_encryption_key=wrapped(DEK)).data_encryption_key == DEK


def test_revoked_access_stops_startup_without_leaking(vault):
    w = wrapped(DEK)
    vault.denied = True
    with pytest.raises(kms.KmsError) as exc:
        Settings(app_env="test", data_encryption_key=w)
    msg = str(exc.value)
    assert msg.startswith("DATA_ENCRYPTION_KEY:") and "HTTP 403" in msg and DEK not in msg and w not in msg


def test_sealed_vault_is_retried_then_reported(vault):
    w = wrapped(DEK)
    vault.sealed = True
    vault.requests.clear()
    with pytest.raises(kms.KmsError, match="HTTP 503"):
        Settings(app_env="test", data_encryption_key=w)
    assert len(vault.requests) == kms.ATTEMPTS


def test_unreachable_vault(vault, monkeypatch):
    w = wrapped(DEK)
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{_free_port()}")
    with pytest.raises(kms.KmsError, match="unreachable"):
        Settings(app_env="test", data_encryption_key=w)


def test_key_rotation_rewrap_and_crypto_shredding(vault):
    old = wrapped(DEK)
    vault.rotate()
    provider = kms.provider_for(kms.KmsConfig.from_env())
    new = kms.rewrap(provider, old)
    assert ":vault:v2:" in new and kms.unwrap(provider, new) == DEK
    # Retiring the old key version makes values wrapped under it unreadable.
    vault.min_decryption_version = 2
    with pytest.raises(kms.KmsError, match="HTTP 400"):
        kms.unwrap(provider, old)
    assert kms.unwrap(provider, new) == DEK


def test_tampered_or_mismatched_values(vault):
    provider = kms.provider_for(kms.KmsConfig.from_env())
    w = wrapped(DEK)
    head, _, payload = w.rpartition(":")
    raw = bytearray(base64.b64decode(payload))
    raw[-1] ^= 1
    with pytest.raises(kms.KmsError):
        kms.unwrap(provider, f"{head}:{base64.b64encode(bytes(raw)).decode()}")
    with pytest.raises(kms.KmsError, match="wrapped with 'command'"):
        kms.unwrap(provider, "mgw-kms:v1:command:abc")


def test_production_requires_https(vault, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")  # KMS_ALLOW_INSECURE_HTTP is ignored in production
    with pytest.raises(kms.KmsError, match="https"):
        kms.provider_for(kms.KmsConfig.from_env())


# ---------------------------------------------------------------- command provider
REVERSE = """import base64, sys
data = sys.stdin.read().strip()
if sys.argv[1] == "fail":
    sys.stderr.write("the input was " + data); sys.exit(3)
if sys.argv[1] == "slow":
    import time; time.sleep(5)
print(base64.b64encode(data[::-1].encode()).decode() if sys.argv[1] == "wrap" else base64.b64decode(data).decode()[::-1])
"""


@pytest.fixture
def command(monkeypatch, tmp_path) -> Path:
    script = tmp_path / "fake_kms.py"
    script.write_text(REVERSE)
    monkeypatch.setenv("APP_ENV", "test")
    monkeypatch.setenv("KMS_PROVIDER", "command")
    monkeypatch.setenv("KMS_WRAP_COMMAND", f'["{sys.executable.replace(chr(92), "/")}", "{script.as_posix()}", "wrap"]')
    monkeypatch.setenv("KMS_UNWRAP_COMMAND", f'["{sys.executable.replace(chr(92), "/")}", "{script.as_posix()}", "unwrap"]')
    return script


def test_command_provider_roundtrip(command):
    w = wrapped(DEK)
    assert w.startswith("mgw-kms:v1:command:") and DEK not in w
    s = Settings(app_env="test", data_encryption_key=w)
    assert s.data_encryption_key == DEK and s.kms_wrapped == ["data_encryption_key"]


def test_command_failure_does_not_echo_its_output(command, monkeypatch):
    w = wrapped(DEK)
    monkeypatch.setenv("KMS_UNWRAP_COMMAND", f'["{sys.executable.replace(chr(92), "/")}", "{command.as_posix()}", "fail"]')
    with pytest.raises(kms.KmsError, match="exit code 3") as exc:
        Settings(app_env="test", data_encryption_key=w)
    assert w.split(":")[-1] not in str(exc.value)


def test_command_timeout_and_missing_program(command, monkeypatch):
    w = wrapped(DEK)
    monkeypatch.setenv("KMS_UNWRAP_COMMAND", f'["{sys.executable.replace(chr(92), "/")}", "{command.as_posix()}", "slow"]')
    monkeypatch.setenv("KMS_COMMAND_TIMEOUT_SECONDS", "0.5")
    with pytest.raises(kms.KmsError, match="timed out"):
        Settings(app_env="test", data_encryption_key=w)
    monkeypatch.setenv("KMS_UNWRAP_COMMAND", "/nonexistent/kms-tool unwrap")
    with pytest.raises(kms.KmsError, match="not found"):
        Settings(app_env="test", data_encryption_key=w)


# ---------------------------------------------------------------- operator tools
def run_tool(args: list[str], stdin: str = "", monkeypatch: Any = None) -> tuple[int, str, str]:
    from app.tools import kms as tool

    out, err = io.StringIO(), io.StringIO()
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    with redirect_stdout(out), redirect_stderr(err):
        code = tool.main(args)
    return code, out.getvalue(), err.getvalue()


def test_tool_generate_check_rewrap_unwrap(vault, monkeypatch, tmp_path):
    code, out, _ = run_tool(["generate", "data_encryption_key"], monkeypatch=monkeypatch)
    assert code == 0 and out.startswith("mgw-kms:v1:vault:")
    dek_file = tmp_path / "data_encryption_key"
    dek_file.write_text(out)
    plain_file = tmp_path / "api_key_hash_pepper"
    plain_file.write_text(PEPPER)
    code, out, _ = run_tool(["check", str(dek_file), str(plain_file)], monkeypatch=monkeypatch)
    assert code == 0 and "unwrapped" in out and "plain" in out and "NOT A 32-BYTE KEY" not in out
    assert "'auth': 'token'" in out and vault.root_token not in out

    vault.rotate()
    code, rewrapped, _ = run_tool(["rewrap"], dek_file.read_text(), monkeypatch)
    assert code == 0 and ":vault:v2:" in rewrapped
    target = tmp_path / "plain.key"
    code, out, err = run_tool(["unwrap", "--out", str(target)], rewrapped, monkeypatch)
    assert code == 0 and out == "" and "fingerprint" in err
    assert len(base64.urlsafe_b64decode(target.read_text())) == 32
    before = target.read_text()
    code, _, err = run_tool(["unwrap", "--out", str(target)], rewrapped, monkeypatch)  # never overwrites
    assert code == 1 and "refusing to overwrite" in err and target.read_text() == before


def test_tool_reports_failures(vault, monkeypatch, tmp_path):
    f = tmp_path / "data_encryption_key"
    f.write_text(wrapped(DEK))
    vault.denied = True
    code, out, _ = run_tool(["check", str(f)], monkeypatch=monkeypatch)
    assert code == 1 and "FAILED" in out and DEK not in out


def test_rotation_tool_accepts_wrapped_key_files(vault, tmp_path):
    from app.tools.rotate_encryption_key import load_key

    f = tmp_path / "new.key"
    f.write_text(wrapped(DEK))
    assert load_key(str(f)) == b"k" * 32


async def test_console_reports_key_management(admin):
    sec = (await admin.get("/api/v1/settings")).json()["system"]["security"]
    assert sec["key_management"] == {"wrapped": [], "provider": None}
