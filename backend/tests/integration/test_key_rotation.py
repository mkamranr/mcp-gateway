"""DATA_ENCRYPTION_KEY rotation tool (spec §27): every stored ciphertext moves to the new key."""

import json
import os

import pytest
from cryptography.exceptions import InvalidTag

from app.core.crypto import Encryptor
from app.tools.rotate_encryption_key import rotate
from devtools import mock_mcp_server

EMAIL = {"to": "cfo@example.com", "subject": "Report", "body": "Quarterly numbers"}


async def test_rotation_reencrypts_secrets_and_approval_arguments(scenario, admin, upstream_url, container):
    r = await admin.post("/api/v1/servers", json={
        "name": "Auth", "alias": "auth", "transport": "streamable_http", "endpoint": upstream_url,
        "allow_private_network": True, "authentication_mode": "bearer", "secret": {"token": "rotate-me-token"}})
    assert r.status_code == 201
    s = await scenario.setup(enable={"send_email": "high"})
    await s.allow(["send_email"], require_approval=True)
    approval_id = (await s.invoke("send_email", EMAIL)).json()["approval_id"]

    db = container.db.db
    old = container.encryptor
    new = Encryptor(os.urandom(32))

    dry = await rotate(db, old, new, dry_run=True)
    assert dry.rotated >= 2 and not dry.failed
    report = await rotate(db, old, new)
    assert report.rotated == dry.rotated and not report.failed
    again = await rotate(db, old, new)  # idempotent
    assert again.rotated == 0 and again.already_new == report.rotated

    secret = await container.repos.secrets.col.find_one({"owner_id": r.json()["id"]})
    assert json.loads(new.decrypt(secret["ciphertext"], f"{secret['tenant_id']}:{secret['_id']}"))["token"] == "rotate-me-token"
    doc = await container.repos.approvals.get(s.tenant_id, approval_id)
    assert json.loads(new.decrypt(doc["arguments_encrypted"], f"{s.tenant_id}:{approval_id}")) == EMAIL
    with pytest.raises(InvalidTag):  # the old key no longer decrypts rotated data
        old.decrypt(doc["arguments_encrypted"], f"{s.tenant_id}:{approval_id}")

    # The live service, switched to the new key, still authenticates upstream and reads approvals.
    old_aead = container.encryptor._aead
    container.encryptor._aead = new._aead  # shared by every service in the container
    mock_mcp_server.STATE["expected_token"] = "rotate-me-token"
    try:
        assert (await admin.post(f"/api/v1/servers/{r.json()['id']}/test")).json()["healthy"] is True
        assert mock_mcp_server.STATE["last_auth"] == "Bearer rotate-me-token"
        assert (await admin.get(f"/api/v1/approvals/{approval_id}")).json()["integrity"] == "verified"
    finally:
        container.encryptor._aead = old_aead
        mock_mcp_server.STATE["expected_token"] = None


async def test_rotation_includes_the_sso_client_secret(admin, mock_idp, container):
    from app.services.sso_service import SECRET_AAD

    r = await admin.put("/api/v1/sso/config", json={"enabled": True, "issuer": mock_idp.issuer,
                                                     "client_id": mock_idp.client_id, "client_secret": "sso-rotate-me"})
    assert r.status_code == 200, r.text
    old, new = container.encryptor, Encryptor(os.urandom(32))
    report = await rotate(container.db.db, old, new)
    assert report.rotated == 1 and not report.failed
    doc = await container.repos.settings.col.find_one({"key": "oidc"})
    assert new.decrypt(doc["value"]["client_secret_enc"], SECRET_AAD) == b"sso-rotate-me"
    assert (await rotate(container.db.db, old, new)).already_new == 1
