from devtools import mock_mcp_server


async def test_health(anon):
    assert (await anon.get("/health/live")).json() == {"status": "ok"}
    r = await anon.get("/health/ready")
    assert r.status_code == 200 and r.json()["status"] == "ready"
    assert r.headers["x-request-id"].startswith("req_")
    assert r.headers["x-content-type-options"] == "nosniff"


async def test_end_to_end_allow(scenario):
    s = await scenario.setup()
    await s.allow(["get_attendance_summary"])
    r = await s.invoke("get_attendance_summary", {"employee_id": "E1001"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "completed"
    assert body["structured_content"]["employee_id"] == "E1001"
    assert mock_mcp_server.CALLS["get_attendance_summary"] == 1
