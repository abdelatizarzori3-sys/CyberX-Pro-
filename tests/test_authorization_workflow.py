from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from backend.app import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(main, "DB_PATH", tmp_path / "test-cyberx.db")
    main.init_db()
    with TestClient(main.app) as test_client:
        yield test_client


def register(client: TestClient, email: str = "owner@example.com") -> tuple[dict, dict]:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "a-long-test-password-123",
            "organization_name": "CyberX Test Org",
        },
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    return payload, {"Authorization": f"Bearer {payload['access_token']}"}


def add_asset(client: TestClient, headers: dict, identifier: str = "demo.example") -> dict:
    response = client.post(
        "/api/v1/assets",
        headers=headers,
        json={"name": "Demo Asset", "asset_type": "domain", "identifier": identifier},
    )
    assert response.status_code == 201, response.text
    return response.json()


def add_authorization(client: TestClient, headers: dict, asset_id: str, **overrides) -> dict:
    now = datetime.now(timezone.utc)
    payload = {
        "asset_id": asset_id,
        "scope_note": "Explicit permission for this test asset only.",
        "starts_at": (now - timedelta(minutes=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "attested": True,
    }
    payload.update(overrides)
    response = client.post("/api/v1/authorizations", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_health_readiness_and_security_headers(client: TestClient):
    response = client.get("/api/v1/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready", "database": "ok"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]


def test_private_endpoints_require_a_valid_session(client: TestClient):
    response = client.get("/api/v1/assets")
    assert response.status_code == 401


def test_scan_request_is_recorded_only_and_revocation_blocks_new_requests(client: TestClient):
    _, headers = register(client)
    asset = add_asset(client, headers)
    authorization = add_authorization(client, headers, asset["id"])

    recorded = client.post("/api/v1/scans", headers=headers, json={"asset_id": asset["id"]})
    assert recorded.status_code == 201
    assert recorded.json()["status"] == "RECORDED"
    assert "لم يتم تنفيذ فحص" in recorded.json()["message"]

    revoked = client.post(
        f"/api/v1/authorizations/{authorization['id']}/revoke", headers=headers
    )
    assert revoked.status_code == 200
    blocked = client.post("/api/v1/scans", headers=headers, json={"asset_id": asset["id"]})
    assert blocked.status_code == 403
    assert client.get("/api/v1/scans", headers=headers).json()[0]["status"] == "RECORDED"
    actions = [row["action"] for row in client.get("/api/v1/audit-logs", headers=headers).json()]
    assert "authorization.revoked" in actions
    assert "scan.blocked" in actions


def test_expired_authorization_cannot_create_a_record(client: TestClient):
    _, headers = register(client)
    asset = add_asset(client, headers)
    authorization = add_authorization(client, headers, asset["id"])
    now = datetime.now(timezone.utc)
    with main.db() as conn:
        conn.execute(
            "UPDATE authorizations SET expires_at=? WHERE id=?",
            ((now - timedelta(days=1)).isoformat(), authorization["id"]),
        )
    response = client.post("/api/v1/scans", headers=headers, json={"asset_id": asset["id"]})
    assert response.status_code == 403
    assert "scan.blocked" in [
        row["action"] for row in client.get("/api/v1/audit-logs", headers=headers).json()
    ]


def test_organizations_cannot_read_or_authorize_each_others_assets(client: TestClient):
    _, first_headers = register(client, "first@example.com")
    foreign_asset = add_asset(client, first_headers, "first.example")
    _, second_headers = register(client, "second@example.com")

    assert client.get("/api/v1/assets", headers=second_headers).json() == []
    authorization = client.post(
        "/api/v1/authorizations",
        headers=second_headers,
        json={
            "asset_id": foreign_asset["id"],
            "scope_note": "Permission should not cross organizations.",
            "starts_at": datetime.now(timezone.utc).isoformat(),
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "attested": True,
        },
    )
    assert authorization.status_code == 404
    scan = client.post(
        "/api/v1/scans", headers=second_headers, json={"asset_id": foreign_asset["id"]}
    )
    assert scan.status_code == 404


def test_logout_invalidates_the_bearer_session(client: TestClient):
    _, headers = register(client)
    assert client.get("/api/v1/me", headers=headers).status_code == 200
    assert client.post("/api/v1/auth/logout", headers=headers).status_code == 200
    assert client.get("/api/v1/me", headers=headers).status_code == 401


def test_blank_values_and_invalid_email_are_rejected(client: TestClient):
    bad_email = client.post(
        "/api/v1/auth/register",
        json={
            "email": "not-an-email",
            "password": "a-long-test-password-123",
            "organization_name": "Test Organization",
        },
    )
    assert bad_email.status_code == 422

    _, headers = register(client)
    blank_asset = client.post(
        "/api/v1/assets",
        headers=headers,
        json={"name": "  ", "asset_type": "domain", "identifier": "demo.example"},
    )
    assert blank_asset.status_code == 422
