"""Tests for data redaction and API routes."""

import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.security.redaction import DataRedactor


client = TestClient(app)


def test_redaction_sensitive_headers():
    headers = {
        "authorization": "Bearer secret_token_12345",
        "x-api-key": "my-secret-key",
        "cookie": "sessionid=secret_cookie_val; Path=/; HttpOnly; Secure",
        "content-type": "application/json"
    }
    redacted = DataRedactor.redact_headers(headers)
    assert redacted["authorization"] == "[REDACTED]"
    assert redacted["x-api-key"] == "[REDACTED]"
    assert "secret_cookie_val" not in redacted["cookie"]
    assert "sessionid=[REDACTED]" in redacted["cookie"]
    assert redacted["content-type"] == "application/json"


def test_health_check_route():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_root_route():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "HeaderSentinel"


def test_scans_list_empty():
    response = client.get("/api/v1/scans")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data


def test_analyze_unauthorized():
    response = client.post("/api/v1/analyze", json={
        "target": "example.com",
        "authorization_confirmed": False
    })
    assert response.status_code == 400
