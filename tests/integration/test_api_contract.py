from __future__ import annotations

from fastapi.testclient import TestClient

from ra_xsoc_api.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "ra-xsoc-api",
    }


def test_analyze_endpoint_accepts_phishing_incident() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "description": (
                "An employee received a suspicious phishing email "
                "containing a malicious login link requesting credentials."
            )
        },
    )

    assert response.status_code == 200

    payload = response.json()

    assert payload["incident_id"]
    assert payload["analysis_id"]

    assert payload["primary_match"]["attack_id"] == "phishing"
    assert payload["primary_match"]["semantic_score"] > 0.0
    assert payload["primary_match"]["hybrid_score"] > 0.0

    assert 0.0 <= payload["confidence"] <= 1.0

    assert payload["severity"]
    assert payload["novelty_status"]
    assert payload["review_status"]

    assert isinstance(payload["alternatives"], list)
    assert isinstance(payload["explanation"], list)

    assert "containment" in payload["playbook"]
    assert "investigation" in payload["playbook"]
    assert "recovery" in payload["playbook"]
    assert "prevention" in payload["playbook"]
    assert "detection_rules" in payload["playbook"]


def test_analyze_endpoint_rejects_empty_description() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "description": "",
        },
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_oversized_description() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "description": "A" * 20_001,
        },
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_invalid_incident_id() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "description": "Suspicious login activity detected.",
            "incident_id": "not-a-uuid",
        },
    )

    assert response.status_code == 422

def test_health_response_contains_request_id() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    request_id = response.headers.get("X-Request-ID")

    assert request_id
    assert len(request_id) > 0


def test_request_id_is_preserved() -> None:
    request_id = "lap-14-3-test"

    response = client.get(
        "/health",
        headers={
            "X-Request-ID": request_id,
        },
    )

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == request_id

def test_readiness_endpoint() -> None:
    response = client.get("/ready")

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "ready"
    assert payload["service"] == "ra-xsoc-api"

def test_validation_error_has_structured_contract() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "description": "",
        },
    )

    assert response.status_code == 422

    payload = response.json()

    assert "error" in payload
    assert payload["error"]["code"] == "VALIDATION_ERROR"
    assert payload["error"]["message"] == "Request validation failed."
    assert isinstance(payload["error"]["details"], list)
    assert payload["request_id"]


def test_validation_error_preserves_request_id() -> None:
    request_id = "lap-14-6-6-test"

    response = client.post(
        "/api/v1/analyze",
        headers={
            "X-Request-ID": request_id,
        },
        json={
            "description": "",
        },
    )

    assert response.status_code == 422

    payload = response.json()

    assert payload["request_id"] == request_id
    assert response.headers["X-Request-ID"] == request_id


def test_missing_required_field_has_structured_error() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={},
    )

    assert response.status_code == 422

    payload = response.json()

    assert payload["error"]["code"] == "VALIDATION_ERROR"
    assert payload["error"]["details"]
    assert payload["request_id"]

def test_case_is_persisted_and_retrievable() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={"description": "A suspicious phishing email requested credentials."},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    listed = client.get("/api/v1/cases")
    assert listed.status_code == 200
    assert any(item["analysis_id"] == analysis_id for item in listed.json())

    detail = client.get(f"/api/v1/cases/{analysis_id}")
    assert detail.status_code == 200
    assert detail.json()["analysis_id"] == analysis_id


def test_case_feedback_lifecycle() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={"description": "A suspicious phishing email requested credentials."},
    )
    assert response.status_code == 200
    analysis_id = response.json()["analysis_id"]

    feedback = client.post(
        f"/api/v1/cases/{analysis_id}/feedback",
        json={"status": "approved", "comments": "Reviewed against the available evidence."},
    )
    assert feedback.status_code == 200
    assert feedback.json()["analysis_id"] == analysis_id
    assert feedback.json()["status"] == "approved"

    detail = client.get(f"/api/v1/cases/{analysis_id}")
    assert detail.status_code == 200
    assert detail.json()["review_status"] == "approved"


def test_analysis_requires_authentication_outside_development(monkeypatch) -> None:
    monkeypatch.setenv("RA_XSOC_ENVIRONMENT", "production")
    monkeypatch.setenv("RA_XSOC_AUTH_REQUIRED", "true")

    response = client.post(
        "/api/v1/analyze",
        json={"description": "A suspicious phishing email requested credentials."},
    )

    assert response.status_code == 401


def test_analysis_accepts_configured_bearer_token_in_production(monkeypatch) -> None:
    from uuid import UUID

    token = "test-token"
    user_id = UUID(int=1)
    monkeypatch.setenv("RA_XSOC_ENVIRONMENT", "production")
    monkeypatch.setenv("RA_XSOC_AUTH_REQUIRED", "true")
    monkeypatch.setenv(
        "RA_XSOC_AUTH_TOKENS",
        f"{token}:{user_id}:test-analyst:analyst",
    )

    response = client.post(
        "/api/v1/analyze",
        headers={"Authorization": f"Bearer {token}"},
        json={"description": "A suspicious phishing email requested credentials."},
    )

    assert response.status_code == 200
