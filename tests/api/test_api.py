from fastapi.testclient import TestClient

from ra_xsoc_api.main import app


client = TestClient(app)


def test_health_endpoint() -> None:
    response = client.get("/health")

    assert response.status_code == 200

    payload = response.json()

    assert payload["status"] == "ok"
    assert payload["service"] == "ra-xsoc-api"


def test_analyze_endpoint_rejects_empty_description() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={
            "description": "",
        },
    )

    assert response.status_code == 422


def test_analyze_endpoint_rejects_missing_description() -> None:
    response = client.post(
        "/api/v1/analyze",
        json={},
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
def test_real_analyze_endpoint_returns_phishing() -> None:
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

    assert payload["primary_match"]["attack_id"] == "phishing"
    assert payload["primary_match"]["semantic_score"] > 0.0
    assert payload["primary_match"]["hybrid_score"] > 0.0

    assert payload["confidence"] == payload["primary_match"]["hybrid_score"]

    assert payload["analysis_id"]
    assert payload["incident_id"]

    assert isinstance(payload["explanation"], list)
    assert payload["explanation"]

    assert "playbook" in payload