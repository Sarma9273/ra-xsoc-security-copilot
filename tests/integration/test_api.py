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


def test_analyze_endpoint_returns_phishing_result() -> None:
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
    assert payload["playbook"] is not None
    assert payload["explanation"]


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