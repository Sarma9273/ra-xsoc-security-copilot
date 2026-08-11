from fastapi.testclient import TestClient

from ra_xsoc_api.main import app


client = TestClient(app)


def test_health_endpoint_still_works() -> None:
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_cors_preflight_rejects_unknown_origin() -> None:
    response = client.options(
        "/health",
        headers={
            "Origin": "http://malicious.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert "access-control-allow-origin" not in response.headers