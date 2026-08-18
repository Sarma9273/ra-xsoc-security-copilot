from __future__ import annotations

from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from ra_xsoc_api.main import app


def create_cors_test_client() -> TestClient:
    cors_app = CORSMiddleware(
        app=app,
        allow_origins=["http://localhost:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "X-Request-ID"],
    )

    return TestClient(cors_app)


def test_health_endpoint_still_works() -> None:
    client = create_cors_test_client()

    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_cors_preflight_rejects_unknown_origin() -> None:
    client = create_cors_test_client()

    response = client.options(
        "/health",
        headers={
            "Origin": "http://malicious.example",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert "access-control-allow-origin" not in response.headers


def test_cors_preflight_allows_frontend_origin() -> None:
    client = create_cors_test_client()

    response = client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers["access-control-allow-origin"] == (
        "http://localhost:5173"
    )