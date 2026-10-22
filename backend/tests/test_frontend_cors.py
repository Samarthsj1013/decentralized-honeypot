from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_vite_origins_are_allowed_for_json_api_requests():
    for origin in (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ):
        response = client.options(
            "/api/v1/evaluations",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type",
            },
        )

        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == origin


def test_unconfigured_origin_does_not_receive_cors_permission():
    response = client.options(
        "/api/v1/evaluations",
        headers={
            "Origin": "https://untrusted.example",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type",
        },
    )

    assert "access-control-allow-origin" not in response.headers
