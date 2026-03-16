from fastapi.testclient import TestClient

from fortipot.api.server import create_app


def test_api_index_lists_endpoints() -> None:
    client = TestClient(create_app("config.example.yaml"))
    response = client.get("/")
    assert response.status_code == 200
    assert "fortipot API" in response.text
    assert "/health" in response.text
    assert "/events" in response.text
    assert "/actions" in response.text
    assert "/config/redacted" in response.text
