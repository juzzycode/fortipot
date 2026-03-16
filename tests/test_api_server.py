from fastapi.testclient import TestClient

from fortipot.api.server import create_app
from fortipot.api.routes_events import _render_events_json


def test_api_index_lists_endpoints() -> None:
    client = TestClient(create_app("config.example.yaml"))
    response = client.get("/")
    assert response.status_code == 200
    assert "fortipot API" in response.text
    assert "/health" in response.text
    assert "/events" in response.text
    assert "/actions" in response.text
    assert "/config/redacted" in response.text


def test_render_events_json_includes_blank_line_between_entries() -> None:
    body = _render_events_json(
        [
            {"id": 1, "src_ip": "10.0.0.25"},
            {"id": 2, "src_ip": "10.0.0.26"},
        ]
    )

    assert body.startswith("[\n{")
    assert "},\n\n{" in body
    assert body.endswith("\n]")
