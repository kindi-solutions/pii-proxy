"""End-to-end tests for the proxy server."""

import pytest
from fastapi.testclient import TestClient

from piiproxy.server import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestHealthEndpoint:
    def test_health(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}
