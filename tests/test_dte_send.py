import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.config import get_settings


client = TestClient(app)
settings = get_settings()


def test_send_dte_dry_run():
    payload = {
        "dte_id": 132,
        "folio": 99999,
        "send": False
    }
    headers = {"X-API-Key": settings.api_key}
    resp = client.post('/api/v1/dte/send', json=payload, headers=headers)
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert 'rebuilt_path' in data and 'signed_path' in data and 'sha1' in data
