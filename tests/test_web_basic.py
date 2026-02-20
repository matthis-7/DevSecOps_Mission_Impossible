import sys
from pathlib import Path

# Ajoute la racine du repo au PYTHONPATH pour importer web.app
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from web.app import app  # noqa: E402


def test_status_endpoint_ok():
    client = app.test_client()
    resp = client.get("/status")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data == {"service": "escape-app-expert", "ok": True}


def test_homepage_responds():
    client = app.test_client()
    resp = client.get("/")
    assert resp.status_code == 200
    # Juste une vérif simple que c'est du HTML
    assert "text/html" in resp.content_type