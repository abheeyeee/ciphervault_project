from pathlib import Path

from fastapi.testclient import TestClient

from web.main import app

client = TestClient(app)


def test_home_and_vault():
    home = client.get('/')
    assert home.status_code == 200
    assert 'Use in your browser' in home.text
    assert '/download' in home.text
    vault = client.get('/app')
    assert vault.status_code == 200
    assert "connect-src 'none'" in vault.text
    assert 'crypto.subtle.encrypt' in vault.text
    assert vault.headers['x-content-type-options'] == 'nosniff'
    assert vault.headers['cache-control'] == 'no-store'


def test_download_is_the_same_self_contained_tool():
    response = client.get('/download')
    assert response.status_code == 200
    assert 'attachment' in response.headers['content-disposition']
    assert 'CipherVault.html' in response.headers['content-disposition']
    assert response.content == client.get('/app').content
    assert '<script src=' not in response.text
    assert '<link ' not in response.text


def test_stateless_health_and_legacy_disabled():
    assert client.get('/health').json() == {'status': 'ok'}
    assert client.get('/api/entries').status_code == 404
    assert client.get('/api/auth/google/callback?mock=true').status_code == 404


def test_render_start_and_health_match_application():
    config = (Path(__file__).parent.parent / 'render.yaml').read_text()
    assert 'uvicorn web.main:app' in config
    assert '--port $PORT' in config
    assert 'healthCheckPath: /health' in config
