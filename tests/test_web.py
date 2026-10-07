from pathlib import Path
import os
import subprocess
import sys

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


def test_old_server_vault_assets_are_not_public():
    for path in ['/static/index.html', '/static/js/app.js', '/static/vault.html']:
        assert client.get(path).status_code == 404


def test_legacy_settings_cannot_enable_server_storage(tmp_path):
    database = tmp_path / 'must-not-exist.db'
    environment = dict(os.environ, ENABLE_LEGACY_API='true',
                       SESSION_SECRET_KEY='synthetic-test-key',
                       DATABASE_URL=f'sqlite:///{database}')
    result = subprocess.run([sys.executable, '-c', '''
import sys
from fastapi.testclient import TestClient
from web.main import app
client = TestClient(app)
for path in ['/api/register', '/api/login', '/api/vault/unlock', '/api/entries']:
    assert client.post(path, json={'password': 'synthetic-password'}).status_code == 404
assert client.get('/api/auth/google/callback?mock=true').status_code == 404
assert 'web.database' not in sys.modules
assert 'web.api' not in sys.modules
assert 'sqlalchemy' not in sys.modules
assert 'set-cookie' not in client.get('/app').headers
'''], env=environment, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert not database.exists()


def test_render_start_and_health_match_application():
    config = (Path(__file__).parent.parent / 'render.yaml').read_text()
    assert 'uvicorn web.main:app' in config
    assert '--port $PORT' in config
    assert 'healthCheckPath: /health' in config
    assert 'pip install -r requirements-web.txt' in config


def test_security_policy_and_asset_allowlist():
    response = client.get('/app')
    policy = response.headers['content-security-policy']
    assert "connect-src 'none'" in policy
    assert "script-src 'sha256-" in policy
    assert "frame-ancestors 'none'" in policy
    assert "script-src 'unsafe-inline'" not in policy
    assert response.headers['cross-origin-resource-policy'] == 'same-origin'
    assert 'camera=()' in response.headers['permissions-policy']
    assert "script-src 'none'" in client.get('/').headers['content-security-policy']
    for filename in ['privacy-still-life.webp', 'vault-preview.webp']:
        asset = client.get('/assets/' + filename)
        assert asset.status_code == 200
        assert asset.headers['content-type'] == 'image/webp'
    for filename in ['vault.html', 'vaults.db', '.env', 'main.py']:
        assert client.get('/assets/' + filename).status_code == 404
