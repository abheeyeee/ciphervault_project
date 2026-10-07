import json
import os
import stat

import pytest

from ciphervault.models import Entry
from ciphervault.vault_handler import VaultHandler, VaultCorrupted, WrongPassword


@pytest.fixture
def vault(tmp_path):
    handler = VaultHandler(str(tmp_path / 'personal.vault'))
    handler.init_vault('synthetic master passphrase')
    handler.add_entry('synthetic master passphrase', Entry.create('Mail', 'test@example.com', 'synthetic entry secret', 'synthetic private note'))
    return handler


def test_local_file_contains_only_encrypted_secrets(vault):
    raw = vault.path.read_text()
    for value in ['synthetic master passphrase', 'test@example.com', 'synthetic entry secret', 'synthetic private note']:
        assert value not in raw
    if os.name == 'posix':
        assert stat.S_IMODE(vault.path.stat().st_mode) == 0o600


def test_init_never_overwrites_existing_file(tmp_path):
    path = tmp_path / 'existing.vault'
    path.write_bytes(b'previous data')
    with pytest.raises(FileExistsError):
        VaultHandler(str(path)).init_vault('synthetic passphrase')
    assert path.read_bytes() == b'previous data'


def test_export_import_authenticate_before_replacing(vault, tmp_path):
    backup = tmp_path / 'backup.vault'
    vault.export_vault('synthetic master passphrase', str(backup))
    if os.name == 'posix':
        assert stat.S_IMODE(backup.stat().st_mode) == 0o600
    other = VaultHandler(str(tmp_path / 'other.vault'))
    other.init_vault('different synthetic master')
    original = other.path.read_bytes()
    with pytest.raises(WrongPassword):
        other.import_vault(str(backup), 'incorrect password')
    assert other.path.read_bytes() == original
    other.import_vault(str(backup), 'synthetic master passphrase')
    assert other.get_entry('synthetic master passphrase', 'Mail').password == 'synthetic entry secret'
    with pytest.raises(FileExistsError):
        vault.export_vault('synthetic master passphrase', str(backup))


def test_tampered_backup_does_not_replace_vault(vault, tmp_path):
    original = vault.path.read_bytes()
    wrapper = json.loads(original)
    wrapper['ciphertext'] = ('A' if wrapper['ciphertext'][0] != 'A' else 'B') + wrapper['ciphertext'][1:]
    backup = tmp_path / 'damaged.vault'
    backup.write_text(json.dumps(wrapper))
    with pytest.raises(WrongPassword):
        vault.import_vault(str(backup), 'synthetic master passphrase')
    assert vault.path.read_bytes() == original


def test_failed_atomic_save_retains_previous_vault(vault, monkeypatch):
    original = vault.path.read_bytes()

    def fail_replace(*args):
        raise OSError('synthetic disk failure')

    monkeypatch.setattr(os, 'replace', fail_replace)
    with pytest.raises(OSError):
        vault.delete_entry('synthetic master passphrase', 'Mail')
    assert vault.path.read_bytes() == original
    assert not vault.path.with_name(vault.path.name + '.lock').exists()
    assert not list(vault.path.parent.glob('.personal.vault-*'))


def test_busy_writer_cannot_overwrite_another_writer(vault):
    original = vault.path.read_bytes()
    with vault._mutation():
        with pytest.raises(RuntimeError, match='busy'):
            VaultHandler(str(vault.path)).delete_entry('synthetic master passphrase', 'Mail')
    assert vault.path.read_bytes() == original


@pytest.mark.skipif(os.name != 'posix', reason='POSIX symlink check')
def test_symlink_vault_is_rejected_without_touching_target(vault, tmp_path):
    original = vault.path.read_bytes()
    link = tmp_path / 'linked.vault'
    link.symlink_to(vault.path)
    with pytest.raises(ValueError, match='symbolic'):
        VaultHandler(str(link)).list_entries('synthetic master passphrase')
    with pytest.raises(ValueError, match='symbolic'):
        VaultHandler(str(link)).wipe_vault()
    assert vault.path.read_bytes() == original


def test_malformed_import_preserves_vault(vault, tmp_path):
    original = vault.path.read_bytes()
    backup = tmp_path / 'invalid.vault'
    backup.write_text('{"magic": "not-base64!"}')
    with pytest.raises(VaultCorrupted):
        vault.import_vault(str(backup), 'synthetic master passphrase')
    assert vault.path.read_bytes() == original


@pytest.mark.parametrize('password', ['', 'short', '12345678901'])
def test_weak_master_change_preserves_existing_vault(vault, password):
    original = vault.path.read_bytes()
    with pytest.raises(ValueError, match='12 characters'):
        vault.change_master_password('synthetic master passphrase', password)
    assert vault.path.read_bytes() == original
    assert vault.get_entry('synthetic master passphrase', 'Mail').password == 'synthetic entry secret'


def test_weak_initial_master_creates_no_file(tmp_path):
    handler = VaultHandler(str(tmp_path / 'personal.vault'))
    with pytest.raises(ValueError, match='12 characters'):
        handler.init_vault('')
    assert not handler.path.exists()
