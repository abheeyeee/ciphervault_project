import pytest
from ciphervault.vault_handler import VaultHandler, WrongPassword
from ciphervault.models import Entry

def test_wrong_password_fails(tmp_path):
    vh = VaultHandler(str(tmp_path / 'test.vault'))
    vh.init_vault('correct-passphrase')
    e = Entry.create('site', 'user', 'pw')
    vh.add_entry('correct-passphrase', e)
    with pytest.raises(WrongPassword):
        vh.get_entry('incorrect', 'site')
    vh.wipe_vault()

def test_change_master_password(tmp_path):
    vh = VaultHandler(str(tmp_path / 'test.vault'))
    vh.init_vault('old-passphrase')
    e = Entry.create('s', 'u', 'p')
    vh.add_entry('old-passphrase', e)
    vh.change_master_password('old-passphrase', 'new-passphrase')
    with pytest.raises(WrongPassword):
        vh.list_entries('old-passphrase')
    entries = vh.list_entries('new-passphrase')
    assert len(entries) == 1
    vh.wipe_vault()
