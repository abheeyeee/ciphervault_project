import tempfile
import pytest
from ciphervault.vault_handler import VaultHandler, WrongPassword
from ciphervault.models import Entry

def test_wrong_password_fails():
    tmp = tempfile.NamedTemporaryFile(suffix='.vault', delete=False)
    path = tmp.name
    tmp.close()
    vh = VaultHandler(path)
    vh.init_vault('correct-pass')
    e = Entry.create('site', 'user', 'pw')
    vh.add_entry('correct-pass', e)
    with pytest.raises(WrongPassword):
        vh.get_entry('incorrect', 'site')
    vh.wipe_vault()

def test_change_master_password():
    tmp = tempfile.NamedTemporaryFile(suffix='.vault', delete=False)
    path = tmp.name
    tmp.close()
    vh = VaultHandler(path)
    vh.init_vault('oldpass')
    e = Entry.create('s', 'u', 'p')
    vh.add_entry('oldpass', e)
    vh.change_master_password('oldpass', 'newpass')
    with pytest.raises(WrongPassword):
        vh.list_entries('oldpass')
    entries = vh.list_entries('newpass')
    assert len(entries) == 1
    vh.wipe_vault()
