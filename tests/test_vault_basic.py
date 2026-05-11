import tempfile
from ciphervault.vault_handler import VaultHandler
from ciphervault.models import Entry

def test_create_and_add_and_get():
    tmp = tempfile.NamedTemporaryFile(suffix='.vault', delete=False)
    path = tmp.name
    tmp.close()
    vh = VaultHandler(path)
    vh.init_vault('strong-pass-123')
    e = Entry.create('site', 'user', 'pw123')
    assert vh.add_entry('strong-pass-123', e)
    got = vh.get_entry('strong-pass-123', 'site')
    assert got is not None
    assert got.username == 'user'
    assert got.password == 'pw123'
    assert vh.delete_entry('strong-pass-123', 'site')
    vh.wipe_vault()
