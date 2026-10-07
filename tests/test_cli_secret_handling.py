import os
from pathlib import Path
import subprocess
import sys

from click.testing import CliRunner

from ciphervault.cli import cli
from ciphervault.models import Entry
from ciphervault.vault_handler import VaultHandler


def test_password_argument_is_rejected_before_master_prompt(tmp_path):
    runner = CliRunner()
    for command in ['add', 'edit']:
        result = runner.invoke(cli, ['--vault', str(tmp_path / 'test.vault'), command, 'Mail', '--password', 'synthetic-command-line-secret'], input='test@example.com\n')
        assert result.exit_code == 2
        assert 'unexpected extra argument' in result.output.lower()
        assert not (tmp_path / 'test.vault').exists()


def test_login_password_is_prompted_without_echo(tmp_path, monkeypatch):
    handler = VaultHandler(str(tmp_path / 'test.vault'))
    handler.init_vault('synthetic master passphrase')
    monkeypatch.setattr('ciphervault.cli.getpass.getpass', lambda prompt: 'synthetic master passphrase')
    runner = CliRunner()
    result = runner.invoke(cli, ['--vault', str(handler.path), 'add', 'Mail', '-u', 'test@example.com', '--password'], input='synthetic-login-secret\nsynthetic-login-secret\n')
    assert result.exit_code == 0, result.output
    assert 'synthetic-login-secret' not in result.output
    assert handler.get_entry('synthetic master passphrase', 'Mail').password == 'synthetic-login-secret'
    result = runner.invoke(cli, ['--vault', str(handler.path), 'edit', 'Mail', '--password'], input='synthetic-replacement-secret\nsynthetic-replacement-secret\n')
    assert result.exit_code == 0, result.output
    assert 'synthetic-replacement-secret' not in result.output
    assert handler.get_entry('synthetic master passphrase', 'Mail').password == 'synthetic-replacement-secret'


def test_clipboard_cleanup_survives_normal_cli_exit(tmp_path):
    # A file-backed fake clipboard lets a separate process expose the original
    # daemon-thread bug without touching the user's real clipboard.
    clipboard = tmp_path / 'fake-clipboard.txt'
    code = '''
from pathlib import Path
import sys
from ciphervault import utils
target = Path(sys.argv[1])
class Clipboard:
    @staticmethod
    def copy(value): target.write_text(value)
    @staticmethod
    def paste(): return target.read_text()
utils.pyperclip = Clipboard
assert utils.copy_to_clipboard('synthetic-clipboard-secret', timeout=0.05)
'''
    subprocess.run([sys.executable, '-c', code, str(clipboard)], check=True, timeout=10)
    assert clipboard.read_text() == ''


def test_clipboard_cleanup_keeps_new_clipboard_contents(monkeypatch):
    from ciphervault import utils
    import threading
    started = threading.Event()
    resume = threading.Event()
    finished = threading.Event()
    state = {'clipboard': ''}

    class Clipboard:
        @staticmethod
        def copy(value):
            state['clipboard'] = value

        @staticmethod
        def paste():
            finished.set()
            return state['clipboard']

    def pause(timeout):
        started.set()
        resume.wait(3)

    monkeypatch.setattr(utils, 'pyperclip', Clipboard)
    monkeypatch.setattr(utils.time, 'sleep', pause)
    assert utils.copy_to_clipboard('synthetic-clipboard-secret')
    assert started.wait(3)
    state['clipboard'] = 'new clipboard contents'
    resume.set()
    assert finished.wait(3)
    assert state['clipboard'] == 'new clipboard contents'
