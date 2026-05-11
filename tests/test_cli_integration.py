# Simple smoke test for CLI entrypoints using subprocess
import subprocess
import sys

def run_cmd(args):
    p = subprocess.run([sys.executable, '-m', 'ciphervault.cli'] + args, input=b'', stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return p

def test_help_shows():
    p = run_cmd(['--help'])
    assert p.returncode == 0
    assert b'CipherVault' in p.stdout or b'CipherVault' in p.stderr
