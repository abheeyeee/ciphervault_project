"""Encrypted local files only; no server, account, or network storage."""
import base64
import json
import os
from contextlib import contextmanager
from pathlib import Path
import secrets
import tempfile
from typing import Optional, List

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type
from .models import Entry

VAULT_MAGIC = b"CIPHER_V1"
MAX_VAULT_BYTES = 20 * 1024 * 1024
ARGON_TIME_COST = 2
ARGON_MEMORY_COST = 2 ** 16
ARGON_PARALLELISM = 2
ARGON_HASH_LEN = 32
ARGON_TYPE = Type.ID


class VaultCorrupted(Exception):
    pass


class WrongPassword(Exception):
    pass


class VaultHandler:
    def __init__(self, path: str):
        self.path = Path(path).expanduser()

    @staticmethod
    def _derive_key(master_password: str, salt: bytes) -> bytes:
        return hash_secret_raw(secret=master_password.encode('utf-8'), salt=salt,
                               time_cost=ARGON_TIME_COST, memory_cost=ARGON_MEMORY_COST,
                               parallelism=ARGON_PARALLELISM, hash_len=ARGON_HASH_LEN,
                               type=ARGON_TYPE)

    def vault_exists(self) -> bool:
        return self.path.exists() or self.path.is_symlink()

    @staticmethod
    def _validate_new_password(password: str):
        if not isinstance(password, str) or len(password) < 12:
            raise ValueError('Use at least 12 characters for a new master password.')

    @contextmanager
    def _mutation(self):
        # Exclusive sidecar creation prevents two CLI writers losing updates.
        lock = self.path.with_name(self.path.name + '.lock')
        try:
            fd = os.open(lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            raise RuntimeError('Vault is busy. If a process crashed, remove its .lock file after checking it is no longer running.')
        try:
            os.close(fd)
            if self.path.is_symlink():
                raise ValueError('Vault paths must not be symbolic links.')
            yield
        finally:
            lock.unlink()

    @staticmethod
    def _load_wrapper(path: Path) -> dict:
        if path.is_symlink():
            raise ValueError('Vault paths must not be symbolic links.')
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(fd, 'rb') as source:
            raw = source.read(MAX_VAULT_BYTES + 1)
        if len(raw) > MAX_VAULT_BYTES:
            raise VaultCorrupted('Vault file is too large.')
        try:
            wrapper = json.loads(raw)
            fields = {name: base64.b64decode(wrapper[name], validate=True)
                      for name in ('magic', 'salt', 'nonce', 'ciphertext')}
            if (fields['magic'] != VAULT_MAGIC or len(fields['salt']) != 16
                    or len(fields['nonce']) != 12 or len(fields['ciphertext']) < 16):
                raise ValueError('Invalid encrypted envelope')
        except (ValueError, TypeError, KeyError):
            raise VaultCorrupted('Missing or invalid vault header.')
        return wrapper

    @staticmethod
    def _decrypt(wrapper: dict, master_password: str) -> dict:
        key = VaultHandler._derive_key(master_password, base64.b64decode(wrapper['salt']))
        try:
            plaintext = AESGCM(key).decrypt(base64.b64decode(wrapper['nonce']),
                                            base64.b64decode(wrapper['ciphertext']), None)
        except InvalidTag:
            raise WrongPassword('Incorrect master password or vault corrupted')
        try:
            data = json.loads(plaintext)
            if not isinstance(data, dict) or not isinstance(data.get('entries'), list):
                raise ValueError('Invalid entries')
            for entry in data['entries']:
                Entry.from_dict(entry)
        except (ValueError, TypeError, KeyError):
            raise VaultCorrupted('Invalid decrypted vault contents.')
        return data

    @staticmethod
    def _atomic_write(path: Path, payload: bytes, create: bool = False):
        if len(payload) > MAX_VAULT_BYTES:
            raise VaultCorrupted('Vault file is too large.')
        if path.is_symlink():
            raise ValueError('Vault paths must not be symbolic links.')
        fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
        try:
            with os.fdopen(fd, 'wb') as target:
                target.write(payload)
                target.flush()
                os.fsync(target.fileno())
            if create:
                # No overwrite, including an existing empty file.
                os.link(temporary, path)
            else:
                os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _write_encrypted(self, data: dict, key: bytes, salt: bytes, create: bool = False):
        nonce = secrets.token_bytes(12)
        ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode('utf-8'), None)
        wrapper = {name: base64.b64encode(value).decode('ascii') for name, value in
                   {'magic': VAULT_MAGIC, 'salt': salt, 'nonce': nonce, 'ciphertext': ct}.items()}
        self._atomic_write(self.path, json.dumps(wrapper).encode('utf-8'), create=create)

    def init_vault(self, master_password: str):
        self._validate_new_password(master_password)
        with self._mutation():
            if self.vault_exists():
                raise FileExistsError('Vault already exists')
            salt = secrets.token_bytes(16)
            self._write_encrypted({'entries': []}, self._derive_key(master_password, salt), salt, create=True)

    def _read_encrypted(self, master_password: str) -> dict:
        return self._decrypt(self._load_wrapper(self.path), master_password)

    def _modify(self, master_password: str, change):
        with self._mutation():
            wrapper = self._load_wrapper(self.path)
            data = self._decrypt(wrapper, master_password)
            result = change(data['entries'])
            salt = base64.b64decode(wrapper['salt'])
            self._write_encrypted(data, self._derive_key(master_password, salt), salt)
            return result

    def add_entry(self, master_password: str, entry: Entry):
        def change(entries):
            entries[:] = [e for e in entries if e['name'].lower() != entry.name.lower()]
            entries.append(entry.to_dict())
            return True
        return self._modify(master_password, change)

    def list_entries(self, master_password: str) -> List[Entry]:
        return [Entry.from_dict(d) for d in self._read_encrypted(master_password)['entries']]

    def get_entry(self, master_password: str, name: str) -> Optional[Entry]:
        return next((e for e in self.list_entries(master_password) if e.name.lower() == name.lower()), None)

    def delete_entry(self, master_password: str, name: str) -> bool:
        def change(entries):
            original = len(entries)
            entries[:] = [e for e in entries if e['name'].lower() != name.lower()]
            return len(entries) < original
        return self._modify(master_password, change)

    def update_entry(self, master_password: str, name: str, new_entry: Entry) -> bool:
        def change(entries):
            for i, entry in enumerate(entries):
                if entry['name'].lower() == name.lower():
                    entries[i] = new_entry.to_dict()
                    return True
            return False
        return self._modify(master_password, change)

    def change_master_password(self, old_password: str, new_password: str):
        self._validate_new_password(new_password)
        with self._mutation():
            data = self._read_encrypted(old_password)
            salt = secrets.token_bytes(16)
            self._write_encrypted(data, self._derive_key(new_password, salt), salt)
        return True

    def export_vault(self, master_password: str, path: str):
        wrapper = self._load_wrapper(self.path)
        self._decrypt(wrapper, master_password)
        self._atomic_write(Path(path).expanduser(), json.dumps(wrapper).encode('utf-8'), create=True)

    def import_vault(self, path: str, master_password: str):
        wrapper = self._load_wrapper(Path(path).expanduser())
        self._decrypt(wrapper, master_password)
        with self._mutation():
            self._atomic_write(self.path, json.dumps(wrapper).encode('utf-8'))

    def wipe_vault(self):
        with self._mutation():
            if not self.vault_exists():
                return False
            self.path.unlink()
            return True
