import json
import base64
from typing import Dict, Optional, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from argon2.low_level import hash_secret_raw, Type
from .models import Entry
import secrets

from web.database import SessionLocal, Vault

VAULT_MAGIC = b"CIPHER_V1"

# Argon2 parameters
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
    def __init__(self, username: str):
        self.username = username
        self._data: Dict[str, dict] = {}

    @staticmethod
    def _derive_key(master_password: str, salt: bytes) -> bytes:
        return hash_secret_raw(
            secret=master_password.encode('utf-8'),
            salt=salt,
            time_cost=ARGON_TIME_COST,
            memory_cost=ARGON_MEMORY_COST,
            parallelism=ARGON_PARALLELISM,
            hash_len=ARGON_HASH_LEN,
            type=ARGON_TYPE
        )

    def vault_exists(self) -> bool:
        with SessionLocal() as db:
            return db.query(Vault).filter(Vault.username == self.username).first() is not None

    def init_vault(self, master_password: str):
        if self.vault_exists():
            raise FileExistsError("Vault already exists")
        salt = secrets.token_bytes(16)
        key = self._derive_key(master_password, salt)
        self._data = {"entries": []}
        self._write_encrypted(self._data, key, salt)

    def _write_encrypted(self, data: dict, key: bytes, salt: bytes):
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(12)
        plaintext = json.dumps(data).encode('utf-8')
        ct = aesgcm.encrypt(nonce, plaintext, None)
        
        with SessionLocal() as db:
            vault = db.query(Vault).filter(Vault.username == self.username).first()
            if not vault:
                vault = Vault(username=self.username)
                db.add(vault)
            vault.magic = base64.b64encode(VAULT_MAGIC).decode('utf-8')
            vault.salt = base64.b64encode(salt).decode('utf-8')
            vault.nonce = base64.b64encode(nonce).decode('utf-8')
            vault.ciphertext = base64.b64encode(ct).decode('utf-8')
            db.commit()

    def _read_encrypted(self, master_password: str) -> dict:
        with SessionLocal() as db:
            vault = db.query(Vault).filter(Vault.username == self.username).first()
            if not vault:
                raise FileNotFoundError("Vault not found. Create it first.")
            wrapper = {
                "magic": vault.magic,
                "salt": vault.salt,
                "nonce": vault.nonce,
                "ciphertext": vault.ciphertext
            }
            
        try:
            magic = base64.b64decode(wrapper["magic"].encode('utf-8'))
        except Exception:
            raise VaultCorrupted("Missing or invalid vault header")
            
        if magic != VAULT_MAGIC:
            raise VaultCorrupted("Vault file not recognized")
            
        salt = base64.b64decode(wrapper["salt"].encode('utf-8'))
        nonce = base64.b64decode(wrapper["nonce"].encode('utf-8'))
        ct = base64.b64decode(wrapper["ciphertext"].encode('utf-8'))
        
        key = self._derive_key(master_password, salt)
        aesgcm = AESGCM(key)
        
        try:
            plaintext = aesgcm.decrypt(nonce, ct, None)
        except InvalidTag:
            raise WrongPassword("Incorrect master password or vault corrupted")
            
        data = json.loads(plaintext.decode('utf-8'))
        self._data = data
        return data

    def _read_raw_field(self, field: str) -> str:
        with SessionLocal() as db:
            vault = db.query(Vault).filter(Vault.username == self.username).first()
            if not vault:
                raise FileNotFoundError("Vault not found.")
            return getattr(vault, field)

    def add_entry(self, master_password: str, entry: Entry):
        data = self._read_encrypted(master_password)
        entries: List[dict] = data.get('entries', [])
        entries = [e for e in entries if e['name'].lower() != entry.name.lower()]
        entries.append(entry.to_dict())
        data['entries'] = entries
        
        salt = base64.b64decode(self._read_raw_field('salt'))
        key = self._derive_key(master_password, salt)
        self._write_encrypted(data, key, salt)
        return True

    def list_entries(self, master_password: str) -> List[Entry]:
        data = self._read_encrypted(master_password)
        return [Entry.from_dict(d) for d in data.get('entries', [])]

    def get_entry(self, master_password: str, name: str) -> Optional[Entry]:
        data = self._read_encrypted(master_password)
        for d in data.get('entries', []):
            if d['name'].lower() == name.lower():
                return Entry.from_dict(d)
        return None

    def delete_entry(self, master_password: str, name: str) -> bool:
        data = self._read_encrypted(master_password)
        orig_len = len(data.get('entries', []))
        entries = [e for e in data.get('entries', []) if e['name'].lower() != name.lower()]
        data['entries'] = entries
        
        salt = base64.b64decode(self._read_raw_field('salt'))
        key = self._derive_key(master_password, salt)
        self._write_encrypted(data, key, salt)
        return len(entries) < orig_len

    def update_entry(self, master_password: str, name: str, new_entry: Entry) -> bool:
        data = self._read_encrypted(master_password)
        updated = False
        entries = []
        for e in data.get('entries', []):
            if e['name'].lower() == name.lower():
                entries.append(new_entry.to_dict())
                updated = True
            else:
                entries.append(e)
        data['entries'] = entries
        
        salt = base64.b64decode(self._read_raw_field('salt'))
        key = self._derive_key(master_password, salt)
        self._write_encrypted(data, key, salt)
        return updated

    def change_master_password(self, old_password: str, new_password: str):
        data = self._read_encrypted(old_password)
        salt = secrets.token_bytes(16)
        key = self._derive_key(new_password, salt)
        self._write_encrypted(data, key, salt)
        return True

    def wipe_vault(self):
        with SessionLocal() as db:
            vault = db.query(Vault).filter(Vault.username == self.username).first()
            if vault:
                db.delete(vault)
                db.commit()
                return True
        return False
