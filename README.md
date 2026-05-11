# CipherVault CLI

CipherVault is a small, secure CLI password manager that stores encrypted vaults locally. It uses Argon2id for key derivation and AES-GCM for authenticated encryption.

## Features

- Create an encrypted vault file
- Add / list / get / edit / delete entries
- Argon2id key derivation
- AES-256-GCM encryption
- Export & import encrypted vault files
- Clipboard copy with auto-clear

## Install

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# run directly
python -m ciphervault.cli --help
```

## Quick commands

- `python -m ciphervault.cli init` — create vault
- `python -m ciphervault.cli add "My Site" -u me@example.com --generate --copy` — add
- `python -m ciphervault.cli list` — list entries
- `python -m ciphervault.cli get "My Site" --show --copy` — show entry
- `python -m ciphervault.cli edit "My Site" --password newPw123` — edit entry
- `python -m ciphervault.cli delete "My Site"` — delete entry

## Security notes

- The vault is stored locally in `~/.ciphervault.vault` by default and created with file mode `600`.
- The master password is never stored in plaintext; Argon2id derives the symmetric key.
- AES-GCM provides confidentiality and authenticity; if the vault is tampered with, decryption will fail.

## Improvements / TODO

- Tune Argon2 parameters for your machine
- Add brute-force lockout and rate limiting
- Add sync with encrypted cloud backups
- Add test matrix in CI
