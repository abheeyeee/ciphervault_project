# CipherVault

An everyday password vault you can **use on the website or download and use offline**. The browser tool encrypts logins on the user's device; no account or server database is needed.

## What you can do

- Create and unlock a vault with a master passphrase.
- Save, search, edit, and delete logins, websites, and notes.
- Generate random passwords and copy saved passwords.
- Automatically lock after inactivity (5 minutes by default).
- Download encrypted backups, import them on another device, and change the master password.
- Download `CipherVault.html`: the same self-contained tool with no external assets or network requests.

## Run locally

Use Python 3.12 for deployment; CI also verifies Python 3.11.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-web.txt
uvicorn web.main:app --host 127.0.0.1 --port 8000 --reload
```

`/` is the landing page, `/app` is the vault, `/download` downloads the offline tool, and `/health` is the deployment health check. Localhost supports Web Crypto; public deployments must use HTTPS.

## Deploy on Render

Use the included `render.yaml` as a Render Blueprint, or update your existing Python web service:

- Build command: `pip install -r requirements-web.txt`
- Start command: `uvicorn web.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`
- Python runtime: 3.12

Web dependencies are pinned, including transitive packages, in `requirements-web.txt`. The Docker image copies only public application files and runs as an unprivileged user. No database, Google credentials, or persistent Render disk is required for the new browser vault. The web server has no vault API or database integration; legacy environment settings cannot enable one. After deployment, verify the landing page, create a vault, add a synthetic login, export a backup, lock/unlock, and download/open the offline file. Updating this repository does not deploy an existing Render service unless it is connected to the branch and auto-deploy is enabled.

## Storage and encryption

The tool derives a non-exportable AES-256-GCM key from the master password using PBKDF2-SHA256 with 600,000 iterations and a random 16-byte salt. Each save uses a fresh random 12-byte IV. Only the encrypted JSON envelope is saved in localStorage or exported. Passwords are generated with `crypto.getRandomValues` and rejection sampling.

New vaults and master-password changes use 600,000 iterations. Compatible imported backups may use 100,000-2,000,000 iterations; subsequent saves retain the imported count until the master password is changed.

The server only delivers public pages, allowlisted landing images, the offline download, crawler guidance, and health status. It never receives master passwords, entries, or encrypted backups. Old login pages and server API scripts are not publicly served.

The vault page allows only its hash-matched script and blocks network connections via Content Security Policy and has no external scripts, fonts, or assets. Decrypted entries exist in the page while unlocked. Locking removes the active key, decrypted state, forms, and entry display; JavaScript cannot guarantee physical memory erasure. Clipboard contents may outlive the page and must be cleared by the user. This project has not undergone an independent security audit.

**Keep encrypted backups outside browser storage.** Clearing site data, private browsing, storage restrictions, or losing a device can erase a vault. There is no password recovery or automatic sync. The website and downloaded file have separate storage. Transfer data by exporting and importing a backup. Older backups retain the master password used when they were created.

The offline HTML file works in current Chrome, Edge, and Firefox with Web Crypto support. File-based localStorage behavior varies between browsers and file locations; keep the file in the same location and retain encrypted backups. The download is not a native app, browser extension, or autofill integration.

## Local Python CLI

The optional CLI uses encrypted `.vault` files on the user's computer. It has no accounts, server API, or database dependencies. The master password derives an AES-256-GCM key using Argon2id, with a fresh salt at creation and password changes and a fresh nonce on every save. Files are written atomically with owner-only permissions on POSIX systems; Windows users must secure the vault folder with their account's filesystem permissions.

```bash
pip install -r requirements.txt
pip install --no-deps -e .
python -m ciphervault.cli --help
```

`--vault /absolute/path/personal.vault` selects the local encrypted file. The default is `~/.ciphervault.vault`. Export creates an encrypted backup without overwriting an existing file. Import verifies the password and contents before replacing a vault, and asks for confirmation when one already exists. A `.lock` sidecar prevents concurrent CLI writes; after a crash, remove it only after confirming no vault process is running.

New CLI master passwords require at least 12 characters. Existing vaults still unlock with their original password. Use `--password` and `--notes` as flags to enter values in hidden prompts; these flags no longer accept secret values as arguments. Omitting `--password` when adding a login generates a random password. This avoids putting passwords and private notes in process arguments or shell history. CLI copy actions keep the process alive to attempt clearing the current clipboard after 10 seconds; clipboard history, unavailable clipboard access, or forced process termination can prevent complete removal.

The CLI and browser encryption formats are separate. **Neither imports the other's backups.** Previous server data is preserved in the private, Git-ignored laptop backup; it is not automatically migrated or shipped. Keep that backup until any needed data has been recovered. The old server API, accounts, OAuth, database module, and API-calling frontend have been removed.

## Validation

```bash
python -m pytest -q
flake8 --jobs=1 --exclude=venv,node_modules,.local-backups --extend-ignore=E501,E302,E303,W293,F401,W291,E305
```

Browser smoke tests live in `tests/browser_smoke.cjs`. Install Playwright in a temporary QA directory, install its Chromium, start the app, then run:

```bash
npm install --prefix /tmp/ciphervault-qa playwright
/tmp/ciphervault-qa/node_modules/.bin/playwright install chromium
NODE_PATH=/tmp/ciphervault-qa/node_modules node tests/browser_smoke.cjs
```

`CIPHERVAULT_URL` defaults to `http://127.0.0.1:8000`. `CHROMIUM_PATH` can select an existing Chromium executable. The test uses synthetic credentials and temporary browser profiles; it exercises encryption at rest, CRUD, wrong-password rejection, password changes, backups/imports, mobile layout, and the actual downloaded file offline. Do not use a browser policy that blocks `file://` access for the offline check.

A scoped security review, validation results, and infrastructure limits are recorded in [docs/SECURITY_REVIEW.md](docs/SECURITY_REVIEW.md).
