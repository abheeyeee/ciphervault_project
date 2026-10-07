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

Python 3.12 is the tested runtime.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install --no-deps -e .
uvicorn web.main:app --host 127.0.0.1 --port 8000 --reload
```

`/` is the landing page, `/app` is the vault, `/download` downloads the offline tool, and `/health` is the deployment health check. Localhost supports Web Crypto; public deployments must use HTTPS.

## Deploy on Render

Use the included `render.yaml` as a Render Blueprint, or update your existing Python web service:

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn web.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`
- Python runtime: 3.12

No database, Google credentials, or persistent Render disk is required for the new browser vault. Keep `ENABLE_LEGACY_API` unset. After deployment, verify the landing page, create a vault, add a synthetic login, export a backup, lock/unlock, and download/open the offline file. Updating this repository does not deploy an existing Render service unless it is connected to the branch and auto-deploy is enabled.

## Storage and encryption

The tool derives a non-exportable AES-256-GCM key from the master password using PBKDF2-SHA256 with 600,000 iterations and a random 16-byte salt. Each save uses a fresh random 12-byte IV. Only the encrypted JSON envelope is saved in localStorage or exported. Passwords are generated with `crypto.getRandomValues` and rejection sampling.

The vault page blocks network connections via Content Security Policy and has no external scripts, fonts, or assets. Decrypted entries exist in the page while unlocked. Locking removes the active key, decrypted state, forms, and entry display; JavaScript cannot guarantee physical memory erasure. Clipboard contents may outlive the page and must be cleared by the user. This project has not undergone an independent security audit.

**Keep encrypted backups outside browser storage.** Clearing site data, private browsing, storage restrictions, or losing a device can erase a vault. There is no password recovery or automatic sync. The website and downloaded file have separate storage. Transfer data by exporting and importing a backup. Older backups retain the master password used when they were created.

The offline HTML file works in current Chrome, Edge, and Firefox with Web Crypto support. File-based localStorage behavior varies between browsers and file locations; keep the file in the same location and retain encrypted backups. The download is not a native app, browser extension, or autofill integration.

## Existing CLI and server vaults

The Python CLI and its existing SQLite vault implementation are retained. **The new browser format does not import old CLI/server exports or automatically migrate existing data.** Keep the previous installation and database if you need those vaults. Existing data is not deleted by the new web app.

Use a separate database for CLI work to preserve the repository's existing database:

```bash
export DATABASE_URL=sqlite:////absolute/path/to/development.db
python -m ciphervault.cli --help
```

The legacy CLI's `--vault` option currently acts as a database account identifier, despite its file-oriented help text. Legacy file import/export commands are not implemented by the current `VaultHandler`; they are not advertised as part of the new download.

For development integrations only, the old server API can be enabled with `ENABLE_LEGACY_API=true` and an explicitly supplied `SESSION_SECRET_KEY`. It retains its previous behavior, including mock OAuth. Do not enable it on the public deployment. The new browser app does not use it.

## Validation

```bash
DATABASE_URL=sqlite:////tmp/ciphervault-tests.db python -m pytest -q
flake8 --exclude=venv --extend-ignore=E501,E302,E303,W293,F401,W291,E305
```

Browser smoke tests live in `tests/browser_smoke.cjs`. Install Playwright in a temporary QA directory, install its Chromium, start the app, then run:

```bash
npm install --prefix /tmp/ciphervault-qa playwright
/tmp/ciphervault-qa/node_modules/.bin/playwright install chromium
NODE_PATH=/tmp/ciphervault-qa/node_modules node tests/browser_smoke.cjs
```

`CIPHERVAULT_URL` defaults to `http://127.0.0.1:8000`. `CHROMIUM_PATH` can select an existing Chromium executable. The test uses synthetic credentials and temporary browser profiles; it exercises encryption at rest, CRUD, wrong-password rejection, password changes, backups/imports, mobile layout, and the actual downloaded file offline. Do not use a browser policy that blocks `file://` access for the offline check.
