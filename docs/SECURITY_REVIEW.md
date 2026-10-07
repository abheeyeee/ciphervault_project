# CipherVault security review

Review date: 2026-10-07. Scope: current application code, remaining dependencies, browser/offline flows, packaging, and available Render service metadata. This is a development review, not a guarantee against every attack.

## Device-only boundary

The server serves fixed public pages, allowlisted images, the offline download, crawler guidance, and health status. It has no vault API, database driver, authentication service, database connection, or persistence disk requirement. Obsolete environment settings cannot enable the removed API. Browser passwords, derived keys, decrypted entries, and encrypted backups do not go to the server.

Browser storage and encrypted export retain the existing `ciphervault-browser` version 1 format. The UI redesign leaves its encryption script unchanged: PBKDF2-SHA256 and AES-256-GCM, fresh salt and IV, non-exportable key. The Python CLI uses separate local encrypted files with Argon2id and authenticated encryption. Old server data is preserved privately rather than silently migrated or deleted.

## Remediations and protection

- Removed the server database, OAuth/accounts, legacy API, old API-calling frontend, and database/auth dependencies.
- Removed command-line password and private-note values from arguments; input uses hidden prompts.
- Enforced a minimum new CLI master-password length and fixed clipboard cleanup being terminated at normal process exit.
- Added atomic owner-only local files, authenticated import, no-overwrite exports, and a competing-writer lock.
- Restricted vault scripts to a SHA-256 hash, blocked network connections, and prevented framing. The downloaded HTML retains its own policy. Responses carry no-referrer, no-store, nosniff, restricted permissions, and same-origin resource policy.
- Limited image serving to explicit public filenames. Docker copies only public app files, excludes private data and configuration, and runs as an unprivileged user. CI has read-only repository permissions.
- Upgraded AnyIO to 4.14.2 and Starlette to 1.3.1 for current advisories. The complete pinned web dependency tree and resolved CLI/test requirements passed `pip-audit` with no known vulnerabilities.

## Verification

27 Python regression/security tests passed. Chromium tests covered encryption at rest, CRUD/search, lock and wrong-password rejection, master-password change, encrypted backups/import, generator, mobile layout, storage failure rollback, auto-lock, tampered-backup rejection, and actual downloaded-file operation offline with no HTTP requests. The redesign was checked at desktop, 390px, and 320px widths in both themes. Automated WCAG A/AA checks found no violations on the landing and vault gate pages.

Local Lighthouse mobile measurements: performance 100, accessibility 100, best practices 100, SEO 92; LCP approximately 1.4 seconds, CLS 0, no blocking time. The robots check was blocked by the page's restrictive CSP; the endpoint itself returned valid crawler guidance. These are local lab results, not measured production Core Web Vitals.

## Infrastructure evidence and limits

The connected Render workspace contains the CipherVault Docker web service, linked to this repository's `main` branch with deployment after checks pass. No PostgreSQL or Key Value instances were listed. Its existing health-check path is empty; the application exposes `/health`, and `render.yaml` configures that path for Blueprint deployments. Source changes do not automatically update existing dashboard settings.

The local Docker daemon was unavailable, so the Docker build could not be exercised locally; Render's build and live endpoint checks must validate the image. GitHub CI passed on the pushed cleanup. The GitHub branch API reports that `main` is **not protected**. Enable required checks and pull-request review before treating publication of vault code as reviewed. Provider access controls, account MFA, secret environment values, historical provider disk contents, and all provider-side caches were not independently audited. No unrelated service or account resource was modified.

The historical `vaults.db` file is purged from the published main branch under the owner's explicit approval. A private recovery copy and pre-rewrite Git bundle are retained on the laptop. Rewriting Git cannot revoke copies in old clones, forks, pull-request refs, provider caches, or previous deployment artifacts. GitHub support can assist with cached historical sensitive-data removal. Other checkouts must fetch the rewritten branch without merging the old history back in.

Users must trust their device, browser extensions, master password, and delivered application code. Decrypted secrets are present while unlocked; JavaScript cannot promise physical memory erasure. Clipboard history may retain copied passwords. Browser data can be lost, and forgotten master passwords cannot be recovered. Keep encrypted backups outside browser storage.
