"""Serve the device-only vault. This server never handles vault contents."""
from pathlib import Path
import re

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

app = FastAPI(title="CipherVault", docs_url=None, redoc_url=None, openapi_url=None)
static_dir = Path(__file__).parent / "static"
# The offline page carries the same restrictive policy. Reading fixed local
# markup here does not involve vault files, request data, or environment secrets.
vault_policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"',
                         (static_dir / "vault.html").read_text()).group(1)
landing_policy = ("default-src 'none'; script-src 'none'; style-src 'unsafe-inline'; "
                  "img-src 'self'; connect-src 'none'; base-uri 'none'; form-action 'none'")
ASSETS = {name: static_dir / "assets" / name for name in
          ("privacy-still-life.webp", "vault-preview.webp")}



@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    policy = vault_policy if request.url.path in ("/app", "/download") else landing_policy
    response.headers["Content-Security-Policy"] = policy + "; frame-ancestors 'none'"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/")
def serve_landing():
    return FileResponse(static_dir / "landing.html")


@app.get("/app")
def serve_app():
    return FileResponse(static_dir / "vault.html")


@app.get("/download")
def download_app():
    return FileResponse(static_dir / "vault.html", media_type="text/html",
                        filename="CipherVault.html")


@app.get("/assets/{name}")
def landing_asset(name: str):
    # An explicit allowlist prevents serving source files or private data.
    if name not in ASSETS:
        raise HTTPException(status_code=404)
    return FileResponse(ASSETS[name], media_type="image/webp")


@app.get("/robots.txt")
def robots():
    return PlainTextResponse("User-agent: *\nAllow: /\nDisallow: /app\nDisallow: /download\nDisallow: /api/\n")


@app.get("/favicon.ico")
def favicon():
    return FileResponse(static_dir / "assets" / "brand-mark.webp", media_type="image/webp")
