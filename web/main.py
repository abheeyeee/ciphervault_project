"""Serve the local-first vault. Vault contents never need a server API."""
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

app = FastAPI(title="CipherVault", docs_url=None, redoc_url=None)
static_dir = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# The server-held legacy vault is only for existing development integrations.
if os.getenv("ENABLE_LEGACY_API") == "true":
    from starlette.middleware.sessions import SessionMiddleware
    from web.api import router

    session_key = os.getenv("SESSION_SECRET_KEY")
    if not session_key:
        raise RuntimeError("SESSION_SECRET_KEY is required for ENABLE_LEGACY_API")
    app.add_middleware(SessionMiddleware, secret_key=session_key)
    app.include_router(router, prefix="/api")


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
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
