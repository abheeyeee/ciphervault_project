from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from starlette.middleware.sessions import SessionMiddleware
import os
from web.api import router
from web.database import init_db

app = FastAPI(title="CipherVault Web")

@app.on_event("startup")
def on_startup():
    init_db()

# SessionMiddleware is required by Authlib
app.add_middleware(SessionMiddleware, secret_key=os.getenv("SESSION_SECRET_KEY", "super-secret-default-key"))

# Include the API router
app.include_router(router, prefix="/api")

# Mount static files
static_dir = os.path.join(os.path.dirname(__file__), "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

@app.get("/")
def serve_landing():
    landing_path = os.path.join(static_dir, "landing.html")
    if os.path.exists(landing_path):
        return FileResponse(landing_path)
    return {"message": "Landing page not found"}

@app.get("/app")
def serve_app():
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "App not found"}
