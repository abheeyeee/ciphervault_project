import os
from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends, status, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
import secrets

from authlib.integrations.starlette_client import OAuth
from starlette.config import Config

from ciphervault.vault_handler import VaultHandler, VaultCorrupted, WrongPassword
from ciphervault.models import Entry
from web.database import SessionLocal, Vault
import zxcvbn

router = APIRouter()

# Setup OAuth
config = Config(environ=os.environ)
oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=os.getenv('GOOGLE_CLIENT_ID', 'mock-id'),
    client_secret=os.getenv('GOOGLE_CLIENT_SECRET', 'mock-secret'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# In-memory session store: token -> {"username": str, "master_password": str, "is_locked": bool}
sessions = {}

# Ensure vaults directory exists
def get_vault_handler(username: str) -> VaultHandler:
    return VaultHandler(username)

class AuthRequest(BaseModel):
    username: str
    master_password: str

class UnlockRequest(BaseModel):
    master_password: str

class EntryModel(BaseModel):
    name: str
    username: str
    password: str
    notes: Optional[str] = ""

class StrengthRequest(BaseModel):
    password: str

def get_session(request: Request):
    token = request.cookies.get("session_token")
    if not token or token not in sessions:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")
    return sessions[token]

def get_unlocked_session(request: Request):
    session = get_session(request)
    if session.get("is_locked", True):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Vault is locked")
    return session

# --- GOOGLE OAUTH ROUTES ---
@router.get("/auth/google/login")
async def google_login(request: Request):
    if os.getenv('GOOGLE_CLIENT_ID') is None:
        # MOCK LOGIN for local development testing
        return RedirectResponse(url="/api/auth/google/callback?mock=true")
    redirect_uri = request.url_for('google_auth_callback')
    return await oauth.google.authorize_redirect(request, redirect_uri)

@router.get("/auth/google/callback", name="google_auth_callback")
async def google_auth_callback(request: Request):
    mock = request.query_params.get("mock")
    if mock == "true":
        user_info = {"email": "mockuser@google.com"}
    else:
        try:
            token = await oauth.google.authorize_access_token(request)
            user_info = token.get('userinfo')
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"OAuth Failed: {str(e)}")

    username = user_info['email']
    session_token = secrets.token_hex(32)
    sessions[session_token] = {
        "username": username,
        "master_password": None,
        "is_locked": True
    }
    
    resp = RedirectResponse(url="/app")
    resp.set_cookie(key="session_token", value=session_token, httponly=True)
    return resp

# --- STANDARD AUTH ROUTES ---
@router.post("/register")
def register(req: AuthRequest, response: Response):
    vh = get_vault_handler(req.username)
    if vh.vault_exists():
        raise HTTPException(status_code=400, detail="User already exists")
    try:
        vh.init_vault(req.master_password)
        token = secrets.token_hex(32)
        sessions[token] = {"username": req.username, "master_password": req.master_password, "is_locked": False}
        response.set_cookie(key="session_token", value=token, httponly=True)
        return {"message": "Registration successful"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/login")
def login(req: AuthRequest, response: Response):
    vh = get_vault_handler(req.username)
    if not vh.vault_exists():
        raise HTTPException(status_code=401, detail="Invalid username or password")
    try:
        vh.list_entries(req.master_password)
        token = secrets.token_hex(32)
        sessions[token] = {"username": req.username, "master_password": req.master_password, "is_locked": False}
        response.set_cookie(key="session_token", value=token, httponly=True)
        return {"message": "Login successful"}
    except (VaultCorrupted, WrongPassword):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get("session_token")
    if token in sessions:
        del sessions[token]
    response.delete_cookie("session_token")
    return {"message": "Logged out"}

# --- VAULT UNLOCK ROUTE ---
@router.post("/vault/unlock")
def unlock_vault(req: UnlockRequest, session: dict = Depends(get_session)):
    vh = get_vault_handler(session["username"])
    master_password = req.master_password
    
    if not vh.vault_exists():
        try:
            vh.init_vault(master_password)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Failed to init vault: {str(e)}")
    else:
        # Existing user, verify password
        try:
            vh.list_entries(master_password)
        except (VaultCorrupted, WrongPassword):
            raise HTTPException(status_code=401, detail="Invalid master password")
            
    session["master_password"] = master_password
    session["is_locked"] = False
    return {"message": "Vault unlocked"}

# --- VAULT OPERATIONS ---
@router.get("/session")
def get_current_session(session: dict = Depends(get_session)):
    return {
        "username": session["username"],
        "is_locked": session.get("is_locked", True)
    }

@router.post("/vault/check-strength")
def check_strength(req: StrengthRequest):
    if not req.password:
        return {"score": 0, "feedback": ""}
    result = zxcvbn.zxcvbn(req.password)
    warning = result.get("feedback", {}).get("warning", "")
    return {"score": result["score"], "feedback": warning}

from fastapi.responses import PlainTextResponse
@router.get("/vault/export", response_class=PlainTextResponse)
def export_vault(session: dict = Depends(get_session)):
    # Exporting only requires authentication, not the master password
    vh = get_vault_handler(session["username"])
    with SessionLocal() as db:
        vault = db.query(Vault).filter(Vault.username == vh.username).first()
        if not vault:
            raise HTTPException(status_code=404, detail="Vault not found")
        # Return as a plain text block
        return f"--- CIPHERVAULT ENCRYPTED EXPORT ---\nMAGIC:{vault.magic}\nSALT:{vault.salt}\nNONCE:{vault.nonce}\nCIPHERTEXT:{vault.ciphertext}\n------------------------------------"

@router.get("/entries")
def get_entries(session: dict = Depends(get_unlocked_session)):
    vh = get_vault_handler(session["username"])
    try:
        entries = vh.list_entries(session["master_password"])
        return [e.to_dict() for e in entries]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/entries")
def add_entry(entry: EntryModel, session: dict = Depends(get_unlocked_session)):
    vh = get_vault_handler(session["username"])
    new_entry = Entry.create(
        name=entry.name,
        username=entry.username,
        password=entry.password,
        notes=entry.notes
    )
    try:
        existing = vh.get_entry(session["master_password"], entry.name)
        if existing:
            raise HTTPException(status_code=400, detail="Entry with this name already exists")
        vh.add_entry(session["master_password"], new_entry)
        return {"message": "Entry added"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/entries/{name}")
def update_entry(name: str, entry: EntryModel, session: dict = Depends(get_unlocked_session)):
    vh = get_vault_handler(session["username"])
    new_entry = Entry.create(
        name=entry.name,
        username=entry.username,
        password=entry.password,
        notes=entry.notes
    )
    try:
        updated = vh.update_entry(session["master_password"], name, new_entry)
        if not updated:
            raise HTTPException(status_code=404, detail="Entry not found")
        return {"message": "Entry updated"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/entries/{name}")
def delete_entry(name: str, session: dict = Depends(get_unlocked_session)):
    vh = get_vault_handler(session["username"])
    try:
        deleted = vh.delete_entry(session["master_password"], name)
        if not deleted:
            raise HTTPException(status_code=404, detail="Entry not found")
        return {"message": "Entry deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
