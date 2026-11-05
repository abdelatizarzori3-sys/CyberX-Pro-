from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parents[2]
STATIC_DIR = BASE_DIR / "frontend"
DB_PATH = Path(os.getenv("CYBERX_DB_PATH", str(BASE_DIR / "cyberx.db")))
SESSION_HOURS = max(1, int(os.getenv("CYBERX_SESSION_HOURS", "12")))


def now() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None = None) -> str:
    return (value or now()).isoformat()


@contextmanager
def db() -> Iterator[sqlite3.Connection]:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=15)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS organizations (
            id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
            email TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS assets (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
            name TEXT NOT NULL, asset_type TEXT NOT NULL, identifier TEXT NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS authorizations (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
            asset_id TEXT NOT NULL REFERENCES assets(id), approved_by TEXT NOT NULL,
            scope_note TEXT NOT NULL, starts_at TEXT NOT NULL, expires_at TEXT NOT NULL,
            revoked_at TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
            asset_id TEXT NOT NULL REFERENCES assets(id), authorization_id TEXT NOT NULL REFERENCES authorizations(id),
            status TEXT NOT NULL, created_by TEXT NOT NULL REFERENCES users(id), created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES organizations(id),
            user_id TEXT NOT NULL REFERENCES users(id), action TEXT NOT NULL,
            details TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(organization_id);
        CREATE INDEX IF NOT EXISTS idx_auth_org_asset ON authorizations(organization_id, asset_id);
        CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(organization_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_org ON audit_logs(organization_id, created_at);
        """)


def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
    return f"{salt.hex()}:{derived.hex()}"


def password_matches(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split(":", 1)
        return hmac.compare_digest(password_hash(password, bytes.fromhex(salt_hex)), f"{salt_hex}:{digest_hex}")
    except (ValueError, TypeError):
        return False


def audit(conn: sqlite3.Connection, org_id: str, user_id: str, action: str, details: str) -> None:
    conn.execute("INSERT INTO audit_logs VALUES (?, ?, ?, ?, ?, ?)",
                 (str(uuid4()), org_id, user_id, action, details[:500], iso()))


class RegisterInput(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=12, max_length=128)
    organization_name: str = Field(min_length=2, max_length=100)


class LoginInput(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=1, max_length=128)


class AssetInput(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    asset_type: str = Field(pattern="^(domain|ip|application|other)$")
    identifier: str = Field(min_length=1, max_length=253)


class AuthorizationInput(BaseModel):
    asset_id: str
    scope_note: str = Field(min_length=10, max_length=1000)
    starts_at: datetime
    expires_at: datetime
    attested: bool


class ScanInput(BaseModel):
    asset_id: str


app = FastAPI(title="CyberX Pro", version="1.0.0", description="MVP آمن لإدارة الأصول والتفويض ومهام التقييم المحلية.")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.on_event("startup")
def startup() -> None:
    init_db()


@app.get("/", include_in_schema=False)
def home() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


def current_user(authorization: str | None = Header(default=None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="يلزم تسجيل الدخول")
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        raise HTTPException(status_code=401, detail="جلسة غير صالحة")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as conn:
        row = conn.execute("""SELECT u.id, u.email, u.organization_id, o.name AS organization_name, s.expires_at
            FROM sessions s JOIN users u ON u.id=s.user_id JOIN organizations o ON o.id=u.organization_id
            WHERE s.token_hash=?""", (token_hash,)).fetchone()
        if not row or datetime.fromisoformat(row["expires_at"]) <= now():
            if row:
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            raise HTTPException(status_code=401, detail="انتهت الجلسة أو أنها غير صالحة")
        return dict(row)


@app.post("/api/v1/auth/register", status_code=201)
def register(data: RegisterInput):
    email = data.email.strip().lower()
    if "@" not in email:
        raise HTTPException(422, "بريد إلكتروني غير صالح")
    org_id, user_id = str(uuid4()), str(uuid4())
    token = secrets.token_urlsafe(36)
    expiry = now() + timedelta(hours=SESSION_HOURS)
    with db() as conn:
        if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "هذا البريد مسجل بالفعل")
        conn.execute("INSERT INTO organizations VALUES (?, ?, ?)", (org_id, data.organization_name.strip(), iso()))
        conn.execute("INSERT INTO users VALUES (?, ?, ?, ?, ?)",
                     (user_id, org_id, email, password_hash(data.password), iso()))
        conn.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                     (hashlib.sha256(token.encode()).hexdigest(), user_id, expiry.isoformat(), iso()))
        audit(conn, org_id, user_id, "account.registered", "إنشاء المؤسسة والحساب")
    return {"access_token": token, "token_type": "bearer", "expires_at": expiry.isoformat(),
            "user": {"id": user_id, "email": email, "organization_id": org_id, "organization_name": data.organization_name.strip()}}


@app.post("/api/v1/auth/login")
def login(data: LoginInput):
    email = data.email.strip().lower()
    with db() as conn:
        row = conn.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row or not password_matches(data.password, row["password_hash"]):
            raise HTTPException(401, "البريد أو كلمة المرور غير صحيحة")
        token = secrets.token_urlsafe(36)
        expiry = now() + timedelta(hours=SESSION_HOURS)
        conn.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                     (hashlib.sha256(token.encode()).hexdigest(), row["id"], expiry.isoformat(), iso()))
        audit(conn, row["organization_id"], row["id"], "auth.login", "تسجيل الدخول")
        return {"access_token": token, "token_type": "bearer", "expires_at": expiry.isoformat(),
                "user": {"id": row["id"], "email": email, "organization_id": row["organization_id"]}}


@app.post("/api/v1/auth/logout")
def logout(user: dict = Depends(current_user), authorization: str = Header()):
    token = authorization.split(" ", 1)[1].strip()
    with db() as conn:
        conn.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
        audit(conn, user["organization_id"], user["id"], "auth.logout", "تسجيل الخروج")
    return {"ok": True}


@app.get("/api/v1/me")
def me(user: dict = Depends(current_user)):
    return {key: user[key] for key in ("id", "email", "organization_id", "organization_name")}


@app.get("/api/v1/assets")
def list_assets(user: dict = Depends(current_user)):
    with db() as conn:
        return [dict(row) for row in conn.execute("SELECT * FROM assets WHERE organization_id=? ORDER BY created_at DESC", (user["organization_id"],))]


@app.post("/api/v1/assets", status_code=201)
def create_asset(data: AssetInput, user: dict = Depends(current_user)):
    asset_id = str(uuid4())
    with db() as conn:
        conn.execute("INSERT INTO assets VALUES (?, ?, ?, ?, ?, ?)",
                     (asset_id, user["organization_id"], data.name.strip(), data.asset_type, data.identifier.strip(), iso()))
        audit(conn, user["organization_id"], user["id"], "asset.created", asset_id)
        return dict(conn.execute("SELECT * FROM assets WHERE id=?", (asset_id,)).fetchone())


@app.get("/api/v1/authorizations")
def list_authorizations(user: dict = Depends(current_user)):
    with db() as conn:
        return [dict(row) for row in conn.execute("""SELECT a.*, x.name AS asset_name FROM authorizations a
            JOIN assets x ON x.id=a.asset_id WHERE a.organization_id=? ORDER BY a.created_at DESC""", (user["organization_id"],))]


@app.post("/api/v1/authorizations", status_code=201)
def create_authorization(data: AuthorizationInput, user: dict = Depends(current_user)):
    start = data.starts_at if data.starts_at.tzinfo else data.starts_at.replace(tzinfo=timezone.utc)
    end = data.expires_at if data.expires_at.tzinfo else data.expires_at.replace(tzinfo=timezone.utc)
    if not data.attested:
        raise HTTPException(400, "يجب تأكيد وجود تفويض موثق قبل التسجيل")
    if end <= start or end <= now():
        raise HTTPException(400, "مدة التفويض غير صالحة أو منتهية")
    auth_id = str(uuid4())
    with db() as conn:
        asset = conn.execute("SELECT id FROM assets WHERE id=? AND organization_id=?", (data.asset_id, user["organization_id"])).fetchone()
        if not asset:
            raise HTTPException(404, "الأصل غير موجود في مؤسستك")
        conn.execute("INSERT INTO authorizations VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?)",
                     (auth_id, user["organization_id"], data.asset_id, user["id"], data.scope_note.strip(), start.isoformat(), end.isoformat(), iso()))
        audit(conn, user["organization_id"], user["id"], "authorization.created", auth_id)
        return dict(conn.execute("SELECT * FROM authorizations WHERE id=?", (auth_id,)).fetchone())


@app.post("/api/v1/authorizations/{authorization_id}/revoke")
def revoke_authorization(authorization_id: str, user: dict = Depends(current_user)):
    with db() as conn:
        row = conn.execute("SELECT id FROM authorizations WHERE id=? AND organization_id=? AND revoked_at IS NULL", (authorization_id, user["organization_id"])).fetchone()
        if not row:
            raise HTTPException(404, "تفويض غير موجود أو ملغى")
        conn.execute("UPDATE authorizations SET revoked_at=? WHERE id=?", (iso(), authorization_id))
        audit(conn, user["organization_id"], user["id"], "authorization.revoked", authorization_id)
    return {"ok": True}


@app.get("/api/v1/scans")
def list_scans(user: dict = Depends(current_user)):
    with db() as conn:
        return [dict(row) for row in conn.execute("""SELECT s.*, a.name AS asset_name, a.identifier FROM scans s
            JOIN assets a ON a.id=s.asset_id WHERE s.organization_id=? ORDER BY s.created_at DESC""", (user["organization_id"],))]


@app.post("/api/v1/scans", status_code=201)
def create_scan(data: ScanInput, user: dict = Depends(current_user)):
    current = now()
    with db() as conn:
        asset = conn.execute("SELECT id FROM assets WHERE id=? AND organization_id=?", (data.asset_id, user["organization_id"])).fetchone()
        if not asset:
            raise HTTPException(404, "الأصل غير موجود في مؤسستك")
        auth = conn.execute("""SELECT id FROM authorizations WHERE asset_id=? AND organization_id=?
            AND revoked_at IS NULL AND starts_at<=? AND expires_at>? ORDER BY created_at DESC LIMIT 1""",
            (data.asset_id, user["organization_id"], current.isoformat(), current.isoformat())).fetchone()
        if not auth:
            audit(conn, user["organization_id"], user["id"], "scan.blocked", data.asset_id)
            raise HTTPException(403, "لا يمكن إنشاء المهمة: لا يوجد تفويض سارٍ لهذا الأصل")
        scan_id = str(uuid4())
        # Deliberately metadata-only: no network requests or target-side operations are performed.
        conn.execute("INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (scan_id, user["organization_id"], data.asset_id, auth["id"], "COMPLETED", user["id"], iso()))
        audit(conn, user["organization_id"], user["id"], "scan.recorded", scan_id)
        return {"id": scan_id, "asset_id": data.asset_id, "authorization_id": auth["id"], "status": "COMPLETED",
                "message": "تم تسجيل المهمة محلياً. لم يتم إرسال أي اتصال إلى الأصل."}


@app.get("/api/v1/audit-logs")
def list_audit(user: dict = Depends(current_user)):
    with db() as conn:
        return [dict(row) for row in conn.execute("SELECT action, details, created_at FROM audit_logs WHERE organization_id=? ORDER BY created_at DESC LIMIT 100", (user["organization_id"],))]


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "service": "cyberx-pro-mvp"}
