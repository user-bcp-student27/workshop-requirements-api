from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import os
import sqlite3
import time
from pathlib import Path
from pathlib import PureWindowsPath
from typing import Any

import urllib3
from fastapi import Body, Depends, FastAPI, File, Header, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware

TOKEN_ISSUER = "workshop-auth-backend"
TOKEN_AUDIENCE = "workshop-requirements-api"
TOKEN_ALGORITHM = "HS256"
TOKEN_TTL_SECONDS = 3600
MIN_TOKEN_SECRET_BYTES = 32
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_UPLOAD_EXTENSIONS = {".txt", ".md", ".pdf"}


def _decode_token_segment(segment: str) -> bytes:
    if not segment:
        raise ValueError("empty token segment")
    padded = segment + "=" * (-len(segment) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)


def _verify_token(token: str, secret: str) -> dict[str, str]:
    if len(secret.encode("utf-8")) < MIN_TOKEN_SECRET_BYTES:
        raise RuntimeError("AUTH_TOKEN_SECRET must contain at least 32 bytes")

    segments = token.split(".")
    if len(segments) != 3:
        raise ValueError("invalid token structure")

    header = json.loads(_decode_token_segment(segments[0]))
    claims = json.loads(_decode_token_segment(segments[1]))
    if not isinstance(header, dict) or header.get("alg") != TOKEN_ALGORITHM or header.get("typ") != "JWT":
        raise ValueError("invalid token header")
    if not isinstance(claims, dict):
        raise ValueError("invalid token claims")

    signing_input = f"{segments[0]}.{segments[1]}".encode("ascii")
    expected_signature = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
    supplied_signature = _decode_token_segment(segments[2])
    if not hmac.compare_digest(expected_signature, supplied_signature):
        raise ValueError("invalid token signature")

    subject = claims.get("sub")
    role = claims.get("role")
    client = claims.get("client")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if not all(isinstance(value, str) and value for value in (subject, role, client)):
        raise ValueError("invalid token identity")
    if role not in {"STUDENT", "TRAINER"}:
        raise ValueError("invalid token role")
    if any(isinstance(value, bool) or not isinstance(value, int) for value in (issued_at, expires_at)):
        raise ValueError("invalid token timestamps")
    if claims.get("iss") != TOKEN_ISSUER or claims.get("aud") != TOKEN_AUDIENCE:
        raise ValueError("invalid token issuer or audience")

    now = int(time.time())
    if issued_at > now + 60 or expires_at <= now or expires_at <= issued_at:
        raise ValueError("expired or not-yet-valid token")
    if expires_at - issued_at > TOKEN_TTL_SECONDS:
        raise ValueError("token lifetime exceeds the allowed limit")

    return {"username": subject, "role": role}


def legacy_identity(authorization: str = Header(default="")) -> dict[str, str]:
    secret = os.getenv("AUTH_TOKEN_SECRET")
    if secret is None or len(secret.encode("utf-8")) < MIN_TOKEN_SECRET_BYTES:
        raise HTTPException(status_code=503, detail="Token validation is not configured")
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token")

    try:
        return _verify_token(authorization.removeprefix("Bearer "), secret)
    except (ValueError, TypeError, UnicodeError, binascii.Error) as error:
        raise HTTPException(status_code=401, detail="Invalid token") from error


def create_app(db_path: str | None = None, upload_dir: str | None = None) -> FastAPI:
    selected_db = db_path or os.getenv("WORKSHOP_DB_PATH", "./data/workshop.db")
    selected_uploads = upload_dir or os.getenv("WORKSHOP_UPLOAD_DIR", "./uploads")
    Path(selected_db).parent.mkdir(parents=True, exist_ok=True)
    Path(selected_uploads).mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(selected_db, check_same_thread=False)
    connection.row_factory = sqlite3.Row
    connection.execute("CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL, owner TEXT NOT NULL, priority TEXT NOT NULL, created_at TEXT NOT NULL)")
    count = connection.execute("SELECT COUNT(*) AS total FROM tasks").fetchone()["total"]
    if count == 0:
        connection.execute("INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES ('Refactor login','Separar responsabilidades en frontend','TODO','student','HIGH',datetime('now'))")
        connection.execute("INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES ('Review API','Revisar seguridad de endpoints','IN_PROGRESS','student','MEDIUM',datetime('now'))")
        connection.execute("INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES ('Trainer notes','Preparar retrospectiva','TODO','trainer','LOW',datetime('now'))")
        connection.commit()

    app = FastAPI(title="Workshop Requirements API", version="0.1.0")
    app.state.connection = connection
    app.state.upload_dir = selected_uploads
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    def as_task(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "title": row["title"],
            "description": row["description"],
            "status": row["status"],
            "owner": row["owner"],
            "priority": row["priority"],
            "createdAt": row["created_at"],
        }

    @app.get("/api/tasks")
    def list_tasks(owner: str | None = Query(default=None), identity: dict[str, str] = Depends(legacy_identity)) -> list[dict[str, Any]]:
        requested_owner = owner or identity["username"]
        if identity["role"] != "TRAINER" and requested_owner != identity["username"]:
            raise HTTPException(status_code=403, detail="Not authorized to access this owner")
        sql = "SELECT id,title,description,status,owner,priority,created_at FROM tasks WHERE owner=? ORDER BY id"
        rows = connection.execute(sql, (requested_owner,)).fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            result.append(as_task(row))
        return result

    @app.post("/api/tasks", status_code=201)
    def create_task(payload: dict[str, Any] = Body(...), identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        title = str(payload.get("title", ""))
        description = str(payload.get("description", ""))
        status = str(payload.get("status", "TODO"))
        priority = str(payload.get("priority", "MEDIUM"))
        owner = str(payload.get("owner", identity["username"]))
        if identity["role"] != "TRAINER" and owner != identity["username"]:
            raise HTTPException(status_code=403, detail="Not authorized to assign this owner")
        sql = "INSERT INTO tasks(title,description,status,owner,priority,created_at) VALUES (?, ?, ?, ?, ?, datetime('now'))"
        cursor = connection.execute(sql, (title, description, status, owner, priority))
        connection.commit()
        row = connection.execute(
            "SELECT id,title,description,status,owner,priority,created_at FROM tasks WHERE id=?",
            (cursor.lastrowid,),
        ).fetchone()
        return as_task(row)

    @app.get("/api/summary")
    def summary(owner: str | None = Query(default=None), identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        requested_owner = owner or identity["username"]
        if identity["role"] != "TRAINER" and requested_owner != identity["username"]:
            raise HTTPException(status_code=403, detail="Not authorized to access this owner")
        rows = connection.execute(
            "SELECT status,priority FROM tasks WHERE owner=?",
            (requested_owner,),
        ).fetchall()
        response: dict[str, Any] = {"owner": requested_owner, "total": 0, "byStatus": {}, "highPriorityOpen": 0}
        for row in rows:
            response["total"] = response["total"] + 1
            if row["status"] in response["byStatus"]:
                response["byStatus"][row["status"]] = response["byStatus"][row["status"]] + 1
            else:
                response["byStatus"][row["status"]] = 1
            if row["priority"] == "HIGH":
                if row["status"] != "DONE":
                    if row["status"] != "ARCHIVED":
                        response["highPriorityOpen"] = response["highPriorityOpen"] + 1
        return response

    @app.post("/api/requirements", status_code=201)
    async def upload_requirement(file: UploadFile = File(...), identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        filename = file.filename or ""
        if (
            not filename
            or filename in {".", ".."}
            or Path(filename).name != filename
            or PureWindowsPath(filename).drive
            or "/" in filename
            or "\\" in filename
        ):
            raise HTTPException(status_code=400, detail="Invalid file name")
        if Path(filename).suffix.lower() not in ALLOWED_UPLOAD_EXTENSIONS:
            raise HTTPException(status_code=415, detail="Unsupported file type")

        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="File exceeds the 10 MiB limit")

        upload_root = Path(selected_uploads).resolve()
        target = Path(selected_uploads) / filename
        resolved_target = target.resolve()
        try:
            resolved_target.relative_to(upload_root)
        except ValueError as error:
            raise HTTPException(status_code=400, detail="Invalid file path") from error
        resolved_target.write_bytes(content)
        return {"owner": identity["username"], "fileName": file.filename, "storedAt": str(target), "size": len(content)}

    @app.get("/api/backend-health")
    def backend_health(identity: dict[str, str] = Depends(legacy_identity)) -> dict[str, Any]:
        url = os.getenv("AUTH_HEALTH_URL", "http://localhost:8080/q/health")
        try:
            response = urllib3.PoolManager().request("GET", url, timeout=3.0)
            return {"requestedBy": identity["username"], "status": response.status, "body": response.data.decode("utf-8")}
        except Exception as error:
            return {"requestedBy": identity["username"], "status": 0, "body": str(error)}

    @app.on_event("shutdown")
    def close_connection() -> None:
        connection.close()

    return app


app = create_app()
