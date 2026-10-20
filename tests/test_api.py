import base64
import hashlib
import hmac
import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

TEST_SECRET = "test-only-secret-with-at-least-32-bytes"
TOKEN_ISSUER = "workshop-auth-backend"
TOKEN_AUDIENCE = "workshop-requirements-api"


def _encode_segment(value: dict[str, object]) -> str:
    encoded = base64.urlsafe_b64encode(json.dumps(value, separators=(",", ":")).encode())
    return encoded.decode().rstrip("=")


def token(
    username: str = "student",
    role: str = "STUDENT",
    *,
    issued_at: int | None = None,
    expires_at: int | None = None,
    issuer: str = TOKEN_ISSUER,
    audience: str = TOKEN_AUDIENCE,
) -> str:
    now = int(time.time())
    header = _encode_segment({"alg": "HS256", "typ": "JWT"})
    claims = _encode_segment({
        "iss": issuer,
        "aud": audience,
        "sub": username,
        "role": role,
        "client": "angular-workshop",
        "iat": issued_at if issued_at is not None else now,
        "exp": expires_at if expires_at is not None else now + 3600,
    })
    signing_input = f"{header}.{claims}"
    signature = hmac.new(TEST_SECRET.encode(), signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{base64.urlsafe_b64encode(signature).decode().rstrip('=')}"


def headers(username: str = "student", role: str = "STUDENT") -> dict[str, str]:
    return {"Authorization": f"Bearer {token(username, role)}"}


def headers_with_token(value: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {value}"}


@pytest.fixture(autouse=True)
def configure_test_token_secret(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AUTH_TOKEN_SECRET", TEST_SECRET)


def test_lists_seeded_tasks(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers=headers())
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_creates_task_and_summary(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        created = client.post(
            "/api/tasks",
            headers=headers(),
            json={"title": "Add tests", "description": "Improve coverage", "status": "TODO", "priority": "HIGH"},
        )
        summary = client.get("/api/summary", headers=headers())
    assert created.status_code == 201
    assert created.json()["owner"] == "student"
    assert summary.json()["total"] == 3


def test_uploads_requirement(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    app = create_app(str(tmp_path / "workshop.db"), str(upload_dir))
    with TestClient(app) as client:
        response = client.post(
            "/api/requirements",
            headers=headers(),
            files={"file": ("requirements.txt", b"Login must be accessible", "text/plain")},
        )
    assert response.status_code == 201
    assert response.json()["fileName"] == "requirements.txt"
    assert (upload_dir / "requirements.txt").exists()


def test_rejects_invalid_token(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers=headers_with_token("invalid"))
    assert response.status_code == 401


def test_rejects_tampered_signature(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    header, claims, _ = token().split(".")
    changed_claims = _encode_segment({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": "trainer",
        "role": "TRAINER",
        "client": "angular-workshop",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    })
    tampered = f"{header}.{changed_claims}.{token().split('.')[2]}"
    assert claims != changed_claims
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers=headers_with_token(tampered))
    assert response.status_code == 401


def test_rejects_wrong_issuer_and_expired_tokens(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        wrong_issuer = client.get("/api/tasks", headers=headers_with_token(token(issuer="other-issuer")))
        expired = client.get(
            "/api/tasks",
            headers=headers_with_token(token(expires_at=int(time.time()) - 1)),
        )
    assert wrong_issuer.status_code == 401
    assert expired.status_code == 401


def test_missing_token_secret_fails_closed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AUTH_TOKEN_SECRET")
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.get("/api/tasks", headers=headers())
    assert response.status_code == 503


def test_student_cannot_read_or_assign_another_owner(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        listing = client.get("/api/tasks?owner=trainer", headers=headers())
        summary = client.get("/api/summary?owner=trainer", headers=headers())
        created = client.post(
            "/api/tasks",
            headers=headers(),
            json={"title": "Not allowed", "description": "Ownership boundary", "owner": "trainer"},
        )
    assert listing.status_code == 403
    assert summary.status_code == 403
    assert created.status_code == 403


def test_trainer_can_access_and_assign_another_owner(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        listing = client.get("/api/tasks?owner=student", headers=headers("trainer", "TRAINER"))
        created = client.post(
            "/api/tasks",
            headers=headers("trainer", "TRAINER"),
            json={"title": "Trainer task", "description": "Assigned task", "owner": "student"},
        )
    assert listing.status_code == 200
    assert len(listing.json()) == 2
    assert created.status_code == 201
    assert created.json()["owner"] == "student"


def test_task_values_with_quotes_are_stored_as_literals(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        created = client.post(
            "/api/tasks",
            headers=headers(),
            json={"title": "Owner's task", "description": "A user's requirement"},
        )
        listing = client.get("/api/tasks", headers=headers())
    assert created.status_code == 201
    assert created.json()["title"] == "Owner's task"
    assert any(task["description"] == "A user's requirement" for task in listing.json())


def test_rejects_upload_path_and_extension_outside_policy(tmp_path: Path) -> None:
    upload_dir = tmp_path / "uploads"
    app = create_app(str(tmp_path / "workshop.db"), str(upload_dir))
    with TestClient(app) as client:
        path = client.post(
            "/api/requirements",
            headers=headers(),
            files={"file": ("../outside.txt", b"content", "text/plain")},
        )
        extension = client.post(
            "/api/requirements",
            headers=headers(),
            files={"file": ("requirements.exe", b"content", "application/octet-stream")},
        )
    assert path.status_code == 400
    assert extension.status_code == 415
    assert not (tmp_path / "outside.txt").exists()


def test_rejects_upload_over_10_mib(tmp_path: Path) -> None:
    app = create_app(str(tmp_path / "workshop.db"), str(tmp_path / "uploads"))
    with TestClient(app) as client:
        response = client.post(
            "/api/requirements",
            headers=headers(),
            files={"file": ("large.txt", b"x" * (10 * 1024 * 1024 + 1), "text/plain")},
        )
    assert response.status_code == 413
