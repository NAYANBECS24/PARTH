from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from backend.database import transaction, utcnow
from backend.repository import identifier


PBKDF2_ITERATIONS = 600_000
SESSION_HOURS = 12
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{3,40}$")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, encoded: str) -> bool:
    try:
        algorithm, iterations, salt, expected = encoded.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), _decode(salt), int(iterations))
        return secrets.compare_digest(actual, _decode(expected))
    except (TypeError, ValueError):
        return False


def validate_credentials(username: str, password: str) -> None:
    if not USERNAME_PATTERN.fullmatch(username):
        raise ValueError("Username must be 3–40 characters using letters, numbers, dot, dash, or underscore")
    if len(password) < 12 or len(password) > 256:
        raise ValueError("Password must be between 12 and 256 characters")


def bootstrap_required() -> bool:
    with transaction() as connection:
        return connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is None


def bootstrap_admin(username: str, password: str) -> tuple[str, dict[str, Any]]:
    validate_credentials(username, password)
    with transaction() as connection:
        if connection.execute("SELECT 1 FROM users LIMIT 1").fetchone():
            raise ValueError("Initial administrator already exists")
        user_id = identifier("user")
        connection.execute(
            "INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
            (user_id, username, hash_password(password), utcnow()),
        )
    return create_session(user_id), {"id": user_id, "username": username, "role": "admin"}


def login(username: str, password: str) -> tuple[str, dict[str, Any]] | None:
    with transaction() as connection:
        row = connection.execute(
            "SELECT id, username, password_hash, role, disabled FROM users WHERE username = ? COLLATE NOCASE",
            (username,),
        ).fetchone()
    if not row or row["disabled"] or not verify_password(password, row["password_hash"]):
        return None
    user = {"id": row["id"], "username": row["username"], "role": row["role"]}
    return create_session(row["id"]), user


def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
    now = datetime.now(UTC).replace(microsecond=0)
    expires = now + timedelta(hours=SESSION_HOURS)
    with transaction() as connection:
        connection.execute("DELETE FROM sessions WHERE expires_at <= ?", (now.isoformat(),))
        connection.execute(
            "INSERT INTO sessions (id, user_id, token_hash, expires_at, created_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?)",
            (identifier("session"), user_id, token_hash, expires.isoformat(), now.isoformat(), now.isoformat()),
        )
    return token


def user_for_token(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
    now = utcnow()
    with transaction() as connection:
        row = connection.execute(
            """SELECT users.id, users.username, users.role, sessions.id AS session_id
               FROM sessions JOIN users ON users.id = sessions.user_id
               WHERE sessions.token_hash = ? AND sessions.expires_at > ? AND users.disabled = 0""",
            (token_hash, now),
        ).fetchone()
        if row:
            connection.execute("UPDATE sessions SET last_seen_at = ? WHERE id = ?", (now, row["session_id"]))
    return {"id": row["id"], "username": row["username"], "role": row["role"]} if row else None


def revoke_session(token: str) -> None:
    token_hash = hashlib.sha256(token.encode("ascii", errors="ignore")).hexdigest()
    with transaction() as connection:
        connection.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash,))


def bearer_token(value: str | None) -> str | None:
    if not value or not value.startswith("Bearer "):
        return None
    token = value[7:].strip()
    return token or None


def audit(user_id: str | None, action: str, subject_type: str, subject_id: str | None = None, detail: dict[str, Any] | None = None) -> None:
    with transaction() as connection:
        connection.execute(
            "INSERT INTO audit_events (user_id, action, subject_type, subject_id, detail_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, action, subject_type, subject_id, json.dumps(detail or {}, sort_keys=True), utcnow()),
        )
