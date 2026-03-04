import base64
import hashlib
import hmac
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except ValueError:
        return default


@dataclass
class AuthUser:
    username: str
    email: str
    webid: str


class AuthStore:
    def __init__(self):
        self.db_path = os.environ.get("AUTH_DB_PATH", "/app/storage/auth.db")
        self.webid_base = os.environ.get("AUTH_WEBID_BASE", "https://local.example/users")
        self.secret = os.environ.get("AUTH_SECRET", "change-me-auth-secret")
        self.token_ttl_minutes = _env_int("AUTH_TOKEN_TTL_MINUTES", 1440)
        self._ensure_db()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _ensure_db(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def _hash_password(self, password: str, salt: bytes) -> str:
        hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
        return base64.b64encode(hashed).decode("utf-8")

    def _make_webid(self, username: str) -> str:
        return f"{self.webid_base}/{username}#me"

    def _validate_password(self, password: str) -> None:
        if len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(ch.islower() for ch in password):
            raise ValueError("Password must include a lowercase letter")
        if not any(ch.isupper() for ch in password):
            raise ValueError("Password must include an uppercase letter")
        if not any(ch.isdigit() for ch in password):
            raise ValueError("Password must include a number")
        if not any(not ch.isalnum() for ch in password):
            raise ValueError("Password must include a special character")

    def create_user(self, username: str, email: str, password: str) -> AuthUser:
        username_clean = username.strip().lower()
        email_clean = email.strip().lower()
        if len(username_clean) < 3:
            raise ValueError("Username must be at least 3 characters")
        if "@" not in email_clean:
            raise ValueError("Email format is invalid")
        self._validate_password(password)

        salt = os.urandom(16)
        password_hash = self._hash_password(password, salt)
        salt_b64 = base64.b64encode(salt).decode("utf-8")

        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO users (username, email, password_hash, salt, created_at) VALUES (?, ?, ?, ?, ?)",
                    (username_clean, email_clean, password_hash, salt_b64, datetime.now(timezone.utc).isoformat()),
                )
                conn.commit()
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username or email already exists") from exc

        return AuthUser(username=username_clean, email=email_clean, webid=self._make_webid(username_clean))

    def authenticate(self, username: str, password: str) -> AuthUser | None:
        username_clean = username.strip().lower()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT username, email, password_hash, salt FROM users WHERE username = ?",
                (username_clean,),
            ).fetchone()

        if not row:
            return None

        stored_username, stored_email, stored_hash, stored_salt = row
        calc_hash = self._hash_password(password, base64.b64decode(stored_salt.encode("utf-8")))
        if not hmac.compare_digest(calc_hash, stored_hash):
            return None

        return AuthUser(username=stored_username, email=stored_email, webid=self._make_webid(stored_username))

    def issue_token(self, user: AuthUser) -> str:
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user.username,
            "email": user.email,
            "webid": user.webid,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=self.token_ttl_minutes)).timestamp()),
        }
        return jwt.encode(payload, self.secret, algorithm="HS256")

    def parse_token(self, token: str) -> AuthUser | None:
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return None

        username = payload.get("sub")
        email = payload.get("email")
        webid = payload.get("webid")
        if not username or not email or not webid:
            return None

        return AuthUser(username=username, email=email, webid=webid)
