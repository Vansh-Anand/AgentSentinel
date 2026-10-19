"""Short-lived, server-issued capabilities for the local external-agent bridge.

The bearer capability grants access only to disposable synthetic lab actions.
It is not public-user authentication or a claim about the Flowise process.
"""
from __future__ import annotations

import base64
from contextlib import closing
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path

from .evidence import load_or_create_key


ROLES = {
    "reader": {"profile": "read_only", "tools": ["read_file", "search_documents", "calculate"]},
    "incident_analyst": {"profile": "balanced", "tools": ["read_file", "search_documents", "calculate", "create_report", "create_ticket"]},
    "ticket_reviewer": {"profile": "approval", "tools": ["read_file", "search_documents", "calculate", "create_report", "create_ticket"]},
}
AUDIENCE = "agentsentinel-local-adapter-v1"
MAX_LIFETIME_SECONDS = 600


class CapabilityError(ValueError):
    pass


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


class CapabilityIssuer:
    def __init__(self, root: Path):
        self.root = root
        self.key = load_or_create_key(root / "adapter.key")
        self.database = root / "runs.sqlite"
        with closing(sqlite3.connect(self.database)) as conn, conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS adapter_capabilities (
                nonce TEXT PRIMARY KEY, owner TEXT NOT NULL, expires INTEGER NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0)""")

    def issue(self, owner: str, role: str, lifetime_seconds: int = 300) -> dict:
        if role not in ROLES or not 1 <= lifetime_seconds <= MAX_LIFETIME_SECONDS:
            raise CapabilityError("INVALID_CAPABILITY_SCOPE")
        now = int(time.time())
        nonce = secrets.token_hex(16)
        scope = ROLES[role]
        claims = {"version": 1, "audience": AUDIENCE, "subject": owner,
                  "role": role, "profile": scope["profile"], "tools": scope["tools"],
                  "issued_at": now, "expires_at": now + lifetime_seconds,
                  "nonce": nonce, "policy_version": 2}
        payload = _b64(json.dumps(claims, sort_keys=True, separators=(",", ":")).encode())
        signature = _b64(hmac.new(self.key, payload.encode(), hashlib.sha256).digest())
        with closing(sqlite3.connect(self.database, timeout=10)) as conn, conn:
            conn.execute("INSERT INTO adapter_capabilities VALUES (?,?,?,0)",
                         (nonce, owner, claims["expires_at"]))
        return {"token": f"{payload}.{signature}", "role": role,
                "profile": scope["profile"], "tools": scope["tools"],
                "expires_at": claims["expires_at"], "nonce": nonce}

    def verify(self, token: str) -> dict:
        try:
            payload, signature = token.split(".")
            if len(token) > 2500 or not hmac.compare_digest(
                _b64(hmac.new(self.key, payload.encode(), hashlib.sha256).digest()), signature
            ):
                raise CapabilityError("INVALID_CAPABILITY")
            claims = json.loads(_decode(payload))
            role = claims["role"]
            if (claims["version"] != 1 or claims["audience"] != AUDIENCE
                    or claims["policy_version"] != 2 or role not in ROLES
                    or claims["profile"] != ROLES[role]["profile"]
                    or claims["tools"] != ROLES[role]["tools"]
                    or not isinstance(claims["subject"], str)
                    or len(claims["subject"]) != 64
                    or not isinstance(claims["nonce"], str)
                    or not isinstance(claims["issued_at"], int)
                    or not isinstance(claims["expires_at"], int)
                    or claims["expires_at"] <= int(time.time())
                    or claims["expires_at"] - claims["issued_at"] > MAX_LIFETIME_SECONDS):
                raise CapabilityError("INVALID_OR_EXPIRED_CAPABILITY")
            with closing(sqlite3.connect(self.database, timeout=10)) as conn, conn:
                row = conn.execute("SELECT owner,expires,revoked FROM adapter_capabilities WHERE nonce=?",
                                   (claims["nonce"],)).fetchone()
            if row is None or row != (claims["subject"], claims["expires_at"], 0):
                raise CapabilityError("REVOKED_OR_UNKNOWN_CAPABILITY")
            return claims
        except (ValueError, KeyError, TypeError, UnicodeError, base64.binascii.Error) as exc:
            if isinstance(exc, CapabilityError):
                raise
            raise CapabilityError("INVALID_CAPABILITY") from None

    def revoke(self, owner: str, nonce: str) -> bool:
        with closing(sqlite3.connect(self.database, timeout=10)) as conn, conn:
            cursor = conn.execute("UPDATE adapter_capabilities SET revoked=1 WHERE owner=? AND nonce=? AND revoked=0",
                                  (owner, nonce))
        return cursor.rowcount == 1
