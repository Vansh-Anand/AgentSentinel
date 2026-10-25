"""Local bearer-session document storage. Content is never interpreted as a path."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone

MAX_DOCUMENT_BYTES = 16_384
MAX_DOCUMENTS = 16
MAX_SESSION_BYTES = 131_072
MAX_GLOBAL_BYTES = 8_388_608


class DocumentError(ValueError):
    pass


class DocumentStore:
    def __init__(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        self.database = root / "documents.sqlite"
        with self.connect() as conn:
            conn.execute("""CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY, owner TEXT NOT NULL, name TEXT NOT NULL,
                content BLOB NOT NULL, sha256 TEXT NOT NULL, created TEXT NOT NULL)""")

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.database, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    @staticmethod
    def metadata(row):
        return {"id": row["id"], "name": row["name"], "bytes": len(row["content"]),
                "sha256": row["sha256"], "created": row["created"],
                "source_id": "SRC-" + row["id"].upper()}

    def upload(self, owner: str, name: str, content: str):
        if (not re.fullmatch(r"[^\\/:\x00-\x1f]{1,100}\.(txt|md|csv)", name, re.I)
                or name.startswith(".") or name.endswith(" ")):
            raise DocumentError("Use a simple .txt, .md or .csv filename; paths are not accepted.")
        data = content.encode("utf-8")
        if not data.strip() or len(data) > MAX_DOCUMENT_BYTES or "\x00" in content:
            raise DocumentError("Document must be nonempty UTF-8 text, at most 16 KiB, without NUL bytes.")
        identifier = uuid.uuid4().hex
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            count, size = conn.execute("SELECT COUNT(*),COALESCE(SUM(length(content)),0) FROM documents WHERE owner=?", (owner,)).fetchone()
            total = conn.execute("SELECT COALESCE(SUM(length(content)),0) FROM documents").fetchone()[0]
            if count >= MAX_DOCUMENTS or size + len(data) > MAX_SESSION_BYTES or total + len(data) > MAX_GLOBAL_BYTES:
                raise DocumentError("Document storage quota reached. Delete unused documents.")
            conn.execute("INSERT INTO documents VALUES (?,?,?,?,?,?)", (identifier, owner, name, data,
                hashlib.sha256(data).hexdigest(), datetime.now(timezone.utc).isoformat()))
            row = conn.execute("SELECT * FROM documents WHERE id=?", (identifier,)).fetchone()
        return self.metadata(row)

    def list(self, owner: str):
        with self.connect() as conn:
            return [self.metadata(row) for row in conn.execute("SELECT * FROM documents WHERE owner=? ORDER BY created DESC", (owner,))]

    def selected(self, owner: str, identifiers: list[str]):
        if len(identifiers) > MAX_DOCUMENTS or len(set(identifiers)) != len(identifiers):
            raise DocumentError("Select at most 16 distinct documents.")
        result = []
        with self.connect() as conn:
            for identifier in identifiers:
                if not re.fullmatch(r"[a-f0-9]{32}", identifier):
                    raise DocumentError("Document not found in this session.")
                row = conn.execute("SELECT * FROM documents WHERE owner=? AND id=?", (owner, identifier)).fetchone()
                if row is None:
                    raise DocumentError("Document not found in this session.")
                result.append((self.metadata(row), bytes(row["content"])))
        return result

    def delete(self, owner: str, identifier: str):
        with self.connect() as conn:
            if conn.execute("DELETE FROM documents WHERE owner=? AND id=?", (owner, identifier)).rowcount != 1:
                raise DocumentError("Document not found in this session.")


def snapshot(selected: list, directory: Path) -> dict:
    directory.mkdir(parents=True, exist_ok=False)
    catalog = {}
    for metadata, data in selected:
        identifier = metadata["id"]
        (directory / identifier).write_bytes(data)
        catalog[identifier] = {**metadata, "classification": "USER_UPLOADED_UNTRUSTED"}
    return catalog
