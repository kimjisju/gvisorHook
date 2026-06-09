from __future__ import annotations

import base64
import hashlib
import json
import secrets
import sqlite3
import threading
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 200_000)
    return "pbkdf2_sha256$200000${}${}".format(
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def _verify_password(password: str, stored: str) -> bool:
    try:
        algorithm, iterations, salt_b64, digest_b64 = stored.split("$", 3)
        if algorithm != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected = base64.b64decode(digest_b64.encode("ascii"))
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, int(iterations))
        return secrets.compare_digest(actual, expected)
    except Exception:
        return False


class AppDatabase:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._migrate()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    is_verified INTEGER NOT NULL DEFAULT 0,
                    verification_token TEXT UNIQUE,
                    verification_token_expires TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS sessions (
                    token TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS guard_runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    agent_name TEXT NOT NULL,
                    user_prompt TEXT NOT NULL,
                    ai_agent_reasoning TEXT,
                    rule_base_result TEXT,
                    rule_base_reason TEXT,
                    guard_llm_result TEXT,
                    guard_llm_reason TEXT,
                    final_decision TEXT NOT NULL,
                    approval_status TEXT NOT NULL DEFAULT 'pending',
                    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
                    approved_at TEXT,
                    created_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS guard_actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_id INTEGER NOT NULL REFERENCES guard_runs(id) ON DELETE CASCADE,
                    action_order INTEGER NOT NULL,
                    agent_name TEXT,
                    event_id TEXT,
                    created_at TEXT,
                    syscall TEXT,
                    path TEXT,
                    argv TEXT,
                    raw_summary TEXT,
                    summary TEXT,
                    meaning TEXT,
                    normalized_action TEXT,
                    target_class TEXT,
                    rule_result TEXT
                );
                """
            )
            self._conn.commit()

    def signup(self, *, name: str, email: str, password: str) -> dict[str, Any]:
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        with self._lock:
            try:
                cursor = self._conn.execute(
                    """
                    INSERT INTO users
                    (name, email, password_hash, is_verified, verification_token, verification_token_expires, created_at)
                    VALUES (?, ?, ?, 0, ?, ?, ?)
                    """,
                    (name, email, _hash_password(password), token, expires, utc_now()),
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("이미 가입된 이메일입니다.") from exc
            self._conn.commit()
            return {"id": cursor.lastrowid, "name": name, "email": email, "verification_token": token}

    def verify_email(self, token: str) -> dict[str, Any] | None:
        now = utc_now()
        with self._lock:
            row = self._conn.execute(
                """
                SELECT * FROM users
                WHERE verification_token = ?
                AND verification_token_expires > ?
                """,
                (token, now),
            ).fetchone()
            if row is None:
                return None
            self._conn.execute(
                """
                UPDATE users
                SET is_verified = 1,
                    verification_token = NULL,
                    verification_token_expires = NULL
                WHERE id = ?
                """,
                (row["id"],),
            )
            self._conn.commit()
            return self._user_dict(row)

    def login(self, *, email: str, password: str) -> dict[str, Any]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if row is None or not _verify_password(password, row["password_hash"]):
                raise PermissionError("이메일 또는 비밀번호가 틀렸습니다.")
            if not row["is_verified"]:
                raise RuntimeError("이메일 인증 후 로그인할 수 있습니다.")
            token = secrets.token_urlsafe(32)
            expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
            self._conn.execute(
                "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                (token, row["id"], utc_now(), expires),
            )
            self._conn.commit()
            return {"token": token, "user": self._user_dict(row)}

    def create_guard_run(self, payload: dict[str, Any]) -> dict[str, Any]:
        actions = payload.get("actions") or []
        if not isinstance(actions, list):
            raise ValueError("actions must be an array")
        now = utc_now()
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO guard_runs
                (
                    user_id, agent_name, user_prompt, ai_agent_reasoning,
                    rule_base_result, rule_base_reason, guard_llm_result, guard_llm_reason,
                    final_decision, approval_status, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, 'pending'), ?)
                """,
                (
                    payload.get("user_id"),
                    payload["agent_name"],
                    payload["user_prompt"],
                    payload.get("ai_agent_reasoning"),
                    payload.get("rule_base_result"),
                    payload.get("rule_base_reason"),
                    payload.get("guard_llm_result"),
                    payload.get("guard_llm_reason"),
                    payload["final_decision"],
                    payload.get("approval_status"),
                    now,
                ),
            )
            run_id = cursor.lastrowid
            inserted_actions: list[dict[str, Any]] = []
            for index, action in enumerate(actions):
                action_cursor = self._conn.execute(
                    """
                    INSERT INTO guard_actions
                    (
                        run_id, action_order, agent_name, event_id, created_at, syscall,
                        path, argv, raw_summary, summary, meaning, normalized_action,
                        target_class, rule_result
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        action.get("action_order", index + 1),
                        action.get("agent_name", payload["agent_name"]),
                        action.get("event_id"),
                        action.get("created_at"),
                        action.get("syscall"),
                        action.get("path"),
                        json.dumps(action.get("argv"), ensure_ascii=False)
                        if action.get("argv") is not None
                        else None,
                        action.get("raw_summary"),
                        action.get("summary"),
                        action.get("meaning"),
                        action.get("normalized_action"),
                        action.get("target_class"),
                        action.get("rule_result"),
                    ),
                )
                inserted_actions.append(self._action_by_id(action_cursor.lastrowid))
            self._conn.commit()
            return {"run": self._run_by_id(run_id), "actions": inserted_actions}

    def list_guard_runs(self) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM guard_runs ORDER BY created_at DESC, id DESC"
            ).fetchall()
            return [
                {**self._run_dict(row), "actions": self._actions_for_run(row["id"])}
                for row in rows
            ]

    def get_guard_run(self, run_id: int) -> dict[str, Any] | None:
        with self._lock:
            run = self._run_by_id(run_id)
            if run is None:
                return None
            return {"run": run, "actions": self._actions_for_run(run_id)}

    def update_guard_run_approval(
        self, run_id: int, *, approval_status: str, approved_by: int | None = None
    ) -> dict[str, Any] | None:
        approved_at = None if approval_status == "pending" else utc_now()
        approved_by = None if approval_status == "pending" else approved_by
        with self._lock:
            cursor = self._conn.execute(
                """
                UPDATE guard_runs
                SET approval_status = ?, approved_by = ?, approved_at = ?
                WHERE id = ?
                """,
                (approval_status, approved_by, approved_at, run_id),
            )
            if cursor.rowcount == 0:
                return None
            self._conn.commit()
            return self._run_by_id(run_id)

    def _user_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return {"id": row["id"], "name": row["name"], "email": row["email"]}

    def _run_by_id(self, run_id: int) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM guard_runs WHERE id = ?", (run_id,)).fetchone()
        return self._run_dict(row) if row is not None else None

    def _action_by_id(self, action_id: int) -> dict[str, Any]:
        row = self._conn.execute("SELECT * FROM guard_actions WHERE id = ?", (action_id,)).fetchone()
        assert row is not None
        return self._action_dict(row)

    def _actions_for_run(self, run_id: int) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM guard_actions WHERE run_id = ? ORDER BY action_order ASC, id ASC",
            (run_id,),
        ).fetchall()
        return [self._action_dict(row) for row in rows]

    def _run_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        return dict(row)

    def _action_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        result = dict(row)
        if result.get("argv"):
            with suppress(json.JSONDecodeError, TypeError):
                result["argv"] = json.loads(result["argv"])
        return result
