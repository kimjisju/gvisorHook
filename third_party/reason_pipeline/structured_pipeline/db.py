from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PipelineDatabase:
    def __init__(self, db_path: Path, mapping_csv_path: Path | None = None) -> None:
        self.db_path = db_path
        self.mapping_csv_path = mapping_csv_path

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS parser_registry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_name TEXT NOT NULL,
                    schema_signature TEXT NOT NULL,
                    parser_path TEXT NOT NULL,
                    parser_code TEXT NOT NULL,
                    generator_model TEXT NOT NULL,
                    last_validation_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(agent_name, schema_signature)
                )
                """
            )
            connection.commit()

    def get_parser_record(self, agent_name: str, schema_signature: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.db_path) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                """
                SELECT *
                FROM parser_registry
                WHERE agent_name = ? AND schema_signature = ?
                """,
                (agent_name, schema_signature),
            ).fetchone()
        return dict(row) if row else None

    def upsert_parser_record(
        self,
        *,
        agent_name: str,
        schema_signature: str,
        parser_path: str,
        parser_code: str,
        generator_model: str,
        last_validation_error: str | None,
    ) -> None:
        timestamp = utcnow_iso()
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                INSERT INTO parser_registry (
                    agent_name,
                    schema_signature,
                    parser_path,
                    parser_code,
                    generator_model,
                    last_validation_error,
                    created_at,
                    updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(agent_name, schema_signature) DO UPDATE SET
                    parser_path = excluded.parser_path,
                    parser_code = excluded.parser_code,
                    generator_model = excluded.generator_model,
                    last_validation_error = excluded.last_validation_error,
                    updated_at = excluded.updated_at
                """,
                (
                    agent_name,
                    schema_signature,
                    parser_path,
                    parser_code,
                    generator_model,
                    last_validation_error,
                    timestamp,
                    timestamp,
                ),
            )
            connection.commit()
