from __future__ import annotations

import csv
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class SyscallImpact:
    syscall_name: str
    affects_host_os: int
    category: str
    rationale: str
    source: str
    is_known: bool


class PipelineDatabase:
    def __init__(self, db_path: Path, mapping_csv_path: Path) -> None:
        self.db_path = db_path
        self.mapping_csv_path = mapping_csv_path

    def initialize(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path) as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS syscall_host_impact_map (
                    syscall_name TEXT PRIMARY KEY,
                    affects_host_os INTEGER NOT NULL CHECK (affects_host_os IN (0, 1)),
                    category TEXT NOT NULL,
                    rationale TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
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
        self._seed_mapping_table()

    def _seed_mapping_table(self) -> None:
        if not self.mapping_csv_path.exists():
            raise FileNotFoundError(f"mapping table not found: {self.mapping_csv_path}")

        with self.mapping_csv_path.open("r", encoding="utf-8", newline="") as handle:
            rows = list(csv.DictReader(handle))

        with sqlite3.connect(self.db_path) as connection:
            for row in rows:
                connection.execute(
                    """
                    INSERT INTO syscall_host_impact_map (
                        syscall_name,
                        affects_host_os,
                        category,
                        rationale,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?)
                    ON CONFLICT(syscall_name) DO UPDATE SET
                        affects_host_os = excluded.affects_host_os,
                        category = excluded.category,
                        rationale = excluded.rationale,
                        updated_at = excluded.updated_at
                    """,
                    (
                        row["syscall_name"].strip().lower(),
                        int(row["affects_host_os"]),
                        row["category"].strip(),
                        row["rationale"].strip(),
                        utcnow_iso(),
                    ),
                )
            connection.commit()

    def lookup_syscall(self, syscall_name: str) -> SyscallImpact:
        normalized_name = syscall_name.strip().lower()
        with sqlite3.connect(self.db_path) as connection:
            row = connection.execute(
                """
                SELECT syscall_name, affects_host_os, category, rationale
                FROM syscall_host_impact_map
                WHERE syscall_name = ?
                """,
                (normalized_name,),
            ).fetchone()

        if row is None:
            return SyscallImpact(
                syscall_name=normalized_name,
                affects_host_os=1,
                category="unknown",
                rationale="Unknown syscalls are conservatively treated as host-impacting to avoid false negatives.",
                source="fallback",
                is_known=False,
            )

        return SyscallImpact(
            syscall_name=row[0],
            affects_host_os=int(row[1]),
            category=row[2],
            rationale=row[3],
            source="mapping_table",
            is_known=True,
        )

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
