"""封装 SQLite 连接、建表和事务边界。"""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actors (
    actor_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    active INTEGER NOT NULL CHECK(active IN (0, 1)),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sites (
    site_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    name TEXT NOT NULL,
    timezone_name TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS domain_records (
    record_id TEXT PRIMARY KEY,
    site_id TEXT NOT NULL REFERENCES sites(site_id),
    category TEXT NOT NULL,
    external_key TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    created_by TEXT NOT NULL REFERENCES actors(actor_id),
    created_at TEXT NOT NULL,
    UNIQUE(site_id, category, external_key)
);
CREATE TABLE IF NOT EXISTS request_receipts (
    request_id TEXT PRIMARY KEY,
    action TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    response_json TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    actor_id TEXT NOT NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    detail_json TEXT NOT NULL,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL UNIQUE,
    occurred_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS subjects (
    subject_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES organizations(organization_id),
    display_name TEXT NOT NULL,
    trust_tier TEXT NOT NULL CHECK(trust_tier IN ('high', 'medium', 'low')),
    status TEXT NOT NULL CHECK(status IN ('active', 'suspended')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS authorization_grants (
    grant_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
    target_pattern TEXT NOT NULL,
    action_type TEXT NOT NULL,
    quota_limit INTEGER NOT NULL CHECK(quota_limit >= 1),
    quota_window_seconds INTEGER NOT NULL CHECK(quota_window_seconds >= 1),
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS risk_rules (
    rule_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK(version >= 1),
    name TEXT NOT NULL,
    rule_type TEXT NOT NULL,
    params_json TEXT NOT NULL,
    score INTEGER NOT NULL CHECK(score >= 0),
    measure TEXT NOT NULL CHECK(measure IN ('throttle', 'suspend', 'review')),
    status TEXT NOT NULL CHECK(status IN ('active', 'superseded', 'retired')),
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (rule_id, version)
);
CREATE TABLE IF NOT EXISTS ruleset_generations (
    generation INTEGER PRIMARY KEY AUTOINCREMENT,
    change_summary_json TEXT NOT NULL,
    changed_by TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS action_records (
    action_id TEXT PRIMARY KEY,
    subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
    target TEXT NOT NULL,
    action_type TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    received_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_action_records_subject_time ON action_records(subject_id, occurred_at);
CREATE TABLE IF NOT EXISTS decisions (
    decision_id TEXT PRIMARY KEY,
    action_id TEXT NOT NULL UNIQUE REFERENCES action_records(action_id),
    subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
    ruleset_generation INTEGER NOT NULL,
    risk_score INTEGER NOT NULL,
    measure TEXT NOT NULL CHECK(measure IN ('allow', 'throttle', 'suspend', 'review')),
    triggered_json TEXT NOT NULL,
    features_json TEXT NOT NULL,
    intervention_id TEXT,
    decided_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS interventions (
    intervention_id TEXT PRIMARY KEY,
    decision_id TEXT NOT NULL REFERENCES decisions(decision_id),
    subject_id TEXT NOT NULL REFERENCES subjects(subject_id),
    kind TEXT NOT NULL CHECK(kind IN ('throttle', 'suspend', 'review')),
    status TEXT NOT NULL CHECK(status IN ('active', 'pending', 'confirmed', 'released')),
    detail_json TEXT NOT NULL,
    expires_at TEXT,
    created_at TEXT NOT NULL,
    resolved_by TEXT,
    resolved_at TEXT,
    resolution TEXT,
    resolution_reason TEXT
);
CREATE INDEX IF NOT EXISTS idx_interventions_subject_status ON interventions(subject_id, status);
CREATE TABLE IF NOT EXISTS quota_ledger (
    entry_id TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL REFERENCES authorization_grants(grant_id),
    action_id TEXT NOT NULL UNIQUE REFERENCES action_records(action_id),
    subject_id TEXT NOT NULL,
    occurred_at TEXT NOT NULL,
    deducted_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_quota_ledger_grant_time ON quota_ledger(grant_id, occurred_at);
"""


class Database:
    """管理 SQLite 数据库并为服务提供短事务。"""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        self.connection = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self.connection.execute("PRAGMA busy_timeout = 5000")
        self.connection.executescript(SCHEMA)

    @contextmanager
    def transaction(self, immediate: bool = False) -> Iterator[sqlite3.Connection]:
        """在异常时回滚，在成功时提交。"""

        self.connection.execute("BEGIN IMMEDIATE" if immediate else "BEGIN")
        try:
            yield self.connection
        except Exception:
            self.connection.rollback()
            raise
        else:
            self.connection.commit()

    def close(self) -> None:
        """关闭底层连接。"""

        self.connection.close()
