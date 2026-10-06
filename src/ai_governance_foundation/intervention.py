"""访问行为判定与干预服务。

在基础服务之上提供：按时间到达的动作记录接入、版本化判定规则、
结合主体、目标、历史频率与当前授权的风险判定、限流/暂停/人工复核干预、
复核人员恢复以及可解释的判定查询。所有状态保存在 SQLite 中，
重启后尚未处理的干预队列继续保留；判定完成后规则变更不会改写历史结论。
"""

from __future__ import annotations

import json
import re
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import Any

from . import risk
from .audit import append_event, canonical_json, digest
from .clock import format_timestamp, parse_timestamp
from .errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from .models import Decision, IngestResult, Intervention, Subject
from .service import DomainService


TARGET_PATTERN = re.compile(r"^(\*|[A-Za-z0-9][A-Za-z0-9_.:-]{0,126}\*?)$")
TARGET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$")
INTERVENTION_STATUSES = frozenset({"active", "pending", "confirmed", "released"})
RESOLUTIONS = frozenset({"confirm", "release"})
OPEN_INTERVENTION_WHERE = "(kind='suspend' AND status='active') OR (kind='review' AND status='pending')"


class InterventionService(DomainService):
    """协调动作接入、风险判定、干预执行与复核恢复。"""

    # —— 基础校验 ——

    @staticmethod
    def _bounded_int(value: Any, field: str, minimum: int, maximum: int) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
            raise ValidationError(f"{field} 必须是 {minimum} 到 {maximum} 的整数")
        return value

    def _target(self, value: str) -> str:
        value = str(value).strip()
        if not TARGET.fullmatch(value):
            raise ValidationError("target 格式无效")
        return value

    def _target_pattern(self, value: str) -> str:
        value = str(value).strip()
        if not TARGET_PATTERN.fullmatch(value):
            raise ValidationError("target_pattern 格式无效")
        return value

    def _timestamp(self, value: str, field: str) -> tuple[datetime, str]:
        try:
            parsed = parse_timestamp(value)
        except ValueError as exc:
            raise ValidationError(f"{field} 必须是带时区的 ISO 8601 时间") from exc
        return parsed, format_timestamp(parsed)

    def _now_z(self) -> str:
        return format_timestamp(self.clock.now())

    def _rule_spec(self, name: str, rule_type: str, params: Any, score: Any,
                   measure: str) -> tuple[str, dict[str, Any], int, str]:
        name = self._text(name, "name")
        if rule_type not in risk.RULE_TYPES:
            raise ValidationError("rule_type 不在允许范围内")
        if not isinstance(params, dict):
            raise ValidationError("params 必须是对象")
        cleaned: dict[str, Any] = {}
        if rule_type == "frequency_spike":
            cleaned = {
                "window_seconds": self._bounded_int(params.get("window_seconds"), "window_seconds", 1, 86400),
                "max_actions": self._bounded_int(params.get("max_actions"), "max_actions", 1, 100000),
            }
        elif rule_type == "target_diversity":
            cleaned = {
                "window_seconds": self._bounded_int(params.get("window_seconds"), "window_seconds", 1, 86400),
                "max_distinct_targets": self._bounded_int(
                    params.get("max_distinct_targets"), "max_distinct_targets", 1, 100000),
            }
        score = self._bounded_int(score, "score", 1, 1000)
        if measure not in risk.INTERVENTION_MEASURES:
            raise ValidationError("measure 必须是 throttle、suspend 或 review")
        return name, cleaned, score, measure

    # —— 行记录转换 ——

    @staticmethod
    def _subject_from_row(row: sqlite3.Row) -> Subject:
        return Subject(row["subject_id"], row["organization_id"], row["display_name"],
                       row["trust_tier"], row["status"], row["created_at"])

    @staticmethod
    def _decision_from_row(row: sqlite3.Row) -> Decision:
        return Decision(row["decision_id"], row["action_id"], row["subject_id"],
                        row["ruleset_generation"], row["risk_score"], row["measure"],
                        json.loads(row["triggered_json"]), json.loads(row["features_json"]),
                        row["intervention_id"], row["decided_at"])

    @staticmethod
    def _intervention_from_row(row: sqlite3.Row) -> Intervention:
        return Intervention(row["intervention_id"], row["decision_id"], row["subject_id"],
                            row["kind"], row["status"], json.loads(row["detail_json"]),
                            row["expires_at"], row["created_at"], row["resolved_by"],
                            row["resolved_at"], row["resolution"], row["resolution_reason"])

    # —— 主体与授权 ——

    def register_subject(self, *, request_id: str, actor_id: str, subject_id: str,
                         organization_id: str, display_name: str, trust_tier: str):
        payload = {"actor_id": actor_id, "subject_id": subject_id, "organization_id": organization_id,
                   "display_name": display_name, "trust_tier": trust_tier}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            if actor.organization_id != organization_id and actor.role != "admin":
                raise PermissionDenied("不能为其他组织登记主体")
            subject_id = self._identifier(subject_id, "subject_id")
            display_name = self._text(display_name, "display_name")
            if trust_tier not in risk.TRUST_TIERS:
                raise ValidationError("trust_tier 必须是 high、medium 或 low")
            if connection.execute("SELECT 1 FROM organizations WHERE organization_id=?",
                                  (organization_id,)).fetchone() is None:
                raise NotFoundError("组织不存在")

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO subjects(subject_id,organization_id,display_name,trust_tier,status,created_at) "
                        "VALUES(?,?,?,?,'active',?)",
                        (subject_id, organization_id, display_name, trust_tier, self._now_z()),
                    )
                except Exception as exc:
                    raise ConflictError("主体编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="subject.registered",
                             resource_type="subject", resource_id=subject_id,
                             detail={"organization_id": organization_id, "trust_tier": trust_tier},
                             occurred_at=self._now_z())
                return "subject", subject_id, {"subject_id": subject_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="register_subject", payload=payload, create=create)

    def create_grant(self, *, request_id: str, actor_id: str, grant_id: str, subject_id: str,
                     target_pattern: str, action_type: str, quota_limit: int,
                     quota_window_seconds: int, valid_from: str, valid_until: str):
        payload = {"actor_id": actor_id, "grant_id": grant_id, "subject_id": subject_id,
                   "target_pattern": target_pattern, "action_type": action_type,
                   "quota_limit": quota_limit, "quota_window_seconds": quota_window_seconds,
                   "valid_from": valid_from, "valid_until": valid_until}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            grant_id = self._identifier(grant_id, "grant_id")
            subject_id = self._identifier(subject_id, "subject_id")
            target_pattern = self._target_pattern(target_pattern)
            action_type = self._identifier(action_type, "action_type") if action_type != "*" else "*"
            quota_limit = self._bounded_int(quota_limit, "quota_limit", 1, 1000000)
            quota_window_seconds = self._bounded_int(
                quota_window_seconds, "quota_window_seconds", 1, 2592000)
            _, from_z = self._timestamp(valid_from, "valid_from")
            _, until_z = self._timestamp(valid_until, "valid_until")
            if from_z >= until_z:
                raise ValidationError("valid_from 必须早于 valid_until")
            subject = connection.execute("SELECT * FROM subjects WHERE subject_id=?",
                                         (subject_id,)).fetchone()
            if subject is None:
                raise NotFoundError("主体不存在")
            if actor.organization_id != subject["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能为其他组织的主体授权")

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO authorization_grants(grant_id,subject_id,target_pattern,action_type,"
                        "quota_limit,quota_window_seconds,valid_from,valid_until,status,created_at) "
                        "VALUES(?,?,?,?,?,?,?,?,'active',?)",
                        (grant_id, subject_id, target_pattern, action_type, quota_limit,
                         quota_window_seconds, from_z, until_z, self._now_z()),
                    )
                except Exception as exc:
                    raise ConflictError("授权编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="grant.created",
                             resource_type="grant", resource_id=grant_id,
                             detail={"subject_id": subject_id, "target_pattern": target_pattern,
                                     "action_type": action_type, "quota_limit": quota_limit,
                                     "quota_window_seconds": quota_window_seconds,
                                     "valid_from": from_z, "valid_until": until_z},
                             occurred_at=self._now_z())
                return "grant", grant_id, {"grant_id": grant_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="create_grant", payload=payload, create=create)

    def revoke_grant(self, *, request_id: str, actor_id: str, grant_id: str):
        payload = {"actor_id": actor_id, "grant_id": grant_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            grant_id = self._identifier(grant_id, "grant_id")
            grant = connection.execute("SELECT * FROM authorization_grants WHERE grant_id=?",
                                       (grant_id,)).fetchone()
            if grant is None:
                raise NotFoundError("授权不存在")
            subject = connection.execute("SELECT * FROM subjects WHERE subject_id=?",
                                         (grant["subject_id"],)).fetchone()
            if actor.organization_id != subject["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能撤销其他组织的授权")

            def create() -> tuple[str, str, dict[str, Any]]:
                if grant["status"] != "active":
                    raise ConflictError("授权已经撤销")
                connection.execute("UPDATE authorization_grants SET status='revoked' WHERE grant_id=?",
                                   (grant_id,))
                append_event(connection, actor_id=actor_id, action="grant.revoked",
                             resource_type="grant", resource_id=grant_id,
                             detail={"subject_id": grant["subject_id"]}, occurred_at=self._now_z())
                return "grant", grant_id, {"grant_id": grant_id, "status": "revoked"}

            return self._idempotent(connection, request_id=request_id,
                                    action="revoke_grant", payload=payload, create=create)

    # —— 判定规则的版本化管理 ——

    def _bump_generation(self, connection, *, actor_id: str, summary: dict[str, Any]) -> None:
        connection.execute(
            "INSERT INTO ruleset_generations(change_summary_json,changed_by,created_at) VALUES(?,?,?)",
            (canonical_json(summary), actor_id, self._now_z()),
        )

    def _current_generation(self, connection) -> int:
        row = connection.execute("SELECT MAX(generation) AS generation FROM ruleset_generations").fetchone()
        return row["generation"] or 0

    def _active_rules(self, connection) -> list[risk.RuleVersion]:
        rows = connection.execute(
            "SELECT r.* FROM risk_rules r "
            "JOIN (SELECT rule_id, MAX(version) AS version FROM risk_rules GROUP BY rule_id) latest "
            "ON r.rule_id=latest.rule_id AND r.version=latest.version "
            "WHERE r.status='active' ORDER BY r.rule_id"
        ).fetchall()
        return [risk.RuleVersion(rule_id=row["rule_id"], version=row["version"], name=row["name"],
                                 rule_type=row["rule_type"], params=json.loads(row["params_json"]),
                                 score=row["score"], measure=row["measure"]) for row in rows]

    def create_rule(self, *, request_id: str, actor_id: str, rule_id: str, name: str,
                    rule_type: str, params: dict[str, Any], score: int, measure: str):
        payload = {"actor_id": actor_id, "rule_id": rule_id, "name": name, "rule_type": rule_type,
                   "params": params, "score": score, "measure": measure}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            rule_id = self._identifier(rule_id, "rule_id")
            name, cleaned, score, measure = self._rule_spec(name, rule_type, params, score, measure)

            def create() -> tuple[str, str, dict[str, Any]]:
                if connection.execute("SELECT 1 FROM risk_rules WHERE rule_id=?", (rule_id,)).fetchone():
                    raise ConflictError("规则编号已经存在")
                connection.execute(
                    "INSERT INTO risk_rules(rule_id,version,name,rule_type,params_json,score,measure,status,"
                    "created_by,created_at) VALUES(?,1,?,?,?,?,?,'active',?,?)",
                    (rule_id, name, rule_type, canonical_json(cleaned), score, measure,
                     actor_id, self._now_z()),
                )
                self._bump_generation(connection, actor_id=actor_id,
                                      summary={"change": "rule.created", "rule_id": rule_id, "version": 1})
                append_event(connection, actor_id=actor_id, action="rule.created",
                             resource_type="rule", resource_id=rule_id,
                             detail={"name": name, "rule_type": rule_type, "version": 1},
                             occurred_at=self._now_z())
                return "rule", rule_id, {"rule_id": rule_id, "version": 1}

            return self._idempotent(connection, request_id=request_id,
                                    action="create_rule", payload=payload, create=create)

    def update_rule(self, *, request_id: str, actor_id: str, rule_id: str, name: str,
                    rule_type: str, params: dict[str, Any], score: int, measure: str):
        """以新版本替换规则；已经完成的判定保持原样。"""

        payload = {"actor_id": actor_id, "rule_id": rule_id, "name": name, "rule_type": rule_type,
                   "params": params, "score": score, "measure": measure}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            rule_id = self._identifier(rule_id, "rule_id")
            name, cleaned, score, measure = self._rule_spec(name, rule_type, params, score, measure)
            row = connection.execute("SELECT MAX(version) AS version FROM risk_rules WHERE rule_id=?",
                                     (rule_id,)).fetchone()
            if row["version"] is None:
                raise NotFoundError("规则不存在")
            version = row["version"] + 1

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute("UPDATE risk_rules SET status='superseded' WHERE rule_id=? AND status='active'",
                                   (rule_id,))
                connection.execute(
                    "INSERT INTO risk_rules(rule_id,version,name,rule_type,params_json,score,measure,status,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?,'active',?,?)",
                    (rule_id, version, name, rule_type, canonical_json(cleaned), score, measure,
                     actor_id, self._now_z()),
                )
                self._bump_generation(connection, actor_id=actor_id,
                                      summary={"change": "rule.updated", "rule_id": rule_id, "version": version})
                append_event(connection, actor_id=actor_id, action="rule.updated",
                             resource_type="rule", resource_id=rule_id,
                             detail={"name": name, "rule_type": rule_type, "version": version},
                             occurred_at=self._now_z())
                return "rule", rule_id, {"rule_id": rule_id, "version": version}

            return self._idempotent(connection, request_id=request_id,
                                    action="update_rule", payload=payload, create=create)

    def retire_rule(self, *, request_id: str, actor_id: str, rule_id: str):
        payload = {"actor_id": actor_id, "rule_id": rule_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            rule_id = self._identifier(rule_id, "rule_id")
            row = connection.execute(
                "SELECT * FROM risk_rules WHERE rule_id=? AND status='active' ORDER BY version DESC LIMIT 1",
                (rule_id,)).fetchone()
            if row is None:
                if connection.execute("SELECT 1 FROM risk_rules WHERE rule_id=?", (rule_id,)).fetchone() is None:
                    raise NotFoundError("规则不存在")
                raise ConflictError("规则已经停用")

            def create() -> tuple[str, str, dict[str, Any]]:
                connection.execute("UPDATE risk_rules SET status='retired' WHERE rule_id=? AND version=?",
                                   (rule_id, row["version"]))
                self._bump_generation(connection, actor_id=actor_id,
                                      summary={"change": "rule.retired", "rule_id": rule_id})
                append_event(connection, actor_id=actor_id, action="rule.retired",
                             resource_type="rule", resource_id=rule_id,
                             detail={"version": row["version"]}, occurred_at=self._now_z())
                return "rule", rule_id, {"rule_id": rule_id, "status": "retired"}

            return self._idempotent(connection, request_id=request_id,
                                    action="retire_rule", payload=payload, create=create)

    def list_rules(self) -> list[dict[str, Any]]:
        rows = self.database.connection.execute(
            "SELECT r.* FROM risk_rules r "
            "JOIN (SELECT rule_id, MAX(version) AS version FROM risk_rules GROUP BY rule_id) latest "
            "ON r.rule_id=latest.rule_id AND r.version=latest.version "
            "WHERE r.status='active' ORDER BY r.rule_id"
        ).fetchall()
        return [{"rule_id": row["rule_id"], "version": row["version"], "name": row["name"],
                 "rule_type": row["rule_type"], "params": json.loads(row["params_json"]),
                 "score": row["score"], "measure": row["measure"]} for row in rows]

    # —— 动作接入与风险判定 ——

    def _stored_response(self, connection, *, request_id: str, action: str,
                         payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
        """返回已存响应表示请求重放，返回 None 表示需要执行。"""

        request_id = self._identifier(request_id, "request_id")
        payload_hash = digest(payload)
        row = connection.execute("SELECT * FROM request_receipts WHERE request_id=?",
                                 (request_id,)).fetchone()
        if row is None:
            return request_id, None
        if row["action"] != action or row["payload_hash"] != payload_hash:
            raise ConflictError("request_id 已被不同内容使用")
        return request_id, json.loads(row["response_json"])

    def _store_response(self, connection, *, request_id: str, action: str, payload: dict[str, Any],
                        resource_id: str, response: dict[str, Any]) -> None:
        connection.execute(
            "INSERT INTO request_receipts(request_id,action,payload_hash,resource_type,resource_id,"
            "response_json,created_at) VALUES(?,?,?,?,?,?,?)",
            (request_id, action, digest(payload), "decision", resource_id,
             canonical_json(response), self._now()),
        )

    @staticmethod
    def _target_matches(pattern: str, target: str) -> bool:
        if pattern == "*":
            return True
        if pattern.endswith("*"):
            return target.startswith(pattern[:-1])
        return pattern == target

    def _best_grant(self, connection, *, subject_id: str, target: str, action_type: str,
                    occurred_z: str) -> sqlite3.Row | None:
        rows = connection.execute(
            "SELECT * FROM authorization_grants WHERE subject_id=? AND status='active' "
            "AND valid_from<=? AND valid_until>=?",
            (subject_id, occurred_z, occurred_z),
        ).fetchall()
        matches = [row for row in rows
                   if self._target_matches(row["target_pattern"], target)
                   and row["action_type"] in ("*", action_type)]
        if not matches:
            return None
        matches.sort(key=lambda row: (len(row["target_pattern"]), row["quota_limit"]), reverse=True)
        return matches[0]

    def _behavior_signals(self, connection, *, subject: sqlite3.Row, target: str, action_type: str,
                          occurred_dt: datetime, occurred_z: str,
                          rules: list[risk.RuleVersion]) -> tuple[risk.BehaviorSignals, sqlite3.Row | None, dict[str, Any]]:
        subject_id = subject["subject_id"]
        windows = sorted({window for rule in rules
                          if (window := rule.window_seconds()) is not None})
        window_counts: dict[int, int] = {}
        window_distinct: dict[int, int] = {}
        for window in windows:
            since = format_timestamp(occurred_dt - timedelta(seconds=window))
            row = connection.execute(
                "SELECT COUNT(*) AS count, COUNT(DISTINCT target) AS distinct_targets "
                "FROM action_records WHERE subject_id=? AND occurred_at>? AND occurred_at<=?",
                (subject_id, since, occurred_z),
            ).fetchone()
            window_counts[window] = row["count"]
            window_distinct[window] = row["distinct_targets"]
        grant = self._best_grant(connection, subject_id=subject_id, target=target,
                                 action_type=action_type, occurred_z=occurred_z)
        quota_remaining = None
        if grant is not None:
            since = format_timestamp(occurred_dt - timedelta(seconds=grant["quota_window_seconds"]))
            used = connection.execute(
                "SELECT COUNT(*) AS count FROM quota_ledger WHERE grant_id=? AND occurred_at>? AND occurred_at<=?",
                (grant["grant_id"], since, occurred_z),
            ).fetchone()["count"]
            quota_remaining = grant["quota_limit"] - used
        throttle = connection.execute(
            "SELECT intervention_id FROM interventions WHERE subject_id=? AND kind='throttle' "
            "AND status='active' AND expires_at>? ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (subject_id, occurred_z),
        ).fetchone()
        signals = risk.BehaviorSignals(
            trust_tier=subject["trust_tier"], authorized=grant is not None, target=target,
            action_type=action_type, quota_remaining=quota_remaining,
            window_counts=window_counts, window_distinct_targets=window_distinct,
            active_throttle_id=throttle["intervention_id"] if throttle else None,
        )
        features = {
            "trust_tier": subject["trust_tier"],
            "authorized": grant is not None,
            "grant_id": grant["grant_id"] if grant is not None else None,
            "quota_remaining": quota_remaining,
            "window_counts": {str(window): count for window, count in window_counts.items()},
            "window_distinct_targets": {str(window): count for window, count in window_distinct.items()},
            "active_throttle_id": signals.active_throttle_id,
        }
        return signals, grant, features

    @staticmethod
    def _rule_summaries(triggered: list[dict[str, Any]]) -> list[dict[str, Any]]:
        return [{"rule_id": item["rule_id"], "version": item["version"], "name": item["name"]}
                for item in triggered if item["rule_id"] is not None]

    def _create_throttle(self, connection, *, actor_id: str, decision_id: str, subject_id: str,
                         occurred_dt: datetime, triggered: list[dict[str, Any]], score: int,
                         now_z: str) -> str:
        windows = [item["evidence"]["window_seconds"] for item in triggered
                   if isinstance(item.get("evidence"), dict) and "window_seconds" in item["evidence"]]
        throttle_seconds = max(windows) if windows else 300
        intervention_id = uuid.uuid4().hex
        expires_z = format_timestamp(occurred_dt + timedelta(seconds=throttle_seconds))
        detail = {"triggered_rules": self._rule_summaries(triggered), "risk_score": score,
                  "window_seconds": throttle_seconds}
        connection.execute(
            "INSERT INTO interventions(intervention_id,decision_id,subject_id,kind,status,detail_json,"
            "expires_at,created_at) VALUES(?,?,?,'throttle','active',?,?,?)",
            (intervention_id, decision_id, subject_id, canonical_json(detail), expires_z, now_z),
        )
        append_event(connection, actor_id=actor_id, action="intervention.created",
                     resource_type="intervention", resource_id=intervention_id,
                     detail={"kind": "throttle", "decision_id": decision_id, "subject_id": subject_id,
                             "expires_at": expires_z},
                     occurred_at=now_z)
        return intervention_id

    def _create_blocking_intervention(self, connection, *, actor_id: str, decision_id: str,
                                      subject_id: str, measure: str, triggered: list[dict[str, Any]],
                                      score: int, now_z: str) -> str:
        intervention_id = uuid.uuid4().hex
        status = "pending" if measure == "review" else "active"
        detail = {"triggered_rules": self._rule_summaries(triggered), "risk_score": score}
        connection.execute(
            "INSERT INTO interventions(intervention_id,decision_id,subject_id,kind,status,detail_json,"
            "expires_at,created_at) VALUES(?,?,?,?,?,?,NULL,?)",
            (intervention_id, decision_id, subject_id, measure, status, canonical_json(detail), now_z),
        )
        connection.execute("UPDATE subjects SET status='suspended' WHERE subject_id=?", (subject_id,))
        append_event(connection, actor_id=actor_id, action="intervention.created",
                     resource_type="intervention", resource_id=intervention_id,
                     detail={"kind": measure, "decision_id": decision_id, "subject_id": subject_id},
                     occurred_at=now_z)
        return intervention_id

    def _judge_fresh_action(self, connection, *, actor_id: str, request_id: str, action_id: str,
                            subject: sqlite3.Row, target: str, action_type: str,
                            occurred_dt: datetime, occurred_z: str, metadata: dict[str, Any],
                            business_hash: str) -> dict[str, Any]:
        now_z = self._now_z()
        subject_id = subject["subject_id"]
        connection.execute(
            "INSERT INTO action_records(action_id,subject_id,target,action_type,occurred_at,metadata_json,"
            "payload_hash,received_at) VALUES(?,?,?,?,?,?,?,?)",
            (action_id, subject_id, target, action_type, occurred_z, canonical_json(metadata),
             business_hash, now_z),
        )
        append_event(connection, actor_id=actor_id, action="action.recorded",
                     resource_type="action", resource_id=action_id,
                     detail={"subject_id": subject_id, "target": target, "action_type": action_type,
                             "occurred_at": occurred_z},
                     occurred_at=now_z)
        generation = self._current_generation(connection)
        open_intervention = connection.execute(
            f"SELECT * FROM interventions WHERE subject_id=? AND ({OPEN_INTERVENTION_WHERE}) "
            "ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (subject_id,),
        ).fetchone()
        grant = None
        if open_intervention is not None:
            # 存在未解除的暂停或复核：直接阻断，不再重复评估与扣减额度。
            measure = open_intervention["kind"]
            score = risk.TRUST_BASE_SCORE[subject["trust_tier"]]
            triggered = [{
                "rule_id": None, "version": None, "name": "存在未解除的干预，动作被直接阻断",
                "rule_type": "open_intervention", "measure": measure, "score": 0,
                "evidence": {"intervention_id": open_intervention["intervention_id"], "kind": measure},
            }]
            features = {"trust_tier": subject["trust_tier"],
                        "open_intervention_id": open_intervention["intervention_id"]}
            reused_intervention_id = open_intervention["intervention_id"]
        else:
            rules = self._active_rules(connection)
            signals, grant, features = self._behavior_signals(
                connection, subject=subject, target=target, action_type=action_type,
                occurred_dt=occurred_dt, occurred_z=occurred_z, rules=rules)
            evaluation = risk.evaluate(rules, signals)
            measure = evaluation.measure
            score = evaluation.score
            triggered = evaluation.triggered
            reused_intervention_id = (
                features["active_throttle_id"] if measure == "throttle" else None
            )
        decision_id = uuid.uuid4().hex
        connection.execute(
            "INSERT INTO decisions(decision_id,action_id,subject_id,ruleset_generation,risk_score,measure,"
            "triggered_json,features_json,intervention_id,decided_at) VALUES(?,?,?,?,?,?,?,?,NULL,?)",
            (decision_id, action_id, subject_id, generation, score, measure,
             canonical_json(triggered), canonical_json(features), now_z),
        )
        intervention_id = reused_intervention_id
        if open_intervention is None:
            if measure == "throttle" and intervention_id is None:
                intervention_id = self._create_throttle(
                    connection, actor_id=actor_id, decision_id=decision_id, subject_id=subject_id,
                    occurred_dt=occurred_dt, triggered=triggered, score=score, now_z=now_z)
            elif measure in ("suspend", "review"):
                intervention_id = self._create_blocking_intervention(
                    connection, actor_id=actor_id, decision_id=decision_id, subject_id=subject_id,
                    measure=measure, triggered=triggered, score=score, now_z=now_z)
            if measure in ("allow", "throttle") and grant is not None:
                connection.execute(
                    "INSERT INTO quota_ledger(entry_id,grant_id,action_id,subject_id,occurred_at,deducted_at) "
                    "VALUES(?,?,?,?,?,?)",
                    (uuid.uuid4().hex, grant["grant_id"], action_id, subject_id, occurred_z, now_z),
                )
        if intervention_id is not None:
            connection.execute("UPDATE decisions SET intervention_id=? WHERE decision_id=?",
                               (intervention_id, decision_id))
        append_event(connection, actor_id=actor_id, action="decision.made",
                     resource_type="decision", resource_id=decision_id,
                     detail={"action_id": action_id, "subject_id": subject_id, "measure": measure,
                             "risk_score": score, "ruleset_generation": generation,
                             "triggered_rules": [item["rule_id"] for item in triggered
                                                 if item["rule_id"] is not None]},
                     occurred_at=now_z)
        return {"request_id": request_id, "action_id": action_id, "decision_id": decision_id,
                "measure": measure, "risk_score": score, "duplicate": False}

    def ingest_action(self, *, request_id: str, actor_id: str, action_id: str, subject_id: str,
                      target: str, action_type: str, occurred_at: str,
                      metadata: dict[str, Any] | None = None) -> IngestResult:
        """接入一条按时间到达的动作记录并完成风险判定。

        request_id 保证请求级幂等；action_id 保证业务级去重，
        重复上报同一动作返回原判定且不会重复扣减额度。
        """

        metadata = metadata if metadata is not None else {}
        if not isinstance(metadata, dict):
            raise ValidationError("metadata 必须是对象")
        payload = {"actor_id": actor_id, "action_id": action_id, "subject_id": subject_id,
                   "target": target, "action_type": action_type, "occurred_at": occurred_at,
                   "metadata": metadata}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            action_id = self._identifier(action_id, "action_id")
            subject_id = self._identifier(subject_id, "subject_id")
            target = self._target(target)
            action_type = self._identifier(action_type, "action_type")
            occurred_dt, occurred_z = self._timestamp(occurred_at, "occurred_at")
            request_id, cached = self._stored_response(connection, request_id=request_id,
                                                       action="ingest_action", payload=payload)
            if cached is not None:
                return IngestResult(**cached, replayed=True)
            subject = connection.execute("SELECT * FROM subjects WHERE subject_id=?",
                                         (subject_id,)).fetchone()
            if subject is None:
                raise NotFoundError("主体不存在")
            if actor.organization_id != subject["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能上报其他组织主体的动作")
            business = {"subject_id": subject_id, "target": target, "action_type": action_type,
                        "occurred_at": occurred_z, "metadata": metadata}
            business_hash = digest(business)
            existing = connection.execute("SELECT * FROM action_records WHERE action_id=?",
                                          (action_id,)).fetchone()
            if existing is not None:
                if existing["payload_hash"] != business_hash:
                    raise ConflictError("动作编号已被不同内容使用")
                decision_row = connection.execute("SELECT * FROM decisions WHERE action_id=?",
                                                  (action_id,)).fetchone()
                response = {"request_id": request_id, "action_id": action_id,
                            "decision_id": decision_row["decision_id"],
                            "measure": decision_row["measure"],
                            "risk_score": decision_row["risk_score"], "duplicate": True}
                self._store_response(connection, request_id=request_id, action="ingest_action",
                                     payload=payload, resource_id=decision_row["decision_id"],
                                     response=response)
                return IngestResult(**response, replayed=False)
            response = self._judge_fresh_action(
                connection, actor_id=actor_id, request_id=request_id, action_id=action_id,
                subject=subject, target=target, action_type=action_type, occurred_dt=occurred_dt,
                occurred_z=occurred_z, metadata=metadata, business_hash=business_hash)
            self._store_response(connection, request_id=request_id, action="ingest_action",
                                 payload=payload, resource_id=response["decision_id"],
                                 response=response)
            return IngestResult(**response, replayed=False)

    # —— 复核与恢复 ——

    def resolve_intervention(self, *, request_id: str, actor_id: str, intervention_id: str,
                             resolution: str, reason: str = ""):
        """复核人员确认处置，或在证据不足时恢复任务。"""

        if resolution not in RESOLUTIONS:
            raise ValidationError("resolution 必须是 confirm 或 release")
        payload = {"actor_id": actor_id, "intervention_id": intervention_id,
                   "resolution": resolution, "reason": reason}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "reviewer")
            intervention_id = self._identifier(intervention_id, "intervention_id")
            if resolution == "release":
                reason = self._text(reason, "reason", 500)
            else:
                reason = str(reason or "").strip()
                if len(reason) > 500:
                    raise ValidationError("reason 不能超过 500 个字符")
            row = connection.execute("SELECT * FROM interventions WHERE intervention_id=?",
                                     (intervention_id,)).fetchone()
            if row is None:
                raise NotFoundError("干预不存在")
            subject = connection.execute("SELECT * FROM subjects WHERE subject_id=?",
                                         (row["subject_id"],)).fetchone()
            if actor.organization_id != subject["organization_id"] and actor.role != "admin":
                raise PermissionDenied("不能处理其他组织的干预")

            def create() -> tuple[str, str, dict[str, Any]]:
                if row["status"] not in ("pending", "active"):
                    raise ConflictError("干预已经处理完成")
                status = "released" if resolution == "release" else "confirmed"
                now_z = self._now_z()
                connection.execute(
                    "UPDATE interventions SET status=?, resolved_by=?, resolved_at=?, resolution=?, "
                    "resolution_reason=? WHERE intervention_id=?",
                    (status, actor_id, now_z, resolution, reason, intervention_id),
                )
                resumed = False
                if resolution == "release" and row["kind"] in ("suspend", "review"):
                    still_open = connection.execute(
                        f"SELECT 1 FROM interventions WHERE subject_id=? AND intervention_id!=? "
                        f"AND ({OPEN_INTERVENTION_WHERE})",
                        (row["subject_id"], intervention_id),
                    ).fetchone()
                    if still_open is None:
                        connection.execute("UPDATE subjects SET status='active' WHERE subject_id=?",
                                           (row["subject_id"],))
                        resumed = True
                append_event(connection, actor_id=actor_id, action="intervention.resolved",
                             resource_type="intervention", resource_id=intervention_id,
                             detail={"kind": row["kind"], "resolution": resolution, "reason": reason,
                                     "subject_resumed": resumed},
                             occurred_at=now_z)
                return "intervention", intervention_id, {
                    "intervention_id": intervention_id, "status": status, "subject_resumed": resumed}

            return self._idempotent(connection, request_id=request_id,
                                    action="resolve_intervention", payload=payload, create=create)

    # —— 查询与解释 ——

    def get_subject(self, subject_id: str) -> Subject:
        row = self.database.connection.execute("SELECT * FROM subjects WHERE subject_id=?",
                                               (subject_id,)).fetchone()
        if row is None:
            raise NotFoundError("主体不存在")
        return self._subject_from_row(row)

    def get_decision(self, decision_id: str) -> Decision:
        row = self.database.connection.execute("SELECT * FROM decisions WHERE decision_id=?",
                                               (decision_id,)).fetchone()
        if row is None:
            raise NotFoundError("判定不存在")
        return self._decision_from_row(row)

    def explain_decision(self, decision_id: str) -> dict[str, Any]:
        """返回判定触发了哪些规则、依据的行为特征以及最终采取的措施。"""

        row = self.database.connection.execute("SELECT * FROM decisions WHERE decision_id=?",
                                               (decision_id,)).fetchone()
        if row is None:
            raise NotFoundError("判定不存在")
        decision = self._decision_from_row(row)
        intervention = None
        if decision.intervention_id is not None:
            intervention_row = self.database.connection.execute(
                "SELECT * FROM interventions WHERE intervention_id=?",
                (decision.intervention_id,),
            ).fetchone()
            if intervention_row is not None:
                intervention = self._intervention_from_row(intervention_row).__dict__
        return {
            "decision_id": decision.decision_id,
            "action_id": decision.action_id,
            "subject_id": decision.subject_id,
            "measure": decision.measure,
            "risk_score": decision.risk_score,
            "ruleset_generation": decision.ruleset_generation,
            "triggered_rules": decision.triggered,
            "features": decision.features,
            "decided_at": decision.decided_at,
            "intervention": intervention,
        }

    def list_decisions(self, subject_id: str | None = None, limit: int = 50) -> list[Decision]:
        limit = self._bounded_int(limit, "limit", 1, 500)
        if subject_id:
            rows = self.database.connection.execute(
                "SELECT * FROM decisions WHERE subject_id=? ORDER BY decided_at DESC, rowid DESC LIMIT ?",
                (subject_id, limit),
            ).fetchall()
        else:
            rows = self.database.connection.execute(
                "SELECT * FROM decisions ORDER BY decided_at DESC, rowid DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [self._decision_from_row(row) for row in rows]

    def list_interventions(self, status: str | None = None,
                           subject_id: str | None = None) -> list[Intervention]:
        if status is not None and status not in INTERVENTION_STATUSES:
            raise ValidationError("status 不在允许范围内")
        query = "SELECT * FROM interventions WHERE 1=1"
        parameters: list[Any] = []
        if status:
            query += " AND status=?"
            parameters.append(status)
        if subject_id:
            query += " AND subject_id=?"
            parameters.append(subject_id)
        query += " ORDER BY created_at, rowid"
        rows = self.database.connection.execute(query, parameters).fetchall()
        return [self._intervention_from_row(row) for row in rows]
