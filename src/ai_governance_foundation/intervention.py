"""访问行为判定与干预服务。

在基础身份与审计能力之上,接收按时间到达的动作记录,结合主体、目标、
历史频率与当前授权计算风险,触发限流、暂停或转人工复核,并支持复核人员
在证据不足时恢复任务。判定结果落库后不可变:规则更新只会产生新版本,
已经完成的判断始终保留当时使用的规则快照。同一动作重复上报不会重复扣减
额度,重启后尚未处理的干预队列继续保留。
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any

from .audit import append_event, canonical_json
from .errors import ConflictError, NotFoundError, ValidationError
from .models import WriteReceipt
from .rules import DEFAULT_THROTTLE_SECONDS, rule_hit, strongest_measure, validate_rule_params
from .service import DomainService

OPEN_STATUSES = ("pending", "active")
RESOLUTIONS = frozenset({"resumed", "confirmed"})
INTERVENTION_STATUSES = frozenset({"pending", "active", "resolved"})


class InterventionService(DomainService):
    """协调动作判定、额度扣减、干预队列与人工复核。"""

    @staticmethod
    def _moment(value: datetime) -> str:
        return value.astimezone(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

    def _parse_moment(self, value: Any, field: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field} 必须是 ISO-8601 时间") from exc
        if parsed.tzinfo is None:
            raise ValidationError(f"{field} 必须包含时区")
        return parsed.astimezone(timezone.utc)

    # ---- 风险规则 ----

    def upsert_rule(self, *, request_id: str, actor_id: str, rule_id: str, name: str,
                    rule_type: str, params: Any, measure: str, risk_score: Any) -> WriteReceipt:
        """登记或更新规则;更新只会追加新版本,历史判定仍引用旧版本快照。"""

        normalized = validate_rule_params(rule_type, measure, params)
        if isinstance(risk_score, bool) or not isinstance(risk_score, int) or not 1 <= risk_score <= 100:
            raise ValidationError("risk_score 必须是 1 到 100 的整数")
        payload = {"actor_id": actor_id, "rule_id": rule_id, "name": name, "rule_type": rule_type,
                   "params": normalized, "measure": measure, "risk_score": risk_score}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin")
            rule_id = self._identifier(rule_id, "rule_id")
            name = self._text(name, "name")

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT MAX(version) AS version FROM risk_rules WHERE rule_id=?", (rule_id,)
                ).fetchone()
                version = (row["version"] or 0) + 1
                connection.execute(
                    "INSERT INTO risk_rules(rule_id,version,name,rule_type,params_json,measure,risk_score,"
                    "created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (rule_id, version, name, rule_type, canonical_json(normalized), measure, risk_score,
                     actor_id, self._now()),
                )
                append_event(connection, actor_id=actor_id, action="rule.upserted",
                             resource_type="risk_rule", resource_id=rule_id,
                             detail={"version": version, "rule_type": rule_type, "measure": measure,
                                     "risk_score": risk_score, "params": normalized},
                             occurred_at=self._now())
                return "risk_rule", rule_id, {"rule_id": rule_id, "version": version}

            return self._idempotent(connection, request_id=request_id,
                                    action="upsert_rule", payload=payload, create=create)

    @staticmethod
    def _rule_view(row) -> dict[str, Any]:
        return {"rule_id": row["rule_id"], "version": row["version"], "name": row["name"],
                "rule_type": row["rule_type"], "params": json.loads(row["params_json"]),
                "measure": row["measure"], "risk_score": row["risk_score"],
                "created_by": row["created_by"], "created_at": row["created_at"]}

    _LATEST_RULES_SQL = (
        "SELECT r.* FROM risk_rules r "
        "JOIN (SELECT rule_id, MAX(version) AS version FROM risk_rules GROUP BY rule_id) latest "
        "ON r.rule_id=latest.rule_id AND r.version=latest.version ORDER BY r.rule_id"
    )

    def list_rules(self) -> list[dict[str, Any]]:
        """列出每条规则的最新版本。"""

        rows = self.database.connection.execute(self._LATEST_RULES_SQL).fetchall()
        return [self._rule_view(row) for row in rows]

    def _active_rules(self, connection) -> list[dict[str, Any]]:
        rows = connection.execute(self._LATEST_RULES_SQL).fetchall()
        return [self._rule_view(row) for row in rows]

    # ---- 授权 ----

    def _target_pattern(self, value: Any) -> str:
        pattern = str(value).strip()
        base = pattern[:-1] if pattern.endswith("*") else pattern
        self._identifier(base, "target_pattern")
        return pattern

    def grant_authorization(self, *, request_id: str, actor_id: str, authorization_id: str,
                            subject_id: str, target_pattern: str, quota: Any,
                            window_seconds: Any) -> WriteReceipt:
        """授予主体对目标范围的访问额度。"""

        if isinstance(quota, bool) or not isinstance(quota, int) or quota <= 0:
            raise ValidationError("quota 必须是正整数")
        if isinstance(window_seconds, bool) or not isinstance(window_seconds, int) or window_seconds <= 0:
            raise ValidationError("window_seconds 必须是正整数")
        payload = {"actor_id": actor_id, "authorization_id": authorization_id, "subject_id": subject_id,
                   "target_pattern": target_pattern, "quota": quota, "window_seconds": window_seconds}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            authorization_id = self._identifier(authorization_id, "authorization_id")
            subject_id = self._identifier(subject_id, "subject_id")
            target_pattern = self._target_pattern(target_pattern)

            def create() -> tuple[str, str, dict[str, Any]]:
                try:
                    connection.execute(
                        "INSERT INTO authorizations(authorization_id,subject_id,target_pattern,quota,"
                        "window_seconds,status,created_by,created_at) VALUES(?,?,?,?,?,'active',?,?)",
                        (authorization_id, subject_id, target_pattern, quota, window_seconds,
                         actor_id, self._now()),
                    )
                except Exception as exc:
                    raise ConflictError("授权编号已经存在") from exc
                append_event(connection, actor_id=actor_id, action="authorization.granted",
                             resource_type="authorization", resource_id=authorization_id,
                             detail={"subject_id": subject_id, "target_pattern": target_pattern,
                                     "quota": quota, "window_seconds": window_seconds},
                             occurred_at=self._now())
                return "authorization", authorization_id, {"authorization_id": authorization_id}

            return self._idempotent(connection, request_id=request_id,
                                    action="grant_authorization", payload=payload, create=create)

    def revoke_authorization(self, *, request_id: str, actor_id: str, authorization_id: str) -> WriteReceipt:
        """撤销授权,撤销后立即参与后续判定。"""

        payload = {"actor_id": actor_id, "authorization_id": authorization_id}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT * FROM authorizations WHERE authorization_id=?", (authorization_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError("授权不存在")
                if row["status"] != "active":
                    raise ConflictError("授权已撤销")
                connection.execute(
                    "UPDATE authorizations SET status='revoked', revoked_at=? WHERE authorization_id=?",
                    (self._now(), authorization_id),
                )
                append_event(connection, actor_id=actor_id, action="authorization.revoked",
                             resource_type="authorization", resource_id=authorization_id,
                             detail={"subject_id": row["subject_id"]}, occurred_at=self._now())
                return "authorization", authorization_id, {"authorization_id": authorization_id,
                                                           "status": "revoked"}

            return self._idempotent(connection, request_id=request_id,
                                    action="revoke_authorization", payload=payload, create=create)

    def get_authorization(self, authorization_id: str) -> dict[str, Any]:
        """返回授权详情与累计扣减次数,用于核对额度。"""

        row = self.database.connection.execute(
            "SELECT * FROM authorizations WHERE authorization_id=?", (authorization_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError("授权不存在")
        used = self.database.connection.execute(
            "SELECT COUNT(*) AS count FROM quota_ledger WHERE authorization_id=?", (authorization_id,)
        ).fetchone()["count"]
        return {"authorization_id": row["authorization_id"], "subject_id": row["subject_id"],
                "target_pattern": row["target_pattern"], "quota": row["quota"],
                "window_seconds": row["window_seconds"], "status": row["status"],
                "deducted_total": used, "created_by": row["created_by"],
                "created_at": row["created_at"], "revoked_at": row["revoked_at"]}

    @staticmethod
    def _match_authorization(connection, subject_id: str, target_id: str):
        rows = connection.execute(
            "SELECT * FROM authorizations WHERE subject_id=? AND status='active' "
            "ORDER BY created_at, authorization_id",
            (subject_id,),
        ).fetchall()
        best = None
        best_specificity = -1
        for row in rows:
            pattern = row["target_pattern"]
            if pattern.endswith("*"):
                prefix = pattern[:-1]
                if target_id.startswith(prefix) and len(prefix) > best_specificity:
                    best, best_specificity = row, len(prefix)
            elif pattern == target_id and len(pattern) + 1 > best_specificity:
                best, best_specificity = row, len(pattern) + 1
        return best

    # ---- 动作判定 ----

    def _action_count(self, connection, subject_id: str, moment: datetime, window_seconds: int) -> int:
        since = self._moment(moment - timedelta(seconds=window_seconds))
        return connection.execute(
            "SELECT COUNT(*) AS count FROM action_log WHERE subject_id=? AND occurred_at>? AND occurred_at<=?",
            (subject_id, since, self._moment(moment)),
        ).fetchone()["count"]

    def _target_count(self, connection, subject_id: str, moment: datetime, window_seconds: int) -> int:
        since = self._moment(moment - timedelta(seconds=window_seconds))
        return connection.execute(
            "SELECT COUNT(DISTINCT target_id) AS count FROM action_log "
            "WHERE subject_id=? AND occurred_at>? AND occurred_at<=?",
            (subject_id, since, self._moment(moment)),
        ).fetchone()["count"]

    def _ledger_count(self, connection, authorization_id: str, moment: datetime, window_seconds: int) -> int:
        since = self._moment(moment - timedelta(seconds=window_seconds))
        return connection.execute(
            "SELECT COUNT(*) AS count FROM quota_ledger WHERE authorization_id=? AND deducted_at>? AND deducted_at<=?",
            (authorization_id, since, self._moment(moment)),
        ).fetchone()["count"]

    def _set_task_status(self, connection, task_id: str, subject_id: str, status: str) -> None:
        connection.execute(
            "INSERT INTO task_states(task_id,subject_id,status,updated_at) VALUES(?,?,?,?) "
            "ON CONFLICT(task_id) DO UPDATE SET status=excluded.status, updated_at=excluded.updated_at",
            (task_id, subject_id, status, self._now()),
        )

    def ingest_action(self, *, actor_id: str, action_id: str, subject_id: str, target_id: str,
                      action_type: str, task_id: str, occurred_at: Any,
                      metadata: Any = None) -> dict[str, Any]:
        """接收一条动作记录并完成风险判定;同一 action_id 重复上报直接返回原判定。"""

        metadata = {} if metadata is None else metadata
        if not isinstance(metadata, dict):
            raise ValidationError("metadata 必须是对象")
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "admin", "operator")
            action_id = self._identifier(action_id, "action_id")
            subject_id = self._identifier(subject_id, "subject_id")
            target_id = self._identifier(target_id, "target_id")
            task_id = self._identifier(task_id, "task_id")
            action_type = self._text(action_type, "action_type", 80)
            moment = self._parse_moment(occurred_at, "occurred_at")
            occurred = self._moment(moment)

            existing = connection.execute(
                "SELECT * FROM decisions WHERE action_id=?", (action_id,)
            ).fetchone()
            if existing is not None:
                return self._decision_view(connection, existing, replayed=True)

            connection.execute(
                "INSERT INTO action_log(action_id,subject_id,target_id,action_type,task_id,occurred_at,"
                "received_at,metadata_json) VALUES(?,?,?,?,?,?,?,?)",
                (action_id, subject_id, target_id, action_type, task_id, occurred,
                 self._moment(self.clock.now()), canonical_json(metadata)),
            )

            rules = self._active_rules(connection)
            authorization = self._match_authorization(connection, subject_id, target_id)
            quota_remaining = None
            if authorization is not None:
                used = self._ledger_count(connection, authorization["authorization_id"],
                                          moment, authorization["window_seconds"])
                quota_remaining = authorization["quota"] - used

            task_row = connection.execute(
                "SELECT * FROM task_states WHERE task_id=?", (task_id,)).fetchone()
            task_status = task_row["status"] if task_row else "running"
            open_rows = connection.execute(
                "SELECT * FROM interventions WHERE task_id=? AND status IN ('pending','active')",
                (task_id,),
            ).fetchall()
            subject_throttle = connection.execute(
                "SELECT * FROM interventions WHERE subject_id=? AND kind='throttle' AND status='active' "
                "AND expires_at>? ORDER BY created_at DESC, intervention_id DESC LIMIT 1",
                (subject_id, occurred),
            ).fetchone()

            triggered: list[dict[str, Any]] = []
            if task_status == "suspended":
                kinds = {row["kind"] for row in open_rows}
                rule_id = "system:task-under-review" if "review" in kinds else "system:task-suspended"
                triggered.append({"rule_id": rule_id, "version": 0, "name": "任务处于阻断状态",
                                  "rule_type": "system", "measure": "suspend", "risk_score": 100,
                                  "params": {},
                                  "detail": "任务已被暂停,后续动作保持阻断并等待复核结论"})
            if subject_throttle is not None:
                triggered.append({"rule_id": "system:subject-throttled", "version": 0,
                                  "name": "主体处于限流中", "rule_type": "system",
                                  "measure": "throttle", "risk_score": 0, "params": {},
                                  "detail": f"限流有效期至 {subject_throttle['expires_at']}"})
            for rule in rules:
                frequency = None
                distinct_targets = None
                if rule["rule_type"] == "frequency_spike":
                    frequency = self._action_count(connection, subject_id, moment,
                                                   rule["params"]["window_seconds"])
                elif rule["rule_type"] == "target_scatter":
                    distinct_targets = self._target_count(connection, subject_id, moment,
                                                          rule["params"]["window_seconds"])
                hit, detail = rule_hit(rule, authorization_matched=authorization is not None,
                                       quota_remaining=quota_remaining, frequency=frequency,
                                       distinct_targets=distinct_targets)
                if hit:
                    triggered.append({"rule_id": rule["rule_id"], "version": rule["version"],
                                      "name": rule["name"], "rule_type": rule["rule_type"],
                                      "measure": rule["measure"], "risk_score": rule["risk_score"],
                                      "params": rule["params"], "detail": detail})

            measure = strongest_measure([item["measure"] for item in triggered])
            risk_score = min(100, sum(item["risk_score"] for item in triggered))

            if measure in ("allow", "throttle") and authorization is not None:
                connection.execute(
                    "INSERT INTO quota_ledger(authorization_id,action_id,deducted_at) VALUES(?,?,?)",
                    (authorization["authorization_id"], action_id, occurred),
                )

            decision_id = uuid.uuid4().hex
            snapshot = [{"rule_id": rule["rule_id"], "version": rule["version"], "name": rule["name"],
                         "rule_type": rule["rule_type"], "params": rule["params"],
                         "measure": rule["measure"], "risk_score": rule["risk_score"]}
                        for rule in rules]
            connection.execute(
                "INSERT INTO decisions(decision_id,action_id,subject_id,target_id,task_id,risk_score,"
                "measure,triggered_json,snapshot_json,decided_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (decision_id, action_id, subject_id, target_id, task_id, risk_score, measure,
                 canonical_json(triggered), canonical_json(snapshot), self._now()),
            )

            interventions = self._apply_interventions(
                connection, decision_id=decision_id, measure=measure, subject_id=subject_id,
                task_id=task_id, moment=moment, triggered=triggered, open_rows=open_rows,
                subject_throttle=subject_throttle)
            append_event(connection, actor_id=actor_id, action="action.decided",
                         resource_type="decision", resource_id=decision_id,
                         detail={"action_id": action_id, "subject_id": subject_id,
                                 "target_id": target_id, "task_id": task_id, "measure": measure,
                                 "risk_score": risk_score,
                                 "triggered": [item["rule_id"] for item in triggered],
                                 "interventions": [item["intervention_id"] for item in interventions]},
                         occurred_at=self._now())
            row = connection.execute(
                "SELECT * FROM decisions WHERE decision_id=?", (decision_id,)).fetchone()
            return self._decision_view(connection, row, replayed=False)

    def _apply_interventions(self, connection, *, decision_id: str, measure: str, subject_id: str,
                             task_id: str, moment: datetime, triggered: list[dict[str, Any]],
                             open_rows, subject_throttle) -> list[dict[str, Any]]:
        created: list[dict[str, Any]] = []
        task_held = any((row["kind"] == "review" and row["status"] == "pending")
                        or (row["kind"] == "suspend" and row["status"] == "active")
                        for row in open_rows)
        if task_held:
            # 任务已被既有干预阻断:本次判定只留证据,不重复创建干预。
            self._set_task_status(connection, task_id, subject_id, "suspended")
            return created
        if measure == "throttle":
            self._set_task_status(connection, task_id, subject_id, "running")
            if subject_throttle is None:
                seconds = DEFAULT_THROTTLE_SECONDS
                for item in triggered:
                    if item["measure"] == "throttle" and item["rule_type"] != "system":
                        seconds = item["params"].get("throttle_seconds", DEFAULT_THROTTLE_SECONDS)
                        break
                expires = self._moment(moment + timedelta(seconds=seconds))
                intervention_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO interventions(intervention_id,decision_id,subject_id,task_id,kind,status,"
                    "detail_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    (intervention_id, decision_id, subject_id, task_id, "throttle", "active",
                     canonical_json({"triggered_rules": [item["rule_id"] for item in triggered],
                                     "throttle_seconds": seconds}),
                     self._now(), expires),
                )
                append_event(connection, actor_id="system", action="intervention.created",
                             resource_type="intervention", resource_id=intervention_id,
                             detail={"kind": "throttle", "subject_id": subject_id, "task_id": task_id,
                                     "expires_at": expires},
                             occurred_at=self._now())
                created.append({"intervention_id": intervention_id, "kind": "throttle", "status": "active"})
        elif measure in ("review", "suspend"):
            kind = "review" if measure == "review" else "suspend"
            status = "pending" if measure == "review" else "active"
            if not any(row["kind"] == kind and row["status"] == status for row in open_rows):
                intervention_id = uuid.uuid4().hex
                connection.execute(
                    "INSERT INTO interventions(intervention_id,decision_id,subject_id,task_id,kind,status,"
                    "detail_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,NULL)",
                    (intervention_id, decision_id, subject_id, task_id, kind, status,
                     canonical_json({"triggered_rules": [item["rule_id"] for item in triggered]}),
                     self._now()),
                )
                append_event(connection, actor_id="system", action="intervention.created",
                             resource_type="intervention", resource_id=intervention_id,
                             detail={"kind": kind, "subject_id": subject_id, "task_id": task_id},
                             occurred_at=self._now())
                created.append({"intervention_id": intervention_id, "kind": kind, "status": status})
            self._set_task_status(connection, task_id, subject_id, "suspended")
        else:
            self._set_task_status(connection, task_id, subject_id, "running")
        return created

    # ---- 判定解释 ----

    @staticmethod
    def _intervention_view(row) -> dict[str, Any]:
        return {"intervention_id": row["intervention_id"], "decision_id": row["decision_id"],
                "subject_id": row["subject_id"], "task_id": row["task_id"], "kind": row["kind"],
                "status": row["status"], "detail": json.loads(row["detail_json"]),
                "created_at": row["created_at"], "expires_at": row["expires_at"],
                "resolved_at": row["resolved_at"], "resolved_by": row["resolved_by"],
                "resolution": row["resolution"], "resolution_note": row["resolution_note"]}

    def _decision_view(self, connection, decision_row, *, replayed: bool) -> dict[str, Any]:
        interventions = connection.execute(
            "SELECT * FROM interventions WHERE decision_id=? ORDER BY created_at, intervention_id",
            (decision_row["decision_id"],),
        ).fetchall()
        return {"decision_id": decision_row["decision_id"], "action_id": decision_row["action_id"],
                "subject_id": decision_row["subject_id"], "target_id": decision_row["target_id"],
                "task_id": decision_row["task_id"], "risk_score": decision_row["risk_score"],
                "measure": decision_row["measure"],
                "triggered_rules": json.loads(decision_row["triggered_json"]),
                "rule_snapshot": json.loads(decision_row["snapshot_json"]),
                "interventions": [self._intervention_view(row) for row in interventions],
                "decided_at": decision_row["decided_at"], "replayed": replayed}

    def get_decision(self, action_id: str) -> dict[str, Any]:
        """解释一次判定:触发了哪些规则、当时的规则快照以及最终采取的措施。"""

        row = self.database.connection.execute(
            "SELECT * FROM decisions WHERE action_id=?", (action_id,)).fetchone()
        if row is None:
            raise NotFoundError("判定不存在")
        view = self._decision_view(self.database.connection, row, replayed=False)
        del view["replayed"]
        return view

    # ---- 干预队列与人工复核 ----

    def list_interventions(self, status: str | None = None) -> list[dict[str, Any]]:
        """列出干预队列;重启后未处理的 pending/active 干预仍然保留。"""

        if status is not None and status not in INTERVENTION_STATUSES:
            raise ValidationError("status 不在允许范围内")
        query = "SELECT * FROM interventions"
        parameters: list[Any] = []
        if status is not None:
            query += " WHERE status=?"
            parameters.append(status)
        query += " ORDER BY created_at, intervention_id"
        rows = self.database.connection.execute(query, parameters).fetchall()
        return [self._intervention_view(row) for row in rows]

    def get_task(self, task_id: str) -> dict[str, Any]:
        row = self.database.connection.execute(
            "SELECT * FROM task_states WHERE task_id=?", (task_id,)).fetchone()
        if row is None:
            raise NotFoundError("任务不存在")
        return {"task_id": row["task_id"], "subject_id": row["subject_id"],
                "status": row["status"], "updated_at": row["updated_at"]}

    def resolve_intervention(self, *, request_id: str, actor_id: str, intervention_id: str,
                             resolution: str, note: str = "") -> WriteReceipt:
        """复核处置:resumed 在证据不足时恢复任务,confirmed 维持阻断。"""

        if resolution not in RESOLUTIONS:
            raise ValidationError("resolution 必须是 resumed 或 confirmed")
        note = str(note).strip()
        if len(note) > 500:
            raise ValidationError("note 不能超过 500 个字符")
        payload = {"actor_id": actor_id, "intervention_id": intervention_id,
                   "resolution": resolution, "note": note}
        with self.database.transaction(immediate=True) as connection:
            actor = self._actor(connection, actor_id)
            self._require(actor, "reviewer", "admin")

            def create() -> tuple[str, str, dict[str, Any]]:
                row = connection.execute(
                    "SELECT * FROM interventions WHERE intervention_id=?", (intervention_id,)
                ).fetchone()
                if row is None:
                    raise NotFoundError("干预不存在")
                if row["status"] == "resolved":
                    raise ConflictError("干预已处理")
                now = self._now()
                connection.execute(
                    "UPDATE interventions SET status='resolved', resolved_at=?, resolved_by=?, "
                    "resolution=?, resolution_note=? WHERE intervention_id=?",
                    (now, actor_id, resolution, note, intervention_id),
                )
                if resolution == "resumed":
                    remaining = connection.execute(
                        "SELECT COUNT(*) AS count FROM interventions WHERE task_id=? AND "
                        "((kind='review' AND status='pending') OR (kind='suspend' AND status='active'))",
                        (row["task_id"],),
                    ).fetchone()["count"]
                    if remaining == 0:
                        self._set_task_status(connection, row["task_id"], row["subject_id"], "running")
                        append_event(connection, actor_id=actor_id, action="task.resumed",
                                     resource_type="task", resource_id=row["task_id"],
                                     detail={"intervention_id": intervention_id, "note": note},
                                     occurred_at=now)
                elif row["kind"] == "review":
                    existing = connection.execute(
                        "SELECT 1 FROM interventions WHERE task_id=? AND kind='suspend' AND status='active'",
                        (row["task_id"],),
                    ).fetchone()
                    if existing is None:
                        suspend_id = uuid.uuid4().hex
                        connection.execute(
                            "INSERT INTO interventions(intervention_id,decision_id,subject_id,task_id,kind,"
                            "status,detail_json,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,NULL)",
                            (suspend_id, row["decision_id"], row["subject_id"], row["task_id"],
                             "suspend", "active",
                             canonical_json({"escalated_from": intervention_id}), now),
                        )
                        append_event(connection, actor_id=actor_id, action="intervention.created",
                                     resource_type="intervention", resource_id=suspend_id,
                                     detail={"kind": "suspend", "subject_id": row["subject_id"],
                                             "task_id": row["task_id"],
                                             "escalated_from": intervention_id},
                                     occurred_at=now)
                append_event(connection, actor_id=actor_id, action="intervention.resolved",
                             resource_type="intervention", resource_id=intervention_id,
                             detail={"resolution": resolution, "note": note, "kind": row["kind"],
                                     "task_id": row["task_id"]},
                             occurred_at=now)
                task = connection.execute(
                    "SELECT status FROM task_states WHERE task_id=?", (row["task_id"],)).fetchone()
                return "intervention", intervention_id, {
                    "intervention_id": intervention_id, "resolution": resolution,
                    "task_status": task["status"] if task else "running"}

            return self._idempotent(connection, request_id=request_id,
                                    action="resolve_intervention", payload=payload, create=create)
