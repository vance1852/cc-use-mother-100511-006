"""运行基础服务与访问行为干预链路的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .intervention import InterventionService
from .storage import Database

CLOCK = FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc))


def _foundation_chain(service: InterventionService) -> dict[str, object]:
    """执行原有登记链,验证基础能力不受影响。"""

    service.register_organization(request_id="req-org", actor_id="bootstrap",
                                  organization_id="org-001", name="示范科研机构")
    service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                           display_name="系统管理员", role="admin", organization_id="org-001")
    service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                           display_name="项目负责人", role="operator", organization_id="org-001")
    service.register_actor(request_id="req-reviewer", actor_id="admin-001", new_actor_id="reviewer-001",
                           display_name="复核员", role="reviewer", organization_id="org-001")
    service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                          organization_id="org-001", name="一号创新节点", timezone_name="Asia/Shanghai")
    first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                       category="institution_profile", external_key="record-001",
                                       data={"name": "基础资料", "enabled": True})
    replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                        category="institution_profile", external_key="record-001",
                                        data={"name": "基础资料", "enabled": True})
    return {"first_replayed": first.replayed, "second_replayed": replay.replayed,
            "records": len(service.list_domain_data("site-001"))}


def _intervention_chain(service: InterventionService) -> dict[str, object]:
    """执行动作判定、干预、复核与恢复链路。"""

    service.upsert_rule(request_id="req-rule-freq", actor_id="admin-001", rule_id="rule-frequency",
                        name="高频动作限流", rule_type="frequency_spike",
                        params={"window_seconds": 60, "max_actions": 3, "throttle_seconds": 120},
                        measure="throttle", risk_score=40)
    service.upsert_rule(request_id="req-rule-scatter", actor_id="admin-001", rule_id="rule-scatter",
                        name="多入口探测复核", rule_type="target_scatter",
                        params={"window_seconds": 300, "max_targets": 2},
                        measure="review", risk_score=70)
    service.upsert_rule(request_id="req-rule-unauth", actor_id="admin-001", rule_id="rule-unauthorized",
                        name="未授权目标暂停", rule_type="unauthorized_target", params={},
                        measure="suspend", risk_score=90)
    service.grant_authorization(request_id="req-auth", actor_id="admin-001", authorization_id="auth-001",
                                subject_id="agent-007", target_pattern="portal-*", quota=10,
                                window_seconds=60)

    def act(action_id: str, target: str, occurred_at: str) -> dict[str, object]:
        return service.ingest_action(actor_id="operator-001", action_id=action_id,
                                     subject_id="agent-007", target_id=target,
                                     action_type="http_request", task_id="task-001",
                                     occurred_at=occurred_at)

    # 阶段一:连续探测不同入口触发人工复核,任务被挂起。
    act("act-001", "portal-a", "2026-09-25T08:00:01Z")
    act("act-002", "portal-b", "2026-09-25T08:00:02Z")
    scatter = act("act-003", "portal-c", "2026-09-25T08:00:03Z")
    held_replay = act("act-003", "portal-c", "2026-09-25T08:00:03Z")
    quota_after_replay = service.get_authorization("auth-001")["deducted_total"]
    blocked = act("act-004", "portal-d", "2026-09-25T08:00:04Z")

    # 复核人员认为证据不足,恢复任务。
    pending = service.list_interventions(status="pending")
    service.resolve_intervention(request_id="req-resolve-1", actor_id="reviewer-001",
                                 intervention_id=pending[0]["intervention_id"],
                                 resolution="resumed", note="证据不足,恢复任务")
    task_after_resume = service.get_task("task-001")["status"]

    # 阶段二:窗口滑出后高频动作触发限流,限流期内不重复建干预。
    act("act-005", "portal-a", "2026-09-25T08:06:01Z")
    act("act-006", "portal-a", "2026-09-25T08:06:02Z")
    act("act-007", "portal-a", "2026-09-25T08:06:03Z")
    throttled = act("act-008", "portal-a", "2026-09-25T08:06:04Z")
    act("act-009", "portal-a", "2026-09-25T08:06:05Z")

    # 阶段三:访问未授权目标触发暂停,复核后再次恢复。
    unauthorized = act("act-010", "db-prod", "2026-09-25T08:06:06Z")
    suspends = [item for item in service.list_interventions(status="active") if item["kind"] == "suspend"]
    service.resolve_intervention(request_id="req-resolve-2", actor_id="reviewer-001",
                                 intervention_id=suspends[0]["intervention_id"],
                                 resolution="resumed", note="误报,恢复")

    service.upsert_rule(request_id="req-rule-scatter-v2", actor_id="admin-001", rule_id="rule-scatter",
                        name="多入口探测复核", rule_type="target_scatter",
                        params={"window_seconds": 300, "max_targets": 5},
                        measure="review", risk_score=70)
    explained = service.get_decision("act-003")
    snapshot_version = [item["version"] for item in explained["rule_snapshot"]
                        if item["rule_id"] == "rule-scatter"][0]
    current_version = [item for item in service.list_rules()
                       if item["rule_id"] == "rule-scatter"][0]["version"]

    open_queue = service.list_interventions(status="pending") + service.list_interventions(status="active")
    return {"scatter_measure": scatter["measure"],
            "held_replay_detected": held_replay["replayed"],
            "quota_after_replay": quota_after_replay,
            "blocked_measure": blocked["measure"],
            "task_after_resume": task_after_resume,
            "throttle_measure": throttled["measure"],
            "throttle_interventions": len([item for item in service.list_interventions()
                                           if item["kind"] == "throttle"]),
            "unauthorized_measure": unauthorized["measure"],
            "snapshot_rule_version": snapshot_version,
            "current_rule_version": current_version,
            "quota_final": service.get_authorization("auth-001")["deducted_total"],
            "open_queue_before_restart": len(open_queue)}


def run() -> dict[str, object]:
    """执行完整验收链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "acceptance.sqlite3"
        database = Database(path)
        service = InterventionService(database, CLOCK)
        foundation = _foundation_chain(service)
        intervention = _intervention_chain(service)
        database.close()

        reopened = Database(path)
        reopened_service = InterventionService(reopened, CLOCK)
        queue_after_restart = (len(reopened_service.list_interventions(status="pending"))
                               + len(reopened_service.list_interventions(status="active")))
        valid, event_count = reopened_service.verify_audit()
        reopened.close()

        intervention["open_queue_after_restart"] = queue_after_restart
        return {"status": "ok", "records": foundation["records"], "audit_events": event_count,
                "audit_valid": valid, "first_replayed": foundation["first_replayed"],
                "second_replayed": foundation["second_replayed"], "intervention": intervention}


EXPECTED_INTERVENTION = {
    "scatter_measure": "review",
    "held_replay_detected": True,
    "quota_after_replay": 2,
    "blocked_measure": "suspend",
    "task_after_resume": "running",
    "throttle_measure": "throttle",
    "throttle_interventions": 1,
    "unauthorized_measure": "suspend",
    "snapshot_rule_version": 1,
    "current_rule_version": 2,
    "quota_final": 7,
}


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    intervention = result["intervention"]
    expectations_met = all(intervention[key] == value for key, value in EXPECTED_INTERVENTION.items())
    queue_preserved = (intervention["open_queue_after_restart"]
                       == intervention["open_queue_before_restart"] > 0)
    ok = result["status"] == "ok" and result["audit_valid"] and expectations_met and queue_preserved
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
