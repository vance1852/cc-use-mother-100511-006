"""运行基础服务的离线端到端验收。"""

from __future__ import annotations

import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .clock import FixedClock
from .intervention import InterventionService
from .storage import Database


def run() -> dict[str, object]:
    """执行一条完整登记链与访问行为干预链并返回结果。"""

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "acceptance.sqlite3"
        database = Database(path)
        clock = FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc))
        service = InterventionService(database, clock)
        service.register_organization(request_id="req-org", actor_id="bootstrap",
                                      organization_id="org-001", name="示范科研机构")
        service.register_actor(request_id="req-admin", actor_id="bootstrap", new_actor_id="admin-001",
                               display_name="系统管理员", role="admin", organization_id="org-001")
        service.register_actor(request_id="req-operator", actor_id="admin-001", new_actor_id="operator-001",
                               display_name="项目负责人", role="operator", organization_id="org-001")
        service.register_actor(request_id="req-reviewer", actor_id="admin-001", new_actor_id="reviewer-001",
                               display_name="复核人员", role="reviewer", organization_id="org-001")
        service.register_site(request_id="req-site", actor_id="operator-001", site_id="site-001",
                              organization_id="org-001", name="一号创新节点", timezone_name="Asia/Shanghai")
        first = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                           category="institution_profile", external_key="record-001",
                                           data={"name": "基础资料", "enabled": True})
        replay = service.record_domain_data(request_id="req-data", actor_id="operator-001", site_id="site-001",
                                            category="institution_profile", external_key="record-001",
                                            data={"name": "基础资料", "enabled": True})

        # —— 访问行为判定与干预：红队智能体连续尝试不同入口 ——
        service.register_subject(request_id="req-subject", actor_id="operator-001", subject_id="agent-007",
                                 organization_id="org-001", display_name="红队智能体", trust_tier="medium")
        service.create_grant(request_id="req-grant", actor_id="operator-001", grant_id="grant-entry",
                             subject_id="agent-007", target_pattern="api:entry:*", action_type="invoke",
                             quota_limit=50, quota_window_seconds=300,
                             valid_from="2026-09-25T00:00:00Z", valid_until="2026-09-26T00:00:00Z")
        service.create_rule(request_id="req-rule-frequency", actor_id="admin-001", rule_id="rule-frequency",
                            name="高频访问限流", rule_type="frequency_spike",
                            params={"window_seconds": 60, "max_actions": 2}, score=30, measure="throttle")
        service.create_rule(request_id="req-rule-diversity", actor_id="admin-001", rule_id="rule-diversity",
                            name="多入口探测复核", rule_type="target_diversity",
                            params={"window_seconds": 300, "max_distinct_targets": 3},
                            score=60, measure="review")
        service.create_rule(request_id="req-rule-unauthorized", actor_id="admin-001",
                            rule_id="rule-unauthorized", name="未授权目标暂停",
                            rule_type="unauthorized_target", params={}, score=80, measure="suspend")

        def ingest(request_id: str, action_id: str, target: str, occurred_at: str):
            return service.ingest_action(request_id=request_id, actor_id="operator-001",
                                         action_id=action_id, subject_id="agent-007", target=target,
                                         action_type="invoke", occurred_at=occurred_at,
                                         metadata={"source": "red-team"})

        r1 = ingest("req-a1", "a-001", "api:entry:1", "2026-09-25T08:00:00Z")
        r2 = ingest("req-a2", "a-002", "api:entry:2", "2026-09-25T08:00:10Z")
        r3 = ingest("req-a3", "a-003", "api:entry:3", "2026-09-25T08:00:20Z")  # 频率超限 → 限流
        duplicate = service.ingest_action(request_id="req-a2-retry", actor_id="operator-001",
                                          action_id="a-002", subject_id="agent-007", target="api:entry:2",
                                          action_type="invoke", occurred_at="2026-09-25T08:00:10Z",
                                          metadata={"source": "red-team"})
        r4 = ingest("req-a4", "a-004", "api:entry:4", "2026-09-25T08:00:30Z")  # 入口过多 → 转人工复核并暂停
        r5 = ingest("req-a5", "a-005", "api:entry:5", "2026-09-25T08:00:40Z")  # 干预未解除 → 直接阻断
        r4_explain = service.explain_decision(r4.decision_id)
        pending = service.list_interventions(status="pending")
        r5_explain = service.explain_decision(r5.decision_id)
        blocked_without_new_intervention = (
            r5.measure == "review"
            and r5_explain["intervention"]["intervention_id"] == pending[0].intervention_id
        )
        # 复核人员证据不足时恢复任务
        service.resolve_intervention(request_id="req-release-1", actor_id="reviewer-001",
                                     intervention_id=pending[0].intervention_id, resolution="release",
                                     reason="证据不足：入口均在授权范围内")
        # 规则更新只影响之后的判定
        service.update_rule(request_id="req-rule-frequency-v2", actor_id="admin-001",
                            rule_id="rule-frequency", name="高频访问限流", rule_type="frequency_spike",
                            params={"window_seconds": 60, "max_actions": 1}, score=40, measure="throttle")
        r3_explain = service.explain_decision(r3.decision_id)
        old_decision_unchanged = (
            r3_explain["measure"] == "throttle"
            and r3_explain["triggered_rules"][0]["rule_id"] == "rule-frequency"
            and r3_explain["triggered_rules"][0]["version"] == 1
            and r3_explain["triggered_rules"][0]["evidence"]["max_actions"] == 2
        )
        r6 = ingest("req-a6", "a-006", "api:entry:1", "2026-09-25T08:00:50Z")  # 再次转人工复核
        database.close()

        # 重启后尚未处理的干预队列继续保留，复核可以继续进行
        restarted_database = Database(path)
        restarted = InterventionService(
            restarted_database, FixedClock(datetime(2026, 9, 25, 9, 0, tzinfo=timezone.utc)))
        pending_after_restart = restarted.list_interventions(status="pending")
        restarted.resolve_intervention(request_id="req-release-2", actor_id="reviewer-001",
                                       intervention_id=pending_after_restart[0].intervention_id,
                                       resolution="release", reason="证据不足：复核后确认无恶意")
        subject_after_restart = restarted.get_subject("agent-007")
        r7 = restarted.ingest_action(request_id="req-a7", actor_id="operator-001", action_id="a-007",
                                     subject_id="agent-007", target="db:finance:ledger",
                                     action_type="invoke", occurred_at="2026-09-25T08:10:00Z",
                                     metadata={"source": "red-team"})
        valid, event_count = restarted.verify_audit()
        records = restarted.list_domain_data("site-001")
        result = {"status": "ok", "records": len(records), "audit_events": event_count,
                  "audit_valid": valid, "first_replayed": first.replayed,
                  "second_replayed": replay.replayed,
                  "measures": [r1.measure, r2.measure, r3.measure, r4.measure, r5.measure],
                  "duplicate_decision_same": duplicate.duplicate and duplicate.decision_id == r2.decision_id,
                  "quota_not_double_deducted": r4_explain["features"]["quota_remaining"] == 47,
                  "blocked_without_new_intervention": blocked_without_new_intervention,
                  "old_decision_unchanged": old_decision_unchanged,
                  "review_after_rule_update": r6.measure,
                  "pending_after_restart": len(pending_after_restart),
                  "resumed_after_restart": subject_after_restart.status == "active",
                  "unauthorized_measure": r7.measure}
        restarted_database.close()
        return result


def main() -> int:
    """打印验收结果并设置退出码。"""

    result = run()
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0 if result["status"] == "ok" and result["audit_valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
