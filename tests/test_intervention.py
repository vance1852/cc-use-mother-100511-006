import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ai_governance_foundation.api import route
from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import ConflictError, PermissionDenied, ValidationError
from ai_governance_foundation.intervention import InterventionService
from ai_governance_foundation.storage import Database


class InterventionTest(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = InterventionService(
            self.database, FixedClock(datetime(2026, 10, 1, tzinfo=timezone.utc)))
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="治理机构")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="op", actor_id="admin1", new_actor_id="op1",
                                    display_name="操作员", role="operator", organization_id="o1")
        self.service.register_actor(request_id="rev", actor_id="admin1", new_actor_id="rev1",
                                    display_name="复核员", role="reviewer", organization_id="o1")

    def tearDown(self):
        self.database.close()

    def add_subject(self, subject_id="agent-1", trust_tier="medium"):
        self.service.register_subject(request_id=f"sub-{subject_id}", actor_id="op1",
                                      subject_id=subject_id, organization_id="o1",
                                      display_name="智能体", trust_tier=trust_tier)

    def add_grant(self, grant_id="g1", subject_id="agent-1", pattern="api:*", quota=100, window=300):
        self.service.create_grant(request_id=f"grant-{grant_id}", actor_id="op1", grant_id=grant_id,
                                  subject_id=subject_id, target_pattern=pattern, action_type="invoke",
                                  quota_limit=quota, quota_window_seconds=window,
                                  valid_from="2026-10-01T00:00:00Z",
                                  valid_until="2026-10-02T00:00:00Z")

    def add_rule(self, rule_id, rule_type, params, score, measure):
        self.service.create_rule(request_id=f"rule-{rule_id}", actor_id="admin1", rule_id=rule_id,
                                 name=rule_id, rule_type=rule_type, params=params,
                                 score=score, measure=measure)

    def ingest(self, action_id, target="api:res:1", occurred_at="2026-10-01T08:00:00Z",
               subject_id="agent-1", request_id=None):
        return self.service.ingest_action(
            request_id=request_id or f"req-{action_id}", actor_id="op1", action_id=action_id,
            subject_id=subject_id, target=target, action_type="invoke", occurred_at=occurred_at)

    def trigger_review(self):
        self.add_subject()
        self.add_grant()
        self.add_rule("r-div", "target_diversity",
                      {"window_seconds": 300, "max_distinct_targets": 2}, 60, "review")
        self.ingest("a1", target="api:e:1", occurred_at="2026-10-01T08:00:00Z")
        self.ingest("a2", target="api:e:2", occurred_at="2026-10-01T08:00:05Z")
        return self.ingest("a3", target="api:e:3", occurred_at="2026-10-01T08:00:10Z")

    def test_frequency_spike_triggers_throttle(self):
        self.add_subject()
        self.add_grant()
        self.add_rule("r-freq", "frequency_spike", {"window_seconds": 60, "max_actions": 2}, 30, "throttle")
        r1 = self.ingest("a1", occurred_at="2026-10-01T08:00:00Z")
        r2 = self.ingest("a2", occurred_at="2026-10-01T08:00:10Z")
        r3 = self.ingest("a3", occurred_at="2026-10-01T08:00:20Z")
        self.assertEqual("allow", r1.measure)
        self.assertEqual("allow", r2.measure)
        self.assertEqual("throttle", r3.measure)
        explain = self.service.explain_decision(r3.decision_id)
        self.assertEqual("r-freq", explain["triggered_rules"][0]["rule_id"])
        self.assertEqual(3, explain["triggered_rules"][0]["evidence"]["observed_actions"])
        self.assertEqual("throttle", explain["intervention"]["kind"])
        self.assertEqual(1, len(self.service.list_interventions()))

    def test_target_diversity_triggers_review_and_blocks_followup(self):
        r3 = self.trigger_review()
        self.assertEqual("review", r3.measure)
        self.assertEqual("suspended", self.service.get_subject("agent-1").status)
        # 干预未解除时后续动作被直接阻断，且不会重复创建干预
        r4 = self.ingest("a4", target="api:e:4", occurred_at="2026-10-01T08:00:15Z")
        self.assertEqual("review", r4.measure)
        pending = self.service.list_interventions(status="pending")
        self.assertEqual(1, len(pending))
        explain = self.service.explain_decision(r4.decision_id)
        self.assertEqual("open_intervention", explain["triggered_rules"][0]["rule_type"])
        self.assertEqual(pending[0].intervention_id, explain["intervention"]["intervention_id"])

    def test_unauthorized_target_suspends_subject(self):
        self.add_subject()
        self.add_rule("r-unauth", "unauthorized_target", {}, 80, "suspend")
        r1 = self.ingest("a1", target="db:finance:ledger")
        self.assertEqual("suspend", r1.measure)
        self.assertEqual("suspended", self.service.get_subject("agent-1").status)
        explain = self.service.explain_decision(r1.decision_id)
        self.assertEqual("r-unauth", explain["triggered_rules"][0]["rule_id"])
        self.assertEqual("db:finance:ledger", explain["triggered_rules"][0]["evidence"]["target"])

    def test_score_escalation_sends_to_review(self):
        self.add_subject(trust_tier="low")
        self.add_rule("r-unauth", "unauthorized_target", {}, 90, "suspend")
        r1 = self.ingest("a1", target="db:finance:ledger")
        self.assertEqual("review", r1.measure)  # 90 + 15 >= 100，升级为人工复核
        explain = self.service.explain_decision(r1.decision_id)
        rule_types = [item["rule_type"] for item in explain["triggered_rules"]]
        self.assertIn("score_escalation", rule_types)

    def test_quota_exhaustion_triggers_throttle(self):
        self.add_subject()
        self.add_grant(quota=2)
        self.add_rule("r-quota", "quota_exhaustion", {}, 40, "throttle")
        self.assertEqual("allow", self.ingest("a1", occurred_at="2026-10-01T08:00:00Z").measure)
        self.assertEqual("allow", self.ingest("a2", occurred_at="2026-10-01T08:00:10Z").measure)
        r3 = self.ingest("a3", occurred_at="2026-10-01T08:00:20Z")
        self.assertEqual("throttle", r3.measure)
        explain = self.service.explain_decision(r3.decision_id)
        self.assertEqual(0, explain["triggered_rules"][0]["evidence"]["quota_remaining"])

    def test_duplicate_action_does_not_deduct_quota_twice(self):
        self.add_subject()
        self.add_grant(quota=10)
        r1 = self.ingest("a1", occurred_at="2026-10-01T08:00:00Z")
        duplicate = self.service.ingest_action(
            request_id="req-a1-retry", actor_id="op1", action_id="a1", subject_id="agent-1",
            target="api:res:1", action_type="invoke", occurred_at="2026-10-01T08:00:00Z")
        self.assertTrue(duplicate.duplicate)
        self.assertFalse(duplicate.replayed)
        self.assertEqual(r1.decision_id, duplicate.decision_id)
        replay = self.ingest("a1", occurred_at="2026-10-01T08:00:00Z")
        self.assertTrue(replay.replayed)
        self.assertEqual(r1.decision_id, replay.decision_id)
        r2 = self.ingest("a2", occurred_at="2026-10-01T08:00:10Z")
        explain = self.service.explain_decision(r2.decision_id)
        self.assertEqual(9, explain["features"]["quota_remaining"])  # 只扣减了 a1 一次
        self.assertEqual(2, len(self.service.list_decisions("agent-1")))

    def test_same_action_id_with_different_content_conflicts(self):
        self.add_subject()
        self.add_grant()
        self.ingest("a1", target="api:res:1")
        with self.assertRaises(ConflictError):
            self.service.ingest_action(request_id="req-other", actor_id="op1", action_id="a1",
                                       subject_id="agent-1", target="api:res:2",
                                       action_type="invoke", occurred_at="2026-10-01T08:00:00Z")

    def test_active_throttle_limits_until_expiry(self):
        self.add_subject()
        self.add_grant()
        self.add_rule("r-freq", "frequency_spike", {"window_seconds": 60, "max_actions": 2}, 30, "throttle")
        self.ingest("a1", occurred_at="2026-10-01T08:00:00Z")
        self.ingest("a2", occurred_at="2026-10-01T08:00:10Z")
        self.ingest("a3", occurred_at="2026-10-01T08:00:20Z")  # 触发限流，有效期到 08:01:20
        throttle_id = self.service.list_interventions()[0].intervention_id
        r4 = self.ingest("a4", occurred_at="2026-10-01T08:01:15Z")  # 规则未命中但限流仍生效
        self.assertEqual("throttle", r4.measure)
        explain = self.service.explain_decision(r4.decision_id)
        self.assertEqual("active_throttle", explain["triggered_rules"][0]["rule_type"])
        self.assertEqual(throttle_id, explain["intervention"]["intervention_id"])
        self.assertEqual(1, len(self.service.list_interventions()))  # 未重复创建
        r5 = self.ingest("a5", occurred_at="2026-10-01T08:01:25Z")  # 限流已过期
        self.assertEqual("allow", r5.measure)

    def test_reviewer_releases_when_evidence_insufficient(self):
        self.trigger_review()
        pending = self.service.list_interventions(status="pending")
        receipt = self.service.resolve_intervention(
            request_id="rel-1", actor_id="rev1", intervention_id=pending[0].intervention_id,
            resolution="release", reason="证据不足，目标均在授权范围内")
        self.assertFalse(receipt.replayed)
        self.assertEqual("active", self.service.get_subject("agent-1").status)
        resolved = self.service.list_interventions(subject_id="agent-1")[0]
        self.assertEqual("released", resolved.status)
        self.assertEqual("rev1", resolved.resolved_by)
        self.assertEqual("release", resolved.resolution)
        self.assertEqual("证据不足，目标均在授权范围内", resolved.resolution_reason)
        follow_up = self.ingest("a9", target="api:e:9", occurred_at="2026-10-01T08:10:00Z")
        self.assertEqual("allow", follow_up.measure)

    def test_release_requires_reason(self):
        self.trigger_review()
        pending = self.service.list_interventions(status="pending")
        with self.assertRaises(ValidationError):
            self.service.resolve_intervention(request_id="rel-x", actor_id="rev1",
                                              intervention_id=pending[0].intervention_id,
                                              resolution="release", reason="")

    def test_operator_cannot_resolve_intervention(self):
        self.trigger_review()
        pending = self.service.list_interventions(status="pending")
        with self.assertRaises(PermissionDenied):
            self.service.resolve_intervention(request_id="rel-y", actor_id="op1",
                                              intervention_id=pending[0].intervention_id,
                                              resolution="release", reason="证据不足")

    def test_confirm_keeps_subject_suspended(self):
        self.trigger_review()
        pending = self.service.list_interventions(status="pending")
        self.service.resolve_intervention(request_id="cfm-1", actor_id="rev1",
                                          intervention_id=pending[0].intervention_id,
                                          resolution="confirm")
        self.assertEqual("suspended", self.service.get_subject("agent-1").status)
        resolved = self.service.list_interventions(subject_id="agent-1")[0]
        self.assertEqual("confirmed", resolved.status)
        with self.assertRaises(ConflictError):
            self.service.resolve_intervention(request_id="cfm-2", actor_id="rev1",
                                              intervention_id=pending[0].intervention_id,
                                              resolution="release", reason="证据不足")

    def test_rule_update_keeps_completed_decisions(self):
        self.add_subject()
        self.add_grant()
        self.add_rule("r-freq", "frequency_spike", {"window_seconds": 60, "max_actions": 1}, 30, "throttle")
        self.ingest("a1", occurred_at="2026-10-01T08:00:00Z")
        r2 = self.ingest("a2", occurred_at="2026-10-01T08:00:05Z")
        self.assertEqual("throttle", r2.measure)
        self.service.update_rule(request_id="upd-1", actor_id="admin1", rule_id="r-freq", name="r-freq",
                                 rule_type="frequency_spike",
                                 params={"window_seconds": 60, "max_actions": 100},
                                 score=5, measure="throttle")
        old = self.service.explain_decision(r2.decision_id)
        self.assertEqual("throttle", old["measure"])
        self.assertEqual(1, old["triggered_rules"][0]["version"])
        self.assertEqual(1, old["triggered_rules"][0]["evidence"]["max_actions"])
        r3 = self.ingest("a3", occurred_at="2026-10-01T08:01:10Z")  # 限流已过期，按新版本评估
        self.assertEqual("allow", r3.measure)
        rules = self.service.list_rules()
        self.assertEqual(2, rules[0]["version"])
        self.assertEqual(100, rules[0]["params"]["max_actions"])

    def test_retired_rule_no_longer_applies(self):
        self.add_subject()
        self.add_grant()
        self.add_rule("r-freq", "frequency_spike", {"window_seconds": 60, "max_actions": 1}, 30, "throttle")
        self.service.retire_rule(request_id="ret-1", actor_id="admin1", rule_id="r-freq")
        self.assertEqual([], self.service.list_rules())
        self.ingest("a1", occurred_at="2026-10-01T08:00:00Z")
        r2 = self.ingest("a2", occurred_at="2026-10-01T08:00:05Z")
        self.assertEqual("allow", r2.measure)

    def test_operator_cannot_manage_rules(self):
        with self.assertRaises(PermissionDenied):
            self.service.create_rule(request_id="rx", actor_id="op1", rule_id="r1", name="n",
                                     rule_type="unauthorized_target", params={}, score=10,
                                     measure="suspend")

    def test_restart_preserves_pending_interventions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.sqlite3"
            database = Database(path)
            service = InterventionService(
                database, FixedClock(datetime(2026, 10, 1, tzinfo=timezone.utc)))
            service.register_organization(request_id="org", actor_id="bootstrap",
                                          organization_id="o1", name="治理机构")
            service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="admin1",
                                   display_name="管理员", role="admin", organization_id="o1")
            service.register_actor(request_id="op", actor_id="admin1", new_actor_id="op1",
                                   display_name="操作员", role="operator", organization_id="o1")
            service.register_actor(request_id="rev", actor_id="admin1", new_actor_id="rev1",
                                   display_name="复核员", role="reviewer", organization_id="o1")
            service.register_subject(request_id="sub", actor_id="op1", subject_id="agent-1",
                                     organization_id="o1", display_name="智能体", trust_tier="medium")
            service.create_grant(request_id="grant", actor_id="op1", grant_id="g1", subject_id="agent-1",
                                 target_pattern="api:*", action_type="invoke", quota_limit=100,
                                 quota_window_seconds=300, valid_from="2026-10-01T00:00:00Z",
                                 valid_until="2026-10-02T00:00:00Z")
            service.create_rule(request_id="rule", actor_id="admin1", rule_id="r-div", name="r-div",
                                rule_type="target_diversity",
                                params={"window_seconds": 300, "max_distinct_targets": 2},
                                score=60, measure="review")
            for index in range(3):
                service.ingest_action(request_id=f"req-{index}", actor_id="op1", action_id=f"a-{index}",
                                      subject_id="agent-1", target=f"api:e:{index}",
                                      action_type="invoke",
                                      occurred_at=f"2026-10-01T08:00:0{index}Z")
            database.close()

            restarted = InterventionService(
                Database(path), FixedClock(datetime(2026, 10, 1, 9, 0, tzinfo=timezone.utc)))
            pending = restarted.list_interventions(status="pending")
            self.assertEqual(1, len(pending))
            self.assertEqual("review", pending[0].kind)
            restarted.resolve_intervention(request_id="rel-restart", actor_id="rev1",
                                           intervention_id=pending[0].intervention_id,
                                           resolution="release", reason="证据不足")
            self.assertEqual("active", restarted.get_subject("agent-1").status)
            valid, _ = restarted.verify_audit()
            self.assertTrue(valid)
            restarted.database.close()

    def test_http_surface_for_ingest_and_explain(self):
        self.add_subject()
        self.add_grant()
        self.add_rule("r-unauth", "unauthorized_target", {}, 80, "suspend")
        status, payload = route(self.service, "POST", "/action-records",
                                {"request_id": "http-a1", "action_id": "a1", "subject_id": "agent-1",
                                 "target": "db:x:y", "action_type": "invoke",
                                 "occurred_at": "2026-10-01T08:00:00Z"},
                                {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        self.assertEqual("suspend", payload["measure"])
        status, explanation = route(self.service, "GET", f"/decisions/{payload['decision_id']}", None)
        self.assertEqual(200, status)
        self.assertEqual("r-unauth", explanation["triggered_rules"][0]["rule_id"])
        self.assertEqual("suspend", explanation["intervention"]["kind"])
        status, queue = route(self.service, "GET", "/interventions?status=active", None)
        self.assertEqual(200, status)
        self.assertEqual(1, len(queue["items"]))
        status, subject = route(self.service, "GET", "/subjects/agent-1", None)
        self.assertEqual("suspended", subject["status"])


if __name__ == "__main__":
    unittest.main()
