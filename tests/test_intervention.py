import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from ai_governance_foundation.api import route
from ai_governance_foundation.clock import FixedClock
from ai_governance_foundation.errors import (ConflictError, NotFoundError,
                                             PermissionDenied, ValidationError)
from ai_governance_foundation.intervention import InterventionService
from ai_governance_foundation.storage import Database

CLOCK = FixedClock(datetime(2026, 9, 25, 8, 0, tzinfo=timezone.utc))


class InterventionTestBase(unittest.TestCase):
    def setUp(self):
        self.database = Database()
        self.service = InterventionService(self.database, CLOCK)
        self.service.register_organization(request_id="org", actor_id="bootstrap",
                                           organization_id="o1", name="科研机构一")
        self.service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                    display_name="管理员", role="admin", organization_id="o1")
        self.service.register_actor(request_id="operator", actor_id="a1", new_actor_id="op1",
                                    display_name="操作员", role="operator", organization_id="o1")
        self.service.register_actor(request_id="reviewer", actor_id="a1", new_actor_id="rv1",
                                    display_name="复核员", role="reviewer", organization_id="o1")
        self.service.register_actor(request_id="auditor", actor_id="a1", new_actor_id="au1",
                                    display_name="审计员", role="auditor", organization_id="o1")
        self._rule_seq = 0

    def tearDown(self):
        self.database.close()

    def add_rule(self, rule_id, rule_type, params, measure, risk_score=50):
        self._rule_seq += 1
        return self.service.upsert_rule(request_id=f"rule-{self._rule_seq}", actor_id="a1",
                                        rule_id=rule_id, name=rule_id, rule_type=rule_type,
                                        params=params, measure=measure, risk_score=risk_score)

    def grant(self, subject="agent-1", pattern="portal-*", quota=10, window=60, auth_id="auth-1"):
        return self.service.grant_authorization(request_id=f"grant-{auth_id}", actor_id="a1",
                                                authorization_id=auth_id, subject_id=subject,
                                                target_pattern=pattern, quota=quota,
                                                window_seconds=window)

    def act(self, action_id, subject="agent-1", target="portal-a", task="task-1",
            at="2026-09-25T08:00:01Z"):
        return self.service.ingest_action(actor_id="op1", action_id=action_id, subject_id=subject,
                                          target_id=target, action_type="http_request",
                                          task_id=task, occurred_at=at)


class RuleManagementTest(InterventionTestBase):
    def test_upsert_creates_new_versions(self):
        self.add_rule("r1", "frequency_spike", {"window_seconds": 60, "max_actions": 3}, "throttle")
        self.add_rule("r1", "frequency_spike", {"window_seconds": 60, "max_actions": 5}, "throttle")
        rules = self.service.list_rules()
        self.assertEqual(1, len(rules))
        self.assertEqual(2, rules[0]["version"])
        self.assertEqual(5, rules[0]["params"]["max_actions"])

    def test_invalid_rule_rejected(self):
        with self.assertRaises(ValidationError):
            self.add_rule("r1", "frequency_spike", {"max_actions": 3}, "throttle")
        with self.assertRaises(ValidationError):
            self.add_rule("r2", "target_scatter", {"window_seconds": 60}, "review")
        with self.assertRaises(ValidationError):
            self.add_rule("r3", "unknown_type", {}, "review")
        with self.assertRaises(ValidationError):
            self.add_rule("r4", "quota_exceeded", {}, "block")
        with self.assertRaises(ValidationError):
            self.service.upsert_rule(request_id="bad-score", actor_id="a1", rule_id="r5", name="r5",
                                     rule_type="quota_exceeded", params={}, measure="throttle",
                                     risk_score=0)

    def test_only_admin_manages_rules(self):
        with self.assertRaises(PermissionDenied):
            self.service.upsert_rule(request_id="deny", actor_id="op1", rule_id="r1", name="r1",
                                     rule_type="quota_exceeded", params={}, measure="throttle",
                                     risk_score=10)


class DecisionTest(InterventionTestBase):
    def test_allow_when_authorized_and_quiet(self):
        self.add_rule("freq", "frequency_spike", {"window_seconds": 60, "max_actions": 3}, "throttle")
        self.grant()
        view = self.act("act-1")
        self.assertEqual("allow", view["measure"])
        self.assertEqual(0, view["risk_score"])
        self.assertEqual([], view["triggered_rules"])
        self.assertFalse(view["replayed"])
        self.assertEqual(1, self.service.get_authorization("auth-1")["deducted_total"])

    def test_frequency_spike_triggers_throttle(self):
        self.add_rule("freq", "frequency_spike",
                      {"window_seconds": 60, "max_actions": 2, "throttle_seconds": 30}, "throttle")
        self.grant()
        self.act("a1", at="2026-09-25T08:00:01Z")
        self.act("a2", at="2026-09-25T08:00:02Z")
        third = self.act("a3", at="2026-09-25T08:00:03Z")
        self.assertEqual("throttle", third["measure"])
        self.assertEqual("freq", third["triggered_rules"][0]["rule_id"])
        self.assertIn("第 3 次", third["triggered_rules"][0]["detail"])
        self.assertEqual("throttle", third["interventions"][0]["kind"])
        self.assertTrue(third["interventions"][0]["expires_at"].startswith("2026-09-25T08:00:33"))
        fourth = self.act("a4", at="2026-09-25T08:00:04Z")
        self.assertEqual("throttle", fourth["measure"])
        system_rules = [item["rule_id"] for item in fourth["triggered_rules"]]
        self.assertIn("system:subject-throttled", system_rules)
        throttles = [item for item in self.service.list_interventions() if item["kind"] == "throttle"]
        self.assertEqual(1, len(throttles))
        self.assertEqual(4, self.service.get_authorization("auth-1")["deducted_total"])

    def test_target_scatter_triggers_review_and_holds_task(self):
        self.add_rule("scatter", "target_scatter", {"window_seconds": 300, "max_targets": 1}, "review")
        self.grant()
        self.act("a1", target="portal-a", at="2026-09-25T08:00:01Z")
        second = self.act("a2", target="portal-b", at="2026-09-25T08:00:02Z")
        self.assertEqual("review", second["measure"])
        self.assertEqual("pending", second["interventions"][0]["status"])
        self.assertEqual("suspended", self.service.get_task("task-1")["status"])
        third = self.act("a3", target="portal-a", at="2026-09-25T08:00:03Z")
        self.assertEqual("suspend", third["measure"])
        self.assertEqual("system:task-under-review", third["triggered_rules"][0]["rule_id"])
        self.assertEqual(1, len(self.service.list_interventions(status="pending")))
        self.assertEqual(1, self.service.get_authorization("auth-1")["deducted_total"])

    def test_unauthorized_target_triggers_suspend(self):
        self.add_rule("unauth", "unauthorized_target", {}, "suspend")
        view = self.act("a1", target="db-prod")
        self.assertEqual("suspend", view["measure"])
        self.assertEqual("unauth", view["triggered_rules"][0]["rule_id"])
        self.assertEqual("suspend", view["interventions"][0]["kind"])
        self.assertEqual("suspended", self.service.get_task("task-1")["status"])

    def test_revoked_authorization_makes_target_unauthorized(self):
        self.add_rule("unauth", "unauthorized_target", {}, "suspend")
        self.grant()
        self.service.revoke_authorization(request_id="revoke-1", actor_id="a1",
                                          authorization_id="auth-1")
        view = self.act("a1")
        self.assertEqual("suspend", view["measure"])
        with self.assertRaises(ConflictError):
            self.service.revoke_authorization(request_id="revoke-2", actor_id="a1",
                                              authorization_id="auth-1")
        with self.assertRaises(NotFoundError):
            self.service.revoke_authorization(request_id="revoke-3", actor_id="a1",
                                              authorization_id="missing")

    def test_quota_exceeded_triggers_configured_measure(self):
        self.add_rule("quota", "quota_exceeded", {}, "throttle")
        self.grant(quota=1)
        first = self.act("a1", at="2026-09-25T08:00:01Z")
        self.assertEqual("allow", first["measure"])
        second = self.act("a2", at="2026-09-25T08:00:02Z")
        self.assertEqual("throttle", second["measure"])
        self.assertIn("额度已用尽", second["triggered_rules"][0]["detail"])
        self.assertEqual(2, self.service.get_authorization("auth-1")["deducted_total"])

    def test_duplicate_action_replays_without_side_effects(self):
        self.add_rule("scatter", "target_scatter", {"window_seconds": 300, "max_targets": 1}, "review")
        self.grant()
        first = self.act("a1", target="portal-a", at="2026-09-25T08:00:01Z")
        replay = self.act("a1", target="portal-a", at="2026-09-25T08:00:01Z")
        self.assertFalse(first["replayed"])
        self.assertTrue(replay["replayed"])
        self.assertEqual(first["decision_id"], replay["decision_id"])
        self.assertEqual(1, self.service.get_authorization("auth-1")["deducted_total"])
        held = self.act("a2", target="portal-b", at="2026-09-25T08:00:02Z")
        self.assertEqual("review", held["measure"])
        held_replay = self.act("a2", target="portal-b", at="2026-09-25T08:00:02Z")
        self.assertTrue(held_replay["replayed"])
        self.assertEqual(1, len(self.service.list_interventions(status="pending")))
        self.assertEqual(1, self.service.get_authorization("auth-1")["deducted_total"])

    def test_ingest_requires_operator_role(self):
        with self.assertRaises(PermissionDenied):
            self.service.ingest_action(actor_id="rv1", action_id="a1", subject_id="agent-1",
                                       target_id="portal-a", action_type="http_request",
                                       task_id="task-1", occurred_at="2026-09-25T08:00:01Z")
        with self.assertRaises(PermissionDenied):
            self.service.ingest_action(actor_id="au1", action_id="a1", subject_id="agent-1",
                                       target_id="portal-a", action_type="http_request",
                                       task_id="task-1", occurred_at="2026-09-25T08:00:01Z")

    def test_occurred_at_requires_timezone(self):
        with self.assertRaises(ValidationError):
            self.act("a1", at="2026-09-25 08:00:00")

    def test_explain_decision_lists_rules_and_measure(self):
        self.add_rule("unauth", "unauthorized_target", {}, "suspend", risk_score=90)
        self.act("a1", target="db-prod")
        explained = self.service.get_decision("a1")
        self.assertEqual("suspend", explained["measure"])
        self.assertEqual(90, explained["risk_score"])
        self.assertEqual("unauth", explained["triggered_rules"][0]["rule_id"])
        self.assertEqual(1, explained["rule_snapshot"][0]["version"])
        self.assertEqual("suspend", explained["interventions"][0]["kind"])
        with self.assertRaises(NotFoundError):
            self.service.get_decision("missing")

    def test_rule_update_keeps_completed_decisions(self):
        self.add_rule("scatter", "target_scatter", {"window_seconds": 300, "max_targets": 1}, "review")
        self.grant()
        self.act("a1", target="portal-a", at="2026-09-25T08:00:01Z")
        self.act("a2", target="portal-b", at="2026-09-25T08:00:02Z")
        self.add_rule("scatter", "target_scatter", {"window_seconds": 300, "max_targets": 9}, "review")
        explained = self.service.get_decision("a2")
        snapshot = [item for item in explained["rule_snapshot"] if item["rule_id"] == "scatter"]
        self.assertEqual(1, snapshot[0]["version"])
        self.assertEqual(1, snapshot[0]["params"]["max_targets"])
        self.assertEqual("review", explained["measure"])
        rules = self.service.list_rules()
        self.assertEqual(2, rules[0]["version"])
        follow_up = self.act("a3", target="portal-x", task="task-2", at="2026-09-25T08:00:03Z")
        self.assertEqual("allow", follow_up["measure"])


class ResolveTest(InterventionTestBase):
    def _hold_task(self):
        self.add_rule("scatter", "target_scatter", {"window_seconds": 300, "max_targets": 1}, "review")
        self.grant()
        self.act("a1", target="portal-a", at="2026-09-25T08:00:01Z")
        self.act("a2", target="portal-b", at="2026-09-25T08:00:02Z")
        return self.service.list_interventions(status="pending")[0]

    def test_reviewer_resumes_task_when_evidence_insufficient(self):
        pending = self._hold_task()
        self.service.resolve_intervention(request_id="resolve-1", actor_id="rv1",
                                          intervention_id=pending["intervention_id"],
                                          resolution="resumed", note="证据不足,恢复任务")
        self.assertEqual("running", self.service.get_task("task-1")["status"])
        resolved = self.service.list_interventions(status="resolved")[0]
        self.assertEqual("resumed", resolved["resolution"])
        self.assertEqual("rv1", resolved["resolved_by"])
        follow_up = self.act("a3", target="portal-a", at="2026-09-25T08:10:01Z")
        self.assertEqual("allow", follow_up["measure"])

    def test_confirm_review_escalates_to_suspend(self):
        pending = self._hold_task()
        self.service.resolve_intervention(request_id="resolve-1", actor_id="rv1",
                                          intervention_id=pending["intervention_id"],
                                          resolution="confirmed", note="确为异常探测")
        self.assertEqual("suspended", self.service.get_task("task-1")["status"])
        suspends = [item for item in self.service.list_interventions(status="active")
                    if item["kind"] == "suspend"]
        self.assertEqual(1, len(suspends))
        self.assertEqual(pending["intervention_id"], suspends[0]["detail"]["escalated_from"])

    def test_resolve_requires_reviewer_role(self):
        pending = self._hold_task()
        with self.assertRaises(PermissionDenied):
            self.service.resolve_intervention(request_id="deny-1", actor_id="op1",
                                              intervention_id=pending["intervention_id"],
                                              resolution="resumed")
        with self.assertRaises(PermissionDenied):
            self.service.resolve_intervention(request_id="deny-2", actor_id="au1",
                                              intervention_id=pending["intervention_id"],
                                              resolution="resumed")

    def test_resolve_twice_conflicts_but_request_replays(self):
        pending = self._hold_task()
        first = self.service.resolve_intervention(request_id="resolve-1", actor_id="rv1",
                                                  intervention_id=pending["intervention_id"],
                                                  resolution="resumed")
        self.assertFalse(first.replayed)
        replay = self.service.resolve_intervention(request_id="resolve-1", actor_id="rv1",
                                                   intervention_id=pending["intervention_id"],
                                                   resolution="resumed")
        self.assertTrue(replay.replayed)
        with self.assertRaises(ConflictError):
            self.service.resolve_intervention(request_id="resolve-2", actor_id="rv1",
                                              intervention_id=pending["intervention_id"],
                                              resolution="confirmed")
        with self.assertRaises(NotFoundError):
            self.service.resolve_intervention(request_id="resolve-3", actor_id="rv1",
                                              intervention_id="missing", resolution="resumed")
        with self.assertRaises(ValidationError):
            self.service.resolve_intervention(request_id="resolve-4", actor_id="rv1",
                                              intervention_id=pending["intervention_id"],
                                              resolution="unknown")


class PersistenceTest(unittest.TestCase):
    def test_restart_preserves_open_interventions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "service.sqlite3"
            database = Database(path)
            service = InterventionService(database, CLOCK)
            service.register_organization(request_id="org", actor_id="bootstrap",
                                          organization_id="o1", name="科研机构一")
            service.register_actor(request_id="admin", actor_id="bootstrap", new_actor_id="a1",
                                   display_name="管理员", role="admin", organization_id="o1")
            service.register_actor(request_id="operator", actor_id="a1", new_actor_id="op1",
                                   display_name="操作员", role="operator", organization_id="o1")
            service.register_actor(request_id="reviewer", actor_id="a1", new_actor_id="rv1",
                                   display_name="复核员", role="reviewer", organization_id="o1")
            service.upsert_rule(request_id="rule", actor_id="a1", rule_id="scatter", name="scatter",
                                rule_type="target_scatter",
                                params={"window_seconds": 300, "max_targets": 1},
                                measure="review", risk_score=70)
            service.ingest_action(actor_id="op1", action_id="a1", subject_id="agent-1",
                                  target_id="portal-a", action_type="http_request", task_id="task-1",
                                  occurred_at="2026-09-25T08:00:01Z")
            service.ingest_action(actor_id="op1", action_id="a2", subject_id="agent-1",
                                  target_id="portal-b", action_type="http_request", task_id="task-1",
                                  occurred_at="2026-09-25T08:00:02Z")
            self.assertEqual(1, len(service.list_interventions(status="pending")))
            database.close()

            reopened = Database(path)
            restored = InterventionService(reopened, CLOCK)
            pending = restored.list_interventions(status="pending")
            self.assertEqual(1, len(pending))
            self.assertEqual("task-1", pending[0]["task_id"])
            self.assertEqual("suspended", restored.get_task("task-1")["status"])
            restored.resolve_intervention(request_id="resolve", actor_id="rv1",
                                          intervention_id=pending[0]["intervention_id"],
                                          resolution="resumed", note="证据不足")
            self.assertEqual("running", restored.get_task("task-1")["status"])
            valid, _ = restored.verify_audit()
            self.assertTrue(valid)
            reopened.close()


class InterventionApiTest(InterventionTestBase):
    def test_post_action_and_explain_via_api(self):
        self.add_rule("unauth", "unauthorized_target", {}, "suspend")
        status, payload = route(self.service, "POST", "/actions",
                                {"action_id": "a1", "subject_id": "agent-1", "target_id": "db-prod",
                                 "action_type": "http_request", "task_id": "task-1",
                                 "occurred_at": "2026-09-25T08:00:01Z"},
                                {"X-Actor-Id": "op1"})
        self.assertEqual(201, status)
        self.assertEqual("suspend", payload["measure"])
        status, payload = route(self.service, "GET", "/decisions/a1", None)
        self.assertEqual(200, status)
        self.assertEqual("unauth", payload["triggered_rules"][0]["rule_id"])
        self.assertEqual("suspend", payload["measure"])

    def test_replayed_action_returns_200(self):
        body = {"action_id": "a1", "subject_id": "agent-1", "target_id": "portal-a",
                "action_type": "http_request", "task_id": "task-1",
                "occurred_at": "2026-09-25T08:00:01Z"}
        first_status, _ = route(self.service, "POST", "/actions", body, {"X-Actor-Id": "op1"})
        second_status, payload = route(self.service, "POST", "/actions", body, {"X-Actor-Id": "op1"})
        self.assertEqual(201, first_status)
        self.assertEqual(200, second_status)
        self.assertTrue(payload["replayed"])

    def test_queue_and_resolve_via_api(self):
        self.add_rule("scatter", "target_scatter", {"window_seconds": 300, "max_targets": 1}, "review")
        for action_id, target in (("a1", "portal-a"), ("a2", "portal-b")):
            route(self.service, "POST", "/actions",
                  {"action_id": action_id, "subject_id": "agent-1", "target_id": target,
                   "action_type": "http_request", "task_id": "task-1",
                   "occurred_at": "2026-09-25T08:00:01Z"}, {"X-Actor-Id": "op1"})
        status, payload = route(self.service, "GET", "/interventions?status=pending", None)
        self.assertEqual(200, status)
        self.assertEqual(1, len(payload["items"]))
        intervention_id = payload["items"][0]["intervention_id"]
        status, _ = route(self.service, "POST", f"/interventions/{intervention_id}/resolve",
                          {"request_id": "resolve-1", "resolution": "resumed",
                           "note": "证据不足"}, {"X-Actor-Id": "rv1"})
        self.assertEqual(201, status)
        status, payload = route(self.service, "GET", "/tasks/task-1", None)
        self.assertEqual(200, status)
        self.assertEqual("running", payload["status"])

    def test_unknown_decision_returns_404(self):
        status, payload = route(self.service, "GET", "/decisions/missing", None)
        self.assertEqual(404, status)
        self.assertEqual("not_found", payload["error"])


if __name__ == "__main__":
    unittest.main()
