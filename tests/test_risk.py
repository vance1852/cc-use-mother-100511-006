import unittest

from ai_governance_foundation import risk


def make_signals(**overrides):
    base = dict(trust_tier="medium", authorized=True, target="api:x", action_type="invoke",
                quota_remaining=10, window_counts={}, window_distinct_targets={},
                active_throttle_id=None)
    base.update(overrides)
    return risk.BehaviorSignals(**base)


class RiskEngineTest(unittest.TestCase):
    def test_no_rules_allows(self):
        evaluation = risk.evaluate([], make_signals())
        self.assertEqual("allow", evaluation.measure)
        self.assertEqual(5, evaluation.score)  # medium 信任等级基础分
        self.assertEqual([], evaluation.triggered)

    def test_frequency_rule_matches_with_evidence(self):
        rule = risk.RuleVersion("r1", 1, "频率", "frequency_spike",
                                {"window_seconds": 60, "max_actions": 2}, 30, "throttle")
        evaluation = risk.evaluate([rule], make_signals(window_counts={60: 3}))
        self.assertEqual("throttle", evaluation.measure)
        self.assertEqual(35, evaluation.score)
        self.assertEqual(3, evaluation.triggered[0]["evidence"]["observed_actions"])

    def test_strongest_measure_wins(self):
        rules = [
            risk.RuleVersion("r1", 1, "频率", "frequency_spike",
                             {"window_seconds": 60, "max_actions": 1}, 30, "throttle"),
            risk.RuleVersion("r2", 1, "未授权", "unauthorized_target", {}, 50, "suspend"),
        ]
        evaluation = risk.evaluate(
            rules, make_signals(authorized=False, quota_remaining=None, window_counts={60: 5}))
        self.assertEqual("suspend", evaluation.measure)
        self.assertEqual(2, len(evaluation.triggered))

    def test_score_escalation_overrides_to_review(self):
        rule = risk.RuleVersion("r1", 1, "未授权", "unauthorized_target", {}, 90, "suspend")
        evaluation = risk.evaluate(
            [rule], make_signals(trust_tier="low", authorized=False, quota_remaining=None))
        self.assertEqual("review", evaluation.measure)
        self.assertEqual("score_escalation", evaluation.triggered[-1]["rule_type"])
        self.assertEqual(105, evaluation.score)

    def test_active_throttle_floors_measure(self):
        evaluation = risk.evaluate([], make_signals(active_throttle_id="i-1"))
        self.assertEqual("throttle", evaluation.measure)
        self.assertEqual("active_throttle", evaluation.triggered[0]["rule_type"])

    def test_quota_exhaustion_requires_zero_remaining(self):
        rule = risk.RuleVersion("r1", 1, "额度", "quota_exhaustion", {}, 40, "throttle")
        self.assertEqual("allow", risk.evaluate([rule], make_signals(quota_remaining=1)).measure)
        triggered = risk.evaluate([rule], make_signals(quota_remaining=0))
        self.assertEqual("throttle", triggered.measure)


if __name__ == "__main__":
    unittest.main()
