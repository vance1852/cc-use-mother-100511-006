import unittest

from ai_governance_foundation.acceptance import run


class AcceptanceTest(unittest.TestCase):
    def test_offline_acceptance(self):
        result = run()
        self.assertEqual("ok", result["status"])
        self.assertTrue(result["audit_valid"])
        self.assertFalse(result["first_replayed"])
        self.assertTrue(result["second_replayed"])
        self.assertEqual(1, result["records"])
        # 访问行为判定与干预
        self.assertEqual(["allow", "allow", "throttle", "review", "review"], result["measures"])
        self.assertTrue(result["duplicate_decision_same"])
        self.assertTrue(result["quota_not_double_deducted"])
        self.assertTrue(result["blocked_without_new_intervention"])
        self.assertTrue(result["old_decision_unchanged"])
        self.assertEqual("review", result["review_after_rule_update"])
        self.assertEqual(1, result["pending_after_restart"])
        self.assertTrue(result["resumed_after_restart"])
        self.assertEqual("suspend", result["unauthorized_measure"])


if __name__ == "__main__":
    unittest.main()
