"""定义访问行为风险规则的类型、参数校验与命中逻辑。"""

from __future__ import annotations

from typing import Any

from .errors import ValidationError

RULE_TYPES = frozenset({"unauthorized_target", "quota_exceeded", "frequency_spike", "target_scatter"})
MEASURES = frozenset({"throttle", "suspend", "review"})
MEASURE_RANK = {"allow": 0, "throttle": 1, "review": 2, "suspend": 3}
DEFAULT_THROTTLE_SECONDS = 60


def _positive_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValidationError(f"{field} 必须是正整数")
    return value


def validate_rule_params(rule_type: str, measure: str, params: Any) -> dict[str, Any]:
    """校验并规范化规则参数,返回可安全快照的副本。"""

    if rule_type not in RULE_TYPES:
        raise ValidationError("rule_type 不在允许范围内")
    if measure not in MEASURES:
        raise ValidationError("measure 不在允许范围内")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise ValidationError("params 必须是对象")
    normalized = dict(params)
    if rule_type == "frequency_spike":
        _positive_int(normalized.get("window_seconds"), "window_seconds")
        _positive_int(normalized.get("max_actions"), "max_actions")
    if rule_type == "target_scatter":
        _positive_int(normalized.get("window_seconds"), "window_seconds")
        _positive_int(normalized.get("max_targets"), "max_targets")
    if measure == "throttle":
        normalized["throttle_seconds"] = _positive_int(
            normalized.get("throttle_seconds", DEFAULT_THROTTLE_SECONDS), "throttle_seconds")
    return normalized


def strongest_measure(measures: list[str]) -> str:
    """在多条命中措施中返回最强的一条。"""

    if not measures:
        return "allow"
    return max(measures, key=lambda item: MEASURE_RANK[item])


def rule_hit(rule: dict[str, Any], *, authorization_matched: bool, quota_remaining: int | None,
             frequency: int | None, distinct_targets: int | None) -> tuple[bool, str]:
    """判断单条规则是否命中,并返回中文证据描述。"""

    rule_type = rule["rule_type"]
    params = rule["params"]
    if rule_type == "unauthorized_target":
        if not authorization_matched:
            return True, "主体没有覆盖该目标的有效授权"
        return False, ""
    if rule_type == "quota_exceeded":
        if quota_remaining is not None and quota_remaining <= 0:
            return True, f"当前授权额度已用尽(剩余 {quota_remaining})"
        return False, ""
    if rule_type == "frequency_spike":
        if frequency is not None and frequency > params["max_actions"]:
            return True, (f"主体在 {params['window_seconds']} 秒窗口内已到达第 {frequency} 次动作"
                          f"(阈值 {params['max_actions']})")
        return False, ""
    if rule_type == "target_scatter":
        if distinct_targets is not None and distinct_targets > params["max_targets"]:
            return True, (f"主体在 {params['window_seconds']} 秒窗口内触及 {distinct_targets} 个不同目标"
                          f"(阈值 {params['max_targets']})")
        return False, ""
    return False, ""
