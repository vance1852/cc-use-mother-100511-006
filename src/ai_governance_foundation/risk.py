"""访问行为风险判定引擎。

引擎只依赖纯数据输入，便于离线测试与规则替换；服务层负责持久化判定结果，
规则后续变更不会改写已经完成的判定。
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


MEASURE_SEVERITY = {"allow": 0, "throttle": 1, "suspend": 2, "review": 3}
SEVERITY_MEASURE = {severity: measure for measure, severity in MEASURE_SEVERITY.items()}
INTERVENTION_MEASURES = frozenset({"throttle", "suspend", "review"})

RULE_TYPES = frozenset({
    "frequency_spike",      # 时间窗内动作频率超限
    "target_diversity",     # 时间窗内尝试的不同目标（入口）过多
    "unauthorized_target",  # 当前授权未覆盖目标或动作类型
    "quota_exhaustion",     # 授权额度在窗口内已经耗尽
})

TRUST_BASE_SCORE = {"high": 0, "medium": 5, "low": 15}
TRUST_TIERS = frozenset(TRUST_BASE_SCORE)

# 命中规则的总分达到该阈值时，无论单条规则给出什么措施都升级为人工复核。
SCORE_ESCALATION_THRESHOLD = 100

_WINDOW_LIMIT_PARAMS = {
    "frequency_spike": "max_actions",
    "target_diversity": "max_distinct_targets",
}


@dataclass(frozen=True)
class RuleVersion:
    """一条规则在某个版本下的不可变定义。"""

    rule_id: str
    version: int
    name: str
    rule_type: str
    params: dict[str, Any]
    score: int
    measure: str

    def window_seconds(self) -> int | None:
        """返回该规则需要统计的时间窗秒数，无窗口规则返回 None。"""

        if self.rule_type in _WINDOW_LIMIT_PARAMS:
            return int(self.params["window_seconds"])
        return None


@dataclass(frozen=True)
class BehaviorSignals:
    """判定一个动作时所需的主体行为特征。"""

    trust_tier: str
    authorized: bool
    target: str
    action_type: str
    quota_remaining: int | None
    window_counts: dict[int, int]
    window_distinct_targets: dict[int, int]
    active_throttle_id: str | None


@dataclass(frozen=True)
class Evaluation:
    """一次风险判定的完整结果。"""

    measure: str
    score: int
    triggered: list[dict[str, Any]]


def _match(rule: RuleVersion, signals: BehaviorSignals) -> dict[str, Any] | None:
    """返回规则命中的证据，未命中返回 None。"""

    if rule.rule_type == "unauthorized_target":
        if signals.authorized:
            return None
        return {"target": signals.target, "action_type": signals.action_type, "authorized": False}
    if rule.rule_type == "quota_exhaustion":
        if not signals.authorized or signals.quota_remaining is None or signals.quota_remaining > 0:
            return None
        return {"quota_remaining": signals.quota_remaining}
    if rule.rule_type == "frequency_spike":
        window = int(rule.params["window_seconds"])
        limit = int(rule.params["max_actions"])
        observed = signals.window_counts.get(window, 0)
        if observed <= limit:
            return None
        return {"window_seconds": window, "max_actions": limit, "observed_actions": observed}
    if rule.rule_type == "target_diversity":
        window = int(rule.params["window_seconds"])
        limit = int(rule.params["max_distinct_targets"])
        observed = signals.window_distinct_targets.get(window, 0)
        if observed <= limit:
            return None
        return {"window_seconds": window, "max_distinct_targets": limit,
                "observed_distinct_targets": observed}
    return None


def evaluate(rules: list[RuleVersion], signals: BehaviorSignals) -> Evaluation:
    """按当前生效规则计算风险分数与最终措施。"""

    triggered: list[dict[str, Any]] = []
    for rule in rules:
        evidence = _match(rule, signals)
        if evidence is None:
            continue
        triggered.append({
            "rule_id": rule.rule_id,
            "version": rule.version,
            "name": rule.name,
            "rule_type": rule.rule_type,
            "measure": rule.measure,
            "score": rule.score,
            "evidence": evidence,
        })
    score = TRUST_BASE_SCORE[signals.trust_tier] + sum(item["score"] for item in triggered)
    severity = max((MEASURE_SEVERITY[item["measure"]] for item in triggered), default=0)
    if signals.active_throttle_id is not None and severity < MEASURE_SEVERITY["throttle"]:
        severity = MEASURE_SEVERITY["throttle"]
        triggered.append({
            "rule_id": None,
            "version": None,
            "name": "限流干预仍在生效",
            "rule_type": "active_throttle",
            "measure": "throttle",
            "score": 0,
            "evidence": {"intervention_id": signals.active_throttle_id},
        })
    if score >= SCORE_ESCALATION_THRESHOLD and severity < MEASURE_SEVERITY["review"]:
        severity = MEASURE_SEVERITY["review"]
        triggered.append({
            "rule_id": None,
            "version": None,
            "name": "综合风险分数达到人工复核阈值",
            "rule_type": "score_escalation",
            "measure": "review",
            "score": 0,
            "evidence": {"threshold": SCORE_ESCALATION_THRESHOLD, "score": score},
        })
    return Evaluation(SEVERITY_MEASURE[severity], score, triggered)
