"""定义基础服务在模块边界使用的数据对象。"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Actor:
    """表示具有明确角色的后台操作者。"""

    actor_id: str
    display_name: str
    role: str
    organization_id: str
    active: bool


@dataclass(frozen=True)
class Site:
    """表示科研创新机构下的业务场所。"""

    site_id: str
    organization_id: str
    name: str
    timezone_name: str
    version: int


@dataclass(frozen=True)
class DomainRecord:
    """表示已经持久化的领域资料记录。"""

    record_id: str
    site_id: str
    category: str
    external_key: str
    payload: dict[str, Any]
    created_by: str
    created_at: str


@dataclass(frozen=True)
class WriteReceipt:
    """描述一次幂等写入的稳定结果。"""

    request_id: str
    resource_type: str
    resource_id: str
    replayed: bool


@dataclass(frozen=True)
class Subject:
    """表示被监控的智能体主体。"""

    subject_id: str
    organization_id: str
    display_name: str
    trust_tier: str
    status: str
    created_at: str


@dataclass(frozen=True)
class Decision:
    """表示一次已经完成且不可改写的风险判定。"""

    decision_id: str
    action_id: str
    subject_id: str
    ruleset_generation: int
    risk_score: int
    measure: str
    triggered: list[dict[str, Any]]
    features: dict[str, Any]
    intervention_id: str | None
    decided_at: str


@dataclass(frozen=True)
class Intervention:
    """表示一次限流、暂停或人工复核干预。"""

    intervention_id: str
    decision_id: str
    subject_id: str
    kind: str
    status: str
    detail: dict[str, Any]
    expires_at: str | None
    created_at: str
    resolved_by: str | None
    resolved_at: str | None
    resolution: str | None
    resolution_reason: str | None


@dataclass(frozen=True)
class IngestResult:
    """描述动作记录接入的稳定结果。"""

    request_id: str
    action_id: str
    decision_id: str
    measure: str
    risk_score: int
    duplicate: bool
    replayed: bool
