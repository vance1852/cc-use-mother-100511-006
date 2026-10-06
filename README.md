# 异常访问实时干预服务

本项目提供人工智能治理协作的服务端基础能力,用于登记主体、任务、权限、风险事件和结构化证据,
并通过角色权限、请求幂等、SQLite 事务与审计链保持业务状态一致。

在此之上,服务接收按时间到达的访问动作记录,结合主体、目标、历史频率和当前授权计算风险,
触发限流(throttle)、暂停(suspend)或转人工复核(review);复核人员在证据不足时可以恢复任务。

## 判定与干预语义

- **风险规则**:`frequency_spike`(窗口内动作频率)、`target_scatter`(窗口内不同目标数,
  对应"连续尝试不同入口"的探测行为)、`unauthorized_target`(无有效授权)、
  `quota_exceeded`(授权额度用尽)。多条命中时取最强措施:allow < throttle < review < suspend。
- **判定不可变**:每次判定把当时生效的规则版本快照存入 `decisions`;规则更新只追加新版本,
  已经完成的判断永远引用旧快照,不受更新影响。
- **幂等**:`action_id` 是去重键,重复上报同一动作直接返回原判定;额度账本以
  `(authorization_id, action_id)` 为主键,重复上报不会重复扣减额度。
- **重启保留**:干预队列(pending/active)全部落 SQLite,重启后未处理的干预继续保留。
- **可解释**:`GET /decisions/{action_id}` 返回触发的规则、证据描述、规则快照、
  最终措施以及干预的复核处置结果。

## 主要接口

写接口要求 `X-Actor-Id` 头标识操作者;`actor_id` 不放在请求体中。

- `POST /rules`、`GET /rules` — 登记/更新风险规则(admin),更新产生新版本
- `POST /authorizations`、`GET /authorizations/{id}`、`POST /authorizations/{id}/revoke` — 授权与额度
- `POST /actions` — 接收动作记录并返回判定(201 新判定,200 幂等重放)
- `GET /decisions/{action_id}` — 判定解释:触发规则、快照、最终措施
- `GET /interventions?status=pending|active|resolved` — 干预队列
- `POST /interventions/{id}/resolve` — 复核处置(reviewer/admin):
  `resolution=resumed` 证据不足恢复任务,`confirmed` 维持阻断(review 会升级为 suspend)
- `GET /tasks/{task_id}` — 任务运行状态(running/suspended)

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 构建检查

```bash
python3 -m compileall -q src tests
```

## 离线验收

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.acceptance
```

## HTTP 服务

```bash
PYTHONPATH=src python3 -m ai_governance_foundation.api --database ai_governance.sqlite3 --host 127.0.0.1 --port 8080
```

服务提供健康检查和带操作者身份的业务请求,重启后 SQLite 中的状态、干预队列与审计历史继续保留。
