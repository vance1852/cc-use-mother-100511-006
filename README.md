# 异常访问实时干预服务

本项目提供人工智能治理协作的服务端基础能力，用于登记主体、任务、权限、风险事件和结构化证据，并通过角色权限、请求幂等、SQLite 事务与审计链保持业务状态一致。

在此之上，服务内置**访问行为判定与干预**能力：接收按时间到达的动作记录，结合主体、目标、历史频率和当前授权计算风险，实时触发限流、暂停或转人工复核，避免监控人员直到任务结束才发现异常、无法及时阻断。

## 判定与干预语义

- **动作接入**：`POST /action-records` 接收动作记录（主体、目标、动作类型、发生时间）。`request_id` 保证请求级幂等；`action_id` 保证业务级去重——重复上报同一动作返回原判定，不会重复扣减额度。
- **风险判定**：结合主体信任等级、目标与动作类型是否被当前授权覆盖、时间窗内的历史频率与不同目标数、授权额度余量计算风险分数。
- **干预措施**：按命中规则的最高严重度执行 `throttle`（限流，带有效期）→ `suspend`（暂停主体）→ `review`（转人工复核并暂停主体）；多条规则同时命中使综合分数达到阈值时升级为人工复核。存在未解除的暂停或复核时，后续动作直接阻断且不再重复扣减额度。
- **复核恢复**：复核人员（reviewer/admin）可确认处置（`confirm`），或在证据不足时恢复任务（`release`，必须填写理由）；恢复后主体回到正常状态。
- **规则版本化**：规则更新生成新版本，只影响之后的判定；已经完成的判定保存触发规则快照与行为特征，不会被改写。
- **持久化**：全部状态保存在 SQLite 中，重启后尚未处理的干预队列继续保留，复核可继续进行。
- **可解释查询**：`GET /decisions/{id}` 返回触发了哪些规则（含版本与证据）、当时的行为特征以及最终采取的措施。

## 判定规则类型

| rule_type | 参数 | 说明 |
| --- | --- | --- |
| `frequency_spike` | `window_seconds`, `max_actions` | 时间窗内动作频率超限 |
| `target_diversity` | `window_seconds`, `max_distinct_targets` | 时间窗内尝试的不同目标（入口）过多 |
| `unauthorized_target` | 无 | 当前授权未覆盖目标或动作类型 |
| `quota_exhaustion` | 无 | 授权额度在窗口内已经耗尽 |

## 主要接口

- `POST /subjects`、`POST /grants`、`POST /grant-revocations`：登记被监控主体与其授权（额度、有效期、目标模式）。
- `POST /rules`、`POST /rule-updates`、`POST /rule-retirements`、`GET /rules`：判定规则的版本化管理（仅 admin）。
- `POST /action-records`：接入动作记录并返回判定结果（operator/admin）。
- `GET /decisions?subject_id=`、`GET /decisions/{id}`：判定查询与解释。
- `GET /interventions?status=pending`：干预队列（`pending` 为待人工复核）。
- `POST /intervention-resolutions`：复核处置（reviewer/admin），`resolution` 为 `confirm` 或 `release`。
- `GET /subjects/{id}`：主体当前状态。

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

服务提供健康检查和带操作者身份的业务请求，重启后 SQLite 中的状态、干预队列与审计历史继续保留。
