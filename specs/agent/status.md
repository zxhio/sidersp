# agent status

## 定位

`status` 表示 `agent` 当前运行态总览。

`health` 只表示进程存活。

具体 API 路由见 `../agent-api.md`。

---

## health

`GET /api/v1/health` 用于进程存活检查。

成功响应：

```json
{
  "status": "ok"
}
```

字段约定：

### `status`

- 固定值：`ok`

---

## status

`GET /api/v1/status` 用于查看 agent 当前运行态总览。

建议结构：

```json
{
  "status": "running",
  "attachments": 1,
  "ruleset_version": 12,
  "response_configured": true,
  "dispatch_enabled": false
}
```

字段约定：

### `status`

- 可选值：`running` / `degraded`
- `running`：主要运行态正常
- `degraded`：进程存活，但部分运行态能力不可用

### `attachments`

- 当前 attachment 数量

### `ruleset_version`

- 当前运行态 ruleset 版本
- 未加载时为 `0`

### `response_configured`

- 是否已配置 response 默认出口

### `dispatch_enabled`

- dispatch 是否启用
