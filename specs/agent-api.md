# agent API

`agent` API 总览。

服务定位和边界见：`agent.md`。

---

## 基础接口

详细定义见：`agent/status.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/health` | 进程存活检查 |
| `GET` | `/api/v1/status` | 查看 agent 当前运行态总览 |

---

## Attachments

XDP attachment 运行态资源。

详细定义见：`agent/attachments.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `POST` | `/api/v1/attachments` | 创建 attachment |
| `POST` | `/api/v1/attachments?dry_run=true` | 只校验 attachment，不挂载运行态 |
| `GET` | `/api/v1/attachments` | 查看所有 attachments |
| `GET` | `/api/v1/attachments/{ifindex}` | 查看指定 attachment |
| `PATCH` | `/api/v1/attachments/{ifindex}` | 修改 attachment 的 `enabled` 状态 |
| `DELETE` | `/api/v1/attachments/{ifindex}` | 删除 attachment |

---

## Ruleset

当前运行时规则集。

详细定义见：`agent/ruleset.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/ruleset` | 查看当前运行时 `ruleset` 摘要 |
| `PUT` | `/api/v1/ruleset` | 整体替换当前运行时 `ruleset` |
| `PUT` | `/api/v1/ruleset?dry_run=true` | 只校验 `ruleset`，不应用 |
| `DELETE` | `/api/v1/ruleset` | 清空当前运行时 `ruleset` |

---

## Events

内核规则匹配事件推送。

详细定义见：`agent/events.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/events/stream` | 通过 SSE 推送内核上报事件 |

---

## Stats

当前运行态计数。

详细定义见：`agent/stats.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/stats` | 查看当前运行态计数 |

---

## Response

响应包默认出口网口配置。

详细定义见：`agent/response.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/response` | 查看 response 配置 |
| `PUT` | `/api/v1/response` | 整体替换 response 配置 |
| `DELETE` | `/api/v1/response` | 删除 response 配置并恢复默认同口发送 |

---

## Dispatch

数据包分发配置。

详细定义见：`agent/dispatch.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/dispatch` | 查看 dispatch 配置 |
| `PUT` | `/api/v1/dispatch` | 整体替换 dispatch 配置 |
| `DELETE` | `/api/v1/dispatch` | 删除 dispatch 配置 |
