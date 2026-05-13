# mgr API

`mgr` API 总览。

服务定位和边界见：`mgr.md`。

---

## 基础接口

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/health` | 进程存活检查 |
| `GET` | `/api/v1/status` | 查看 mgr 当前状态 |

---

## Rules

用户管理的规则资源。

详细定义见：`mgr/rules.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `POST` | `/api/v1/rules` | 创建规则 |
| `GET` | `/api/v1/rules` | 查看规则列表 |
| `GET` | `/api/v1/rules/{id}` | 查看指定规则 |
| `PUT` | `/api/v1/rules/{id}` | 整体替换指定规则 |
| `PATCH` | `/api/v1/rules/{id}` | 修改规则部分字段 |
| `DELETE` | `/api/v1/rules/{id}` | 删除指定规则 |

---

## Config

管理侧配置资源。

详细定义见：`mgr/config.md`

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/config` | 查看当前配置 |
| `PUT` | `/api/v1/config` | 整体替换配置 |

---

## Stats

历史统计查询资源。

详细定义见：`mgr/stats.md`

查询参数 `from` / `to` 使用秒级时间戳。

| 方法 | 路径 | 描述 |
|---|---|---|
| `GET` | `/api/v1/stats/summary` | 查看历史统计摘要 |
| `GET` | `/api/v1/stats/rules` | 查看规则维度历史统计 |
| `GET` | `/api/v1/stats/events` | 查看历史事件记录 |