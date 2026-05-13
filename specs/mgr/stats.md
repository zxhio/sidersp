# mgr stats

## 定位

`stats` 表示 `mgr` 持久化后的历史统计数据。

- 面向 Web 页面展示
- 用于趋势统计、规则命中分析和事件追溯
- 数据来源于 `agent` 当前运行态 stats 和 events
- `mgr` 不透传 `agent` 的 `/api/v1/stats`

---

## API

具体 API 路由见 `../mgr-api.md`。

- `GET /api/v1/stats/summary`：历史统计摘要
- `GET /api/v1/stats/rules`：规则维度历史统计
- `GET /api/v1/stats/events`：历史事件查询

---

## 查询参数

### `from`

- 可选
- 秒级时间戳
- 查询起始时间

### `to`

- 可选
- 秒级时间戳
- 查询结束时间

### `rule_id`

- 可选
- 用于过滤指定规则
- 适用于 `stats/rules` 和 `stats/events`

### `action`

- 可选
- 用于过滤指定响应动作
- 适用于 `stats/events`

### `limit`

- 可选
- 返回数量限制
- 适用于 `stats/events`

### `cursor`

- 可选
- 分页游标
- 适用于 `stats/events`

---

## Summary

`summary` 表示历史统计摘要。

用于展示一段时间内的总体运行情况。

建议字段：

```json
{
  "from": 1710000000,
  "to": 1710003600,
  "ingress_packets": 100000,
  "match_packets": 1200,
  "kernel_response_packets": 800,
  "userspace_response_packets": 300,
  "error_packets": 5
}
```

字段说明：

- `ingress_packets`：进入 XDP 的总包数
- `match_packets`：命中规则的包数
- `kernel_response_packets`：进入 kernel response 路径的包数
- `userspace_response_packets`：进入 userspace response 路径的包数
- `error_packets`：错误总数

---

## Rules

`rules` 表示规则维度的历史命中统计。

用于展示每条规则的命中次数，以及触发的响应动作数量。

建议字段：

```json
{
  "rules": [
    {
      "rule_id": 1001,
      "name": "http_tcp_reset",
      "hit_packets": 1200,
      "actions": {
        "tcp_reset": 1200
      }
    }
  ]
}
```

字段说明：

- `rule_id`：规则 ID
- `name`：规则名称，来自 `rules`
- `hit_packets`：规则命中次数
- `actions`：按 `response.action` 聚合的动作次数

---

## Events

`events` 表示历史事件记录。

用于追溯规则命中、响应动作和执行结果。

建议字段：

```json
{
  "events": [
    {
      "timestamp": 1710000001,
      "rule_id": 1001,
      "action": "tcp_reset",
      "path": "kernel",
      "verdict": "xdp_tx",
      "result": "sent",
      "ifindex": 3
    }
  ],
  "next_cursor": ""
}
```

字段说明：

- `timestamp`：事件时间，秒级时间戳
- `rule_id`：命中的规则 ID
- `action`：触发的 `response.action`
- `path`：执行路径
- `verdict`：dataplane 处置结果
- `result`：执行结果
- `ifindex`：入站网卡 ifindex
- `next_cursor`：下一页游标

---

## `path` 枚举

- `none`：不构造响应包
- `kernel`：内核态响应
- `userspace`：用户态响应或分发

---

## `verdict` 枚举

- `observe`：仅观测
- `xdp_tx`：通过原入站网口 `XDP_TX` 发出
- `xsk_redirect`：原始包转入 XSK
- `redirect_tx`：通过 BPF redirect 从配置出口发出

---

## `result` 枚举

- `matched`：规则命中，未发送响应
- `sent`：响应包已发送
- `failed`：响应执行失败

---

## 数据来源

- `mgr` 定期采集 `agent` 当前运行态 stats
- `mgr` 消费 `agent` events stream
- `mgr` 持久化统计结果和事件记录
- Web 页面通过 `/api/v1/stats/*` 查询历史数据
- 采集周期、保留期、bucket 大小和聚合策略是 mgr 实现配置，不是 `agent` API 合同
- `mgr` 可以按需要对 agent 当前 counters 做采样、差分和历史聚合

---

## 资源边界

- `agent/stats.md`：定义 agent 当前运行态计数
- `mgr/stats.md`：定义 mgr 历史统计查询
- `rules`：通过 `rule_id` 与 stats/events 关联
