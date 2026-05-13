# agent dispatch

## 定位

`dispatch` 表示 `agent` 的命中包异步分发能力。

- 与 `response` 同层
- `response` 负责主动回包
- `dispatch` 负责把命中包转交给 downstream
- `dispatch` 不构造响应包
- `dispatch` 不影响 response 执行结果
- 具体 API 路由见 `../agent-api.md`

---

## 执行模型

规则命中后，如果 `dispatch.enabled=true`，命中包需要进入 XSK，由用户态异步分发。

流程：

```text
match hit
  -> XDP_REDIRECT to XSK
  -> XSK worker receives original packet
  -> response execution if needed
  -> dispatch enqueue
  -> dispatch worker
  -> downstream
```

约定：

- XDP 侧负责将命中包转入 XSK
- XSK worker 负责接收原始包
- response 优先执行
- dispatch 只做非阻塞入队
- dispatch worker 异步发送到 downstream
- 队列满或发送失败只影响 dispatch 自身 stats

---

## 与 response 的关系

`response` 和 `dispatch` 都基于规则命中后的原始包处理。

- `response`：决定是否构造并发送响应包
- `dispatch`：决定是否把命中包交给后续分析链路

当 `dispatch.enabled=true` 时：

- 命中包通过 XSK 进入用户态
- 用户态可先完成 response，再将包放入 dispatch 队列
- dispatch 不阻塞 response
- dispatch 失败不影响 response 结果

---

## downstream

当前 downstream 使用 `AF_PACKET`。

语义：

- dispatch worker 从队列取包
- 通过 `AF_PACKET` 从 `target_ifindex` 发出
- downstream 从目标网口接收流量
- 适合接 Suricata、Zeek、tcpdump 或其他旁路分析服务

---

## 资源结构

```json
{
  "enabled": true,
  "backend": "af_packet",
  "target_ifindex": 4,
  "target_ifname": "eth2",
  "vlan_mode": "preserve",
  "queue_size": 4096,
  "max_packet_bytes": 0
}
```

---

## 字段约定

### `enabled`

- 可选
- 默认值：`false`
- 表示是否启用 dispatch

### `backend`

- 可选
- 默认值：`af_packet`
- 当前支持 `af_packet`
- 表示 dispatch downstream 类型

### `target_ifindex`

- `enabled=true` 时必填
- 必须大于 `0`
- Linux 网卡 `ifindex`
- 表示 dispatch 目标出口网口
- `enabled=false` 时可为空或 `0`

### `target_ifname`

- 可选
- 如果传入，需要校验是否和 `target_ifindex` 匹配
- 仅用于展示、日志和调试

### `vlan_mode`

- 可选
- 默认值：`preserve`
- 可选值：`preserve` / `access`
- 表示通过目标网口分发时 VLAN tag 的处理方式

### `queue_size`

- 可选
- 默认值：`4096`
- 必须大于 `0`
- 表示 dispatch 异步队列大小

### `max_packet_bytes`

- 可选
- 默认值：`0`
- `0` 表示分发完整包
- 大于 `0` 表示最多保留指定字节数
- 用于降低复制和发送成本

---

## `vlan_mode` 语义

### `preserve`

- 保留原始包中的 VLAN tag
- 适合目标网口是 trunk 口的场景
- 分发包从目标网口发出时继续携带原 VLAN tag

### `access`

- 去掉原始包中的 VLAN tag
- 适合目标网口是 access 口的场景
- 分发包从目标网口发出时不携带 VLAN tag

---

## 异步边界

- dispatch 不阻塞 response
- dispatch 不等待 downstream 返回结果
- dispatch 使用非阻塞入队
- dispatch 入队失败时直接丢弃当前包
- dispatch 失败不影响 response 结果
- dispatch 不作为响应包构造的数据来源
- dispatch 不改变 response 执行结果

---

## API 行为

### get

`GET /api/v1/dispatch` 查看当前 dispatch 配置。

- 未配置时返回默认禁用状态
- `enabled=false`
- `backend=af_packet`
- `queue_size=4096`
- `max_packet_bytes=0`

### put

`PUT /api/v1/dispatch` 整体替换 dispatch 配置。

- `enabled=true` 时必须配置 `target_ifindex`
- 如果传入 `target_ifname`，必须和 `target_ifindex` 匹配
- 成功后返回规范化后的 dispatch 配置

### delete

`DELETE /api/v1/dispatch` 删除 dispatch 配置。

- 删除后恢复默认禁用状态
- 成功时返回 `204`
- 未配置时也返回 `204`

### recovery

- 进程重启后 dispatch 配置恢复为默认禁用状态
- 需要恢复 dispatch 时，由 `mgr` 重新调用 `PUT /api/v1/dispatch` 下发期望配置

---

## stats 关联

dispatch 相关计数见 `./stats.md`。

字段：

- `dispatch.packets`：进入 dispatch 流程的包数
- `dispatch.queued_packets`：成功进入 dispatch 队列的包数
- `dispatch.dropped_packets`：dispatch 入队失败导致丢弃的包数
- `dispatch.sent_packets`：成功发送到 downstream 的包数
- `dispatch.error_packets`：dispatch worker 发送失败数

---

## 资源边界

- `dispatch`：描述命中包异步分发配置
- `response`：描述主动响应包执行路径
- `attachments`：提供 XSK 用户态收包能力
- `stats`：记录 dispatch 当前运行态计数
- `events`：可上报 dispatch 执行结果

---

## Roadmap

- 支持更多 downstream backend，例如 HTTP、gRPC、Unix socket、pcap file
- 支持 packet sampling
- 支持更细粒度的队列和 backpressure 策略
