# agent attachments

## 定位

`attachments` 表示 `agent` 管理的 XDP 挂载配置。

- 一个 `attachment` 对应一个网卡
- 使用 `ifindex` 唯一标识
- 统一管理 XDP attach 和该网卡的 XSK runtime
- 具体 API 路由见 `../agent-api.md`

---

## 资源结构

```json
{
  "ifindex": 3,
  "ifname": "eth1",
  "attach_mode": "native",
  "enabled": true,
  "miss_verdict": "pass",
  "channels": {
    "rx_queue_count": 0,
    "max_rx_queue_count": 2
  },
  "xsk": {
    "enabled": true,
    "queues": [0, 1],
    "umem": {
      "frame_size": 2048,
      "frame_count": 4096,
      "fill_ring_size": 2048,
      "completion_ring_size": 2048,
      "rx_ring_size": 2048,
      "tx_ring_size": 2048,
      "tx_frame_reserve": 256
    }
  },
  "runtime": {
    "program_id": 128
  }
}
```

---

## 字段约定

### `ifindex`

- 必填
- 必须大于 `0`
- Linux 网卡 `ifindex`
- 作为 attachment 唯一标识

### `ifname`

- 可选
- 如果传入，需要校验是否和 `ifindex` 匹配
- 仅用于展示、日志和调试

### `attach_mode`

- 可选
- 默认值：`native`
- 可选值：`generic` / `native` / `driver`
- 表示 XDP 挂载模式

### `enabled`

- 只读
- 表示 attachment 当前是否启用
- 创建成功后为 `true`
- 只能通过 `PATCH` 修改
- `true`：XDP 已挂载；如果 `xsk.enabled=true`，XSK 已启动
- `false`：attachment 保留在内存状态中，但 XDP 未挂载，XSK 未启动

### `miss_verdict`

- 可选
- 默认值：`pass`
- 可选值：`pass` / `drop`
- 表示未命中规则时的默认处理
- `pass`：放行
- `drop`：丢弃

### `channels.rx_queue_count`

- 可选
- 默认值：`0`
- `0` 表示使用 `channels.max_rx_queue_count`
- 大于 `0` 时不能超过 `channels.max_rx_queue_count`
- 表示启用的 RX queue 数量

### `channels.max_rx_queue_count`

- 只读
- 网卡支持的最大 RX queue 数量

### `xsk.enabled`

- 可选
- 默认值：`false`
- 表示是否启用该网卡的 XSK
- 只有 `enabled=true` 时才会实际启动 XSK
- `enabled=false` 时即使 `xsk.enabled=true` 也不启动 XSK

### `xsk.queues`

- 可选
- 省略或为空时由 `agent` 自动补全
- 不能重复
- queue id 必须小于实际启用的 RX queue 数量
- 表示 XSK 使用的 queue 列表
- 自动补全规则：
  - 如果 `channels.rx_queue_count > 0`，使用 `[0..rx_queue_count-1]`
  - 如果 `channels.rx_queue_count = 0`，使用 `[0..max_rx_queue_count-1]`
  - 如果无法获取 `max_rx_queue_count`，使用 `[0]`

### `xsk.umem.frame_size`

- 可选
- 默认值：`2048`
- 可选值：`2048` / `4096`
- 表示 UMEM frame 大小

### `xsk.umem.frame_count`

- 可选
- 默认值：`4096`
- 必须是 `2` 的幂
- 表示 UMEM frame 数量

### `xsk.umem.*_ring_size`

- 可选
- 默认值：`2048`
- 必须是 `2` 的幂
- 包括：
  - `fill_ring_size`
  - `completion_ring_size`
  - `rx_ring_size`
  - `tx_ring_size`
- 分别表示 XSK fill / completion / RX / TX ring 大小

### `xsk.umem.tx_frame_reserve`

- 可选
- 默认值：`256`
- 必须小于 `xsk.umem.frame_size`
- 表示 TX frame 预留空间

### `runtime.program_id`

- 只读
- 未挂载时为空或 `0`
- 当前挂载的 BPF program ID

---

## 资源边界

- `attachments`：描述 XDP 挂载配置、XSK 配置和运行态状态
- `ruleset`：负责运行时规则集
- `response`：负责响应包默认出口网口
- `dispatch`：负责数据包分发配置

---

## 创建、启停和删除

### create

`POST /api/v1/attachments` 创建并启用 attachment。

- 请求中不包含 `enabled`
- 同一 `ifindex` 已存在时返回 `409 conflict`
- 创建成功后执行 XDP attach
- 如果 `xsk.enabled=true`，同时启动 XSK
- 任一步失败时回滚已完成的运行态操作
- 成功后写入内存状态并返回规范化后的 attachment

### patch

`PATCH /api/v1/attachments/{ifindex}` 只允许修改 `enabled`。

请求结构：

```json
{
  "enabled": true
}
```

- `false -> true`：挂载 XDP，并按 `xsk.enabled` 决定是否启动 XSK
- `true -> false`：停止 XSK，卸载 XDP，保留内存状态
- 不允许修改 queues、UMEM、attach mode、miss verdict
- 资源不存在时返回 `404 not_found`

### delete

`DELETE /api/v1/attachments/{ifindex}` 删除 attachment。

- 如果 XSK 正在运行，先停止 XSK
- 如果 XDP 已挂载，再卸载 XDP
- 删除内存中的 attachment 配置
- 资源不存在时返回 `404 not_found`
- 成功时返回 `204`

---

## 状态存储

`agent` 在内存中维护 attachment 状态。

- `POST` 成功后写入内存状态
- `GET` 从内存状态读取
- `PATCH` 更新内存状态和运行态
- `DELETE` 删除内存状态
- 进程重启后内存状态丢失
- `agent` 不持久化 attachment
- 需要恢复时，由 `mgr` 重新调用 `POST /api/v1/attachments` 下发期望 attachment

---

## dry-run

`POST /api/v1/attachments?dry_run=true` 只校验并返回规范化后的 attachment。

- 执行默认值填充、规范化、校验和网卡能力查询
- 不挂载 XDP
- 不启动 XSK
- 不保存运行态状态
- 即使同一 `ifindex` 已存在，也只返回校验结果，不修改现有资源

---

## runtime 状态

`runtime` 字段只读。

运行态状态至少包含：

- `runtime.program_id`：当前挂载的 BPF program ID

未启用或未挂载成功时：

- `enabled=false`
- `runtime.program_id` 为空或 `0`
