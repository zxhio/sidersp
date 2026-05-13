# agent events

## 定位

`events` 表示 `agent` 的运行态事件推送。

- 事件由 XDP / XSK / response 路径产生
- 通过 `/api/v1/events/stream` 推送
- 不做历史存储
- 不提供历史查询
- 不作为响应包构造的数据通道
- BPF ringbuf 只提供 32-byte 原始观测事件
- `path`、`result`、`ifindex` 是 agent/mgr 可派生或补充的逻辑字段
- 具体 API 路由见 `../agent-api.md`

---

## 事件类型

### `rule_event`

规则运行态事件。

- 用于记录规则命中
- 用于记录 response 执行结果
- 通过 `action` 表示规则动作
- 通过 `verdict` 表示 dataplane 处置结果
- 可通过派生字段表示执行路径和 userspace 执行结果

---

## 事件结构

```json
{
  "timestamp": 1710000000,
  "type": "rule_event",
  "rule_id": 1002,
  "action": "tcp_reset",
  "path": "kernel",
  "verdict": "xdp_tx",
  "result": "sent",
  "ifindex": 2,
  "sip": 167837962,
  "dip": 3232235796,
  "sport": 52345,
  "dport": 80,
  "ip_proto": 6
}
```

---

## 字段约定

### `timestamp`

- 秒级时间戳
- 表示事件产生时间

### `type`

- 事件类型
- 当前固定为 `rule_event`

### `rule_id`

- 命中的规则 ID
- 来自运行时 `ruleset`
- 用于和 `mgr` 中的规则、stats 关联

### `action`

- 当前规则的 `response.action`
- 枚举值以 `../mgr/rules.md` 为准

### `path`

- 可选
- 执行路径
- 可选值：`none` / `kernel` / `userspace`
- 不来自 BPF ringbuf 原始事件
- 由 agent 根据 `action` 和运行态执行路径派生

### `verdict`

- 可选
- dataplane 对命中包的处置结果
- 可选值：`observe` / `xdp_tx` / `xsk_redirect` / `redirect_tx`
- 不等同于 XDP 程序返回值

### `result`

- 可选
- 执行结果
- 可选值：`matched` / `sent` / `failed`
- BPF ringbuf 原始事件不携带该字段
- kernel response 成功可由 BPF verdict 派生为 `sent`
- userspace response 成功或失败来自 response 执行结果

### `ifindex`

- 可选
- 入站网卡 `ifindex`
- 不来自 BPF ringbuf 原始事件
- 由 agent 根据 attachment / event reader context 补充

### `sip`

- 源 IPv4 地址
- 使用整数表示
- 不存在时为 `0`

### `dip`

- 目的 IPv4 地址
- 使用整数表示
- 不存在时为 `0`

### `sport`

- 源端口
- 不存在时为 `0`

### `dport`

- 目的端口
- 不存在时为 `0`

### `ip_proto`

- IP 协议号
- 不存在时为 `0`

---

## path 语义

### `none`

- 不构造响应包
- 常用于 `none` / `alert`

### `kernel`

- BPF 内核态构造响应包
- 常用于 kernel response action

### `userspace`

- 命中包进入用户态
- 常用于 userspace response 或 dispatch

---

## verdict 语义

### `observe`

- 仅记录规则命中
- 不发送响应包
- 常用于 `none` / `alert`

### `xdp_tx`

- BPF 构造响应包
- 通过原入站网口 `XDP_TX` 发出

### `xsk_redirect`

- 原始包进入 XSK
- 后续由用户态决定 response / dispatch

### `redirect_tx`

- BPF 构造响应包
- 通过 `bpf_redirect` 从配置出口发出

---

## result 语义

### `matched`

- 规则已命中
- 不表示响应包已经发送
- 常用于 `none` / `alert`

### `sent`

- 响应包已发送
- 常用于 response 成功事件

### `failed`

- 响应执行失败
- 包括响应构造失败、redirect 失败、XSK TX 失败、AF_PACKET TX 失败等

---

## BPF ringbuf ABI

ringbuf ABI 是 agent 内部实现约定，不直接作为外部 API 暴露。

`agent` 负责将 ringbuf event 解码为本文件定义的逻辑事件结构。

当前 ringbuf `rule_event` 固定 32 bytes，只包含：

- `timestamp_ns`
- `rule_id`
- `pkt_conds`
- `sip`
- `dip`
- `action`
- `sport`
- `dport`
- `verdict`
- `ip_proto`

具体 ringbuf event ABI 见 `bpf-abi.md`。

---

## 边界说明

- events 是运行态观察记录，不是完整 packet snapshot
- events 不携带构造响应包所需的完整数据
- userspace response 必须使用 XSK 收到的原始包构造响应
- 历史事件存储和查询由 `mgr` 负责
