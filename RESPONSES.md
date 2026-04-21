# Responses

本文档定义主动响应动作模型和执行路径。

规则命中后，控制面会将 `response.action` 编码为内核态 action code。  
`tcp_reset` 属于同步 TX：BPF 直接构造响应包并 `XDP_TX`；ICMP/ARP/TCP handshake spoof 属于 XSK TX：BPF 在帧头写入 `xsk_meta` 后提交到 XSK。

## 动作命名

响应动作统一使用 snake_case：

| action | 说明 |
|--------|------|
| `none` | 不执行响应 |
| `alert` | 只记录观测/告警结果 |
| `tcp_reset` | BPF 内同步构造 TCP RST 并 `XDP_TX` |
| `icmp_echo_reply` | 用户态基于 XSK 原包构造 ICMP echo reply 并发送 |
| `arp_reply` | 用户态基于 XSK 原包构造 ARP reply 并发送 |
| `tcp_syn_ack` | 用户态基于 XSK 原包构造 TCP SYN-ACK 并发送 |

## 执行路径

### 同步 TX

用于必须低延迟响应的动作。同步 TX 动作为 `tcp_reset`。

```text
packet in -> BPF parse/match -> build TCP RST in-place -> XDP_TX
```

同步 TX 不依赖 ringbuf 或用户态执行。ringbuf event 只用于观测。

### XSK TX

用于需要完整原包上下文的 spoof 动作。

```text
packet in -> BPF parse/match -> prepend xsk_meta -> submit to XSK
XSK worker -> read xsk_meta -> parse full packet -> build response -> XSK_TX
```

XSK TX 不依赖 ringbuf 携带原包或构包字段。`xsk_meta` 携带 `rule_id` 和 `action`，用户态 XSK worker 从 XSK 原包中解析构造响应所需字段。

## 响应结果结构

> Note: The following structure represents the planned XSK worker response
> result. The current implementation only emits ringbuf observation events
> with verdict (OBSERVE / TX / XSK). Full response results will be available
> after the XSK worker implementation is complete.

响应结果由 BPF TX 统计或用户态 XSK worker 生成，用于状态展示和审计。

```json
{
  "ts": 1713000000000000000,
  "rule_id": 1001,
  "action": "icmp_echo_reply",
  "result": "sent",
  "ifindex": 2,
  "rx_queue": 0,
  "sip": 167837962,
  "dip": 3232235796,
  "sport": 52345,
  "dport": 80,
  "ip_proto": 1,
  "error": ""
}
```

## 模块边界

- BPF 同步 TX 实现固定动作 `tcp_reset`。
- 用户态 XSK worker 只处理需要完整原包上下文的 TX action。
- 控制面负责校验和编码 action；具体执行行为由 BPF / XSK worker 按 action 固化。
- ringbuf 只做观测事件，不作为构包数据通道。
