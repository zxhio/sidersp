# Events

本文档定义数据面观测事件模型。

事件由数据面产出，用于状态展示、统计和审计。  
事件不承担构造响应包所需的原始包传输；XSK TX 需要完整原包时，通过 XSK 获取。

## 事件定位

- 同步 TX 动作：BPF 可输出观测事件，但响应不依赖事件消费。
- XSK TX 动作：BPF 将原包提交到 XSK；ringbuf event 只记录命中和提交结果。
- 用户态 XSK worker 另外输出响应结果，见 `RESPONSES.md`。

## 事件结构

```json
{
  "timestamp_ns": 1713000000000000000,
  "rule_id": 1001,
  "pkt_conds": 131,
  "action": "tcp_reset",
  "verdict": "xdp_tx",
  "sip": 167837962,
  "dip": 3232235796,
  "sport": 52345,
  "dport": 80,
  "ip_proto": 6
}
```

## 字段说明

| 字段 | 说明 |
|------|------|
| `rule_id` | 命中的规则 ID |
| `pkt_conds` | 数据面提取的条件位 |
| `action` | 响应动作；BPF ringbuf 字段为 action code，用户侧展示为动作名 |
| `verdict` | 数据面业务裁决：`observe`、`xdp_tx`、`xsk` |
| `sip` / `dip` | IPv4 地址，host byte order |
| `sport` / `dport` | L4 端口，host byte order |
| `ip_proto` | IP protocol |

## 原始包上下文

事件不是“大而全”的 packet snapshot。  
需要 MAC、ARP 字段、ICMP id/seq、TCP seq/ack/options 等上下文时，XSK TX 通过 XSK 读取完整原包并在用户态解析。
