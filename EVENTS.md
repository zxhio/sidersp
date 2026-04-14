# Events

本文档定义首版最小事件模型。

事件由数据面产出，用于向控制面传递命中结果。  
当前事件结构以内核态 `bpf/` 实现为准。

## 事件结构

```json
{
  "timestamp_ns": 1713000000000000000,
  "rule_id": 1001,
  "pkt_conds": 131,
  "action": 1,
  "sip": 167837962,
  "dip": 3232235796,
  "sport": 52345,
  "dport": 80,
  "tcp_flags": 18,
  "ip_proto": 6,
  "payload_len": 128
}
```