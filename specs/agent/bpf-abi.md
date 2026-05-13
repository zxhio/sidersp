# agent BPF ABI

## 定位

`bpf-abi` 定义 BPF 程序和 Go dataplane loader / userspace worker 之间的内部 ABI。

- 只约束 agent 内部实现
- 外部 HTTP API 不直接暴露 BPF map、code 或 struct layout
- 快路径处理语义见 `dataplane.md`
- 事件 API 语义见 `events.md`
- stats API 语义见 `stats.md`

---

## 常量

rule slots：

- `RULE_GROUPS=8`
- `RULES_PER_GROUP=64`
- `MAX_RULE_SLOTS=512`

`mask_t` 是 512 bit 的规则槽位 bitmap。

```text
bits[0..7] uint64
slot = group * 64 + bit
```

---

## BPF maps

| map | type | max entries | key | value | 用途 |
|---|---|---:|---|---|---|
| `rule_index_map` | `ARRAY` | `512` | `uint32 slot` | `rule_meta` | slot 到规则运行态元数据 |
| `global_cfg_map` | `ARRAY` | `1` | `uint32 0` | `global_cfg` | 全局候选规则和 optional bitmap |
| `tx_config_map` | `ARRAY` | `1` | `uint32 0` | `tx_config` | BPF kernel response TX 配置 |
| `src_port_index_map` | `HASH` | `4096` | `uint16 port` | `mask_t` | 源端口倒排索引 |
| `dst_port_index_map` | `HASH` | `4096` | `uint16 port` | `mask_t` | 目的端口倒排索引 |
| `vlan_index_map` | `HASH` | `4096` | `uint16 vlan` | `mask_t` | VLAN 倒排索引 |
| `src_prefix_lpm_map` | `LPM_TRIE` | `4096` | `ipv4_lpm_key` | `mask_t` | 源 IPv4 前缀索引 |
| `dst_prefix_lpm_map` | `LPM_TRIE` | `4096` | `ipv4_lpm_key` | `mask_t` | 目的 IPv4 前缀索引 |
| `flow_cache_map` | `LRU_HASH` | `65536` | `flow_cache_key` | `flow_cache_entry` | 短期 flow action cache |
| `event_ringbuf` | `RINGBUF` | `16 MiB` | none | `rule_event` | 规则事件输出 |
| `stats_map` | `PERCPU_ARRAY` | `STAT_COUNT` | `uint32 index` | `uint64` | BPF 侧计数 |
| `xsks_map` | `XSKMAP` | `64` | `uint32 queue_id` | `uint32 fd` | RX queue 到 XSK socket |

---

## rule_meta

`rule_index_map` 的 value。

```c
struct rule_meta {
    __u32 rule_id;
    __u32 required_mask;
    __u16 action;
    __u8  flags;
};
```

字段：

- `rule_id`：来自 `ruleset.rules[].rule_id`
- `required_mask`：规则要求的正向条件 bitmask
- `action`：BPF action code
- `flags`：预留，当前写入 `0`

不进入 `rule_meta`：

- `priority`
- `name`
- `enabled`
- `response.params`
- `created_at`
- `updated_at`

---

## global_cfg

`global_cfg_map[0]` 的 value。

| 字段 | 类型 | 含义 |
|---|---|---|
| `all_active_rules` | `mask_t` | 所有已编译启用规则 |
| `vlan_optional_rules` | `mask_t` | 未配置 VLAN 条件的规则 |
| `src_port_optional_rules` | `mask_t` | 未配置源端口条件的规则 |
| `dst_port_optional_rules` | `mask_t` | 未配置目的端口条件的规则 |
| `src_prefix_optional_rules` | `mask_t` | 未配置源前缀条件的规则 |
| `dst_prefix_optional_rules` | `mask_t` | 未配置目的前缀条件的规则 |
| `ingress_verdict` | `uint32` | `attachment.miss_verdict` 的编译值，`0=pass`，`1=drop` |

---

## 倒排索引

- `vlan_index_map` key 是 VLAN ID。
- `src_port_index_map` key 是 TCP/UDP 源端口。
- `dst_port_index_map` key 是 TCP/UDP 目的端口。
- `src_prefix_lpm_map` 和 `dst_prefix_lpm_map` value 是累计候选 bitmap。
- LPM lookup 使用 `/32` key 查找，userspace 必须生成和 BPF lookup 一致的 key 字节布局。

sentinel：

- VLAN `0xffff` 表示无 VLAN。
- port `0` 表示无端口条件。

---

## condition bits

`required_mask` 和 `pkt_conds` 使用相同 bit layout。

| bit | name | 含义 |
|---:|---|---|
| 0 | `COND_PROTO_TCP` | IPv4 TCP |
| 1 | `COND_PROTO_UDP` | IPv4 UDP |
| 2 | `COND_PROTO_ICMP` | IPv4 ICMP |
| 3 | `COND_PROTO_ARP` | ARP |
| 4 | `COND_VLAN` | 包含 VLAN tag |
| 5 | `COND_SRC_PREFIX` | 源 IPv4 命中源前缀条件 |
| 6 | `COND_DST_PREFIX` | 目的 IPv4 命中目的前缀条件 |
| 7 | `COND_SRC_PORT` | TCP/UDP 源端口命中 |
| 8 | `COND_DST_PORT` | TCP/UDP 目的端口命中 |
| 9 | `COND_TCP_SYN` | TCP SYN |
| 10 | `COND_TCP_ACK` | TCP ACK |
| 11 | `COND_TCP_RST` | TCP RST |
| 12 | `COND_TCP_FIN` | TCP FIN |
| 13 | `COND_TCP_PSH` | TCP PSH |
| 14 | `COND_ICMP_ECHO_REQUEST` | ICMP echo request |
| 15 | `COND_ICMP_ECHO_REPLY` | ICMP echo reply |
| 16 | `COND_ARP_REQUEST` | ARP request |
| 17 | `COND_ARP_REPLY` | ARP reply |
| 18 | `COND_L4_PAYLOAD` | L4 payload 长度大于 0 |

---

## action codes

| code | name | `response.action` |
|---:|---|---|
| 0 | `ACTION_NONE` | `none` |
| 1 | `ACTION_ALERT` | `alert` |
| 2 | `ACTION_TCP_RESET` | `tcp_reset` |
| 3 | `ACTION_ICMP_ECHO_REPLY` | `icmp_echo_reply` |
| 4 | `ACTION_ARP_REPLY` | `arp_reply` |
| 5 | `ACTION_TCP_SYN_ACK` | `tcp_syn_ack` |
| 6 | `ACTION_ICMP_PORT_UNREACHABLE` | `icmp_port_unreachable` |
| 7 | `ACTION_UDP_ECHO_REPLY` | `udp_echo_reply` |
| 8 | `ACTION_DNS_REFUSED` | `dns_refused` |
| 9 | `ACTION_ICMP_HOST_UNREACHABLE` | `icmp_host_unreachable` |
| 10 | `ACTION_ICMP_ADMIN_PROHIBITED` | `icmp_admin_prohibited` |
| 11 | `ACTION_DNS_SINKHOLE` | `dns_sinkhole` |

---

## event verdict codes

`rule_event.verdict` 不是 XDP verdict。

它表示命中规则后的 dataplane 处置结果，并映射到 `events.md` 的 `verdict` 字符串。

| code | BPF name | `events.verdict` | 含义 |
|---:|---|---|---|
| 0 | `VERDICT_OBSERVE` | `observe` | 仅观测，不发送响应 |
| 1 | `VERDICT_TX` | `xdp_tx` | 通过原入站网口 `XDP_TX` 发送 |
| 2 | `VERDICT_XSK` | `xsk_redirect` | 原始包重定向到 XSK |
| 3 | `VERDICT_REDIRECT_TX` | `redirect_tx` | 通过 BPF redirect 从配置出口发送 |

`path`、`result` 和 `ifindex` 不是 BPF ringbuf ABI 字段。需要展示时由 agent 根据
action、runtime path、attachment / reader context 或 userspace response result
派生。

---

## tx_config

`tx_config_map[0]` 的 value。

`tx_config` 只作用于 BPF kernel response 路径。字段名沿用当前 BPF ABI 的
`tcp_reset_*`，语义适用于当前 kernel response action。

| 字段 | 类型 | 含义 |
|---|---|---|
| `tcp_reset_mode` | `uint32` | `0=xdp_tx`，`1=redirect` |
| `tcp_reset_egress_ifindex` | `uint32` | redirect 出口 ifindex |
| `tcp_reset_vlan_mode` | `uint32` | `0=preserve`，`1=access` |
| `tcp_reset_failure_verdict` | `uint32` | kernel response 构造或发送失败后的处置，`0=pass`，`1=drop` |

---

## ringbuf event ABI

`event_ringbuf` 容量为 `16 MiB`。

- 每个匹配包最多尝试写入一个 `rule_event`
- ringbuf 满或 reserve 失败时丢弃事件
- 丢弃时递增 `STAT_EVENT_DROPPED_PACKETS`

`rule_event` 固定 32 bytes。

| offset | size | field | byte order / 含义 |
|---:|---:|---|---|
| 0 | 8 | `timestamp_ns` | monotonic nanoseconds |
| 8 | 4 | `rule_id` | host order |
| 12 | 4 | `pkt_conds` | condition bitmask |
| 16 | 4 | `sip` | host order IPv4 |
| 20 | 4 | `dip` | host order IPv4 |
| 24 | 2 | `action` | action code |
| 26 | 2 | `sport` | host order |
| 28 | 2 | `dport` | host order |
| 30 | 1 | `verdict` | event verdict code |
| 31 | 1 | `ip_proto` | IP protocol number |

不在 `rule_event` 中：

- `ifindex`：由 agent 的 attachment / reader context 补充。
- `path`：由 action 和运行态执行路径派生。
- `result`：由 response / dispatch userspace 执行结果产生，不进入 BPF ringbuf。

---

## stats map

`stats_map` 是 `PERCPU_ARRAY<uint32, uint64>`。

counter 语义以 `stats.md` 的返回字段和累加位置为基础。

| index | name | 对齐字段 | 累加位置 |
|---:|---|---|---|
| 0 | `STAT_INGRESS_PACKETS` | `ingress.packets` | XDP 程序入口，早于 parse |
| 1 | `STAT_PARSE_OK_PACKETS` | `parse.ok_packets` | 基础协议解析成功后 |
| 2 | `STAT_PARSE_ERROR_PACKETS` | `parse.error_packets` | parse 失败并走 attachment `miss_verdict` 前 |
| 3 | `STAT_MATCH_HIT_PACKETS` | `match.hit_packets` | 规则选择完成后、action 执行前 |
| 4 | `STAT_MATCH_MISS_PACKETS` | `match.miss_packets` | 规则匹配结束且未命中，走 attachment `miss_verdict` 前 |
| 5 | `STAT_KERNEL_RESPONSE_PACKETS` | `kernel_response.packets` | action 分派到 kernel response 后、构造响应包前 |
| 6 | `STAT_KERNEL_RESPONSE_XDP_TX_PACKETS` | `kernel_response.xdp_tx_packets` | 响应包构造完成并成功提交 `XDP_TX` 后 |
| 7 | `STAT_KERNEL_RESPONSE_REDIRECT_PACKETS` | `kernel_response.redirect_packets` | 响应包构造、出口解析和 redirect 提交成功后 |
| 8 | `STAT_KERNEL_RESPONSE_ERROR_PACKETS` | `kernel_response.error_packets` | kernel response 构造、出口解析、redirect 准备或提交失败时 |
| 9 | `STAT_XSK_REDIRECT_PACKETS` | `xsk_redirect.packets` | XSK metadata 写入完成并成功提交 redirect 后 |
| 10 | `STAT_XSK_REDIRECT_ERROR_PACKETS` | `xsk_redirect.error_packets` | XSK metadata 写入失败、XSK map redirect 失败或提交失败时 |
| 11 | `STAT_EVENT_DROPPED_PACKETS` | `errors.xdp_packets` 的输入 | ringbuf reserve 失败或事件丢弃时 |

不进入 BPF `stats_map`：

- `userspace_response.*`：由 userspace response runtime 累加。
- `dispatch.*`：由 dispatch runtime 累加。
- `errors.xdp_packets`：API 返回时由 XDP/BPF 侧错误字段聚合生成。
- `errors.xsk_packets`：API 返回时由 XSK/userspace 侧错误字段聚合生成。

---

## XSK metadata ABI

XSK redirect 前，BPF 在 XDP metadata 写入 8 bytes `xsk_meta`。

```c
struct xsk_meta {
    __u32 rule_id;
    __u16 action;
    __u16 reserved;
};
```

约定：

- `rule_id` 来自命中的 `rule_meta.rule_id`
- `action` 是 BPF action code
- `reserved` 当前为 `0`

---

## 变更约定

- 修改 BPF map 名称、类型、key/value 布局、condition bit、action code、event code、stats index、event ABI 或 XSK metadata ABI 时，必须同步更新本文件。
- 修改 BPF 结构后必须重新生成 `internal/dataplane/sidersp_bpfel.go`。
- 不直接编辑 `internal/dataplane/sidersp_bpfel.go`。
