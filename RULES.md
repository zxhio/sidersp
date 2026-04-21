# Rules

本文档定义规则模型、匹配语义和响应路径语义。

## 规则结构

```yaml
id: 1001
name: http_tcp_reset
enabled: true
priority: 100
match:
  protocol: tcp
  vlans: [100, 200]
  src_prefixes: ["10.0.0.0/8"]
  dst_prefixes: ["192.168.1.0/24"]
  src_ports: [12345, 23456]
  dst_ports: [80, 8080]
  tcp_flags:
    syn: true
response:
  action: tcp_reset
```

### `match`

- `protocol`：可选但推荐填写，支持 `tcp`、`udp`、`icmp`、`arp`。
- `vlans`：可选，匹配 VLAN ID。
- `src_prefixes` / `dst_prefixes`：可选，匹配 IPv4 前缀。
- `src_ports` / `dst_ports`：可选，匹配 TCP/UDP 端口。
- `tcp_flags`：可选，仅对 TCP 生效，支持 `true` 条件。
- `icmp`：可选，仅对 ICMP 生效，例如 `type: echo_request`。
- `arp`：可选，仅对 ARP 生效，例如 `operation: request`。

规则不支持否定条件。下面这种规则会被控制面拒绝：

```yaml
tcp_flags:
  syn: true
  ack: false
```

规则模型不包含 `features` 字段。

### `response`

```yaml
response:
  action: tcp_reset
  params: {}
```

- `action` 表示命中后的响应动作，统一使用 snake_case。
- `params` 保留在规则结构中，不写入 BPF `rule_meta`。

执行路径不暴露为规则字段。控制面只编码 `action`，具体行为由数据面和响应执行模块按 action 固化。

Action 列表：

| action | 说明 |
|--------|------|
| `none` | 不执行响应动作 |
| `alert` | 只输出观测/告警结果 |
| `tcp_reset` | BPF 内同步构造 TCP RST 并 `XDP_TX` |
| `icmp_echo_reply` | 原包提交到 XSK 后由用户态构造 echo reply 并 TX |
| `arp_reply` | 原包提交到 XSK 后由用户态构造 ARP reply 并 TX |
| `tcp_syn_ack` | 原包提交到 XSK 后由用户态构造 TCP SYN-ACK 并 TX |

示例：

```yaml
response:
  action: icmp_echo_reply
```

```yaml
response:
  action: arp_reply
  params:
    sender_mac: "02:00:00:00:00:01"
```

## 优先级语义

- `priority` 数值越小，优先级越高
- 多条规则同时满足时，优先选择 `priority` 更小的规则
- 相同 `priority` 下保持现有顺序

## 控制面归一化

规则加载后，控制面只把 `response.action` 编码为内核态 action code。执行行为在数据面代码中按 action 固化：

- `none`：静默匹配后 `XDP_PASS`
- `alert`：输出观测事件后 `XDP_PASS`
- `tcp_reset`：同步构造 TCP RST 并 `XDP_TX`
- `icmp_echo_reply` / `arp_reply` / `tcp_syn_ack`：提交到 XSK，由用户态响应执行模块 TX

外部规则不暴露 `xdp`、`xsk`、`用户态` 等实现细节。

控制面同时负责把规则编译成内核态所需的低级结构：

- 过滤 `enabled=false` 的规则。
- 校验 rule id 唯一。
- 校验 match 字段和 action 名称的合法取值。
- 按 `(priority ASC, id ASC)` 排序 active rules。
- 将具体值写入索引 map，例如端口、VLAN、IPv4 前缀。
- 将正向语义条件编译成 `required_mask`。

内核态 `rule_meta` 只保存 active compiled rule：

```text
rule_id
required_mask
action
flags
```

`enabled`、`priority` 和否定条件不进入内核态规则。
