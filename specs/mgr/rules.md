# mgr rules

## 定位

`rules` 表示用户管理的规则资源。

- 由 `mgr` 提供 CRUD
- 由 `mgr` 持久化
- 面向 Web/API 展示和编辑
- `agent` 不直接接收 `rules`
- `mgr` 根据启用的 `rules` 生成最终 `ruleset` 下发给 `agent`

---

## 资源结构

```json
{
  "rule_id": 1001,
  "name": "http_tcp_reset",
  "enabled": true,
  "priority": 100,
  "match": {
    "protocol": "tcp",
    "vlans": [100, 200],
    "src_prefixes": ["10.0.0.0/8"],
    "dst_prefixes": ["192.168.1.0/24"],
    "src_ports": [12345, 23456],
    "dst_ports": [80, 8080],
    "tcp_flags": {
      "syn": true
    }
  },
  "response": {
    "action": "tcp_reset",
    "params": {}
  },
  "created_at": 1710000000,
  "updated_at": 1710003600
}
```

---

## 字段约定

### `rule_id`

- 只读
- 类型：`uint32`
- 由 `mgr` 生成
- 创建后不可修改
- 删除后不复用
- 用于 `stats` / `events` 关联规则

### `name`

- 必填
- 不能为空
- 用于展示、搜索和审计

### `enabled`

- 可选
- 默认值：`false`
- `true`：参与生成最终 `ruleset`
- `false`：只持久化，不下发到 `agent`

### `priority`

- 可选
- 默认值：`0`
- 必须大于等于 `0`
- 数值越小优先级越高

### `match`

- 可选
- 为空表示匹配所有包
- 同一字段内多个值是 OR
- 不同字段之间是 AND
- 只支持正向匹配，不支持否定条件

### `response.action`

- 必填
- 表示规则命中后的响应动作
- 必须是支持的 action 枚举值
- 下发时保留到 agent `ruleset`
- 具体执行路径由 `agent` 的 `response` 逻辑决定

### `response.params`

- 可选
- 动作相关参数
- 不同 `action` 有不同参数约束
- 不需要参数的 `action` 应为空或省略

### `created_at`

- 只读
- 秒级时间戳
- 规则创建时间

### `updated_at`

- 只读
- 秒级时间戳
- 规则更新时间

---

## Match 字段

### `match.protocol`

- 可选
- 可选值：`tcp` / `udp` / `icmp` / `arp`
- 表示协议匹配条件

### `match.vlans`

- 可选
- VLAN ID 数组
- 取值范围：`0..4095`

### `match.src_prefixes`

- 可选
- IPv4 CIDR 数组
- 表示源 IP 前缀匹配

### `match.dst_prefixes`

- 可选
- IPv4 CIDR 数组
- 表示目的 IP 前缀匹配

### `match.src_ports`

- 可选
- TCP / UDP 源端口数组
- 取值范围：`1..65535`

### `match.dst_ports`

- 可选
- TCP / UDP 目的端口数组
- 取值范围：`1..65535`

### `match.tcp_flags`

- 可选
- 仅支持值为 `true`
- 可选字段：`syn` / `ack` / `rst` / `fin` / `psh`
- 不支持 `false` 形式的否定条件

### `match.icmp.type`

- 可选
- 可选值：`echo_request` / `echo_reply`

### `match.arp.operation`

- 可选
- 可选值：`request` / `reply`

---

## Match 语义

- 配置的所有字段必须同时匹配
- 字段未配置时表示该字段为 wildcard
- 同一字段内多个值表示 OR
- 不同字段之间表示 AND
- 如果多条规则同时匹配，按排序结果选择第一条
- 排序规则为：`priority ASC, rule_id ASC`

---

## Response Action

`response.action` 可选值：

- `none`：仅匹配，不执行响应动作
- `alert`：产生事件，不执行响应动作
- `tcp_reset`：构造 TCP RST 响应
- `icmp_echo_reply`：构造 ICMP echo reply 响应
- `tcp_syn_ack`：构造 TCP SYN-ACK 响应
- `icmp_port_unreachable`：构造 ICMP port unreachable 响应
- `icmp_host_unreachable`：构造 ICMP host unreachable 响应
- `icmp_admin_prohibited`：构造 ICMP admin prohibited 响应
- `udp_echo_reply`：构造 UDP echo reply 响应
- `dns_sinkhole`：构造 DNS sinkhole 响应
- `dns_refused`：构造 DNS refused 响应
- `arp_reply`：构造 ARP reply 响应

---

## Response Params

### `none`

- 不允许 `params`

### `alert`

- 不允许 `params`

### `tcp_reset`

- 不允许 `params`

### `icmp_echo_reply`

- 不允许 `params`

### `tcp_syn_ack`

- 可选 `tcp_seq`
- `tcp_seq` 取值范围：`0..4294967295`
- 省略时由 `agent` 使用默认值

### `icmp_port_unreachable`

- 不允许 `params`

### `icmp_host_unreachable`

- 不允许 `params`

### `icmp_admin_prohibited`

- 不允许 `params`

### `udp_echo_reply`

- 不允许 `params`

### `dns_refused`

- 可选 `rcode`
- 可选值：`refused` / `nxdomain` / `servfail`
- 省略时默认 `refused`

### `dns_sinkhole`

- 必填 `family`
- `family` 可选值：`ipv4` / `ipv6` / `dual`
- `family=ipv4` 时需要 `answers_v4`
- `family=ipv6` 时需要 `answers_v6`
- `family=dual` 时需要 `answers_v4` 和 `answers_v6`
- 可选 `ttl`
- `ttl` 取值范围：`0..2147483647`
- 省略时默认 `60`

### `arp_reply`

- 可选 `hardware_addr`
- 可选 `sender_ipv4`

---

## Action 兼容性

- `tcp_reset` 要求 `match.protocol=tcp`
- `icmp_echo_reply` 要求 `match.protocol=icmp` 且 `match.icmp.type=echo_request`
- `tcp_syn_ack` 要求 `match.protocol=tcp` 且 `match.tcp_flags.syn=true`
- `icmp_port_unreachable` 要求 `match.protocol=udp`
- `icmp_host_unreachable` 要求 `match.protocol=udp`
- `icmp_admin_prohibited` 要求 `match.protocol=udp`
- `udp_echo_reply` 要求 `match.protocol=udp`
- `dns_sinkhole` 要求 `match.protocol=udp`
- `dns_refused` 要求 `match.protocol=udp`
- `arp_reply` 要求 `match.protocol=arp` 且 `match.arp.operation=request`
- 不兼容的 `match` / `response.action` 组合必须拒绝

---

## 校验约定

- `rule_id` 由 `mgr` 生成，创建请求中不需要传入，并且不复用历史 `rule_id`
- `name` 不能为空
- `priority` 必须大于等于 `0`
- `match` 只能包含支持的正向匹配字段
- `protocol`、`response.action`、`icmp.type`、`arp.operation` 必须是合法值
- `vlans` 取值范围为 `0..4095`
- `src_ports` / `dst_ports` 取值范围为 `1..65535`
- `src_prefixes` / `dst_prefixes` 必须是合法 IPv4 CIDR
- `tcp_flags` 只允许配置为 `true`
- `response.params` 必须符合对应 `response.action` 的参数约束
- 不兼容的 `match` / `response.action` 组合必须拒绝

---

## Rules 到 Ruleset

`mgr` 根据 `rules` 生成最终 `ruleset`。

生成流程：

- 过滤 `enabled=false` 的规则
- 按 `priority ASC, rule_id ASC` 排序
- 去掉管理态字段
- 生成 `version`
- 调用 `agent` 的 `PUT /api/v1/ruleset`

不会进入 `ruleset` 的字段：

- `name`
- `enabled`
- `created_at`
- `updated_at`
- 仅供管理态使用的字段

保留进入 `ruleset` 的字段：

- `rule_id`
- `priority`
- `match`
- `response`

---

## 资源边界

- `rules`：用户管理的规则资源，由 `mgr` 持久化
- `ruleset`：由 `mgr` 内部生成，只用于下发给 `agent`
- `stats` / `events`：通过 `rule_id` 关联规则
- `agent/response.md`：描述 response 的运行态执行路径
