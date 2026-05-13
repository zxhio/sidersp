# agent response

## 定位

`response` 描述 `agent` 的响应相关运行态能力。

包含两部分：

- `/api/v1/response`：响应包默认出口配置
- response execution：`response.action` 在 agent 中的执行路径

约定：

- `response.action` 来自运行时 `ruleset`
- `response.action` 的枚举和参数约束以 `../mgr/rules.md` 为准
- `agent` 根据 `response.action` 选择运行态执行路径
- 具体 API 路由见 `../agent-api.md`

---

## Response API

`/api/v1/response` 用于配置异口响应时使用的默认出口网口。

未配置 response 时，默认使用入站网口发送。

## 资源结构

```json
{
  "ifindex": 3,
  "ifname": "eth1",
  "vlan_mode": "preserve"
}
```

---

## 字段约定

### `ifindex`

- `PUT /api/v1/response` 时必填
- 必须大于 `0`
- Linux 网卡 `ifindex`
- 表示 response 默认出口网口
- 未配置 response 时为空或 `0`

### `ifname`

- 可选
- 如果传入，需要校验是否和 `ifindex` 匹配
- 仅用于展示、日志和调试

### `vlan_mode`

- 可选
- 默认值：`preserve`
- 可选值：`preserve` / `access`
- 表示异口响应时 VLAN tag 的处理方式

---

## `vlan_mode` 语义

### `preserve`

- 保留原始请求包中的 VLAN tag
- 适合 response 网口是 trunk 口的场景
- 响应包从 response 网口发出时继续携带原 VLAN tag

### `access`

- 去掉原始请求包中的 VLAN tag
- 适合 response 网口是 access 口的场景
- 响应包从 response 网口发出时不携带 VLAN tag

---

## API 行为

### get

`GET /api/v1/response` 查看当前 response 配置。

- 未配置时返回默认同口发送状态
- `ifindex` 为空或 `0`
- `vlan_mode` 使用默认值 `preserve`

### put

`PUT /api/v1/response` 整体替换 response 配置。

- 校验 `ifindex`
- 如果传入 `ifname`，必须和 `ifindex` 匹配
- 成功后返回规范化后的 response 配置

### delete

`DELETE /api/v1/response` 删除 response 配置。

- 删除后恢复默认同口发送
- 成功时返回 `204`
- 未配置时也返回 `204`

### recovery

- 进程重启后 response 配置恢复为默认同口发送
- 需要恢复异口 response 时，由 `mgr` 重新调用 `PUT /api/v1/response` 下发期望配置

---

## Response Execution

`agent` 根据 `ruleset.rules[].response.action` 选择运行态执行路径。

### no response

用于：

- `none`
- `alert`

语义：

- 不构造响应包
- `alert` 只产生事件
- 事件 `path=none`，`verdict=observe`，`result=matched`

### kernel response

用于：

- `tcp_reset`
- `icmp_port_unreachable`
- `icmp_host_unreachable`
- `icmp_admin_prohibited`

语义：

- 在 XDP/BPF 内核态构造响应包
- 入站网口支持发送时，通过 `XDP_TX` 从原网口发出
- 入站网口不支持发送时，通过 `bpf_redirect` 从 response 网口发出
- 异口发送时根据 `vlan_mode` 处理 VLAN tag
- `XDP_TX` 成功时事件 `path=kernel`，`verdict=xdp_tx`，`result=sent`
- `bpf_redirect` 成功时事件 `path=kernel`，`verdict=redirect_tx`，`result=sent`
- 失败时事件 `path=kernel`，使用对应 `verdict`，`result=failed`

### userspace response

用于：

- `icmp_echo_reply`
- `tcp_syn_ack`
- `udp_echo_reply`
- `dns_sinkhole`
- `dns_refused`
- `arp_reply`

语义：

- XDP 侧通过 `XDP_REDIRECT` 将原始包转入 XSK
- 用户态从 XSK 收包
- 用户态构造响应包
- 入站网口支持发送时，通过 XSK 从原网口发出
- 入站网口不支持发送时，通过 `AF_PACKET` 从 response 网口发出
- 异口发送时根据 `vlan_mode` 处理 VLAN tag
- BPF redirect 成功时，ringbuf 事件可派生为 `path=userspace`、`verdict=xsk_redirect`
- `verdict=xsk_redirect` 只表示原始包进入 XSK，不表示响应包已发送
- userspace response 的 `sent` / `failed` 来自 response 执行结果，不来自 BPF ringbuf

userspace response 构包需要完整原始包，不能依赖 ringbuf event。

---

## 构包数据来源

### 来自 `ruleset`

`ruleset.rules[].response.action` 决定执行路径和 response builder。

`ruleset.rules[].response.params` 只用于需要动作参数的 userspace response。参数约束以
`../mgr/rules.md` 为准。

| `response.action` | 使用的 `response.params` |
|---|---|
| `tcp_syn_ack` | `tcp_seq`，省略时使用默认值 |
| `dns_refused` | `rcode`，省略时默认 `refused` |
| `dns_sinkhole` | `family`、`answers_v4`、`answers_v6`、`ttl` |
| `arp_reply` | `hardware_addr`、`sender_ipv4` |

以下 action 不使用 `response.params`：

- `none`
- `alert`
- `tcp_reset`
- `icmp_echo_reply`
- `icmp_port_unreachable`
- `icmp_host_unreachable`
- `icmp_admin_prohibited`
- `udp_echo_reply`

### 来自原始包

userspace response 从 XSK 收到的原始包中提取构包字段。

- Ethernet MAC 地址和 VLAN tag
- IPv4 地址和 L4 tuple
- ICMP echo request 字段
- UDP payload
- DNS request ID、flags、question 和 query type
- ARP request sender / target 字段

### 来自运行态配置

`/api/v1/response` 提供默认出口配置。

- `ifindex` / `ifname`：异口发送的默认出口
- `vlan_mode`：异口发送时 VLAN tag 处理方式

未配置 response 出口时，默认从入站网口发送。

### 来自 XSK metadata

XSK metadata 只携带 dispatch 必要信息。

- `rule_id`
- action code

metadata 不携带 packet tuple、DNS question、ARP 字段或 response 参数。

---

## Action 路径映射

| `response.action` | 路径 |
|---|---|
| `none` | `none` |
| `alert` | `none` |
| `tcp_reset` | `kernel` |
| `icmp_port_unreachable` | `kernel` |
| `icmp_host_unreachable` | `kernel` |
| `icmp_admin_prohibited` | `kernel` |
| `icmp_echo_reply` | `userspace` |
| `tcp_syn_ack` | `userspace` |
| `udp_echo_reply` | `userspace` |
| `dns_sinkhole` | `userspace` |
| `dns_refused` | `userspace` |
| `arp_reply` | `userspace` |

---

## stats 关联

kernel response：

- `kernel_response.packets`
- `kernel_response.xdp_tx_packets`
- `kernel_response.redirect_packets`
- `kernel_response.error_packets`

userspace response：

- `xsk_redirect.packets`
- `xsk_redirect.error_packets`
- `userspace_response.xsk_rx_packets`
- `userspace_response.packets`
- `userspace_response.xsk_tx_packets`
- `userspace_response.af_packet_tx_packets`
- `userspace_response.error_packets`

---

## events 关联

response 执行结果通过 `events` 上报。

事件字段约定见 `events.md`。

常见结果：

- `matched`：规则命中，但没有响应包发送
- `sent`：响应包已发送
- `failed`：响应执行失败

---

## 资源边界

- `response`：描述 response 默认出口配置和响应执行路径
- `ruleset`：提供 `response.action` 和 `response.params`
- `../mgr/rules.md`：定义 `response.action` 枚举和参数约束
- `events`：上报响应执行结果
- `stats`：记录响应相关运行态计数

不作为本文件公共合同的内部细节：

- result buffer 的存储结构、容量和淘汰策略
- runtime YAML 的旧字段布局
- AF_XDP / AF_PACKET socket 的具体实现
- response builder 的内部解析和 checksum 流程

如后续需要暴露 result 查询、持久化配置或 transport 选择，必须新增明确 API / config
合同，而不是从旧 runtime 文档隐式继承。
