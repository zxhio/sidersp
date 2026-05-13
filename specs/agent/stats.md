# agent stats

## 定位

`stats` 表示 `agent` 当前运行态计数。

- 只描述当前运行态 counters
- 不保存历史数据
- 不提供历史查询
- 不提供 reset
- 具体 API 路由见 `../agent-api.md`

---

## 统计阶段

- `ingress`：数据包进入 XDP
- `parse`：基础协议解析
- `match`：规则匹配
- `kernel_response`：内核态响应
- `xsk_redirect`：原始包重定向到 XSK
- `userspace_response`：用户态响应
- `dispatch`：命中包异步分发
- `errors`：通用错误

---

## 返回字段口径

字段按 API 返回结构组织。每个字段只定义对外语义和统计位置，不定义内部 counter
名称。内部 BPF ABI 和 counter index 见 `bpf-abi.md`。

### `ingress`

- `packets`
  - 语义：进入 agent dataplane 的包数。
  - 统计位置：包进入 attachment 对应的 XDP 程序入口后立即累加，早于 parse。

### `parse`

- `ok_packets`
  - 语义：基础协议解析成功，并可进入规则匹配的包数。
  - 统计位置：Ethernet / VLAN / IPv4 / TCP / UDP / ICMP / ARP 基础解析通过后累加。
- `error_packets`
  - 语义：基础协议解析失败，不能进入规则匹配的包数。
  - 统计位置：parse 失败并走 attachment `miss_verdict` 前累加。

### `match`

- `hit_packets`
  - 语义：规则匹配成功，并选出最终 `rule_id` 的包数。
  - 统计位置：规则选择完成后、action 执行前累加。
- `miss_packets`
  - 语义：解析成功但没有选出任何规则的包数。
  - 统计位置：规则匹配结束且未命中，走 attachment `miss_verdict` 前累加。

### `kernel_response`

- `packets`
  - 语义：命中 kernel response action，并进入内核态响应路径的包数。
  - 统计位置：action 分派到 kernel response 后、构造响应包前累加。
- `xdp_tx_packets`
  - 语义：通过原入站网口 `XDP_TX` 成功发出的 kernel response 包数。
  - 统计位置：响应包构造完成并成功提交 `XDP_TX` 后累加。
- `redirect_packets`
  - 语义：通过 `bpf_redirect` 从 response 网口成功发出的 kernel response 包数。
  - 统计位置：响应包构造、出口解析和 redirect 提交成功后累加。
- `error_packets`
  - 语义：kernel response 构造或发送失败的包数。
  - 统计位置：构造失败、出口解析失败、redirect 准备失败或发送提交失败时累加。

### `xsk_redirect`

- `packets`
  - 语义：原始包成功通过 `XDP_REDIRECT` 转入 XSK 的包数。
  - 统计位置：XSK metadata 写入完成并成功提交 redirect 后累加。
- `error_packets`
  - 语义：原始包转入 XSK 失败的包数。
  - 统计位置：XSK metadata 写入失败、XSK map redirect 失败或提交失败时累加。

### `userspace_response`

- `xsk_rx_packets`
  - 语义：用户态从 XSK 收到并交给 response 路径处理的原始包数。
  - 统计位置：XSK worker 取到 packet envelope 并识别为 userspace response action 后累加。
- `packets`
  - 语义：用户态成功发送的响应包数。
  - 统计位置：任一 userspace TX backend 成功返回后累加。
- `xsk_tx_packets`
  - 语义：通过原入站网口 XSK 成功发出的 userspace response 包数。
  - 统计位置：同口 XSK TX 成功返回后累加。
- `af_packet_tx_packets`
  - 语义：通过 `AF_PACKET` 从 response 网口成功发出的 userspace response 包数。
  - 统计位置：异口 `AF_PACKET` TX 成功返回后累加。
- `error_packets`
  - 语义：userspace response 构造或发送失败的包数。
  - 统计位置：response 参数解析失败、原始包不兼容、构包失败或 TX backend 失败时累加。

### `dispatch`

- `packets`
  - 语义：进入 dispatch 流程的包数。
  - 统计位置：XSK worker 决定把命中包交给 dispatch 时累加，早于入队。
- `queued_packets`
  - 语义：成功进入 dispatch 队列的包数。
  - 统计位置：非阻塞入队成功后累加。
- `dropped_packets`
  - 语义：未进入 dispatch 队列的包数。
  - 统计位置：队列满、采样或策略导致放弃分发时累加。
- `sent_packets`
  - 语义：成功发送到 downstream 的包数。
  - 统计位置：dispatch worker downstream TX 成功后累加。
- `error_packets`
  - 语义：dispatch worker 发送失败的包数。
  - 统计位置：downstream TX 返回失败后累加。

### `errors`

- `xdp_packets`
  - 语义：XDP/BPF 侧错误聚合。
  - 统计位置：API 返回时由 XDP/BPF 侧阶段错误聚合生成，不作为独立 packet counter 累加。
- `xsk_packets`
  - 语义：XSK/userspace 侧错误聚合。
  - 统计位置：API 返回时由 userspace response 和 dispatch 错误聚合生成，不作为独立 packet counter 累加。

---

## 返回结构示例

```json
{
  "ingress": {
    "packets": 100000
  },
  "parse": {
    "ok_packets": 99000,
    "error_packets": 1000
  },
  "match": {
    "hit_packets": 1200,
    "miss_packets": 97800
  },
  "kernel_response": {
    "packets": 800,
    "xdp_tx_packets": 600,
    "redirect_packets": 200,
    "error_packets": 0
  },
  "xsk_redirect": {
    "packets": 300,
    "error_packets": 2
  },
  "userspace_response": {
    "xsk_rx_packets": 298,
    "packets": 295,
    "xsk_tx_packets": 250,
    "af_packet_tx_packets": 45,
    "error_packets": 3
  },
  "dispatch": {
    "packets": 1200,
    "queued_packets": 1180,
    "dropped_packets": 20,
    "sent_packets": 1100,
    "error_packets": 80
  },
  "errors": {
    "xdp_packets": 0,
    "xsk_packets": 1
  }
}
```

---

## 语义说明

- `xsk_redirect.packets` 只表示原始包成功转入 XSK，不表示用户态响应包已经发出
- `userspace_response.packets` 表示用户态响应包已经成功发出
- `dispatch.packets` 表示规则命中后进入 dispatch 流程的包数
- `dispatch.queued_packets` 表示非阻塞入队成功
- `dispatch.dropped_packets` 不影响 response 执行结果
- `dispatch.sent_packets` 表示异步发送到 downstream 成功
- `kernel_response.error_packets` 不包含 userspace response 错误
- `userspace_response.error_packets` 不包含 kernel response 错误
- `dispatch.error_packets` 不影响 response 结果
- `errors.*` 是聚合视图，允许和各阶段 `error_packets` 重叠
- 本文件约束字段语义和累加位置，不约束内部 counter 名称
- BPF `stats_map` counter 必须以本文件的字段语义和累加位置为基础
