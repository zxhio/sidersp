# BPF Test Plan (MVP)

所有内核测试通过 `objs.XdpSidersp.Test(packet)` 执行，不需要真实网卡。
门控：`SIDERSP_RUN_BPF_TESTS=1`。

本文是测试参考，不定义产品契约。

BPF ABI、事件和统计字段以 `specs/agent/bpf-abi.md`、`specs/agent/events.md` 和 `specs/agent/stats.md` 为准。

---

## 1. Ruleset 编译

| 用例 | 验证点 |
|------|--------|
| 单条规则 | rule_index_map / global_cfg_map / 索引 map 写入正确 |
| 多条规则排序 | slot 按 priority ASC, rule_id ASC |
| enabled=false 过滤 | 不出现在 all_active_rules |
| 空 ruleset | all_active_rules 全零 |
| 条件位编译 | 各 protocol / tcp_flags / icmp / arp 编译为正确的 required_mask |
| optional 路径 | 无条件的规则出现在各 optional 位图 |
| LPM 累积 | /24 条目包含自身和更宽前缀的规则 |
| action 编译 | 11 种 action → 正确 code |

## 2. 解析

gopacket 构造包 → `prog.Test()` → stats 计数判断。

**正常（`parse.error_packets` 不增）**：TCP SYN / TCP ACK / UDP / ICMP echo req / ARP request / VLAN TCP

**失败（`parse.error_packets` 增加）**：截断 eth / 截断 IP / IHL!=5 / 截断 TCP / 截断 UDP / IPv6 / 未知 ethertype / 双层 VLAN

## 3. 匹配

每条用例同时送入 BPF 和 reference matcher，比对结果。

| 用例 | 条件 |
|------|------|
| 单条件 dst_port | dst_ports=[80] |
| 单条件 src_prefix | src_prefixes=[10.0.3.0/24] |
| 单条件 vlan | vlans=[100] |
| 多条件 AND | proto+dst_prefix+dst_port |
| 不匹配 | 错 protocol / 错 port / 错 IP |
| optional 路径 | 无 VLAN 条件 + tagged 包 |

**优先级**：

| 用例 | 规则 | 验证 |
|------|------|------|
| 两条重叠不同 priority | prio 100,200 | 低 prio 胜出 |
| 两条重叠同 priority | 不同 rule_id | 小 rule_id 胜出 |

**LPM 边界**：/24 网络首地址 / 末地址 / 前一地址 / 后一地址

## 4. TX / 重定向

**TCP Reset**：SYN→RST+ACK / ACK+payload→RST / RST 输入不响应

验证 out 包：MAC 交换、IP 交换、port 交换、seq/ack 正确、checksum 合法、window=0。

**ICMP Unreachable**：port_unreachable / host_unreachable / admin_prohibited，通过 stats 计数验证。

**Ingress Verdict**：parse failure 或 no match 时，pass→XDP_PASS / drop→XDP_DROP。

## 5. Event

匹配时验证 event 字段：rule_id / action code / sip / dip / sport / dport / ip_proto / verdict。

`verdict` 逻辑值使用 `observe` / `xdp_tx` / `xsk_redirect` / `redirect_tx`。

不匹配 / parse failure 时无 event。

## 6. Flow Cache

首包填充 cache，重复包命中 cache 执行 action。清空规则后 cache 仍生效。

---

## Benchmark

Benchmark 只覆盖核心热路径和少量稳定 case。

边界条件、错误包、各 action 变体和内部函数耗时留给功能测试或专项回归基准。

| 核心路径 | Case | 衡量点 |
|----------|------|--------|
| Ruleset apply | 256 条混合规则，全量应用 | normalize / compile / map 写入的端到端成本 |
| Parse miss | TCP 包无命中规则，走 `miss_verdict=pass` | 解析、索引查找和 miss path 成本 |
| Indexed match | 256 条混合规则，命中一条 `observe` 规则 | 候选合并、优先级选择和 event 输出成本 |
| Kernel response | TCP SYN 命中 `tcp_reset`，走 `xdp_tx` | match、响应包构造、checksum 和 TX 成本 |
| XSK redirect | 命中 userspace response action，走 `xsk_redirect` | match、metadata 写入和 redirect 成本 |
| Flow cache hit | 同一五元组重复包命中 cache | cache hit 后直接执行 action 的成本 |

默认不设常规 benchmark：

- 单独的 snapshot/build/write/apply 内部函数。
- 增量更新微基准。
- malformed packet、LPM 边界、priority tie 等边界 case。
- 每一种 response action 的独立基准。
- flow cache cold miss 的 false-candidate 细分。
