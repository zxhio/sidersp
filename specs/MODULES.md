# Modules

## 服务边界

`agent` 是运行态服务。

- 负责 XDP / BPF / XSK / 网卡操作
- 接收 `mgr` 下发的最终 `ruleset`
- 不负责规则持久化、配置管理、历史统计和 Web 交互

`mgr` 是管理态服务。

- 负责 rules CRUD、配置管理、历史统计和 Web API
- 根据启用的 `rules` 生成最终 `ruleset`
- 内部调用 `agent` 完成运行态编排
- 不直接操作 XDP / BPF / XSK
- 不对外暴露 `agent` API 或 `ruleset` API

---

## 资源边界

- `rules`：用户管理的规则资源，归属 `mgr`
- `ruleset`：agent 运行态规则集合，由 `mgr` 生成并下发
- `stats`：`agent` 提供当前运行态计数，`mgr` 保存历史统计
- `events`：`agent` 推送运行态事件，`mgr` 可保存历史事件
- `attachments` / `response` / `dispatch`：agent 运行态配置

Web 页面只访问 `mgr`，不直接访问 `agent`。

---

## 服务文档

- `agent.md`
- `mgr.md`

## API 文档

- `agent-api.md`
- `mgr-api.md`

## agent 文档

- `agent/http.md`
- `agent/status.md`
- `agent/attachments.md`
- `agent/ruleset.md`
- `agent/events.md`
- `agent/stats.md`
- `agent/response.md`
- `agent/dispatch.md`
- `agent/dataplane.md`
- `agent/bpf-abi.md`

## mgr 文档

- `mgr/rules.md`
- `mgr/config.md`
- `mgr/stats.md`

## architecture 文档

- `../docs/architecture/agent-layout.md`
- `../docs/architecture/attachments-api.md`
