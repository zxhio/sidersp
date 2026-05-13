# agent

## 定位

`agent` 是本机运行态服务，负责直接操作 `XDP` / `BPF` / `XSK` / 网卡。

- 所有运行态操作通过 HTTP API 交互
- 启动时读取自身配置文件
- 配置文件只包含 `server.listen_addr`
- 不负责规则持久化
- 不负责业务配置管理
- 不负责历史统计存储
- 不负责 Web 交互

---

## 功能范围

- XDP 程序挂载与卸载
- XSK 启动、关闭与启停控制
- 运行时 `ruleset` 更新
- 内核规则匹配事件推送
- 当前运行态 `stats` 查询
- `fast response` 执行
- `XSK response` 执行
- 数据包分发

---

## 非职责范围

- 不提供规则 CRUD
- 不持久化规则
- 不生成 `rule_id`
- 不保存历史 `stats` / `events`
- 不读取和管理业务配置
- 不提供 Web 页面

---

## 核心约定

- 请求中统一使用 `ifindex` 标识网卡
- 返回中可以附带 `ifname`，便于日志、调试和 Web 展示
- `rule_id` 由 `mgr` 生成
- `agent` 不提供单条规则 CRUD，只接收最终 `ruleset`
- `stats` 表示当前运行态计数，不表示历史统计数据
- `events` 表示运行态事件推送，不做历史事件查询
- 与 `mgr` 的边界见 `MODULES.md`

---

## 恢复约定

`agent` 只保存当前进程内的运行态状态。

- 进程重启后，`attachments`、`ruleset`、`response`、`dispatch` 回到空状态或默认状态
- `agent` 不从本地文件恢复旧运行态
- `agent` 不主动从 `mgr` 拉取运行态配置
- 期望运行态由 `mgr` 持久化并重新下发
- `mgr` 重放完成前，`GET /api/v1/status` 只表示 agent 当前实际运行态

---

## 相关文档

- `agent-api.md`：agent API 总览
- `agent/http.md`：agent HTTP 返回约定
- `agent/status.md`：agent health 和 status 定义
- `agent/attachments.md`：XDP attachment 资源定义
- `agent/ruleset.md`：运行时 ruleset 定义
- `agent/events.md`：事件推送定义
- `agent/stats.md`：当前运行态 stats 定义
- `agent/response.md`：response 网口与响应路径定义
- `agent/dispatch.md`：数据包分发配置定义
- `agent/dataplane.md`：快路径包处理语义
- `agent/bpf-abi.md`：BPF / Go 内部 ABI
