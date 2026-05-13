# mgr

## 定位

`mgr` 是管理服务，面向用户和 Web 提供管理 API。

`mgr` 负责规则管理、配置管理、历史统计和对 `agent` 的调用编排。

运行态能力由 `agent` 执行。

---

## 功能范围

- 规则 CRUD 与持久化
- 规则启用 / 停用
- 配置文件读取与管理
- agent 连接配置与状态查看
- agent 期望运行态配置持久化与重放
- 根据 `rules` 生成最终 `ruleset`
- 调用 `agent` 下发最终 `ruleset`
- 调用 `agent` 查看运行态状态、统计和事件流
- 采集并保存运行态历史统计数据
- 为 Web 页面提供统一管理 API

---

## 非职责范围

- 不直接挂载 / 卸载 XDP 程序
- 不直接创建 / 管理 XSK
- 不持久化 agent 的临时运行态状态

`mgr` 可以持久化需要下发给 agent 的期望运行态配置，但不持久化 agent 返回的实际运行态状态。

---

## Rules 与 Ruleset

`rules` 是用户管理的规则资源。

- 由 `mgr` 持久化
- 可创建、编辑、删除、启用、停用
- 用于 Web/API 展示和管理

`ruleset` 是运行态规则集合。

- 由 `mgr` 根据启用的 `rules` 生成
- 只用于下发给 `agent`
- 不作为 `mgr` 对外 API 暴露

规则流程：

- 用户在 Web / API 中创建、编辑、删除、启用、停用规则
- `mgr` 持久化 `rules`
- `mgr` 过滤启用规则，排序并生成最终 `ruleset`
- `mgr` 调用 `agent` 的 `PUT /api/v1/ruleset`
- `agent` 原子替换运行时 `ruleset`

---

## Agent 运行态重放

`agent` 进程重启后不恢复旧运行态，`mgr` 负责重放期望运行态。

触发时机：

- `mgr` 启动后首次连接 `agent`
- `mgr` 检测到 `agent` 重启或运行态为空
- 用户修改需要下发给 `agent` 的运行态配置

重放来源：

- `rules_file`：用户规则，由 `mgr` 生成最终 `ruleset`
- `runtime_file`：`attachments`、`response`、`dispatch` 等期望运行态配置

重放顺序：

- 先下发 `attachments`
- 再下发 `response`
- 再下发 `dispatch`
- 最后下发 `ruleset`

约定：

- `mgr` 不保存 `runtime.program_id`、当前 stats、当前 events 等 agent 实际运行态
- 重放失败时，`mgr` 不把失败步骤视为已生效
- `agent` 的实际运行态以 agent API 当前返回为准

---

## 统一约定

- `mgr` 面向用户和 Web，负责管理态
- `mgr` 可以持久化规则、配置、历史统计和历史事件
- `mgr` 对外只暴露 `rules`、`config`、`status`、`stats`
- `mgr` 负责把 `rules` 转换成 agent 可执行的最终 `ruleset`
- `mgr` 内部调用 agent 完成运行态编排
- 与 `agent` 的边界见 `MODULES.md`

---

## 相关文档

- `mgr-api.md`：mgr API 总览
- `mgr/rules.md`：用户规则资源定义
- `mgr/config.md`：管理侧配置定义
- `mgr/stats.md`：历史统计查询定义
- `agent.md`：agent 服务边界
- `agent-api.md`：agent API 总览
