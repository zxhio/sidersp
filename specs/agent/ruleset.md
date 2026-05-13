# agent ruleset

## 定位

`ruleset` 表示 `agent` 当前运行时规则集。

- 由 `mgr` 根据 `rules` 生成并下发
- `agent` 不提供单条规则 CRUD
- `agent` 不生成 `rule_id`
- `agent` 只使用 `ruleset` 中已有的 `rule_id`
- 具体 API 路由见 `../agent-api.md`

---

## 资源结构

```json
{
  "version": 12,
  "rules": [
    {
      "rule_id": 1001,
      "priority": 10,
      "match": {
        "protocol": "tcp",
        "dst_ports": [80, 8080],
        "tcp_flags": {
          "syn": true
        }
      },
      "response": {
        "action": "tcp_reset",
        "params": {}
      }
    }
  ]
}
```

---

## 字段约定

### `version`

- 必填
- 必须大于 `0`
- 由 `mgr` 生成
- 用于标识本次下发的 `ruleset` 版本

### `rules`

- 必填
- 规则数组
- 只包含需要实际生效的规则
- 不包含 `enabled=false` 的规则

### `rules[].rule_id`

- 必填
- 类型：`uint32`
- 由 `mgr` 生成
- 创建后不可修改
- 删除后不复用
- 用于 `stats` / `events` 关联规则

### `rules[].priority`

- 可选
- 默认值：`0`
- 必须大于等于 `0`
- 数值越小优先级越高
- 多条规则同时命中时，按 `priority ASC, rule_id ASC` 选择第一条

### `rules[].match`

- 可选
- 为空表示匹配所有包
- 字段结构和基础匹配语义见 `../mgr/rules.md`
- `agent` 负责校验、编译和加载运行态匹配结构

### `rules[].response`

- 必填
- 字段结构、动作枚举、参数约束和兼容性见 `../mgr/rules.md`
- `response.action` 由 `agent` 编译为运行态 action code
- 具体执行路径见 `response.md`

### `rules[].response.params`

- 可选
- 动作相关参数
- 不进入 BPF `rule_meta`
- 由需要用户态响应的 action 使用
- 不需要参数的 action 应为空或省略

---

## 与 `mgr/rules.md` 的关系

`mgr/rules.md` 是规则 schema 的权威定义。

`agent/ruleset.md` 只描述 agent 接收的运行态规则集，以及 agent 侧的加载、编译和更新约束。

来自 `rules` 但不会进入 agent `ruleset` 的字段：

- `name`
- `enabled`
- `created_at`
- `updated_at`
- 仅供管理态使用的字段

保留进入 agent `ruleset` 的字段：

- `rule_id`
- `priority`
- `match`
- `response`

---

## Match 语义

`rules[].match` 的字段定义和基础匹配语义以 `../mgr/rules.md` 为准。

`agent` 侧只负责运行态编译和执行，必须保证：

- 按 `priority ASC, rule_id ASC` 编译规则
- 多条规则同时命中时，选择编译顺序中的第一条
- 未配置字段按 wildcard 处理
- 只支持正向匹配，不支持否定条件

---

## Response Action

`rules[].response.action` 的枚举值、参数约束和兼容性以 `../mgr/rules.md` 为准。

`agent` 负责：

- 校验 `response.action`
- 校验 `match` / `response.action` 是否兼容
- 将 `response.action` 编译为运行态 action code
- 根据 `response.action` 选择 no response、kernel response 或 userspace response 路径
- 将执行结果通过 `events` 和 `stats` 上报

具体执行路径见 `response.md`。

---

## 更新语义

`PUT /api/v1/ruleset` 用于整体替换当前运行时 `ruleset`。

更新过程必须是原子的：

- 校验 `ruleset`
- 编译运行态结构
- 更新 BPF maps / 用户态索引
- 全部成功后切换到新版本
- 任一步失败时保留旧版本

`PUT /api/v1/ruleset?dry_run=true` 只校验，不应用。

`DELETE /api/v1/ruleset` 清空当前运行时规则集。

清空 `ruleset` 不影响以下运行态配置：

- `attachments`
- `response`
- `dispatch`

进程重启后当前 `ruleset` 丢失，由 `mgr` 重新生成并调用 `PUT /api/v1/ruleset` 下发。

---

## 编译约定

- `enabled` 不出现在 agent `ruleset` 中
- `name` 不出现在 agent `ruleset` 中
- `created_at` 不出现在 agent `ruleset` 中
- `updated_at` 不出现在 agent `ruleset` 中
- `response.params` 不进入 BPF `rule_meta`
- `agent` 可以将匹配条件编译为索引和 `required_mask`
- 内核事件和统计统一使用 `rule_id`

---

## 运行态字段

BPF `rule_meta` 只包含运行态必要字段。

字段：

```text
rule_id
required_mask
action
flags
```

不进入 BPF `rule_meta` 的字段：

- `priority`
- `name`
- `enabled`
- `response.params`
- `created_at`
- `updated_at`

dataplane 编译语义见 `dataplane.md`。

BPF map、condition bit 和 action code 见 `bpf-abi.md`。

---

## 资源边界

- `ruleset`：当前运行时规则集
- `rules`：由 `mgr` 管理，不由 `agent` 暴露
- `response`：定义 `response.action` 的运行态执行路径
- `events`：上报规则命中和动作结果
- `stats`：记录当前运行态计数
