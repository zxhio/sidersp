# mgr config

## 定位

`config` 表示 `mgr` 的管理侧配置。

- `config.yml` 保存启动配置和管理配置
- `/api/v1/config` 只暴露可管理配置
- 当前不使用数据库，管理态数据持久化到文件
- 具体 API 路由见 `../mgr-api.md`

---

## 配置文件示例

```yaml
server:
  listen_addr: "127.0.0.1:8080"

agent:
  base_url: "http://127.0.0.1:9000"
  timeout_seconds: 5

storage:
  data_dir: "./data"
  rules_file: "./data/rules.json"
  runtime_file: "./data/runtime.json"
  stats_dir: "./data/stats"
```

---

## API 资源结构

```json
{
  "agent": {
    "base_url": "http://127.0.0.1:9000",
    "timeout_seconds": 5
  },
  "storage": {
    "data_dir": "./data",
    "rules_file": "./data/rules.json",
    "runtime_file": "./data/runtime.json",
    "stats_dir": "./data/stats"
  }
}
```

---

## 字段约定

### `server.listen_addr`

- 仅存在于 `config.yml`
- 不通过 `/api/v1/config` 暴露
- 不支持运行期修改
- 表示 `mgr` HTTP API 监听地址

### `agent.base_url`

- 必填
- `agent` API 地址
- `mgr` 通过该地址调用 agent

### `agent.timeout_seconds`

- 可选
- 默认值：`5`
- 调用 `agent` 的 HTTP 超时时间

### `storage.data_dir`

- 可选
- 默认值：`./data`
- 管理态数据目录

### `storage.rules_file`

- 可选
- 默认值：`./data/rules.json`
- 用户规则持久化文件路径

### `storage.runtime_file`

- 可选
- 默认值：`./data/runtime.json`
- attachments / response / dispatch 等运行态期望配置文件路径
- 只保存期望配置，不保存 agent 返回的实际运行态状态

### `storage.stats_dir`

- 可选
- 默认值：`./data/stats`
- 历史统计数据目录

---

## API 语义

### `GET /api/v1/config`

- 查看当前可管理配置
- 不返回 `server.listen_addr`

### `PUT /api/v1/config`

- 整体替换当前可管理配置
- 不修改 `server.listen_addr`

---

## 数据边界

- `config.yml`：保存启动配置和管理配置
- `server.listen_addr`：启动配置，只在进程启动时读取
- `rules_file`：保存用户 `rules`
- `runtime_file`：保存 attachments / response / dispatch 等运行态期望配置
- `stats_dir`：保存历史统计数据
- `mgr` 通过 `agent.base_url` 调用 `agent`
- `agent` 读取自己的配置文件，不读取 `mgr` 的 `config.yml`
