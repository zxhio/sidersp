# agent layout

## 定位

`agent` 内部代码按职责分层。

不是按 HTTP 路由或传输格式分层。

本文是实现分层参考，不定义产品契约。

产品契约以 `specs/` 为准；如果本文和 specs 冲突，以 specs 为准。

---

## 整体分层

```text
resource layer
  api/
  service/
  types/

domain layer
  attachments/
  ruleset/
  response/
  dispatch/

runtime layer
  dataplane/
  xsk/
  netdev/
```

---

## resource layer

`resource layer` 负责运行态资源的对外入口和生命周期编排。

包含：

- `api/`
- `service/`
- `types/`

### `api/`

负责：

- HTTP 路由
- path / query 参数
- JSON DTO
- status code
- request / response

不负责：

- domain 逻辑
- runtime 调用
- XDP / XSK 操作

### `service/`

负责：

- resource 生命周期
- orchestration
- rollback
- runtime coordination
- runtime state

不负责：

- HTTP DTO
- 字段校验细节
- XDP / XSK 底层实现

### `types/`

负责：

- agent 内部共享的资源对象
- resource 层和 domain 层之间的结构定义

---

## domain layer

`domain layer` 负责资源语义。

包含：

- `attachments/`
- `ruleset/`
- `response/`
- `dispatch/`

负责：

- defaults
- normalize
- validate
- 兼容性检查
- compile / build

例如：

- `attachments/` 负责 queue、UMEM、attach mode、miss verdict 校验
- `ruleset/` 负责 normalize、validate、compile、matcher build

不负责：

- HTTP
- rollback
- runtime lifecycle
- dataplane 调用

---

## runtime layer

`runtime layer` 负责 Linux 和 packet runtime 实现。

包含：

- `dataplane/`
- `xsk/`
- `netdev/`

负责：

- XDP attach / detach
- BPF map
- BPF program state
- XSK start / stop
- netdevice capability query
- packet IO

不负责：

- HTTP DTO
- resource 策略
- domain 校验

---

## 目录结构

计划目录结构：

```text
internal/agent/
  api/
    router.go
    handler.go
    services.go
    dto.go
    error.go
    health.go
    status.go
    attachments.go

  service/
    attachments.go

  types/
    attachment.go

  attachments/
    defaults.go
    normalize.go
    validate.go

  dataplane/
  xsk/
  netdev/
```

---

## 核心约定

1. `api/` 只调用 service interface
2. `api/` 不直接调用 `dataplane/` / `xsk/` / `netdev/`
3. `service/` 负责 resource lifecycle
4. `service/` 通过 interface 依赖 runtime modules
5. `service/` 不使用 HTTP request DTO
6. domain package 负责资源语义
7. runtime package 负责底层实现
8. 新增 `ruleset` / `response` / `dispatch` / `stats` 时保持同样边界
