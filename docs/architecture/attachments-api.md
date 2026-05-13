# attachments API 实现参考

## 定位

本文是 `agent` attachments API 的实现参考。

用于实现阶段对照。

实现完成并稳定后可以删除。

本文不新增 API、字段或语义契约。

产品契约以 specs 为准；如果本文和 specs 冲突，以 specs 为准。

外部资源契约见：`../../specs/agent/attachments.md`

API 路由契约见：`../../specs/agent-api.md`

HTTP 返回约定见：`../../specs/agent/http.md`

---

## 资源职责

`attachments` 表示 `agent` 管理的 XDP attachment 资源。

负责：

- XDP attachment 生命周期
- XSK runtime 生命周期编排
- attachment 配置校验
- attachment 启停
- attachment runtime 查询

不负责：

- rules CRUD
- 配置持久化
- 历史状态
- Web UI

不单独实现 `/api/v1/xsks`。

XSK 配置和启停由 `attachments[].xsk` 管理。

---

## service interface

`api` 依赖 service interface。

interface 按资源操作建模：

```go
type AttachmentService interface {
	Validate(ctx context.Context, attachment types.Attachment) (*types.Attachment, error)
	Create(ctx context.Context, attachment types.Attachment) (*types.Attachment, error)
	List(ctx context.Context) ([]types.Attachment, error)
	Get(ctx context.Context, ifindex int) (*types.Attachment, error)
	SetEnabled(ctx context.Context, ifindex int, enabled bool) (*types.Attachment, error)
	Delete(ctx context.Context, ifindex int) error
}
```

`service` 不使用 HTTP request DTO。

使用明确参数或资源对象：

```go
SetEnabled(ctx, ifindex, enabled)
```

不要这样传：

```go
SetEnabled(ctx, AttachmentPatchRequest)
```

---

## DTO 边界

HTTP request / response DTO 只放在 `api/`。

`PATCH /api/v1/attachments/{ifindex}` 只修改生命周期状态：

```go
type AttachmentPatchRequest struct {
	Enabled bool `json:"enabled"`
}
```

不允许 `PATCH` 修改：

- attachment shape
- queues
- UMEM
- attach mode
- miss verdict

`POST /api/v1/attachments` 的 request DTO 不包含 `enabled`。

---

## domain 边界

`internal/agent/attachments/` 负责 attachment 语义。

### `defaults.go`

负责：

- attach mode 默认值
- miss verdict 默认值
- UMEM 默认值

### `normalize.go`

负责：

- normalize
- 派生字段
- rx queue count 自动补全
- xsk queues 自动补全

### `validate.go`

负责校验：

- ifindex
- attach mode
- miss verdict
- rx queue count
- xsk queues
- UMEM
- ifname / ifindex 匹配

queue 和 UMEM 细节属于 domain 逻辑。

不放在 `service/`。

---

## service 边界

`internal/agent/service/attachments.go` 负责 orchestration。

负责：

- Validate
- Attach XDP
- Start XSK
- Rollback
- Save memory state
- Stop XSK
- Detach XDP

不负责：

- queue 校验
- UMEM 校验
- attach mode 校验

这些属于 `attachments/`。

---

## dry-run

`POST /api/v1/attachments?dry_run=true` 只校验并返回 normalized attachment。

执行：

- defaults
- normalize
- validate
- netdev 能力查询

不执行：

- XDP attach
- XSK start
- memory state save

即使同一 `ifindex` 已存在，也不修改现有资源。

语义与 `PUT /api/v1/ruleset?dry_run=true` 保持一致。

---

## 调用链

### dry-run

```text
POST /api/v1/attachments?dry_run=true
  -> api.CreateAttachment
  -> service.Validate
      -> attachments.ApplyDefaults
      -> netdev.Resolve
      -> netdev.MaxRXQueueCount
      -> attachments.Normalize
      -> attachments.Validate
  -> return normalized attachment
```

### create

```text
POST /api/v1/attachments
  -> api.CreateAttachment
  -> service.Create
      -> service.Validate
      -> dataplane.Attach
      -> xsk.Start
      -> save memory state
```

约定：

- create request 不包含 `enabled`
- ifindex 已存在时返回 conflict
- attach 或 XSK start 失败时回滚
- create 成功后保存内存状态
- create 成功后返回 `enabled=true`

### patch

```text
PATCH /api/v1/attachments/{ifindex}
  -> api.PatchAttachment
  -> service.SetEnabled
      -> dataplane.Attach/Detach
      -> xsk.Start/Stop
      -> update memory state
```

约定：

- PATCH 只修改 `enabled`
- true -> false 时先停 XSK，再 detach XDP
- false -> true 时先 attach XDP，再按 xsk.enabled 启动 XSK

### delete

```text
DELETE /api/v1/attachments/{ifindex}
  -> api.DeleteAttachment
  -> service.Delete
      -> xsk.Stop
      -> dataplane.Detach
      -> remove memory state
```

约定：

- delete 删除内存状态
- delete 成功返回 204
- 资源不存在返回 not_found

---

## 核心约定

1. `api` 只负责 HTTP
2. `service` 只负责 orchestration 和 lifecycle
3. `attachments/` 负责 attachment 语义
4. runtime package 负责 Linux / XDP / XSK 实现
5. `service` 不使用 HTTP DTO
6. `PATCH` 只负责启停
7. `dry_run=true` 只校验不应用
8. attachment 状态保存在内存
9. `api` 不直接调用 dataplane / xsk / netdev
10. `service` 通过 interface 依赖 runtime modules
11. 不暴露独立 `/api/v1/xsks`
