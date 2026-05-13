# agent HTTP

## 定位

`http` 定义 agent API 的通用 HTTP 返回约定。

API 路由见 `../agent-api.md`。

---

## 成功响应

成功响应直接返回资源对象。

示例：

```json
{
  "ifindex": 3,
  "enabled": true
}
```

不使用 `data` envelope。

---

## 列表响应

普通列表直接返回数组。

示例：

```json
[
  {
    "ifindex": 3,
    "enabled": true
  }
]
```

---

## 分页响应

需要分页时返回集合对象。

示例：

```json
{
  "items": [],
  "next_cursor": ""
}
```

约定：

- `items`：当前页资源数组
- `next_cursor`：下一页游标；没有下一页时为空

---

## 删除响应

删除成功返回：

```text
204 No Content
```

`204` 响应不返回 body。

---

## SSE 响应

SSE 使用：

```text
text/event-stream
```

SSE 不使用 JSON envelope。

---

## 错误响应

错误响应使用 Problem Details 风格。

示例：

```json
{
  "type": "about:blank",
  "title": "Validation failed",
  "status": 400,
  "detail": "ifindex must be greater than 0",
  "code": "validation_failed"
}
```

---

## 错误字段

### `type`

- 可选
- 默认值：`about:blank`

### `title`

- 简短错误标题

### `status`

- HTTP status code

### `detail`

- 面向调用方的错误说明

### `code`

- 稳定错误码

---

## error code

- `bad_request`：请求格式错误
- `validation_failed`：字段或语义校验失败
- `not_found`：资源不存在
- `conflict`：资源冲突
- `runtime_failed`：运行态操作失败
- `internal_error`：内部错误
