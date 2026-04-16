---
name: rest-api
description: Use when designing or implementing RESTful HTTP APIs with Gin. Covers routing, envelope, status codes, and Gin handler layout.
---

## Routing

Resource-oriented paths. No verbs in URLs.

### Good

```
GET    /api/v1/rules
POST   /api/v1/rules
GET    /api/v1/rules/:id
PUT    /api/v1/rules/:id
DELETE /api/v1/rules/:id
GET    /api/v1/status
POST   /api/v1/rules/:id/enable
POST   /api/v1/rules/:id/disable
```

### Bad

```
GET  /api/v1/getRules
POST /api/v1/createRule
POST /api/v1/deleteRule?id=123
```

## Response Envelope

Always wrap in an envelope.

Single resource:

```json
{"data": {"id": "r1", "name": "rule-1"}}
```

Collection with pagination:

```json
{
  "data": [{"id": "r1"}, {"id": "r2"}],
  "total": 42,
  "page": 1,
  "page_size": 20
}
```

Use query parameters `page` (1-based) and `page_size` (default 100) for collection endpoints.

Error:

```json
{"error": {"code": "VALIDATION_FAILED", "message": "name is required"}}
```

Return `total`, `page`, `page_size` only for collection endpoints. Omit them for single resources.

## Status Codes

- `200` success for `GET`, `PUT`, `PATCH`
- `201` resource created
- `204` success with no body
- `400` invalid request body or params
- `404` resource not found
- `409` conflict
- `500` internal error

## Gin Implementation

### Layout

- Put Gin HTTP code in a dedicated module (e.g. `internal/<module>/`)
- `server.go` for router and server startup
- `handler.go` for endpoint handlers, split to `handlers_*.go` when large
- `types.go` for request and response structs

### Naming

- `Server` struct, `NewServer` / `newRouter` constructors
- `Handler` for handlers, `<Resource>Service` for injected interfaces
- `<Action><Resource>Request` / `<Resource>Response` for request/response structs
- Handler methods: `getItem`, `listItems`, `deleteItem`

### Handler Structure

Handler binds params, validates transport input, then delegates to service.

```go
type Handler struct{ svc ItemService }

func (h *Handler) createItem(c *gin.Context) {
	var req CreateItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	item, err := h.svc.Create(c.Request.Context(), req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"data": item})
}
```

### Request / Response Structs

- Define API-owned request and response structs in `types.go`; do not reference upstream internal types
- Add `json` tags to all fields
- Map between API types and internal types via conversion functions (`newXxxResponse` / `newXxxModel`)
- Request: `<Action><Resource>Request` or shared `<Resource>Body` — e.g. `RuleBody`
- Response: `<Resource>Response` — e.g. `StatsResponse`; use `<Action><Resource>Response` only when a resource has multiple response shapes

### Mapping Functions

- `newXxxResponse`: internal type → API response type; place in handler file or a separate mapper file
- `newXxxModel`: API request type → internal type
- Collection mapping: `newXxxBodies` for batch conversion, calling the single-item function internally
- Copy slice fields defensively with `append([]T(nil), src...)`
