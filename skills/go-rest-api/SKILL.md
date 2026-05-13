---
name: rest-api
description: Use when designing or implementing RESTful HTTP APIs with Gin. Covers routing, REST-style response bodies, status codes, API package layout, DTOs, service interfaces, and handler naming.
---

## Source of truth

Use the matching API spec first.

- Agent HTTP conventions: `specs/agent/http.md`
- Agent routes: `specs/agent-api.md`
- Mgr routes: `specs/mgr-api.md`
- Resource contracts: `specs/agent/` and `specs/mgr/`

If this skill conflicts with a spec, follow the spec and update this skill.

## Routing

Resource-oriented paths. No verbs in URLs.

### Good

```
GET    /api/v1/rules
POST   /api/v1/rules
GET    /api/v1/rules/:id
PUT    /api/v1/rules/:id
PATCH  /api/v1/rules/:id
DELETE /api/v1/rules/:id
GET    /api/v1/status
PUT    /api/v1/ruleset?dry_run=true
```

### Bad

```
GET  /api/v1/getRules
POST /api/v1/createRule
POST /api/v1/deleteRule?id=123
POST /api/v1/rules/:id/enable
POST /api/v1/rules/:id/disable
```

## Response Bodies

Use plain REST response bodies. Do not wrap successful responses in `data` envelopes.

Single resource:

```json
{"id": "r1", "name": "rule-1"}
```

Collection:

```json
[{"id": "r1"}, {"id": "r2"}]
```

Empty collection:

```json
[]
```

Error:

```json
{
  "type": "about:blank",
  "title": "Validation failed",
  "status": 400,
  "detail": "name is required",
  "code": "validation_failed"
}
```

Use Problem Details style for errors. Error `code` values are stable snake_case strings.

Use `204 No Content` with no body for successful delete or successful operations that do not return a resource.

## Pagination

Use query parameters for collection pagination:

- `limit`: maximum items to return, when the API contract defines it
- `cursor`: opaque cursor returned by the previous page

Use a collection object for paginated responses:

```json
{
  "items": [{"id": "r1"}, {"id": "r2"}],
  "next_cursor": "abc"
}
```

Rules:

- Use cursor pagination by default.
- Do not put `page`, `page_size`, `total`, or `data` in new response bodies unless the matching spec requires legacy compatibility.
- Use `next_cursor`; set it to an empty string when there is no next page.
- Treat `cursor` as opaque; clients must not parse it.
- Use `limit` defaults and maximums defined by the API contract.

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

Put Gin HTTP code under `api/`.

```text
api/
  router.go
  handler.go
  services.go
  dto.go
  error.go
  <resources>.go
```

Rules:

- `router.go`: route registration and router constructor.
- `handler.go`: `Handler` struct, constructor, and shared handler helpers.
- `services.go`: service interfaces consumed by API handlers.
- `dto.go`: shared request / response DTOs.
- `error.go`: API error codes and error-to-response mapping.
- `<resources>.go`: resource endpoint handlers; use plural names such as `attachments.go`.

### Naming

- `Handler` for endpoint handlers.
- `NewHandler` / `NewRouter` or local equivalents for constructors.
- `<Resource>Service` for API-facing service interfaces.
- `<Action><Resource>Request` / `<Resource>Response` for request/response structs
- Handler names: `CreateResource`, `ListResources`, `GetResource`, `PatchResource`, `DeleteResource`

### Handler Structure

Handler parses path / query / body, validates transport input, maps DTOs to internal values, delegates to service, maps service results to response DTOs, then writes the HTTP response.

```go
type Handler struct{ svc ItemService }

func (h *Handler) CreateItem(c *gin.Context) {
	var req CreateItemRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		writeError(c, http.StatusBadRequest, "validation_failed", "Validation failed", err.Error())
		return
	}
	item, err := h.svc.Create(c.Request.Context(), newItem(req))
	if err != nil {
		writeError(c, http.StatusInternalServerError, "internal_error", "Internal error", err.Error())
		return
	}
	c.JSON(http.StatusCreated, newItemResponse(*item))
}
```

### Service Interfaces

`api` depends on service interfaces. Define interfaces near the handler in `services.go`.

```go
type ResourceService interface {
	Validate(ctx context.Context, resource resource.Resource) (*resource.Resource, error)
	Create(ctx context.Context, resource resource.Resource) (*resource.Resource, error)
	List(ctx context.Context) ([]resource.Resource, error)
	Get(ctx context.Context, id int) (*resource.Resource, error)
	SetEnabled(ctx context.Context, id int, enabled bool) (*resource.Resource, error)
	Delete(ctx context.Context, id int) error
}
```

Rules:

- Model methods by resource operation.
- Use explicit parameters or internal resource types.
- Do not pass HTTP request DTOs into service methods.
- Lifecycle toggles use explicit methods such as `SetEnabled(ctx, id, enabled)`.

### Request / Response Structs

- Define API-owned request and response structs in `api/`; do not return internal resource types directly.
- Add `json` tags to all fields
- Request: `<Action><Resource>Request`, e.g. `CreateAttachmentRequest`
- Response: `<Resource>Response`, e.g. `AttachmentResponse`
- Use `<Action><Resource>Response` only when a resource has multiple response shapes
- `PATCH` request DTOs include only the fields that endpoint may modify

Do not pass request DTOs through the service boundary:

```go
SetEnabled(ctx, PatchResourceRequest)
```

### Mapping Functions

- `newResource`: API request DTO -> internal resource type
- `newResourceResponse`: internal resource type -> API response DTO
- `newResourceResponses`: internal resource slice -> API response DTO slice
- Copy slice fields defensively with `append([]T(nil), src...)`

### Call Flow

```text
POST /api/v1/resources?dry_run=true
  -> api.CreateResource
  -> service.Validate
  -> return response DTO

POST /api/v1/resources
  -> api.CreateResource
  -> service.Create
  -> return response DTO

PATCH /api/v1/resources/{id}
  -> api.PatchResource
  -> service.SetEnabled
  -> return response DTO

DELETE /api/v1/resources/{id}
  -> api.DeleteResource
  -> service.Delete
  -> return HTTP status
```

`dry_run=true` is an API query parameter. The service owns what validation applies.

### Checklist

- Handler only calls service interfaces.
- Service interfaces do not accept HTTP DTOs.
- Request / response DTOs stay in `api/`.
- File names and type names use the same resource word.
- `PATCH` only changes explicitly allowed fields.
