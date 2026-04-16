---
name: go-gin-api
description: Use when implementing REST APIs in Go with gin-gonic/gin. Follow rest-api for endpoint design, and use handler structs with Gin routing and JSON responses.
---

# Go Gin API

Use this skill when implementing REST APIs in Go with `github.com/gin-gonic/gin`.

Follow `rest-api` for endpoint design and response rules.

## Layout

- Put Gin HTTP code in a dedicated module (e.g. `internal/<module>/`)
- `server.go` for router and server startup
- `handler.go` for endpoint handlers, split to `handlers_*.go` when large
- `types.go` for request and response structs

## Naming

- `Server` struct, `NewServer` / `newRouter` constructors
- `Handler` for handlers, `<Resource>Service` for injected interfaces
- `<Action><Resource>Request` / `<Resource>Response` for request/response structs
- Handler methods: `getItem`, `listItems`, `deleteItem`

## Handler Structure

Handler binds params, validates transport input, then delegates to service.

### Good

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

### Bad

```go
func CreateItem(c *gin.Context) {
	body, _ := io.ReadAll(c.Request.Body)
	var m map[string]any
	json.Unmarshal(body, &m)
	db.Exec("INSERT INTO items (name) VALUES (?)", m["name"])
}
```

## Request / Response Structs

- Keep in the API module, not in business-logic packages
- Do not put request or response structs in `handler.go`
- Put request and response structs in `types.go`
- Put `json` tags on all fields
- Use dedicated response structs only when API shape differs from internal model
- Request: `<Action><Resource>Request` — e.g. `CreateItemRequest`, `UpdateItemRequest`
- Response: `<Resource>Response` — e.g. `ItemResponse`; use `<Action><Resource>Response` only when multiple response shapes exist for the same resource
