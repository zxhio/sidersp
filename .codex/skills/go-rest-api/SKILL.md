---
name: go-rest-api
description: Use when adding or changing RESTful HTTP API endpoints. Follow resource-oriented routing, unified JSON envelope, and standard status codes.
---

# Go REST API

Use this skill when adding or changing RESTful HTTP API endpoints.

Implemented with **github.com/gin-gonic/gin**. Inject dependencies via handler struct fields.

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

Error — top-level `error` object with `code` and `message`:

```json
{"error": {"code": "VALIDATION_FAILED", "message": "name is required"}}
```

Return `total`, `page`, `page_size` only for collection endpoints. Omit them for single resources.

## Status Codes

| Code | Usage |
|------|-------|
| 200  | Success (GET, PUT, PATCH) |
| 201  | Resource created (POST) |
| 204  | Success with no body (DELETE) |
| 400  | Invalid request body or params |
| 404  | Resource not found |
| 409  | Conflict (duplicate resource) |
| 500  | Internal error |
