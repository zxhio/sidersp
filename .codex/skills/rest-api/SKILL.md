---
name: rest-api
description: Use when designing or changing RESTful HTTP APIs. Follow resource-oriented routing, unified JSON envelope, pagination, and standard status codes.
---

# REST API

Use this skill when designing or changing RESTful HTTP APIs.

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
