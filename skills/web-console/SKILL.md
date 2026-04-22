---
name: web-console
description: Use when implementing or changing the frontend management pages under web/.
---

## Scope

Use this skill only for the management frontend under `web/`. The frontend is a configuration and visibility surface; it must not implement rule matching, analysis decisions, response decisions, or core pipeline orchestration.

## Stack

- React (JSX, no TypeScript) + Vite
- API calls through `web/src/api.js`
- Shared styles live in `web/src/index.css` using CSS variables
- Small inline styles are acceptable for local spacing or one-off sizing when an existing class is not worth adding

## Page structure

Pages should follow the existing structure:

```
page-header (h1 + description)
page-body (content)
```

Modals and confirmations should reuse the existing modal classes:

```
modal-overlay (click to dismiss)
  modal
    modal-header
    modal-body or confirm-body
    modal-footer or confirm-footer
```

Do not introduce a second modal system.

## API contract

All backend APIs go through `api.js`. Response envelope:

- Success: `{ "data": ... }` or `{ "data": [...], "total": N, "page": N, "page_size": N }`
- Error: `{ "error": { "code": "...", "message": "..." } }`

New endpoints must be added to `api.js` as exported async functions.

## Rule UI contract

- Rule forms and tables must follow `specs/RULES.md`
- Do not introduce unsupported rule fields such as `features`
- Action names use the snake_case values from `specs/RULES.md`
- The UI may validate inputs for usability, but backend/controlplane validation remains authoritative

## Conventions

- Page components and shared components use default export
- Local helper components may stay in the same file when they are only used by that page
- No state management library; state stays local to pages
- No CSS-in-JS or component styling framework; prefer classes defined in `index.css`
- All backend interaction goes through the API layer; no direct fetch in components
